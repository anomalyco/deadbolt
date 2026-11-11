//! Vault application envelopes shared by the native and browser devices.
//!
//! Transport authenticates the peer. This module applies the vault membership
//! rules; adapters own durable transactions, address books and readiness. No
//! data is sent or accepted until the caller's membership barrier is open.

#[cfg(feature = "storage")]
pub mod storage;

mod round;
pub use round::{RoundState, sync_round};

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    net::SocketAddr,
    time::Duration,
};

use data_encoding::HEXLOWER;
use deadbolt_core::{
    DeviceId, DeviceSecret, Entry, Heads, Log, MissingLog, Signature, Vault, VaultId, VaultWrite,
    valid_name,
};
use n0_future::time::Instant;
use n0_future::{FuturesUnorderedBounded, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::{Blob, PeerAddr, PeerId};

const CONTACT_TIMEOUT: Duration = Duration::from_secs(15);
const CONTACT_CONCURRENCY: usize = 4;

/// Contact a snapshot of peers, with a shared deadline only during startup.
/// At most four contacts run at once, without spawning detached tasks. Each
/// contact must bound its dial and exchange together by the supplied budget.
/// A true result counts as contacted (including unreachable during the dial).
/// Ready rounds have no shared deadline, so every queued peer gets an attempt.
pub async fn contact_round<E, F: Future<Output = Result<bool, E>>>(
    targets: Vec<PeerAddr>,
    deadline: Option<Instant>,
    contact: impl Fn(PeerAddr, Duration) -> F,
) -> Result<Vec<PeerId>, E> {
    let mut targets = targets.into_iter();
    let mut pending = FuturesUnorderedBounded::new(CONTACT_CONCURRENCY);
    let mut completed = Vec::new();
    loop {
        while pending.len() < CONTACT_CONCURRENCY {
            let budget = deadline.map_or(CONTACT_TIMEOUT, |until| {
                CONTACT_TIMEOUT.min(until.saturating_duration_since(Instant::now()))
            });
            if budget.is_zero() {
                break;
            }
            let Some(peer) = targets.next() else { break };
            let contact = &contact;
            pending.push(async move {
                let id = peer.id;
                contact(peer, budget).await.map(|complete| (id, complete))
            });
        }
        let Some(result) = pending.next().await else {
            break;
        };
        let (id, complete) = result?;
        if complete {
            completed.push(id);
        }
    }
    Ok(completed)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Core(#[from] deadbolt_core::Error),
    #[error(transparent)]
    Decode(#[from] deadbolt_core::DecodeError),
    #[error("invalid hex encoding")]
    Hex,
    #[error("{0}")]
    Protocol(&'static str),
    #[error("vault not held")]
    VaultNotHeld,
    #[error("this device is no longer a member of {0}")]
    NotMember(String),
    #[error("that device was removed from {0} and can't rejoin it")]
    Removed(String),
}

/// How to reach a device. Addresses and names are hints, never authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Addr {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct: Vec<SocketAddr>,
}

impl Addr {
    pub fn from_peer(addr: PeerAddr) -> Self {
        Self {
            relay: addr.relay_url,
            direct: addr.direct_addrs,
        }
    }

    pub fn peer(&self, id: PeerId) -> PeerAddr {
        PeerAddr {
            id,
            relay_url: self.relay.clone(),
            direct_addrs: self.direct.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hint {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub addr: Option<Addr>,
    #[serde(default)]
    pub addr_seen: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Hello {
    pub v: u32,
    pub name: String,
    pub addr: Option<Addr>,
    #[serde(default)]
    pub peers: BTreeMap<String, Hint>,
    pub vaults: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub struct Offer {
    pub v: u32,
    pub vault: String,
    pub vault_name: String,
    pub name: String,
    pub addr: Option<Addr>,
}

#[derive(Serialize, Deserialize)]
pub struct JoinBlob {
    pub v: u32,
    pub consent: String,
    pub name: String,
    pub addr: Option<Addr>,
}

#[derive(Serialize, Deserialize)]
pub struct WelcomeMeta {
    pub v: u32,
    pub peers: BTreeMap<String, Hint>,
}

/// The only application I/O seam. `update` must validate privately, commit its
/// new entries durably, then publish them. A precommit error leaves the vault
/// unchanged; an uncertain commit must invalidate the live view until replay.
/// Enforce membership even if a later vault or address-book write fails: an
/// earlier vault may already have committed.
pub trait State {
    type Error: From<Error>;

    fn device_id(&self) -> DeviceId;
    fn device_name(&self) -> &str;
    fn vaults(&self) -> impl Iterator<Item = &Vault>;
    fn hints_for(&self, peer: &DeviceId) -> BTreeMap<String, Hint>;
    fn update<T>(
        &mut self,
        id: VaultId,
        change: impl FnOnce(&mut VaultWrite<'_>, &DeviceSecret) -> Result<T, Error>,
    ) -> Result<T, Self::Error>;
    /// Learn and persist the peer's direct metadata and indirect hints.
    fn learn(
        &mut self,
        peer: &DeviceId,
        name: &str,
        addr: Option<Addr>,
        hints: BTreeMap<String, Hint>,
    ) -> Result<(), Self::Error>;
    /// Record a completed receive (e.g. the native address book's last-seen).
    fn received(&mut self, peer: &DeviceId) -> Result<(), Self::Error>;
}

pub fn clean_name(name: &str) -> String {
    name.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect()
}

fn unhex<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    HEXLOWER
        .decode(text.as_bytes())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::Hex)
}

pub fn hello(s: &impl State, peer: &DeviceId, addr: Option<Addr>) -> Result<Vec<u8>, Error> {
    let vaults = s
        .vaults()
        .filter(|v| v.is_member(peer))
        .map(|v| (v.id().to_string(), HEXLOWER.encode(&v.heads().encode())))
        .collect();
    Ok(serde_json::to_vec(&Hello {
        v: 1,
        name: s.device_name().into(),
        addr,
        peers: s.hints_for(peer),
        vaults,
    })?)
}

/// Snapshot selection is made under the state lock. A pull reacquires that
/// lock only long enough to check current authority and encode one frame.
pub struct OutgoingHistory {
    peer: DeviceId,
    meta: Option<Blob>,
    logs: VecDeque<(VaultId, MissingLog)>,
    scope: HistoryScope,
}

enum HistoryScope {
    Pairing,
    Sync {
        negotiated: BTreeSet<VaultId>,
        data: bool,
    },
}

impl OutgoingHistory {
    pub fn next(&mut self, s: &impl State, ready: bool) -> Result<Option<Blob>, Error> {
        while let Some((id, cursor)) = self.logs.front_mut() {
            if !ready && !matches!(self.scope, HistoryScope::Sync { data: false, .. }) {
                return Err(Error::Protocol("waiting for membership sync"));
            }
            let v = s
                .vaults()
                .find(|v| v.id() == *id)
                .ok_or(Error::VaultNotHeld)?;
            if !v.is_member(&self.peer) {
                self.omit_revoked(s)?;
                continue;
            }
            if matches!(self.scope, HistoryScope::Pairing) && !v.is_member(&s.device_id()) {
                return Err(Error::Protocol("history transfer no longer authorized"));
            }
            if let Some(meta) = self.meta.take() {
                return Ok(Some(meta));
            }
            if let Some(entry) = cursor.next(v)? {
                return Ok(Some(entry.encode()));
            }
            self.logs.pop_front();
        }
        Ok(None)
    }

    // Slow path under the same state lock as next(). Drop *both* phases of
    // each revoked vault, even if later membership resolution changes again.
    // A missing vault, missing signed tip or unexplained loss of admission
    // isn't proof of removal; leave those errors fatal.
    fn omit_revoked(&mut self, s: &impl State) -> Result<(), Error> {
        let denied = || Error::Protocol("history transfer no longer authorized");
        let HistoryScope::Sync { negotiated, .. } = &mut self.scope else {
            return Err(denied());
        };
        let mut removed = BTreeMap::new();
        let mut held = 0;
        for v in s.vaults().filter(|v| negotiated.contains(&v.id())) {
            held += 1;
            if !v.is_member(&self.peer) {
                if !v.was_removed(&self.peer) {
                    return Err(denied());
                }
                removed.insert(v.id(), v);
            }
        }
        if held != negotiated.len() {
            return Err(Error::VaultNotHeld);
        }
        if held == removed.len() {
            return Err(denied()); // No other negotiated vault still admits the peer.
        }
        for (id, cursor) in &self.logs {
            if let Some(vault) = removed.get(id) {
                cursor.check_tips(vault)?;
            }
        }
        self.logs.retain(|(id, _)| !removed.contains_key(id));
        negotiated.retain(|id| !removed.contains_key(id));
        Ok(())
    }

    pub fn outgoing<'a>(
        mut self,
        mut pull: impl FnMut(&mut Self) -> Result<Option<Blob>, crate::HandlerError> + Send + 'a,
    ) -> crate::Outgoing<'a> {
        Box::new(std::iter::from_fn(move || pull(&mut self).transpose()))
    }
}

pub fn missing_for<S: State>(
    s: &mut S,
    peer: &DeviceId,
    bytes: &[u8],
    ready: bool,
) -> Result<OutgoingHistory, S::Error> {
    let hello: Hello = serde_json::from_slice(bytes).map_err(Error::from)?;
    if hello.v != 1 {
        return Err(Error::Protocol("unsupported sync envelope").into());
    }
    s.learn(peer, &hello.name, hello.addr, hello.peers)?;
    let mut logs = VecDeque::new();
    let mut data = Vec::new();
    for (id, heads) in &hello.vaults {
        let Ok(id) = unhex::<32>(id).map(VaultId::from_bytes) else {
            continue;
        };
        let Some(vault) = s.vaults().find(|v| v.id() == id && v.is_member(peer)) else {
            continue;
        };
        let bytes = HEXLOWER.decode(heads.as_bytes()).map_err(|_| Error::Hex)?;
        let heads = Heads::decode(&bytes).map_err(Error::from)?;
        logs.push_back((id, vault.missing_log(&heads, Log::Membership)));
        if ready {
            data.push((id, vault.missing_log(&heads, Log::Data)));
        }
    }
    let negotiated = logs.iter().map(|(id, _)| *id).collect();
    logs.extend(data);
    Ok(OutgoingHistory {
        peer: *peer,
        meta: None,
        logs,
        scope: HistoryScope::Sync {
            negotiated,
            data: ready,
        },
    })
}

/// Skip malformed/rejected entries, not the valid removals beside them. Check
/// data against the evolving membership, and commit independently per vault.
pub fn receive<S: State>(
    s: &mut S,
    peer: &DeviceId,
    entries: Vec<Blob>,
    ready: bool,
) -> Result<usize, S::Error> {
    let mut grouped: BTreeMap<VaultId, Vec<Entry>> = BTreeMap::new();
    for bytes in entries {
        let entry = match Entry::decode(&bytes) {
            Ok(entry) => entry,
            Err(error) => {
                warn!(peer = %peer, "undecodable entry: {error}");
                continue;
            }
        };
        if !s.vaults().any(|v| v.id() == entry.vault()) || (entry.log() == Log::Data && !ready) {
            continue;
        }
        grouped.entry(entry.vault()).or_default().push(entry);
    }
    let mut added = 0;
    for (id, entries) in grouped {
        added += s.update(id, |vault, _| {
            let mut added = 0;
            for entry in entries {
                if entry.log() == Log::Data && !vault.is_member(peer) {
                    continue;
                }
                match vault.apply(entry) {
                    Ok(true) => added += 1,
                    Ok(false) => {}
                    Err(error) => debug!(peer = %peer, "rejected entry: {error}"),
                }
            }
            Ok(added)
        })?;
    }
    s.received(peer)?;
    if added > 0 {
        info!(peer = %peer, entries = added, "received");
    }
    Ok(added)
}

pub fn offer(
    s: &impl State,
    vault: VaultId,
    device: &DeviceId,
    addr: Option<Addr>,
) -> Result<Vec<u8>, Error> {
    let held = s
        .vaults()
        .find(|v| v.id() == vault)
        .ok_or(Error::VaultNotHeld)?;
    can_invite(held, &s.device_id(), device)?;
    Ok(serde_json::to_vec(&Offer {
        v: 2,
        vault: vault.to_string(),
        vault_name: held.name().into(),
        name: s.device_name().into(),
        addr,
    })?)
}

pub fn read_offer(bytes: &[u8]) -> Result<(Offer, VaultId), Error> {
    let offer: Offer = serde_json::from_slice(bytes)?;
    if offer.v != 2 {
        return Err(Error::Protocol("unsupported pairing envelope"));
    }
    if !valid_name(&offer.vault_name) {
        return Err(Error::Protocol("invalid vault name"));
    }
    let vault = VaultId::from_bytes(unhex(&offer.vault)?);
    Ok((offer, vault))
}

pub fn join_blob(
    secret: &DeviceSecret,
    name: &str,
    inviter: DeviceId,
    vault: &VaultId,
    addr: Option<Addr>,
) -> Result<Vec<u8>, Error> {
    Ok(serde_json::to_vec(&JoinBlob {
        v: 2,
        consent: HEXLOWER.encode(secret.join_consent(vault, &inviter).as_bytes()),
        name: name.into(),
        addr,
    })?)
}

/// Check both before offering and again at admission, since membership may
/// change while the pairing proof is in flight.
pub fn can_invite(vault: &Vault, inviter: &DeviceId, device: &DeviceId) -> Result<(), Error> {
    if !vault.is_member(inviter) {
        return Err(Error::NotMember(vault.name().into()));
    }
    if vault.was_removed(device) {
        return Err(Error::Removed(vault.name().into()));
    }
    Ok(())
}

/// Durably admit before sending secrets. Retrying an interrupted join returns
/// the same vault without another Add; a removed device can never rejoin.
pub fn welcome<S: State>(
    s: &mut S,
    vault: VaultId,
    device: DeviceId,
    bytes: &[u8],
    fallback_addr: Option<Addr>,
) -> Result<OutgoingHistory, S::Error> {
    let join: JoinBlob = serde_json::from_slice(bytes).map_err(Error::from)?;
    if join.v != 2 {
        return Err(Error::Protocol("unsupported pairing envelope").into());
    }
    let consent = Signature::from_bytes(unhex(&join.consent)?);
    let add = {
        let held = s
            .vaults()
            .find(|v| v.id() == vault)
            .ok_or(Error::VaultNotHeld)?;
        can_invite(held, &s.device_id(), &device)?;
        !held.is_member(&device)
    };
    if add {
        s.update(vault, |v, secret| Ok(v.add(secret, device, consent)?))?;
    }
    s.learn(
        &device,
        &join.name,
        join.addr.or(fallback_addr),
        BTreeMap::new(),
    )?;
    let meta = Blob::new(
        serde_json::to_vec(&WelcomeMeta {
            v: 2,
            peers: s.hints_for(&device),
        })
        .map_err(Error::from)?,
    );
    let held = s
        .vaults()
        .find(|v| v.id() == vault)
        .ok_or(Error::VaultNotHeld)?;
    let logs = [Log::Membership, Log::Data]
        .into_iter()
        .map(|log| (vault, held.missing_log(&Heads::default(), log)))
        .collect();
    Ok(OutgoingHistory {
        peer: device,
        meta: Some(meta),
        logs,
        scope: HistoryScope::Pairing,
    })
}

/// Validated but not stored, so a fresh device can wait for its passphrase.
pub struct Welcomed {
    pub vault: Vault,
    pub inviter: DeviceId,
    pub inviter_name: String,
    pub inviter_addr: Option<Addr>,
    pub peers: BTreeMap<String, Hint>,
}

/// Private replay until DONE. A cut, invalid signature/dependency, wrong
/// offered vault or missing final admission cannot publish a partial vault.
#[derive(Default)]
pub struct WelcomeReplay {
    meta: Option<WelcomeMeta>,
    vault: Option<Vault>,
}

impl crate::WelcomeSink for WelcomeReplay {
    fn push(&mut self, blob: Blob) -> Result<(), crate::HandlerError> {
        if self.meta.is_none() {
            let meta: WelcomeMeta = serde_json::from_slice(&blob)?;
            if meta.v != 2 {
                return Err(Error::Protocol("unsupported pairing envelope").into());
            }
            self.meta = Some(meta);
        } else {
            let entry = Entry::decode(&blob)?;
            if let Some(vault) = &mut self.vault {
                vault.apply(entry)?;
            } else {
                self.vault = Some(Vault::from_genesis(entry)?);
            }
        }
        Ok(())
    }
}

pub fn verify_welcome(
    device: &DeviceId,
    inviter: DeviceId,
    offer: Offer,
    welcome: WelcomeReplay,
) -> Result<Welcomed, Error> {
    let meta = welcome.meta.ok_or(Error::Protocol("empty welcome"))?;
    let vault = welcome.vault.ok_or(deadbolt_core::Error::InvalidGenesis)?;
    if vault.id().to_string() != offer.vault {
        return Err(Error::Protocol("the welcome is for another vault"));
    }
    if !vault.is_member(device) || !vault.is_member(&inviter) {
        return Err(Error::Protocol("the welcome does not admit this device"));
    }
    Ok(Welcomed {
        vault,
        inviter,
        inviter_name: offer.name,
        inviter_addr: offer.addr,
        peers: meta.peers,
    })
}

#[cfg(test)]
mod contact_tests {
    use super::*;
    use n0_future::time::timeout;
    use std::{cell::Cell, convert::Infallible, future::pending};

    fn peers(count: u8) -> Vec<PeerAddr> {
        (0..count).map(|id| PeerAddr::from([id; 32])).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn healthy_peer_does_not_wait_for_stalled_dials() {
        let start = Instant::now();
        let healthy = Cell::new(None);
        let healthy = &healthy;
        let completed = contact_round(
            peers(3),
            Some(start + CONTACT_TIMEOUT * 2),
            |peer, budget| async move {
                if peer.id[0] < 2 {
                    assert!(timeout(budget, pending::<()>()).await.is_err());
                } else {
                    healthy.set(Some(start.elapsed()));
                }
                Ok::<_, Infallible>(true)
            },
        )
        .await
        .unwrap();
        assert_eq!(healthy.get(), Some(Duration::ZERO));
        assert_eq!(completed.len(), 3);
        assert_eq!(start.elapsed(), CONTACT_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn ready_round_attempts_every_peer_beyond_startup_deadline() {
        let start = Instant::now();
        let active = Cell::new(0);
        let peak = Cell::new(0);
        let attempts = Cell::new(0);
        let healthy = Cell::new(None);
        let (active, peak, attempts, healthy) = (&active, &peak, &attempts, &healthy);
        // More than two full windows of stalled dials ahead of a healthy peer.
        let count = (CONTACT_CONCURRENCY * 3 + 1) as u8;
        let completed = contact_round(peers(count), None, |peer, budget| async move {
            attempts.set(attempts.get() + 1);
            active.set(active.get() + 1);
            peak.set(peak.get().max(active.get()));
            assert_eq!(budget, CONTACT_TIMEOUT);
            if peer.id[0] < count - 1 {
                assert!(timeout(budget, pending::<()>()).await.is_err());
            } else {
                healthy.set(Some(start.elapsed()));
            }
            active.set(active.get() - 1);
            Ok::<_, Infallible>(true)
        })
        .await
        .unwrap();
        assert_eq!(attempts.get(), count);
        assert_eq!(completed.len(), usize::from(count));
        assert_eq!(peak.get(), CONTACT_CONCURRENCY);
        assert_eq!(active.get(), 0);
        assert_eq!(healthy.get(), Some(CONTACT_TIMEOUT * 3));
        assert_eq!(start.elapsed(), CONTACT_TIMEOUT * 3);
    }

    #[tokio::test(start_paused = true)]
    async fn startup_budget_includes_queueing_and_bounds_last_contacts() {
        let start = Instant::now();
        let limit = CONTACT_TIMEOUT * 2;
        let attempts = Cell::new(0);
        let attempts = &attempts;
        let completed = contact_round(
            peers((CONTACT_CONCURRENCY * 4) as u8),
            Some(start + limit),
            |peer, budget| async move {
                attempts.set(attempts.get() + 1);
                // Free one slot partway through: the next contact starts early,
                // and its successor must get less than the per-peer budget.
                if peer.id[0] == 0 {
                    n0_future::time::sleep(Duration::from_secs(5)).await;
                    return Ok::<_, Infallible>(true);
                }
                assert!(timeout(budget, pending::<()>()).await.is_err());
                Ok(false) // An interrupted exchange must not complete the barrier.
            },
        )
        .await
        .unwrap();
        assert_eq!(completed, vec![[0; 32]]);
        assert_eq!(attempts.get(), CONTACT_CONCURRENCY * 2 + 1);
        assert_eq!(start.elapsed(), limit);
    }

    #[tokio::test(start_paused = true)]
    async fn error_drops_in_flight_contacts_without_starting_the_queue() {
        struct Active<'a>(&'a Cell<usize>);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() - 1);
            }
        }
        let active = Cell::new(0);
        let attempts = Cell::new(0);
        let (active, attempts) = (&active, &attempts);
        let result = contact_round(peers(10), None, |peer, budget| async move {
            active.set(active.get() + 1);
            attempts.set(attempts.get() + 1);
            let _active = Active(active);
            if usize::from(peer.id[0]) == CONTACT_CONCURRENCY - 1 {
                return Err("store failed");
            }
            assert!(timeout(budget, pending::<()>()).await.is_err());
            Ok(true)
        })
        .await;
        assert_eq!(result, Err("store failed"));
        assert_eq!(attempts.get(), CONTACT_CONCURRENCY);
        assert_eq!(active.get(), 0);
    }
}
