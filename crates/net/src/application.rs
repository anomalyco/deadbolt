//! Vault application envelopes shared by the native and browser devices.
//!
//! Transport authenticates the peer. This module applies the vault membership
//! rules; adapters own durable transactions, address books and readiness. No
//! data is sent or accepted until the caller's membership barrier is open.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    time::Duration,
};

use data_encoding::HEXLOWER;
use deadbolt_core::v2::{DeviceKeys, Frame, FrameId, KemPublic, LogKind, NetPublic};
use deadbolt_core::{Author, DeviceId, Heads, Signature, Vault, VaultId, VaultWrite, valid_name};
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
    #[error(transparent)]
    Frame(#[from] deadbolt_core::v2::FrameError),
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

pub use deadbolt_proto::peer::{Addr, Hint, clean_name};

impl From<PeerAddr> for Addr {
    fn from(addr: PeerAddr) -> Self {
        Self {
            relay: addr.relay_url,
            direct: addr.direct_addrs,
        }
    }
}

impl PeerAddr {
    /// The address `addr` gives the device `id`.
    pub fn of(id: PeerId, addr: &Addr) -> Self {
        Self {
            id,
            relay_url: addr.relay.clone(),
            direct_addrs: addr.direct.clone(),
        }
    }
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
    /// The joiner's KEM public key, which epoch keys are wrapped to.
    pub kem: String,
    /// The joiner's transport key, for its `DeviceCard`.
    pub net: String,
    pub name: String,
    pub addr: Option<Addr>,
}

#[derive(Serialize, Deserialize)]
pub struct WelcomeMeta {
    pub v: u32,
    pub peers: BTreeMap<String, Hint>,
}

/// The only application I/O seam. `update` must validate privately, commit its
/// new frames durably, then publish them. A precommit error leaves the vault
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
        change: impl FnOnce(&mut VaultWrite<'_>, &Author) -> Result<T, Error>,
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

/// The frames one log of a vault owes a peer, chosen when the exchange
/// starts and sent in stream order. Frames are never taken out of a vault
/// once committed, so each id is still there when its turn comes.
pub struct Missing(VecDeque<FrameId>);

impl Missing {
    fn of(vault: &Vault, heads: &Heads, log: LogKind) -> Self {
        Self(
            vault
                .missing(heads, log)
                .into_iter()
                .map(Frame::id)
                .collect(),
        )
    }

    fn next(&mut self, vault: &Vault) -> Result<Option<Blob>, Error> {
        let Some(id) = self.0.pop_front() else {
            return Ok(None);
        };
        let frame = vault
            .frame(&id)
            .ok_or(Error::Protocol("a selected frame is gone"))?;
        Ok(Some(Blob::new(frame.encode())))
    }
}

/// Snapshot selection is made under the state lock. A pull reacquires that
/// lock only long enough to check current authority and encode one frame.
pub struct OutgoingHistory {
    peer: DeviceId,
    meta: Option<Blob>,
    logs: VecDeque<(VaultId, Missing)>,
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
            if let Some(frame) = cursor.next(v)? {
                return Ok(Some(frame));
            }
            self.logs.pop_front();
        }
        Ok(None)
    }

    // Slow path under the same state lock as next(). Drop *both* phases of
    // each revoked vault, even if later membership resolution changes again.
    // A missing vault or unexplained loss of admission isn't proof of
    // removal; leave those errors fatal.
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
                removed.insert(v.id(), ());
            }
        }
        if held != negotiated.len() {
            return Err(Error::VaultNotHeld);
        }
        if held == removed.len() {
            return Err(denied()); // No other negotiated vault still admits the peer.
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
        logs.push_back((id, Missing::of(vault, &heads, LogKind::Member)));
        if ready {
            data.push((id, Missing::of(vault, &heads, LogKind::Data)));
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

/// One incoming frame stream's memory across its batches: the vaults whose
/// removal of the peer this stream delivered. The sync protocol commits a
/// stream in prefix batches (1, 2, 4, ... frames), so the removal and the
/// data written before it usually arrive in different batches. Keep one per
/// stream, never per peer or across streams.
#[derive(Debug, Default)]
pub struct ReceiveStream {
    removed: BTreeSet<VaultId>,
}

/// Skip malformed frames, not the valid removals beside them, and commit
/// independently per vault.
///
/// Data relayed by a peer the vault no longer admits is dropped, with one
/// exception: the stream that delivers the peer's own removal may still bring
/// data, in that batch or a later one of the same stream. Which of it counts
/// is the fold's call (a removal names the last of the device's frames that
/// does), so data the peer wrote after its removal never counts. Every later
/// stream from it is refused.
pub fn receive<S: State>(
    s: &mut S,
    peer: &DeviceId,
    entries: Vec<Blob>,
    ready: bool,
    stream: &mut ReceiveStream,
) -> Result<usize, S::Error> {
    let mut grouped: BTreeMap<VaultId, Vec<Frame>> = BTreeMap::new();
    for bytes in entries {
        let frame = match Frame::decode(&bytes) {
            Ok(frame) => frame,
            Err(error) => {
                warn!(peer = %peer, "undecodable frame: {error}");
                continue;
            }
        };
        let h = frame.header();
        let data = h.kind.log_kind() == LogKind::Data;
        if !s.vaults().any(|v| v.id() == h.vault) || (data && !ready) {
            continue;
        }
        grouped.entry(h.vault).or_default().push(frame);
    }
    let mut added = 0;
    for (id, frames) in grouped {
        let removed_here = stream.removed.contains(&id);
        let (count, removed) = s.update(id, |vault, author| {
            let kem = author.keys().kem_key();
            let before = vault.is_member(peer);
            let (members, data): (Vec<Frame>, Vec<Frame>) = frames
                .into_iter()
                .partition(|f| f.header().kind.log_kind() == LogKind::Member);
            let mut added = match vault.apply(kem, members) {
                Ok(n) => n,
                Err(error) => {
                    debug!(peer = %peer, "rejected frames: {error}");
                    0
                }
            };
            let removed = before && !vault.is_member(peer);
            if vault.is_member(peer) || removed || removed_here {
                match vault.apply(kem, data) {
                    Ok(n) => added += n,
                    Err(error) => debug!(peer = %peer, "rejected frames: {error}"),
                }
            }
            // What arrived may leave a member without a key it needs (rule
            // E6): rewrap it in the same commit.
            if added > 0
                && let Err(error) = vault.fulfill_reader_duty(author)
            {
                debug!(peer = %peer, "reader duty: {error}");
            }
            Ok((added, removed))
        })?;
        added += count;
        if removed {
            stream.removed.insert(id);
        }
    }
    s.received(peer)?;
    if added > 0 {
        info!(peer = %peer, frames = added, "received");
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
    keys: &DeviceKeys,
    name: &str,
    inviter: DeviceId,
    vault: &VaultId,
    addr: Option<Addr>,
) -> Result<Vec<u8>, Error> {
    let consent =
        deadbolt_core::v2::sign_join_consent(keys.sign_key(), vault, &inviter, &keys.kem_public());
    Ok(serde_json::to_vec(&JoinBlob {
        v: 3,
        consent: HEXLOWER.encode(consent.as_bytes()),
        kem: HEXLOWER.encode(keys.kem_public().as_bytes()),
        net: HEXLOWER.encode(keys.net_public().as_bytes()),
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
    if join.v != 3 {
        return Err(Error::Protocol("unsupported pairing envelope").into());
    }
    let consent = Signature::from_bytes(unhex(&join.consent)?);
    let kem = KemPublic::from_bytes(unhex(&join.kem)?);
    let net = NetPublic::from_bytes(unhex(&join.net)?);
    let label = clean_name(&join.name);
    let add = {
        let held = s
            .vaults()
            .find(|v| v.id() == vault)
            .ok_or(Error::VaultNotHeld)?;
        can_invite(held, &s.device_id(), &device)?;
        !held.is_member(&device)
    };
    if add {
        s.update(vault, |v, author| {
            v.add(author, device, kem, consent)?;
            Ok(v.card(author, device, net, &label)?)
        })?;
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
    let logs = [LogKind::Member, LogKind::Data]
        .into_iter()
        .map(|log| (vault, Missing::of(held, &Heads::default(), log)))
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
    frames: Vec<Frame>,
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
            if self.frames.len() >= deadbolt_core::MAX_FRAMES {
                return Err(deadbolt_core::Error::TooManyFrames.into());
            }
            self.frames.push(Frame::decode(&blob).map_err(Error::from)?);
        }
        Ok(())
    }
}

pub fn verify_welcome(
    keys: &DeviceKeys,
    inviter: DeviceId,
    offer: Offer,
    welcome: WelcomeReplay,
) -> Result<Welcomed, Error> {
    let meta = welcome.meta.ok_or(Error::Protocol("empty welcome"))?;
    let device = &keys.device_id();
    let vault = Vault::open(keys, welcome.frames)?;
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
