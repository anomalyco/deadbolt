//! Vault application envelopes shared by the native and browser devices.
//!
//! Transport authenticates the peer. This module applies the vault membership
//! rules; adapters own durable transactions, address books and readiness. No
//! data is sent or accepted until the caller's membership barrier is open.

use std::{collections::BTreeMap, net::SocketAddr};

use data_encoding::HEXLOWER;
use deadbolt_core::{
    DeviceId, DeviceSecret, Entry, Heads, Log, Signature, Vault, VaultId, valid_name,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::{Blob, PeerAddr, PeerId};

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

/// The only application I/O seam. `update` must stage a private vault, commit
/// its new entries durably, then publish it. A failed commit must not change
/// the live vault. Callers must enforce membership even when a later update
/// or address-book write fails: an earlier vault may already have committed.
pub trait State {
    type Error: From<Error>;

    fn device_id(&self) -> DeviceId;
    fn device_name(&self) -> &str;
    fn vaults(&self) -> impl Iterator<Item = &Vault>;
    fn hints_for(&self, peer: &DeviceId) -> BTreeMap<String, Hint>;
    fn update<T>(
        &mut self,
        id: VaultId,
        change: impl FnOnce(&mut Vault, &DeviceSecret) -> Result<T, Error>,
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

pub fn missing_for<S: State>(
    s: &mut S,
    peer: &DeviceId,
    bytes: &[u8],
    ready: bool,
) -> Result<Vec<Blob>, S::Error> {
    let hello: Hello = serde_json::from_slice(bytes).map_err(Error::from)?;
    if hello.v != 1 {
        return Err(Error::Protocol("unsupported sync envelope").into());
    }
    s.learn(peer, &hello.name, hello.addr, hello.peers)?;
    let mut membership = Vec::new();
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
        for entry in vault.missing_for(&heads) {
            match entry.log() {
                Log::Membership => membership.push(entry.encode()),
                Log::Data if ready => data.push(entry.encode()),
                Log::Data => {}
            }
        }
    }
    membership.append(&mut data);
    Ok(membership)
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

pub fn offer(s: &impl State, vault: VaultId, addr: Option<Addr>) -> Result<Vec<u8>, Error> {
    let held = s
        .vaults()
        .find(|v| v.id() == vault)
        .ok_or(Error::VaultNotHeld)?;
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
) -> Result<Vec<Blob>, S::Error> {
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
    let mut blobs = vec![Blob::new(
        serde_json::to_vec(&WelcomeMeta {
            v: 2,
            peers: s.hints_for(&device),
        })
        .map_err(Error::from)?,
    )];
    let held = s
        .vaults()
        .find(|v| v.id() == vault)
        .ok_or(Error::VaultNotHeld)?;
    blobs.extend(held.entries().into_iter().map(Entry::encode));
    Ok(blobs)
}

/// Validated but not stored, so a fresh device can wait for its passphrase.
pub struct Welcomed {
    pub vault: Vault,
    pub inviter: DeviceId,
    pub inviter_name: String,
    pub inviter_addr: Option<Addr>,
    pub peers: BTreeMap<String, Hint>,
}

pub fn verify_welcome(
    device: &DeviceId,
    inviter: DeviceId,
    offer: Offer,
    welcome: Vec<Blob>,
) -> Result<Welcomed, Error> {
    let mut blobs = welcome.into_iter();
    let meta: WelcomeMeta =
        serde_json::from_slice(&blobs.next().ok_or(Error::Protocol("empty welcome"))?)?;
    if meta.v != 2 {
        return Err(Error::Protocol("unsupported pairing envelope"));
    }
    let entries: Vec<Entry> = blobs
        .map(|bytes| Entry::decode(&bytes))
        .collect::<Result<_, _>>()?;
    let vault = Vault::load(entries)?;
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
