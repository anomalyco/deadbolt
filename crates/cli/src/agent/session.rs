//! The unlocked state: store, device key, vaults and the local address book.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use data_encoding::HEXLOWER;
use deadbolt_core::{
    DeviceId, DeviceSecret, Entry, MembershipOp, Payload, Vault, VaultId, valid_name,
};
use deadbolt_net::{Node, PeerAddr, PeerId};
use deadbolt_store::{KdfParams, Unlocked};
use indexmap::IndexMap;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use crate::config::now;
use crate::protocol::{DeviceInfo, VaultInfo};

const META_DEVICE_NAME: &str = "cli/device-name";
const META_DEFAULT_VAULT: &str = "cli/default-vault";
const META_PEERS: &str = "cli/peers";
const META_FILLED: &str = "cli/autofill-filled";
/// The most logins whose last fill is remembered; the longest unused go first.
const MAX_FILLED: usize = 1000;

/// A device counts as online if it synced this recently.
pub const ONLINE_WINDOW_SECS: u64 = 90;

pub fn hex(bytes: &[u8]) -> String {
    HEXLOWER.encode(bytes)
}

pub fn short(bytes: &[u8]) -> String {
    hex(&bytes[..4])
}

pub fn unhex<const N: usize>(text: &str) -> Result<[u8; N]> {
    HEXLOWER
        .decode(text.as_bytes())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| anyhow!("invalid id {text}"))
}

/// Device names are free text shown to people: trimmed, no control
/// characters, at most 64 characters.
pub fn clean_name(name: &str) -> String {
    name.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect()
}

/// How to reach a device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Addr {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct: Vec<SocketAddr>,
}

impl Addr {
    pub fn from_peer(addr: &PeerAddr) -> Self {
        Self {
            relay: addr.relay_url.clone(),
            direct: addr.direct_addrs.clone(),
        }
    }
}

/// What this device knows about another device. Names and addresses are
/// local knowledge, learned at pairing and gossiped during sync; they are
/// not part of the signed vault log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Peer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<Addr>,
    /// Unix seconds when the address was last heard from the device itself.
    #[serde(default)]
    pub addr_seen: u64,
    /// Unix seconds of the last completed sync session with this device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<u64>,
}

/// A peer hint as gossiped to other devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hint {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub addr: Option<Addr>,
    #[serde(default)]
    pub addr_seen: u64,
}

#[derive(Debug, Default)]
pub struct Meta {
    pub device_name: String,
    pub default_vault: Option<VaultId>,
    pub peers: BTreeMap<String, Peer>,
}

/// What changed since the agent last told its watchers. Recorded where
/// changes become durable, so local writes, sync and pairing all report.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Changes {
    pub vaults: bool,
    pub items: BTreeSet<VaultId>,
    pub devices: BTreeSet<VaultId>,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        !self.vaults && self.items.is_empty() && self.devices.is_empty()
    }

    /// Records entries newly committed to `vault`.
    fn committed(&mut self, vault: VaultId, entries: &[Entry]) {
        for entry in entries {
            match entry.payload() {
                Payload::Data(_) => {
                    self.items.insert(vault);
                }
                Payload::Membership(MembershipOp::Rename { .. }) => self.vaults = true,
                Payload::Membership(op) => {
                    self.vaults = true;
                    self.devices.insert(vault);
                    // A removed device's later writes stop counting.
                    if matches!(op, MembershipOp::Remove { .. }) {
                        self.items.insert(vault);
                    }
                }
            }
        }
    }
}

/// The store opened and decoded, before the network node starts.
pub struct Loaded {
    pub store: Unlocked,
    pub secret: DeviceSecret,
    pub id: DeviceId,
    pub meta: Meta,
    pub vaults: IndexMap<VaultId, Vault>,
    pub changes: Changes,
}

pub(super) fn get_json<T: DeserializeOwned>(store: &Unlocked, name: &str) -> Result<Option<T>> {
    store
        .meta_get(name)?
        .map(|bytes| serde_json::from_slice(&bytes).with_context(|| format!("reading {name}")))
        .transpose()
}

pub(super) fn set_json<T: Serialize>(store: &Unlocked, name: &str, value: &T) -> Result<()> {
    store.meta_set(name, &serde_json::to_vec(value)?)?;
    Ok(())
}

impl Loaded {
    /// Stage and durably publish one vault mutation.
    pub fn update<T>(
        &mut self,
        id: VaultId,
        change: impl FnOnce(&mut Vault, &DeviceSecret) -> Result<T>,
    ) -> Result<T> {
        let store = &self.store;
        let secret = &self.secret;
        let changes = &mut self.changes;
        update(
            self.vaults.get_mut(&id).context("vault not held")?,
            |entries| {
                persist(store, entries)?;
                changes.committed(id, entries);
                Ok(())
            },
            |vault| change(vault, secret),
        )
    }

    /// Creates the device key and store. Blocking (Argon2).
    pub fn setup(
        dir: &Path,
        passphrase: &[u8],
        device_name: &str,
        params: KdfParams,
    ) -> Result<Self> {
        let secret = DeviceSecret::generate();
        let store = deadbolt_store::init_with_params(dir, passphrase, *secret.to_bytes(), params)?;
        let meta = Meta {
            device_name: device_name.into(),
            ..Meta::default()
        };
        let loaded = Self {
            store,
            id: secret.device_id(),
            secret,
            meta,
            vaults: IndexMap::new(),
            changes: Changes::default(),
        };
        save_meta(&loaded.store, &loaded.meta)?;
        Ok(loaded)
    }

    /// Unlocks the store and rebuilds every vault. Blocking (Argon2).
    pub fn open(dir: &Path, passphrase: &[u8]) -> Result<Self> {
        let store = deadbolt_store::unlock(dir, passphrase)?;
        Self::from_unlocked(store)
    }

    /// Rebuilds every vault from an already-unlocked store.
    pub fn from_unlocked(store: Unlocked) -> Result<Self> {
        let secret = DeviceSecret::from_bytes(store.device_secret());
        // Setup stores `null` until the first vault exists.
        let default: Option<String> =
            get_json::<Option<String>>(&store, META_DEFAULT_VAULT)?.flatten();
        let meta = Meta {
            device_name: get_json(&store, META_DEVICE_NAME)?.unwrap_or_default(),
            default_vault: default
                .map(|id| unhex(&id).map(VaultId::from_bytes))
                .transpose()?,
            peers: get_json(&store, META_PEERS)?.unwrap_or_default(),
        };
        let mut grouped: IndexMap<VaultId, Vec<Entry>> = IndexMap::new();
        for item in store.iter_all()? {
            let bytes = item?;
            let entry = Entry::decode(&bytes).context("decoding a stored entry")?;
            grouped.entry(entry.vault()).or_default().push(entry);
        }
        let mut vaults = IndexMap::new();
        for (id, entries) in grouped {
            let vault = Vault::load(entries).with_context(|| format!("loading vault {id}"))?;
            vaults.insert(id, vault);
        }
        Ok(Self {
            store,
            id: secret.device_id(),
            secret,
            meta,
            vaults,
            changes: Changes::default(),
        })
    }
}

fn save_meta(store: &Unlocked, meta: &Meta) -> Result<()> {
    set_json(store, META_DEVICE_NAME, &meta.device_name)?;
    set_json(
        store,
        META_DEFAULT_VAULT,
        &meta.default_vault.map(|id| id.to_string()),
    )?;
    set_json(store, META_PEERS, &meta.peers)
}

pub struct Session {
    state: Loaded,
    pub node: Node,
    pub(super) sync_task: Option<super::AbortOnDrop>,
    /// Passwords made for web forms, until saved; locking drops them.
    pub generated: super::generate::Pending,
}

impl std::ops::Deref for Session {
    type Target = Loaded;
    fn deref(&self) -> &Loaded {
        &self.state
    }
}

impl std::ops::DerefMut for Session {
    fn deref_mut(&mut self) -> &mut Loaded {
        &mut self.state
    }
}

impl Session {
    pub fn new(loaded: Loaded, node: Node) -> Self {
        Self {
            state: loaded,
            node,
            sync_task: None,
            generated: Default::default(),
        }
    }

    pub fn own_addr(&self) -> Addr {
        Addr::from_peer(&self.node.addr())
    }
}

impl Loaded {
    /// Saves the device name, default vault and address book.
    pub fn save_meta(&mut self) -> Result<()> {
        save_meta(&self.store, &self.meta)?;
        self.changes.vaults = true;
        Ok(())
    }

    pub fn save_peers(&self) -> Result<()> {
        set_json(&self.store, META_PEERS, &self.meta.peers)
    }

    /// When each login was last filled into a web page, in Unix seconds, by
    /// `vault:item`. Kept on this device only, to rank a site's logins.
    pub fn filled(&self) -> BTreeMap<String, u64> {
        get_json(&self.store, META_FILLED)
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    pub fn set_filled(&self, login: String, at: u64) -> Result<()> {
        let mut filled = self.filled();
        filled.insert(login, at);
        while filled.len() > MAX_FILLED {
            let Some(oldest) = filled
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            filled.remove(&oldest);
        }
        set_json(&self.store, META_FILLED, &filled)
    }

    /// Every other device that is a member of a vault this device holds.
    pub fn peer_set(&self) -> HashSet<PeerId> {
        self.vaults
            .values()
            .flat_map(|vault| vault.members())
            .filter(|id| *id != self.id)
            .map(|id| *id.as_bytes())
            .collect()
    }

    pub fn peer(&self, id: &DeviceId) -> Option<&Peer> {
        self.meta.peers.get(&id.to_string())
    }

    pub fn peer_mut(&mut self, id: &DeviceId) -> &mut Peer {
        self.meta.peers.entry(id.to_string()).or_default()
    }

    pub fn addr_of(&self, id: &DeviceId) -> PeerAddr {
        let addr = self
            .peer(id)
            .and_then(|p| p.addr.clone())
            .unwrap_or_default();
        PeerAddr {
            id: *id.as_bytes(),
            relay_url: addr.relay,
            direct_addrs: addr.direct,
        }
    }

    /// Hints about the members of the vaults `peer` shares with this device.
    pub fn hints_for(&self, peer: &DeviceId) -> BTreeMap<String, Hint> {
        self.vaults
            .values()
            .filter(|vault| vault.is_member(peer))
            .flat_map(|vault| vault.members())
            .filter(|id| id != peer && *id != self.id)
            .filter_map(|id| {
                let p = self.peer(&id)?;
                Some((
                    id.to_string(),
                    Hint {
                        name: p.name.clone(),
                        addr: p.addr.clone(),
                        addr_seen: p.addr_seen,
                    },
                ))
            })
            .collect()
    }

    /// Records what `from` says about itself (authoritative) and about others
    /// (fills gaps; newer addresses win).
    pub fn learn(
        &mut self,
        from: &DeviceId,
        name: Option<&str>,
        addr: Option<Addr>,
        hints: BTreeMap<String, Hint>,
    ) {
        let me = self.id.to_string();
        let now = now();
        let peer = self.peer_mut(from);
        if let Some(name) = name.map(clean_name).filter(|n| !n.is_empty()) {
            peer.name = Some(name);
        }
        if let Some(addr) = addr {
            peer.addr = Some(addr);
            peer.addr_seen = now;
        }
        let from = from.to_string();
        for (id, hint) in hints.into_iter().take(256) {
            if id == me || id == from || unhex::<32>(&id).is_err() {
                continue;
            }
            let peer = self.meta.peers.entry(id).or_default();
            if peer.name.is_none() {
                peer.name = hint.name.map(|n| clean_name(&n)).filter(|n| !n.is_empty());
            }
            if hint.addr.is_some() && hint.addr_seen > peer.addr_seen {
                peer.addr = hint.addr;
                peer.addr_seen = hint.addr_seen.min(now);
            }
        }
    }

    /// Finds a vault by name or id prefix; `None` means the default vault.
    pub fn resolve(&self, vault: Option<&str>) -> Result<VaultId> {
        let Some(query) = vault else {
            if let Some(id) = self
                .meta
                .default_vault
                .filter(|id| self.vaults.contains_key(id))
            {
                return Ok(id);
            }
            return match self.vaults.len() {
                0 => bail!(
                    "no vaults yet; create one with `deadbolt init` or join one with `deadbolt join`"
                ),
                1 => self.vaults.keys().next().copied().context("no vaults"),
                _ => bail!("no default vault; pick one with --vault or `deadbolt vault default`"),
            };
        };
        let matches = resolve_by_name_or_id(
            self.vaults
                .iter()
                .map(|(id, vault)| (*id, Some(vault.name()))),
            query,
        );
        match matches.as_slice() {
            [id] => Ok(*id),
            [] => bail!("no vault named {query}"),
            _ => bail!("{query} matches several vaults; use the vault id"),
        }
    }

    pub fn vault(&self, id: &VaultId) -> &Vault {
        &self.vaults[id]
    }

    /// The vault, if still held.
    pub fn held(&self, id: &VaultId) -> Option<&Vault> {
        self.vaults.get(id)
    }

    pub fn name_taken(&self, name: &str, except: Option<VaultId>) -> bool {
        self.vaults
            .iter()
            .any(|(id, vault)| Some(*id) != except && vault.name() == name)
    }

    /// Adds a vault this device just created or joined.
    pub fn add_vault(&mut self, vault: Vault) -> Result<()> {
        let id = vault.id();
        if self.vaults.contains_key(&id) {
            bail!("this device already holds vault {}", vault.name());
        }
        persist(&self.store, vault.entries())?;
        self.vaults.insert(id, vault);
        self.changes.vaults = true;
        self.changes.items.insert(id);
        self.changes.devices.insert(id);
        if self.meta.default_vault.is_none() {
            self.meta.default_vault = Some(id);
        }
        self.save_meta()
    }

    pub fn create_vault(&mut self, name: &str) -> Result<VaultId> {
        if !valid_name(name) {
            bail!(
                "invalid vault name {name:?}: use 1-64 lowercase letters, digits, - or _, starting with a letter"
            );
        }
        if self.name_taken(name, None) {
            bail!("a vault named {name} already exists");
        }
        let (vault, _) = Vault::create(&self.secret, name)?;
        let id = vault.id();
        self.add_vault(vault)?;
        Ok(id)
    }

    pub fn vault_info(&self, id: &VaultId) -> VaultInfo {
        let vault = &self.vaults[id];
        VaultInfo {
            id: id.to_string(),
            name: vault.name().into(),
            default: self.meta.default_vault == Some(*id),
            members: vault.members().count(),
            member: vault.is_member(&self.id),
        }
    }

    pub fn vault_infos(&self) -> Vec<VaultInfo> {
        self.vaults.keys().map(|id| self.vault_info(id)).collect()
    }

    pub fn device_info(&self, id: &DeviceId, connected: &HashSet<PeerId>) -> DeviceInfo {
        if *id == self.id {
            return DeviceInfo {
                id: id.to_string(),
                name: Some(self.meta.device_name.clone()),
                this: true,
                connected: false,
                last_seen: None,
            };
        }
        let peer = self.peer(id);
        DeviceInfo {
            id: id.to_string(),
            name: peer.and_then(|p| p.name.clone()),
            this: false,
            connected: connected.contains(id.as_bytes()),
            last_seen: peer.and_then(|p| p.last_seen),
        }
    }

    pub fn online(&self, id: &PeerId, connected: &HashSet<PeerId>) -> bool {
        connected.contains(id)
            || self
                .peer(&DeviceId::from_bytes(*id))
                .and_then(|p| p.last_seen)
                .is_some_and(|seen| now().saturating_sub(seen) <= ONLINE_WINDOW_SECS)
    }

    /// Finds a member of `vault` by name or id prefix.
    pub fn resolve_device(&self, vault: &VaultId, query: &str) -> Result<DeviceId> {
        let matches = resolve_by_name_or_id(
            self.vaults[vault].members().map(|id| {
                let name = if id == self.id {
                    Some(self.meta.device_name.as_str())
                } else {
                    self.peer(&id).and_then(|p| p.name.as_deref())
                };
                (id, name)
            }),
            query,
        );
        match matches.as_slice() {
            [id] => Ok(*id),
            [] => bail!("no device {query} in vault {}", self.vaults[vault].name()),
            _ => bail!("{query} matches several devices; use the device id"),
        }
    }
}

fn resolve_by_name_or_id<'a, T: Copy + std::fmt::Display>(
    candidates: impl Iterator<Item = (T, Option<&'a str>)>,
    query: &str,
) -> Vec<T> {
    let mut names = Vec::new();
    let mut prefixes = Vec::new();
    let prefix = query.to_ascii_lowercase();
    for (id, name) in candidates {
        if name == Some(query) {
            names.push(id);
        }
        if query.len() >= 4 && id.to_string().starts_with(&prefix) {
            prefixes.push(id);
        }
    }
    if names.is_empty() { prefixes } else { names }
}

fn persist<'a>(store: &Unlocked, entries: impl IntoIterator<Item = &'a Entry>) -> Result<()> {
    // Plaintext, wiped as soon as the batch is sealed.
    let encoded: Vec<_> = entries.into_iter().map(Entry::encode).collect();
    if !encoded.is_empty() {
        store.append_batch(encoded.iter().map(|entry| entry.as_slice()))?;
    }
    Ok(())
}

pub(super) fn update<T>(
    vault: &mut Vault,
    persist: impl FnOnce(&[Entry]) -> Result<()>,
    change: impl FnOnce(&mut Vault) -> Result<T>,
) -> Result<T> {
    let heads = vault.heads();
    // Clone the validated state without re-verifying historical signatures.
    // Failed validation or I/O cannot advance the live log.
    let mut staged = vault.clone();
    let result = change(&mut staged)?;
    let entries: Vec<_> = staged.missing_for(&heads).into_iter().cloned().collect();
    persist(&entries)?;
    *vault = staged;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_and_device_prefixes_are_case_insensitive_but_names_win() {
        let dir = tempfile::tempdir().unwrap();
        let mut loaded = Loaded::setup(
            dir.path(),
            b"test",
            "device",
            KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        let id = loaded.create_vault("personal").unwrap();
        assert_eq!(
            loaded
                .resolve(Some(&id.to_string().to_uppercase()))
                .unwrap(),
            id
        );
        assert_eq!(
            loaded
                .resolve(Some(&id.to_string()[..8].to_uppercase()))
                .unwrap(),
            id
        );
        assert_eq!(
            loaded
                .resolve_device(&id, &loaded.id.to_string()[..8].to_uppercase())
                .unwrap(),
            loaded.id
        );
        assert_eq!(loaded.resolve(Some("personal")).unwrap(), id);
        assert!(loaded.resolve(Some("PERSONAL")).is_err());
        let first = VaultId::from_bytes([0xab; 32]);
        let second = VaultId::from_bytes([0xab; 32].map(|b| b + 1));
        assert_eq!(
            resolve_by_name_or_id([(first, None), (second, Some("ABAB"))].into_iter(), "ABAB"),
            vec![second]
        );
        assert!(resolve_by_name_or_id([(first, None)].into_iter(), "ABA").is_empty());
    }

    #[test]
    fn a_device_reopens_before_its_first_vault() {
        let dir = tempfile::tempdir().unwrap();
        let kdf = KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        };
        drop(Loaded::setup(dir.path(), b"test", "device", kdf).unwrap());
        let loaded = Loaded::open(dir.path(), b"test").unwrap();
        assert_eq!(loaded.meta.default_vault, None);
        assert_eq!(loaded.meta.device_name, "device");
    }

    #[test]
    fn failed_write_does_not_advance_log() {
        let secret = DeviceSecret::from_bytes(&[1; 32]);
        let (mut vault, _) = Vault::create(&secret, "test").unwrap();
        let before = vault.heads();
        let result = update(
            &mut vault,
            |_| bail!("injected disk full"),
            |v| Ok(v.rename(&secret, "lost")?),
        );
        assert!(result.is_err());
        assert_eq!(vault.heads(), before);
        assert_eq!(vault.name(), "test");
    }

    #[test]
    fn restart_discovers_vault_from_committed_log() {
        let dir = tempfile::tempdir().unwrap();
        let secret = DeviceSecret::from_bytes(&[1; 32]);
        let store = deadbolt_store::init_with_params(
            dir.path(),
            b"test",
            *secret.to_bytes(),
            KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        let (vault, genesis) = Vault::create(&secret, "test").unwrap();
        store.meta_set("cli/vaults", b"[]").unwrap();
        persist(&store, &[genesis]).unwrap();
        // Crash between committing the genesis and updating cli/vaults metadata.
        drop(store);
        let loaded = Loaded::open(dir.path(), b"test").unwrap();
        assert!(loaded.vaults.contains_key(&vault.id()));
    }
}
