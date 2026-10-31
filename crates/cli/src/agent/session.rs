//! The unlocked state: store, device key, vaults and the local address book.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use data_encoding::HEXLOWER;
use deadbolt_core::{
    DeviceId, DeviceSecret, Entry, MembershipOp, Payload, Vault, VaultId, VaultWrite, valid_name,
};
use deadbolt_net::application::{self, State};
pub use deadbolt_net::application::{Addr, Hint, clean_name};
use deadbolt_net::{Node, PeerAddr, PeerId};
use deadbolt_store::{KdfParams, Unlocked};
use indexmap::IndexMap;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use crate::config::now;
use crate::protocol::{DeviceInfo, ErrorCode, VaultInfo};

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

pub fn unhex<const N: usize>(text: &str) -> Result<[u8; N]> {
    HEXLOWER
        .decode(text.as_bytes())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| anyhow!("invalid id {text}"))
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
    /// Data or label edits to forward, by vault. The watcher sets alone cannot
    /// distinguish a rename from an admission, or a removal invalidating items
    /// from new item data.
    pub edits: BTreeSet<VaultId>,
    pub items: BTreeSet<VaultId>,
    pub devices: BTreeSet<VaultId>,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        !self.vaults && self.items.is_empty() && self.devices.is_empty()
    }

    /// Records entries newly committed to `vault`.
    fn committed(&mut self, vault: VaultId, entries: &[&Entry]) {
        for entry in entries {
            match entry.payload() {
                Payload::Data(_) => {
                    self.edits.insert(vault);
                    self.items.insert(vault);
                }
                Payload::Membership(MembershipOp::Rename { .. }) => {
                    self.edits.insert(vault);
                    self.vaults = true;
                }
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

/// A history retained on disk but excluded from reads, writes and sync.
pub struct UnavailableVault {
    name: String,
    /// Reserve every recorded name, including renames beyond the valid prefix.
    names: BTreeSet<String>,
    error: String,
}

/// The store opened and decoded, before the network node starts.
pub struct Loaded {
    pub store: Unlocked,
    pub secret: DeviceSecret,
    pub id: DeviceId,
    pub meta: Meta,
    pub vaults: IndexMap<VaultId, Vault>,
    pub unavailable: IndexMap<VaultId, UnavailableVault>,
    pub changes: Changes,
    pub health: super::health::State,
    /// Sticky until the store is closed and replayed; readiness cannot heal it.
    pub(super) append_uncertain: bool,
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
    pub fn ensure_usable(&self) -> Result<()> {
        if self.append_uncertain {
            return Err(super::fail(
                ErrorCode::Locked,
                "store commit outcome is uncertain; unlock again to authenticate and reload",
            ));
        }
        Ok(())
    }

    fn check_append<T>(&mut self, result: Result<T>) -> Result<T> {
        if let Some(diagnostic) = result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<deadbolt_store::Error>())
            .and_then(deadbolt_store::Error::append_diagnostic)
        {
            tracing::warn!(failure = %diagnostic, "signed-log commit unconfirmed; quarantining session; unlock to authenticate and replay");
            self.append_uncertain = true;
            // Never serve or republish the pre-commit view, including through
            // State::vaults, direct local reads, or the membership gate.
            self.vaults.clear();
            self.changes = Changes::default();
        }
        result
    }

    /// Stage and durably publish one vault mutation.
    pub fn update<T>(
        &mut self,
        id: VaultId,
        change: impl FnOnce(&mut VaultWrite<'_>, &DeviceSecret) -> Result<T>,
    ) -> Result<T> {
        self.available(id)?;
        let store = &self.store;
        let secret = &self.secret;
        let changes = &mut self.changes;
        let result = self
            .vaults
            .get_mut(&id)
            .context("vault not held")?
            .transact(
                |vault| change(vault, secret),
                |entries| {
                    persist(store, entries.iter().copied())?;
                    changes.committed(id, entries);
                    Ok(())
                },
            );
        self.check_append(result)
    }

    /// Creates the device key and store. Blocking (Argon2).
    pub fn setup(
        dir: &Path,
        passphrase: &[u8],
        device_name: &str,
        params: KdfParams,
    ) -> Result<Self> {
        Self::setup_with(
            dir,
            passphrase,
            device_name,
            params,
            DeviceSecret::generate(),
        )
    }

    /// Creates the store for an existing device key. Blocking (Argon2).
    pub fn setup_with(
        dir: &Path,
        passphrase: &[u8],
        device_name: &str,
        params: KdfParams,
        secret: DeviceSecret,
    ) -> Result<Self> {
        let store = deadbolt_store::init_with_params(dir, passphrase, *secret.to_bytes(), params)?;
        let meta = Meta {
            device_name: device_name.into(),
            ..Meta::default()
        };
        let health = super::health::State::new(&store);
        let loaded = Self {
            store,
            id: secret.device_id(),
            secret,
            meta,
            vaults: IndexMap::new(),
            unavailable: IndexMap::new(),
            changes: Changes::default(),
            health,
            append_uncertain: false,
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
        let mut unavailable = IndexMap::new();
        for (id, entries) in grouped {
            let names: BTreeSet<String> = entries
                .iter()
                .filter_map(|entry| match entry.payload() {
                    Payload::Membership(
                        MembershipOp::Create { name, .. } | MembershipOp::Rename { name },
                    ) => Some(name.clone()),
                    _ => None,
                })
                .collect();
            // Rebuild exactly as Vault::load does, retaining the last validated
            // name on failure, but never publish a partial vault for use/sync.
            let mut entries = entries.into_iter();
            let mut name = id.to_string();
            let genesis = entries.next().context("empty stored vault group")?;
            let result = Vault::from_genesis(genesis).and_then(|mut vault| {
                for entry in entries {
                    name = vault.name().to_owned();
                    vault.apply(entry)?;
                }
                Ok(vault)
            });
            match result {
                Ok(vault) => {
                    vaults.insert(id, vault);
                }
                Err(error) => {
                    tracing::warn!(vault = %id, %error, "vault unavailable; stored entries retained");
                    unavailable.insert(
                        id,
                        UnavailableVault {
                            name,
                            names,
                            error: error.to_string(),
                        },
                    );
                }
            }
        }
        let health = super::health::State::new(&store);
        Ok(Self {
            store,
            id: secret.device_id(),
            secret,
            meta,
            vaults,
            unavailable,
            changes: Changes::default(),
            health,
            append_uncertain: false,
        })
    }
}

impl State for Loaded {
    type Error = anyhow::Error;

    fn device_id(&self) -> DeviceId {
        self.id
    }
    fn device_name(&self) -> &str {
        &self.meta.device_name
    }
    fn vaults(&self) -> impl Iterator<Item = &Vault> {
        self.vaults.values()
    }
    fn hints_for(&self, peer: &DeviceId) -> BTreeMap<String, Hint> {
        self.hints_for(peer)
    }

    fn update<T>(
        &mut self,
        id: VaultId,
        change: impl FnOnce(&mut VaultWrite<'_>, &DeviceSecret) -> Result<T, application::Error>,
    ) -> Result<T> {
        self.update(id, |vault, secret| Ok(change(vault, secret)?))
    }

    fn learn(
        &mut self,
        peer: &DeviceId,
        name: &str,
        addr: Option<Addr>,
        hints: BTreeMap<String, Hint>,
    ) -> Result<()> {
        self.learn(peer, Some(name), addr, hints);
        self.save_peers()
    }

    fn received(&mut self, peer: &DeviceId) -> Result<()> {
        self.peer_mut(peer).last_seen = Some(now());
        self.save_peers()
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
    /// Locally proved designations; locking discards these and every pending read.
    pub(super) approvers: BTreeMap<VaultId, super::remote_read::Designation>,
    pub(super) sync_task: Option<super::AbortOnDrop>,
    pub(super) health_task: Option<super::AbortOnDrop>,
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
            approvers: BTreeMap::new(),
            node,
            sync_task: None,
            health_task: None,
            generated: Default::default(),
        }
    }

    /// A peer remaining in a *different* vault still passes the endpoint gate.
    /// Drop obsolete per-vault designations and cancel their pending requests.
    pub(super) fn revoke_stale_approvers(&mut self) {
        self.approvers.retain(|id, cap| {
            !self.state.append_uncertain
                && self
                    .state
                    .vaults
                    .get(id)
                    .is_some_and(|v| v.is_member(&self.state.id) && v.is_member(&cap.device))
        });
    }

    pub fn own_addr(&self) -> Addr {
        Addr::from_peer(self.node.addr())
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

    fn available(&self, id: VaultId) -> Result<VaultId> {
        self.ensure_usable()?;
        if let Some(vault) = self.unavailable.get(&id) {
            bail!(
                "vault {} ({id}) is unavailable: {}; its stored entries are retained",
                vault.name,
                vault.error
            );
        }
        Ok(id)
    }

    /// Includes histories we cannot load; never replace them with a new welcome.
    pub fn contains_vault(&self, id: &VaultId) -> bool {
        self.vaults.contains_key(id) || self.unavailable.contains_key(id)
    }

    /// Finds a vault by name or id prefix; `None` means the default vault.
    pub fn resolve(&self, vault: Option<&str>) -> Result<VaultId> {
        self.ensure_usable()?;
        let Some(query) = vault else {
            if let Some(id) = self.meta.default_vault.filter(|id| self.contains_vault(id)) {
                // Say how to move on when another vault still works.
                return self
                    .available(id)
                    .map_err(|e| match self.vaults.is_empty() {
                        true => e,
                        false => anyhow!(
                            "{e}; pick another with --vault or `deadbolt vault default <name>`"
                        ),
                    });
            }
            return match self.vaults.len() + self.unavailable.len() {
                0 => bail!(
                    "no vaults yet; create one with `deadbolt init` or join one with `deadbolt join`"
                ),
                1 => self
                    .vaults
                    .keys()
                    .chain(self.unavailable.keys())
                    .next()
                    .copied()
                    .context("no vaults")
                    .and_then(|id| self.available(id)),
                _ => bail!("no default vault; pick one with --vault or `deadbolt vault default`"),
            };
        };
        let matches = resolve_by_name_or_id(
            self.vaults
                .iter()
                .map(|(id, vault)| (*id, Some(vault.name())))
                .chain(self.unavailable.iter().flat_map(|(id, vault)| {
                    vault
                        .names
                        .iter()
                        .map(move |name| (*id, Some(name.as_str())))
                        .chain(std::iter::once((*id, Some(vault.name.as_str()))))
                })),
            query,
        );
        match matches.as_slice() {
            [id] => self.available(*id),
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
            || self
                .unavailable
                .iter()
                .any(|(id, vault)| Some(*id) != except && vault.names.contains(name))
    }

    /// Adds a vault this device just created or joined.
    pub fn add_vault(&mut self, vault: Vault) -> Result<()> {
        let id = vault.id();
        self.available(id)?;
        if self.contains_vault(&id) {
            bail!("this device already holds vault {}", vault.name());
        }
        let result = self
            .store
            .append_batch(vault.iter_entries().map(Entry::encode))
            .map(drop)
            .map_err(Into::into);
        self.check_append(result)?;
        self.vaults.insert(id, vault);
        self.changes.vaults = true;
        self.changes.items.insert(id);
        self.changes.devices.insert(id);
        if self.meta.default_vault.is_none() && self.unavailable.is_empty() {
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
            error: None,
        }
    }

    pub fn vault_infos(&self) -> Vec<VaultInfo> {
        self.vaults
            .keys()
            .map(|id| self.vault_info(id))
            .chain(self.unavailable.iter().map(|(id, vault)| VaultInfo {
                id: id.to_string(),
                name: vault.name.clone(),
                default: self.meta.default_vault == Some(*id),
                members: 0,
                member: false,
                error: Some(format!("{}; stored entries retained", vault.error)),
            }))
            .collect()
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

fn resolve_by_name_or_id<'a, T: Copy + PartialEq + std::fmt::Display>(
    candidates: impl Iterator<Item = (T, Option<&'a str>)>,
    query: &str,
) -> Vec<T> {
    let mut names = Vec::new();
    let mut prefixes = Vec::new();
    let prefix = query.to_ascii_lowercase();
    for (id, name) in candidates {
        if name == Some(query) && !names.contains(&id) {
            names.push(id);
        }
        if query.len() >= 4 && id.to_string().starts_with(&prefix) && !prefixes.contains(&id) {
            prefixes.push(id);
        }
    }
    if names.is_empty() { prefixes } else { names }
}

fn persist<'a>(store: &Unlocked, entries: impl IntoIterator<Item = &'a Entry>) -> Result<()> {
    // Seal and wipe one encoding at a time, inside the same transaction.
    store.append_batch(entries.into_iter().map(Entry::encode))?;
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    /// Real file writes and fsync, with a lost acknowledgement after the selected
    /// sync. Only synthetic stores in a test-owned temporary directory use this.
    #[derive(Debug)]
    struct LostSyncAck {
        file: redb::backends::FileBackend,
        remaining: Arc<AtomicUsize>,
    }

    impl redb::StorageBackend for LostSyncAck {
        fn len(&self) -> std::io::Result<u64> {
            self.file.len()
        }
        fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
            self.file.read(offset, out)
        }
        fn set_len(&self, len: u64) -> std::io::Result<()> {
            self.file.set_len(len)
        }
        fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
            self.file.write(offset, data)
        }
        fn sync_data(&self) -> std::io::Result<()> {
            self.file.sync_data()?;
            if self
                .remaining
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .ok()
                == Some(1)
            {
                return Err(std::io::Error::other("lost sync acknowledgement"));
            }
            Ok(())
        }
    }

    pub(crate) fn fault_store(dir: &Path, secret: [u8; 32]) -> (Loaded, Arc<AtomicUsize>) {
        let remaining = Arc::new(AtomicUsize::new(0));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join(deadbolt_store::DB_FILE))
            .unwrap();
        let store = deadbolt_store::init_with_backend(
            LostSyncAck {
                file: redb::backends::FileBackend::new(file).unwrap(),
                remaining: remaining.clone(),
            },
            b"test",
            secret,
            KdfParams {
                m_cost_kib: 8,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        (Loaded::from_unlocked(store).unwrap(), remaining)
    }

    #[test]
    fn ambiguous_append_removal_requires_replay() {
        let dir = tempfile::tempdir().unwrap();
        let (mut loaded, fault) = fault_store(dir.path(), [7; 32]);
        let id = loaded.create_vault("personal").unwrap();
        let peer = DeviceSecret::from_bytes(&[8; 32]);
        let consent = peer.join_consent(&id, &loaded.id);
        loaded
            .update(id, |v, key| Ok(v.add(key, peer.device_id(), consent)?))
            .unwrap();
        let old_heads = loaded.vault(&id).heads();
        fault.store(2, Ordering::SeqCst);
        assert!(
            loaded
                .update(id, |v, key| Ok(v.remove(key, peer.device_id())?))
                .is_err()
        );
        assert_eq!(fault.load(Ordering::SeqCst), 0);
        assert!(loaded.ensure_usable().is_err());
        assert!(loaded.resolve(None).is_err());
        assert!(loaded.held(&id).is_none());
        assert!(loaded.peer_set().is_empty());
        assert_eq!(State::vaults(&loaded).count(), 0);
        assert!(super::super::sync::hello(&loaded, &peer.device_id(), None).is_err());
        assert!(
            super::super::sync::missing_for(&mut loaded, &peer.device_id(), b"{}", true).is_err()
        );
        assert!(super::super::sync::receive(&mut loaded, &peer.device_id(), vec![], true).is_err());
        assert!(super::super::pairing::offer(&loaded, id, &peer.device_id(), None).is_err());
        assert!(loaded.create_vault("another").is_err());
        drop(loaded);
        let reopened = Loaded::open(dir.path(), b"test").unwrap();
        assert!(!reopened.vault(&id).is_member(&peer.device_id()));
        assert_ne!(reopened.vault(&id).heads(), old_heads);
    }

    #[test]
    fn quarantined_vault_reports_locked_to_clients() {
        let dir = tempfile::tempdir().unwrap();
        let (mut loaded, fault) = fault_store(dir.path(), [7; 32]);
        let id = loaded.create_vault("personal").unwrap();
        fault.store(2, Ordering::SeqCst);
        loaded
            .update(id, |v, key| Ok(v.rename(key, "changed")?))
            .unwrap_err();

        let error = loaded.resolve(None).unwrap_err();
        assert_eq!(crate::client::code(&error), Some(ErrorCode::Locked));
        assert_eq!(
            error.to_string(),
            "store commit outcome is uncertain; unlock again to authenticate and reload"
        );
    }

    #[test]
    fn ambiguous_append_item_does_not_serve_the_old_value() {
        use deadbolt_core::{DataOp, Field, FieldType};
        let dir = tempfile::tempdir().unwrap();
        let (mut loaded, fault) = fault_store(dir.path(), [7; 32]);
        let id = loaded.create_vault("personal").unwrap();
        let (item, _) = loaded
            .update(id, |v, key| {
                Ok(v.create_item(
                    key,
                    "login",
                    None,
                    [("password".into(), Field::new(FieldType::Secret, "old"))],
                )?)
            })
            .unwrap();
        fault.store(2, Ordering::SeqCst);
        let error = loaded
            .update(id, |v, key| {
                Ok(v.write(
                    key,
                    vec![DataOp::set(
                        item,
                        "password",
                        Field::new(FieldType::Secret, "new"),
                    )],
                )?)
            })
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<deadbolt_store::Error>(),
            Some(deadbolt_store::Error::AppendUncertain(_))
        ));
        assert!(loaded.resolve(None).is_err());
        assert!(loaded.held(&id).is_none());
        drop(loaded);
        let reopened = Loaded::open(dir.path(), b"test").unwrap();
        assert_eq!(
            reopened.vault(&id).item(&item).unwrap().fields["password"]
                .value
                .as_str(),
            "new"
        );
    }

    #[test]
    fn ambiguous_append_pairing_never_returns_a_welcome_or_publishes_an_adoption() {
        use super::super::pairing;
        let inviter_dir = tempfile::tempdir().unwrap();
        let joiner_dir = tempfile::tempdir().unwrap();
        let (mut inviter, fault) = fault_store(inviter_dir.path(), [7; 32]);
        let id = inviter.create_vault("personal").unwrap();
        let peer = DeviceSecret::from_bytes(&[8; 32]);
        let offer =
            pairing::read_offer(&pairing::offer(&inviter, id, &peer.device_id(), None).unwrap())
                .unwrap()
                .0;
        let join = pairing::join_blob(&peer, "peer", inviter.id, &id, None).unwrap();
        fault.store(2, Ordering::SeqCst);
        assert!(pairing::welcome(&mut inviter, id, peer.device_id(), &join, None).is_err());
        assert!(inviter.ensure_usable().is_err());
        drop(inviter);
        let mut inviter = Loaded::open(inviter_dir.path(), b"test").unwrap();
        assert!(inviter.vault(&id).is_member(&peer.device_id()));
        let (welcome, _) =
            pairing::welcome(&mut inviter, id, peer.device_id(), &join, None).unwrap();
        let welcomed = pairing::verify_welcome(
            &peer.device_id(),
            inviter.id,
            offer,
            pairing::test_replay(&inviter, welcome),
        )
        .unwrap();
        let (mut joiner, fault) = fault_store(joiner_dir.path(), [8; 32]);
        // Adopt is already past signature/identity validation; its store append
        // must fail closed regardless of whether this is the first held vault.
        fault.store(2, Ordering::SeqCst);
        assert!(pairing::adopt(&mut joiner, welcomed).is_err());
        assert!(joiner.ensure_usable().is_err());
        assert!(joiner.held(&id).is_none());
        assert!(joiner.create_vault("personal").is_err());
        drop(joiner);
        let reopened = Loaded::open(joiner_dir.path(), b"test").unwrap();
        assert!(reopened.held(&id).is_some());
    }

    #[test]
    fn validation_failure_does_not_poison_or_attempt_an_append() {
        let dir = tempfile::tempdir().unwrap();
        let (mut loaded, fault) = fault_store(dir.path(), [7; 32]);
        let id = loaded.create_vault("personal").unwrap();
        let heads = loaded.vault(&id).heads();
        fault.store(2, Ordering::SeqCst);
        assert!(
            loaded
                .update(id, |v, key| -> Result<()> {
                    v.rename(key, "staged")?;
                    bail!("validation rejected the command")
                })
                .is_err()
        );
        assert_eq!(fault.load(Ordering::SeqCst), 2);
        assert_eq!(loaded.vault(&id).heads(), heads);
        loaded.ensure_usable().unwrap();
        fault.store(0, Ordering::SeqCst);
        loaded
            .update(id, |v, key| Ok(v.rename(key, "accepted")?))
            .unwrap();
    }

    #[test]
    fn an_over_budget_history_is_visible_and_isolated_without_losing_entries() {
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
        let bad = loaded.create_vault("personal").unwrap();
        let genesis = loaded.vault(&bad).entries()[0].clone();
        let mut prev = genesis.hash();
        let mut flood = Vec::new();
        for seq in 1..=deadbolt_core::MAX_MEMBERSHIP_ENTRIES {
            let entry = Entry::sign(
                &loaded.secret,
                bad,
                seq,
                [prev],
                Payload::Membership(MembershipOp::Rename {
                    name: if seq == deadbolt_core::MAX_MEMBERSHIP_ENTRIES {
                        "postlimit"
                    } else {
                        "renamed"
                    }
                    .into(),
                }),
            );
            prev = entry.hash();
            flood.push(entry.encode());
        }
        loaded
            .store
            .append_batch(flood.iter().map(|b| b.as_slice()))
            .unwrap();
        let stored = |s: &Loaded| {
            s.store
                .iter_all()
                .unwrap()
                .map(|bytes| Entry::decode(&bytes.unwrap()).unwrap())
                .filter(|entry| entry.vault() == bad)
                .map(|entry| entry.encode())
                .collect::<Vec<_>>()
        };
        let before = stored(&loaded);
        drop(loaded);

        let mut loaded = Loaded::open(dir.path(), b"test").unwrap();
        assert!(loaded.vaults.is_empty());
        assert_eq!(loaded.unavailable.len(), 1);
        assert_eq!(loaded.vault_infos().len(), 1);
        assert!(
            loaded
                .resolve(None)
                .unwrap_err()
                .to_string()
                .contains("unavailable")
        );
        let good = loaded.create_vault("healthy").unwrap();
        assert_eq!(loaded.vaults.len(), 1);
        assert!(loaded.contains_vault(&bad));
        assert!(loaded.held(&bad).is_none());
        let infos = loaded.vault_infos();
        let info = infos.iter().find(|v| v.id == bad.to_string()).unwrap();
        assert!(info.default);
        assert_eq!(info.name, "renamed");
        assert!(info.error.as_ref().unwrap().contains("1000 non-removal"));
        let error = loaded.resolve(None).unwrap_err().to_string();
        assert!(error.contains("unavailable"));
        assert!(error.contains("`deadbolt vault default <name>`"), "{error}");
        for query in [
            "personal",
            "renamed",
            "postlimit",
            &bad.to_string(),
            &bad.to_string()[..8],
        ] {
            assert!(
                loaded
                    .resolve(Some(query))
                    .unwrap_err()
                    .to_string()
                    .contains("unavailable")
            );
        }
        for name in ["personal", "renamed", "postlimit"] {
            assert!(loaded.create_vault(name).is_err());
        }
        assert!(
            loaded
                .add_vault(Vault::from_genesis(genesis).unwrap())
                .is_err()
        );
        assert!(
            loaded
                .update(bad, |v, key| Ok(v.rename(key, "replacement")?))
                .is_err()
        );
        assert_eq!(loaded.resolve(Some("healthy")).unwrap(), good);
        loaded
            .update(good, |v, key| {
                Ok(v.create_item(key, "login", Some("working".into()), [])?)
            })
            .unwrap();
        assert_eq!(loaded.vault(&good).items().len(), 1);
        assert_eq!(stored(&loaded), before);

        // No implicit fallback when an unavailable history is the default or
        // when default metadata is missing. Explicitly choosing healthy works.
        loaded.meta.default_vault = None;
        assert!(loaded.resolve(None).is_err());
        loaded.create_vault("new-vault").unwrap();
        assert_eq!(loaded.meta.default_vault, None);
        assert!(loaded.resolve(None).is_err());
        loaded.meta.default_vault = Some(good);
        loaded.save_meta().unwrap();
        drop(loaded);
        let loaded = Loaded::open(dir.path(), b"test").unwrap();
        assert_eq!(loaded.resolve(None).unwrap(), good);
        assert_eq!(loaded.vault(&good).items().len(), 1);
        assert_eq!(stored(&loaded), before);
        assert_eq!(loaded.vault_infos().len(), 3);
    }

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
        let result = vault.transact(
            |v| Ok(v.rename(&secret, "lost")?),
            |_| bail!("injected disk full"),
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
