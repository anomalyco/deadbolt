//! The unlocked state: store, device key, vaults and the local address book.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use data_encoding::HEXLOWER;
use deadbolt_core::{DeviceId, DeviceSecret, Entry, Vault, VaultId, valid_name};
use deadbolt_net::{Node, PeerAddr, PeerId};
use deadbolt_store::{KdfParams, Unlocked};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::protocol::{DeviceInfo, VaultInfo};

const META_DEVICE_NAME: &str = "cli/device-name";
const META_VAULTS: &str = "cli/vaults";
const META_DEFAULT_VAULT: &str = "cli/default-vault";
const META_PEERS: &str = "cli/peers";

/// A device counts as online if it synced this recently.
pub const ONLINE_WINDOW_SECS: u64 = 90;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

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
    pub vaults: Vec<VaultId>,
    pub default_vault: Option<VaultId>,
    pub peers: BTreeMap<String, Peer>,
}

/// The store opened and decoded, before the network node starts.
pub struct Loaded {
    pub store: Unlocked,
    pub secret: DeviceSecret,
    pub meta: Meta,
    pub vaults: BTreeMap<VaultId, Vault>,
}

fn get_json<T: DeserializeOwned>(store: &Unlocked, name: &str) -> Result<Option<T>> {
    store
        .meta_get(name)?
        .map(|bytes| serde_json::from_slice(&bytes).with_context(|| format!("reading {name}")))
        .transpose()
}

fn set_json<T: Serialize>(store: &Unlocked, name: &str, value: &T) -> Result<()> {
    store.meta_set(name, &serde_json::to_vec(value)?)?;
    Ok(())
}

impl Loaded {
    /// Creates the device key and store. Blocking (Argon2).
    pub fn setup(dir: &Path, passphrase: &[u8], device_name: &str) -> Result<Self> {
        let secret = DeviceSecret::generate();
        let params = match std::env::var("DEADBOLT_KDF").as_deref() {
            // Hidden, for tests only.
            Ok("fast") => KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
            _ => KdfParams::DEFAULT,
        };
        let store = deadbolt_store::init_with_params(dir, passphrase, *secret.to_bytes(), params)?;
        let meta = Meta {
            device_name: device_name.into(),
            ..Meta::default()
        };
        let loaded = Self {
            store,
            secret,
            meta,
            vaults: BTreeMap::new(),
        };
        save_meta(&loaded.store, &loaded.meta)?;
        Ok(loaded)
    }

    /// Unlocks the store and rebuilds every vault. Blocking (Argon2).
    pub fn open(dir: &Path, passphrase: &[u8]) -> Result<Self> {
        let store = deadbolt_store::unlock(dir, passphrase)?;
        let secret = DeviceSecret::from_bytes(store.device_secret());
        let vault_ids: Vec<String> = get_json(&store, META_VAULTS)?.unwrap_or_default();
        let default: Option<String> = get_json(&store, META_DEFAULT_VAULT)?;
        let meta = Meta {
            device_name: get_json(&store, META_DEVICE_NAME)?.unwrap_or_default(),
            vaults: vault_ids
                .iter()
                .map(|id| unhex(id).map(VaultId::from_bytes))
                .collect::<Result<_>>()?,
            default_vault: default
                .map(|id| unhex(&id).map(VaultId::from_bytes))
                .transpose()?,
            peers: get_json(&store, META_PEERS)?.unwrap_or_default(),
        };
        let mut grouped: HashMap<VaultId, Vec<Entry>> = HashMap::new();
        for item in store.iter_all()? {
            let (_, bytes) = item?;
            let entry = Entry::decode(&bytes).context("decoding a stored entry")?;
            grouped.entry(entry.vault()).or_default().push(entry);
        }
        let mut vaults = BTreeMap::new();
        for id in &meta.vaults {
            let entries = grouped.remove(id).unwrap_or_default();
            let vault = Vault::load(entries).with_context(|| format!("loading vault {id}"))?;
            vaults.insert(*id, vault);
        }
        Ok(Self {
            store,
            secret,
            meta,
            vaults,
        })
    }
}

fn save_meta(store: &Unlocked, meta: &Meta) -> Result<()> {
    set_json(store, META_DEVICE_NAME, &meta.device_name)?;
    let ids: Vec<String> = meta.vaults.iter().map(|id| id.to_string()).collect();
    set_json(store, META_VAULTS, &ids)?;
    set_json(
        store,
        META_DEFAULT_VAULT,
        &meta.default_vault.map(|id| id.to_string()),
    )?;
    set_json(store, META_PEERS, &meta.peers)
}

pub struct Session {
    pub store: Unlocked,
    pub secret: DeviceSecret,
    pub id: DeviceId,
    pub meta: Meta,
    pub vaults: BTreeMap<VaultId, Vault>,
    pub node: Node,
}

impl Session {
    pub fn new(loaded: Loaded, node: Node) -> Self {
        let id = loaded.secret.device_id();
        Self {
            store: loaded.store,
            secret: loaded.secret,
            id,
            meta: loaded.meta,
            vaults: loaded.vaults,
            node,
        }
    }

    pub fn save_vaults(&self) -> Result<()> {
        save_meta(&self.store, &self.meta)
    }

    pub fn save_peers(&self) -> Result<()> {
        set_json(&self.store, META_PEERS, &self.meta.peers)
    }

    /// Persists entries that were just applied to a vault.
    pub fn persist(&self, entries: &[Entry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let encoded: Vec<([u8; 32], Vec<u8>)> = entries
            .iter()
            .map(|e| (*e.hash().as_bytes(), e.encode()))
            .collect();
        self.store
            .append_batch(encoded.iter().map(|(hash, bytes)| (hash, bytes.as_slice())))?;
        Ok(())
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

    pub fn own_addr(&self) -> Addr {
        Addr::from_peer(&self.node.addr())
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
            return match self.meta.vaults.as_slice() {
                [] => bail!(
                    "no vaults yet; create one with `deadbolt init` or join one with `deadbolt join`"
                ),
                [only] => Ok(*only),
                _ => bail!("no default vault; pick one with --vault or `deadbolt vault default`"),
            };
        };
        let by_name: Vec<VaultId> = self
            .meta
            .vaults
            .iter()
            .filter(|id| self.vaults[id].name() == query)
            .copied()
            .collect();
        let matches = if by_name.is_empty() && query.len() >= 4 {
            self.meta
                .vaults
                .iter()
                .filter(|id| id.to_string().starts_with(query))
                .copied()
                .collect()
        } else {
            by_name
        };
        match matches.as_slice() {
            [id] => Ok(*id),
            [] => bail!("no vault named {query}"),
            _ => bail!("{query} matches several vaults; use the vault id"),
        }
    }

    pub fn vault(&self, id: &VaultId) -> &Vault {
        &self.vaults[id]
    }

    pub fn name_taken(&self, name: &str, except: Option<VaultId>) -> bool {
        self.vaults
            .iter()
            .any(|(id, vault)| Some(*id) != except && vault.name() == name)
    }

    /// Adds a vault this device just created or joined.
    pub fn add_vault(&mut self, vault: Vault, entries: &[Entry]) -> Result<()> {
        let id = vault.id();
        if self.vaults.contains_key(&id) {
            bail!("this device already holds vault {}", vault.name());
        }
        self.persist(entries)?;
        self.vaults.insert(id, vault);
        self.meta.vaults.push(id);
        if self.meta.default_vault.is_none() {
            self.meta.default_vault = Some(id);
        }
        self.save_vaults()
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
        let (vault, genesis) = Vault::create(&self.secret, name)?;
        let id = vault.id();
        self.add_vault(vault, &[genesis])?;
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
        self.meta
            .vaults
            .iter()
            .map(|id| self.vault_info(id))
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
        let members: Vec<DeviceId> = self.vaults[vault].members().collect();
        let by_name: Vec<DeviceId> = members
            .iter()
            .filter(|id| {
                let name = if **id == self.id {
                    Some(self.meta.device_name.as_str())
                } else {
                    self.peer(id).and_then(|p| p.name.as_deref())
                };
                name == Some(query)
            })
            .copied()
            .collect();
        let matches = if by_name.is_empty() && query.len() >= 4 {
            let query = query.to_ascii_lowercase();
            members
                .into_iter()
                .filter(|id| id.to_string().starts_with(&query))
                .collect()
        } else {
            by_name
        };
        match matches.as_slice() {
            [id] => Ok(*id),
            [] => bail!("no device {query} in vault {}", self.vaults[vault].name()),
            _ => bail!("{query} matches several devices; use the device id"),
        }
    }
}
