//! The unlocked state: the device key, its vaults and the local address
//! book, persisted through a [`VaultStore`].

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use deadbolt_core::v2::{DeviceKeys, Frame, NetPublic, RecoverySecret};
use deadbolt_core::{Author, DeviceId, Vault, VaultId, VaultWrite, recovery, valid_name};
use deadbolt_proto::daemon::{DeviceInfo, ErrorCode, VaultInfo};
use deadbolt_proto::peer::{Addr, Hint, clean_name};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cap::{CapAudit, CapCheck, CapError, CapId, CapTable};
use crate::clock::{Clock, utc_date};
use crate::store::{VaultStore, get_json, set_json};
use crate::{fail, unhex};

const META_DEVICE_NAME: &str = "cli/device-name";
const META_DEFAULT_VAULT: &str = "cli/default-vault";
const META_PEERS: &str = "cli/peers";
const META_FILLED: &str = "cli/autofill-filled";
/// Per vault: devices this device has seen removed (the parking rule's memory).
fn meta_removed(vault: &VaultId) -> String {
    format!("vault/{vault}/removed")
}
/// The most logins whose last fill is remembered; the longest unused go first.
const MAX_FILLED: usize = 1000;

/// A device counts as online if it synced this recently.
pub const ONLINE_WINDOW_SECS: u64 = 90;

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

/// What changed since the daemon last told its watchers. Recorded where
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

    /// Records frames newly committed to `vault`.
    pub(crate) fn committed(&mut self, id: VaultId, vault: &Vault, frames: &[&Frame]) {
        for frame in frames {
            let touch = vault.touched(frame);
            if touch.items {
                self.edits.insert(id);
                self.items.insert(id);
            }
            if touch.name {
                self.edits.insert(id);
                self.vaults = true;
            }
            if touch.devices {
                self.vaults = true;
                self.devices.insert(id);
            }
        }
    }
}

/// A history retained on disk but excluded from reads, writes and sync.
/// Its name is signed into frames that don't open, so it goes by its id.
pub struct UnavailableVault {
    name: String,
    error: String,
}

/// The unlocked vaults of this device: what the daemon serves while unlocked.
/// Every change goes through [`Engine::update`], which commits it to the
/// store before anyone sees it.
pub struct Engine {
    pub(crate) store: Box<dyn VaultStore>,
    clock: Box<dyn Clock>,
    pub id: DeviceId,
    pub meta: Meta,
    pub vaults: IndexMap<VaultId, Vault>,
    pub unavailable: IndexMap<VaultId, UnavailableVault>,
    pub changes: Changes,
    /// Sticky until the store is closed and replayed; readiness cannot heal it.
    pub append_uncertain: bool,
    /// The capabilities callers hold: in memory only, wiped by [`Engine::lock`]
    /// and when the engine drops.
    pub caps: CapTable,
}

impl Engine {
    /// A new device: no vaults yet, named `device_name`.
    pub fn create(
        store: Box<dyn VaultStore>,
        clock: Box<dyn Clock>,
        device_name: &str,
    ) -> Result<Self> {
        let mut engine = Self::empty(store, clock);
        engine.meta.device_name = device_name.into();
        save_meta(engine.store(), &engine.meta)?;
        Ok(engine)
    }

    /// Rebuilds every vault from what `store` holds.
    pub fn open(store: Box<dyn VaultStore>, clock: Box<dyn Clock>) -> Result<Self> {
        let mut engine = Self::empty(store, clock);
        // Setup stores `null` until the first vault exists.
        let default: Option<String> =
            get_json::<Option<String>>(engine.store(), META_DEFAULT_VAULT)?.flatten();
        engine.meta = Meta {
            device_name: get_json(engine.store(), META_DEVICE_NAME)?.unwrap_or_default(),
            default_vault: default
                .map(|id| unhex(&id).map(VaultId::from_bytes))
                .transpose()?,
            peers: get_json(engine.store(), META_PEERS)?.unwrap_or_default(),
        };
        // Decoding checks every frame's signature: spread it across cores.
        let mut stored: Vec<(VaultId, Zeroizing<Vec<u8>>)> = Vec::new();
        engine.store.for_each_frame(&mut |vault, bytes| {
            stored.push((vault, Zeroizing::new(bytes.to_vec())));
            Ok(())
        })?;
        let decoded = deadbolt_core::par::map(&stored, |(_, bytes)| Frame::decode(bytes));
        let mut grouped: IndexMap<VaultId, Result<Vec<Frame>>> = IndexMap::new();
        for ((vault, _), frame) in stored.iter().zip(decoded) {
            let slot = grouped.entry(*vault).or_insert_with(|| Ok(Vec::new()));
            if let Ok(frames) = slot {
                match frame {
                    Ok(frame) => frames.push(frame),
                    Err(error) => *slot = Err(anyhow!("decoding a stored frame: {error}")),
                }
            }
        }
        let keys = engine.keys();
        for (id, frames) in grouped {
            // Never publish a partial vault for use or sync.
            let result = frames.and_then(|frames| Ok(Vault::open(&keys, frames)?));
            match result {
                Ok(mut vault) => {
                    let removed: Vec<String> =
                        get_json(engine.store(), &meta_removed(&id))?.unwrap_or_default();
                    vault.remember_removed(
                        removed
                            .iter()
                            .filter_map(|d| unhex(d).ok().map(DeviceId::from_bytes)),
                    );
                    engine.vaults.insert(id, vault);
                    if let Err(error) = engine.load_proofs(&id) {
                        tracing::warn!(vault = %id, %error, "stored fraud proofs unreadable");
                    }
                    if let Err(error) = engine.load_base(id) {
                        tracing::warn!(vault = %id, %error, "local pack unusable; folding from genesis");
                    }
                }
                Err(error) => {
                    tracing::warn!(vault = %id, %error, "vault unavailable; stored frames retained");
                    engine.unavailable.insert(
                        id,
                        UnavailableVault {
                            name: id.to_string(),
                            error: error.to_string(),
                        },
                    );
                }
            }
        }
        engine.fulfill_reader_duty();
        Ok(engine)
    }

    /// Rule E6 for every vault: rewraps the keys other members can't reach
    /// and this device holds. A failure leaves that vault as it was; a peer
    /// holding the key can still do it, and the next unlock tries again.
    pub fn fulfill_reader_duty(&mut self) -> usize {
        let ids: Vec<VaultId> = self.vaults.keys().copied().collect();
        let mut made = 0;
        for id in ids {
            match self.update(id, |v, a| Ok(v.fulfill_reader_duty(a)?)) {
                Ok(frames) => made += frames.len(),
                Err(error) => tracing::warn!(vault = %id, %error, "reader duty failed"),
            }
        }
        made
    }

    fn empty(store: Box<dyn VaultStore>, clock: Box<dyn Clock>) -> Self {
        let id = DeviceKeys::from_seed(store.device_seed()).device_id();
        Self {
            store,
            clock,
            id,
            meta: Meta::default(),
            vaults: IndexMap::new(),
            unavailable: IndexMap::new(),
            changes: Changes::default(),
            append_uncertain: false,
            caps: CapTable::new(),
        }
    }

    /// Wipes everything granted while unlocked, as the device locks. The
    /// host drops the engine next; until then no capability answers.
    pub fn lock(&mut self) {
        self.caps.clear();
    }

    /// [`CapTable::authorize`] at this engine's now.
    pub fn authorize_cap(&mut self, id: &CapId, required: &CapCheck) -> Result<CapAudit, CapError> {
        self.caps.authorize(self.clock.as_ref(), id, required)
    }

    /// Where this engine persists.
    pub fn store(&self) -> &dyn VaultStore {
        self.store.as_ref()
    }

    /// This device's keys, fresh from the store's seed (which it keeps in
    /// locked memory). The engine holds no copy of its own: take them for
    /// one step and let them drop, which wipes them.
    pub fn keys(&self) -> DeviceKeys {
        DeviceKeys::from_seed(self.store.device_seed())
    }

    /// This device as the author of a write made now.
    pub fn author(&self) -> Author {
        Author::new(self.keys(), self.wall_clock().as_millis() as u64)
    }

    /// Now, since the Unix epoch.
    pub fn wall_clock(&self) -> Duration {
        self.clock.now()
    }

    /// Now, in Unix seconds.
    pub fn now(&self) -> u64 {
        self.wall_clock().as_secs()
    }

    /// Today as a UTC `YYYY-MM-DD` date.
    pub fn today(&self) -> String {
        utc_date(self.now())
    }

    pub fn ensure_usable(&self) -> Result<()> {
        if self.append_uncertain {
            return Err(fail(
                ErrorCode::Locked,
                "store commit outcome is uncertain; unlock again to authenticate and reload",
            ));
        }
        Ok(())
    }

    pub(crate) fn check_append<T>(&mut self, result: Result<T>) -> Result<T> {
        if let Some(diagnostic) = result
            .as_ref()
            .err()
            .and_then(|error| self.store.uncertain(error))
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
        change: impl FnOnce(&mut VaultWrite<'_>, &Author) -> Result<T>,
    ) -> Result<T> {
        self.available(id)?;
        let author = self.author();
        let store = &self.store;
        let changes = &mut self.changes;
        let vault = self.vaults.get_mut(&id).context("vault not held")?;
        let removed = vault.previously_removed().len();
        let result = vault.transact(
            |vault| change(vault, &author),
            |vault, frames| {
                store.append(id, &mut frames.iter().copied())?;
                changes.committed(id, vault, frames);
                Ok(())
            },
        );
        let result = self.check_append(result)?;
        if self
            .vaults
            .get(&id)
            .is_some_and(|v| v.previously_removed().len() != removed)
        {
            self.save_removed(&id)?;
        }
        self.maybe_checkpoint(id);
        Ok(result)
    }

    /// Saves the parking rule's memory for `vault`.
    pub(crate) fn save_removed(&self, vault: &VaultId) -> Result<()> {
        let removed: Vec<String> = self.vaults[vault]
            .previously_removed()
            .iter()
            .map(ToString::to_string)
            .collect();
        set_json(self.store(), &meta_removed(vault), &removed)
    }

    /// Saves the device name, default vault and address book.
    pub fn save_meta(&mut self) -> Result<()> {
        save_meta(self.store(), &self.meta)?;
        self.changes.vaults = true;
        Ok(())
    }

    pub fn save_peers(&self) -> Result<()> {
        set_json(self.store(), META_PEERS, &self.meta.peers)
    }

    /// When each login was last filled into a web page, in Unix seconds, by
    /// `vault:item`. Kept on this device only, to rank a site's logins.
    pub fn filled(&self) -> BTreeMap<String, u64> {
        get_json(self.store(), META_FILLED)
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
        set_json(self.store(), META_FILLED, &filled)
    }

    /// Every other device that is a member of a vault this device holds.
    pub fn peer_set(&self) -> HashSet<DeviceId> {
        self.vaults
            .values()
            .flat_map(|vault| vault.members())
            .filter(|id| *id != self.id)
            .collect()
    }

    /// The transport key (`D_net`) `device` signed into its `Add` in a held
    /// vault: the iroh id it is dialed and admitted by.
    pub fn net_of(&self, device: &DeviceId) -> Option<NetPublic> {
        self.vaults.values().find_map(|v| v.device_net(device))
    }

    /// The device, member or removed, whose transport key is `net`, if
    /// every held vault that knows the key agrees. A key is bound only by
    /// its holder's signature, so this holds unless one holder speaks for
    /// two devices.
    pub fn device_for_net(&self, net: &NetPublic) -> Option<DeviceId> {
        let mut found = self
            .vaults
            .values()
            .filter_map(|v| v.device_with_net(net.as_bytes()));
        let first = found.next()?;
        found.all(|d| d == first).then_some(first)
    }

    /// The transport keys of every other member, from every held vault:
    /// who this device dials.
    pub fn peer_nets(&self) -> HashSet<NetPublic> {
        self.vaults
            .values()
            .flat_map(|v| {
                v.members()
                    .filter(|d| *d != self.id)
                    .filter_map(|d| v.device_net(&d))
            })
            .collect()
    }

    /// Who the membership gate admits: every other member, and every device
    /// a held vault removed, which may still push membership frames only
    /// (`deadbolt_net::application::receive`), so a removal that lost to its
    /// target's concurrent one can be undone without a third device.
    pub fn admitted_nets(&self) -> HashSet<NetPublic> {
        let mut nets = self.peer_nets();
        nets.extend(self.vaults.values().flat_map(|v| {
            v.removed_devices()
                .filter(|d| *d != self.id)
                .filter_map(|d| v.device_net(&d))
        }));
        nets
    }

    pub fn peer(&self, id: &DeviceId) -> Option<&Peer> {
        self.meta.peers.get(&id.to_string())
    }

    pub fn peer_mut(&mut self, id: &DeviceId) -> &mut Peer {
        self.meta.peers.entry(id.to_string()).or_default()
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
    /// (fills gaps; newer addresses win). Only current peers may supply hints.
    pub fn learn(
        &mut self,
        from: &DeviceId,
        name: Option<&str>,
        addr: Option<Addr>,
        hints: BTreeMap<String, Hint>,
    ) {
        let allowed = self.peer_set();
        if !allowed.contains(from) {
            return;
        }
        let bounded = |mut addr: Addr| {
            addr.relay = addr.relay.filter(|url| {
                url.len() <= 512
                    && (url.starts_with("https://") || url.starts_with("http://"))
                    && !url.chars().any(|c| c.is_whitespace() || c.is_control())
                    && deadbolt_core::site::url_host(url).is_some()
            });
            addr.direct.truncate(16);
            addr
        };
        let now = self.now();
        let peer = self.peer_mut(from);
        if let Some(name) = name.map(clean_name).filter(|n| !n.is_empty()) {
            peer.name = Some(name);
        }
        if let Some(addr) = addr {
            peer.addr = Some(bounded(addr));
            peer.addr_seen = now;
        }
        let from = from.to_string();
        for (id, hint) in hints.into_iter().take(256) {
            if id == from
                || !unhex::<32>(&id)
                    .ok()
                    .map(DeviceId::from_bytes)
                    .is_some_and(|id| allowed.contains(&id))
            {
                continue;
            }
            let peer = self.meta.peers.entry(id).or_default();
            if peer.name.is_none() {
                peer.name = hint.name.map(|n| clean_name(&n)).filter(|n| !n.is_empty());
            }
            let seen = hint.addr_seen.min(now);
            if hint.addr.is_some() && seen > peer.addr_seen {
                peer.addr = hint.addr.map(bounded);
                peer.addr_seen = seen;
            }
        }
    }

    pub fn available(&self, id: VaultId) -> Result<VaultId> {
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
                .chain(
                    self.unavailable
                        .iter()
                        .map(|(id, vault)| (*id, Some(vault.name.as_str()))),
                ),
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

    /// Whether a held vault other than `except` is named `name`. An
    /// unavailable one goes by its id, which is never a valid name.
    pub fn name_taken(&self, name: &str, except: Option<VaultId>) -> bool {
        self.vaults
            .iter()
            .any(|(id, vault)| Some(*id) != except && vault.name() == name)
    }

    /// Adds a vault this device just created or joined. Once its frames
    /// are stored the vault is held, whatever follows: the bookkeeping after
    /// (the parking rule's memory, the default vault) only warns when it
    /// fails, so a caller never loses what it made (a new vault's kit).
    pub fn add_vault(&mut self, vault: Vault) -> Result<()> {
        let id = vault.id();
        self.available(id)?;
        if self.contains_vault(&id) {
            bail!("this device already holds vault {}", vault.name());
        }
        let result = self.store.append(id, &mut vault.frames());
        self.check_append(result)?;
        self.vaults.insert(id, vault);
        self.changes.vaults = true;
        self.changes.items.insert(id);
        self.changes.devices.insert(id);
        if let Err(error) = self.save_removed(&id) {
            tracing::warn!(vault = %id, %error, "saving the removed devices failed");
        }
        if self.meta.default_vault.is_none() && self.unavailable.is_empty() {
            self.meta.default_vault = Some(id);
            if let Err(error) = self.save_meta() {
                tracing::warn!(vault = %id, %error, "saving the default vault failed");
            }
        }
        Ok(())
    }

    /// [`Engine::create_vault_with_kit`], dropping (and wiping) the kit.
    pub fn create_vault(&mut self, name: &str) -> Result<VaultId> {
        Ok(self.create_vault_with_kit(name)?.0)
    }

    /// Creates a vault under a new recovery root, returning its id and the
    /// root's 24-word recovery kit. The kit is shown once and never stored.
    pub fn create_vault_with_kit(&mut self, name: &str) -> Result<(VaultId, Zeroizing<String>)> {
        if !valid_name(name) {
            bail!(
                "invalid vault name {name:?}: use 1-64 lowercase letters, digits, - or _, starting with a letter"
            );
        }
        if self.name_taken(name, None) {
            bail!("a vault named {name} already exists");
        }
        let root = RecoverySecret::generate()?;
        let label = self.meta.device_name.clone();
        let (vault, _) = Vault::create(&root, &self.author(), name, &label)?;
        let words = recovery::encode(&root);
        drop(root);
        let id = vault.id();
        self.add_vault(vault)?;
        Ok((id, words))
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
                error: Some(format!("{}; stored frames retained", vault.error)),
            }))
            .collect()
    }

    pub fn device_info(&self, id: &DeviceId, connected: &HashSet<DeviceId>) -> DeviceInfo {
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
            name: peer
                .and_then(|p| p.name.clone())
                .or_else(|| self.card_label(id).map(str::to_owned)),
            this: false,
            connected: connected.contains(id),
            last_seen: peer.and_then(|p| p.last_seen),
        }
    }

    pub fn online(&self, id: &DeviceId, connected: &HashSet<DeviceId>) -> bool {
        connected.contains(id)
            || self
                .peer(id)
                .and_then(|p| p.last_seen)
                .is_some_and(|seen| self.now().saturating_sub(seen) <= ONLINE_WINDOW_SECS)
    }

    /// The label `device` gave itself in a vault's `DeviceCard`.
    pub fn card_label(&self, device: &DeviceId) -> Option<&str> {
        self.vaults
            .values()
            .find_map(|v| v.device_label(device))
            .filter(|l| !l.is_empty())
    }

    /// Finds a member of `vault` by name or id prefix.
    pub fn resolve_device(&self, vault: &VaultId, query: &str) -> Result<DeviceId> {
        let matches = resolve_by_name_or_id(
            self.vaults[vault].members().map(|id| {
                let name = if id == self.id {
                    Some(self.meta.device_name.as_str())
                } else {
                    self.peer(&id)
                        .and_then(|p| p.name.as_deref())
                        .or_else(|| self.card_label(&id))
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

fn save_meta(store: &dyn VaultStore, meta: &Meta) -> Result<()> {
    set_json(store, META_DEVICE_NAME, &meta.device_name)?;
    set_json(
        store,
        META_DEFAULT_VAULT,
        &meta.default_vault.map(|id| id.to_string()),
    )?;
    set_json(store, META_PEERS, &meta.peers)
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

#[cfg(test)]
mod tests;
