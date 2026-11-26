//! The unlocked state on this device: the engine's vaults over the sealed
//! store on disk, plus the network node while unlocked.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::disk::{KdfParams, Unlocked};
use anyhow::Result;
use deadbolt_core::v2::{DeviceKeys, EpochId, EpochKey, Frame, NetPublic, Pack};
use deadbolt_core::{Author, DeviceId, PackSite, Vault, VaultId, VaultWrite};
use deadbolt_engine::{Engine, VaultStore};
use deadbolt_net::application;
pub use deadbolt_net::application::{Addr, Hint, clean_name};
use deadbolt_net::{Node, PeerAddr};
use zeroize::Zeroizing;

use crate::config::SystemClock;
pub use crate::config::now;
pub use deadbolt_engine::store::{get_json, set_json};
pub use deadbolt_engine::{Changes, hex, unhex};

/// The transport key iroh runs on for the device seeded `seed`: `D_net`,
/// never `D_sign`. Peers know it from the device's `DeviceCard`, which is
/// how a connection's iroh id maps back to a device
/// ([`deadbolt_engine::Engine::device_for_net`]).
pub fn node_key(seed: &[u8; 32]) -> [u8; 32] {
    *DeviceKeys::from_seed(seed).net_key().to_bytes()
}

/// The sealed device directory as the engine's [`VaultStore`].
pub struct NativeStore(Arc<Unlocked>);

impl VaultStore for NativeStore {
    fn device_seed(&self) -> &[u8; 32] {
        self.0.device_seed()
    }

    fn for_each_frame(&self, each: &mut dyn FnMut(VaultId, &[u8]) -> Result<()>) -> Result<()> {
        self.0.for_each_frame(each)
    }

    fn append(&self, vault: VaultId, frames: &mut dyn Iterator<Item = &Frame>) -> Result<()> {
        Ok(self.0.append_frames(vault, frames)?)
    }

    fn meta_get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.0.meta_get(name)?)
    }

    fn meta_set(&self, name: &str, value: &[u8]) -> Result<()> {
        Ok(self.0.meta_set(name, value)?)
    }

    fn uncertain(&self, error: &anyhow::Error) -> Option<String> {
        error
            .downcast_ref::<crate::disk::Error>()
            .and_then(crate::disk::Error::append_diagnostic)
    }

    fn keeps_packs(&self) -> bool {
        true
    }

    fn seal_pack(&self, pack: &Pack, site: &PackSite) -> Result<Vec<u8>> {
        Ok(self.0.seal_pack(pack, site)?)
    }

    fn install_pack(&self, vault: VaultId, sealed: &[u8]) -> Result<()> {
        self.0.install_pack(vault, sealed)?;
        Ok(())
    }

    fn load_pack(&self, vault: VaultId) -> Result<Option<Vec<u8>>> {
        Ok(self.0.load_pack(vault)?)
    }

    fn open_pack(
        &self,
        sealed: &[u8],
        vault: VaultId,
        key_for: &dyn Fn(&EpochId) -> Option<EpochKey>,
    ) -> Result<Pack> {
        Ok(crate::disk::open_pack(sealed, vault, key_for)?)
    }
}

/// The store opened and decoded, before the network node starts: the
/// engine's state, and the store it persists to for what only this host
/// does with it (passphrase checks, Touch ID, Activity).
pub struct Loaded {
    pub(super) engine: Engine,
    pub store: Arc<Unlocked>,
    pub health: super::health::State,
}

impl std::ops::Deref for Loaded {
    type Target = Engine;
    fn deref(&self) -> &Engine {
        &self.engine
    }
}

impl std::ops::DerefMut for Loaded {
    fn deref_mut(&mut self) -> &mut Engine {
        &mut self.engine
    }
}

impl Loaded {
    /// Creates the device key and store. Blocking (Argon2).
    pub fn setup(
        dir: &Path,
        passphrase: &[u8],
        device_name: &str,
        params: KdfParams,
    ) -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut_slice())?;
        Self::setup_with(dir, passphrase, device_name, params, &seed)
    }

    /// Creates the store for an existing device seed. Blocking (Argon2).
    pub fn setup_with(
        dir: &Path,
        passphrase: &[u8],
        device_name: &str,
        params: KdfParams,
        seed: &[u8; 32],
    ) -> Result<Self> {
        let store = crate::disk::init_with_params(dir, passphrase, seed, params)?;
        let store = Arc::new(store);
        let engine = Engine::create(
            Box::new(NativeStore(store.clone())),
            Box::new(SystemClock),
            device_name,
        )?;
        Ok(Self::new(engine, store))
    }

    /// Unlocks the store and rebuilds every vault. Blocking (Argon2).
    pub fn open(dir: &Path, passphrase: &[u8]) -> Result<Self> {
        let store = crate::disk::unlock(dir, passphrase)?;
        Self::from_unlocked(store)
    }

    /// Rebuilds every vault from an already-unlocked store.
    pub fn from_unlocked(store: Unlocked) -> Result<Self> {
        let store = Arc::new(store);
        let engine = Engine::open(Box::new(NativeStore(store.clone())), Box::new(SystemClock))?;
        Ok(Self::new(engine, store))
    }

    fn new(engine: Engine, store: Arc<Unlocked>) -> Self {
        let health = super::health::State::new(engine.store());
        Self {
            engine,
            store,
            health,
        }
    }

    /// The key this device's iroh node runs on; see [`node_key`].
    pub fn node_key(&self) -> [u8; 32] {
        node_key(self.store.device_seed())
    }

    /// Where to dial `id`: its card's transport key and its last address.
    /// `None` while no held vault has its card.
    pub fn addr_of(&self, id: &DeviceId) -> Option<PeerAddr> {
        let net = self.net_of(id)?;
        let addr = self
            .peer(id)
            .and_then(|p| p.addr.clone())
            .unwrap_or_default();
        Some(PeerAddr::of(*net.as_bytes(), &addr))
    }

    /// The device on the other end of a sync connection from transport key
    /// `peer`, member or removed.
    pub fn device_of(&self, peer: &deadbolt_net::PeerId) -> Result<DeviceId> {
        self.device_for_net(&NetPublic::from_bytes(*peer))
            .ok_or_else(|| anyhow::anyhow!("no held vault has a card for that transport key"))
    }

    /// The devices behind connected transport keys.
    pub fn connected_devices(
        &self,
        nets: impl IntoIterator<Item = deadbolt_net::PeerId>,
    ) -> std::collections::HashSet<DeviceId> {
        nets.into_iter()
            .filter_map(|net| self.device_for_net(&NetPublic::from_bytes(net)))
            .collect()
    }
}

impl application::State for Loaded {
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
        self.engine.hints_for(peer)
    }

    fn update<T>(
        &mut self,
        id: VaultId,
        change: impl FnOnce(&mut VaultWrite<'_>, &Author) -> Result<T, application::Error>,
    ) -> Result<T> {
        self.engine
            .update(id, |vault, author| Ok(change(vault, author)?))
    }

    fn learn(
        &mut self,
        peer: &DeviceId,
        name: &str,
        addr: Option<Addr>,
        hints: BTreeMap<String, Hint>,
    ) -> Result<()> {
        self.engine.learn(peer, Some(name), addr, hints);
        self.save_peers()
    }

    fn received(&mut self, peer: &DeviceId) -> Result<()> {
        let now = self.now();
        self.peer_mut(peer).last_seen = Some(now);
        self.save_peers()
    }
}

pub struct Session {
    state: Loaded,
    pub node: Node,
    pub(super) sync_task: Option<super::AbortOnDrop>,
    pub(super) health_task: Option<super::AbortOnDrop>,
    /// Passwords made for web forms, until saved; locking drops them.
    pub generated: deadbolt_engine::generate::Pending,
    /// When this session began: the epoch of [`Session::elapsed`].
    started: Instant,
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
            health_task: None,
            generated: Default::default(),
            started: Instant::now(),
        }
    }

    pub fn own_addr(&self) -> Addr {
        Addr::from(self.node.addr())
    }

    /// Monotonic time since the session began.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::protocol::ErrorCode;
    use anyhow::bail;
    use deadbolt_core::v2::RecoverySecret;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    /// A device whose `fault` counter makes a frame append land but report
    /// failure (see `crate::disk::Unlocked::lost_ack`).
    pub(crate) fn fault_store(dir: &Path, seed: [u8; 32]) -> (Loaded, Arc<AtomicUsize>) {
        let store = crate::disk::init_with_params(dir, b"test", &seed, FAST).unwrap();
        let fault = store.lost_ack.clone();
        (Loaded::from_unlocked(store).unwrap(), fault)
    }

    /// Keys for a device seeded `seed`, and its consent to join `vault`
    /// through `inviter`.
    pub(crate) fn peer(
        seed: u8,
        vault: &VaultId,
        inviter: &DeviceId,
    ) -> (DeviceKeys, deadbolt_core::v2::JoinConsent) {
        let keys = DeviceKeys::from_seed(&[seed; 32]);
        let consent = deadbolt_core::v2::sign_join_consent(&keys, vault, inviter);
        (keys, consent)
    }

    /// Device `seed` as the author of a write made now.
    pub(crate) fn author(seed: u8) -> Author {
        Author::new(DeviceKeys::from_seed(&[seed; 32]), now() * 1000)
    }

    /// Runs `change` on a vault no store holds, as a test peer's copy.
    pub(crate) fn local<T>(
        vault: &mut Vault,
        change: impl FnOnce(&mut VaultWrite<'_>) -> Result<T, deadbolt_core::Error>,
    ) -> T {
        vault.transact(change, |_, _| Ok(())).unwrap()
    }

    /// A frame's bytes, as sync carries them.
    pub(crate) fn blob(vault: &Vault, frame: deadbolt_core::v2::FrameId) -> deadbolt_net::Blob {
        deadbolt_net::Blob::new(vault.frame(&frame).unwrap().encode())
    }

    #[test]
    fn ambiguous_append_removal_requires_replay() {
        let dir = tempfile::tempdir().unwrap();
        let (mut loaded, fault) = fault_store(dir.path(), [7; 32]);
        let id = loaded.create_vault("personal").unwrap();
        let (peer, consent) = peer(8, &id, &loaded.id);
        let pid = peer.device_id();
        loaded
            .update(id, |v, a| Ok(v.add(a, pid, peer.kem_public(), consent)?))
            .unwrap();
        let old_heads = loaded.vault(&id).heads();
        fault.store(1, Ordering::SeqCst);
        assert!(loaded.update(id, |v, a| Ok(v.remove(a, pid)?)).is_err());
        assert_eq!(fault.load(Ordering::SeqCst), 0);
        assert!(loaded.ensure_usable().is_err());
        assert!(loaded.resolve(None).is_err());
        assert!(loaded.held(&id).is_none());
        assert!(loaded.peer_set().is_empty());
        assert_eq!(application::State::vaults(&loaded).count(), 0);
        assert!(super::super::sync::hello(&loaded, &pid, None).is_err());
        assert!(super::super::sync::missing_for(&mut loaded, &pid, b"{}", true).is_err());
        assert!(
            super::super::sync::receive(&mut loaded, &pid, vec![], true, &mut Default::default())
                .is_err()
        );
        assert!(super::super::pairing::offer(&loaded, id, pid.as_bytes(), None).is_err());
        assert!(loaded.create_vault("another").is_err());
        drop(loaded);
        let reopened = Loaded::open(dir.path(), b"test").unwrap();
        assert!(!reopened.vault(&id).is_member(&pid));
        assert_ne!(reopened.vault(&id).heads(), old_heads);
    }

    #[test]
    fn quarantined_vault_reports_locked_to_clients() {
        let dir = tempfile::tempdir().unwrap();
        let (mut loaded, fault) = fault_store(dir.path(), [7; 32]);
        let id = loaded.create_vault("personal").unwrap();
        fault.store(1, Ordering::SeqCst);
        loaded
            .update(id, |v, a| Ok(v.rename(a, "changed")?))
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
            .update(id, |v, a| {
                Ok(v.create_item(
                    a,
                    "login",
                    None,
                    [("password".into(), Field::new(FieldType::Secret, "old"))],
                )?)
            })
            .unwrap();
        fault.store(1, Ordering::SeqCst);
        let set = DataOp::set(item, "password", Field::new(FieldType::Secret, "new"));
        let error = loaded
            .update(id, |v, a| Ok(v.write(a, vec![set])?))
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<crate::disk::Error>(),
            Some(crate::disk::Error::AppendUncertain(_))
        ));
        assert!(loaded.resolve(None).is_err());
        assert!(loaded.held(&id).is_none());
        drop(loaded);
        let reopened = Loaded::open(dir.path(), b"test").unwrap();
        let password = &reopened.vault(&id).item(&item).unwrap().fields["password"];
        assert_eq!(password.value.as_str(), "new");
    }

    #[test]
    fn ambiguous_append_pairing_never_returns_a_welcome_or_publishes_an_adoption() {
        use super::super::pairing;
        let inviter_dir = tempfile::tempdir().unwrap();
        let joiner_dir = tempfile::tempdir().unwrap();
        let (mut inviter, fault) = fault_store(inviter_dir.path(), [7; 32]);
        let id = inviter.create_vault("personal").unwrap();
        let peer = DeviceKeys::from_seed(&[8; 32]);
        let pid = peer.device_id();
        let offer =
            pairing::read_offer(&pairing::offer(&inviter, id, pid.as_bytes(), None).unwrap())
                .unwrap()
                .0;
        let join = pairing::join_blob(&peer, "peer", inviter.id, &id, None).unwrap();
        fault.store(1, Ordering::SeqCst);
        assert!(pairing::welcome(&mut inviter, id, pid, &join, None).is_err());
        assert!(inviter.ensure_usable().is_err());
        drop(inviter);
        let mut inviter = Loaded::open(inviter_dir.path(), b"test").unwrap();
        assert!(inviter.vault(&id).is_member(&pid));
        let (welcome, _) = pairing::welcome(&mut inviter, id, pid, &join, None).unwrap();
        let welcomed = pairing::verify_welcome(
            &peer,
            inviter.id,
            offer,
            pairing::test_replay(&inviter, welcome),
        )
        .unwrap();
        let (mut joiner, fault) = fault_store(joiner_dir.path(), [8; 32]);
        // Adopt is already past signature/identity validation; its store append
        // must fail closed regardless of whether this is the first held vault.
        fault.store(1, Ordering::SeqCst);
        assert!(pairing::adopt(&mut joiner, welcomed).is_err());
        assert!(joiner.ensure_usable().is_err());
        assert!(joiner.held(&id).is_none());
        assert!(joiner.create_vault("personal").is_err());
        drop(joiner);
        let reopened = Loaded::open(joiner_dir.path(), b"test").unwrap();
        assert!(reopened.contains_vault(&id), "the landed frames are kept");
    }

    #[test]
    fn validation_failure_does_not_poison_or_attempt_an_append() {
        let dir = tempfile::tempdir().unwrap();
        let (mut loaded, fault) = fault_store(dir.path(), [7; 32]);
        let id = loaded.create_vault("personal").unwrap();
        let heads = loaded.vault(&id).heads();
        fault.store(1, Ordering::SeqCst);
        assert!(
            loaded
                .update(id, |v, a| -> Result<()> {
                    v.rename(a, "staged")?;
                    bail!("validation rejected the command")
                })
                .is_err()
        );
        assert_eq!(fault.load(Ordering::SeqCst), 1);
        assert_eq!(loaded.vault(&id).heads(), heads);
        loaded.ensure_usable().unwrap();
        fault.store(0, Ordering::SeqCst);
        loaded
            .update(id, |v, a| Ok(v.rename(a, "accepted")?))
            .unwrap();
    }

    #[test]
    fn a_damaged_vault_is_visible_and_isolated_without_losing_frames() {
        let dir = tempfile::tempdir().unwrap();
        let mut loaded = Loaded::setup(dir.path(), b"test", "device", FAST).unwrap();
        let bad = loaded.create_vault("personal").unwrap();
        drop(loaded);
        let vault_dir = dir.path().join("v").join(bad.to_string());
        let members = || {
            let blocks = deadbolt_pack::FsBlocks::open(&vault_dir).unwrap();
            deadbolt_pack::log::recover(&blocks, "members.log").unwrap()
        };
        // A member frame that won't decode, as a damaged disk might leave.
        let blocks = deadbolt_pack::FsBlocks::open(&vault_dir).unwrap();
        deadbolt_pack::log::append(&blocks, "members.log", b"not a frame").unwrap();
        let before = members();

        let mut loaded = Loaded::open(dir.path(), b"test").unwrap();
        assert!(loaded.vaults.is_empty());
        assert_eq!(loaded.unavailable.len(), 1);
        let infos = loaded.vault_infos();
        assert!(infos[0].default);
        let error = infos[0].error.as_ref().unwrap();
        assert!(error.contains("stored frames retained"), "{error}");
        let error = loaded.resolve(None).unwrap_err().to_string();
        assert!(error.contains("unavailable"), "{error}");
        let good = loaded.create_vault("healthy").unwrap();
        let error = loaded.resolve(None).unwrap_err().to_string();
        assert!(error.contains("`deadbolt vault default <name>`"), "{error}");
        let prefix = loaded.resolve(Some(&bad.to_string()[..8])).unwrap_err();
        assert!(prefix.to_string().contains("unavailable"));
        assert!(loaded.held(&bad).is_none());
        assert!(
            loaded
                .update(bad, |v, a| Ok(v.rename(a, "replacement")?))
                .is_err()
        );
        assert_eq!(loaded.resolve(Some("healthy")).unwrap(), good);
        loaded.meta.default_vault = Some(good);
        loaded.save_meta().unwrap();
        drop(loaded);
        let loaded = Loaded::open(dir.path(), b"test").unwrap();
        assert_eq!(loaded.resolve(None).unwrap(), good);
        assert_eq!(members(), before);
    }

    #[test]
    fn a_device_reopens_before_its_first_vault() {
        let dir = tempfile::tempdir().unwrap();
        drop(Loaded::setup(dir.path(), b"test", "device", FAST).unwrap());
        let loaded = Loaded::open(dir.path(), b"test").unwrap();
        assert_eq!(loaded.meta.default_vault, None);
        assert_eq!(loaded.meta.device_name, "device");
    }

    #[test]
    fn restart_discovers_vault_from_committed_frames() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::disk::init_with_params(dir.path(), b"test", &[1; 32], FAST).unwrap();
        let author = Author::new(DeviceKeys::from_seed(&[1; 32]), 0);
        let root = RecoverySecret::from_bytes([2; 32]);
        let (vault, frames) = Vault::create(&root, &author, "test", "device").unwrap();
        store.meta_set("cli/vaults", b"[]").unwrap();
        store.append_frames(vault.id(), &mut frames.iter()).unwrap();
        // Crash between committing the frames and updating metadata.
        drop(store);
        let loaded = Loaded::open(dir.path(), b"test").unwrap();
        assert!(loaded.vaults.contains_key(&vault.id()));
    }
}
