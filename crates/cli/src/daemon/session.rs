//! The unlocked state on this device: the engine's vaults over the sealed
//! store on disk, plus the network node while unlocked.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use deadbolt_core::{DeviceId, DeviceSecret, Vault, VaultId, VaultWrite};
use deadbolt_engine::{Engine, VaultStore};
use deadbolt_net::application;
pub use deadbolt_net::application::{Addr, Hint, clean_name};
use deadbolt_net::{Node, PeerAddr};
use deadbolt_store::{KdfParams, Unlocked};
use zeroize::Zeroizing;

use crate::config::SystemClock;
pub use crate::config::now;
pub use deadbolt_engine::store::{get_json, set_json};
pub use deadbolt_engine::{Changes, hex, unhex};

/// `store.redb` as the engine's [`VaultStore`].
pub struct NativeStore(Arc<Unlocked>);

impl VaultStore for NativeStore {
    fn device_secret(&self) -> &[u8; 32] {
        self.0.device_secret()
    }

    fn for_each_entry(&self, each: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        for entry in self.0.iter_all()? {
            each(&entry?)?;
        }
        Ok(())
    }

    fn append(&self, entries: &mut dyn Iterator<Item = Zeroizing<Vec<u8>>>) -> Result<()> {
        self.0.append_batch(entries)?;
        Ok(())
    }

    fn meta_get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.0.meta_get(name)?)
    }

    fn meta_set(&self, name: &str, value: &[u8]) -> Result<()> {
        Ok(self.0.meta_set(name, value)?)
    }

    fn uncertain(&self, error: &anyhow::Error) -> Option<String> {
        error
            .downcast_ref::<deadbolt_store::Error>()
            .and_then(deadbolt_store::Error::append_diagnostic)
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
        let store = deadbolt_store::unlock(dir, passphrase)?;
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

    pub fn addr_of(&self, id: &DeviceId) -> PeerAddr {
        let addr = self
            .peer(id)
            .and_then(|p| p.addr.clone())
            .unwrap_or_default();
        PeerAddr::of(*id.as_bytes(), &addr)
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
        change: impl FnOnce(&mut VaultWrite<'_>, &DeviceSecret) -> Result<T, application::Error>,
    ) -> Result<T> {
        self.engine
            .update(id, |vault, secret| Ok(change(vault, secret)?))
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
    use deadbolt_core::{Entry, MembershipOp, Payload};
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
        assert_eq!(application::State::vaults(&loaded).count(), 0);
        assert!(super::super::sync::hello(&loaded, &peer.device_id(), None).is_err());
        assert!(
            super::super::sync::missing_for(&mut loaded, &peer.device_id(), b"{}", true).is_err()
        );
        assert!(
            super::super::sync::receive(
                &mut loaded,
                &peer.device_id(),
                vec![],
                true,
                &mut Default::default()
            )
            .is_err()
        );
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
        store.append_batch([genesis.encode()]).unwrap();
        // Crash between committing the genesis and updating cli/vaults metadata.
        drop(store);
        let loaded = Loaded::open(dir.path(), b"test").unwrap();
        assert!(loaded.vaults.contains_key(&vault.id()));
    }
}
