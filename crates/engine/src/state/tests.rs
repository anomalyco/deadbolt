use super::*;
use crate::testing;

#[test]
fn vault_and_device_prefixes_are_case_insensitive_but_names_win() {
    let loaded = testing::engine();
    let id = loaded.resolve(Some("personal")).unwrap();
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
fn failed_write_does_not_advance_log() {
    let mut engine = testing::engine();
    let id = engine.resolve(Some("personal")).unwrap();
    let vault = engine.vaults.get_mut(&id).unwrap();
    let before = vault.heads();
    let author = Author::new(DeviceKeys::from_seed(&[7; 32]), 0);
    let result: Result<_> = vault.transact(
        |v| Ok(v.rename(&author, "lost")?),
        |_, _| bail!("injected disk full"),
    );
    assert!(result.is_err());
    assert_eq!(vault.heads(), before);
    assert_eq!(vault.name(), "personal");
}

#[test]
fn the_keys_come_from_the_store_each_time() {
    let mut engine = testing::engine();
    let me = engine.id;
    assert_eq!(engine.keys().device_id(), me);
    let id = engine.resolve(Some("personal")).unwrap();
    engine
        .update(id, |vault, author| {
            assert_eq!(author.id(), me);
            Ok(vault.rename(author, "renamed")?)
        })
        .unwrap();
    assert_eq!(engine.vault(&id).name(), "renamed");
    assert_eq!(engine.vault(&id).device_label(&me).unwrap(), "test");

    let store = crate::store::MemoryStore::new([3; 32]);
    assert_eq!(store.device_seed(), &[3; 32]);
}

#[test]
fn a_new_vault_gives_its_kit_once_and_reopens_from_its_frames() {
    let mut engine = testing::engine();
    let (id, words) = engine.create_vault_with_kit("work").unwrap();
    assert_eq!(words.split(' ').count(), 24);
    let root = recovery::decode(&words).unwrap();
    assert_eq!(engine.vault(&id).recovery_root(), Some(root.recovery_id()));
    let frames: Vec<Frame> = engine.vault(&id).frames().cloned().collect();
    let reopened = Vault::open(&engine.keys(), frames).unwrap();
    assert_eq!(reopened.name(), "work");
}

/// A memory store two engines share, so the second opens what the first wrote.
struct Shared(std::sync::Arc<crate::MemoryStore>);

impl VaultStore for Shared {
    fn device_seed(&self) -> &[u8; 32] {
        self.0.device_seed()
    }
    fn for_each_frame(&self, each: &mut dyn FnMut(VaultId, &[u8]) -> Result<()>) -> Result<()> {
        self.0.for_each_frame(each)
    }
    fn append(&self, vault: VaultId, frames: &mut dyn Iterator<Item = &Frame>) -> Result<()> {
        self.0.append(vault, frames)
    }
    fn meta_get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.0.meta_get(name)
    }
    fn meta_set(&self, name: &str, value: &[u8]) -> Result<()> {
        self.0.meta_set(name, value)
    }
    fn uncertain(&self, error: &anyhow::Error) -> Option<String> {
        self.0.uncertain(error)
    }
}

/// Unlocking (decoding every frame, resolving membership, opening each
/// epoch and folding) takes at most 5 ms at 5,000 items. The passphrase KDF
/// runs before this and isn't counted. Timing, so release builds only.
#[test]
#[cfg_attr(debug_assertions, ignore = "timing: run with --release")]
fn unlock_takes_at_most_5_ms_at_5000_items() {
    use deadbolt_core::{DataOp, Field, FieldType};
    let store = std::sync::Arc::new(crate::MemoryStore::new([7; 32]));
    let clock = || Box::new(crate::clock::FixedClock(testing::NOW));
    let mut engine = Engine::create(Box::new(Shared(store.clone())), clock(), "test").unwrap();
    let id = engine.create_vault("personal").unwrap();
    let items: Vec<_> = (0..5000)
        .map(|i| {
            DataOp::create(
                "login",
                Some(format!("Site {i}")),
                [
                    (
                        "username".into(),
                        Field::new(FieldType::Text, "me@example.com"),
                    ),
                    (
                        "password".into(),
                        Field::new(FieldType::Secret, format!("pw-{i}")),
                    ),
                    (
                        "url".into(),
                        Field::new(FieldType::Url, format!("https://{i}.example.com")),
                    ),
                ],
            )
        })
        .collect();
    engine
        .update(id, |v, a| Ok(v.create_items(a, items)?))
        .unwrap();
    drop(engine);
    let mut best = std::time::Duration::MAX;
    for _ in 0..5 {
        let start = std::time::Instant::now();
        let engine = Engine::open(Box::new(Shared(store.clone())), clock()).unwrap();
        best = best.min(start.elapsed());
        assert_eq!(engine.vault(&id).items().len(), 5000);
    }
    assert!(
        best <= std::time::Duration::from_millis(5),
        "unlock took {best:?}"
    );
}

/// A store whose metadata writes fail once `broken` is set.
struct BrokenMeta {
    inner: crate::store::MemoryStore,
    broken: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl VaultStore for BrokenMeta {
    fn device_seed(&self) -> &[u8; 32] {
        self.inner.device_seed()
    }

    fn for_each_frame(&self, each: &mut dyn FnMut(VaultId, &[u8]) -> Result<()>) -> Result<()> {
        self.inner.for_each_frame(each)
    }

    fn append(&self, vault: VaultId, frames: &mut dyn Iterator<Item = &Frame>) -> Result<()> {
        self.inner.append(vault, frames)
    }

    fn meta_get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.inner.meta_get(name)
    }

    fn meta_set(&self, name: &str, value: &[u8]) -> Result<()> {
        if self.broken.load(std::sync::atomic::Ordering::SeqCst) {
            bail!("injected: metadata write failed");
        }
        self.inner.meta_set(name, value)
    }

    fn uncertain(&self, _: &anyhow::Error) -> Option<String> {
        None
    }
}

/// The frames are durable before any metadata is written: a failure after
/// them still hands back the 24 words, and the vault is held and usable.
#[test]
fn a_metadata_failure_after_the_frames_keeps_the_kit_and_the_vault() {
    let broken = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let store = BrokenMeta {
        inner: crate::store::MemoryStore::new([9; 32]),
        broken: broken.clone(),
    };
    let clock = Box::new(crate::clock::FixedClock(testing::NOW));
    let mut engine = Engine::create(Box::new(store), clock, "test").unwrap();
    broken.store(true, std::sync::atomic::Ordering::SeqCst);
    let (id, words) = engine.create_vault_with_kit("work").unwrap();
    let root = recovery::decode(&words).unwrap();
    assert_eq!(engine.vault(&id).recovery_root(), Some(root.recovery_id()));
    assert_eq!(engine.resolve(Some("work")).unwrap(), id);
    assert!(!engine.append_uncertain);
    broken.store(false, std::sync::atomic::Ordering::SeqCst);
    engine
        .update(id, |v, a| Ok(v.rename(a, "renamed")?))
        .unwrap();
    assert_eq!(engine.vault(&id).name(), "renamed");
}

struct FailedPack(Shared);

impl VaultStore for FailedPack {
    fn device_seed(&self) -> &[u8; 32] {
        self.0.device_seed()
    }
    fn for_each_frame(&self, each: &mut dyn FnMut(VaultId, &[u8]) -> Result<()>) -> Result<()> {
        self.0.for_each_frame(each)
    }
    fn append(&self, vault: VaultId, frames: &mut dyn Iterator<Item = &Frame>) -> Result<()> {
        self.0.append(vault, frames)
    }
    fn meta_get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.0.meta_get(name)
    }
    fn meta_set(&self, name: &str, value: &[u8]) -> Result<()> {
        self.0.meta_set(name, value)
    }
    fn uncertain(&self, _: &anyhow::Error) -> Option<String> {
        None
    }
    fn keeps_packs(&self) -> bool {
        true
    }
    fn seal_pack(
        &self,
        pack: &deadbolt_core::v2::Pack,
        _: &deadbolt_core::PackSite,
    ) -> Result<Vec<u8>> {
        Ok(pack.split()?.meta.to_vec())
    }
    fn install_pack(&self, _: VaultId, _: &[u8]) -> Result<()> {
        bail!("injected pack install failure")
    }
}

#[test]
fn failed_pack_install_keeps_the_committed_checkpoint_as_the_live_base() {
    let store = std::sync::Arc::new(crate::MemoryStore::new([7; 32]));
    let mut engine = Engine::create(
        Box::new(FailedPack(Shared(store))),
        Box::new(crate::clock::FixedClock(testing::NOW)),
        "test",
    )
    .unwrap();
    let id = engine.create_vault("personal").unwrap();
    let author = engine.author();
    for i in 0..500 {
        engine
            .vaults
            .get_mut(&id)
            .unwrap()
            .transact(
                |v| Ok::<_, anyhow::Error>(v.rename(&author, format!("personal-{i}"))?),
                |_, frames| engine.store.append(id, &mut frames.iter().copied()),
            )
            .unwrap();
    }
    assert!(engine.vault(&id).checkpoint_due());
    assert!(
        engine
            .checkpoint(id)
            .unwrap_err()
            .to_string()
            .contains("injected")
    );
    let checkpoint = engine.vault(&id).base_checkpoint().unwrap();
    assert!(engine.vault(&id).frame(&checkpoint).is_some());
    assert!(!engine.vault(&id).checkpoint_due());
    engine.update(id, |v, a| Ok(v.rename(a, "after")?)).unwrap();
    assert_eq!(engine.maybe_checkpoint(id), None);
    assert_eq!(engine.vault(&id).checkpoints().count(), 1);
}

#[test]
fn learned_addresses_are_bounded_and_only_current_members_are_recorded() {
    let mut engine = testing::engine();
    let vault = engine.resolve(Some("personal")).unwrap();
    let other = Author::new(DeviceKeys::from_seed(&[8; 32]), 0);
    let consent = other.join_consent(&vault, &engine.id);
    engine
        .update(vault, |v, a| {
            Ok(v.add(a, other.id(), other.keys().kem_public(), consent)?)
        })
        .unwrap();
    let addr = Addr {
        relay: Some(format!("https://{}.example", "x".repeat(600))),
        direct: vec!["127.0.0.1:1234".parse().unwrap(); 100],
    };
    let unknown = DeviceId::from_bytes([0x42; 32]);
    let hints = [(
        unknown.to_string(),
        Hint {
            name: Some("unknown".into()),
            addr: Some(addr.clone()),
            addr_seen: 1,
        },
    )]
    .into();
    engine.learn(&other.id(), Some("peer"), Some(addr.clone()), hints);
    assert!(engine.peer(&unknown).is_none());
    let learned = engine.peer(&other.id()).unwrap().addr.as_ref().unwrap();
    assert!(learned.relay.is_none());
    assert_eq!(learned.direct.len(), 16);
    engine.learn(
        &other.id(),
        None,
        Some(Addr {
            relay: Some("not a URL".into()),
            direct: vec![],
        }),
        BTreeMap::new(),
    );
    assert!(
        engine
            .peer(&other.id())
            .unwrap()
            .addr
            .as_ref()
            .unwrap()
            .relay
            .is_none()
    );
    engine
        .update(vault, |v, a| Ok(v.remove(a, other.id())?))
        .unwrap();
    engine.meta.peers.remove(&other.id().to_string());
    engine.learn(&other.id(), Some("removed"), Some(addr), BTreeMap::new());
    assert!(engine.peer(&other.id()).is_none());
}

#[test]
fn learned_addresses_reject_unknown_senders_and_future_overwrites() {
    let mut engine = testing::engine();
    let vault = engine.resolve(Some("personal")).unwrap();
    let other = Author::new(DeviceKeys::from_seed(&[8; 32]), 0);
    let target = Author::new(DeviceKeys::from_seed(&[9; 32]), 0);
    for author in [&other, &target] {
        let consent = author.join_consent(&vault, &engine.id);
        engine
            .update(vault, |v, a| {
                Ok(v.add(a, author.id(), author.keys().kem_public(), consent)?)
            })
            .unwrap();
    }
    let addr = Addr {
        relay: None,
        direct: vec!["127.0.0.1:1234".parse().unwrap()],
    };
    for from in [DeviceId::from_bytes([0x42; 32]), engine.id] {
        engine.learn(&from, Some("unknown"), Some(addr.clone()), BTreeMap::new());
        assert!(engine.peer(&from).is_none());
    }
    engine.learn(&target.id(), None, Some(addr.clone()), BTreeMap::new());
    engine.learn(
        &other.id(),
        None,
        None,
        [(
            target.id().to_string(),
            Hint {
                name: None,
                addr: Some(Addr::default()),
                addr_seen: u64::MAX,
            },
        )]
        .into(),
    );
    assert_eq!(
        engine.peer(&target.id()).unwrap().addr.as_ref(),
        Some(&addr)
    );
    assert_eq!(engine.peer(&target.id()).unwrap().addr_seen, engine.now());
}
