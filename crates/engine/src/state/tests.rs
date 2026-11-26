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
