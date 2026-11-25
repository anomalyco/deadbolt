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
    assert_eq!(engine.vault(&id).device_card(&me).unwrap().1, "test");

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
