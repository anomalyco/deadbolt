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
