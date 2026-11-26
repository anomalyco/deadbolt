use deadbolt_core::v2::KemSecret;
use deadbolt_pack::objects::list_outbox;
use deadbolt_pack::{Blocks, MemBlocks};
use zeroize::Zeroizing;

use super::{VAULT, device_kem, item_id};
use crate::{OutboxMutation, ViewerError, drain_outbox, open_entry, queue_save};

fn login(password: &str) -> OutboxMutation {
    OutboxMutation::SaveLogin {
        url: "https://example.com/login".into(),
        username: "alex@example.com".into(),
        password: Zeroizing::new(password.into()),
        title: Some("Example".into()),
    }
}

fn queue(blocks: &MemBlocks, mutation: &OutboxMutation) -> String {
    queue_save(
        blocks,
        &VAULT,
        &device_kem().public_key(),
        mutation,
        super::NOW * 1000,
    )
    .unwrap()
}

#[test]
fn the_app_drains_what_the_viewer_queued() {
    let blocks = MemBlocks::new();
    let mutations = [
        login("hunter2"),
        OutboxMutation::SavePasskey {
            rp_id: "example.com".into(),
            user_name: "alex".into(),
            user_handle: "aGFuZGxl".into(),
            credential_id: "Y3JlZA".into(),
            private_key: Zeroizing::new("cGtjczg".into()),
            title: None,
        },
        OutboxMutation::TouchUsed {
            item_id: item_id(3),
            used_unix: 1_800_000_000,
        },
    ];
    let mut names: Vec<String> = mutations.iter().map(|m| queue(&blocks, m)).collect();
    names.sort();
    for name in &names {
        assert!(
            name.starts_with("outbox/") && name.ends_with(".wrap"),
            "{name}"
        );
        // Sealed: the password is nowhere in the bytes.
        let bytes = blocks.file(name).unwrap();
        assert!(!bytes.windows(7).any(|w| w == b"hunter2"));
    }
    assert_eq!(list_outbox(&blocks).unwrap(), names);

    let mut seen = Vec::new();
    let drained = drain_outbox(&blocks, &VAULT, &device_kem(), |name, mutation| {
        seen.push((name.to_owned(), mutation));
        Ok(())
    })
    .unwrap();
    assert_eq!(drained.applied, names);
    assert!(drained.rejected.is_empty());
    assert!(list_outbox(&blocks).unwrap().is_empty());
    let mut got: Vec<OutboxMutation> = seen.into_iter().map(|(_, m)| m).collect();
    for want in &mutations {
        let at = got.iter().position(|m| m == want).unwrap();
        got.remove(at);
    }
    assert!(got.is_empty());
}

#[test]
fn only_the_apps_kem_secret_opens_an_entry() {
    let blocks = MemBlocks::new();
    let name = queue(&blocks, &login("hunter2"));
    let entry = blocks.file(&name).unwrap();
    let other = KemSecret::from_bytes(&[8; 32]);
    assert_eq!(
        open_entry(&VAULT, &other, &name, &entry).unwrap_err(),
        ViewerError::WrongKey
    );
    let drained = drain_outbox(&blocks, &VAULT, &other, |_, _| panic!("applied")).unwrap();
    assert_eq!(drained.rejected.len(), 1);
    // Left on disk for the right key.
    assert_eq!(list_outbox(&blocks).unwrap(), std::slice::from_ref(&name));
    assert_eq!(
        open_entry(&VAULT, &device_kem(), &name, &entry).unwrap(),
        login("hunter2")
    );
}

#[test]
fn altered_moved_or_misfiled_entries_never_open() {
    let blocks = MemBlocks::new();
    let name = queue(&blocks, &login("hunter2"));
    let entry = blocks.file(&name).unwrap();
    let kem = device_kem();
    let len = entry.len();
    // The suite, the wrap's ephemeral key and ciphertext, the nonce, the body.
    for at in [5, 6, 40, 90, 100, 130, len - 1] {
        let mut bad = entry.clone();
        bad[at] ^= 1;
        assert_eq!(
            open_entry(&VAULT, &kem, &name, &bad).unwrap_err(),
            ViewerError::WrongKey,
            "flip at {at}"
        );
    }
    for at in [0, 4] {
        let mut bad = entry.clone();
        bad[at] ^= 1;
        assert!(matches!(
            open_entry(&VAULT, &kem, &name, &bad),
            Err(ViewerError::Corrupt { .. })
        ));
    }
    assert!(matches!(
        open_entry(&VAULT, &kem, &name, &entry[..50]),
        Err(ViewerError::Corrupt { .. })
    ));
    // A copy under another name is not a second save.
    let copy = format!("outbox/{}.wrap", "0".repeat(32));
    assert_eq!(
        open_entry(&VAULT, &kem, &copy, &entry).unwrap_err(),
        ViewerError::WrongKey
    );
    assert!(matches!(
        open_entry(&VAULT, &kem, "outbox/x.wrap", &entry),
        Err(ViewerError::Corrupt { .. })
    ));
    // Nor is it another vault's.
    assert_eq!(
        open_entry(&[0xee; 32], &kem, &name, &entry).unwrap_err(),
        ViewerError::WrongKey
    );
}

#[test]
fn padding_hides_a_passwords_length() {
    let blocks = MemBlocks::new();
    let short = queue(&blocks, &login("a"));
    let long = queue(&blocks, &login(&"b".repeat(64)));
    assert_eq!(
        blocks.file(&short).unwrap().len(),
        blocks.file(&long).unwrap().len()
    );
}

#[test]
fn a_failed_apply_keeps_the_entry_queued() {
    let blocks = MemBlocks::new();
    let name = queue(&blocks, &login("hunter2"));
    let failed = drain_outbox(&blocks, &VAULT, &device_kem(), |_, _| {
        Err(ViewerError::invalid("vault locked"))
    });
    assert!(failed.is_err());
    assert_eq!(list_outbox(&blocks).unwrap(), [name]);
    assert!(blocks.delete("outbox/missing.wrap").is_ok());
}

#[test]
fn oversized_mutations_are_refused() {
    let blocks = MemBlocks::new();
    let huge = login(&"x".repeat(crate::outbox::MAX_MUTATION_LEN));
    assert!(matches!(
        queue_save(
            &blocks,
            &VAULT,
            &device_kem().public_key(),
            &huge,
            super::NOW * 1000
        ),
        Err(ViewerError::InvalidInput { .. })
    ));
    assert!(list_outbox(&blocks).unwrap().is_empty());
}

#[test]
fn debug_leaves_secrets_out() {
    let shown = format!("{:?}", login("hunter2"));
    assert!(!shown.contains("hunter2") && shown.contains("alex@example.com"));
}

#[test]
fn mutations_drain_in_chronological_order() {
    let blocks = MemBlocks::new();
    let times = [
        0xfe,
        0xff,
        0x100,
        0xffff,
        0x10000,
        super::NOW * 1000,
        (1 << 48) - 1,
    ];
    let mut expected = Vec::new();
    let mut names = Vec::new();
    for now_ms in times {
        let mutation = login(&format!("password-{now_ms}"));
        let name = queue_save(
            &blocks,
            &VAULT,
            &device_kem().public_key(),
            &mutation,
            now_ms,
        )
        .unwrap();
        assert!(name.starts_with(&format!("outbox/{now_ms:012x}")));
        names.push(name);
        expected.push(mutation);
    }
    assert_eq!(list_outbox(&blocks).unwrap(), names);
    let mut replayed = Vec::new();
    let drained = drain_outbox(&blocks, &VAULT, &device_kem(), |_, mutation| {
        replayed.push(mutation);
        Ok(())
    })
    .unwrap();
    assert_eq!(replayed, expected);
    assert_eq!(drained.applied, names);
    assert!(drained.rejected.is_empty());
    assert!(list_outbox(&blocks).unwrap().is_empty());
}

#[test]
fn an_out_of_range_timestamp_is_not_silently_truncated() {
    let blocks = MemBlocks::new();
    assert!(matches!(
        queue_save(
            &blocks,
            &VAULT,
            &device_kem().public_key(),
            &login("pw"),
            1 << 48
        ),
        Err(ViewerError::InvalidInput { .. })
    ));
    assert!(list_outbox(&blocks).unwrap().is_empty());
}
