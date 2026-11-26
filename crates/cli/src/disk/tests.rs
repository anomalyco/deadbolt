use super::*;
use deadbolt_core::v2::RecoverySecret;
use deadbolt_core::{Author, Vault};

const FAST: KdfParams = KdfParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const ROOMY: Budget = Budget {
    rows: 1_000,
    bytes: 1 << 20,
};

/// The rows' bytes, as text, newest first.
fn rows(store: &Unlocked) -> Vec<String> {
    let page = store.activity_list(0, None, 100).unwrap();
    page.rows
        .iter()
        .map(|r| String::from_utf8(r.bytes.to_vec()).unwrap())
        .collect()
}

#[test]
fn the_passphrase_opens_the_device_and_nothing_else_does() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!is_initialized(dir.path()));
    assert!(matches!(
        unlock(dir.path(), b"pass"),
        Err(Error::NotInitialized(_))
    ));
    let store = init_with_params(dir.path(), b"pass", &[7; 32], FAST).unwrap();
    assert!(is_initialized(dir.path()));
    assert!(matches!(unlock(dir.path(), b"pass"), Err(Error::InUse)));
    store.meta_set("cli/name", b"laptop").unwrap();
    assert!(store.passphrase_check().unwrap().matches(b"pass"));
    assert!(!store.passphrase_check().unwrap().matches(b"nope"));
    drop(store);
    assert!(matches!(
        init_with_params(dir.path(), b"other", &[1; 32], FAST),
        Err(Error::AlreadyExists(_))
    ));
    assert!(matches!(
        unlock(dir.path(), b"nope"),
        Err(Error::WrongPassphrase)
    ));
    let store = unlock(dir.path(), b"pass").unwrap();
    assert_eq!(store.device_seed(), &[7; 32]);
    assert_eq!(&**store.meta_get("cli/name").unwrap().unwrap(), b"laptop");
}

#[test]
fn frames_and_vault_state_persist_per_vault() {
    let dir = tempfile::tempdir().unwrap();
    let store = init_with_params(dir.path(), b"pass", &[7; 32], FAST).unwrap();
    let author = Author::new(deadbolt_core::v2::DeviceKeys::from_seed(&[7; 32]), 1);
    let root = RecoverySecret::from_bytes([3; 32]);
    let (vault, frames) = Vault::create(&root, &author, "personal", "laptop").unwrap();
    let id = vault.id();
    store.append_frames(id, &mut frames.iter()).unwrap();
    let name = format!("vault/{id}/removed");
    store.meta_set(&name, b"[]").unwrap();
    drop(store);
    let store = unlock(dir.path(), b"pass").unwrap();
    let mut read = Vec::new();
    store
        .for_each_frame(&mut |vault, bytes| {
            assert_eq!(vault, id);
            read.push(Frame::decode(bytes)?);
            Ok(())
        })
        .unwrap();
    assert_eq!(read.len(), frames.len());
    let reopened = Vault::open(author.keys(), read).unwrap();
    assert_eq!(reopened.name(), "personal");
    assert_eq!(&**store.meta_get(&name).unwrap().unwrap(), b"[]");
    assert!(store.meta_get("vault/x/removed").unwrap().is_none());
    assert!(
        dir.path()
            .join("v")
            .join(id.to_string())
            .join("members.log")
            .is_file()
    );
}

#[test]
fn the_biometric_slot_opens_the_device_and_clears_while_locked() {
    let dir = tempfile::tempdir().unwrap();
    let store = init_with_params(dir.path(), b"pass", &[7; 32], FAST).unwrap();
    let key = generate_biometric_key().unwrap();
    assert!(store.set_biometric(&key, b"").is_err());
    store.set_biometric(&key, b"token").unwrap();
    assert!(store.check_biometric(&key).unwrap());
    assert!(!store.check_biometric(&[0; 32]).unwrap());
    assert_eq!(
        store.biometric_token().unwrap().as_deref(),
        Some(&b"token"[..])
    );
    drop(store);
    assert_eq!(
        biometric_token(dir.path()).unwrap().as_deref(),
        Some(&b"token"[..])
    );
    assert!(matches!(
        unlock_biometric(dir.path(), &[0; 32]),
        Err(Error::InvalidBiometric)
    ));
    let store = unlock_biometric(dir.path(), &key).unwrap();
    assert_eq!(store.device_seed(), &[7; 32]);
    drop(store);
    assert!(clear_biometric(dir.path()).unwrap());
    assert!(!clear_biometric(dir.path()).unwrap());
    assert!(biometric_token(dir.path()).unwrap().is_none());
}

/// Appends one row timed `time` whose bytes are its time.
fn row(store: &Unlocked, time: u64, keep_from: u64, budget: Budget) -> u64 {
    let text = time.to_string();
    store
        .activity_append([(time, text.as_bytes())], keep_from, budget)
        .unwrap()[0]
}

#[test]
fn activity_lists_newest_first_and_old_rows_go() {
    let dir = tempfile::tempdir().unwrap();
    let store = init_with_params(dir.path(), b"pass", &[1; 32], FAST).unwrap();
    assert!(store.activity_list(0, None, 10).unwrap().rows.is_empty());
    let ids = store
        .activity_append([(10, &b"10"[..]), (20, b"20"), (30, b"30")], 0, ROOMY)
        .unwrap();
    assert_eq!(ids, [0, 1, 2]);
    let page = store.activity_list(15, None, 10).unwrap();
    let seen: Vec<_> = page.rows.iter().map(|r| (r.id, &r.bytes[..])).collect();
    assert_eq!(seen, [(2, &b"30"[..]), (1, b"20")]);
    let older = store.activity_list(0, Some(2), 10).unwrap();
    assert_eq!(older.rows.iter().map(|r| r.id).collect::<Vec<_>>(), [1, 0]);
    assert_eq!(row(&store, 40, 25, ROOMY), 3);
    assert_eq!(rows(&store), ["40", "30"]);
    assert_eq!(
        store.activity_list(0, None, 10).unwrap().dropped,
        None,
        "aged, not dropped"
    );
    drop(store);
    let store = unlock(dir.path(), b"pass").unwrap();
    assert_eq!(rows(&store), ["40", "30"]);
    assert_eq!(row(&store, 50, 0, ROOMY), 4);
}

#[test]
fn activity_keeps_to_its_budget_across_chunks_and_unlocks() {
    let dir = tempfile::tempdir().unwrap();
    let store = init_with_params(dir.path(), b"pass", &[1; 32], FAST).unwrap();
    let three = Budget {
        rows: 3,
        bytes: 1 << 20,
    };
    for time in 1..=5 {
        row(&store, time, 0, three);
    }
    assert_eq!(rows(&store), ["5", "4", "3"]);
    let dropped = Dropped {
        count: 2,
        last_id: 1,
        last_time: 2,
    };
    assert_eq!(
        store.activity_list(0, None, 10).unwrap().dropped,
        Some(dropped)
    );
    assert_eq!(store.activity_list(0, None, 2).unwrap().dropped, None);
    assert_eq!(
        store.activity_list(0, Some(3), 2).unwrap().dropped,
        Some(dropped)
    );
    assert_eq!(store.activity_list(3, None, 10).unwrap().dropped, None);
    // Enough rows to fill several chunks: old chunks go, the floor stays.
    let many = Budget {
        rows: 10,
        bytes: 1 << 20,
    };
    for time in 6..1500 {
        row(&store, time, 0, many);
    }
    assert_eq!(rows(&store).len(), 10);
    drop(store);
    let store = unlock(dir.path(), b"pass").unwrap();
    let want: Vec<String> = (1490..1500).rev().map(|t: u64| t.to_string()).collect();
    assert_eq!(rows(&store), want);
    let page = store.activity_list(0, None, 100).unwrap();
    assert_eq!(page.dropped.unwrap().count, 1500 - 1 - 10);
    let chunks = fs::read_dir(dir.path().join("device"))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("activity-")
        })
        .count();
    assert!(chunks <= 2, "{chunks} chunks left");
    // However big, the newest row stays.
    let small = Budget {
        rows: 1_000,
        bytes: 400,
    };
    store
        .activity_append([(2000, &[b'x'; 1_000][..])], 0, small)
        .unwrap();
    assert_eq!(rows(&store).len(), 1);
}
