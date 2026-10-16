use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use tempfile::TempDir;

use crate::kdf::KdfHeader;
use crate::store as raw;
use crate::{DB_FILE, EntryHash, Error, KdfParams, Unlocked};

// Minimum Argon2 cost so tests stay fast; the default profile is covered by
// `default_kdf_params_roundtrip`.
const FAST: KdfParams = KdfParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const PASS: &[u8] = b"correct horse battery staple";
const SECRET: [u8; 32] = [0x5a; 32];

fn init(dir: &Path) -> Unlocked {
    crate::init_with_params(dir, PASS, SECRET, FAST).unwrap()
}

fn unlock(dir: &Path) -> Unlocked {
    crate::unlock(dir, PASS).unwrap()
}

fn hash(n: u64) -> EntryHash {
    *blake3::hash(&n.to_le_bytes()).as_bytes()
}

fn body(n: u64) -> Vec<u8> {
    format!("entry number {n} ")
        .repeat(1 + (n as usize % 7))
        .into_bytes()
}

/// Appends one entry; `false` if its hash is already stored.
fn append(store: &Unlocked, hash: &EntryHash, bytes: &[u8]) -> Result<bool, Error> {
    Ok(store.append_batch([(hash, bytes)])? == 1)
}

fn all(store: &Unlocked) -> Vec<(EntryHash, Vec<u8>)> {
    store
        .iter_all()
        .unwrap()
        .map(|r| r.map(|(h, b)| (h, b.to_vec())))
        .collect::<Result<_, _>>()
        .unwrap()
}

fn db_path(dir: &Path) -> PathBuf {
    dir.join(DB_FILE)
}

/// Reads a raw (still encrypted) value straight out of redb.
fn raw_value<K: redb::Key + 'static>(
    dir: &Path,
    table: TableDefinition<K, &'static [u8]>,
    key: K::SelfType<'_>,
) -> Vec<u8> {
    let db = redb::Database::open(db_path(dir)).unwrap();
    let txn = db.begin_read().unwrap();
    let t = txn.open_table(table).unwrap();
    t.get(key).unwrap().unwrap().value().to_vec()
}

/// Flips one byte inside every on-disk occurrence of `needle`.
fn flip_on_disk(dir: &Path, needle: &[u8]) {
    let path = db_path(dir);
    let mut file = std::fs::read(&path).unwrap();
    let mut hits = 0;
    let mut i = 0;
    while i + needle.len() <= file.len() {
        if &file[i..i + needle.len()] == needle {
            file[i + needle.len() / 2] ^= 0x01;
            hits += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    assert!(hits > 0, "needle not found on disk");
    std::fs::write(&path, file).unwrap();
}

fn mutate_raw(dir: &Path, f: impl FnOnce(&redb::WriteTransaction)) {
    let db = redb::Database::open(db_path(dir)).unwrap();
    let txn = db.begin_write().unwrap();
    f(&txn);
    txn.commit().unwrap();
}

#[test]
fn roundtrip() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("nested/data");
    assert!(!crate::is_initialized(&dir));
    let store = init(&dir);
    assert!(crate::is_initialized(&dir));
    assert_eq!(store.device_secret(), &SECRET);
    assert!(all(&store).is_empty());

    for n in 0..20 {
        assert!(append(&store, &hash(n), &body(n)).unwrap());
    }
    assert!(append(&store, &hash(100), b"").unwrap());

    let entries = all(&store);
    assert_eq!(entries.len(), 21);
    for (n, (h, b)) in entries.iter().take(20).enumerate() {
        assert_eq!(h, &hash(n as u64));
        assert_eq!(b, &body(n as u64));
    }
    assert_eq!(entries[20], (hash(100), Vec::new()));

    store.meta_set("vault_id", b"v-123").unwrap();
    store.meta_set("theme", b"dark").unwrap();
    store.meta_set("theme", b"light").unwrap();
    assert_eq!(
        store.meta_get("vault_id").unwrap().unwrap().as_slice(),
        b"v-123"
    );
    assert_eq!(
        store.meta_get("theme").unwrap().unwrap().as_slice(),
        b"light"
    );
    assert!(store.meta_get("missing").unwrap().is_none());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&db_path(&dir)), 0o600);
    }
    // Only the database file remains; the init temp file is gone.
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

    drop(store);
    let store = unlock(&dir);
    assert_eq!(store.device_secret(), &SECRET);
    assert_eq!(all(&store), entries);
    assert_eq!(
        store.meta_get("vault_id").unwrap().unwrap().as_slice(),
        b"v-123"
    );
}

#[test]
fn plaintext_never_on_disk() {
    let tmp = TempDir::new().unwrap();
    let store = init(tmp.path());
    let marker = b"SUPER-SECRET-PASSWORD-MARKER";
    append(&store, &hash(1), marker).unwrap();
    store.meta_set("vault_name", marker).unwrap();
    drop(store);
    let file = std::fs::read(db_path(tmp.path())).unwrap();
    let contains = |needle: &[u8]| file.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(marker));
    assert!(!contains(b"vault_name"));
    assert!(!contains(&hash(1)));
    assert!(!contains(&SECRET));
}

#[test]
fn duplicate_appends_are_skipped() {
    let tmp = TempDir::new().unwrap();
    let store = init(tmp.path());
    assert!(append(&store, &hash(1), b"one").unwrap());
    assert!(!append(&store, &hash(1), b"other").unwrap());
    let (h2, h3) = (hash(2), hash(3));
    let added = store
        .append_batch([
            (&hash(1), &b"x"[..]),
            (&h2, &b"two"[..]),
            (&h2, &b"two again"[..]),
            (&h3, &b"three"[..]),
        ])
        .unwrap();
    assert_eq!(added, 2);
    assert_eq!(store.append_batch([]).unwrap(), 0);
    assert_eq!(
        all(&store),
        [
            (hash(1), b"one".to_vec()),
            (h2, b"two".to_vec()),
            (h3, b"three".to_vec())
        ]
    );
}

#[test]
fn reopen_after_append() {
    let tmp = TempDir::new().unwrap();
    drop(init(tmp.path()));
    for round in 0..5u64 {
        let store = unlock(tmp.path());
        assert_eq!(all(&store).len() as u64, round * 10);
        for n in round * 10..round * 10 + 10 {
            append(&store, &hash(n), &body(n)).unwrap();
        }
    }
    let store = unlock(tmp.path());
    let entries = all(&store);
    assert_eq!(entries.len(), 50);
    for (n, (h, b)) in entries.into_iter().enumerate() {
        assert_eq!(h, hash(n as u64));
        assert_eq!(b, body(n as u64));
    }
}

#[test]
fn wrong_passphrase() {
    let tmp = TempDir::new().unwrap();
    drop(init(tmp.path()));
    assert!(matches!(
        crate::unlock(tmp.path(), b"wrong"),
        Err(Error::WrongPassphrase)
    ));
    assert!(matches!(
        crate::unlock(tmp.path(), b""),
        Err(Error::WrongPassphrase)
    ));
    // A failed attempt releases the file and leaves the store usable.
    assert_eq!(unlock(tmp.path()).device_secret(), &SECRET);
}

#[test]
fn missing_store() {
    let tmp = TempDir::new().unwrap();
    assert!(matches!(
        crate::unlock(tmp.path(), PASS),
        Err(Error::NotInitialized(_))
    ));
    assert!(matches!(
        crate::unlock(&tmp.path().join("nope"), PASS),
        Err(Error::NotInitialized(_))
    ));
}

#[test]
fn init_over_existing_refused() {
    let tmp = TempDir::new().unwrap();
    let store = init(tmp.path());
    append(&store, &hash(1), b"keep me").unwrap();
    drop(store);
    let before = std::fs::read(db_path(tmp.path())).unwrap();

    let err = crate::init_with_params(tmp.path(), b"other", [1; 32], FAST).unwrap_err();
    assert!(matches!(err, Error::AlreadyExists(_)), "{err:?}");
    assert_eq!(std::fs::read(db_path(tmp.path())).unwrap(), before);
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);

    let store = unlock(tmp.path());
    assert_eq!(store.device_secret(), &SECRET);
    assert_eq!(all(&store), [(hash(1), b"keep me".to_vec())]);
}

#[test]
fn init_refuses_while_open() {
    let tmp = TempDir::new().unwrap();
    let _store = init(tmp.path());
    assert!(matches!(
        crate::init_with_params(tmp.path(), PASS, SECRET, FAST),
        Err(Error::AlreadyExists(_))
    ));
}

#[test]
fn second_open_is_in_use() {
    let tmp = TempDir::new().unwrap();
    let store = init(tmp.path());
    assert!(matches!(crate::unlock(tmp.path(), PASS), Err(Error::InUse)));
    drop(store);
    drop(unlock(tmp.path()));
}

#[test]
fn change_passphrase() {
    let tmp = TempDir::new().unwrap();
    let store = init(tmp.path());
    append(&store, &hash(1), b"data").unwrap();
    store.meta_set("k", b"v").unwrap();

    assert!(matches!(
        store.change_passphrase(b"not it", b"new"),
        Err(Error::WrongPassphrase)
    ));
    store.change_passphrase(PASS, b"new pass").unwrap();
    // The open handle keeps working.
    append(&store, &hash(2), b"more").unwrap();
    drop(store);

    assert!(matches!(
        crate::unlock(tmp.path(), PASS),
        Err(Error::WrongPassphrase)
    ));
    let store = crate::unlock(tmp.path(), b"new pass").unwrap();
    assert_eq!(store.device_secret(), &SECRET);
    assert_eq!(
        all(&store),
        vec![(hash(1), b"data".to_vec()), (hash(2), b"more".to_vec())]
    );
    assert_eq!(store.meta_get("k").unwrap().unwrap().as_slice(), b"v");
    assert_eq!(store.kdf_params().unwrap(), FAST);

    let stronger = KdfParams {
        m_cost_kib: 64,
        t_cost: 2,
        p_cost: 2,
    };
    store
        .change_passphrase_with_params(b"new pass", b"new pass", stronger)
        .unwrap();
    assert_eq!(store.kdf_params().unwrap(), stronger);
    drop(store);
    let store = crate::unlock(tmp.path(), b"new pass").unwrap();
    assert_eq!(store.kdf_params().unwrap(), stronger);
    assert_eq!(all(&store).len(), 2);
}

/// Rewrites one stored value with a byte flipped, through redb, so page
/// checksums stay valid and only the AEAD layer can notice.
fn flip_value<K: redb::Key + 'static>(
    dir: &Path,
    table: TableDefinition<K, &'static [u8]>,
    key: K::SelfType<'_>,
    index: usize,
) where
    for<'a> K::SelfType<'a>: Clone,
{
    mutate_raw(dir, |txn| {
        let mut t = txn.open_table(table).unwrap();
        let mut value = t.get(key.clone()).unwrap().unwrap().value().to_vec();
        value[index] ^= 0x01;
        t.insert(key, value.as_slice()).unwrap();
    });
}

fn store_with_entries(n: u64) -> TempDir {
    let tmp = TempDir::new().unwrap();
    let store = init(tmp.path());
    for i in 0..n {
        append(&store, &hash(i), &body(i)).unwrap();
    }
    store.meta_set("vault_id", b"v-1").unwrap();
    tmp
}

#[test]
fn flipped_byte_on_disk_fails_unlock() {
    let raws: [fn(&Path) -> Vec<u8>; 3] = [
        |dir| raw_value(dir, raw::LOG, 2)[24..].to_vec(),
        |dir| raw_value(dir, raw::HEADER, "keyset"),
        |dir| raw_value(dir, raw::HEADER, "log_len"),
    ];
    for raw in raws {
        let tmp = store_with_entries(5);
        let needle = raw(tmp.path());
        flip_on_disk(tmp.path(), &needle);
        let err = crate::unlock(tmp.path(), PASS).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
    }
}

#[test]
fn tampered_log_entry() {
    for index in [0, 24, 40, 70] {
        // nonce, first ciphertext byte, hash region, payload region
        let tmp = store_with_entries(5);
        flip_value(tmp.path(), raw::LOG, 2, index);

        let store = unlock(tmp.path());
        let results: Vec<_> = store.iter_all().unwrap().collect();
        assert_eq!(results.len(), 3, "two good entries, then one error");
        assert!(results[0].is_ok() && results[1].is_ok());
        assert!(matches!(results[2], Err(Error::Corrupt(_))));
    }
    // Last byte = tag.
    let tmp = store_with_entries(3);
    let len = raw_value(tmp.path(), raw::LOG, 0).len();
    flip_value(tmp.path(), raw::LOG, 0, len - 1);
    assert!(matches!(
        unlock(tmp.path()).iter_all().unwrap().next(),
        Some(Err(Error::Corrupt(_)))
    ));
}

#[test]
fn tampered_keyset() {
    for index in [0, 30, 87] {
        let tmp = store_with_entries(1);
        flip_value(tmp.path(), raw::HEADER, "keyset", index);
        assert!(matches!(
            crate::unlock(tmp.path(), PASS),
            Err(Error::WrongPassphrase)
        ));
    }
}

#[test]
fn tampered_log_len() {
    let tmp = store_with_entries(3);
    flip_value(tmp.path(), raw::HEADER, "log_len", 30);
    let store = unlock(tmp.path());
    assert!(matches!(store.iter_all(), Err(Error::Corrupt(_))));
    assert!(matches!(
        append(&store, &hash(9), b""),
        Err(Error::Corrupt(_))
    ));
}

#[test]
fn tampered_kdf_params() {
    let tmp = TempDir::new().unwrap();
    drop(init(tmp.path()));
    // Raise t_cost on disk: AAD binding makes the key set fail to open.
    mutate_raw(tmp.path(), |txn| {
        let mut t = txn.open_table(raw::HEADER).unwrap();
        let mut kdf = t.get("kdf").unwrap().unwrap().value().to_vec();
        kdf[5] = 2;
        t.insert("kdf", kdf.as_slice()).unwrap();
    });
    assert!(matches!(
        crate::unlock(tmp.path(), PASS),
        Err(Error::WrongPassphrase)
    ));
    // Absurd memory cost is rejected before Argon2 tries to allocate it.
    mutate_raw(tmp.path(), |txn| {
        let mut t = txn.open_table(raw::HEADER).unwrap();
        let mut kdf = t.get("kdf").unwrap().unwrap().value().to_vec();
        kdf[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
        t.insert("kdf", kdf.as_slice()).unwrap();
    });
    assert!(matches!(
        crate::unlock(tmp.path(), PASS),
        Err(Error::Corrupt(_))
    ));
}

#[test]
fn tampered_meta() {
    let tmp = TempDir::new().unwrap();
    let store = init(tmp.path());
    store.meta_set("a", b"value a").unwrap();
    store.meta_set("b", b"value b").unwrap();
    let (blind_a, blind_b) = (
        store.keys_for_test().meta_blind("a"),
        store.keys_for_test().meta_blind("b"),
    );
    drop(store);

    // Swapping two values between names is detected.
    mutate_raw(tmp.path(), |txn| {
        let mut t = txn.open_table(raw::META).unwrap();
        let a = t.get(&blind_a).unwrap().unwrap().value().to_vec();
        let b = t.get(&blind_b).unwrap().unwrap().value().to_vec();
        t.insert(&blind_a, b.as_slice()).unwrap();
        t.insert(&blind_b, a.as_slice()).unwrap();
    });
    let store = unlock(tmp.path());
    assert!(matches!(store.meta_get("a"), Err(Error::Corrupt(_))));
    store.meta_set("a", b"fresh").unwrap();
    assert_eq!(store.meta_get("a").unwrap().unwrap().as_slice(), b"fresh");
    drop(store);

    flip_value(tmp.path(), raw::META, &blind_a, 30);
    let store = unlock(tmp.path());
    assert!(matches!(store.meta_get("a"), Err(Error::Corrupt(_))));
}

#[test]
fn deleted_swapped_or_truncated_entries_detected() {
    let setup = || {
        let tmp = TempDir::new().unwrap();
        let store = init(tmp.path());
        for n in 0..4 {
            append(&store, &hash(n), &body(n)).unwrap();
        }
        tmp
    };
    let fails = |dir: &Path| {
        let store = unlock(dir);
        store
            .iter_all()
            .unwrap()
            .any(|r| matches!(r, Err(Error::Corrupt(_))))
    };

    // Delete a middle entry.
    let tmp = setup();
    mutate_raw(tmp.path(), |txn| {
        txn.open_table(raw::LOG).unwrap().remove(1).unwrap();
    });
    assert!(fails(tmp.path()));

    // Delete the last entry. Appending must refuse rather than reuse its slot.
    let tmp = setup();
    mutate_raw(tmp.path(), |txn| {
        txn.open_table(raw::LOG).unwrap().remove(3).unwrap();
    });
    assert!(fails(tmp.path()));
    assert!(matches!(
        append(&unlock(tmp.path()), &hash(9), b""),
        Err(Error::Corrupt(_))
    ));

    // Swap two entries.
    let tmp = setup();
    mutate_raw(tmp.path(), |txn| {
        let mut t = txn.open_table(raw::LOG).unwrap();
        let a = t.get(0).unwrap().unwrap().value().to_vec();
        let b = t.get(1).unwrap().unwrap().value().to_vec();
        t.insert(0, b.as_slice()).unwrap();
        t.insert(1, a.as_slice()).unwrap();
    });
    assert!(fails(tmp.path()));
}

/// Flip bytes all over the file: every outcome must be an error or the
/// original data, never different data and never a panic.
#[test]
fn random_bit_flips_never_yield_garbage() {
    let tmp = TempDir::new().unwrap();
    let store = init(tmp.path());
    for n in 0..30 {
        append(&store, &hash(n), &body(n)).unwrap();
    }
    store.meta_set("vault_id", b"abc").unwrap();
    let expected = all(&store);
    drop(store);
    let pristine = std::fs::read(db_path(tmp.path())).unwrap();

    let check = |dir: &Path| -> Result<(), Error> {
        let store = crate::unlock(dir, PASS)?;
        assert_eq!(store.device_secret(), &SECRET);
        let got = store
            .iter_all()?
            .map(|r| r.map(|(h, b)| (h, b.to_vec())))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(got, expected);
        if let Some(v) = store.meta_get("vault_id")? {
            assert_eq!(v.as_slice(), b"abc");
        }
        Ok(())
    };

    // Most of the file is preallocated zeros; aim at the bytes in use.
    let used: Vec<usize> = (0..pristine.len()).filter(|&i| pristine[i] != 0).collect();
    let step = (used.len() / 1500).max(1);
    let (mut ok, mut err) = (0, 0);
    for &pos in used.iter().step_by(step) {
        let mut file = pristine.clone();
        file[pos] ^= 0x40;
        std::fs::write(db_path(tmp.path()), &file).unwrap();
        let outcome = std::panic::catch_unwind(|| check(tmp.path()));
        match outcome {
            Ok(Ok(())) => ok += 1,
            Ok(Err(_)) => err += 1,
            Err(_) => panic!("panic or wrong data after flipping byte {pos}"),
        }
    }
    assert!(err > 0, "expected some flips to be detected");
    eprintln!("bit flips: {ok} harmless, {err} detected");
}

#[test]
fn survives_kill_mid_write() {
    let tmp = TempDir::new().unwrap();
    drop(init(tmp.path()));
    for round in 0..4u64 {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "tests::crash_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("DEADBOLT_STORE_CRASH_DIR", tmp.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        assert!(
            lines.any(|l| l.unwrap().contains("crash-child-writing")),
            "child never started"
        );
        std::thread::sleep(Duration::from_millis(30 + round * 40));
        child.kill().unwrap();
        child.wait().unwrap();

        // `all` fails unless the entries match the sealed log length.
        let entries = all(&unlock(tmp.path()));
        for (n, (h, b)) in entries.iter().enumerate() {
            assert_eq!(h, &hash(n as u64));
            assert_eq!(b, &body(n as u64));
        }
    }
    assert!(
        !all(&unlock(tmp.path())).is_empty(),
        "child never committed anything"
    );
}

/// Helper process for `survives_kill_mid_write`; a no-op unless spawned by it.
#[test]
fn crash_child() {
    let Some(dir) = std::env::var_os("DEADBOLT_STORE_CRASH_DIR") else {
        return;
    };
    let store = unlock(Path::new(&dir));
    println!("crash-child-writing");
    let mut n = all(&store).len() as u64;
    loop {
        let batch: Vec<_> = (n..n + 1 + n % 5).map(|i| (hash(i), body(i))).collect();
        n += store
            .append_batch(batch.iter().map(|(h, b)| (h, b.as_slice())))
            .unwrap() as u64;
        store.meta_set("last", &n.to_le_bytes()).unwrap();
    }
}

#[test]
fn default_kdf_params_roundtrip() {
    let tmp = TempDir::new().unwrap();
    drop(crate::init(tmp.path(), PASS, SECRET).unwrap());
    let kdf = KdfHeader::decode(&raw_value(tmp.path(), raw::HEADER, "kdf")).unwrap();
    assert_eq!(kdf.params, KdfParams::DEFAULT);
    assert_eq!(unlock(tmp.path()).device_secret(), &SECRET);
}

#[test]
fn kdf_header_encoding() {
    let header = KdfHeader::generate(FAST).unwrap();
    let decoded = KdfHeader::decode(&header.encode()).unwrap();
    assert!(decoded == header);
    assert!(KdfHeader::decode(&header.encode()[1..]).is_err());
    let mut bad_alg = header.encode();
    bad_alg[0] = 9;
    assert!(KdfHeader::decode(&bad_alg).is_err());
    // Different salts give different keys for the same passphrase.
    let other = KdfHeader::generate(FAST).unwrap();
    assert_ne!(*header.derive(PASS).unwrap(), *other.derive(PASS).unwrap());
    assert_eq!(
        *header.derive(PASS).unwrap(),
        *decoded.derive(PASS).unwrap()
    );
    assert!(matches!(
        crate::init_with_params(
            Path::new("/nonexistent/never"),
            PASS,
            SECRET,
            KdfParams {
                m_cost_kib: 1,
                t_cost: 1,
                p_cost: 1
            },
        ),
        Err(Error::InvalidKdfParams(_))
    ));
}
