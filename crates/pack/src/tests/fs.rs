use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use super::{EPOCH_KEY, frame, keys_for, logical, pack_input, secret_of};
use crate::{BlockReader, Blocks, Error, FsBlocks, Result, VaultDir, VaultReader, log};

fn temp() -> (tempfile::TempDir, FsBlocks) {
    let dir = tempfile::tempdir().unwrap();
    let blocks = FsBlocks::open(dir.path().join("v").join("vault")).unwrap();
    (dir, blocks)
}

/// Files are `0600` and directories `0700`, whatever the umask allows more.
#[cfg(unix)]
#[test]
fn fs_blocks_keep_files_and_directories_private() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, blocks) = temp();
    blocks.create_new("gen-1.pack", b"abc").unwrap();
    blocks.append_sync("wal-0.log", b"12").unwrap();
    blocks.create_new("blob/abcd", b"blob").unwrap();
    let _lock = blocks.try_lock_writer().unwrap();
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let root = dir.path().join("v");
    for path in [root.clone(), root.join("vault"), root.join("vault/blob")] {
        assert_eq!(mode(&path), 0o700, "{}", path.display());
    }
    for name in ["gen-1.pack", "wal-0.log", "blob/abcd", "LOCK"] {
        assert_eq!(mode(&root.join("vault").join(name)), 0o600, "{name}");
    }
}

#[test]
fn fs_blocks_create_append_read_list_delete_truncate() {
    let (_dir, blocks) = temp();
    blocks.create_new("gen-1.pack", b"abc").unwrap();
    assert!(matches!(
        blocks.create_new("gen-1.pack", b"x"),
        Err(Error::AlreadyExists { .. })
    ));
    assert_eq!(blocks.read_all("gen-1.pack").unwrap(), b"abc");

    assert_eq!(blocks.append_sync("wal-0.log", b"12").unwrap(), 0);
    assert_eq!(blocks.append_sync("wal-0.log", b"345").unwrap(), 2);
    assert_eq!(blocks.read_range("wal-0.log", 1, 3).unwrap(), b"234");
    assert!(matches!(
        blocks.read_range("wal-0.log", 3, 5),
        Err(Error::OutOfRange { .. })
    ));

    blocks.create_new("blob/abcd", b"blob").unwrap();
    assert_eq!(blocks.list_prefix("blob/").unwrap(), ["blob/abcd"]);
    assert_eq!(blocks.list_prefix("wal-").unwrap(), ["wal-0.log"]);
    let _lock = blocks.try_lock_writer().unwrap();
    assert_eq!(
        blocks.list_prefix("").unwrap(),
        ["gen-1.pack", "wal-0.log"],
        "LOCK is never listed"
    );
    assert!(blocks.list_prefix("outbox/").unwrap().is_empty());

    blocks.truncate_tail("wal-0.log", 2).unwrap();
    assert_eq!(blocks.read_all("wal-0.log").unwrap(), b"12");
    assert!(matches!(
        blocks.truncate_tail("wal-0.log", 10),
        Err(Error::InvalidTruncate { .. })
    ));

    assert!(blocks.delete("gen-1.pack").unwrap());
    assert!(!blocks.delete("gen-1.pack").unwrap());
    assert!(matches!(
        blocks.read_all("gen-1.pack"),
        Err(Error::NotFound { .. })
    ));
    assert!(matches!(
        blocks.create_new("../escape", b""),
        Err(Error::InvalidName { .. })
    ));
}

#[test]
fn the_writer_lock_is_exclusive() {
    let (dir, blocks) = temp();
    let other = FsBlocks::open(dir.path().join("v").join("vault")).unwrap();
    let (writer, _) = VaultDir::open(blocks).unwrap();
    assert!(matches!(VaultDir::open(other), Err(Error::Locked)));
    drop(writer);
    let again = FsBlocks::open(dir.path().join("v").join("vault")).unwrap();
    assert!(VaultDir::open(again).is_ok());
}

#[test]
fn an_open_handle_outlives_a_delete() {
    let (_dir, blocks) = temp();
    blocks.create_new("gen-1.pack", b"immutable").unwrap();
    let reader = blocks.open_read("gen-1.pack").unwrap();
    assert!(blocks.delete("gen-1.pack").unwrap());
    assert_eq!(reader.read_all().unwrap(), b"immutable");
    assert_eq!(reader.read_range(2, 3).unwrap(), b"mut");
    // Names are never reused, but nothing stops a new file under another.
    blocks.create_new("gen-2.pack", b"next").unwrap();
}

#[test]
fn readers_see_every_committed_frame_while_the_writer_compacts() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let committed = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));

    let writer = {
        let (root, committed, done) = (root.clone(), committed.clone(), done.clone());
        thread::spawn(move || -> Result<()> {
            let (mut vault, _) = VaultDir::open(FsBlocks::open(root)?)?;
            let mut frames = Vec::new();
            for round in 0..12 {
                for j in 0..4 {
                    let frame = frame(round * 4 + j);
                    vault.append_wal(&frame)?;
                    frames.push(frame);
                    committed.store(frames.len(), Ordering::SeqCst);
                }
                let split = frames.len() - 2;
                vault.compact(pack_input(&frames[..split]), &EPOCH_KEY, &frames[split..])?;
            }
            done.store(true, Ordering::SeqCst);
            Ok(())
        })
    };
    let readers: Vec<_> = (0..3)
        .map(|_| {
            let (root, committed, done) = (root.clone(), committed.clone(), done.clone());
            thread::spawn(move || -> Result<usize> {
                let blocks = FsBlocks::open(root)?;
                let mut snapshots = 0;
                while !done.load(Ordering::SeqCst) || snapshots == 0 {
                    let floor = committed.load(Ordering::SeqCst);
                    let reader = VaultReader::open(&blocks)?;
                    let seen = logical(reader.pack(), &reader.wal()?);
                    for i in 0..floor {
                        assert!(
                            seen.contains(&frame(i)),
                            "frame {i} missing from a snapshot taken at {floor}"
                        );
                    }
                    if let Some(pack) = reader.pack() {
                        let keys = keys_for(pack);
                        let index = pack.read_index(&keys)?;
                        if let Some(item) = index.items().first() {
                            let head = pack.read_head(&keys, item)?;
                            let frame = &head[b"head:".len()..];
                            let hit = index.lookup_by_key(&keys, frame)[0];
                            assert_eq!(&pack.read_secret(&keys, &hit)?[..], secret_of(frame));
                        }
                    }
                    snapshots += 1;
                }
                Ok(snapshots)
            })
        })
        .collect();
    writer.join().unwrap().unwrap();
    for reader in readers {
        assert!(reader.join().unwrap().unwrap() > 0);
    }
    let reader = VaultReader::open(&FsBlocks::open(&root).unwrap()).unwrap();
    assert_eq!(logical(reader.pack(), &reader.wal().unwrap()).len(), 48);
}

#[test]
fn a_failed_partial_append_leaves_nothing_behind_for_the_retry() {
    let (dir, blocks) = temp();
    let root = dir.path().join("v").join("vault");
    let (vault, _) = VaultDir::open(blocks).unwrap();
    for i in 0..3 {
        vault.append_wal(&frame(i)).unwrap();
    }
    let wal = vault.active_wal();
    let before = vault.blocks().read_all(&wal).unwrap();
    for landed in [1, 7, log::RECORD_OVERHEAD + 3] {
        vault.blocks().fail_next_append(landed);
        assert!(matches!(
            vault.append_wal(&frame(99)),
            Err(Error::Io { .. })
        ));
        assert_eq!(
            vault.blocks().read_all(&wal).unwrap(),
            before,
            "{landed} landed bytes were cut back"
        );
    }
    // The retry lands on a record boundary.
    vault.append_wal(&frame(99)).unwrap();
    drop(vault);

    let expected: Vec<Vec<u8>> = [0, 1, 2, 99].into_iter().map(frame).collect();
    let reader = VaultReader::open(&FsBlocks::open(&root).unwrap()).unwrap();
    assert_eq!(reader.wal().unwrap(), expected);
    let (_, loaded) = VaultDir::open(FsBlocks::open(&root).unwrap()).unwrap();
    assert_eq!(loaded.wal, expected);
}
