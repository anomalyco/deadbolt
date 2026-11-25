use std::collections::BTreeSet;

use super::{EPOCH_KEY, frame, logical, pack_input};
use crate::{Error, MemBlocks, Result, VaultDir, VaultReader};

fn members() -> Vec<Vec<u8>> {
    vec![b"member-0".to_vec(), b"member-1".to_vec()]
}

/// A directory holding frames 0..9: with `compacted`, gen-1 covers 0..4,
/// wal-1 carries 4..6 and 6..9 came after; without, all nine are in wal-0.
fn base(compacted: bool) -> (MemBlocks, BTreeSet<Vec<u8>>) {
    let blocks = MemBlocks::new();
    let (mut dir, _) = VaultDir::open(blocks.clone()).unwrap();
    for member in members() {
        dir.append_member(&member).unwrap();
    }
    let frames: Vec<Vec<u8>> = (0..9).map(frame).collect();
    if compacted {
        for frame in &frames[..6] {
            dir.append_wal(frame).unwrap();
        }
        dir.compact(pack_input(&frames[..4]), &EPOCH_KEY, &frames[4..6])
            .unwrap();
        for frame in &frames[6..] {
            dir.append_wal(frame).unwrap();
        }
        assert_eq!(blocks.names(), ["gen-1.pack", "members.log", "wal-1.log"]);
    } else {
        for frame in &frames {
            dir.append_wal(frame).unwrap();
        }
    }
    drop(dir);
    (blocks.reboot(), frames.into_iter().collect())
}

/// Opens and compacts: all but the last two frames into the pack, those two
/// carried into the new WAL.
fn compact_all(blocks: &MemBlocks) -> Result<()> {
    let (mut dir, loaded) = VaultDir::open(blocks.clone())?;
    let all: Vec<Vec<u8>> = logical(loaded.pack.as_ref(), &loaded.wal)
        .into_iter()
        .collect();
    let split = all.len().saturating_sub(2);
    dir.compact(pack_input(&all[..split]), &EPOCH_KEY, &all[split..])?;
    Ok(())
}

/// W3 opens exactly `expected`, for the writer and for a lock-free reader.
fn check_open(blocks: &MemBlocks, expected: &BTreeSet<Vec<u8>>, ctx: &str) {
    let (dir, loaded) = VaultDir::open(blocks.clone()).unwrap_or_else(|err| panic!("{ctx}: {err}"));
    assert_eq!(loaded.members, members(), "{ctx}");
    assert_eq!(
        &logical(loaded.pack.as_ref(), &loaded.wal),
        expected,
        "{ctx}"
    );
    drop(dir);
    let reader = VaultReader::open(blocks).unwrap();
    assert_eq!(reader.members().unwrap(), members(), "{ctx}: reader");
    assert_eq!(
        &logical(reader.pack(), &reader.wal().unwrap()),
        expected,
        "{ctx}: reader"
    );
}

/// Power cuts that land none, some or all of a write's bytes.
const KEEPS: [Option<usize>; 8] = [
    None,
    Some(0),
    Some(1),
    Some(4),
    Some(13),
    Some(140),
    Some(400),
    Some(usize::MAX),
];

fn crash_matrix(compacted: bool) -> usize {
    let (base, expected) = base(compacted);
    let probe = base.reboot();
    compact_all(&probe).unwrap();
    let ops = probe.ops();
    // generation, wal, then a delete per older generation and WAL.
    assert_eq!(ops, if compacted { 4 } else { 3 });
    check_open(&probe, &expected, "no crash");

    let mut cases = 0;
    for op in 0..ops {
        for keep in KEEPS {
            let ctx = format!("compacted={compacted}, crash at op {op} keeping {keep:?}");
            let blocks = base.reboot();
            blocks.crash_at(op, keep);
            assert!(matches!(compact_all(&blocks), Err(Error::Crashed)), "{ctx}");
            let after = blocks.reboot();
            check_open(&after, &expected, &ctx);

            // The directory keeps working: append, compact, reopen.
            let (dir, _) = VaultDir::open(after.clone()).unwrap();
            dir.append_wal(&frame(100)).unwrap();
            drop(dir);
            compact_all(&after).unwrap();
            let mut more = expected.clone();
            more.insert(frame(100));
            check_open(&after, &more, &format!("{ctx}, then compacted again"));
            let names = after.names();
            let count = |prefix: &str| names.iter().filter(|name| name.starts_with(prefix)).count();
            assert_eq!(
                (count("gen-"), count("wal-")),
                (1, 1),
                "{ctx}: old generations cleaned up: {names:?}"
            );
            cases += 1;
        }
    }
    cases
}

#[test]
fn a_crash_at_every_compaction_step_loses_no_frame() {
    assert_eq!(crash_matrix(true), 4 * KEEPS.len());
}

#[test]
fn a_crash_during_the_first_compaction_loses_no_frame() {
    assert_eq!(crash_matrix(false), 3 * KEEPS.len());
}

#[test]
fn the_named_compaction_crash_states_open_correctly() {
    let (base, expected) = base(true);

    // A pack cut short mid-write is skipped, and its number never reused.
    let blocks = base.reboot();
    blocks.crash_at(0, Some(200));
    assert!(compact_all(&blocks).is_err());
    let after = blocks.reboot();
    let (dir, loaded) = VaultDir::open(after.clone()).unwrap();
    assert_eq!(
        (loaded.generation, loaded.skipped.as_slice()),
        (Some(1), [2].as_slice())
    );
    assert_eq!(dir.next_generation(), 3);
    assert_eq!(dir.active_wal(), "wal-1.log");
    drop(dir);
    check_open(&after, &expected, "partial gen-2");

    // A complete pack with no new WAL: the old WAL still holds the tail.
    let blocks = base.reboot();
    blocks.crash_at(1, None);
    assert!(compact_all(&blocks).is_err());
    let after = blocks.reboot();
    assert_eq!(
        after.names(),
        ["gen-1.pack", "gen-2.pack", "members.log", "wal-1.log"]
    );
    let (dir, loaded) = VaultDir::open(after.clone()).unwrap();
    assert_eq!(loaded.generation, Some(2));
    assert_eq!(dir.active_wal(), "wal-2.log");
    drop(dir);
    check_open(&after, &expected, "gen-2 without wal-2");

    // Both written, gen-1 deleted, wal-1 not yet.
    let blocks = base.reboot();
    blocks.crash_at(3, None);
    assert!(compact_all(&blocks).is_err());
    let after = blocks.reboot();
    assert_eq!(
        after.names(),
        ["gen-2.pack", "members.log", "wal-1.log", "wal-2.log"]
    );
    check_open(&after, &expected, "gen-1 deleted, wal-1 kept");
}

#[test]
fn only_one_writer_at_a_time() {
    let blocks = MemBlocks::new();
    let (dir, _) = VaultDir::open(blocks.clone()).unwrap();
    assert!(matches!(VaultDir::open(blocks.clone()), Err(Error::Locked)));
    // Readers never need the lock.
    assert!(VaultReader::open(&blocks).is_ok());
    drop(dir);
    assert!(VaultDir::open(blocks).is_ok());
}

#[test]
fn a_reader_keeps_its_snapshot_while_the_writer_compacts() {
    let (blocks, expected) = base(true);
    let reader = VaultReader::open(&blocks).unwrap();
    compact_all(&blocks).unwrap();
    compact_all(&blocks).unwrap();
    assert!(!blocks.names().contains(&"gen-1.pack".to_owned()));
    assert_eq!(logical(reader.pack(), &reader.wal().unwrap()), expected);
    assert_eq!(reader.wal_generations(), [1]);
}

#[test]
fn torn_tails_are_cut_on_open_in_every_log() {
    let (blocks, expected) = base(true);
    for name in ["members.log", "wal-1.log"] {
        let mut bytes = blocks.file(name).unwrap();
        bytes.extend_from_slice(&[9, 0, 0, 0, 1, 2]);
        blocks.put_raw(name, &bytes);
    }
    blocks.put_raw("activity-7.log", &[3, 0, 0]);
    let (dir, loaded) = VaultDir::open(blocks.clone()).unwrap();
    assert_eq!(loaded.members, members());
    assert_eq!(logical(loaded.pack.as_ref(), &loaded.wal), expected);
    assert_eq!(blocks.file("activity-7.log").unwrap(), b"");
    dir.append_activity(7, b"seen").unwrap();
    assert_eq!(dir.read_activity(7).unwrap(), [b"seen".to_vec()]);
    assert_eq!(dir.activity_logs().unwrap(), [7]);
    assert!(dir.delete_activity(7).unwrap());
}

#[test]
fn middle_corruption_in_a_wal_fails_the_open() {
    let (blocks, _) = base(true);
    blocks.flip_bit("wal-1.log", 6, 0);
    assert!(matches!(
        VaultDir::open(blocks),
        Err(Error::CorruptLog { offset: 0, .. })
    ));
}

#[test]
fn carrying_a_frame_no_wal_holds_is_refused() {
    let (blocks, expected) = base(true);
    let names = blocks.names();
    let (mut dir, loaded) = VaultDir::open(blocks.clone()).unwrap();
    let all: Vec<Vec<u8>> = logical(loaded.pack.as_ref(), &loaded.wal)
        .into_iter()
        .collect();
    // frame 0 lives only in gen-1.pack; frame 500 nowhere.
    for (carried, count) in [
        (vec![frame(0)], 1),
        (vec![frame(8), frame(500)], 1),
        (vec![frame(0), frame(500)], 2),
    ] {
        let rest: Vec<Vec<u8>> = all
            .iter()
            .filter(|f| !carried.contains(f))
            .cloned()
            .collect();
        assert!(
            matches!(
                dir.compact(pack_input(&rest), &EPOCH_KEY, &carried),
                Err(Error::InvalidCompactionInput { count: n }) if n == count
            ),
            "{carried:?}"
        );
        assert_eq!(blocks.names(), names, "nothing written");
    }
    assert_eq!(dir.next_generation(), 2);

    // The WAL tail carries, and a reader opened before the compaction and
    // one opened after it both see every frame.
    let before = VaultReader::open(&blocks).unwrap();
    let split = all.len() - 3;
    assert!(loaded.wal.contains(&all[split]));
    dir.compact(pack_input(&all[..split]), &EPOCH_KEY, &all[split..])
        .unwrap();
    drop(dir);
    assert_eq!(logical(before.pack(), &before.wal().unwrap()), expected);
    check_open(&blocks, &expected, "after a valid carry");
}
