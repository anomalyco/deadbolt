use super::VAULT;
use crate::local::{self, LocalState};
use crate::{DeviceRoot, Error, MemAnchor, MemBlocks, NoopAnchor, RollbackAnchor, RollbackToken};

fn root() -> DeviceRoot {
    DeviceRoot::from_bytes(&[9; 32])
}

fn commit<A: RollbackAnchor>(
    blocks: &MemBlocks,
    anchor: &A,
    prev: Option<&LocalState>,
    body: &str,
) -> LocalState {
    local::commit(
        blocks,
        anchor,
        &VAULT,
        &root(),
        prev,
        b"slots",
        body.as_bytes(),
    )
    .unwrap()
}

fn open<A: RollbackAnchor>(blocks: &MemBlocks, anchor: &A) -> crate::Result<Option<LocalState>> {
    local::open(blocks, anchor, &VAULT, &root())
}

fn local_files(blocks: &MemBlocks) -> Vec<String> {
    blocks
        .names()
        .into_iter()
        .filter(|name| name.starts_with("local-"))
        .collect()
}

/// Commits 1 and 2 under an anchor.
fn two_commits() -> (MemBlocks, MemAnchor, LocalState) {
    let blocks = MemBlocks::new();
    let anchor = MemAnchor::new();
    let first = commit(&blocks, &anchor, None, "one");
    let second = commit(&blocks, &anchor, Some(&first), "two");
    (blocks, anchor, second)
}

#[test]
fn commits_chain_and_leave_one_file() {
    let blocks = MemBlocks::new();
    let anchor = MemAnchor::new();
    assert!(open(&blocks, &anchor).unwrap().is_none());
    let first = commit(&blocks, &anchor, None, "one");
    let second = commit(&blocks, &anchor, Some(&first), "two");
    let third = commit(&blocks, &anchor, Some(&second), "three");
    assert_eq!((first.seq, first.prev_mac), (1, [0; 24]));
    assert_eq!(second.prev_mac, first.cur_mac);
    assert_eq!(third.prev_mac, second.cur_mac);
    assert_eq!(local_files(&blocks), ["local-3.sealed"]);
    let opened = open(&blocks, &anchor).unwrap().unwrap();
    assert_eq!(
        (opened.seq, &opened.body[..], &opened.slots[..]),
        (3, b"three".as_slice(), b"slots".as_slice())
    );
    assert_eq!(opened.token(), third.token());
    assert_eq!(anchor.token(), Some(third.token()));
}

#[test]
fn the_token_is_56_bytes() {
    let token = RollbackToken {
        commit_seq: 7,
        prev_mac: [1; 24],
        cur_mac: [2; 24],
    };
    assert_eq!(RollbackToken::LEN, 56);
    assert_eq!(RollbackToken::from_bytes(&token.to_bytes()), Some(token));
    assert_eq!(RollbackToken::from_bytes(&[0; 55]), None);
}

const KEEPS: [Option<usize>; 6] = [None, Some(0), Some(7), Some(60), Some(90), Some(usize::MAX)];

#[test]
fn a_crash_at_any_commit_step_reopens_without_a_false_alarm() {
    let (base, anchor, second) = two_commits();
    let probe = base.reboot();
    commit(&probe, &anchor, Some(&second), "three");
    let ops = probe.ops();
    assert_eq!(ops, 2, "create local-3, delete local-2");

    for op in 0..ops {
        for keep in KEEPS {
            let ctx = format!("crash at op {op} keeping {keep:?}");
            let blocks = base.reboot();
            let anchor = MemAnchor::new();
            anchor.set(Some(second.token()));
            blocks.crash_at(op, keep);
            let result = local::commit(
                &blocks,
                &anchor,
                &VAULT,
                &root(),
                Some(&second),
                b"slots",
                b"three",
            );
            assert!(blocks.crashed(), "{ctx}");
            // A cut during the best-effort cleanup leaves the commit standing.
            assert!(matches!(result, Err(Error::Crashed)) || op == 1, "{ctx}");

            let after = blocks.reboot();
            let opened = open(&after, &anchor)
                .unwrap_or_else(|err| panic!("{ctx}: {err}"))
                .unwrap();
            let body = if opened.seq == 3 { "three" } else { "two" };
            assert_eq!(&opened.body[..], body.as_bytes(), "{ctx}");
            assert_eq!(
                anchor.token(),
                Some(opened.token()),
                "{ctx}: anchor caught up"
            );
            assert_eq!(
                local_files(&after),
                [format!("local-{}.sealed", opened.seq)],
                "{ctx}"
            );

            let next = commit(&after, &anchor, Some(&opened), "next");
            assert_eq!(
                open(&after, &anchor).unwrap().unwrap().token(),
                next.token(),
                "{ctx}"
            );
        }
    }
}

#[test]
fn a_power_cut_between_file_and_anchor_heals_forward() {
    let (blocks, anchor, second) = two_commits();
    anchor.fail_next_store();
    let failed = local::commit(
        &blocks,
        &anchor,
        &VAULT,
        &root(),
        Some(&second),
        b"slots",
        b"three",
    );
    assert!(matches!(failed, Err(Error::Anchor(_))));
    // Both files survive: nothing is deleted before the anchor moves.
    assert_eq!(local_files(&blocks), ["local-2.sealed", "local-3.sealed"]);
    assert_eq!(anchor.token(), Some(second.token()));

    let opened = open(&blocks, &anchor).unwrap().unwrap();
    assert_eq!((opened.seq, opened.prev_mac), (3, second.cur_mac));
    assert_eq!(anchor.token(), Some(opened.token()));
    assert_eq!(local_files(&blocks), ["local-3.sealed"]);
}

#[test]
fn restoring_an_older_commit_is_a_rollback() {
    let (blocks, anchor, second) = two_commits();
    let old = blocks.file("local-2.sealed").unwrap();
    commit(&blocks, &anchor, Some(&second), "three");
    blocks.remove_raw("local-3.sealed");
    blocks.put_raw("local-2.sealed", &old);
    assert!(matches!(
        open(&blocks, &anchor),
        Err(Error::RollbackDetected {
            disk: Some(2),
            anchor: 3
        })
    ));
    assert_eq!(
        local_files(&blocks),
        ["local-2.sealed"],
        "nothing deleted on a rollback"
    );

    blocks.remove_raw("local-2.sealed");
    assert!(matches!(
        open(&blocks, &anchor),
        Err(Error::RollbackDetected {
            disk: None,
            anchor: 3
        })
    ));
}

#[test]
fn a_forked_chain_is_a_rollback() {
    let (blocks, anchor, _) = two_commits();
    // Another chain under the same root, at the same and the next seq.
    let fork = MemBlocks::new();
    let one = commit(&fork, &NoopAnchor, None, "fork one");
    let two = commit(&fork, &NoopAnchor, Some(&one), "fork two");
    let fork_two = fork.file("local-2.sealed").unwrap();
    commit(&fork, &NoopAnchor, Some(&two), "fork three");
    let fork_three = fork.file("local-3.sealed").unwrap();

    // seq == anchor + 1, but its prev_mac isn't the anchor's cur_mac.
    blocks.put_raw("local-3.sealed", &fork_three);
    assert!(matches!(
        open(&blocks, &anchor),
        Err(Error::RollbackDetected {
            disk: Some(3),
            anchor: 2
        })
    ));

    // seq == anchor, different MAC.
    blocks.remove_raw("local-3.sealed");
    blocks.put_raw("local-2.sealed", &fork_two);
    assert!(matches!(
        open(&blocks, &anchor),
        Err(Error::RollbackDetected {
            disk: Some(2),
            anchor: 2
        })
    ));
}

#[test]
fn skipping_past_the_anchor_is_a_rollback() {
    let (blocks, anchor, second) = two_commits();
    let third = commit(&blocks, &NoopAnchor, Some(&second), "three");
    commit(&blocks, &NoopAnchor, Some(&third), "four");
    assert!(matches!(
        open(&blocks, &anchor),
        Err(Error::RollbackDetected {
            disk: Some(4),
            anchor: 2
        })
    ));
}

#[test]
fn torn_or_tampered_files_are_never_accepted() {
    let (blocks, anchor, second) = two_commits();
    // A tampered key slot fails the AEAD; the anchor then sees nothing valid.
    blocks.flip_bit("local-2.sealed", 8 + 8 + 24 + 4 + 1, 0);
    assert!(matches!(
        open(&blocks, &anchor),
        Err(Error::RollbackDetected {
            disk: None,
            anchor: 2
        })
    ));

    // A wrong root opens nothing, and deletes nothing.
    let (blocks, anchor, _) = two_commits();
    let wrong = local::open(
        &blocks,
        &NoopAnchor,
        &VAULT,
        &DeviceRoot::from_bytes(&[8; 32]),
    );
    assert!(matches!(wrong, Err(Error::Decrypt)));
    assert!(matches!(
        local::open(&blocks, &anchor, &[7; 32], &root()),
        Err(Error::RollbackDetected { .. })
    ));
    assert_eq!(local_files(&blocks), ["local-2.sealed"]);
    assert_eq!(second.seq, 2);
}

#[test]
fn without_an_anchor_the_newest_valid_file_wins() {
    let (blocks, _, second) = two_commits();
    let opened = open(&blocks, &NoopAnchor).unwrap().unwrap();
    assert_eq!(opened.token(), second.token());
    // A fresh keystore starts anchoring from what's on disk.
    let fresh = MemAnchor::new();
    open(&blocks, &fresh).unwrap();
    assert_eq!(fresh.token(), Some(second.token()));
}

/// The bytes of a first commit, with how far into them the sealed body starts.
fn first_commit_file() -> (Vec<u8>, usize) {
    let blocks = MemBlocks::new();
    commit(&blocks, &NoopAnchor, None, "the first state");
    let bytes = blocks.file("local-1.sealed").unwrap();
    // magic, seq, prev_mac, slots_len, "slots", sealed_len
    (bytes, 8 + 8 + 24 + 4 + b"slots".len() + 4)
}

#[test]
fn a_first_commit_cut_short_anywhere_is_cleared_on_open() {
    let (full, sealed_at) = first_commit_file();
    assert!(full.len() > sealed_at + 40);
    for cut in 0..full.len() {
        let fresh = MemAnchor::new();
        let anchors: [&dyn RollbackAnchor; 2] = [&NoopAnchor, &fresh];
        for anchor in anchors {
            let ctx = format!(
                "cut at {cut} of {} (sealed body at {sealed_at})",
                full.len()
            );
            let blocks = MemBlocks::new();
            blocks.put_raw("local-1.sealed", &full[..cut]);
            assert!(
                matches!(
                    local::decode("local-1.sealed", &VAULT, &root(), 1, &full[..cut]),
                    Err(Error::CorruptLocal { .. })
                ),
                "{ctx}: a short file is corrupt, never a decrypt failure"
            );
            assert!(open(&blocks, &anchor).unwrap().is_none(), "{ctx}");
            assert!(local_files(&blocks).is_empty(), "{ctx}: torn file cleared");
            let first = commit(&blocks, &anchor, None, "again");
            let reopened = open(&blocks, &anchor).unwrap().unwrap();
            assert_eq!(reopened.token(), first.token(), "{ctx}");
            assert_eq!(&reopened.body[..], b"again", "{ctx}");
        }
    }
}

#[test]
fn a_power_cut_during_the_first_commit_never_bricks_the_device() {
    let (full, _) = first_commit_file();
    for keep in [None, Some(0), Some(30), Some(60), Some(full.len() - 1)] {
        let blocks = MemBlocks::new();
        let anchor = MemAnchor::new();
        blocks.crash_at(0, keep);
        let body = b"the first state";
        assert!(local::commit(&blocks, &anchor, &VAULT, &root(), None, b"slots", body).is_err());
        let after = blocks.reboot();
        assert!(open(&after, &anchor).unwrap().is_none(), "keep {keep:?}");
        let first = commit(&after, &anchor, None, "x");
        assert_eq!(
            open(&after, &anchor).unwrap().unwrap().token(),
            first.token()
        );
    }
}

#[test]
fn peek_skips_torn_files_and_reports_damaged_ones() {
    let (full, _) = first_commit_file();
    for cut in 0..full.len() {
        let blocks = MemBlocks::new();
        blocks.put_raw("local-1.sealed", &full[..cut]);
        assert!(
            local::peek_slots(&blocks).unwrap().is_none(),
            "cut at {cut}: torn, so no state"
        );
    }
    let blocks = MemBlocks::new();
    blocks.put_raw("local-1.sealed", &full);
    assert_eq!(
        local::peek_slots(&blocks).unwrap().as_deref(),
        Some(b"slots".as_slice())
    );
    // A torn newer commit falls back to the complete one below it.
    let mut second = full[..30].to_vec();
    second[15] = 2;
    blocks.put_raw("local-2.sealed", &second);
    assert_eq!(
        local::peek_slots(&blocks).unwrap().as_deref(),
        Some(b"slots".as_slice())
    );

    let mut wrong_seq = full.clone();
    wrong_seq[15] = 9;
    for damaged in [
        [b"XXXX".as_slice(), &full[4..]].concat(),
        b"XX".to_vec(),
        wrong_seq,
    ] {
        let blocks = MemBlocks::new();
        blocks.put_raw("local-1.sealed", &damaged);
        assert!(
            matches!(local::peek_slots(&blocks), Err(Error::CorruptLocal { .. })),
            "{damaged:?}"
        );
    }
}

#[test]
fn a_complete_file_that_fails_to_open_is_reported_and_kept() {
    let (full, _) = first_commit_file();
    // The wrong root: a decrypt failure, and the file stays.
    let blocks = MemBlocks::new();
    blocks.put_raw("local-1.sealed", &full);
    let wrong = DeviceRoot::from_bytes(&[8; 32]);
    for anchor in [&NoopAnchor as &dyn RollbackAnchor, &MemAnchor::new()] {
        assert!(matches!(
            local::open(&blocks, &anchor, &VAULT, &wrong),
            Err(Error::Decrypt)
        ));
        assert_eq!(blocks.file("local-1.sealed").unwrap(), full);
    }
    // A flipped ciphertext byte, under the right root: the same.
    blocks.flip_bit("local-1.sealed", full.len() - 20, 0);
    assert!(matches!(open(&blocks, &NoopAnchor), Err(Error::Decrypt)));
    assert_eq!(local_files(&blocks), ["local-1.sealed"]);

    // Bytes past the sealed body, or a wrong magic: corrupt, not torn, kept.
    for damaged in [
        [full.as_slice(), b"extra"].concat(),
        [b"XXXX".as_slice(), &full[4..]].concat(),
    ] {
        let blocks = MemBlocks::new();
        blocks.put_raw("local-1.sealed", &damaged);
        assert!(matches!(
            open(&blocks, &NoopAnchor),
            Err(Error::CorruptLocal { .. })
        ));
        assert_eq!(blocks.file("local-1.sealed").unwrap(), damaged);
    }
}
