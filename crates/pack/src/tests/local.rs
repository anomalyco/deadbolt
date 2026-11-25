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
