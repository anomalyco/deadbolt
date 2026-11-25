//! Push order, idempotent retries, self-rollback, and pull-side regression
//! detection against `FaultyObjStore`.

use std::collections::BTreeSet;

use deadbolt_core::v2::{FrameKind, LogKind};

use super::fixture::{data_chain, data_frame, device, fraud, genesis};
use crate::path::{Area, RemotePath, area_prefix};
use crate::planner::check_fetched;
use crate::{
    Call, FaultyObjStore, ObjStore, Observed, Outbox, PushStop, RemoteAnomaly, RemoteError,
    SelfRollback, SyncAnchor, check_self_rollback, plan_pull, plan_push, push,
};

fn area_of(call: &Call) -> Option<Area> {
    match call {
        Call::Put { name, create_only } => {
            assert!(create_only, "every push PUT is create-only");
            Some(RemotePath::parse(name).unwrap().area())
        }
        _ => None,
    }
}

#[tokio::test]
async fn push_lands_blobs_packs_proofs_members_then_data_in_seq_order() {
    let (vault, _, members) = genesis(2);
    let a = device(1);
    let b = device(2);
    let mut frames = data_chain(&a, vault, 4, 1, &[2]);
    frames.extend(data_chain(&b, vault, 3, 2, &[]));
    frames.extend(members.iter().cloned());
    frames.reverse();
    let outbox = Outbox {
        blobs: [&b"blob"[..], b"blob2"]
            .map(|b| (*blake3::hash(b).as_bytes(), b.to_vec()))
            .to_vec(),
        packs: vec![(*blake3::hash(b"pack").as_bytes(), b"pack".to_vec())],
        frauds: vec![fraud(&b, vault)],
        frames,
    };
    let plan = plan_push(&vault, outbox).unwrap();
    let store = FaultyObjStore::new();
    let report = push(&store, &plan).await.unwrap();
    assert_eq!(report.created, plan.steps.len());
    assert_eq!(report.stopped, None);

    let areas: Vec<Area> = store.calls().iter().filter_map(area_of).collect();
    let mut sorted = areas.clone();
    sorted.sort_by_key(|a| {
        [
            Area::Blob,
            Area::Pack,
            Area::Fraud,
            Area::Member,
            Area::Data,
        ]
        .iter()
        .position(|x| x == a)
    });
    assert_eq!(areas, sorted);
    assert_eq!(areas.iter().filter(|a| **a == Area::Data).count(), 7);

    // Within each stream, seqs ascend.
    let mut last: std::collections::BTreeMap<_, u64> = Default::default();
    for step in &plan.steps {
        if let RemotePath::Frame {
            kind, author, seq, ..
        } = step.path
        {
            let prev = last.insert((kind.log_kind(), author), seq);
            assert!(prev.is_none_or(|p| p < seq));
        }
    }
    let checkpoint = RemotePath::frame(vault, FrameKind::Checkpoint, a.device_id(), 2);
    assert!(store.inner().peek(&checkpoint.to_name()).is_some());
}

#[test]
fn push_plan_refuses_foreign_and_forked_input() {
    let (vault, _, _) = genesis(0);
    let a = device(1);
    let other = crate::tests::fixture::vault();
    let foreign = Outbox {
        frames: data_chain(&a, other, 1, 1, &[]),
        ..Outbox::default()
    };
    assert!(matches!(
        plan_push(&vault, foreign),
        Err(RemoteError::Plan(_))
    ));
    let mut forked = data_chain(&a, vault, 2, 1, &[]);
    forked.push(data_frame(&a, vault, 1, forked[0].id(), 9, false));
    let forked = Outbox {
        frames: forked,
        ..Outbox::default()
    };
    assert!(matches!(
        plan_push(&vault, forked),
        Err(RemoteError::Plan(_))
    ));
    let wrong_proof = Outbox {
        frauds: vec![fraud(&a, other)],
        ..Outbox::default()
    };
    assert!(matches!(
        plan_push(&vault, wrong_proof),
        Err(RemoteError::Plan(_))
    ));
}

#[tokio::test]
async fn a_lost_response_then_retry_is_idempotent() {
    let (vault, _, members) = genesis(1);
    let a = device(1);
    let mut frames = members;
    frames.extend(data_chain(&a, vault, 3, 1, &[]));
    let plan = plan_push(
        &vault,
        Outbox {
            frames,
            ..Outbox::default()
        },
    )
    .unwrap();
    let store = FaultyObjStore::new();
    store.lose_put_responses(1);
    assert!(push(&store, &plan).await.is_err());
    let report = push(&store, &plan).await.unwrap();
    assert_eq!(report.already_present, 1);
    assert_eq!(report.created, plan.steps.len() - 1);
    assert_eq!(report.stopped, None);
    // And again: everything is already there.
    let again = push(&store, &plan).await.unwrap();
    assert_eq!(again.already_present, plan.steps.len());
}

#[tokio::test]
async fn own_name_holding_another_frame_is_a_self_rollback() {
    let (vault, _, _) = genesis(0);
    let a = device(1);
    let local = data_chain(&a, vault, 3, 1, &[]);
    // The store already has a different seq 1 by this device (a restored backup forked it).
    let theirs = data_frame(&a, vault, 1, local[0].id(), 7, false);
    let store = FaultyObjStore::new();
    store.inner().plant(
        &RemotePath::frame(vault, FrameKind::Data, a.device_id(), 1).to_name(),
        &theirs.encode(),
    );
    let plan = plan_push(
        &vault,
        Outbox {
            frames: local,
            ..Outbox::default()
        },
    )
    .unwrap();
    let report = push(&store, &plan).await.unwrap();
    assert_eq!(report.created, 1);
    assert_eq!(
        report.stopped,
        Some(PushStop::SelfRollback(SelfRollback {
            log: LogKind::Data,
            remote_ahead: Vec::new(),
            conflicting: Some(RemotePath::frame(vault, FrameKind::Data, a.device_id(), 1)),
        }))
    );
    let seq2 = RemotePath::frame(vault, FrameKind::Data, a.device_id(), 2).to_name();
    assert!(
        store.inner().peek(&seq2).is_none(),
        "nothing pushed past the fork"
    );
}

#[tokio::test]
async fn own_name_holding_garbage_is_an_anomaly_not_a_fork() {
    let (vault, _, _) = genesis(0);
    let a = device(1);
    let local = data_chain(&a, vault, 1, 1, &[]);
    let name = RemotePath::frame(vault, FrameKind::Data, a.device_id(), 0).to_name();
    let store = FaultyObjStore::new();
    store.inner().plant(&name, &local[0].encode()[..100]);
    let plan = plan_push(
        &vault,
        Outbox {
            frames: local,
            ..Outbox::default()
        },
    )
    .unwrap();
    let report = push(&store, &plan).await.unwrap();
    assert!(matches!(
        report.stopped,
        Some(PushStop::Anomaly(RemoteAnomaly::Mismatched {
            reason: "does not verify as a frame",
            ..
        }))
    ));
}

#[tokio::test]
async fn own_stream_ahead_of_the_acknowledged_tip_is_found_before_pushing() {
    let (vault, _, _) = genesis(0);
    let a = device(1);
    let store = FaultyObjStore::new();
    let chain = data_chain(&a, vault, 6, 1, &[4]);
    let plan = plan_push(
        &vault,
        Outbox {
            frames: chain.clone(),
            ..Outbox::default()
        },
    )
    .unwrap();
    push(&store, &plan).await.unwrap();

    let me = a.device_id();
    let acknowledged = |n: usize| {
        let mut anchor = SyncAnchor::default();
        for frame in &chain[..n] {
            anchor.observe(frame).unwrap();
        }
        anchor
    };
    let path = |seq, checkpoint| {
        let kind = if checkpoint {
            FrameKind::Checkpoint
        } else {
            FrameKind::Data
        };
        RemotePath::frame(vault, kind, me, seq)
    };
    assert_eq!(
        check_self_rollback(&store, &vault, &me, &acknowledged(3))
            .await
            .unwrap(),
        [SelfRollback {
            log: LogKind::Data,
            remote_ahead: vec![path(3, false), path(4, true), path(5, false)],
            conflicting: None
        }]
    );
    let fresh = SyncAnchor::default();
    assert_eq!(
        check_self_rollback(&store, &vault, &me, &fresh)
            .await
            .unwrap()[0]
            .remote_ahead
            .len(),
        6
    );
    assert!(
        check_self_rollback(&store, &vault, &me, &acknowledged(6))
            .await
            .unwrap()
            .is_empty()
    );
    let other = device(2).device_id();
    assert!(
        check_self_rollback(&store, &vault, &other, &fresh)
            .await
            .unwrap()
            .is_empty()
    );
}

async fn seeded() -> (
    deadbolt_core::VaultId,
    FaultyObjStore,
    Vec<deadbolt_core::v2::Frame>,
) {
    let (vault, _, members) = genesis(2);
    let a = device(1);
    let b = device(2);
    let mut frames = members;
    frames.extend(data_chain(&a, vault, 5, 1, &[]));
    frames.extend(data_chain(&b, vault, 4, 2, &[]));
    let store = FaultyObjStore::new();
    let plan = plan_push(
        &vault,
        Outbox {
            frames: frames.clone(),
            frauds: vec![fraud(&b, vault)],
            ..Outbox::default()
        },
    )
    .unwrap();
    push(&store, &plan).await.unwrap();
    (vault, store, frames)
}

/// Fetches and accepts everything a plan names, as a client would.
async fn apply(store: &FaultyObjStore, anchor: &mut SyncAnchor, plan: &crate::PullPlan) {
    for path in &plan.fetch {
        let bytes = store.get(&path.to_name(), None).await.unwrap().unwrap();
        if matches!(path, RemotePath::Frame { .. }) {
            let frame = check_fetched(anchor, path, &bytes).unwrap();
            anchor.observe(&frame).unwrap();
        }
    }
}

#[tokio::test]
async fn pull_lists_members_then_data_then_proofs_and_fetches_in_that_order() {
    let (vault, store, frames) = seeded().await;
    store.clear_calls();
    let mut anchor = SyncAnchor::default();
    let plan = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    let prefixes: Vec<String> = store
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::List { prefix, .. } => Some(prefix),
            _ => None,
        })
        .collect();
    assert_eq!(
        prefixes,
        [Area::Member, Area::Data, Area::Fraud].map(|a| area_prefix(&vault, a))
    );
    assert!(plan.anomalies.is_empty());
    assert_eq!(plan.fetch.len(), frames.len() + 1);
    let areas: Vec<Area> = plan.fetch.iter().map(RemotePath::area).collect();
    let first_data = areas.iter().position(|a| *a == Area::Data).unwrap();
    assert!(areas[..first_data].iter().all(|a| *a == Area::Member));
    assert_eq!(areas.last(), Some(&Area::Fraud));
    apply(&store, &mut anchor, &plan).await;
    assert_eq!(
        anchor.tip(LogKind::Data, &device(1).device_id()).unwrap().0,
        4
    );

    // Nothing new: an incremental pull lists one page per stream and fetches nothing.
    let authors: BTreeSet<_> = [device(1).device_id(), device(2).device_id()].into();
    let quiet = plan_pull(&store, &vault, &anchor, Some(&authors))
        .await
        .unwrap();
    assert!(quiet.fetch.iter().all(|p| p.area() == Area::Fraud));
    assert!(quiet.anomalies.is_empty());
    assert_eq!(quiet.verify.len(), anchor.seen.len());

    // A new frame shows up in the next incremental pull.
    let a = device(1);
    let prev = anchor.tip(LogKind::Data, &a.device_id()).unwrap().1;
    let next = data_frame(&a, vault, 5, prev, 1, true);
    push(
        &store,
        &plan_push(
            &vault,
            Outbox {
                frames: vec![next.clone()],
                ..Outbox::default()
            },
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let more = plan_pull(&store, &vault, &anchor, Some(&authors))
        .await
        .unwrap();
    let frames: Vec<_> = more
        .fetch
        .iter()
        .filter(|p| p.area() == Area::Data)
        .collect();
    assert_eq!(
        frames,
        [&RemotePath::frame(
            vault,
            FrameKind::Checkpoint,
            a.device_id(),
            5
        )]
    );
}

#[tokio::test]
async fn wiped_or_rolled_back_streams_are_remote_regressed() {
    let (vault, store, _) = seeded().await;
    let mut anchor = SyncAnchor::default();
    let plan = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    let before = store.snapshot();
    apply(&store, &mut anchor, &plan).await;

    // The store loses device 1's last two frames.
    let a = device(1).device_id();
    let last_two = [3, 4].map(|s| RemotePath::frame(vault, FrameKind::Data, a, s).to_name());
    store.wipe(|n| last_two.iter().any(|x| x == n));
    for data_authors in [None, Some(BTreeSet::from([a]))] {
        let plan = plan_pull(&store, &vault, &anchor, data_authors.as_ref())
            .await
            .unwrap();
        assert_eq!(
            plan.anomalies,
            [RemoteAnomaly::RemoteRegressed {
                log: LogKind::Data,
                author: a,
                expected_seq: 4,
                expected_id: anchor.tip(LogKind::Data, &a).unwrap().1,
                observed: Observed::Missing {
                    max_seq: if data_authors.is_none() {
                        Some(2)
                    } else {
                        None
                    }
                },
            }]
        );
    }

    // A whole-bucket rollback to an empty store loses every stream.
    store.rollback(&crate::MemSnapshot::default());
    let plan = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    assert_eq!(plan.anomalies.len(), anchor.seen.len());
    store.rollback(&before);

    // Collection after an accepted checkpoint is not an alarm.
    let tip = anchor.tip(LogKind::Data, &a).unwrap();
    anchor
        .adopt_checkpoint(&std::collections::BTreeMap::from([(a, tip)]))
        .unwrap();
    store.wipe(|n| last_two.iter().any(|x| x == n));
    assert!(
        plan_pull(&store, &vault, &anchor, None)
            .await
            .unwrap()
            .anomalies
            .is_empty()
    );
}

#[tokio::test]
async fn a_swapped_or_truncated_tip_fails_verification() {
    let (vault, store, frames) = seeded().await;
    let mut anchor = SyncAnchor::default();
    let plan = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    apply(&store, &mut anchor, &plan).await;

    let b = device(2);
    let tip = RemotePath::frame(vault, FrameKind::Data, b.device_id(), 3);
    let prev = frames
        .iter()
        .find(|f| f.header().author == b.device_id() && f.header().seq == 2)
        .unwrap()
        .id();
    let swapped = data_frame(&b, vault, 3, prev, 99, false);
    store.inner().plant(&tip.to_name(), &swapped.encode());
    let plan = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    assert!(plan.anomalies.is_empty(), "LIST alone cannot see a swap");
    assert!(plan.verify.contains(&tip));
    let bytes = store.get(&tip.to_name(), None).await.unwrap().unwrap();
    assert_eq!(
        check_fetched(&anchor, &tip, &bytes),
        Err(RemoteAnomaly::RemoteRegressed {
            log: LogKind::Data,
            author: b.device_id(),
            expected_seq: 3,
            expected_id: anchor.tip(LogKind::Data, &b.device_id()).unwrap().1,
            observed: Observed::Different(swapped.id()),
        })
    );

    store.truncate(|_| true, 150);
    let bytes = store.get(&tip.to_name(), None).await.unwrap().unwrap();
    assert!(matches!(
        check_fetched(&anchor, &tip, &bytes),
        Err(RemoteAnomaly::Mismatched { .. })
    ));

    // A valid frame filed under the wrong name.
    store.heal();
    let wrong = RemotePath::frame(vault, FrameKind::Data, b.device_id(), 2);
    assert!(matches!(
        check_fetched(&anchor, &wrong, &swapped.encode()),
        Err(RemoteAnomaly::Mismatched {
            reason: "frame header disagrees with its name",
            ..
        })
    ));
}

#[tokio::test]
async fn a_stale_list_delays_but_never_alarms() {
    let (vault, store, _) = seeded().await;
    let mut anchor = SyncAnchor::default();
    let first = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    apply(&store, &mut anchor, &first).await;
    store.freeze_list();
    let a = device(1);
    let prev = anchor.tip(LogKind::Data, &a.device_id()).unwrap().1;
    let next = data_frame(&a, vault, 5, prev, 1, false);
    push(
        &store,
        &plan_push(
            &vault,
            Outbox {
                frames: vec![next],
                ..Outbox::default()
            },
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let stale = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    assert!(stale.anomalies.is_empty());
    assert!(stale.fetch.iter().all(|p| p.area() == Area::Fraud));
    store.heal();
    let fresh = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    assert_eq!(
        fresh
            .fetch
            .iter()
            .filter(|p| p.area() == Area::Data)
            .count(),
        1
    );
}
