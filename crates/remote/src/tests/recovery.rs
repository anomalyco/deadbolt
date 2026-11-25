//! Zero-state recovery from LIST alone, withholding, and the anchor's
//! encoding.

use std::collections::BTreeMap;

use deadbolt_core::v2::{DeltaClock, FrameId, FrameKind, LogKind, VectorClock};

use super::fixture::{data_chain, device, genesis};
use crate::path::{Area, RemotePath, area_prefix};
use crate::{
    FaultyObjStore, ObjStore, Outbox, RemoteAnomaly, RemoteError, SyncAnchor, check_withholding,
    plan_pull, plan_push, plan_recovery_bootstrap, push,
};

#[tokio::test]
async fn recovery_finds_members_newest_checkpoints_and_the_tail_from_list_alone() {
    let (vault, root, members) = genesis(2);
    let a = device(1);
    let b = device(2);
    let mut frames = members.clone();
    frames.extend(data_chain(&a, vault, 8, 1, &[2, 5]));
    frames.extend(data_chain(&b, vault, 5, 2, &[3]));
    let store = FaultyObjStore::new();
    push(
        &store,
        &plan_push(
            &vault,
            Outbox {
                frames,
                ..Outbox::default()
            },
        )
        .unwrap(),
    )
    .await
    .unwrap();

    let listed_m = store
        .list(&area_prefix(&vault, Area::Member), None)
        .await
        .unwrap();
    let listed_d = store
        .list(&area_prefix(&vault, Area::Data), None)
        .await
        .unwrap();
    let plan = plan_recovery_bootstrap(&vault, &listed_m, &listed_d, &[]).unwrap();
    assert_eq!(
        plan.members,
        (0..3)
            .map(|s| RemotePath::frame(vault, FrameKind::Member, root, s))
            .collect::<Vec<_>>()
    );
    assert!(plan.anomalies.is_empty());
    assert_eq!(
        plan.checkpoints,
        [
            RemotePath::frame(vault, FrameKind::Checkpoint, a.device_id(), 5),
            RemotePath::frame(vault, FrameKind::Checkpoint, b.device_id(), 3),
            RemotePath::frame(vault, FrameKind::Checkpoint, a.device_id(), 2),
        ],
        "every checkpoint, so a disputed newest one falls back to an older base"
    );
    assert_eq!(plan.checkpoint(), plan.checkpoints.first());

    // The caller opens the checkpoint and learns its frontier: a at 5, b at 3.
    let frontier = BTreeMap::from([(a.device_id(), 5), (b.device_id(), 3)]);
    let tail = plan.tail(&frontier);
    assert!(tail.holes.is_empty());
    let tail = tail.frames;
    let expect: Vec<RemotePath> = [(a.device_id(), 6), (a.device_id(), 7), (b.device_id(), 4)]
        .iter()
        .map(|&(d, s)| RemotePath::frame(vault, FrameKind::Data, d, s))
        .collect();
    let mut tail_sorted = tail.clone();
    tail_sorted.sort();
    let mut expect_sorted = expect;
    expect_sorted.sort();
    assert_eq!(tail_sorted, expect_sorted);
    // A frontier missing an author yields that author's whole stream.
    assert_eq!(plan.tail(&BTreeMap::new()).frames.len(), 13);
}

#[tokio::test]
async fn recovery_flags_holes_in_member_streams_and_refuses_an_empty_vault() {
    let (vault, root, members) = genesis(3);
    let store = FaultyObjStore::new();
    push(
        &store,
        &plan_push(
            &vault,
            Outbox {
                frames: members,
                ..Outbox::default()
            },
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let hidden = RemotePath::frame(vault, FrameKind::Member, root, 2).to_name();
    store.withhold(move |n| n == hidden);
    let listed_m = store
        .list(&area_prefix(&vault, Area::Member), None)
        .await
        .unwrap();
    let plan = plan_recovery_bootstrap(&vault, &listed_m, &[], &[]).unwrap();
    assert_eq!(
        plan.anomalies,
        [RemoteAnomaly::StreamHole {
            log: LogKind::Member,
            author: root,
            missing_seq: 2,
            max_seq: 3
        }]
    );
    assert!(plan.checkpoints.is_empty());
    assert!(matches!(
        plan_recovery_bootstrap(&vault, &[], &[], &[]),
        Err(RemoteError::Plan(_))
    ));
    // Foreign names are ignored, not trusted.
    let other = crate::tests::fixture::vault();
    let foreign = vec![RemotePath::frame(other, FrameKind::Member, root, 0).to_name()];
    assert!(plan_recovery_bootstrap(&vault, &foreign, &[], &[]).is_err());
}

#[tokio::test]
async fn clocks_citing_unlisted_frames_prove_withholding() {
    let (vault, _, members) = genesis(1);
    let a = device(1);
    let b = device(2);
    let mut frames = members;
    frames.extend(data_chain(&a, vault, 3, 1, &[]));
    frames.extend(data_chain(&b, vault, 6, 2, &[]));
    let store = FaultyObjStore::new();
    push(
        &store,
        &plan_push(
            &vault,
            Outbox {
                frames,
                ..Outbox::default()
            },
        )
        .unwrap(),
    )
    .await
    .unwrap();
    // The store hides b's frames from seq 3 on.
    let b_prefix = crate::path::stream_prefix(&vault, LogKind::Data, &b.device_id());
    store.withhold(move |n| {
        n.starts_with(&b_prefix)
            && matches!(RemotePath::parse(n), Ok(RemotePath::Frame { seq, .. }) if seq >= 3)
    });
    let plan = plan_pull(&store, &vault, &SyncAnchor::default(), None)
        .await
        .unwrap();
    let tips = plan.index.tips(LogKind::Data);
    assert_eq!(tips[&b.device_id()], 2);

    // a's frame (decrypted by the caller) cites b at 5: core clocks keep
    // counts, so frames 0..=5 of b are the count 6.
    let clock = VectorClock::from_counts([(a.device_id(), 3), (b.device_id(), 6)]);
    assert_eq!(
        check_withholding(&clock, &tips, &BTreeMap::new()),
        [RemoteAnomaly::Withheld {
            author: b.device_id(),
            required_seq: 5,
            remote_max_seq: Some(2)
        }]
    );
    // An author the store has never shown at all.
    let c = device(3).device_id();
    assert_eq!(
        check_withholding(&VectorClock::from_counts([(c, 1)]), &tips, &BTreeMap::new()),
        [RemoteAnomaly::Withheld {
            author: c,
            required_seq: 0,
            remote_max_seq: None
        }]
    );
    // Covered by a checkpoint: collected, not withheld.
    let compacted = BTreeMap::from([(b.device_id(), 5)]);
    assert!(check_withholding(&clock, &tips, &compacted).is_empty());
    // A delta clock cites the same way.
    let delta = DeltaClock::new(vec![(b.device_id(), 6)]).unwrap();
    assert_eq!(check_withholding(&delta, &tips, &BTreeMap::new()).len(), 1);
    // The listed tip itself (count = tip + 1) is not withheld; one past it is.
    let at_tip = VectorClock::from_counts([(b.device_id(), 3)]);
    assert!(check_withholding(&at_tip, &tips, &BTreeMap::new()).is_empty());
    let past_tip = VectorClock::from_counts([(b.device_id(), 4)]);
    assert_eq!(
        check_withholding(&past_tip, &tips, &BTreeMap::new()),
        [RemoteAnomaly::Withheld {
            author: b.device_id(),
            required_seq: 3,
            remote_max_seq: Some(2)
        }]
    );
    store.heal();
    let healed = plan_pull(&store, &vault, &SyncAnchor::default(), None)
        .await
        .unwrap();
    assert!(
        check_withholding(&clock, &healed.index.tips(LogKind::Data), &BTreeMap::new()).is_empty()
    );
}

#[test]
fn anchor_round_trips_and_refuses_garbage() {
    let (vault, _, members) = genesis(1);
    let mut anchor = SyncAnchor::default();
    for frame in &members {
        anchor.observe(frame).unwrap();
    }
    let chain = data_chain(&device(1), vault, 3, 1, &[]);
    for frame in &chain {
        anchor.observe(frame).unwrap();
    }
    let me = device(1).device_id();
    anchor
        .adopt_checkpoint(&BTreeMap::from([(me, (1, chain[1].id()))]))
        .unwrap();
    anchor
        .adopt_checkpoint(&BTreeMap::from([(me, (0, chain[0].id()))]))
        .unwrap();
    assert_eq!(anchor.compacted[&me], 1);
    assert_eq!(anchor.tip(LogKind::Data, &me), Some((2, chain[2].id())));
    anchor.note_fraud([7; 32]);
    let bytes = anchor.encode();
    assert_eq!(SyncAnchor::decode(&bytes).unwrap(), anchor);
    assert_eq!(
        SyncAnchor::decode(&SyncAnchor::default().encode()).unwrap(),
        SyncAnchor::default()
    );
    for cut in 0..bytes.len() {
        assert!(SyncAnchor::decode(&bytes[..cut]).is_err(), "cut at {cut}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(SyncAnchor::decode(&extra).is_err());
    let mut version = bytes;
    version[0] = 9;
    assert!(SyncAnchor::decode(&version).is_err());
}

#[test]
fn observe_moves_one_linked_seq_at_a_time_and_refuses_a_swap() {
    let (vault, _, _) = genesis(0);
    let a = device(1);
    let me = a.device_id();
    let chain = data_chain(&a, vault, 3, 1, &[]);
    let mut anchor = SyncAnchor::default();
    // An unanchored stream starts at seq 0, never mid-stream.
    assert_eq!(
        anchor.observe(&chain[2]),
        Err(RemoteAnomaly::StreamGap {
            log: LogKind::Data,
            author: me,
            anchored_seq: None,
            observed_seq: 2
        })
    );
    anchor.observe(&chain[0]).unwrap();
    // Skipping seq 1 is refused.
    assert!(matches!(
        anchor.observe(&chain[2]),
        Err(RemoteAnomaly::StreamGap {
            anchored_seq: Some(0),
            observed_seq: 2,
            ..
        })
    ));
    // seq 1 that does not link to the anchored seq 0 is refused.
    let unlinked = super::fixture::data_frame(&a, vault, 1, FrameId::from_bytes([9; 32]), 1, false);
    assert_eq!(
        anchor.observe(&unlinked),
        Err(RemoteAnomaly::ChainBroken {
            log: LogKind::Data,
            author: me,
            seq: 1,
            expected_prev: chain[0].id(),
            observed_prev: FrameId::from_bytes([9; 32]),
        })
    );
    assert_eq!(anchor.tip(LogKind::Data, &me), Some((0, chain[0].id())));
    anchor.observe(&chain[1]).unwrap();
    anchor.observe(&chain[2]).unwrap();
    // Older frames leave the anchor alone.
    anchor.observe(&chain[0]).unwrap();
    assert_eq!(anchor.tip(LogKind::Data, &me), Some((2, chain[2].id())));
    let fork = super::fixture::data_frame(&a, vault, 2, chain[1].id(), 9, false);
    assert!(matches!(
        anchor.observe(&fork),
        Err(RemoteAnomaly::RemoteRegressed { .. })
    ));
}

#[test]
fn adopting_a_checkpoint_anchors_past_a_collected_prefix() {
    let (vault, _, _) = genesis(0);
    let a = device(1);
    let me = a.device_id();
    let chain = data_chain(&a, vault, 6, 1, &[]);
    let mut anchor = SyncAnchor::default();
    // seq 0..=3 were collected: seq 4 alone cannot start the stream...
    assert!(anchor.observe(&chain[4]).is_err());
    // ...but a verified checkpoint's frontier at 3 can.
    anchor
        .adopt_checkpoint(&BTreeMap::from([(me, (3, chain[3].id()))]))
        .unwrap();
    assert_eq!(anchor.compacted[&me], 3);
    anchor.observe(&chain[4]).unwrap();
    anchor.observe(&chain[5]).unwrap();
    // A frontier naming another frame at an anchored seq is refused whole.
    let before = anchor.clone();
    let other = super::fixture::data_frame(&a, vault, 5, chain[4].id(), 9, false);
    assert!(matches!(
        anchor.adopt_checkpoint(&BTreeMap::from([(me, (5, other.id()))])),
        Err(RemoteAnomaly::RemoteRegressed { .. })
    ));
    assert_eq!(anchor, before);
}

#[tokio::test]
async fn recovery_lists_fraud_proofs_and_finds_holes_in_the_tail() {
    let (vault, _, members) = genesis(0);
    let a = device(1);
    let b = device(2);
    let mut frames = members;
    frames.extend(data_chain(&a, vault, 8, 1, &[2]));
    frames.extend(data_chain(&b, vault, 3, 2, &[]));
    let store = FaultyObjStore::new();
    let plan = plan_push(
        &vault,
        Outbox {
            frames,
            frauds: vec![super::fixture::fraud(&b, vault)],
            ..Outbox::default()
        },
    )
    .unwrap();
    push(&store, &plan).await.unwrap();
    // The store hides a's seq 5 (say, a Dispute) from the middle of the tail.
    let hidden = RemotePath::frame(vault, FrameKind::Data, a.device_id(), 5).to_name();
    store.withhold(move |n| n == hidden);
    let list = |area| {
        let store = store.clone();
        async move { store.list(&area_prefix(&vault, area), None).await.unwrap() }
    };
    let (listed_m, listed_d, listed_x) = (
        list(Area::Member).await,
        list(Area::Data).await,
        list(Area::Fraud).await,
    );
    let plan = plan_recovery_bootstrap(&vault, &listed_m, &listed_d, &listed_x).unwrap();
    assert_eq!(plan.frauds.len(), 1);
    assert_eq!(plan.frauds[0].area(), Area::Fraud);

    let tail = plan.tail(&BTreeMap::from([(a.device_id(), 2)]));
    assert_eq!(
        tail.holes,
        [RemoteAnomaly::StreamHole {
            log: LogKind::Data,
            author: a.device_id(),
            missing_seq: 5,
            max_seq: 7
        }]
    );
    // Everything listed is still named, so the caller can show it.
    assert_eq!(tail.frames.len(), 4 + 3);
    // A frontier above the hole sees none.
    assert!(
        plan.tail(&BTreeMap::from([(a.device_id(), 5)]))
            .holes
            .is_empty()
    );
}
