//! Zero-state recovery from LIST alone, withholding, and the anchor's
//! encoding.

use std::collections::BTreeMap;

use deadbolt_core::v2::{FrameKind, LogKind};

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
    let plan = plan_recovery_bootstrap(&vault, &listed_m, &listed_d).unwrap();
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
        ]
    );
    assert_eq!(plan.checkpoint(), plan.checkpoints.first());

    // The caller opens the checkpoint and learns its frontier: a at 5, b at 3.
    let frontier = BTreeMap::from([(a.device_id(), 5), (b.device_id(), 3)]);
    let tail = plan.tail(&frontier);
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
    assert_eq!(plan.tail(&BTreeMap::new()).len(), 13);
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
    let plan = plan_recovery_bootstrap(&vault, &listed_m, &[]).unwrap();
    assert_eq!(
        plan.anomalies,
        [RemoteAnomaly::Withheld {
            author: root,
            required_seq: 2,
            remote_max_seq: Some(3)
        }]
    );
    assert!(plan.checkpoints.is_empty());
    assert!(matches!(
        plan_recovery_bootstrap(&vault, &[], &[]),
        Err(RemoteError::Plan(_))
    ));
    // Foreign names are ignored, not trusted.
    let other = crate::tests::fixture::vault();
    let foreign = vec![RemotePath::frame(other, FrameKind::Member, root, 0).to_name()];
    assert!(plan_recovery_bootstrap(&vault, &foreign, &[]).is_err());
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

    // a's frame (decrypted by the caller) cites b at 5.
    let clock = [(a.device_id(), 2), (b.device_id(), 5)];
    assert_eq!(
        check_withholding(clock, &tips, &BTreeMap::new()),
        [RemoteAnomaly::Withheld {
            author: b.device_id(),
            required_seq: 5,
            remote_max_seq: Some(2)
        }]
    );
    // An author the store has never shown at all.
    let c = device(3).device_id();
    assert_eq!(
        check_withholding([(c, 0)], &tips, &BTreeMap::new()),
        [RemoteAnomaly::Withheld {
            author: c,
            required_seq: 0,
            remote_max_seq: None
        }]
    );
    // Covered by a checkpoint: collected, not withheld.
    let compacted = BTreeMap::from([(b.device_id(), 5)]);
    assert!(check_withholding(clock, &tips, &compacted).is_empty());
    store.heal();
    let healed = plan_pull(&store, &vault, &SyncAnchor::default(), None)
        .await
        .unwrap();
    assert!(
        check_withholding(clock, &healed.index.tips(LogKind::Data), &BTreeMap::new()).is_empty()
    );
}

#[test]
fn anchor_round_trips_and_refuses_garbage() {
    let (vault, _, members) = genesis(1);
    let mut anchor = SyncAnchor::default();
    for frame in &members {
        anchor.observe(frame).unwrap();
    }
    for frame in data_chain(&device(1), vault, 3, 1, &[]) {
        anchor.observe(&frame).unwrap();
    }
    anchor.note_compacted([(device(1).device_id(), 1)]);
    anchor.note_compacted([(device(1).device_id(), 0)]);
    assert_eq!(anchor.compacted[&device(1).device_id()], 1);
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
fn observe_keeps_the_newest_and_refuses_a_swap_at_the_anchor() {
    let (vault, _, _) = genesis(0);
    let a = device(1);
    let chain = data_chain(&a, vault, 3, 1, &[]);
    let mut anchor = SyncAnchor::default();
    anchor.observe(&chain[2]).unwrap();
    anchor.observe(&chain[0]).unwrap();
    assert_eq!(
        anchor.tip(LogKind::Data, &a.device_id()),
        Some((2, chain[2].id()))
    );
    let fork = super::fixture::data_frame(&a, vault, 2, chain[1].id(), 9, false);
    assert!(matches!(
        anchor.observe(&fork),
        Err(RemoteAnomaly::RemoteRegressed { .. })
    ));
}
