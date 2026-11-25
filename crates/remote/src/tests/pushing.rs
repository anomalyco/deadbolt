//! Push-side hardening: content-addressed objects are verified before and
//! after a create-only PUT, an own name holding another vault's or kind's
//! frame is an anomaly, and self-rollback is judged against the
//! acknowledged tip, not unpushed local edits.

use deadbolt_core::v2::{FrameKind, LogKind};

use super::fixture::{data_chain, data_frame, device, fraud, genesis, vault as other_vault};
use crate::path::RemotePath;
use crate::{
    FaultyObjStore, Outbox, PushStop, RemoteAnomaly, RemoteError, SelfRollback, SyncAnchor,
    check_self_rollback, plan_push, push,
};

fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

#[test]
fn plan_push_refuses_blobs_and_packs_that_do_not_hash_to_their_name() {
    let (vault, _, _) = genesis(0);
    let good = Outbox {
        blobs: vec![(hash(b"blob"), b"blob".to_vec())],
        packs: vec![(hash(b"pack"), b"pack".to_vec())],
        ..Outbox::default()
    };
    assert_eq!(plan_push(&vault, good).unwrap().steps.len(), 2);
    for outbox in [
        Outbox {
            blobs: vec![(hash(b"blob"), b"blob, torn".to_vec())],
            ..Outbox::default()
        },
        Outbox {
            packs: vec![([7; 32], b"pack".to_vec())],
            ..Outbox::default()
        },
    ] {
        assert!(matches!(
            plan_push(&vault, outbox),
            Err(RemoteError::Plan(_))
        ));
    }
}

#[tokio::test]
async fn a_torn_or_planted_content_addressed_object_is_repaired() {
    let (vault, _, _) = genesis(0);
    let proof = fraud(&device(2), vault);
    let blob = b"attachment".to_vec();
    let plan = plan_push(
        &vault,
        Outbox {
            blobs: vec![(hash(&blob), blob.clone())],
            frauds: vec![proof],
            ..Outbox::default()
        },
    )
    .unwrap();
    let blob_name = RemotePath::Blob {
        vault,
        hash: hash(&blob),
    }
    .to_name();
    let proof_name = RemotePath::Fraud {
        vault,
        hash: proof.proof_hash(),
    }
    .to_name();
    let store = FaultyObjStore::new();
    // An interrupted upload left half the blob; a hostile store planted junk proof bytes.
    store.inner().plant(&blob_name, &blob[..4]);
    store.inner().plant(&proof_name, &[0; 482]);
    let report = push(&store, &plan).await.unwrap();
    assert_eq!((report.created, report.repaired), (0, 2));
    assert_eq!(store.inner().peek(&blob_name).unwrap(), blob);
    assert_eq!(store.inner().peek(&proof_name).unwrap(), proof.encode());
    // Intact copies are left alone.
    let again = push(&store, &plan).await.unwrap();
    assert_eq!((again.already_present, again.repaired), (2, 0));
}

#[tokio::test]
async fn an_own_name_holding_another_vaults_or_kinds_frame_is_mismatched() {
    let (vault, _, _) = genesis(0);
    let a = device(1);
    let local = data_chain(&a, vault, 2, 1, &[]);
    let name = RemotePath::frame(vault, FrameKind::Data, a.device_id(), 1).to_name();
    let plan = plan_push(
        &vault,
        Outbox {
            frames: local.clone(),
            ..Outbox::default()
        },
    )
    .unwrap();
    let replayed = [
        // The same author's seq 1 in another vault, replayed here.
        data_frame(&a, other_vault(), 1, local[0].id(), 1, false),
        // A Checkpoint frame filed under the bare name.
        data_frame(&a, vault, 1, local[0].id(), 1, true),
    ];
    for frame in replayed {
        let store = FaultyObjStore::new();
        store.inner().plant(&name, &frame.encode());
        let report = push(&store, &plan).await.unwrap();
        assert_eq!(
            report.stopped,
            Some(PushStop::Anomaly(RemoteAnomaly::Mismatched {
                name: name.clone(),
                reason: "frame header disagrees with its name",
            }))
        );
    }
}

#[tokio::test]
async fn a_restore_with_unpushed_edits_is_caught_against_the_acknowledged_tip() {
    let (vault, _, _) = genesis(0);
    let a = device(1);
    let me = a.device_id();
    // Before the backup was restored, the store took seq 0..=5 (a checkpoint at 4).
    let pushed = data_chain(&a, vault, 6, 1, &[4]);
    let store = FaultyObjStore::new();
    let plan = plan_push(
        &vault,
        Outbox {
            frames: pushed.clone(),
            ..Outbox::default()
        },
    )
    .unwrap();
    push(&store, &plan).await.unwrap();
    // The backup's anchor had seen 0..=2; offline edits since made a local 3..=6.
    let mut anchor = SyncAnchor::default();
    for frame in &pushed[..3] {
        anchor.observe(frame).unwrap();
    }
    let found = check_self_rollback(&store, &vault, &me, &anchor)
        .await
        .unwrap();
    assert_eq!(
        found,
        [SelfRollback {
            log: LogKind::Data,
            remote_ahead: [
                (3, FrameKind::Data),
                (4, FrameKind::Checkpoint),
                (5, FrameKind::Data)
            ]
            .map(|(seq, kind)| RemotePath::frame(vault, kind, me, seq))
            .to_vec(),
            conflicting: None,
        }],
        "the local tip (6) would have listed nothing above it"
    );
}
