//! Pull-side hardening: twins at one position, legitimate GC versus
//! regression, Member holes, and fraud proof tracking.

use std::collections::{BTreeMap, BTreeSet};

use deadbolt_core::VaultId;
use deadbolt_core::v2::{Frame, FrameKind, LogKind};

use super::fixture::{data_chain, data_frame, device, fraud, genesis};
use crate::path::{Area, RemotePath, area_prefix};
use crate::{
    FaultyObjStore, ObjStore, Outbox, PullPlan, RemoteAnomaly, SyncAnchor, Twin, check_fetched,
    check_fetched_fraud, plan_pull, plan_push, push, resolve_twin,
};

async fn seed(frames: Vec<Frame>, with_fraud: bool) -> (VaultId, FaultyObjStore) {
    let vault = frames[0].header().vault;
    let store = FaultyObjStore::new();
    let frauds = if with_fraud {
        vec![fraud(&device(2), vault)]
    } else {
        Vec::new()
    };
    let plan = plan_push(
        &vault,
        Outbox {
            frames,
            frauds,
            ..Outbox::default()
        },
    )
    .unwrap();
    push(&store, &plan).await.unwrap();
    (vault, store)
}

async fn get(store: &FaultyObjStore, path: &RemotePath) -> Vec<u8> {
    store.get(&path.to_name(), None).await.unwrap().unwrap()
}

/// Fetches and accepts every frame and proof a plan names.
async fn apply(store: &FaultyObjStore, vault: &VaultId, anchor: &mut SyncAnchor, plan: &PullPlan) {
    for path in &plan.fetch {
        let bytes = get(store, path).await;
        match path {
            RemotePath::Frame { .. } => anchor
                .observe(&check_fetched(anchor, path, &bytes).unwrap())
                .unwrap(),
            RemotePath::Fraud { hash, .. } => {
                check_fetched_fraud(vault, path, &bytes).unwrap();
                anchor.note_fraud(*hash);
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn a_twin_fetches_both_spellings_and_resolves_to_fraud_or_one() {
    let (vault, _, members) = genesis(0);
    let a = device(1);
    let chain = data_chain(&a, vault, 3, 1, &[]);
    let mut frames = members;
    frames.extend(chain.iter().cloned());
    let (_, store) = seed(frames, false).await;
    // The author also signed a checkpoint at seq 2: two frames, one position.
    let twin = data_frame(&a, vault, 2, chain[1].id(), 1, true);
    let bare = RemotePath::frame(vault, FrameKind::Data, a.device_id(), 2);
    let dotc = RemotePath::frame(vault, FrameKind::Checkpoint, a.device_id(), 2);
    store.inner().plant(&dotc.to_name(), &twin.encode());

    let plan = plan_pull(&store, &vault, &SyncAnchor::default(), None)
        .await
        .unwrap();
    assert!(
        plan.fetch.contains(&bare),
        "<seq> is not shadowed by <seq>.c"
    );
    assert!(plan.fetch.contains(&dotc));
    assert_eq!(plan.twins, [(bare, dotc)]);
    assert_eq!(
        plan.index.paths(&vault, LogKind::Data, &a.device_id(), 2),
        [bare, dotc]
    );
    let resolved = resolve_twin(
        (&bare, &get(&store, &bare).await),
        (&dotc, &get(&store, &dotc).await),
    )
    .unwrap();
    let Twin::Fraud(proof) = resolved else {
        panic!("both verify: equivocation");
    };
    assert_eq!(proof.verify().unwrap().seq, 2);

    // A store-planted junk twin is ignored: the real frame stands.
    store.inner().plant(&dotc.to_name(), b"junk");
    assert_eq!(
        resolve_twin(
            (&bare, &get(&store, &bare).await),
            (&dotc, &get(&store, &dotc).await)
        ),
        Ok(Twin::One(Box::new(chain[2].clone())))
    );
    // A checkpoint-kind frame filed under the bare name is not the bare frame.
    store.inner().plant(&bare.to_name(), &twin.encode());
    assert!(resolve_twin((&bare, &twin.encode()), (&dotc, b"junk")).is_err());
}

#[tokio::test]
async fn legitimate_gc_defers_instead_of_alarming_until_the_checkpoint_is_adopted() {
    let (vault, _, members) = genesis(1);
    let (a, b) = (device(1), device(2));
    let a_chain = data_chain(&a, vault, 5, 1, &[]);
    let b_chain = data_chain(&b, vault, 4, 2, &[]);
    let mut frames = members;
    frames.extend(a_chain.iter().cloned());
    frames.extend(b_chain.iter().cloned());
    let (_, store) = seed(frames, false).await;
    let mut anchor = SyncAnchor::default();
    let first = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    apply(&store, &vault, &mut anchor, &first).await;

    // a checkpoints at seq 5 (frontier a:4, b:3), then the GC collects
    // everything at or below the frontier.
    let checkpoint = data_frame(&a, vault, 5, a_chain[4].id(), 1, true);
    let landed = plan_push(
        &vault,
        Outbox {
            frames: vec![checkpoint.clone()],
            ..Outbox::default()
        },
    )
    .unwrap();
    push(&store, &landed).await.unwrap();
    let data = area_prefix(&vault, Area::Data);
    store.wipe(|n| n.starts_with(&data) && !n.ends_with(".c"));

    let authors = BTreeSet::from([a.device_id(), b.device_id()]);
    for data_authors in [None, Some(&authors)] {
        let plan = plan_pull(&store, &vault, &anchor, data_authors)
            .await
            .unwrap();
        assert!(plan.anomalies.is_empty(), "{:?}", plan.anomalies);
        assert_eq!(plan.deferred.len(), 2);
        let dotc = RemotePath::frame(vault, FrameKind::Checkpoint, a.device_id(), 5);
        assert!(plan.fetch.contains(&dotc));
        // Until a checkpoint is verified and adopted, the losses stand.
        assert_eq!(plan.confirm_deferred(&anchor).len(), 2);
        let mut adopted = anchor.clone();
        let frame = check_fetched(&adopted, &dotc, &get(&store, &dotc).await).unwrap();
        let frontier = BTreeMap::from([
            (a.device_id(), (4, a_chain[4].id())),
            (b.device_id(), (3, b_chain[3].id())),
        ]);
        adopted.adopt_checkpoint(&frontier).unwrap();
        adopted.observe(&frame).unwrap();
        assert!(plan.confirm_deferred(&adopted).is_empty());
    }

    // A wipe with no checkpoint to explain it alarms at once.
    store.wipe(|n| n.ends_with(".c"));
    let plan = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    assert_eq!(plan.anomalies.len(), 2);
    assert!(plan.deferred.is_empty());
}

#[tokio::test]
async fn member_holes_and_wiped_fraud_proofs_are_anomalies() {
    let (vault, root, members) = genesis(2);
    let (_, store) = seed(members, true).await;
    let mut anchor = SyncAnchor::default();
    let plan = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    assert!(plan.anomalies.is_empty());
    assert_eq!(plan.fetch.last().map(RemotePath::area), Some(Area::Fraud));
    apply(&store, &vault, &mut anchor, &plan).await;
    assert_eq!(anchor.frauds.len(), 1);

    // A known proof is not fetched again.
    let again = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    assert!(again.fetch.iter().all(|p| p.area() != Area::Fraud));
    assert!(again.anomalies.is_empty());

    // The store hides Member seq 1 and drops the proof.
    let hidden = RemotePath::frame(vault, FrameKind::Member, root, 1).to_name();
    store.withhold(move |n| n == hidden);
    let proofs = area_prefix(&vault, Area::Fraud);
    store.wipe(|n| n.starts_with(&proofs));
    let plan = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    let hash = *anchor.frauds.iter().next().unwrap();
    assert!(plan.anomalies.contains(&RemoteAnomaly::StreamHole {
        log: LogKind::Member,
        author: root,
        missing_seq: 1,
        max_seq: 2
    }));
    assert!(plan.anomalies.contains(&RemoteAnomaly::FraudWiped { hash }));
}

#[test]
fn fetched_fraud_proofs_must_match_their_name_and_vault() {
    let (vault, _, _) = genesis(0);
    let proof = fraud(&device(2), vault);
    let bytes = proof.encode();
    let path = RemotePath::Fraud {
        vault,
        hash: proof.proof_hash(),
    };
    assert_eq!(check_fetched_fraud(&vault, &path, &bytes), Ok(proof));
    let renamed = RemotePath::Fraud {
        vault,
        hash: [1; 32],
    };
    assert!(check_fetched_fraud(&vault, &renamed, &bytes).is_err());
    assert!(check_fetched_fraud(&vault, &path, &bytes[..100]).is_err());
    let other = super::fixture::vault();
    let foreign = fraud(&device(2), other);
    let foreign_path = RemotePath::Fraud {
        vault,
        hash: foreign.proof_hash(),
    };
    assert!(check_fetched_fraud(&vault, &foreign_path, &foreign.encode()).is_err());
}
