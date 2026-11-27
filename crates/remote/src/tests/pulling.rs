//! Pull-side hardening: twins at one position, legitimate GC versus
//! regression, Member holes, and fraud proof tracking.

use std::collections::{BTreeMap, BTreeSet};

use deadbolt_core::VaultId;
use deadbolt_core::v2::{Frame, FrameKind, LogKind};

use super::fixture::{data_chain, data_frame, device, fraud, genesis};
use crate::path::{Area, RemotePath, area_prefix};
use crate::{
    CitedCounts, FaultyObjStore, ObjStore, Outbox, PullPlan, RemoteAnomaly, RemoteIndex,
    SyncAnchor, Twin, check_fetched, check_fetched_fraud, plan_pull, plan_push, push, resolve_twin,
    withheld,
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

/// GETs everything a plan names.
async fn fetch(store: &FaultyObjStore, plan: &PullPlan) -> BTreeMap<RemotePath, Vec<u8>> {
    let mut fetched = BTreeMap::new();
    for path in plan.fetch.iter().chain(&plan.verify) {
        fetched.insert(*path, get(store, path).await);
    }
    fetched
}

#[tokio::test]
async fn listed_objects_missing_on_get_cannot_hide_regressions() {
    let (vault, _, members) = genesis(1);
    let author = device(1);
    let data = data_chain(&author, vault, 1, 1, &[]);
    let mut frames = members.clone();
    frames.extend(data.clone());
    let (_, store) = seed(frames, true).await;
    let mut anchor = SyncAnchor::default();
    anchor.observe(&members[0]).unwrap();
    anchor.observe(&data[0]).unwrap();
    for name in store
        .list(&area_prefix(&vault, Area::Fraud), None)
        .await
        .unwrap()
    {
        let RemotePath::Fraud { hash, .. } = RemotePath::parse(&name).unwrap() else {
            panic!("proof path")
        };
        anchor.note_fraud(hash);
    }
    store.freeze_list();
    store.wipe(|_| true);
    let plan = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    assert!(
        plan.anomalies.is_empty(),
        "LIST alone cannot reveal the lie"
    );
    assert!(!plan.fetch.is_empty() && !plan.verify.is_empty());
    for path in plan.fetch.iter().chain(&plan.verify) {
        assert!(store.get(&path.to_name(), None).await.unwrap().is_none());
    }
    let judged = plan.judge(
        &vault,
        &anchor,
        &device(9).device_id(),
        |_, _| None,
        &BTreeMap::new(),
    );
    assert!(judged.anomalies.iter().any(|a| matches!(
        a,
        RemoteAnomaly::RemoteRegressed {
            log: LogKind::Member,
            ..
        }
    )));
    assert!(
        judged
            .anomalies
            .iter()
            .any(|a| matches!(a, RemoteAnomaly::Mismatched { .. }))
    );
    assert!(
        judged
            .anomalies
            .iter()
            .any(|a| matches!(a, RemoteAnomaly::FraudWiped { .. }))
    );
    assert!(matches!(
        &judged.confirm_deferred(&anchor)[..],
        [RemoteAnomaly::RemoteRegressed {
            log: LogKind::Data,
            ..
        }]
    ));
    anchor
        .adopt_checkpoint(&BTreeMap::from([(author.device_id(), (0, data[0].id()))]))
        .unwrap();
    assert!(judged.confirm_deferred(&anchor).is_empty());
}

#[tokio::test]
async fn a_new_listed_data_frame_missing_on_get_is_deferred() {
    let (vault, _, members) = genesis(0);
    let author = device(1);
    let data = data_chain(&author, vault, 1, 1, &[]);
    let mut frames = members;
    frames.extend(data.clone());
    let (_, store) = seed(frames, false).await;
    store.freeze_list();
    store.wipe(|n| n.contains("/d/"));
    let mut anchor = SyncAnchor::default();
    let plan = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    let mut fetched = BTreeMap::new();
    for path in &plan.fetch {
        if let Some(bytes) = store.get(&path.to_name(), None).await.unwrap() {
            fetched.insert(*path, bytes);
        }
    }
    let judged = plan.judge(
        &vault,
        &anchor,
        &device(9).device_id(),
        |_, _| None,
        &fetched,
    );
    assert!(judged.anomalies.is_empty());
    assert!(matches!(
        &judged.confirm_deferred(&anchor)[..],
        [RemoteAnomaly::Withheld {
            required_seq: 0,
            ..
        }]
    ));
    anchor
        .adopt_checkpoint(&BTreeMap::from([(author.device_id(), (0, data[0].id()))]))
        .unwrap();
    assert!(judged.confirm_deferred(&anchor).is_empty());
}

/// Fetches, judges (as a device with no frames of its own) and accepts
/// every frame and proof a plan names.
async fn apply(store: &FaultyObjStore, vault: &VaultId, anchor: &mut SyncAnchor, plan: &PullPlan) {
    let me = device(9).device_id();
    let judged = plan.judge(vault, anchor, &me, |_, _| None, &fetch(store, plan).await);
    assert!(judged.anomalies.is_empty(), "{:?}", judged.anomalies);
    for frame in &judged.frames {
        anchor.observe(frame).unwrap();
    }
    for proof in &judged.proofs {
        anchor.note_fraud(proof.proof_hash());
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
    // Judged whole, the twin is the proof and neither of its frames.
    let me = device(9).device_id();
    let fetched = fetch(&store, &plan).await;
    let judged = plan.judge(&vault, &SyncAnchor::default(), &me, |_, _| None, &fetched);
    assert!(judged.anomalies.is_empty(), "{:?}", judged.anomalies);
    assert_eq!(judged.proofs, [*proof.clone()]);
    let at_twin = |f: &Frame| f.header().author == a.device_id() && f.header().seq == 2;
    assert!(!judged.frames.iter().any(at_twin));

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

/// Clock entries as counts, for tests.
struct Cites(Vec<(deadbolt_core::DeviceId, u64)>);

impl CitedCounts for Cites {
    fn cited_counts(&self) -> Vec<(deadbolt_core::DeviceId, u64)> {
        self.0.clone()
    }
}

#[test]
fn a_withheld_frame_is_reported_once_in_author_and_seq_order() {
    let (vault, _, _) = genesis(0);
    let (a, b) = (device(1).device_id(), device(2).device_id());
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let names: Vec<String> = (0..2)
        .map(|seq| RemotePath::frame(vault, FrameKind::Data, lo, seq).to_name())
        .collect();
    let index = RemoteIndex::from_names(&vault, &names);
    // Two members cite hi:0..=1 (unlisted) and lo:0..=3 (listed to 1).
    let clocks = [Cites(vec![(hi, 2), (lo, 4)]), Cites(vec![(lo, 4), (hi, 1)])];
    let found = withheld(&clocks, &index, &BTreeMap::new());
    let at: Vec<_> = found
        .iter()
        .map(|w| match w {
            RemoteAnomaly::Withheld {
                author,
                required_seq,
                ..
            } => (*author, *required_seq),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(at, [(lo, 3), (hi, 0), (hi, 1)]);
    // What a checkpoint covers may be gone.
    let compacted = BTreeMap::from([(lo, 3), (hi, 1)]);
    assert!(withheld(&clocks, &index, &compacted).is_empty());
}

/// A store-planted junk `<seq>.c` beside this device's own `<seq>` is no
/// way around the self-rollback check: the frame that wins the twin is
/// judged as any own frame is.
#[tokio::test]
async fn a_junk_twin_beside_an_own_frame_still_trips_self_rollback() {
    let (vault, _, members) = genesis(0);
    let me = device(1);
    let chain = data_chain(&me, vault, 3, 1, &[]);
    let mut frames = members;
    frames.extend(chain.iter().cloned());
    let (_, store) = seed(frames, false).await;
    let bare = RemotePath::frame(vault, FrameKind::Data, me.device_id(), 2);
    let dotc = RemotePath::frame(vault, FrameKind::Checkpoint, me.device_id(), 2);
    store.inner().plant(&dotc.to_name(), b"junk");

    let anchor = SyncAnchor::default();
    let plan = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    assert_eq!(plan.twins, [(bare, dotc)]);
    // The replica holds seqs 0 and 1 (restored from a backup), not 2.
    let ids: Vec<_> = chain.iter().map(Frame::id).collect();
    let local = |log, seq: u64| (log == LogKind::Data && seq < 2).then(|| ids[seq as usize]);
    let judged = plan.judge(
        &vault,
        &anchor,
        &me.device_id(),
        local,
        &fetch(&store, &plan).await,
    );
    let rollbacks: Vec<_> = judged
        .anomalies
        .iter()
        .filter_map(|a| match a {
            RemoteAnomaly::SelfRollback(r) => Some(r.remote_ahead.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(rollbacks, [vec![bare]], "{:?}", judged.anomalies);
    assert!(!judged.frames.contains(&chain[2]), "never applied");
}

/// A twin the store kept only one half of between LIST and GET is that
/// half, judged like any other object.
#[tokio::test]
async fn a_twin_with_one_half_gone_is_judged_by_the_half_left() {
    let (vault, _, members) = genesis(0);
    let a = device(1);
    let chain = data_chain(&a, vault, 2, 1, &[]);
    let mut frames = members;
    frames.extend(chain.iter().cloned());
    let (_, store) = seed(frames, false).await;
    let twin = data_frame(&a, vault, 2, chain[1].id(), 1, true);
    let bare = RemotePath::frame(vault, FrameKind::Data, a.device_id(), 2);
    let dotc = RemotePath::frame(vault, FrameKind::Checkpoint, a.device_id(), 2);
    store.inner().plant(&bare.to_name(), b"junk");
    store.inner().plant(&dotc.to_name(), &twin.encode());

    let anchor = SyncAnchor::default();
    let plan = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    assert_eq!(plan.twins, [(bare, dotc)]);
    let mut fetched = fetch(&store, &plan).await;
    fetched.remove(&bare);
    let me = device(9).device_id();
    let judged = plan.judge(&vault, &anchor, &me, |_, _| None, &fetched);
    assert!(judged.anomalies.is_empty(), "{:?}", judged.anomalies);
    assert!(judged.frames.contains(&twin), "the half left is kept");
    // ...and a half left that is junk is an anomaly, not silence.
    let mut fetched = fetch(&store, &plan).await;
    fetched.remove(&dotc);
    let judged = plan.judge(&vault, &anchor, &me, |_, _| None, &fetched);
    assert!(
        judged.anomalies.iter().any(|x| matches!(x,
            RemoteAnomaly::Mismatched { name, .. } if *name == bare.to_name())),
        "{:?}",
        judged.anomalies
    );
}

/// A twin at the anchored tip is checked against the anchor, never applied
/// again: junk beside the anchored frame is quiet, a swapped frame beside
/// junk is a regression.
#[tokio::test]
async fn a_twin_at_the_anchored_tip_is_checked_not_applied_again() {
    let (vault, _, members) = genesis(0);
    let a = device(1);
    let chain = data_chain(&a, vault, 3, 1, &[]);
    let mut frames = members;
    frames.extend(chain.iter().cloned());
    let (_, store) = seed(frames, false).await;
    let mut anchor = SyncAnchor::default();
    let first = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    apply(&store, &vault, &mut anchor, &first).await;
    let bare = RemotePath::frame(vault, FrameKind::Data, a.device_id(), 2);
    let dotc = RemotePath::frame(vault, FrameKind::Checkpoint, a.device_id(), 2);
    store.inner().plant(&dotc.to_name(), b"junk");

    let me = device(9).device_id();
    let plan = plan_pull(&store, &vault, &anchor, None).await.unwrap();
    assert!(plan.verify.contains(&bare) && plan.verify.contains(&dotc));
    let judged = plan.judge(
        &vault,
        &anchor,
        &me,
        |_, _| None,
        &fetch(&store, &plan).await,
    );
    assert!(judged.anomalies.is_empty(), "{:?}", judged.anomalies);
    assert!(
        judged.frames.is_empty(),
        "the anchored tip isn't applied again"
    );

    let swapped = data_frame(&a, vault, 2, chain[1].id(), 7, false);
    store.inner().plant(&bare.to_name(), &swapped.encode());
    let judged = plan.judge(
        &vault,
        &anchor,
        &me,
        |_, _| None,
        &fetch(&store, &plan).await,
    );
    assert!(
        judged.anomalies.iter().any(|x| matches!(
            x,
            RemoteAnomaly::RemoteRegressed {
                expected_seq: 2,
                ..
            }
        )),
        "{:?}",
        judged.anomalies
    );
}
