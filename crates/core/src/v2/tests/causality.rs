//! Regression tests for audit #4: register `follows` must be transitive even when a writer's
//! honest (E7) clock is not causally closed, folds from genesis and from a checkpoint must
//! agree exactly, and a forged future `dclock` count must never poison later edits.

use super::super::*;
use super::sim::{K_MAC, Sim, adders, dev, item, membership};

fn set(value: &str) -> DataOp {
    DataOp::SetField {
        item: item(0),
        field: "x".into(),
        value: FieldValue {
            kind: "text".into(),
            value: value.into(),
        },
    }
}

fn values(state: &FoldedState) -> Vec<String> {
    state.items[&item(0)].fields["x"]
        .writes()
        .iter()
        .filter_map(|w| Some(w.value.as_ref()?.value.clone()))
        .collect()
}

/// `a0 -> b0 -> c0`, where `C` read `b0` but has not decrypted `a0`: `c0`'s honest clock is
/// `{B: 1}`. Transitively `c0` still follows `a0`, so in every delivery order and through
/// every checkpoint only `c0` stands.
#[test]
fn non_transitive_e7_clocks_fold_identically_with_and_without_compaction() {
    let m = membership(3, None);
    let adders = adders(3);
    let ctx = FoldContext {
        membership: &m,
        adders: &adders,
    };
    let mut sim = Sim::new(3);
    let a0 = sim.write(0, vec![set("a")]);
    sim.sync(0, 1);
    let b0 = sim.write(1, vec![set("b")]);
    sim.knows[2].insert(b0);
    let c0 = sim.write(2, vec![set("c")]);
    let DataBody::Data(p) = &sim.frames[c0].body else {
        unreachable!()
    };
    assert_eq!(p.dclock.entries(), &[(dev(1), 1)], "C never saw a0");

    let full = fold_from_scratch(&ctx, sim.shuffled(0));
    assert_eq!(values(&full), ["c"]);
    let mac = state_mac(&K_MAC, &full).unwrap();
    for seed in 1..24 {
        assert_eq!(
            fold_from_scratch(&ctx, sim.shuffled(seed)),
            full,
            "seed {seed}"
        );
    }

    let frames =
        |ids: &[usize]| -> Vec<&DataFrame> { ids.iter().map(|&i| &sim.frames[i]).collect() };
    for view in [
        &[a0][..],
        &[a0, b0],
        &[b0],
        &[c0],
        &[b0, c0],
        &[a0, c0],
        &[a0, b0, c0],
    ] {
        let pack = compact(&ctx, None, frames(view)).unwrap();
        for seed in 0..6 {
            let state = fold_from_checkpoint(&ctx, &pack, sim.shuffled(seed)).unwrap();
            assert_eq!(state, full, "view {view:?} seed {seed}");
            assert_eq!(state_mac(&K_MAC, &state).unwrap(), mac);
        }
        let again = super::sim::round_trip(&pack);
        assert_eq!(again, pack);
    }
}

/// A compacted frame that saw a tail frame: `b0` (counted) is compacted while `a0` waits in
/// the tail because the checkpointer did not count `A` yet. Once `a0` counts, the pack's
/// `seen_by` thresholds still say `b0` followed it, exactly as a fold from genesis does.
#[test]
fn a_compacted_frame_still_dominates_the_tail_frame_it_saw() {
    let before = membership(3, Some((0, None)));
    let after = membership(3, None);
    let adders = adders(3);
    let ctx_before = FoldContext {
        membership: &before,
        adders: &adders,
    };
    let ctx = FoldContext {
        membership: &after,
        adders: &adders,
    };
    let mut sim = Sim::new(3);
    let a0 = sim.write(0, vec![set("a")]);
    sim.sync(0, 1);
    let b0 = sim.write(1, vec![set("b")]);
    let pack = compact(&ctx_before, None, [&sim.frames[a0], &sim.frames[b0]]).unwrap();
    assert!(!pack.meta.frontier.contains_key(&dev(0)));
    assert_eq!(pack.meta.seen_by[&(dev(0), 0)], [(dev(1), 0)].into());
    sim.sync(1, 2);
    sim.write(2, vec![set("c")]);

    let full = fold_from_scratch(&ctx, sim.shuffled(3));
    assert_eq!(values(&full), ["c"]);
    let decoded = super::sim::round_trip(&pack);
    assert_eq!(
        fold_from_checkpoint(&ctx, &decoded, sim.shuffled(4)).unwrap(),
        full
    );
}

/// A data frame with a synthetic id, built directly so its `dclock` can be forged.
fn forged(
    author: usize,
    seq: u64,
    prev: FrameId,
    dclock: Vec<(crate::id::DeviceId, u64)>,
    ops: Vec<DataOp>,
) -> DataFrame {
    let payload = DataPayload {
        mheads: Vec::new(),
        dclock: DeltaClock::new(dclock).unwrap(),
        timestamp_ms: 1,
        ops,
    };
    let bytes = payload.encode().unwrap();
    DataFrame {
        id: FrameId::from_bytes(blake3::hash(&bytes).into()),
        author: dev(author),
        seq,
        prev,
        epoch: EpochId::ZERO,
        body: DataBody::Data(payload),
    }
}

/// A "super-clock": `M` claims to have seen `u64::MAX` frames of `A`. That frame never
/// resolves, so it is never applied or compacted, and `A`'s later edits still win. A cycle of
/// frames naming each other's future never resolves either.
#[test]
fn forged_future_counts_never_apply_or_poison_later_edits() {
    let m = membership(3, None);
    let adders = adders(3);
    let ctx = FoldContext {
        membership: &m,
        adders: &adders,
    };
    let mut sim = Sim::new(3);
    let poison = forged(
        2,
        0,
        FrameId::ZERO,
        vec![(dev(0), u64::MAX)],
        vec![set("m")],
    );
    sim.write(0, vec![set("a0")]);
    sim.write(0, vec![set("a1")]);
    let mut frames: Vec<DataFrame> = sim.frames.clone();
    frames.push(poison.clone());
    // B and C name each other's next frame: a cycle.
    let b0 = forged(1, 0, FrameId::ZERO, vec![(dev(2), 2)], vec![set("cycle-b")]);
    let c1 = forged(2, 1, poison.id, vec![(dev(1), 1)], vec![set("cycle-c")]);
    frames.extend([b0, c1]);

    let state = fold_from_scratch(&ctx, &frames);
    assert_eq!(values(&state), ["a1"]);
    let pack = compact(&ctx, None, &frames).unwrap();
    assert_eq!(pack.state, state);
    assert!(!pack.meta.frontier.contains_key(&dev(1)));
    assert!(!pack.meta.frontier.contains_key(&dev(2)));
    assert_eq!(pack.meta.frontier[&dev(0)].0, 1);
}
