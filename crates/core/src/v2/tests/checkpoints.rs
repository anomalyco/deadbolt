//! Proof gap #2: the folded state and `state_mac` are bit-identical with and without
//! compaction, including 60-day-offline late writers whose frames branched before the
//! checkpoint, under random delivery orders. Run at `PROPTEST_CASES=2000`.

use proptest::prelude::*;

use super::super::*;
use super::sim::{DAY_MS, K_MAC, Sim, adders, membership, op, sealed};

type OpSpec = (u8, u8, u8, u8, u8);

#[derive(Debug, Clone)]
enum Step {
    Write(u8, Vec<OpSpec>),
    Sync(u8, u8),
}

fn step() -> impl Strategy<Value = Step> {
    let spec = (0u8..10, 0u8..4, 0u8..3, 0u8..4, any::<u8>());
    prop_oneof![
        3 => (any::<u8>(), prop::collection::vec(spec, 1..4)).prop_map(|(d, ops)| Step::Write(d, ops)),
        2 => (any::<u8>(), any::<u8>()).prop_map(|(a, b)| Step::Sync(a, b)),
    ]
}

#[derive(Debug, Clone)]
struct Scenario {
    n: usize,
    /// Devices that go offline for 60 days after phase 1 (the last device always does).
    offline_mask: u8,
    removal: Option<(u8, Option<u64>)>,
    /// The checkpointer has not yet seen the removal.
    stale: bool,
    second_checkpoint: bool,
    /// Per-author frontier cuts (seq limits) for each checkpoint, or none.
    cuts: Option<([u64; 5], [u64; 5])>,
    phases: [Vec<Step>; 4],
    seed: u64,
}

fn scenario() -> impl Strategy<Value = Scenario> {
    (
        3usize..=5,
        any::<u8>(),
        prop::option::of((any::<u8>(), prop::option::of(0u64..6))),
        any::<bool>(),
        any::<bool>(),
        prop::option::of((
            prop::array::uniform5(0u64..8),
            prop::array::uniform5(0u64..12),
        )),
        [
            prop::collection::vec(step(), 0..10),
            prop::collection::vec(step(), 1..16),
            prop::collection::vec(step(), 0..12),
            prop::collection::vec(step(), 0..6),
        ],
        any::<u64>(),
    )
        .prop_map(
            |(n, offline_mask, removal, stale, second_checkpoint, cuts, phases, seed)| Scenario {
                n,
                offline_mask,
                removal,
                stale,
                second_checkpoint,
                cuts,
                phases,
                seed,
            },
        )
}

fn run(sim: &mut Sim, steps: &[Step]) {
    let n = sim.n;
    for s in steps {
        match s {
            Step::Write(d, specs) => {
                let d = usize::from(*d) % n;
                let ops = specs.iter().map(|&spec| op(d, n, spec)).collect();
                sim.write(d, ops);
            }
            Step::Sync(a, b) => sim.sync(usize::from(*a) % n, usize::from(*b) % n),
        }
    }
}

/// Folds `pack` plus every frame it does not cover and checks it against the full fold.
fn check_pack(
    sim: &Sim,
    ctx: &FoldContext<'_>,
    pack: &Pack,
    full: &FoldedState,
    full_mac: [u8; 32],
    stale: bool,
    seed: u64,
) -> Result<(), TestCaseError> {
    let frontier = &pack.meta.frontier;
    let tail: Vec<&DataFrame> = sim
        .shuffled(seed)
        .into_iter()
        .filter(|f| frontier.get(&f.author).is_none_or(|(s, _)| f.seq > *s))
        .collect();
    match fold_from_checkpoint(ctx, pack, tail) {
        Ok(state) => {
            prop_assert_eq!(&state, full);
            prop_assert_eq!(state_mac(&K_MAC, &state).unwrap(), full_mac);
            // Delivering the already-covered frames again changes nothing.
            let again = fold_from_checkpoint(ctx, pack, sim.shuffled(seed ^ 7)).unwrap();
            prop_assert_eq!(&again, full);
        }
        Err(CheckpointError::Invalidated(_)) => {
            prop_assert!(
                stale,
                "only a checkpoint made before a removal can be invalidated"
            );
        }
        Err(e) => prop_assert!(false, "unexpected error {e}"),
    }
    Ok(())
}

fn prove(sc: &Scenario) -> Result<(), TestCaseError> {
    let n = sc.n;
    let late = n - 1;
    let removal = sc
        .removal
        .map(|(v, last)| (1 + usize::from(v) % (n - 1), last));
    let final_m = membership(n, removal);
    let ckpt_m = if sc.stale {
        membership(n, None)
    } else {
        final_m.clone()
    };
    let adders = adders(n);
    let ctx = FoldContext {
        membership: &final_m,
        adders: &adders,
    };
    let ckpt_ctx = FoldContext {
        membership: &ckpt_m,
        adders: &adders,
    };

    let mut sim = Sim::new(n);
    run(&mut sim, &sc.phases[0]);
    // 60 days offline: the late writer (and maybe others) keep writing on stale clocks.
    sim.offline.insert(late);
    for d in 1..n - 1 {
        if sc.offline_mask & (1 << d) != 0 {
            sim.offline.insert(d);
        }
    }
    run(&mut sim, &sc.phases[1]);
    sim.now_ms += 60 * DAY_MS;
    let checkpointer = (0..n).find(|d| !sim.offline.contains(d)).unwrap_or(0);
    let cut1 = sc.cuts.map(|c| c.0);
    let cut2 = sc.cuts.map(|c| c.1);
    let (pack1, bytes1, ckpt1) =
        sim.checkpoint_cut(checkpointer, &ckpt_ctx, None, cut1.as_ref().map(|c| &c[..]));
    run(&mut sim, &sc.phases[2]);
    let second = sc.second_checkpoint.then(|| {
        let cut = cut2.as_ref().map(|c| &c[..]);
        sim.checkpoint_cut(checkpointer, &ckpt_ctx, Some(&pack1), cut)
    });
    run(&mut sim, &sc.phases[3]);
    // The late writers come back: every frame is delivered.
    sim.offline.clear();

    // (a) Full uncompacted fold from genesis, order-independent.
    let full = fold_from_scratch(&ctx, sim.shuffled(sc.seed));
    prop_assert_eq!(&fold_from_scratch(&ctx, sim.shuffled(!sc.seed)), &full);
    let full_mac = state_mac(&K_MAC, &full).unwrap();
    prop_assert_eq!(
        FoldedState::decode(&full.encode().unwrap()).unwrap(),
        full.clone()
    );
    // Compacting everything leaves nothing to fold and the same state.
    let all = compact(&ctx, None, sim.shuffled(sc.seed ^ 3)).unwrap();
    prop_assert_eq!(&all.state, &full);

    // (b) Checkpoint pack (from its bytes) + post-frontier and late tail.
    let decoded1 = super::sim::round_trip(&pack1);
    check_pack(&sim, &ctx, &decoded1, &full, full_mac, sc.stale, sc.seed)?;
    if let Some((pack2, bytes2, ckpt2)) = &second {
        prop_assert_eq!(&super::sim::round_trip(pack2), pack2);
        check_pack(&sim, &ctx, pack2, &full, full_mac, sc.stale, sc.seed ^ 11)?;
        let frame = &sim.frames[*ckpt2];
        let DataBody::Checkpoint(payload) = &frame.body else {
            unreachable!()
        };
        prop_assert_eq!(
            verify_checkpoint(
                &K_MAC,
                &ckpt_ctx,
                frame.id,
                payload,
                Some((pack2, PackCommitment::of(&sealed(bytes2)))),
                sim.shuffled(sc.seed)
            )
            .unwrap(),
            CheckpointVerdict::Agreed
        );
    }

    // A full peer agrees with an honest checkpoint and disputes a tampered one.
    let DataBody::Checkpoint(payload) = &sim.frames[ckpt1].body else {
        unreachable!()
    };
    let id = sim.frames[ckpt1].id;
    let frames = sim.shuffled(sc.seed);
    let verdict = verify_checkpoint(
        &K_MAC,
        &ckpt_ctx,
        id,
        payload,
        Some((&decoded1, PackCommitment::of(&sealed(&bytes1)))),
        frames.iter().copied(),
    );
    prop_assert_eq!(verdict.unwrap(), CheckpointVerdict::Agreed);
    let mut forged = payload.clone();
    forged.state_mac[0] ^= 1;
    let verdict = verify_checkpoint(&K_MAC, &ckpt_ctx, id, &forged, None, frames.iter().copied());
    let expected = state_mac(&K_MAC, &pack1.state).unwrap();
    prop_assert_eq!(
        verdict.unwrap(),
        CheckpointVerdict::Disputed {
            dispute: DataOp::Dispute {
                checkpoint: id,
                expected_state_mac: expected,
            }
        }
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::default())]

    #[test]
    fn prop_state_mac_identical_with_and_without_compaction(sc in scenario()) {
        prove(&sc)?;
    }
}

#[test]
fn incremental_checkpoint_restores_previously_uncompacted_causality() {
    let mut sim = Sim::new(2);
    let membership = membership(2, None);
    let adders = adders(2);
    let ctx = FoldContext {
        membership: &membership,
        adders: &adders,
    };
    sim.write(1, vec![op(1, 2, (4, 0, 0, 0, 0))]);
    sim.sync(0, 1);
    sim.write(0, vec![op(0, 2, (4, 1, 0, 0, 0))]);
    let a0 = &sim.frames[1];
    let frontier = [(a0.author, (a0.seq, a0.id))].into();
    let first =
        super::super::fold::compact_at(&ctx, None, sim.frames.iter(), Some(&frontier)).unwrap();
    assert!(!first.meta.seen_by.is_empty());
    let (second, bytes, index) = sim.checkpoint(0, &ctx, Some(&first));
    let frame = &sim.frames[index];
    let DataBody::Checkpoint(payload) = &frame.body else {
        unreachable!()
    };
    assert_eq!(
        verify_checkpoint(
            &K_MAC,
            &ctx,
            frame.id,
            payload,
            Some((&second, PackCommitment::of(&sealed(&bytes)))),
            sim.frames.iter()
        )
        .unwrap(),
        CheckpointVerdict::Agreed
    );
    let from_genesis =
        super::super::fold::compact_at(&ctx, None, sim.frames.iter(), Some(&second.meta.frontier))
            .unwrap();
    assert_eq!(second.meta, from_genesis.meta);
    assert_eq!(
        payload.meta_mac,
        build_checkpoint(
            &K_MAC,
            &from_genesis,
            payload.pack_commitment(),
            vec![],
            payload.timestamp_ms
        )
        .unwrap()
        .meta_mac
    );
}
