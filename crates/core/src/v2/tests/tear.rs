//! Regressions from round 2 of the model-based hunt (`tear`), each reproducing its shrunk
//! counterexample: a forked data stream no longer freezes honest frames that cite it, GC never
//! strands collected frames behind a base that cannot rebuild them, and data sealed under an
//! epoch that lost its authorization counts for nobody and is re-emitted by its writer.

use std::collections::{BTreeMap, BTreeSet};

use crate::id::DeviceId;

use super::super::*;
use super::epochs::{kem_map, pool};
use super::revocation::vault_with;
use super::sim::{K_MAC, Sim, adders, dev, item, membership};

fn set(field: &str, value: &str) -> DataOp {
    DataOp::SetField {
        item: item(0),
        field: field.into(),
        value: FieldValue {
            kind: "text".into(),
            value: value.into(),
        },
    }
}

fn mac(ctx: &FoldContext<'_>, frames: &[&DataFrame]) -> [u8; 32] {
    state_mac(&K_MAC, &fold_from_scratch(ctx, frames.iter().copied())).unwrap()
}

// ---------------------------------------------------------------------------------------------
// B: a forked data stream
// ---------------------------------------------------------------------------------------------

/// `[Write{3}, Sync{3,2}, ForkData{3}, Write{2}]`: honest `2:0` cites `(dev3, 1)`. A peer
/// holding both siblings of `3:0` used to cut device 3's chain at seq 0 and wait forever for
/// `(dev3, 1)`, freezing `2:0` and everything after it. Every peer now folds alike, whether
/// it holds one sibling and the fraud proof, both siblings, or only the honest frame.
#[test]
fn a_forked_stream_never_freezes_honest_frames_that_cite_it() {
    let mut sim = Sim::new(4);
    let first = sim.write(3, vec![set("user", "by 3")]);
    sim.sync(3, 2);
    let honest = sim.write(2, vec![set("pass", "by 2")]);
    let DataBody::Data(p) = &sim.frames[honest].body else {
        unreachable!()
    };
    assert_eq!(p.dclock.entries(), [(dev(3), 1)], "2:0 cites 3:0");
    let mut sibling = sim.frames[first].clone();
    sibling.id = FrameId::from_bytes([0xf0; 32]);
    if let DataBody::Data(p) = &mut sibling.body {
        p.ops = vec![set("user", "forked by 3")];
    }
    let (a, b, h) = (&sim.frames[first], &sibling, &sim.frames[honest]);

    // A fraud proof (or both siblings) puts device 3's data fork at seq 0.
    let mut aware = membership(4, Some((3, None)));
    aware.data_fork_seq.insert(dev(3), 0);
    let unaware = membership(4, None);
    let adders = adders(4);
    let ctx = |m| FoldContext {
        membership: m,
        adders: &adders,
    };
    let both = fold_from_scratch(&ctx(&aware), [a, b, h]);
    assert!(
        both.dots().contains(&(dev(2), 0)),
        "2:0 must not wait for the cut stream"
    );
    let expected = mac(&ctx(&aware), &[h]);
    for held in [vec![a, h], vec![b, h], vec![a, b, h], vec![h, b, a]] {
        assert_eq!(mac(&ctx(&aware), &held), expected, "{held:?}");
    }
    // Holding both siblings is proof enough, before the fraud proof resolves.
    assert_eq!(mac(&ctx(&unaware), &[a, b, h]), expected);

    // Compacting and folding on top of the checkpoint agrees too.
    let pack = compact(&ctx(&aware), None, [a, b, h]).unwrap();
    assert!(!pack.meta.frontier.contains_key(&dev(3)));
    let on_top = fold_from_checkpoint(&ctx(&aware), &pack, [a, b, h]).unwrap();
    assert_eq!(state_mac(&K_MAC, &on_top).unwrap(), expected);
}

// ---------------------------------------------------------------------------------------------
// C: GC bases and collected frames
// ---------------------------------------------------------------------------------------------

fn gc_checkpoint(id: u8, frontier: &[(usize, u64)]) -> GcCheckpoint {
    GcCheckpoint {
        id: FrameId::from_bytes([id; 32]),
        author: dev(0),
        seq: 50,
        first_seen_ms: 0,
        meta: PackMeta {
            frontier: frontier
                .iter()
                .map(|&(d, s)| (dev(d), (s, FrameId::ZERO)))
                .collect(),
            ..PackMeta::default()
        },
    }
}

fn gc_frames(upto: &[(usize, u64)]) -> Vec<GcFrame> {
    upto.iter()
        .flat_map(|&(d, n)| {
            (0..=n).map(move |s| GcFrame {
                id: FrameId::from_bytes(
                    [u8::try_from(d * 32).unwrap() + u8::try_from(s).unwrap(); 32],
                ),
                author: dev(d),
                seq: s,
            })
        })
        .collect()
}

fn covering(members: &BTreeSet<DeviceId>) -> BTreeMap<DeviceId, VectorClock> {
    let clock = VectorClock::from_counts([(dev(0), 51)]);
    members.iter().map(|m| (*m, clock.clone())).collect()
}

/// Repro 1: device X collects behind base `c1` (dev0 ≤ 5, dev1 ≤ 2); device Y, which also
/// holds the bigger `c2` (dev0 ≤ 3, dev1 ≤ 6), used to pick `c2` and collect dev1 3..=6,
/// leaving dev0 4..=5 (gone behind `c1`) and dev1 3..=6 (gone behind `c2`) rebuildable from
/// neither. Given what was collected, Y only accepts a base that covers it.
#[test]
fn concurrent_gcs_never_pick_a_base_that_misses_collected_frames() {
    let m = membership(2, None);
    let clocks = covering(&m.devices);
    let none = BTreeSet::new();
    let frames = gc_frames(&[(0, 8), (1, 8)]);
    let (c1, c2) = (
        gc_checkpoint(1, &[(0, 5), (1, 2)]),
        gc_checkpoint(2, &[(0, 3), (1, 6)]),
    );

    let x = plan_gc(
        0,
        &m,
        &clocks,
        std::slice::from_ref(&c1),
        &none,
        &frames,
        &BTreeMap::new(),
    );
    assert_eq!(x.base, Some(c1.id));
    let collected: BTreeMap<DeviceId, u64> = c1
        .meta
        .frontier
        .iter()
        .map(|(a, (s, _))| (*a, *s))
        .collect();

    let both = [c1.clone(), c2.clone()];
    let naive = plan_gc(0, &m, &clocks, &both, &none, &frames, &BTreeMap::new());
    assert_eq!(
        naive.base,
        Some(c2.id),
        "without the floor, Y prefers the bigger c2"
    );
    let y = plan_gc(0, &m, &clocks, &both, &none, &frames, &collected);
    assert_eq!(y.base, Some(c1.id));
    assert!(y.stranded.is_empty());

    // A base dominating the floor is fine; one that only knows c2 strands dev0 ≤ 5 and deletes
    // nothing.
    let c3 = gc_checkpoint(3, &[(0, 7), (1, 6)]);
    let z = plan_gc(
        0,
        &m,
        &clocks,
        &[c1, c2.clone(), c3.clone()],
        &none,
        &frames,
        &collected,
    );
    assert_eq!(z.base, Some(c3.id));
    let lone = plan_gc(0, &m, &clocks, &[c2], &none, &frames, &collected);
    assert_eq!(lone.base, None);
    assert!(lone.delete_frames.is_empty());
    assert_eq!(lone.stranded, [(dev(0), 5)].into());
}

/// Repro 2: after a GC collected dev1 ≤ 2 behind `c1`, a `Remove(dev1)` whose `last_seen_seq`
/// came from the frames the remover still held (none) cut dev1 below the collected frames,
/// invalidating every surviving checkpoint. `removal_last_seen` raises it to what was collected;
/// the planner re-checks checkpoints against membership and reports the stranded floor.
#[test]
fn a_post_gc_removal_cannot_orphan_the_surviving_checkpoint() {
    let before = membership(3, None);
    let none = BTreeSet::new();
    let c1 = gc_checkpoint(1, &[(0, 5), (1, 2)]);
    let collected: BTreeMap<DeviceId, u64> = [(dev(0), 5), (dev(1), 2)].into();
    let frames = gc_frames(&[(0, 8), (1, 4)]);
    let clocks = covering(&before.devices);
    let plan = plan_gc(
        0,
        &before,
        &clocks,
        std::slice::from_ref(&c1),
        &none,
        &frames,
        &collected,
    );
    assert_eq!(plan.base, Some(c1.id));

    // The remover holds none of dev1's collected frames.
    let held = None;
    assert_eq!(removal_last_seen(&dev(1), held, &collected), Some(2));
    assert_eq!(removal_last_seen(&dev(1), Some(4), &collected), Some(4));
    assert_eq!(removal_last_seen(&dev(2), None, &collected), None);

    let clamped = membership(3, Some((1, removal_last_seen(&dev(1), held, &collected))));
    assert_eq!(check_counts(&clamped, &c1.meta), Ok(()));
    let clocks = covering(&clamped.devices);
    let plan = plan_gc(
        0,
        &clamped,
        &clocks,
        std::slice::from_ref(&c1),
        &none,
        &frames,
        &collected,
    );
    assert_eq!(plan.base, Some(c1.id));
    assert!(plan.stranded.is_empty() && plan.invalidated.is_empty());

    // The unclamped cutoff invalidates c1: never a base, nothing deleted, the floor reported.
    let cut = membership(3, Some((1, held)));
    assert_eq!(
        check_counts(&cut, &c1.meta),
        Err(CheckpointError::Invalidated(dev(1)))
    );
    let plan = plan_gc(
        0,
        &cut,
        &clocks,
        std::slice::from_ref(&c1),
        &none,
        &frames,
        &collected,
    );
    assert_eq!(plan.invalidated, [c1.id].into());
    assert!(plan.eligible.is_empty() && plan.base.is_none() && plan.delete_frames.is_empty());
    assert_eq!(
        plan.stranded, collected,
        "c1 was the only checkpoint covering either floor"
    );
}

// ---------------------------------------------------------------------------------------------
// D: data under an epoch that loses its authorization
// ---------------------------------------------------------------------------------------------

fn payload(value: &str) -> DataPayload {
    DataPayload {
        mheads: Vec::new(),
        dclock: DeltaClock::default(),
        timestamp_ms: 1,
        ops: vec![set("user", value)],
    }
}

fn ring_of(graph: &EpochGraph, keys: &DeviceKeys) -> EpochKeyring {
    let mut ring = EpochKeyring::new();
    graph.unlock(&keys.device_id(), keys.kem_key(), &mut ring);
    ring
}

/// A reader's view of a data frame: opened if it holds the key, else by header alone.
fn as_read(frame: &Frame, ring: &EpochKeyring) -> DataFrame {
    ring.get(&frame.header().epoch).map_or_else(
        || DataFrame::unreadable(frame).unwrap(),
        |key| DataFrame::open(frame, key).unwrap(),
    )
}

/// Repro 1, `[ForkRecovery, Add{A->D}, DeliverOne{C}, Write{C}, Quiesce]`: C holds only the
/// root's rotation to R1 and writes under its epoch `er`; the root also signed a sibling at the
/// same Member seq, voiding both, so `er` loses authorization. Reader duty never rewraps `er`
/// (the round-1 I3 rule), so D could never read C's write. It now counts for nobody, C learns to
/// re-emit it, and C and D fold the same state.
#[test]
fn data_under_a_rotation_a_root_fork_voided_is_uncounted_and_re_emitted() {
    let p = pool();
    let (a, b, c, d) = (&p.devices[0], &p.devices[1], &p.devices[2], &p.devices[3]);
    let (r0, r1) = (&p.roots[0], &p.roots[1]);
    let v = vault_with(&[a, b, c]);
    let vault = v.vault;
    let res = resolve(&vault, &v.frames, &[]);
    let last = v.frames.last().unwrap().id();
    let mut root_ring = EpochKeyring::new();
    root_ring.insert(v.e0, v.k0.clone());

    // ForkRecovery: two root frames at Member seq 4.
    let mut to_r1 = kem_map(&res);
    to_r1.remove(&r0.recovery_id());
    to_r1.insert(r1.recovery_id(), r1.kem_public());
    let consent =
        sign_rotate_recovery_consent(&p.root_sks[1], &vault, &r0.recovery_id(), &r1.kem_public());
    let kr = EpochKey::from_bytes([0x81; 32]);
    let rotation = build_rotate_recovery_frame(
        &p.root_sks[0],
        vault,
        &res,
        4,
        last,
        vec![last],
        r1.recovery_id(),
        r1.kem_public(),
        consent,
        &kr,
        vec![v.e0],
        &root_ring,
        &to_r1,
    )
    .unwrap();
    let er = EpochId::from_frame_id(rotation.id());
    let ks = EpochKey::from_bytes([0x82; 32]);
    let sibling = build_standalone_rotate_frame(
        &p.root_sks[0],
        vault,
        &res,
        4,
        last,
        vec![last],
        &ks,
        vec![v.e0],
        &root_ring,
        &kem_map(&res),
    )
    .unwrap();
    // Add{A->D}, under e0.
    let add_d = build_add_frame(
        a.sign_key(),
        vault,
        &res,
        0,
        FrameId::ZERO,
        vec![last],
        d.device_id(),
        d.kem_public(),
        sign_join_consent(d, &vault, &a.device_id()),
        Some((v.e0, &v.k0)),
    )
    .unwrap();

    // DeliverOne{C}: C holds only the rotation, whose epoch is its clean tip. Write{C}.
    let mut c_view = v.frames.clone();
    c_view.push(rotation.clone());
    let res_c = resolve(&vault, &c_view, &[]);
    let graph_c = EpochGraph::build(vault, &c_view, &res_c);
    let c_ring = ring_of(&graph_c, c);
    assert_eq!(
        graph_c.select_write_epoch(&res_c, &c_ring, &BTreeSet::new()),
        WriteEpochDecision::Use(er)
    );
    let w0 = payload("by C")
        .seal(c.sign_key(), vault, 0, FrameId::ZERO, er, &kr)
        .unwrap();

    // Quiesce: the fork voids the rotation.
    let mut all = v.frames.clone();
    all.extend([rotation, sibling, add_d.clone()]);
    let res_all = resolve(&vault, &all, &[]);
    assert!(res_all.recovery_frozen);
    assert!(!res_all.is_authorized_epoch(&er));
    assert!(res_all.is_active_device(&c.device_id()) && res_all.is_active_device(&d.device_id()));
    let graph = EpochGraph::build(vault, &all, &res_all);
    let c_ring = ring_of(&graph, c);
    assert!(!ring_of(&graph, d).contains(&er));
    assert!(
        graph
            .needed_rewraps(&c_ring, &res_all, &[er].into())
            .iter()
            .all(|(e, _)| *e != er),
        "reader duty must never rewrap the voided epoch"
    );
    let adders = adders_from_frames(&res_all, &all);
    let ctx = FoldContext {
        membership: &res_all,
        adders: &adders,
    };
    let w0_c = DataFrame::open(&w0, &kr).unwrap();
    assert!(res_all.counts_data(&c.device_id(), 0, &[]));
    assert!(
        !ctx.counts(&w0_c),
        "data under a voided epoch counts for nobody"
    );
    assert_eq!(uncounted_own_frames(&ctx, &c.device_id(), [&w0_c]), [&w0_c]);

    // A mints the clean tip; C re-emits under it.
    let a_ring = ring_of(&graph, a);
    let WriteEpochDecision::MintRotate { parents } =
        graph.select_write_epoch(&res_all, &a_ring, &BTreeSet::new())
    else {
        panic!("no clean tip after the fork");
    };
    let kq = EpochKey::from_bytes([0x83; 32]);
    let merge = build_standalone_rotate_frame(
        a.sign_key(),
        vault,
        &res_all,
        1,
        add_d.id(),
        vec![add_d.id()],
        &kq,
        parents,
        &a_ring,
        &kem_map(&res_all),
    )
    .unwrap();
    let eq = EpochId::from_frame_id(merge.id());
    all.push(merge);
    let res_q = resolve(&vault, &all, &[]);
    let graph = EpochGraph::build(vault, &all, &res_q);
    let (c_ring, d_ring) = (ring_of(&graph, c), ring_of(&graph, d));
    assert_eq!(
        graph.select_write_epoch(&res_q, &c_ring, &BTreeSet::new()),
        WriteEpochDecision::Use(eq)
    );
    let w1 = payload("by C")
        .seal(c.sign_key(), vault, 1, w0.id(), eq, &kq)
        .unwrap();
    let adders = adders_from_frames(&res_q, &all);
    let ctx = FoldContext {
        membership: &res_q,
        adders: &adders,
    };
    let at_c = [as_read(&w0, &c_ring), as_read(&w1, &c_ring)];
    let at_d = [as_read(&w0, &d_ring), as_read(&w1, &d_ring)];
    let blind = [DataFrame::unreadable(&w0).unwrap(), as_read(&w1, &d_ring)];
    let state = fold_from_scratch(&ctx, &at_c);
    assert_eq!(state.dots(), [(c.device_id(), 1)].into());
    let expected = mac(&ctx, &at_c.iter().collect::<Vec<_>>());
    assert_eq!(mac(&ctx, &at_d.iter().collect::<Vec<_>>()), expected);
    assert_eq!(mac(&ctx, &blind.iter().collect::<Vec<_>>()), expected);
}

/// Repro 2, `[Add{B->E}, Remove{B->C}, Remove{E->B}, Write{E}, Quiesce]`: E removes B and
/// writes under that removal's epoch `e2`, but `Remove(B)` loses to B's `Remove(C)`, so B
/// stays a member and could never read E's write. The write now counts for nobody; B folds it
/// by header alone, E re-emits it under the clean tip, and both fold the same state. C, removed,
/// still cannot open the clean tip (I3).
#[test]
fn data_under_a_losing_removals_epoch_is_uncounted_and_re_emitted() {
    let p = pool();
    let (a, b, c, e) = (&p.devices[0], &p.devices[1], &p.devices[2], &p.devices[4]);
    let v = vault_with(&[a, b, c]);
    let vault = v.vault;
    let last = v.frames.last().unwrap().id();
    let mut e0_ring = EpochKeyring::new();
    e0_ring.insert(v.e0, v.k0.clone());
    let res0 = resolve(&vault, &v.frames, &[]);
    let add_e = build_add_frame(
        b.sign_key(),
        vault,
        &res0,
        0,
        FrameId::ZERO,
        vec![last],
        e.device_id(),
        e.kem_public(),
        sign_join_consent(e, &vault, &b.device_id()),
        Some((v.e0, &v.k0)),
    )
    .unwrap();
    let mut view = v.frames.clone();
    view.push(add_e.clone());
    let res1 = resolve(&vault, &view, &[]);
    let without = |gone: &DeviceKeys| {
        let mut to = kem_map(&res1);
        to.remove(&gone.device_id());
        to
    };
    let k1 = EpochKey::from_bytes([0x91; 32]);
    let remove_c = build_remove_frame(
        b.sign_key(),
        vault,
        &res1,
        1,
        add_e.id(),
        vec![add_e.id()],
        c.device_id(),
        None,
        &k1,
        vec![v.e0],
        &e0_ring,
        &without(c),
    )
    .unwrap();
    let e1 = EpochId::from_frame_id(remove_c.id());
    let k2 = EpochKey::from_bytes([0x92; 32]);
    let remove_b = build_remove_frame(
        e.sign_key(),
        vault,
        &res1,
        0,
        FrameId::ZERO,
        vec![add_e.id()],
        b.device_id(),
        None,
        &k2,
        vec![v.e0],
        &e0_ring,
        &without(b),
    )
    .unwrap();
    let e2 = EpochId::from_frame_id(remove_b.id());

    // E's view: its own removal of B is the clean tip.
    let mut e_view = view.clone();
    e_view.push(remove_b.clone());
    let res_e = resolve(&vault, &e_view, &[]);
    let graph_e = EpochGraph::build(vault, &e_view, &res_e);
    assert_eq!(
        graph_e.select_write_epoch(&res_e, &ring_of(&graph_e, e), &BTreeSet::new()),
        WriteEpochDecision::Use(e2)
    );
    let w0 = payload("by E")
        .seal(e.sign_key(), vault, 0, FrameId::ZERO, e2, &k2)
        .unwrap();

    // Quiesce: B's Remove(C) wins, E's Remove(B) loses.
    let mut all = view;
    all.extend([remove_c, remove_b]);
    let res = resolve(&vault, &all, &[]);
    assert!(res.is_active_device(&b.device_id()));
    assert!(!res.is_active_device(&c.device_id()));
    assert!(!res.is_authorized_epoch(&e2) && res.is_authorized_epoch(&e1));
    let graph = EpochGraph::build(vault, &all, &res);
    let (b_ring, e_ring) = (ring_of(&graph, b), ring_of(&graph, e));
    assert!(!b_ring.contains(&e2));
    assert!(
        graph
            .needed_rewraps(&e_ring, &res, &[e2].into())
            .iter()
            .all(|(ep, _)| *ep != e2),
        "reader duty must never rewrap the losing removal's epoch"
    );
    let adders = adders_from_frames(&res, &all);
    let ctx = FoldContext {
        membership: &res,
        adders: &adders,
    };
    let w0_e = DataFrame::open(&w0, &k2).unwrap();
    assert!(!ctx.counts(&w0_e));
    let redo = uncounted_own_frames(&ctx, &e.device_id(), [&w0_e]);
    assert_eq!(redo, [&w0_e]);

    // E re-emits the same ops under the clean tip e1.
    assert_eq!(
        graph.select_write_epoch(&res, &e_ring, &BTreeSet::new()),
        WriteEpochDecision::Use(e1)
    );
    let DataBody::Data(ops) = &redo[0].body else {
        unreachable!()
    };
    let again = DataPayload {
        ops: ops.ops.clone(),
        ..payload("")
    };
    let w1 = again
        .seal(e.sign_key(), vault, 1, w0.id(), e1, &k1)
        .unwrap();
    let at_e = [as_read(&w0, &e_ring), as_read(&w1, &e_ring)];
    let at_b = [as_read(&w0, &b_ring), as_read(&w1, &b_ring)];
    assert_eq!(at_b[0], DataFrame::unreadable(&w0).unwrap());
    let state = fold_from_scratch(&ctx, &at_b);
    assert_eq!(state.dots(), [(e.device_id(), 1)].into());
    assert_eq!(
        mac(&ctx, &at_b.iter().collect::<Vec<_>>()),
        mac(&ctx, &at_e.iter().collect::<Vec<_>>())
    );
    // Every frame that counts is one B can open.
    for f in [&w0, &w1] {
        let read = as_read(f, &e_ring);
        assert_eq!(ctx.counts(&read), b_ring.contains(&f.header().epoch));
    }
    assert!(!ring_of(&graph, c).contains(&e1), "I3: removed C opened e1");
}
