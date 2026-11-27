//! Named tests for delta clocks, data ops, register semantics, sealed payloads, checkpoint
//! disputes, E7 frontier honesty and the GC planner.

use std::collections::{BTreeMap, BTreeSet};

use crate::id::DeviceId;

use super::super::*;
use super::sim::{DAY_MS, K_MAC, Sim, adders, dev, item, membership, sealed};

fn set(it: u8, field: &str, value: &str) -> DataOp {
    DataOp::SetField {
        item: item(it),
        field: field.into(),
        value: FieldValue {
            kind: "text".into(),
            value: value.into(),
        },
    }
}

fn field_values(state: &FoldedState, it: u8, field: &str) -> Vec<String> {
    state.items[&item(it)].fields[field]
        .writes()
        .iter()
        .filter_map(|w| Some(w.value.as_ref()?.value.clone()))
        .collect()
}

#[test]
fn delta_clock_is_minimal_and_rebuilds_the_full_clock() {
    let (a, b, c) = (dev(0), dev(1), dev(2));
    let prev = VectorClock::from_counts([(a, 3), (b, 1)]);
    let now = VectorClock::from_counts([(a, 3), (b, 4), (c, 2)]);
    let delta = diff_clock(&prev, &now);
    assert_eq!(delta.entries(), &[(b, 4), (c, 2)]);
    let full = frame_clock(&prev, &delta, a, 3);
    assert_eq!(full, VectorClock::from_counts([(a, 4), (b, 4), (c, 2)]));
    assert!(full.covers(&a, 3) && !full.covers(&a, 4));
    // The writer's own stream never appears in its dclock.
    let own = next_dclock(&prev, &VectorClock::from_counts([(a, 9), (b, 2)]), &a);
    assert_eq!(own.entries(), &[(b, 2)]);
}

#[test]
fn delta_clock_rejects_non_canonical_entries() {
    let (a, b) = (dev(0), dev(1));
    assert!(DeltaClock::new(vec![(b, 1), (a, 1)]).is_err());
    assert!(DeltaClock::new(vec![(a, 1), (a, 2)]).is_err());
    assert!(DeltaClock::new(vec![(a, 0)]).is_err());
    let mut payload = DataPayload {
        mheads: Vec::new(),
        dclock: DeltaClock::new(vec![(a, 1), (b, 2)]).unwrap(),
        timestamp_ms: 7,
        ops: vec![set(0, "user", "x")],
    };
    let mut bytes = payload.encode().unwrap();
    // Swap the two dclock authors on the wire: decode must refuse it.
    let (x, y) = (8, 8 + 40);
    let first: Vec<u8> = bytes[x..x + 32].to_vec();
    let second: Vec<u8> = bytes[y..y + 32].to_vec();
    bytes[x..x + 32].copy_from_slice(&second);
    bytes[y..y + 32].copy_from_slice(&first);
    assert_eq!(
        DataPayload::decode(&bytes).unwrap_err(),
        PayloadError::NotCanonical("dclock")
    );
    payload.mheads = vec![FrameId::from_bytes([2; 32]), FrameId::from_bytes([1; 32])];
    assert_eq!(
        payload.encode().unwrap_err(),
        PayloadError::NotCanonical("mheads")
    );
    let mut ok = DataPayload::decode(
        &DataPayload {
            mheads: Vec::new(),
            ..payload.clone()
        }
        .encode()
        .unwrap(),
    )
    .unwrap()
    .encode()
    .unwrap();
    ok.push(0);
    assert_eq!(
        DataPayload::decode(&ok).unwrap_err(),
        PayloadError::TrailingBytes
    );
}

#[test]
fn strict_causal_comparison_of_dots() {
    let (a, b) = (dev(0), dev(1));
    let dot = |author, seq| Dot {
        author,
        seq,
        frame: FrameId::from_bytes([u8::try_from(seq).unwrap(); 32]),
    };
    let a0 = (dot(a, 0), VectorClock::from_counts([(a, 1)]));
    let b0 = (dot(b, 0), VectorClock::from_counts([(b, 1)]));
    let b1 = (dot(b, 1), VectorClock::from_counts([(a, 1), (b, 2)]));
    assert_eq!(
        compare((&a0.0, &a0.1), (&b0.0, &b0.1)),
        Causality::Concurrent
    );
    assert_eq!(compare((&a0.0, &a0.1), (&b1.0, &b1.1)), Causality::Before);
    assert_eq!(compare((&b1.0, &b1.1), (&a0.0, &a0.1)), Causality::After);
    assert_eq!(compare((&b1.0, &b1.1), (&b1.0, &b1.1)), Causality::Equal);
    assert!(happened_before(&b0.0, &b1.0, &b1.1));
    assert_eq!(tie_break(&a0.0, &b0.0), std::cmp::Ordering::Less);
}

#[test]
fn sealed_data_and_checkpoint_frames_round_trip() {
    let keys = DeviceKeys::from_seed(&[9; 32]);
    let vault = derive_vault_id(&keys.device_id(), &[1; 32]);
    let epoch = EpochId::from_bytes([3; 32]);
    let key = EpochKey::from_bytes([4; 32]);
    let payload = DataPayload {
        mheads: vec![FrameId::from_bytes([1; 32])],
        dclock: DeltaClock::new(vec![(dev(1), 2)]).unwrap(),
        timestamp_ms: 42,
        ops: vec![
            set(0, "user", "alice"),
            DataOp::VaultMeta {
                name: "Home".into(),
            },
            DataOp::DeviceCard {
                device: keys.device_id(),
                net_pk: keys.net_public(),
                label: "Laptop".into(),
            },
        ],
    };
    let frame = payload
        .seal(keys.sign_key(), vault, 0, FrameId::ZERO, epoch, &key)
        .unwrap();
    let wire = Frame::decode(&frame.encode()).unwrap();
    let opened = DataFrame::open(&wire, &key).unwrap();
    assert_eq!(opened.body, DataBody::Data(payload));
    assert_eq!(
        (opened.author, opened.seq, opened.id),
        (keys.device_id(), 0, frame.id())
    );
    assert!(DataFrame::open(&wire, &EpochKey::from_bytes([5; 32])).is_err());

    let ckpt = CheckpointPayload {
        frontier: vec![(dev(0), 4, FrameId::from_bytes([8; 32]))],
        mheads: Vec::new(),
        timestamp_ms: 9,
        state_mac: [1; 32],
        meta_mac: [4; 32],
        pack_hash: [2; 32],
        pack_len: 3,
    };
    let frame = ckpt
        .seal(keys.sign_key(), vault, 1, wire.id(), epoch, &key)
        .unwrap();
    let opened = DataFrame::open(&Frame::decode(&frame.encode()).unwrap(), &key).unwrap();
    assert_eq!(opened.body, DataBody::Checkpoint(ckpt));
}

#[test]
fn concurrent_writes_conflict_and_a_later_write_supersedes_them() {
    let m = membership(2, None);
    let adders = adders(2);
    let ctx = FoldContext {
        membership: &m,
        adders: &adders,
    };
    let mut sim = Sim::new(2);
    sim.write(0, vec![set(0, "user", "a")]);
    sim.write(1, vec![set(0, "user", "b")]);
    let state = fold_from_scratch(&ctx, sim.shuffled(1));
    let reg = &state.items[&item(0)].fields["user"];
    assert!(reg.is_conflicted());
    assert_eq!(field_values(&state, 0, "user"), ["a", "b"]);
    // Winner is the highest (author, seq, frame_id): device 1.
    assert_eq!(reg.winner().unwrap().dot.author, dev(1));

    sim.sync(0, 1);
    sim.write(0, vec![set(0, "user", "c")]);
    let state = fold_from_scratch(&ctx, sim.shuffled(2));
    assert_eq!(field_values(&state, 0, "user"), ["c"]);
}

#[test]
fn concurrent_edit_beats_delete_and_tombstones_carry_time() {
    let m = membership(2, None);
    let adders = adders(2);
    let ctx = FoldContext {
        membership: &m,
        adders: &adders,
    };
    let mut sim = Sim::new(2);
    sim.write(
        0,
        vec![DataOp::PutItem {
            item: item(0),
            kind: "login".into(),
        }],
    );
    sim.sync(0, 1);
    sim.write(0, vec![DataOp::DeleteItem { item: item(0) }]);
    let deleted_at = sim.now_ms;
    let state = fold_from_scratch(&ctx, sim.shuffled(3));
    assert!(state.items[&item(0)].deleted());
    assert_eq!(state.tombstones()[&item(0)].at_ms, deleted_at);
    assert!(state.items[&item(0)].live_fields().is_none());

    sim.write(1, vec![set(0, "pass", "x")]);
    let state = fold_from_scratch(&ctx, sim.shuffled(4));
    assert!(!state.items[&item(0)].deleted(), "the concurrent edit wins");
    assert!(state.tombstones().is_empty());
    assert_eq!(state.items[&item(0)].live_fields().unwrap().len(), 1);
}

#[test]
fn device_cards_need_the_device_or_its_adder() {
    let m = membership(3, None);
    let adders = adders(3);
    let ctx = FoldContext {
        membership: &m,
        adders: &adders,
    };
    let card = |d: usize, label: &str| DataOp::DeviceCard {
        device: dev(d),
        net_pk: NetPublic::from_bytes([7; 32]),
        label: label.into(),
    };
    let mut sim = Sim::new(3);
    sim.write(0, vec![card(1, "by adder")]);
    sim.write(2, vec![card(2, "by self")]);
    sim.write(2, vec![card(0, "forged")]);
    let state = fold_from_scratch(&ctx, sim.shuffled(5));
    let label = |d| {
        state.device_cards[&dev(d)]
            .winner()
            .unwrap()
            .value
            .label
            .clone()
    };
    assert_eq!(label(1), "by adder");
    assert_eq!(label(2), "by self");
    assert!(
        !state.device_cards.contains_key(&dev(0)),
        "a third party cannot card a device"
    );
}

#[test]
fn late_writer_after_compaction_still_conflicts_with_surviving_writes() {
    let m = membership(3, None);
    let adders = adders(3);
    let ctx = FoldContext {
        membership: &m,
        adders: &adders,
    };
    let mut sim = Sim::new(3);
    sim.write(0, vec![set(0, "user", "base")]);
    sim.sync(0, 2);
    sim.offline.insert(2);
    sim.write(2, vec![set(0, "user", "late")]);
    sim.now_ms += 60 * DAY_MS;
    sim.write(0, vec![set(0, "user", "new")]);
    sim.write(1, vec![set(1, "url", "x")]);
    sim.sync(0, 1);
    let (pack, _, _) = sim.checkpoint(0, &ctx, None);
    assert!(!pack.meta.frontier.contains_key(&dev(2)) || pack.meta.frontier[&dev(2)].0 == 0);
    sim.offline.clear();
    let late: Vec<&DataFrame> = sim.frames.iter().filter(|f| f.author == dev(2)).collect();
    let compacted = fold_from_checkpoint(&ctx, &pack, late).unwrap();
    let full = fold_from_scratch(&ctx, sim.shuffled(6));
    assert_eq!(compacted, full);
    assert_eq!(field_values(&full, 0, "user"), ["new", "late"]);
}

#[test]
fn a_removal_below_the_frontier_invalidates_the_checkpoint() {
    let before = membership(2, None);
    let adders = adders(2);
    let ctx = FoldContext {
        membership: &before,
        adders: &adders,
    };
    let mut sim = Sim::new(2);
    for i in 0..3 {
        sim.write(1, vec![set(0, "user", &format!("{i}"))]);
    }
    sim.sync(0, 1);
    let (pack, _, _) = sim.checkpoint(0, &ctx, None);
    let after = membership(2, Some((1, Some(0))));
    let ctx_after = FoldContext {
        membership: &after,
        adders: &adders,
    };
    assert_eq!(
        fold_from_checkpoint(&ctx_after, &pack, sim.shuffled(1)).unwrap_err(),
        CheckpointError::Invalidated(dev(1))
    );
    // A checkpointer that knew the removal stops the frontier at last_seen_seq.
    let pack = compact(&ctx_after, None, sim.shuffled(2)).unwrap();
    assert_eq!(pack.meta.frontier[&dev(1)].0, 0);
    let mut other = adders.clone();
    other.insert(dev(1), dev(1));
    let mut sim2 = Sim::new(2);
    sim2.write(
        0,
        vec![DataOp::DeviceCard {
            device: dev(1),
            net_pk: NetPublic::from_bytes([1; 32]),
            label: "x".into(),
        }],
    );
    let pack = compact(&ctx, None, sim2.shuffled(1)).unwrap();
    let ctx_other = FoldContext {
        membership: &before,
        adders: &other,
    };
    assert_eq!(
        fold_from_checkpoint(&ctx_other, &pack, []).unwrap_err(),
        CheckpointError::AdderChanged(dev(1))
    );
}

#[test]
fn dispute_detection_and_unverifiable_peers() {
    let m = membership(2, None);
    let adders = adders(2);
    let ctx = FoldContext {
        membership: &m,
        adders: &adders,
    };
    let mut sim = Sim::new(2);
    sim.write(0, vec![set(0, "user", "a")]);
    sim.write(1, vec![set(0, "user", "b")]);
    sim.sync(0, 1);
    let (pack, bytes, at) = sim.checkpoint(0, &ctx, None);
    let DataBody::Checkpoint(payload) = sim.frames[at].body.clone() else {
        unreachable!()
    };
    let id = sim.frames[at].id;
    let all = sim.shuffled(1);
    let agreed = verify_checkpoint(
        &K_MAC,
        &ctx,
        id,
        &payload,
        Some((&pack, PackCommitment::of(&sealed(&bytes)))),
        all.iter().copied(),
    );
    assert_eq!(agreed.unwrap(), CheckpointVerdict::Agreed);

    // The fetched encrypted pack file does not match the commitment: disputed.
    let mut bad_pack = sealed(&bytes);
    *bad_pack.last_mut().unwrap() ^= 1;
    let verdict = verify_checkpoint(
        &K_MAC,
        &ctx,
        id,
        &payload,
        Some((&pack, PackCommitment::of(&bad_pack))),
        all.iter().copied(),
    );
    assert!(matches!(
        verdict.unwrap(),
        CheckpointVerdict::Disputed { .. }
    ));

    let partial: Vec<&DataFrame> = all.iter().copied().filter(|f| f.author == dev(0)).collect();
    let verdict = verify_checkpoint(&K_MAC, &ctx, id, &payload, None, partial);
    assert_eq!(verdict.unwrap(), CheckpointVerdict::Unverifiable);

    let mut lie = payload.clone();
    lie.state_mac = [0; 32];
    let CheckpointVerdict::Disputed { dispute } =
        verify_checkpoint(&K_MAC, &ctx, id, &lie, None, all.iter().copied()).unwrap()
    else {
        panic!("a wrong state_mac must be disputed");
    };
    assert_eq!(
        dispute,
        DataOp::Dispute {
            checkpoint: id,
            expected_state_mac: state_mac(&K_MAC, &pack.state).unwrap(),
        }
    );
    // The dispute travels as a data op; GC then refuses that checkpoint.
    sim.write(1, vec![dispute]);
    let state = fold_from_scratch(&ctx, sim.shuffled(2));
    let members: BTreeSet<DeviceId> = [dev(0), dev(1)].into();
    assert!(state.is_disputed(&id, &members));
    assert!(!state.is_disputed(&id, &[dev(0)].into()));
}

#[test]
fn e7_frontier_honesty_stops_at_gaps_and_undecryptable_frames() {
    let (a, b, c) = (dev(0), dev(1), dev(2));
    let clock = honest_clock([
        (a, 0, true),
        (a, 1, true),
        (a, 2, false),
        (a, 3, true),
        (b, 1, true),
        (c, 0, true),
        (c, 1, true),
    ]);
    assert_eq!(clock, VectorClock::from_counts([(a, 2), (c, 2)]));
    // A second copy that failed to open poisons that seq too.
    assert_eq!(
        honest_clock([(a, 0, true), (a, 0, false)]),
        VectorClock::new()
    );
    let delta = next_dclock(&VectorClock::from_counts([(a, 2)]), &clock, &b);
    assert_eq!(delta.entries(), &[(c, 2)]);
}

fn gc_checkpoint(
    author: usize,
    seq: u64,
    timestamp_ms: u64,
    frontier: &[(usize, u64)],
) -> GcCheckpoint {
    GcCheckpoint {
        id: FrameId::from_bytes(
            [u8::try_from(author * 16).unwrap() + u8::try_from(seq).unwrap(); 32],
        ),
        author: dev(author),
        seq,
        first_seen_ms: timestamp_ms,
        meta: PackMeta {
            frontier: frontier
                .iter()
                .map(|&(d, s)| (dev(d), (s, FrameId::ZERO)))
                .collect(),
            ..PackMeta::default()
        },
    }
}

#[test]
fn gc_needs_full_coverage_or_thirty_days_and_never_a_dispute() {
    assert!(!should_checkpoint(
        CHECKPOINT_TRIGGER_BYTES - 1,
        CHECKPOINT_TRIGGER_FRAMES - 1
    ));
    assert!(should_checkpoint(CHECKPOINT_TRIGGER_BYTES, 0));
    assert!(should_checkpoint(0, CHECKPOINT_TRIGGER_FRAMES));

    let current = membership(3, None);
    let members = &current.devices;
    let now = 100 * DAY_MS;
    let mut c = gc_checkpoint(0, 5, now - DAY_MS, &[(0, 4), (1, 2)]);
    let tomb = Tombstone {
        dot: Dot {
            author: dev(1),
            seq: 1,
            frame: FrameId::ZERO,
        },
        at_ms: 1,
    };
    c.meta.tombstones.insert(item(0), tomb);
    let frames: Vec<GcFrame> = [(0, 3), (0, 4), (0, 5), (1, 2), (1, 3), (2, 0)]
        .iter()
        .map(|&(d, s)| GcFrame {
            id: FrameId::from_bytes([u8::try_from(d * 10 + s).unwrap(); 32]),
            author: dev(d),
            seq: s as u64,
        })
        .collect();
    let covering = VectorClock::from_counts([(dev(0), 6)]);
    let mut clocks: BTreeMap<DeviceId, VectorClock> =
        members.iter().map(|m| (*m, covering.clone())).collect();
    let none = BTreeSet::new();

    let plan = plan_gc(
        now,
        &current,
        &clocks,
        std::slice::from_ref(&c),
        &none,
        &frames,
        &BTreeMap::new(),
    );
    assert_eq!(plan.eligible[&c.id], Eligibility::Covered);
    assert_eq!(plan.base, Some(c.id));
    let expected: Vec<FrameId> = [(0, 3), (0, 4), (1, 2)]
        .iter()
        .map(|&(d, s): &(usize, usize)| {
            FrameId::from_bytes([u8::try_from(d * 10 + s).unwrap(); 32])
        })
        .collect();
    let mut expected = expected;
    expected.sort();
    assert_eq!(plan.delete_frames, expected);
    assert!(
        plan.expired_tombstones.is_empty(),
        "a base this peer has known for a day keeps its tombstones"
    );

    // One drawer iPad has not covered it: wait, then fall back to the 30-day grace.
    clocks.insert(dev(2), VectorClock::new());
    let plan = plan_gc(
        now,
        &current,
        &clocks,
        std::slice::from_ref(&c),
        &none,
        &frames,
        &BTreeMap::new(),
    );
    assert!(plan.eligible.is_empty() && plan.delete_frames.is_empty());
    let later = c.first_seen_ms + GC_GRACE_MS;
    let plan = plan_gc(
        later,
        &current,
        &clocks,
        std::slice::from_ref(&c),
        &none,
        &frames,
        &BTreeMap::new(),
    );
    assert_eq!(plan.eligible[&c.id], Eligibility::Grace);
    assert_eq!(plan.expired_tombstones[&item(0)], tomb);

    // A dispute by a current member blocks GC forever; one by a removed device does not.
    let dispute = |author| DisputeRecord {
        checkpoint: c.id,
        author,
        expected_state_mac: [0; 32],
    };
    let disputes: BTreeSet<DisputeRecord> = [dispute(dev(1))].into();
    let plan = plan_gc(
        later * 10,
        &current,
        &clocks,
        std::slice::from_ref(&c),
        &disputes,
        &frames,
        &BTreeMap::new(),
    );
    assert!(plan.disputed.contains(&c.id) && plan.eligible.is_empty() && plan.base.is_none());
    let outsider: BTreeSet<DisputeRecord> = [dispute(dev(9))].into();
    let plan = plan_gc(
        later,
        &current,
        &clocks,
        std::slice::from_ref(&c),
        &outsider,
        &frames,
        &BTreeMap::new(),
    );
    assert_eq!(plan.base, Some(c.id));

    // The newest eligible checkpoint is the base.
    let newer = gc_checkpoint(1, 4, later - 1, &[(0, 5), (1, 3)]);
    let both = [c.clone(), newer.clone()];
    let plan = plan_gc(
        later + GC_GRACE_MS,
        &current,
        &clocks,
        &both,
        &none,
        &frames,
        &BTreeMap::new(),
    );
    assert_eq!(plan.base, Some(newer.id));
    assert_eq!(plan.delete_frames.len(), 5);
}
