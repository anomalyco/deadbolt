//! Regression tests for checkpoints and GC: local-time grace, base selection and empty
//! membership in the GC planner, the encrypted pack commitment, non-fraud verdicts, and the
//! data-plane wire cleanups (empty field names, a data frame's own epoch).

use std::collections::{BTreeMap, BTreeSet};

use super::super::*;
use super::sim::{DAY_MS, K_MAC, Sim, adders, dev, item, membership, sealed};

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

fn checkpoint(id: u8, first_seen_ms: u64, frontier: &[(usize, u64)]) -> GcCheckpoint {
    GcCheckpoint {
        id: FrameId::from_bytes([id; 32]),
        author: dev(0),
        seq: 9,
        first_seen_ms,
        frontier: frontier
            .iter()
            .map(|&(d, s)| (dev(d), (s, FrameId::ZERO)))
            .collect(),
        tombstones: BTreeMap::new(),
    }
}

/// Audit #6: grace runs on this peer's clock, the base is the checkpoint covering the most
/// frames (no timestamp can pin it), an empty membership never makes "every member covered
/// it" vacuously true, and a tombstone forged to `at_ms = 0` waits out the base's local grace.
#[test]
fn gc_never_trusts_wire_timestamps_or_an_empty_membership() {
    let now = 1_000 * DAY_MS;
    let members: BTreeSet<_> = [dev(0), dev(1)].into();
    let none = BTreeSet::new();
    let uncovered: BTreeMap<_, _> = members.iter().map(|m| (*m, VectorClock::new())).collect();

    // Seen just now (its author may have claimed timestamp_ms = 0): not eligible.
    let fresh = checkpoint(1, now, &[(0, 3)]);
    let plan = plan_gc(
        now,
        &members,
        &uncovered,
        std::slice::from_ref(&fresh),
        &none,
        &[],
    );
    assert!(plan.eligible.is_empty() && plan.base.is_none());
    let plan = plan_gc(
        now + GC_GRACE_MS,
        &members,
        &uncovered,
        &[fresh],
        &none,
        &[],
    );
    assert_eq!(plan.base, Some(FrameId::from_bytes([1; 32])));

    // Both covered: the one covering more frames is the base, whatever the times say.
    let covering = VectorClock::from_counts([(dev(0), 10)]);
    let covered: BTreeMap<_, _> = members.iter().map(|m| (*m, covering.clone())).collect();
    let small = checkpoint(2, u64::MAX, &[(0, 1)]);
    let big = checkpoint(3, 0, &[(0, 5), (1, 2)]);
    let plan = plan_gc(
        now,
        &members,
        &covered,
        &[small.clone(), big.clone()],
        &none,
        &[],
    );
    assert_eq!(plan.base, Some(big.id));

    // No current members: nothing is ever eligible.
    let plan = plan_gc(
        u64::MAX,
        &BTreeSet::new(),
        &covered,
        &[small, big],
        &none,
        &[],
    );
    assert!(plan.eligible.is_empty() && plan.base.is_none());

    // A forged at_ms = 0 tombstone in a base this peer has known for a day stays.
    let mut tomb_base = checkpoint(4, now - DAY_MS, &[(0, 5)]);
    let tomb = Tombstone {
        dot: Dot {
            author: dev(0),
            seq: 2,
            frame: FrameId::ZERO,
        },
        at_ms: 0,
    };
    tomb_base.tombstones.insert(item(0), tomb);
    let plan = plan_gc(now, &members, &covered, &[tomb_base.clone()], &none, &[]);
    assert_eq!(plan.base, Some(tomb_base.id));
    assert!(plan.expired_tombstones.is_empty());
    let plan = plan_gc(
        now + GC_GRACE_MS,
        &members,
        &covered,
        &[tomb_base],
        &none,
        &[],
    );
    assert_eq!(plan.expired_tombstones[&item(0)], tomb);
}

/// Audit #7, #11 and #13: a checkpoint commits to the encrypted pack file; a removal after the
/// checkpoint makes it `Invalidated`, not disputed; and a frontier frame that is not on an
/// unbroken `prev` chain makes it `Unverifiable`.
#[test]
fn checkpoints_commit_to_the_sealed_pack_and_judge_without_false_disputes() {
    let before = membership(2, None);
    let adders = adders(2);
    let ctx = FoldContext {
        membership: &before,
        adders: &adders,
    };
    let mut sim = Sim::new(2);
    for i in 0..3 {
        sim.write(1, vec![set("user", &format!("{i}"))]);
    }
    sim.sync(0, 1);
    let (pack, plain, at) = sim.checkpoint(0, &ctx, None);
    let DataBody::Checkpoint(payload) = sim.frames[at].body.clone() else {
        unreachable!()
    };
    let id = sim.frames[at].id;
    let file = sealed(&plain);
    assert_eq!(payload.pack_commitment(), PackCommitment::of(&file));
    assert_ne!(payload.pack_hash, *blake3::hash(&plain).as_bytes());
    let frames: Vec<&DataFrame> = sim.frames.iter().collect();
    let verify =
        |ctx: &FoldContext<'_>, pack: Option<(&Pack, PackCommitment)>, frames: &[&DataFrame]| {
            verify_checkpoint(&K_MAC, ctx, id, &payload, pack, frames.iter().copied()).unwrap()
        };
    let honest = Some((&pack, PackCommitment::of(&file)));
    assert_eq!(verify(&ctx, honest, &frames), CheckpointVerdict::Agreed);
    // Committing to the plaintext instead of the sealed file is a mismatch.
    let wrong = Some((&pack, PackCommitment::of(&plain)));
    assert!(matches!(
        verify(&ctx, wrong, &frames),
        CheckpointVerdict::Disputed { .. }
    ));

    // Device 1 is removed after the checkpoint with only seq 0 counting.
    let after = membership(2, Some((1, Some(0))));
    let ctx_after = FoldContext {
        membership: &after,
        adders: &adders,
    };
    assert_eq!(
        verify(&ctx_after, honest, &frames),
        CheckpointVerdict::Invalidated
    );

    // A gap below the frontier, or a frontier id not on the held chain: unverifiable.
    let gap: Vec<&DataFrame> = frames
        .iter()
        .copied()
        .filter(|f| !(f.author == dev(1) && f.seq == 1))
        .collect();
    assert_eq!(verify(&ctx, None, &gap), CheckpointVerdict::Unverifiable);
    let mut sibling = sim
        .frames
        .iter()
        .find(|f| f.author == dev(1) && f.seq == 2)
        .unwrap()
        .clone();
    sibling.id = FrameId::from_bytes([0xab; 32]);
    let swapped: Vec<&DataFrame> = frames
        .iter()
        .copied()
        .filter(|f| !(f.author == dev(1) && f.seq == 2))
        .chain([&sibling])
        .collect();
    assert_eq!(
        verify(&ctx, None, &swapped),
        CheckpointVerdict::Unverifiable
    );
    // A fork sibling next to the real chain is ignored.
    let mut with_sibling = frames.clone();
    with_sibling.push(&sibling);
    assert_eq!(verify(&ctx, None, &with_sibling), CheckpointVerdict::Agreed);
}

/// Audit (low): an empty field name is rejected on encode and in a decoded state.
#[test]
fn empty_field_names_are_rejected_everywhere() {
    let payload = DataPayload {
        mheads: Vec::new(),
        dclock: DeltaClock::default(),
        timestamp_ms: 1,
        ops: vec![set("", "x")],
    };
    assert!(matches!(payload.encode(), Err(PayloadError::Invalid(_))));
    let clear = DataPayload {
        ops: vec![DataOp::ClearField {
            item: item(0),
            field: String::new(),
        }],
        ..payload.clone()
    };
    assert!(matches!(clear.encode(), Err(PayloadError::Invalid(_))));

    // Fold a frame built in memory (bypassing encode) to get a state with an empty field.
    let m = membership(1, None);
    let adders = adders(1);
    let ctx = FoldContext {
        membership: &m,
        adders: &adders,
    };
    let frame = DataFrame {
        id: FrameId::from_bytes([1; 32]),
        author: dev(0),
        seq: 0,
        prev: FrameId::ZERO,
        epoch: EpochId::ZERO,
        body: DataBody::Data(payload),
    };
    let state = fold_from_scratch(&ctx, [&frame]);
    let bytes = state.encode().unwrap();
    assert_eq!(
        FoldedState::decode(&bytes).unwrap_err(),
        PayloadError::Invalid("field name must be non-empty")
    );
}

/// Audit (low): an opened data frame carries the epoch it was sealed under, so a checkpoint's
/// `K_mac` always comes from its own frame's epoch.
#[test]
fn opened_frames_carry_their_epoch() {
    let keys = DeviceKeys::from_seed(&[0x91; 32]);
    let vault = derive_vault_id(&keys.device_id(), &[1; 32]);
    let epoch = EpochId::from_bytes([0x92; 32]);
    let key = EpochKey::from_bytes([0x93; 32]);
    let payload = DataPayload {
        mheads: Vec::new(),
        dclock: DeltaClock::default(),
        timestamp_ms: 1,
        ops: vec![set("user", "x")],
    };
    let frame = payload
        .seal(keys.sign_key(), vault, 0, FrameId::ZERO, epoch, &key)
        .unwrap();
    assert_eq!(DataFrame::open(&frame, &key).unwrap().epoch, epoch);
}
