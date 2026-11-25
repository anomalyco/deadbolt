//! Regression tests for membership continuity: per-author `prev` chains (no competing-root hash
//! lottery), retired recovery roots that can no longer freeze the lineage, devices that can
//! never become recovery roots, and withheld `Member` fork chains in `counts_data`.

use super::super::*;
use super::model::{assert_matches_ref, dummy_rotate, pool};
use super::view;

/// Audit #2: a stolen `R_0` signs `RotateRecovery` frames at unrelated seqs off one old
/// `prev`. Neither continues `R_0`'s log, so neither is placed, and there is no fork to prove
/// and no competing-root hash lottery.
#[test]
fn rotate_recovery_frames_off_an_old_prev_are_never_placed() {
    let p = pool();
    let (r0, r1, r2) = (&p.roots[0], &p.roots[1], &p.roots[2]);
    let k0 = EpochKey::from_bytes([1; 32]);
    let create = build_create_frame(r0, p.nonce, &k0).unwrap();
    let vault = create.header().vault;
    let e0 = EpochId::from_frame_id(create.id());
    let rotate_to = |seq: u64, new: &RecoverySecret, tag: u8| {
        Frame::sign_member(
            &p.root_sks[0],
            vault,
            seq,
            create.id(),
            MemberBody {
                deps: vec![create.id()],
                op: Some(MemberOp::RotateRecovery {
                    new: new.recovery_id(),
                    new_kem: new.kem_public(),
                    consent: sign_rotate_recovery_consent(
                        &new.signing_key(),
                        &vault,
                        &r0.recovery_id(),
                        &new.kem_public(),
                    ),
                }),
                rotate: Some(dummy_rotate(vec![e0], new.recovery_id(), tag)),
            },
        )
        .unwrap()
    };
    let at_10 = rotate_to(10, r1, 1);
    let at_20 = rotate_to(20, r2, 2);
    let frames = vec![create, at_10.clone(), at_20.clone()];

    let resolved = assert_matches_ref(vault, &frames, &[]);
    assert!(resolved.unplaced_frames.contains(&at_10.id()));
    assert!(resolved.unplaced_frames.contains(&at_20.id()));
    assert!(!resolved.dag_frames.contains(&at_10.id()));
    assert!(!resolved.authorized_frames.contains(&at_10.id()));
    assert!(!resolved.authorized_frames.contains(&at_20.id()));
    assert_eq!(resolved.recovery_lineage, vec![r0.recovery_id()]);
    assert_eq!(resolved.active_recovery, Some(r0.recovery_id()));
    assert!(!resolved.recovery_frozen);
}

struct Handoff {
    vault: crate::id::VaultId,
    e0: EpochId,
    create: Frame,
    handoff: Frame,
}

/// `R_0` hands recovery to `R_1` at `R_0` seq 1.
fn handoff() -> Handoff {
    let p = pool();
    let (r0, r1) = (&p.roots[0], &p.roots[1]);
    let k0 = EpochKey::from_bytes([2; 32]);
    let create = build_create_frame(r0, p.nonce, &k0).unwrap();
    let vault = create.header().vault;
    let e0 = EpochId::from_frame_id(create.id());
    let mut ring = EpochKeyring::new();
    ring.insert(e0, k0);
    let recipients = [(r1.recovery_id(), r1.kem_public())].into();
    let handoff = build_rotate_recovery_frame(
        &p.root_sks[0],
        vault,
        &view(&[&create]),
        1,
        create.id(),
        vec![create.id()],
        r1.recovery_id(),
        r1.kem_public(),
        sign_rotate_recovery_consent(&p.root_sks[1], &vault, &r0.recovery_id(), &r1.kem_public()),
        &EpochKey::from_bytes([3; 32]),
        vec![e0],
        &ring,
        &recipients,
    )
    .unwrap();
    Handoff {
        vault,
        e0,
        create,
        handoff,
    }
}

/// Audit #3: once `R_0` handed recovery to `R_1`, a later fork by the retired `R_0` (in its
/// data log, or in `Member` above the handoff) cannot freeze `R_1`. A fork at the handoff
/// itself still freezes.
#[test]
fn a_retired_root_cannot_freeze_the_active_root() {
    let p = pool();
    let (r0, r1, r2) = (&p.roots[0], &p.roots[1], &p.roots[2]);
    let h = handoff();
    let base = vec![h.create.clone(), h.handoff.clone()];
    let healthy = assert_matches_ref(h.vault, &base, &[]);
    assert_eq!(healthy.active_recovery, Some(r1.recovery_id()));

    // (a) R_0 forks its data log at seq 0.
    let k = EpochKey::from_bytes([4; 32]);
    let sk0 = &p.root_sks[0];
    let d_a = Frame::seal_data(sk0, h.vault, 0, FrameId::ZERO, h.e0, &k, b"a").unwrap();
    let d_b = Frame::seal_data(sk0, h.vault, 0, FrameId::ZERO, h.e0, &k, b"b").unwrap();
    let data_fork = FraudProof::from_frames(&d_a, &d_b).unwrap();
    let res = assert_matches_ref(h.vault, &base, &[data_fork]);
    assert!(!res.recovery_frozen);
    assert_eq!(res.active_recovery, Some(r1.recovery_id()));

    // (b) R_0 forks in Member at seq 2, after its handoff at seq 1.
    let at_2 = |tag: u8| {
        Frame::sign_member(
            sk0,
            h.vault,
            2,
            h.handoff.id(),
            MemberBody {
                deps: vec![h.handoff.id()],
                op: None,
                rotate: Some(dummy_rotate(vec![h.e0], r0.recovery_id(), tag)),
            },
        )
        .unwrap()
    };
    let mut forked = base.clone();
    forked.extend([at_2(5), at_2(6)]);
    let res = assert_matches_ref(h.vault, &forked, &[]);
    assert_eq!(res.member_fork_seq.get(&r0.recovery_id()), Some(&2));
    assert!(!res.recovery_frozen);
    assert_eq!(res.active_recovery, Some(r1.recovery_id()));

    // (c) R_0 forks AT its handoff: a competing RotateRecovery at seq 1 still freezes.
    let competing = Frame::sign_member(
        sk0,
        h.vault,
        1,
        h.create.id(),
        MemberBody {
            deps: vec![h.create.id()],
            op: Some(MemberOp::RotateRecovery {
                new: r2.recovery_id(),
                new_kem: r2.kem_public(),
                consent: sign_rotate_recovery_consent(
                    &p.root_sks[2],
                    &h.vault,
                    &r0.recovery_id(),
                    &r2.kem_public(),
                ),
            }),
            rotate: Some(dummy_rotate(vec![h.e0], r2.recovery_id(), 7)),
        },
    )
    .unwrap();
    let mut frames = base;
    frames.push(competing);
    let res = assert_matches_ref(h.vault, &frames, &[]);
    assert!(res.recovery_frozen);
    assert_eq!(res.active_recovery, None);
}

/// Audit (low): a principal already added as an ordinary device can never become a recovery
/// root, so one key cannot hold both roles.
#[test]
fn rotate_recovery_to_an_added_device_is_rejected() {
    let p = pool();
    let r0 = &p.roots[0];
    let d = &p.devices[0];
    let k0 = EpochKey::from_bytes([8; 32]);
    let create = build_create_frame(r0, p.nonce, &k0).unwrap();
    let vault = create.header().vault;
    let e0 = EpochId::from_frame_id(create.id());
    let add_d = build_add_frame(
        &p.root_sks[0],
        vault,
        &view(&[&create]),
        1,
        create.id(),
        vec![create.id()],
        d.device_id(),
        d.kem_public(),
        sign_join_consent(d.sign_key(), &vault, &r0.recovery_id(), &d.kem_public()),
        Some((e0, &k0)),
    )
    .unwrap();
    let to_d = Frame::sign_member(
        &p.root_sks[0],
        vault,
        2,
        add_d.id(),
        MemberBody {
            deps: vec![add_d.id()],
            op: Some(MemberOp::RotateRecovery {
                new: d.device_id(),
                new_kem: d.kem_public(),
                consent: sign_rotate_recovery_consent(
                    d.sign_key(),
                    &vault,
                    &r0.recovery_id(),
                    &d.kem_public(),
                ),
            }),
            rotate: Some(dummy_rotate(vec![e0], d.device_id(), 9)),
        },
    )
    .unwrap();
    let res = assert_matches_ref(vault, &[create, add_d, to_d.clone()], &[]);
    assert!(!res.authorized_frames.contains(&to_d.id()));
    assert_eq!(res.recovery_lineage, vec![r0.recovery_id()]);
    assert_eq!(res.active_recovery, Some(r0.recovery_id()));
    assert!(res.is_active_device(&d.device_id()));
}

/// Audit #10: data from an author that forked in `Member` counts only under heads this peer
/// placed outside the fork's descendants. A head it cannot place may be a withheld frame on
/// a fork branch, so it never counts (instead of counting until the branch shows up).
#[test]
fn withheld_fork_chain_heads_never_count() {
    let p = pool();
    let r0 = &p.roots[0];
    let b = &p.devices[1];
    let k0 = EpochKey::from_bytes([10; 32]);
    let create = build_create_frame(r0, p.nonce, &k0).unwrap();
    let vault = create.header().vault;
    let e0 = EpochId::from_frame_id(create.id());
    let add_b = build_add_frame(
        &p.root_sks[0],
        vault,
        &view(&[&create]),
        1,
        create.id(),
        vec![create.id()],
        b.device_id(),
        b.kem_public(),
        sign_join_consent(b.sign_key(), &vault, &r0.recovery_id(), &b.kem_public()),
        Some((e0, &k0)),
    )
    .unwrap();
    let member = |seq: u64, prev: FrameId, deps: Vec<FrameId>, tag: u8| {
        Frame::sign_member(
            b.sign_key(),
            vault,
            seq,
            prev,
            MemberBody {
                deps,
                op: None,
                rotate: Some(dummy_rotate(vec![e0], b.device_id(), tag)),
            },
        )
        .unwrap()
    };
    let m0 = member(0, FrameId::ZERO, vec![add_b.id()], 20);
    let m1a = member(1, m0.id(), vec![m0.id()], 21);
    let m1b = member(1, m0.id(), vec![m0.id()], 22);
    // Withheld: continues branch b and is never delivered to this peer.
    let m2b = member(2, m1b.id(), vec![m1b.id()], 23);
    let proof = FraudProof::from_frames(&m1a, &m1b).unwrap();

    let frames = vec![create, add_b.clone(), m0.clone(), m1a.clone()];
    let res = assert_matches_ref(vault, &frames, &[proof]);
    assert_eq!(res.member_fork_seq.get(&b.device_id()), Some(&1));
    let id = b.device_id();
    assert!(res.counts_data(&id, 0, &[m0.id()]));
    assert!(res.counts_data(&id, 0, &[add_b.id()]));
    assert!(!res.counts_data(&id, 0, &[m1a.id()]), "a fork branch");
    assert!(!res.counts_data(&id, 0, &[m2b.id()]), "a withheld branch");
    assert!(!res.counts_data(&id, 0, &[m0.id(), m2b.id()]));
}
