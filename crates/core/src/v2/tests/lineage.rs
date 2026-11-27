//! Named security and exhaustive small-scope tests for `class = 0` recovery lineage,
//! `RotateRecovery`, competing root forks, and keyless `FraudProof`s.

use std::collections::{BTreeMap, BTreeSet};

use super::super::*;
use super::model::{assert_matches_ref, dummy_rotate, pool, shuffled};
use super::view;

#[test]
fn rotate_recovery_beats_depth1_backdating_stolen_laptop() {
    let p = pool();
    let (r0, r1) = (&p.roots[0], &p.roots[1]);
    let (r0_sk, r1_sk) = (&p.root_sks[0], &p.root_sks[1]);
    let (laptop, phone) = (&p.devices[0], &p.devices[1]);
    let k0 = EpochKey::from_bytes([1; 32]);

    let create = build_create_frame(r0, p.nonce, &k0).unwrap();
    let vault = create.header().vault;
    let e0 = EpochId::from_frame_id(create.id());

    // Depth 1: laptop added. Depth 2: phone added.
    let add_laptop = build_add_frame(
        r0_sk,
        vault,
        &view(&[&create]),
        1,
        create.id(),
        vec![create.id()],
        laptop.device_id(),
        laptop.kem_public(),
        sign_join_consent(laptop, &vault, &r0.recovery_id()),
        Some((e0, &k0)),
    )
    .unwrap();
    let add_phone = build_add_frame(
        r0_sk,
        vault,
        &view(&[&create, &add_laptop]),
        2,
        add_laptop.id(),
        vec![add_laptop.id()],
        phone.device_id(),
        phone.kem_public(),
        sign_join_consent(phone, &vault, &r0.recovery_id()),
        Some((e0, &k0)),
    )
    .unwrap();

    // Depth 3: R0 rotates recovery to R1 (so R1 is at depth 3 > laptop's depth 1!).
    let mut rec1 = BTreeMap::new();
    rec1.insert(laptop.device_id(), laptop.kem_public());
    rec1.insert(phone.device_id(), phone.kem_public());
    rec1.insert(r1.recovery_id(), r1.kem_public());
    let k1 = EpochKey::from_bytes([2; 32]);
    let mut ring = EpochKeyring::new();
    ring.insert(e0, k0);
    let rot_rec = build_rotate_recovery_frame(
        r0_sk,
        vault,
        &view(&[&create, &add_laptop, &add_phone]),
        3,
        add_phone.id(),
        vec![add_phone.id()],
        r1.recovery_id(),
        r1.kem_public(),
        sign_rotate_recovery_consent(r1_sk, &vault, &r0.recovery_id(), &r1.kem_public()),
        &k1,
        vec![e0],
        &ring,
        &rec1,
    )
    .unwrap();
    let e1 = EpochId::from_frame_id(rot_rec.id());
    ring.insert(e1, k1);

    // Stolen depth-1 laptop back-dates Remove(phone) AND tries Remove(R1) using old parent add_phone.
    let laptop_rem_phone = Frame::sign_member(
        laptop.sign_key(),
        vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps: vec![add_phone.id()],
            op: Some(MemberOp::Remove {
                device: phone.device_id(),
                last_seen_seq: None,
            }),
            rotate: Some(covered_rotate([r0.recovery_id(), laptop.device_id()], 10)),
        },
    )
    .unwrap();
    let laptop_rem_r1 = Frame::sign_member(
        laptop.sign_key(),
        vault,
        1,
        laptop_rem_phone.id(),
        MemberBody {
            deps: vec![rot_rec.id(), laptop_rem_phone.id()]
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            op: Some(MemberOp::Remove {
                device: r1.recovery_id(),
                last_seen_seq: None,
            }),
            rotate: Some(dummy_rotate(vec![e1], laptop.device_id(), 11)),
        },
    )
    .unwrap();

    // Depth 4: R1 (class = 0!) removes stolen laptop with pre-theft deps (cutting laptop_rem_phone!).
    let mut rec2 = BTreeMap::new();
    rec2.insert(phone.device_id(), phone.kem_public());
    rec2.insert(r1.recovery_id(), r1.kem_public());
    let k2 = EpochKey::from_bytes([3; 32]);
    let r1_rem_laptop = build_remove_frame(
        r1_sk,
        vault,
        &view(&[&create, &add_laptop, &add_phone, &rot_rec]),
        0,
        FrameId::ZERO,
        vec![rot_rec.id()],
        laptop.device_id(),
        Some(4),
        &k2,
        vec![e1],
        &ring,
        &rec2,
    )
    .unwrap();

    let frames = vec![
        create,
        add_laptop,
        add_phone,
        rot_rec,
        laptop_rem_phone,
        laptop_rem_r1,
        r1_rem_laptop,
    ];
    let resolved = assert_matches_ref(vault, &frames, &[]);
    assert_eq!(resolved.active_recovery, Some(r1.recovery_id()));
    assert!(!resolved.recovery_frozen);
    assert!(resolved.is_active_device(&phone.device_id()));
    assert!(!resolved.is_active_device(&laptop.device_id()));
    assert_eq!(resolved.removed.get(&laptop.device_id()), Some(&Some(4)));

    // Delivery order independence.
    for seed in 1..=8 {
        assert_eq!(resolve(&vault, &shuffled(&frames, seed), &[]), resolved);
    }
}

#[test]
fn competing_root_rotations_freeze_lineage_with_no_hash_lottery() {
    let p = pool();
    let (r0, r1a, r1b) = (&p.roots[0], &p.roots[1], &p.roots[2]);
    let (r0_sk, r1a_sk, r1b_sk) = (&p.root_sks[0], &p.root_sks[1], &p.root_sks[2]);
    let dev = &p.devices[0];
    let k0 = EpochKey::from_bytes([4; 32]);
    let create = build_create_frame(r0, p.nonce, &k0).unwrap();
    let vault = create.header().vault;
    let e0 = EpochId::from_frame_id(create.id());
    let add_dev = build_add_frame(
        r0_sk,
        vault,
        &view(&[&create]),
        1,
        create.id(),
        vec![create.id()],
        dev.device_id(),
        dev.kem_public(),
        sign_join_consent(dev, &vault, &r0.recovery_id()),
        Some((e0, &k0)),
    )
    .unwrap();

    // R0 equivocates at seq 2 with two competing RotateRecovery frames!
    let rot_a = Frame::sign_member(
        r0_sk,
        vault,
        2,
        add_dev.id(),
        MemberBody {
            deps: vec![add_dev.id()],
            op: Some(MemberOp::RotateRecovery {
                new: r1a.recovery_id(),
                new_kem: r1a.kem_public(),
                consent: sign_rotate_recovery_consent(
                    r1a_sk,
                    &vault,
                    &r0.recovery_id(),
                    &r1a.kem_public(),
                ),
            }),
            rotate: Some(covered_rotate([r1a.recovery_id(), dev.device_id()], 1)),
        },
    )
    .unwrap();
    let rot_b = Frame::sign_member(
        r0_sk,
        vault,
        2,
        add_dev.id(),
        MemberBody {
            deps: vec![add_dev.id()],
            op: Some(MemberOp::RotateRecovery {
                new: r1b.recovery_id(),
                new_kem: r1b.kem_public(),
                consent: sign_rotate_recovery_consent(
                    r1b_sk,
                    &vault,
                    &r0.recovery_id(),
                    &r1b.kem_public(),
                ),
            }),
            rotate: Some(covered_rotate([r1b.recovery_id(), dev.device_id()], 2)),
        },
    )
    .unwrap();

    let proof = FraudProof::from_frames(&rot_a, &rot_b).unwrap();
    let both = vec![
        create.clone(),
        add_dev.clone(),
        rot_a.clone(),
        rot_b.clone(),
    ];
    let only_a = vec![create.clone(), add_dev.clone(), rot_a];
    let only_b = vec![create, add_dev, rot_b];

    let res_both = assert_matches_ref(vault, &both, &[]);
    let res_a = assert_matches_ref(vault, &only_a, &[proof]);
    let res_b = assert_matches_ref(vault, &only_b, &[proof]);

    assert!(res_both.recovery_frozen);
    assert_eq!(res_both.active_recovery, None);
    assert!(res_both.is_active_device(&dev.device_id()));
    // Identical outcome whether a peer saw branch A + proof, branch B + proof, or both!
    assert_eq!(res_a.devices, res_both.devices);
    assert_eq!(res_b.devices, res_both.devices);
    assert_eq!(res_a.active_recovery, res_both.active_recovery);
    assert_eq!(res_b.active_recovery, res_both.active_recovery);
    assert_eq!(res_a.recovery_frozen, res_both.recovery_frozen);
    assert_eq!(res_b.recovery_frozen, res_both.recovery_frozen);
    assert_eq!(res_a.authorized_frames, res_both.authorized_frames);
    assert_eq!(res_b.authorized_frames, res_both.authorized_frames);
}

#[test]
fn data_fork_removes_at_seq_minus_1_and_member_fork_filters_mheads() {
    let p = pool();
    let r0 = &p.roots[0];
    let r0_sk = &p.root_sks[0];
    let (a, b) = (&p.devices[0], &p.devices[1]);
    let k0 = EpochKey::from_bytes([8; 32]);
    let create = build_create_frame(r0, p.nonce, &k0).unwrap();
    let vault = create.header().vault;
    let e0 = EpochId::from_frame_id(create.id());
    let add_a = build_add_frame(
        r0_sk,
        vault,
        &view(&[&create]),
        1,
        create.id(),
        vec![create.id()],
        a.device_id(),
        a.kem_public(),
        sign_join_consent(a, &vault, &r0.recovery_id()),
        Some((e0, &k0)),
    )
    .unwrap();
    let add_b = build_add_frame(
        r0_sk,
        vault,
        &view(&[&create, &add_a]),
        2,
        add_a.id(),
        vec![add_a.id()],
        b.device_id(),
        b.kem_public(),
        sign_join_consent(b, &vault, &r0.recovery_id()),
        Some((e0, &k0)),
    )
    .unwrap();

    // Device A forks in Data at seq 2 -> removed with last_seen_seq = Some(1).
    let d0 = Frame::seal_data(a.sign_key(), vault, 0, FrameId::ZERO, e0, &k0, b"0").unwrap();
    let d1 = Frame::seal_data(a.sign_key(), vault, 1, d0.id(), e0, &k0, b"1").unwrap();
    let d2a = Frame::seal_data(a.sign_key(), vault, 2, d1.id(), e0, &k0, b"2a").unwrap();
    let d2b = Frame::seal_data(a.sign_key(), vault, 2, d1.id(), e0, &k0, b"2b").unwrap();
    let data_proof = FraudProof::from_frames(&d2a, &d2b).unwrap();

    // Device B forks in Member at seq 0 -> both branches void; B's data with mheads descending
    // from either fork branch does not count, while earlier mheads still count.
    let m0a = Frame::sign_member(
        b.sign_key(),
        vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps: vec![add_b.id()],
            op: None,
            rotate: Some(dummy_rotate(vec![e0], b.device_id(), 51)),
        },
    )
    .unwrap();
    let m0b = Frame::sign_member(
        b.sign_key(),
        vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps: vec![add_b.id()],
            op: None,
            rotate: Some(dummy_rotate(vec![e0], b.device_id(), 52)),
        },
    )
    .unwrap();
    let m_proof = FraudProof::from_frames(&m0a, &m0b).unwrap();

    let frames = vec![create, add_a, add_b.clone(), m0a.clone(), m0b.clone()];
    let resolved = assert_matches_ref(vault, &frames, &[data_proof, m_proof]);

    // A removed with cutoff 1.
    assert!(!resolved.is_active_device(&a.device_id()));
    assert_eq!(resolved.removed.get(&a.device_id()), Some(&Some(1)));
    assert!(resolved.counts_data(&a.device_id(), 1, &[add_b.id()]));
    assert!(!resolved.counts_data(&a.device_id(), 2, &[add_b.id()]));

    // B's Member fork branches are both void; data descending from m0a or m0b does not count.
    assert!(!resolved.authorized_frames.contains(&m0a.id()));
    assert!(!resolved.authorized_frames.contains(&m0b.id()));
    assert!(resolved.counts_data(&b.device_id(), 0, &[add_b.id()]));
    assert!(!resolved.counts_data(&b.device_id(), 0, &[m0a.id()]));
    assert!(!resolved.counts_data(&b.device_id(), 0, &[m0b.id()]));
}

#[test]
fn exhaustive_small_scope_all_delivery_permutations_and_removal_cycles() {
    let p = pool();
    let (r0, r1) = (&p.roots[0], &p.roots[1]);
    let (r0_sk, r1_sk) = (&p.root_sks[0], &p.root_sks[1]);
    let (a, b, c) = (&p.devices[0], &p.devices[1], &p.devices[2]);
    let k0 = EpochKey::from_bytes([91; 32]);

    let create = build_create_frame(r0, p.nonce, &k0).unwrap();
    let vault = create.header().vault;

    let add_a = build_add_frame(
        r0_sk,
        vault,
        &view(&[&create]),
        1,
        create.id(),
        vec![create.id()],
        a.device_id(),
        a.kem_public(),
        sign_join_consent(a, &vault, &r0.recovery_id()),
        None,
    )
    .unwrap();
    let add_b = build_add_frame(
        r0_sk,
        vault,
        &view(&[&create, &add_a]),
        2,
        add_a.id(),
        vec![add_a.id()],
        b.device_id(),
        b.kem_public(),
        sign_join_consent(b, &vault, &r0.recovery_id()),
        None,
    )
    .unwrap();
    let add_c = build_add_frame(
        r0_sk,
        vault,
        &view(&[&create, &add_a, &add_b]),
        3,
        add_b.id(),
        vec![add_b.id()],
        c.device_id(),
        c.kem_public(),
        sign_join_consent(c, &vault, &r0.recovery_id()),
        None,
    )
    .unwrap();

    // 3-way removal cycle: A removes B, B removes C, C removes A (all concurrent after add_c).
    let rem_ab = Frame::sign_member(
        a.sign_key(),
        vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps: vec![add_c.id()],
            op: Some(MemberOp::Remove {
                device: b.device_id(),
                last_seen_seq: Some(1),
            }),
            rotate: Some(covered_rotate(
                [r0.recovery_id(), a.device_id(), c.device_id()],
                1,
            )),
        },
    )
    .unwrap();
    let rem_bc = Frame::sign_member(
        b.sign_key(),
        vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps: vec![add_c.id()],
            op: Some(MemberOp::Remove {
                device: c.device_id(),
                last_seen_seq: Some(2),
            }),
            rotate: Some(covered_rotate(
                [r0.recovery_id(), a.device_id(), b.device_id()],
                2,
            )),
        },
    )
    .unwrap();
    let rem_ca = Frame::sign_member(
        c.sign_key(),
        vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps: vec![add_c.id()],
            op: Some(MemberOp::Remove {
                device: a.device_id(),
                last_seen_seq: Some(3),
            }),
            rotate: Some(covered_rotate(
                [r0.recovery_id(), b.device_id(), c.device_id()],
                3,
            )),
        },
    )
    .unwrap();
    // Plus a RotateRecovery R0 -> R1 and R1 removing A (class 0 overrides A!).
    let rot_r1 = Frame::sign_member(
        r0_sk,
        vault,
        4,
        add_c.id(),
        MemberBody {
            deps: vec![add_c.id()],
            op: Some(MemberOp::RotateRecovery {
                new: r1.recovery_id(),
                new_kem: r1.kem_public(),
                consent: sign_rotate_recovery_consent(
                    r1_sk,
                    &vault,
                    &r0.recovery_id(),
                    &r1.kem_public(),
                ),
            }),
            rotate: Some(covered_rotate(
                [
                    r1.recovery_id(),
                    a.device_id(),
                    b.device_id(),
                    c.device_id(),
                ],
                4,
            )),
        },
    )
    .unwrap();
    let rem_r1_a = Frame::sign_member(
        r1_sk,
        vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps: vec![rot_r1.id()],
            op: Some(MemberOp::Remove {
                device: a.device_id(),
                last_seen_seq: Some(0),
            }),
            rotate: Some(covered_rotate(
                [r1.recovery_id(), b.device_id(), c.device_id()],
                5,
            )),
        },
    )
    .unwrap();

    // Exhaustively check ALL 2^5 = 32 subsets of the 5 concurrent operations against RefGraph!
    let base = vec![create, add_a, add_b, add_c];
    let extras = vec![rem_ab, rem_bc, rem_ca, rot_r1, rem_r1_a];
    for mask in 0usize..(1 << extras.len()) {
        let mut sub = base.clone();
        for (bit, f) in extras.iter().enumerate() {
            if (mask >> bit) & 1 == 1 {
                sub.push(f.clone());
            }
        }
        let expected = assert_matches_ref(vault, &sub, &[]);
        // Verify reverse order and a shuffled permutation are bit-identical (I4).
        let mut rev = sub.clone();
        rev.reverse();
        assert_eq!(resolve(&vault, &rev, &[]), expected);
        assert_eq!(
            resolve(&vault, &shuffled(&sub, mask as u64 + 99), &[]),
            expected
        );
    }

    // Exhaustively test all 5! = 120 permutations of the 5 concurrent ops appended to base!
    let mut indices = [0usize, 1, 2, 3, 4];
    let mut full = base.clone();
    full.extend(extras.clone());
    let expected_full = assert_matches_ref(vault, &full, &[]);
    // Heap's algorithm for all 120 permutations.
    let mut c_arr = [0usize; 5];
    let mut count = 0usize;
    let check_perm = |idx: &[usize; 5]| {
        let mut perm = base.clone();
        for &i in idx {
            perm.push(extras[i].clone());
        }
        assert_eq!(resolve(&vault, &perm, &[]), expected_full);
    };
    check_perm(&indices);
    count += 1;
    let mut i = 0;
    while i < 5 {
        if c_arr[i] < i {
            if i % 2 == 0 {
                indices.swap(0, i);
            } else {
                indices.swap(c_arr[i], i);
            }
            check_perm(&indices);
            count += 1;
            c_arr[i] += 1;
            i = 0;
        } else {
            c_arr[i] = 0;
            i += 1;
        }
    }
    assert_eq!(count, 120);
}

// ============================================================================
// Randomized property test (verified at DEADBOLT_MEMBERSHIP_CASES=20000)
// ============================================================================

fn coverage_base() -> Vec<Frame> {
    let p = pool();
    let key = EpochKey::from_bytes([0x71; 32]);
    let mut frames = vec![build_create_frame(&p.roots[0], p.nonce, &key).unwrap()];
    for device in &p.devices[..3] {
        let prev = frames.last().unwrap().id();
        let frame = build_add_frame(
            &p.root_sks[0],
            p.vault,
            &resolve(&p.vault, &frames, &[]),
            frames.len() as u64,
            prev,
            vec![prev],
            device.device_id(),
            device.kem_public(),
            sign_join_consent(device, &p.vault, &p.roots[0].recovery_id()),
            None,
        )
        .unwrap();
        frames.push(frame);
    }
    frames
}

fn covered_rotate(recipients: impl IntoIterator<Item = crate::id::DeviceId>, tag: u8) -> Rotate {
    Rotate {
        suite: SUITE_X25519_WRAP,
        parents: vec![],
        commit: [tag; 32],
        back: vec![],
        wraps: recipients
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|id| (id, [tag; WRAP_LEN]))
            .collect(),
    }
}

#[test]
fn retrospective_member_equivocation_cannot_resurrect_a_removed_device() {
    let p = pool();
    let (b, c, d) = (&p.devices[0], &p.devices[1], &p.devices[2]);
    let root = p.roots[0].recovery_id();
    for (killer_is_root, killer) in [(false, d.sign_key()), (true, &p.root_sks[0])] {
        let mut frames = coverage_base();
        let tip = frames.last().unwrap().id();
        let remove_c = Frame::sign_member(
            b.sign_key(),
            p.vault,
            0,
            FrameId::ZERO,
            MemberBody {
                deps: vec![tip],
                op: Some(MemberOp::Remove {
                    device: c.device_id(),
                    last_seen_seq: None,
                }),
                rotate: Some(covered_rotate([root, b.device_id(), d.device_id()], 1)),
            },
        )
        .unwrap();
        let kill_b = Frame::sign_member(
            killer,
            p.vault,
            if killer_is_root { 4 } else { 0 },
            if killer_is_root { tip } else { FrameId::ZERO },
            MemberBody {
                deps: [tip, remove_c.id()]
                    .into_iter()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                op: Some(MemberOp::Remove {
                    device: b.device_id(),
                    last_seen_seq: None,
                }),
                rotate: Some(covered_rotate([root, d.device_id()], 2)),
            },
        )
        .unwrap();
        frames.extend([remove_c.clone(), kill_b.clone()]);
        assert!(!resolve(&p.vault, &frames, &[]).is_active_device(&b.device_id()));
        let mut fork_body = remove_c.member_body().unwrap().clone();
        fork_body.op = Some(MemberOp::Remove {
            device: c.device_id(),
            last_seen_seq: Some(0),
        });
        frames
            .push(Frame::sign_member(b.sign_key(), p.vault, 0, FrameId::ZERO, fork_body).unwrap());
        let got = resolve(&p.vault, &frames, &[]);
        assert!(got.authorized_frames.contains(&kill_b.id()));
        assert!(!got.is_active_device(&b.device_id()));
        assert_matches_ref(p.vault, &frames, &[]);
        for seed in 0..4 {
            assert_eq!(resolve(&p.vault, &shuffled(&frames, seed), &[]), got);
        }
        // If the killer actually saw both fork branches, C was still active.
        let fork = frames.last().unwrap().id();
        frames.retain(|frame| frame.id() != kill_b.id());
        let mut body = kill_b.member_body().unwrap().clone();
        body.deps.push(fork);
        body.deps.sort();
        let invalid = Frame::sign_member(
            killer,
            p.vault,
            kill_b.header().seq,
            kill_b.header().prev,
            body,
        )
        .unwrap();
        frames.push(invalid.clone());
        let got = assert_matches_ref(p.vault, &frames, &[]);
        assert!(!got.authorized_frames.contains(&invalid.id()));
        assert!(got.is_active_device(&b.device_id()));
    }
}

#[test]
fn under_inclusive_handoff_does_not_steal_the_next_roots_seniority() {
    let p = pool();
    let mut frames = coverage_base();
    let (b, c, d) = (&p.devices[0], &p.devices[1], &p.devices[2]);
    let (r0, r1, r2) = (
        p.roots[0].recovery_id(),
        p.roots[1].recovery_id(),
        p.roots[2].recovery_id(),
    );
    let tip = frames.last().unwrap().id();
    for (i, recipients) in [
        (1, vec![r1, b.device_id(), c.device_id()]),
        (2, vec![r2, b.device_id(), c.device_id(), d.device_id()]),
    ] {
        let prev = frames.last().unwrap().id();
        let new = p.roots[i].recovery_id();
        frames.push(
            Frame::sign_member(
                &p.root_sks[0],
                p.vault,
                frames.len() as u64,
                prev,
                MemberBody {
                    deps: vec![prev],
                    op: Some(MemberOp::RotateRecovery {
                        new,
                        new_kem: p.roots[i].kem_public(),
                        consent: sign_rotate_recovery_consent(
                            &p.root_sks[i],
                            &p.vault,
                            &r0,
                            &p.roots[i].kem_public(),
                        ),
                    }),
                    rotate: Some(covered_rotate(recipients, i as u8)),
                },
            )
            .unwrap(),
        );
    }
    let handoff = frames.last().unwrap().id();
    let kill_b = Frame::sign_member(
        &p.root_sks[2],
        p.vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps: vec![handoff],
            op: Some(MemberOp::Remove {
                device: b.device_id(),
                last_seen_seq: None,
            }),
            rotate: Some(covered_rotate([r2, c.device_id(), d.device_id()], 3)),
        },
    )
    .unwrap();
    let kill_c = Frame::sign_member(
        b.sign_key(),
        p.vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps: vec![tip],
            op: Some(MemberOp::Remove {
                device: c.device_id(),
                last_seen_seq: None,
            }),
            rotate: Some(covered_rotate([r0, b.device_id(), d.device_id()], 4)),
        },
    )
    .unwrap();
    frames.extend([kill_b.clone(), kill_c]);
    let got = resolve(&p.vault, &frames, &[]);
    assert_eq!(got.recovery_lineage, vec![r0, r2]);
    assert!(got.authorized_frames.contains(&kill_b.id()));
    assert!(!got.is_active_device(&b.device_id()));
    assert!(got.is_active_device(&c.device_id()));
    assert_matches_ref(p.vault, &frames, &[]);
}

#[test]
fn genesis_must_wrap_to_its_author() {
    let p = pool();
    let mut body = coverage_base()[0].member_body().unwrap().clone();
    body.rotate = Some(covered_rotate([p.devices[0].device_id()], 1));
    let create = Frame::sign_member(&p.root_sks[0], p.vault, 0, FrameId::ZERO, body).unwrap();
    let got = assert_matches_ref(p.vault, &[create], &[]);
    assert!(got.recovery_lineage.is_empty());
    assert!(got.authorized_frames.is_empty());
}

#[test]
fn concurrent_removal_and_recovery_handoff_keep_their_causal_recipients() {
    let p = pool();
    let (b, c, d) = (&p.devices[0], &p.devices[1], &p.devices[2]);
    let (r0, r1) = (p.roots[0].recovery_id(), p.roots[1].recovery_id());
    let mut frames = coverage_base();
    let tip = frames.last().unwrap().id();
    let handoff = Frame::sign_member(
        &p.root_sks[0],
        p.vault,
        4,
        tip,
        MemberBody {
            deps: vec![tip],
            op: Some(MemberOp::RotateRecovery {
                new: r1,
                new_kem: p.roots[1].kem_public(),
                consent: sign_rotate_recovery_consent(
                    &p.root_sks[1],
                    &p.vault,
                    &r0,
                    &p.roots[1].kem_public(),
                ),
            }),
            rotate: Some(covered_rotate(
                [r1, b.device_id(), c.device_id(), d.device_id()],
                1,
            )),
        },
    )
    .unwrap();
    let removal = Frame::sign_member(
        d.sign_key(),
        p.vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps: vec![tip],
            op: Some(MemberOp::Remove {
                device: c.device_id(),
                last_seen_seq: None,
            }),
            rotate: Some(covered_rotate([r0, b.device_id(), d.device_id()], 2)),
        },
    )
    .unwrap();
    frames.extend([handoff.clone(), removal.clone()]);
    let got = assert_matches_ref(p.vault, &frames, &[]);
    assert!(got.authorized_frames.contains(&handoff.id()));
    assert!(got.authorized_frames.contains(&removal.id()));
    assert_eq!(got.active_recovery, Some(r1));
    assert!(!got.is_active_device(&c.device_id()));
}

#[test]
fn a_fork_voided_admission_does_not_block_an_honest_removal() {
    let p = pool();
    let (a, b, d, x) = (&p.devices[0], &p.devices[1], &p.devices[2], &p.devices[3]);
    let root = p.roots[0].recovery_id();
    let mut frames = coverage_base();
    let tip = frames.last().unwrap().id();
    let epoch = EpochId::from_frame_id(frames[0].id());
    let add = build_add_frame(
        a.sign_key(),
        p.vault,
        &resolve(&p.vault, &frames, &[]),
        0,
        FrameId::ZERO,
        vec![tip],
        x.device_id(),
        x.kem_public(),
        sign_join_consent(x, &p.vault, &a.device_id()),
        None,
    )
    .unwrap();
    let rewrap = Rewrap {
        epoch,
        suite: SUITE_X25519_WRAP,
        wraps: vec![(x.device_id(), [1; WRAP_LEN])],
    };
    let witnessed = Frame::sign_member(
        d.sign_key(),
        p.vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps: vec![add.id()],
            op: Some(MemberOp::Rewrap(rewrap.clone())),
            rotate: None,
        },
    )
    .unwrap();
    frames.extend([add.clone(), witnessed.clone()]);
    let before = resolve(&p.vault, &frames, &[]);
    assert!(before.is_active_device(&x.device_id()));
    assert!(before.authorized_frames.contains(&witnessed.id()));
    let mut fork_body = add.member_body().unwrap().clone();
    if let Some(MemberOp::Add { rewrap: offer, .. }) = &mut fork_body.op {
        *offer = Some(rewrap);
    }
    let sibling = Frame::sign_member(a.sign_key(), p.vault, 0, FrameId::ZERO, fork_body).unwrap();
    let removal = Frame::sign_member(
        d.sign_key(),
        p.vault,
        1,
        witnessed.id(),
        MemberBody {
            deps: vec![witnessed.id()],
            op: Some(MemberOp::Remove {
                device: a.device_id(),
                last_seen_seq: None,
            }),
            rotate: Some(covered_rotate([root, b.device_id(), d.device_id()], 2)),
        },
    )
    .unwrap();
    // D's chain still includes Add(X), but it does not cite the sibling.
    frames.push(removal.clone());
    for explicit_proof in [false, true] {
        let mut view = frames.clone();
        let proofs = if explicit_proof {
            vec![FraudProof::from_frames(&add, &sibling).unwrap()]
        } else {
            view.push(sibling.clone());
            vec![]
        };
        let got = resolve(&p.vault, &view, &proofs);
        assert!(!got.is_active_device(&x.device_id()));
        assert!(got.authorized_frames.contains(&removal.id()));
        assert!(!got.is_active_device(&a.device_id()));
        assert!(got.removed.contains_key(&a.device_id()));
        assert_matches_ref(p.vault, &view, &proofs);
        for seed in 0..4 {
            assert_eq!(resolve(&p.vault, &shuffled(&view, seed), &proofs), got);
        }
    }
}
