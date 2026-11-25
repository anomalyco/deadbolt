//! Named multi-device epoch scenarios for I1, I2, I3, back-links, and E6 reader duty.

use std::collections::{BTreeMap, BTreeSet};

use crate::id::DeviceId;

use super::super::*;
use super::epochs::{all_deps_with_prev, kem_map, member_heads, next_member_slot, pool};

#[test]
fn i1_i2_i3_concurrent_offline_removals_and_dual_merge() {
    let p = pool();
    let (r0, r0_sk, r0_kem) = (&p.roots[0], &p.root_sks[0], &p.root_kems[0]);
    let (a, b, c, x, y) = (
        &p.devices[0],
        &p.devices[1],
        &p.devices[2],
        &p.devices[3],
        &p.devices[4],
    );
    let k0 = EpochKey::from_bytes([1; 32]);
    let create = build_create_frame(r0, p.nonce, &k0).unwrap();
    let vault = create.header().vault;
    let e0 = EpochId::from_frame_id(create.id());

    let mut base = vec![create];
    for dev in [a, b, c, x, y] {
        let (seq, prev) = next_member_slot(&base, r0.recovery_id());
        let deps = all_deps_with_prev(member_heads(&base), prev);
        let add = build_add_frame(
            r0_sk,
            vault,
            &resolve(&vault, &base, &[]),
            seq,
            prev,
            deps,
            dev.device_id(),
            dev.kem_public(),
            sign_join_consent(dev.sign_key(), &vault, &r0.recovery_id(), &dev.kem_public()),
            Some((e0, &k0)),
        )
        .unwrap();
        base.push(add);
    }

    // Data written under e0 before the partition.
    let d_x =
        Frame::seal_data(x.sign_key(), vault, 0, FrameId::ZERO, e0, &k0, b"from-x-e0").unwrap();
    let d_y =
        Frame::seal_data(y.sign_key(), vault, 0, FrameId::ZERO, e0, &k0, b"from-y-e0").unwrap();

    // Offline partition: A removes X (mints e1 to {A,B,C,Y,R0}); B removes Y (mints e2 to {A,B,C,X,R0}).
    let mut ring0 = EpochKeyring::new();
    ring0.insert(e0, k0.clone());
    let base_heads = member_heads(&base);

    let mut rec_no_x = BTreeMap::new();
    for dev in [a, b, c, y] {
        rec_no_x.insert(dev.device_id(), dev.kem_public());
    }
    rec_no_x.insert(r0.recovery_id(), r0.kem_public());
    let k1 = EpochKey::from_bytes([2; 32]);
    let rem_x = build_remove_frame(
        a.sign_key(),
        vault,
        &resolve(&vault, &base, &[]),
        0,
        FrameId::ZERO,
        base_heads.clone(),
        x.device_id(),
        Some(0),
        &k1,
        vec![e0],
        &ring0,
        &rec_no_x,
    )
    .unwrap();
    let e1 = EpochId::from_frame_id(rem_x.id());

    let mut rec_no_y = BTreeMap::new();
    for dev in [a, b, c, x] {
        rec_no_y.insert(dev.device_id(), dev.kem_public());
    }
    rec_no_y.insert(r0.recovery_id(), r0.kem_public());
    let k2 = EpochKey::from_bytes([3; 32]);
    let rem_y = build_remove_frame(
        b.sign_key(),
        vault,
        &resolve(&vault, &base, &[]),
        0,
        FrameId::ZERO,
        base_heads,
        y.device_id(),
        Some(0),
        &k2,
        vec![e0],
        &ring0,
        &rec_no_y,
    )
    .unwrap();
    let e2 = EpochId::from_frame_id(rem_y.id());

    let mut merged = base;
    merged.push(rem_x);
    merged.push(rem_y);

    let res_mid = resolve(&vault, &merged, &[]);
    let graph_mid = EpochGraph::build(vault, &merged, &res_mid);
    // Neither e1 (has Y) nor e2 (has X) is clean!
    assert!(graph_mid.clean_tips(&res_mid).is_empty());

    // Both A and C independently mint clean-tip Rotates offline (dual merge!).
    let mut a_ring = EpochKeyring::new();
    graph_mid.unlock(&a.device_id(), a.kem_key(), &mut a_ring);
    let WriteEpochDecision::MintRotate { parents: a_parents } =
        graph_mid.select_write_epoch(&res_mid, &a_ring, &BTreeSet::new())
    else {
        panic!("expected MintRotate for A");
    };
    assert_eq!(a_parents.len(), 2);
    let rec_clean = kem_map(&res_mid);
    let k3a = EpochKey::from_bytes([4; 32]);
    let (a_seq, a_prev) = next_member_slot(&merged, a.device_id());
    let e3a_frame = build_standalone_rotate_frame(
        a.sign_key(),
        vault,
        &res_mid,
        a_seq,
        a_prev,
        all_deps_with_prev(member_heads(&merged), a_prev),
        &k3a,
        a_parents,
        &a_ring,
        &rec_clean,
    )
    .unwrap();
    let e3a = EpochId::from_frame_id(e3a_frame.id());

    let mut c_ring = EpochKeyring::new();
    graph_mid.unlock(&c.device_id(), c.kem_key(), &mut c_ring);
    let WriteEpochDecision::MintRotate { parents: c_parents } =
        graph_mid.select_write_epoch(&res_mid, &c_ring, &BTreeSet::new())
    else {
        panic!("expected MintRotate for C");
    };
    let k3c = EpochKey::from_bytes([5; 32]);
    let e3c_frame = build_standalone_rotate_frame(
        c.sign_key(),
        vault,
        &res_mid,
        0,
        FrameId::ZERO,
        member_heads(&merged),
        &k3c,
        c_parents,
        &c_ring,
        &rec_clean,
    )
    .unwrap();
    let e3c = EpochId::from_frame_id(e3c_frame.id());

    merged.push(e3a_frame);
    merged.push(e3c_frame);

    let res_final = resolve(&vault, &merged, &[]);
    let graph_final = EpochGraph::build(vault, &merged, &res_final);
    let expected_tip = e3a.min(e3c);

    // I1 + I2: Every active member & recovery root converges on min(e3a, e3c) and decrypts all history.
    let active_principals: Vec<(DeviceId, &KemSecret)> = vec![
        (a.device_id(), a.kem_key()),
        (b.device_id(), b.kem_key()),
        (c.device_id(), c.kem_key()),
        (r0.recovery_id(), r0_kem),
    ];
    for (id, kem) in active_principals {
        let mut ring = EpochKeyring::new();
        let report = graph_final.unlock(&id, kem, &mut ring);
        assert!(report.bad_commits.is_empty());
        assert_eq!(
            graph_final.select_write_epoch(&res_final, &ring, &BTreeSet::new()),
            WriteEpochDecision::Use(expected_tip)
        );
        assert_eq!(
            d_x.open_sealed(ring.get(&e0).unwrap()).unwrap().as_slice(),
            b"from-x-e0"
        );
        assert_eq!(
            d_y.open_sealed(ring.get(&e0).unwrap()).unwrap().as_slice(),
            b"from-y-e0"
        );
    }

    // I3: Removed devices X and Y cannot unwrap post-removal epochs (e1 for X, e2 for Y, e3a/e3c for both).
    let mut x_ring = EpochKeyring::new();
    graph_final.unlock(&x.device_id(), x.kem_key(), &mut x_ring);
    assert!(!x_ring.contains(&e1));
    assert!(!x_ring.contains(&e3a));
    assert!(!x_ring.contains(&e3c));

    let mut y_ring = EpochKeyring::new();
    graph_final.unlock(&y.device_id(), y.kem_key(), &mut y_ring);
    assert!(!y_ring.contains(&e2));
    assert!(!y_ring.contains(&e3a));
    assert!(!y_ring.contains(&e3c));
}

#[test]
fn i2_sixty_day_offline_device_and_newly_added_device_decrypt_via_back_links() {
    let p = pool();
    let (r0, r0_sk) = (&p.roots[0], &p.root_sks[0]);
    let (a, offline, temp, new_phone) =
        (&p.devices[0], &p.devices[1], &p.devices[2], &p.devices[3]);

    let k0 = EpochKey::from_bytes([10; 32]);
    let create = build_create_frame(r0, p.nonce, &k0).unwrap();
    let vault = create.header().vault;
    let e0 = EpochId::from_frame_id(create.id());
    let mut frames = vec![create];

    for dev in [a, offline, temp] {
        let (seq, prev) = next_member_slot(&frames, r0.recovery_id());
        let deps = all_deps_with_prev(member_heads(&frames), prev);
        let add = build_add_frame(
            r0_sk,
            vault,
            &resolve(&vault, &frames, &[]),
            seq,
            prev,
            deps,
            dev.device_id(),
            dev.kem_public(),
            sign_join_consent(dev.sign_key(), &vault, &r0.recovery_id(), &dev.kem_public()),
            Some((e0, &k0)),
        )
        .unwrap();
        frames.push(add);
    }

    // Offline writes under e0 while disconnected for 60 days.
    let offline_write = Frame::seal_data(
        offline.sign_key(),
        vault,
        0,
        FrameId::ZERO,
        e0,
        &k0,
        b"60-day-offline-edit",
    )
    .unwrap();

    // Meanwhile A removes temp (minting e1) and then adds new_phone (rewrapping e1 ONLY).
    let mut a_ring = EpochKeyring::new();
    a_ring.insert(e0, k0);
    let mut rec1 = BTreeMap::new();
    rec1.insert(a.device_id(), a.kem_public());
    rec1.insert(offline.device_id(), offline.kem_public());
    rec1.insert(r0.recovery_id(), r0.kem_public());
    let k1 = EpochKey::from_bytes([11; 32]);
    let rem_temp = build_remove_frame(
        a.sign_key(),
        vault,
        &resolve(&vault, &frames, &[]),
        0,
        FrameId::ZERO,
        member_heads(&frames),
        temp.device_id(),
        None,
        &k1,
        vec![e0],
        &a_ring,
        &rec1,
    )
    .unwrap();
    let e1 = EpochId::from_frame_id(rem_temp.id());
    frames.push(rem_temp);

    let (a_seq, a_prev) = next_member_slot(&frames, a.device_id());
    let add_new_phone = build_add_frame(
        a.sign_key(),
        vault,
        &resolve(&vault, &frames, &[]),
        a_seq,
        a_prev,
        all_deps_with_prev(member_heads(&frames), a_prev),
        new_phone.device_id(),
        new_phone.kem_public(),
        sign_join_consent(
            new_phone.sign_key(),
            &vault,
            &a.device_id(),
            &new_phone.kem_public(),
        ),
        Some((e1, &k1)),
    )
    .unwrap();
    frames.push(add_new_phone);

    let resolved = resolve(&vault, &frames, &[]);
    let graph = EpochGraph::build(vault, &frames, &resolved);

    // NewPhone starts with zero keyring -> unwraps e1 -> walks back-link to e0 -> opens offline_write!
    let mut phone_ring = EpochKeyring::new();
    graph.unlock(&new_phone.device_id(), new_phone.kem_key(), &mut phone_ring);
    assert!(phone_ring.contains(&e1));
    assert!(phone_ring.contains(&e0));
    assert_eq!(
        offline_write
            .open_sealed(phone_ring.get(&e0).unwrap())
            .unwrap()
            .as_slice(),
        b"60-day-offline-edit"
    );
    assert_eq!(
        graph.select_write_epoch(&resolved, &phone_ring, &BTreeSet::new()),
        WriteEpochDecision::Use(e1)
    );

    // Offline returns -> unwraps e1 directly -> converges on e1.
    let mut off_ring = EpochKeyring::new();
    graph.unlock(&offline.device_id(), offline.kem_key(), &mut off_ring);
    assert_eq!(
        graph.select_write_epoch(&resolved, &off_ring, &BTreeSet::new()),
        WriteEpochDecision::Use(e1)
    );
}

#[test]
fn e6_reader_duty_rewraps_for_concurrent_add_and_rotate() {
    let p = pool();
    let (r0, r0_sk) = (&p.roots[0], &p.root_sks[0]);
    let (a, b, x, newcomer) = (&p.devices[0], &p.devices[1], &p.devices[2], &p.devices[3]);

    let k0 = EpochKey::from_bytes([15; 32]);
    let create = build_create_frame(r0, p.nonce, &k0).unwrap();
    let vault = create.header().vault;
    let e0 = EpochId::from_frame_id(create.id());
    let mut frames = vec![create];
    for dev in [a, b, x] {
        let (seq, prev) = next_member_slot(&frames, r0.recovery_id());
        let deps = all_deps_with_prev(member_heads(&frames), prev);
        let add = build_add_frame(
            r0_sk,
            vault,
            &resolve(&vault, &frames, &[]),
            seq,
            prev,
            deps,
            dev.device_id(),
            dev.kem_public(),
            sign_join_consent(dev.sign_key(), &vault, &r0.recovery_id(), &dev.kem_public()),
            Some((e0, &k0)),
        )
        .unwrap();
        frames.push(add);
    }
    let heads_before = member_heads(&frames);

    // Concurrently offline: A adds newcomer (wrapping e0); B removes X (minting e1 without newcomer).
    let add_new = build_add_frame(
        a.sign_key(),
        vault,
        &resolve(&vault, &frames, &[]),
        0,
        FrameId::ZERO,
        heads_before.clone(),
        newcomer.device_id(),
        newcomer.kem_public(),
        sign_join_consent(
            newcomer.sign_key(),
            &vault,
            &a.device_id(),
            &newcomer.kem_public(),
        ),
        Some((e0, &k0)),
    )
    .unwrap();

    let mut b_ring = EpochKeyring::new();
    b_ring.insert(e0, k0);
    let mut rec_b = BTreeMap::new();
    rec_b.insert(a.device_id(), a.kem_public());
    rec_b.insert(b.device_id(), b.kem_public());
    rec_b.insert(r0.recovery_id(), r0.kem_public());
    let k1 = EpochKey::from_bytes([16; 32]);
    let rem_x = build_remove_frame(
        b.sign_key(),
        vault,
        &resolve(&vault, &frames, &[]),
        0,
        FrameId::ZERO,
        heads_before,
        x.device_id(),
        None,
        &k1,
        vec![e0],
        &b_ring,
        &rec_b,
    )
    .unwrap();
    let e1 = EpochId::from_frame_id(rem_x.id());
    let d_e1 =
        Frame::seal_data(b.sign_key(), vault, 0, FrameId::ZERO, e1, &k1, b"e1-secret").unwrap();

    frames.push(add_new);
    frames.push(rem_x);

    let res1 = resolve(&vault, &frames, &[]);
    let g1 = EpochGraph::build(vault, &frames, &res1);

    // Before E6 reader duty: newcomer awaits rewrap for clean tip e1.
    let mut new_ring = EpochKeyring::new();
    g1.unlock(&newcomer.device_id(), newcomer.kem_key(), &mut new_ring);
    assert_eq!(
        g1.select_write_epoch(&res1, &new_ring, &BTreeSet::new()),
        WriteEpochDecision::AwaitingRewrap(e1)
    );

    // A runs E6 reader duty and emits Rewrap(e1, [newcomer]).
    let mut a_ring = EpochKeyring::new();
    g1.unlock(&a.device_id(), a.kem_key(), &mut a_ring);
    let counted_epochs: BTreeSet<EpochId> = [e1].into_iter().collect();
    let plan = g1.needed_rewraps(&a_ring, &res1, &counted_epochs);
    assert_eq!(plan, vec![(e1, vec![newcomer.device_id()])]);

    let (a_seq, a_prev) = next_member_slot(&frames, a.device_id());
    let mut target_map = BTreeMap::new();
    target_map.insert(newcomer.device_id(), newcomer.kem_public());
    let rewrap = build_rewrap_frame(
        a.sign_key(),
        vault,
        &res1,
        a_seq,
        a_prev,
        all_deps_with_prev(member_heads(&frames), a_prev),
        e1,
        a_ring.get(&e1).unwrap(),
        &target_map,
    )
    .unwrap();
    frames.push(rewrap);

    let res2 = resolve(&vault, &frames, &[]);
    let g2 = EpochGraph::build(vault, &frames, &res2);
    let mut new_ring2 = EpochKeyring::new();
    g2.unlock(&newcomer.device_id(), newcomer.kem_key(), &mut new_ring2);
    assert_eq!(
        g2.select_write_epoch(&res2, &new_ring2, &BTreeSet::new()),
        WriteEpochDecision::Use(e1)
    );
    assert_eq!(
        d_e1.open_sealed(new_ring2.get(&e1).unwrap())
            .unwrap()
            .as_slice(),
        b"e1-secret"
    );
}

// ============================================================================
// Randomized Multi-Device Property Suite (I1, I2, I3 at 20,000 cases)
// ============================================================================
