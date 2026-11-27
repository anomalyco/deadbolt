//! Regression tests for Padmé on every target width and for the three wrap attacks on the
//! epoch graph: a junk wrap to the cold recovery root, a junk wrap to an online member, and a
//! fake back-link hiding a missing rewrap.

use std::collections::BTreeSet;

use super::super::*;
use super::epochs::{kem_map, pool};

/// Audit #1: exact Padmé lengths, identical on 32-bit (`wasm32`) and 64-bit targets. The old
/// `usize::BITS` arithmetic padded nothing above the floor on 64-bit (`301 -> 305`).
#[test]
fn padme_lengths_are_exact_and_width_independent() {
    let expected: [(usize, usize); 13] = [
        (0, 256),
        (252, 256),
        (253, 272),
        (256, 272),
        (300, 304),
        (301, 320),
        (500, 512),
        (1000, 1024),
        (1020, 1024),
        (4096, 4352),
        (5000, 5120),
        (65536, 67584),
        (1_000_000, 1_015_808),
    ];
    for (len, padded) in expected {
        assert_eq!(padme_padded_len(len).unwrap(), padded, "len {len}");
    }
    // Every length above the floor that is not already on a Padmé boundary pays some
    // padding, and never more than 12%.
    let mut padded_some = 0;
    for len in 253..20_000usize {
        let raw = len + 4;
        let padded = padme_padded_len(len).unwrap();
        assert!(padded >= raw);
        assert!((padded - raw) as f64 / raw as f64 <= 0.12, "len {len}");
        if padded > raw {
            padded_some += 1;
        }
    }
    assert!(
        padded_some > 15_000,
        "Padmé must actually pad: {padded_some}"
    );
}

#[test]
fn recovery_wraps_are_deterministic_and_checkable_without_the_root_secret() {
    let root = RecoverySecret::from_bytes([0x81; 32]);
    let key = EpochKey::from_bytes([0x82; 32]);
    let (info, aad) = (b"info".as_slice(), b"aad".as_slice());
    let pk = root.kem_public();
    let w1 = wrap_recovery_epoch_key(SUITE_X25519_WRAP, &pk, info, aad, &key).unwrap();
    let w2 = wrap_recovery_epoch_key(SUITE_X25519_WRAP, &pk, info, aad, &key).unwrap();
    assert_eq!(w1, w2);
    let opened = unwrap_epoch_key(SUITE_X25519_WRAP, &root.kem_secret(), info, aad, &w1).unwrap();
    assert_eq!(opened.as_bytes(), key.as_bytes());
    assert!(verify_recovery_wrap(&key, &pk, info, aad, &w1));
    // All wraps use the same checkable construction; other keys, contexts and junk fail.
    let random = wrap_epoch_key(SUITE_X25519_WRAP, &pk, info, aad, &key).unwrap();
    assert!(verify_recovery_wrap(&key, &pk, info, aad, &random));
    let other = EpochKey::from_bytes([0x83; 32]);
    assert!(!verify_recovery_wrap(&other, &pk, info, aad, &w1));
    assert!(!verify_recovery_wrap(&key, &pk, b"other", aad, &w1));
    assert!(!verify_recovery_wrap(
        &key,
        &pk,
        info,
        aad,
        &[0x42; WRAP_LEN]
    ));
}

struct Scene {
    vault: crate::id::VaultId,
    e0: EpochId,
    frames: Vec<Frame>,
}

/// Genesis plus devices added by the root with `e0` wrapped inline.
fn scene(devices: &[&DeviceKeys]) -> (Scene, EpochKey) {
    let p = pool();
    let r0 = &p.roots[0];
    let k0 = EpochKey::from_bytes([0x84; 32]);
    let create = build_create_frame(r0, p.nonce, &k0).unwrap();
    let vault = create.header().vault;
    let e0 = EpochId::from_frame_id(create.id());
    let mut frames = vec![create];
    for (i, dev) in devices.iter().enumerate() {
        let prev = frames.last().unwrap().id();
        let add = build_add_frame(
            &p.root_sks[0],
            vault,
            &resolve(&vault, &frames, &[]),
            i as u64 + 1,
            prev,
            vec![prev],
            dev.device_id(),
            dev.kem_public(),
            sign_join_consent(dev, &vault, &r0.recovery_id()),
            Some((e0, &k0)),
        )
        .unwrap();
        frames.push(add);
    }
    (Scene { vault, e0, frames }, k0)
}

/// Re-signs `frame` after `edit` swaps bytes of equal length: the header (and so every other
/// wrap's AAD) is unchanged, as a malicious author would produce.
fn tampered(
    frame: &Frame,
    author: &crate::id::DeviceSecret,
    edit: impl FnOnce(&mut MemberBody),
) -> Frame {
    let mut body = frame.member_body().unwrap().clone();
    edit(&mut body);
    let h = frame.header();
    let out = Frame::sign_member(author, h.vault, h.seq, h.prev, body).unwrap();
    assert_eq!(out.header_bytes(), frame.header_bytes());
    out
}

/// Builds A's standalone `Rotate` over `s`, then lets `edit` corrupt it.
fn rotate_by_a(
    s: &Scene,
    k0: &EpochKey,
    k1: &EpochKey,
    edit: impl FnOnce(&mut MemberBody),
) -> Frame {
    let a = &pool().devices[0];
    let res = resolve(&s.vault, &s.frames, &[]);
    let mut ring = EpochKeyring::new();
    ring.insert(s.e0, k0.clone());
    let last = s.frames.last().unwrap().id();
    let honest = build_standalone_rotate_frame(
        a.sign_key(),
        s.vault,
        &res,
        0,
        FrameId::ZERO,
        vec![last],
        k1,
        vec![s.e0],
        &ring,
        &kem_map(&res),
    )
    .unwrap();
    tampered(&honest, a.sign_key(), edit)
}

fn junk_wrap_to(target: crate::id::DeviceId) -> impl FnOnce(&mut MemberBody) {
    move |body: &mut MemberBody| {
        for (to, wrap) in &mut body.rotate.as_mut().unwrap().wraps {
            if *to == target {
                *wrap = [0x42; WRAP_LEN];
            }
        }
    }
}

/// Audit #5 (a): a rotator puts junk in the cold recovery root's wrap. Any online holder of
/// the `commit`-verified key sees it, with no `R_kem` secret, and repairs it.
#[test]
fn a_poisoned_recovery_wrap_is_caught_online_and_repaired() {
    let p = pool();
    let (r0, a, b) = (&p.roots[0], &p.devices[0], &p.devices[1]);
    let (mut s, k0) = scene(&[a, b]);
    let k1 = EpochKey::from_bytes([0x85; 32]);
    let rotate = rotate_by_a(&s, &k0, &k1, junk_wrap_to(r0.recovery_id()));
    let e1 = EpochId::from_frame_id(rotate.id());
    s.frames.push(rotate);
    let res = resolve(&s.vault, &s.frames, &[]);
    let graph = EpochGraph::build(s.vault, &s.frames, &res);
    let mut b_ring = EpochKeyring::new();
    graph.unlock(&b.device_id(), b.kem_key(), &mut b_ring);
    let plan = graph.needed_rewraps(&b_ring, &res, &BTreeSet::new());
    assert_eq!(plan, vec![(e1, vec![r0.recovery_id()])]);

    let repair = build_recovery_repair_rewrap(
        &graph,
        &res,
        b.sign_key(),
        0,
        FrameId::ZERO,
        vec![e1.as_frame_id()],
        e1,
        b_ring.get(&e1).unwrap(),
    )
    .unwrap();
    s.frames.push(repair);
    let res = resolve(&s.vault, &s.frames, &[]);
    let graph = EpochGraph::build(s.vault, &s.frames, &res);
    let mut r_ring = EpochKeyring::new();
    let report = graph.unlock(&r0.recovery_id(), &r0.kem_secret(), &mut r_ring);
    assert_eq!(r_ring.get(&e1).unwrap().as_bytes(), k1.as_bytes());
    assert_eq!(report.bad_offers.len(), 1, "the junk offer is reported");
    let mut b_ring = EpochKeyring::new();
    graph.unlock(&b.device_id(), b.kem_key(), &mut b_ring);
    assert_eq!(
        graph.needed_rewraps(&b_ring, &res, &BTreeSet::new()),
        Vec::new()
    );
}

/// Audit #5 (b): junk in an online member's wrap is reported by `unlock`, and the member
/// mints a fresh `Rotate` instead of waiting forever in `AwaitingRewrap`.
#[test]
fn a_junk_offer_does_not_wedge_an_online_member() {
    let p = pool();
    let (a, b) = (&p.devices[0], &p.devices[1]);
    let (mut s, k0) = scene(&[a, b]);
    let k1 = EpochKey::from_bytes([0x86; 32]);
    let rotate = rotate_by_a(&s, &k0, &k1, junk_wrap_to(b.device_id()));
    let e1 = EpochId::from_frame_id(rotate.id());
    s.frames.push(rotate);
    let res = resolve(&s.vault, &s.frames, &[]);
    let graph = EpochGraph::build(s.vault, &s.frames, &res);
    let mut b_ring = EpochKeyring::new();
    let report = graph.unlock(&b.device_id(), b.kem_key(), &mut b_ring);
    assert!(!b_ring.contains(&e1));
    assert_eq!(report.bad_offers.len(), 1);
    assert_eq!(report.bad_offers[0].epoch, e1);
    assert_eq!(report.bad_epochs(), [e1].into());
    assert_eq!(
        graph.select_write_epoch(&res, &b_ring, &BTreeSet::new()),
        WriteEpochDecision::AwaitingRewrap(e1),
        "without the report the member would wait"
    );
    assert_eq!(
        graph.select_write_epoch(&res, &b_ring, &report.bad_epochs()),
        WriteEpochDecision::MintRotate { parents: vec![e1] }
    );
}

/// Audit #5 (c): a fake back-link from a new epoch to a counted one must not convince the
/// reader-duty planner that a member who only holds the new epoch can reach the old one.
#[test]
fn a_fake_back_link_does_not_suppress_a_rewrap() {
    let p = pool();
    let (a, b, c) = (&p.devices[0], &p.devices[1], &p.devices[2]);
    let (mut s, k0) = scene(&[a, b]);
    let vault = s.vault;
    let mut ring = EpochKeyring::new();
    ring.insert(s.e0, k0.clone());

    // A removes B (e1); data lands in e1; A adds C without wrapping e1 to it.
    let res = resolve(&vault, &s.frames, &[]);
    let mut to = kem_map(&res);
    to.remove(&b.device_id());
    let k1 = EpochKey::from_bytes([0x87; 32]);
    let last = s.frames.last().unwrap().id();
    let rem_b = build_remove_frame(
        a.sign_key(),
        vault,
        &res,
        0,
        FrameId::ZERO,
        vec![last],
        b.device_id(),
        None,
        &k1,
        vec![s.e0],
        &ring,
        &to,
    )
    .unwrap();
    let e1 = EpochId::from_frame_id(rem_b.id());
    ring.insert(e1, k1.clone());
    s.frames.push(rem_b.clone());
    let add_c = build_add_frame(
        a.sign_key(),
        vault,
        &resolve(&vault, &s.frames, &[]),
        1,
        rem_b.id(),
        vec![rem_b.id()],
        c.device_id(),
        c.kem_public(),
        sign_join_consent(c, &vault, &a.device_id()),
        None,
    )
    .unwrap();
    s.frames.push(add_c.clone());

    // A mints e2 over e1 with a real back-link, then swaps the link for junk.
    let res = resolve(&vault, &s.frames, &[]);
    let k2 = EpochKey::from_bytes([0x88; 32]);
    let honest = build_standalone_rotate_frame(
        a.sign_key(),
        vault,
        &res,
        2,
        add_c.id(),
        vec![add_c.id()],
        &k2,
        vec![e1],
        &ring,
        &kem_map(&res),
    )
    .unwrap();
    let counted: BTreeSet<EpochId> = [e1].into();
    let plan_for = |rotate: Frame| {
        let mut frames = s.frames.clone();
        frames.push(rotate);
        let res = resolve(&vault, &frames, &[]);
        let graph = EpochGraph::build(vault, &frames, &res);
        let mut a_ring = EpochKeyring::new();
        let report = graph.unlock(&a.device_id(), a.kem_key(), &mut a_ring);
        (graph.needed_rewraps(&a_ring, &res, &counted), report)
    };
    let (honest_plan, honest_report) = plan_for(honest.clone());
    assert!(
        honest_plan.iter().all(|(e, _)| *e != e1),
        "a real back-link reaches e1: {honest_plan:?}"
    );
    let e2_honest = EpochId::from_frame_id(honest.id());
    assert!(honest_report.verified_back.contains(&(e2_honest, e1)));

    let fake = tampered(&honest, a.sign_key(), |body| {
        body.rotate.as_mut().unwrap().back[0].1 = [0x42; BACK_LINK_LEN];
    });
    let e2 = EpochId::from_frame_id(fake.id());
    let (plan, report) = plan_for(fake);
    assert!(plan.contains(&(e1, vec![c.device_id()])), "{plan:?}");
    assert!(!report.verified_back.contains(&(e2, e1)));
    assert_eq!(report.bad_back_links.len(), 1);
    assert_eq!(report.bad_back_links[0].epoch, e1);
}

#[test]
fn under_inclusive_rotation_never_authorizes_its_epoch() {
    let p = pool();
    let (m, a) = (&p.devices[0], &p.devices[1]);
    for omitted in [a.device_id(), p.roots[0].recovery_id()] {
        let (mut s, k0) = scene(&[m, a]);
        let k1 = EpochKey::from_bytes([0x98; 32]);
        let honest = rotate_by_a(&s, &k0, &k1, |_| {});
        let mut body = honest.member_body().unwrap().clone();
        body.rotate
            .as_mut()
            .unwrap()
            .wraps
            .retain(|(id, _)| *id != omitted);
        let malicious = Frame::sign_member(m.sign_key(), s.vault, 0, FrameId::ZERO, body).unwrap();
        let bad_epoch = EpochId::from_frame_id(malicious.id());
        s.frames.push(malicious);
        let res = resolve(&s.vault, &s.frames, &[]);
        assert!(!res.is_authorized_epoch(&bad_epoch));
        let graph = EpochGraph::build(s.vault, &s.frames, &res);
        let mut ring = EpochKeyring::new();
        graph.unlock(&a.device_id(), a.kem_key(), &mut ring);
        assert_eq!(
            graph.select_write_epoch(&res, &ring, &BTreeSet::new()),
            WriteEpochDecision::Use(s.e0)
        );
        let payload = DataPayload {
            mheads: vec![s.frames.last().unwrap().id()],
            dclock: DeltaClock::default(),
            timestamp_ms: 1,
            ops: vec![],
        };
        let frame = payload
            .seal(m.sign_key(), s.vault, 0, FrameId::ZERO, bad_epoch, &k1)
            .unwrap();
        let opened = DataFrame::open(&frame, &k1).unwrap();
        let adders = std::collections::BTreeMap::new();
        assert!(
            !FoldContext {
                membership: &res,
                adders: &adders
            }
            .counts(&opened)
        );
    }
}

#[test]
fn an_online_junk_wrap_is_repaired_after_the_recipient_rotates() {
    let p = pool();
    let (m, a, d) = (&p.devices[0], &p.devices[1], &p.devices[2]);
    let (mut s, k0) = scene(&[m, a, d]);
    let k1 = EpochKey::from_bytes([0x99; 32]);
    let bad = rotate_by_a(&s, &k0, &k1, junk_wrap_to(d.device_id()));
    let e1 = EpochId::from_frame_id(bad.id());
    s.frames.push(bad);
    let res = resolve(&s.vault, &s.frames, &[]);
    let graph = EpochGraph::build(s.vault, &s.frames, &res);
    let mut d_ring = EpochKeyring::new();
    graph.unlock(&d.device_id(), d.kem_key(), &mut d_ring);
    assert!(!d_ring.contains(&e1));
    let k2 = EpochKey::from_bytes([0x9a; 32]);
    let fresh = build_standalone_rotate_frame(
        d.sign_key(),
        s.vault,
        &res,
        0,
        FrameId::ZERO,
        vec![e1.as_frame_id()],
        &k2,
        vec![e1],
        &d_ring,
        &kem_map(&res),
    )
    .unwrap();
    assert!(
        fresh
            .member_body()
            .unwrap()
            .rotate
            .as_ref()
            .unwrap()
            .back
            .is_empty()
    );
    s.frames.push(fresh);
    let res = resolve(&s.vault, &s.frames, &[]);
    let graph = EpochGraph::build(s.vault, &s.frames, &res);
    let mut a_ring = EpochKeyring::new();
    graph.unlock(&a.device_id(), a.kem_key(), &mut a_ring);
    let plan = graph.needed_rewraps(&a_ring, &res, &[e1].into());
    assert!(plan.contains(&(e1, vec![d.device_id()])), "{plan:?}");
    let repair = build_rewrap_frame(
        a.sign_key(),
        s.vault,
        &res,
        0,
        FrameId::ZERO,
        vec![s.frames.last().unwrap().id()],
        e1,
        a_ring.get(&e1).unwrap(),
        &[(d.device_id(), d.kem_public())].into(),
    )
    .unwrap();
    let payload = DataPayload {
        mheads: vec![e1.as_frame_id()],
        dclock: DeltaClock::default(),
        timestamp_ms: 1,
        ops: vec![],
    };
    let data = payload
        .seal(m.sign_key(), s.vault, 0, FrameId::ZERO, e1, &k1)
        .unwrap();
    let adders = std::collections::BTreeMap::new();
    assert!(
        FoldContext {
            membership: &res,
            adders: &adders
        }
        .counts(&DataFrame::open(&data, &k1).unwrap())
    );
    s.frames.push(repair);
    let res = resolve(&s.vault, &s.frames, &[]);
    let graph = EpochGraph::build(s.vault, &s.frames, &res);
    graph.unlock(&d.device_id(), d.kem_key(), &mut d_ring);
    assert_eq!(
        DataFrame::open(&data, d_ring.get(&e1).unwrap())
            .unwrap()
            .body,
        DataBody::Data(payload)
    );
}
