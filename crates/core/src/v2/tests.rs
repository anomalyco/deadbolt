//! Security, wire-format, epoch, and property test suite for `deadbolt_core::v2`.

mod causality;
mod checkpoints;
mod compaction;
mod continuity;
mod dataplane;
mod epochs;
mod lineage;
mod model;
mod order;
mod revocation;
mod scenarios;
mod sim;
mod tear;
mod wraps;

use std::collections::{BTreeMap, BTreeSet};

use crate::id::{DeviceId, DeviceSecret, Signature, VaultId};

use super::*;

/// The membership a builder sees after `frames` (all in one vault).
pub(super) fn view(frames: &[&Frame]) -> ResolvedMembership {
    resolve(&frames[0].header().vault, frames.iter().copied(), &[])
}

#[expect(
    clippy::disallowed_methods,
    reason = "test configuration boundary matching v1 membership_tests"
)]
pub(crate) fn membership_cases() -> u32 {
    std::env::var("DEADBOLT_MEMBERSHIP_CASES")
        .ok()
        .map(|n| n.parse().expect("valid DEADBOLT_MEMBERSHIP_CASES"))
        .unwrap_or(16)
}

// Known small-order X25519 points (RFC 7748 / Curve25519 low-order subgroup).
const LOW_ORDER_X25519_POINTS: [[u8; 32]; 7] = [
    [0u8; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

#[test]
fn x25519_wrap_round_trip_and_context_bound_determinism() {
    let recipient = KemSecret::from_bytes(&[0x42; 32]);
    let key = EpochKey::from_bytes([0x99; 32]);
    let info = b"deadbolt/v2 wrap test";
    let aad = b"header-aad";

    let w1 = wrap_epoch_key(SUITE_X25519_WRAP, &recipient.public_key(), info, aad, &key).unwrap();
    let w2 = wrap_epoch_key(SUITE_X25519_WRAP, &recipient.public_key(), info, aad, &key).unwrap();
    assert_eq!(w1.len(), WRAP_LEN);
    assert_eq!(w1, w2, "wraps must be checkable by every epoch key holder");

    let opened1 = unwrap_epoch_key(SUITE_X25519_WRAP, &recipient, info, aad, &w1).unwrap();
    let opened2 = unwrap_epoch_key(SUITE_X25519_WRAP, &recipient, info, aad, &w2).unwrap();
    assert_eq!(opened1.as_bytes(), key.as_bytes());
    assert_eq!(opened2.as_bytes(), key.as_bytes());

    // Wrong info, wrong AAD, wrong recipient, or tampered byte must fail.
    assert_eq!(
        unwrap_epoch_key(SUITE_X25519_WRAP, &recipient, b"wrong-info", aad, &w1).unwrap_err(),
        CryptoError::DecryptFailed
    );
    assert_eq!(
        unwrap_epoch_key(SUITE_X25519_WRAP, &recipient, info, b"wrong-aad", &w1).unwrap_err(),
        CryptoError::DecryptFailed
    );
    let other = KemSecret::from_bytes(&[0x43; 32]);
    assert_eq!(
        unwrap_epoch_key(SUITE_X25519_WRAP, &other, info, aad, &w1).unwrap_err(),
        CryptoError::DecryptFailed
    );
    let mut tampered = w1;
    tampered[79] ^= 0x01;
    assert_eq!(
        unwrap_epoch_key(SUITE_X25519_WRAP, &recipient, info, aad, &tampered).unwrap_err(),
        CryptoError::DecryptFailed
    );
}

#[test]
fn x25519_wrap_rejects_reserved_and_unknown_suites() {
    let recipient = KemSecret::from_bytes(&[0x11; 32]);
    let key = EpochKey::from_bytes([0x22; 32]);
    let dummy = [0u8; WRAP_LEN];
    for bad_suite in [0u8, SUITE_XWING_RESERVED, 3, 255] {
        assert_eq!(
            wrap_epoch_key(bad_suite, &recipient.public_key(), b"i", b"a", &key).unwrap_err(),
            CryptoError::UnsupportedSuite(bad_suite)
        );
        assert_eq!(
            unwrap_epoch_key(bad_suite, &recipient, b"i", b"a", &dummy).unwrap_err(),
            CryptoError::UnsupportedSuite(bad_suite)
        );
    }
}

#[test]
fn x25519_rejects_non_contributory_public_keys() {
    let recipient = KemSecret::from_bytes(&[0x55; 32]);
    let key = EpochKey::from_bytes([0x66; 32]);
    for point in LOW_ORDER_X25519_POINTS {
        let pk = KemPublic::from_bytes(point);
        assert_eq!(
            wrap_epoch_key(SUITE_X25519_WRAP, &pk, b"i", b"a", &key).unwrap_err(),
            CryptoError::NonContributoryKey,
            "wrap must reject low-order point {point:02x?}"
        );
        let mut wrapped = [0u8; WRAP_LEN];
        wrapped[..32].copy_from_slice(&point);
        assert_eq!(
            unwrap_epoch_key(SUITE_X25519_WRAP, &recipient, b"i", b"a", &wrapped).unwrap_err(),
            CryptoError::NonContributoryKey,
            "unwrap must reject low-order ephemeral point {point:02x?}"
        );
    }
}

#[test]
fn ed25519_verify_strict_rejects_malleable_and_small_order_signatures() {
    let sk = DeviceSecret::from_bytes(&[0x07; 32]);
    let pk = sk.device_id();
    let msg = b"deadbolt/v2 strict check";
    let sig = sign(&sk, msg);
    assert!(verify_strict(&pk, msg, &sig));
    assert!(!verify_strict(&pk, b"other", &sig));

    // Malleable signature: S >= L (ed25519 group order) must be rejected.
    let mut malleable = *sig.as_bytes();
    malleable[63] |= 0xf0;
    assert!(!verify_strict(&pk, msg, &Signature::from_bytes(malleable)));

    // Small-order public key (identity point) must be rejected.
    let mut id_pk = [0u8; 32];
    id_pk[0] = 1;
    assert!(!verify_strict(
        &DeviceId::from_bytes(id_pk),
        msg,
        &Signature::from_bytes([0u8; 64])
    ));
}

#[test]
fn padme_round_trip_overhead_and_canonical_rejection() {
    let mut lens: Vec<usize> = (0..=600).collect();
    for exp in 8..=16 {
        let p = 1usize << exp;
        lens.extend([p - 5, p - 4, p - 1, p, p + 1]);
    }
    for len in lens {
        let pt: Vec<u8> = (0..len)
            .map(|i| (i.wrapping_mul(31) & 0xff) as u8)
            .collect();
        let padded = padme_pad(&pt).unwrap();
        assert!(padded.len() >= PADME_FLOOR);
        if len + 4 > PADME_FLOOR {
            let overhead = (padded.len() - (len + 4)) as f64 / (len + 4) as f64;
            assert!(overhead <= 0.12, "len={len} overhead={overhead}");
        }
        assert_eq!(padme_unpad(&padded).unwrap(), pt.as_slice());

        // Mutating any padding byte to non-zero must fail.
        if padded.len() > 4 + len {
            let mut bad = padded.to_vec();
            *bad.last_mut().unwrap() = 0x01;
            assert_eq!(padme_unpad(&bad).unwrap_err(), CryptoError::InvalidPadding);
        }
    }
    // Truncated, over-padded, and short buffers must fail.
    assert_eq!(
        padme_unpad(&[0u8; 255]).unwrap_err(),
        CryptoError::InvalidPadding
    );
    let mut over = padme_pad(b"hi").unwrap().to_vec();
    over.push(0);
    assert_eq!(padme_unpad(&over).unwrap_err(), CryptoError::InvalidPadding);
}

#[test]
fn key_separation_recovery_and_device_keys() {
    let rs = RecoverySecret::from_bytes([0xaa; 32]);
    assert_ne!(rs.recovery_id().as_bytes(), rs.kem_public().as_bytes());

    let dev = DeviceKeys::from_seed(&[0xbb; 32]);
    assert_ne!(dev.device_id().as_bytes(), dev.kem_public().as_bytes());
    assert_ne!(dev.device_id().as_bytes(), dev.net_public().as_bytes());
    assert_ne!(dev.kem_public().as_bytes(), dev.net_public().as_bytes());

    // Explicit reuse of D_sign as D_net must be rejected.
    let raw = [0xcc; 32];
    let err = DeviceKeys::from_parts(
        DeviceSecret::from_bytes(&raw),
        KemSecret::from_bytes(&[0xdd; 32]),
        NetSecret::from_bytes(&raw),
    )
    .unwrap_err();
    assert_eq!(err, CryptoError::TransportKeyReusesSignKey);
}

#[test]
fn frame_wire_canonicality_header_size_and_cross_binding() {
    let rs = RecoverySecret::from_bytes([1; 32]);
    let k0 = EpochKey::from_bytes([2; 32]);
    let create = build_create_frame(&rs, [3; 32], &k0).unwrap();
    assert_eq!(create.header_bytes().len(), HEADER_LEN);
    assert_eq!(HEADER_LEN, 145);

    let wire = create.encode();
    let decoded = Frame::decode(&wire).unwrap();
    assert_eq!(decoded, create);

    // Trailing byte rejected.
    let mut trailing = wire.clone();
    trailing.push(0);
    assert_eq!(
        Frame::decode(&trailing).unwrap_err(),
        FrameError::TrailingBytes
    );

    // Truncated rejected.
    assert_eq!(
        Frame::decode(&wire[..wire.len() - 1]).unwrap_err(),
        FrameError::UnexpectedEnd
    );

    // Bad magic rejected.
    let mut bad_magic = wire.clone();
    bad_magic[3] = b'1';
    assert_eq!(Frame::decode(&bad_magic).unwrap_err(), FrameError::BadMagic);

    // Tampered signature rejected before body decode.
    let mut bad_sig = wire.clone();
    *bad_sig.last_mut().unwrap() ^= 0x80;
    assert_eq!(
        Frame::decode(&bad_sig).unwrap_err(),
        FrameError::BadSignature
    );

    // Oversized body_len rejected before allocation.
    let mut huge = wire.clone();
    huge[141..145].copy_from_slice(&((MAX_BODY_LEN as u32) + 1).to_be_bytes());
    assert!(matches!(
        Frame::decode(&huge).unwrap_err(),
        FrameError::BodyTooLarge { .. }
    ));

    // Data & Checkpoint frames: non-deterministic ciphertext + cross-vault/epoch/seq/author AAD binding.
    let vault = create.header().vault;
    let epoch0 = EpochId::from_frame_id(create.id());
    let dev = DeviceKeys::from_seed(&[9; 32]);
    let d1 = Frame::seal_data(
        dev.sign_key(),
        vault,
        0,
        FrameId::ZERO,
        epoch0,
        &k0,
        b"secret-item-1",
    )
    .unwrap();
    let d2 = Frame::seal_data(
        dev.sign_key(),
        vault,
        0,
        FrameId::ZERO,
        epoch0,
        &k0,
        b"secret-item-1",
    )
    .unwrap();
    assert_ne!(d1.body(), d2.body(), "AEAD nonces must always be fresh");
    assert_eq!(d1.open_sealed(&k0).unwrap().as_slice(), b"secret-item-1");

    // Checkpoint shell round-trip.
    let ckpt = Frame::seal_checkpoint(
        dev.sign_key(),
        vault,
        1,
        d1.id(),
        epoch0,
        &k0,
        b"checkpoint-payload",
    )
    .unwrap();
    assert_eq!(ckpt.header().kind, FrameKind::Checkpoint);
    assert_eq!(
        ckpt.open_sealed(&k0).unwrap().as_slice(),
        b"checkpoint-payload"
    );
    assert_eq!(Frame::decode(&ckpt.encode()).unwrap(), ckpt);

    // Re-signing d1's ciphertext under another vault, epoch, seq, or author must fail AEAD open.
    let other_vault = VaultId::from_bytes([0xee; 32]);
    let other_epoch = EpochId::from_bytes([0xdd; 32]);
    let other_dev = DeviceKeys::from_seed(&[10; 32]);
    for (v, auth, seq, prev, ep) in [
        (other_vault, dev.sign_key(), 0, FrameId::ZERO, epoch0),
        (vault, dev.sign_key(), 0, FrameId::ZERO, other_epoch),
        (vault, dev.sign_key(), 1, d1.id(), epoch0),
        (vault, other_dev.sign_key(), 0, FrameId::ZERO, epoch0),
    ] {
        let hdr = FrameHeader {
            kind: FrameKind::Data,
            vault: v,
            author: auth.device_id(),
            seq,
            prev,
            epoch: ep,
            body_len: d1.body().len() as u32,
        };
        let hdr_bytes = hdr.encode();
        let body_hash: [u8; 32] = blake3::hash(d1.body()).into();
        let sig = sign(auth, &frame_signature_message(&hdr_bytes, &body_hash));
        let mut forged = Vec::new();
        forged.extend_from_slice(&hdr_bytes);
        forged.extend_from_slice(d1.body());
        forged.extend_from_slice(sig.as_bytes());
        let transplanted = Frame::decode(&forged).unwrap();
        assert!(matches!(
            transplanted.open_sealed(&k0).unwrap_err(),
            FrameError::Crypto(CryptoError::DecryptFailed)
        ));
    }
}

#[test]
fn e1_atomicity_and_non_canonical_deps_rejected() {
    let rs = RecoverySecret::from_bytes([11; 32]);
    let root_sk = rs.signing_key();
    let nonce = [12; 32];
    let vault = derive_vault_id(&root_sk.device_id(), &nonce);
    let dev = DeviceKeys::from_seed(&[13; 32]);

    // Create without Rotate rejected.
    let bad_create = Frame::sign_member(
        &root_sk,
        vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps: Vec::new(),
            op: Some(MemberOp::Create {
                nonce,
                recovery_kem: rs.kem_public(),
            }),
            rotate: None,
        },
    );
    assert!(matches!(bad_create, Err(FrameError::InvalidStructure(_))));

    let k0 = EpochKey::from_bytes([14; 32]);
    let create = build_create_frame(&rs, nonce, &k0).unwrap();

    // Remove without Rotate rejected.
    let bad_remove = Frame::sign_member(
        &root_sk,
        vault,
        1,
        create.id(),
        MemberBody {
            deps: vec![create.id()],
            op: Some(MemberOp::Remove {
                device: dev.device_id(),
                last_seen_seq: None,
            }),
            rotate: None,
        },
    );
    assert!(matches!(bad_remove, Err(FrameError::InvalidStructure(_))));

    // Add WITH Rotate rejected (E1).
    let consent = sign_join_consent(&dev, &vault, &root_sk.device_id());
    let dummy_rot = Rotate {
        suite: SUITE_X25519_WRAP,
        parents: vec![EpochId::from_frame_id(create.id())],
        commit: [0; 32],
        back: Vec::new(),
        wraps: vec![(dev.device_id(), [0; WRAP_LEN])],
    };
    let bad_add = Frame::sign_member(
        &root_sk,
        vault,
        1,
        create.id(),
        MemberBody {
            deps: vec![create.id()],
            op: Some(MemberOp::Add {
                device: dev.device_id(),
                kem: dev.kem_public(),
                consent,
                rewrap: None,
            }),
            rotate: Some(dummy_rot),
        },
    );
    assert!(matches!(bad_add, Err(FrameError::InvalidStructure(_))));

    // Add with wrong-kem consent rejected.
    let mut wrong_kem_consent = sign_join_consent(&dev, &vault, &root_sk.device_id());
    wrong_kem_consent.consent = sign(
        dev.sign_key(),
        &join_consent_message(
            &vault,
            &root_sk.device_id(),
            &dev.device_id(),
            &KemPublic::from_bytes([0x99; 32]),
            &dev.net_public(),
        ),
    );
    let bad_consent = build_add_frame(
        &root_sk,
        vault,
        &view(&[&create]),
        1,
        create.id(),
        vec![create.id()],
        dev.device_id(),
        dev.kem_public(),
        wrong_kem_consent,
        None,
    );
    assert!(matches!(
        bad_consent,
        Err(EpochError::Frame(FrameError::InvalidConsent))
    ));

    // A transport key the device didn't prove it holds is rejected: another
    // device's key, with only the joiner's own signatures.
    let other = DeviceKeys::from_seed(&[0x77; 32]);
    let mut stolen_net = sign_join_consent(&dev, &vault, &root_sk.device_id());
    stolen_net.net = other.net_public();
    stolen_net.consent = sign(
        dev.sign_key(),
        &join_consent_message(
            &vault,
            &root_sk.device_id(),
            &dev.device_id(),
            &dev.kem_public(),
            &other.net_public(),
        ),
    );
    let claimed = build_add_frame(
        &root_sk,
        vault,
        &view(&[&create]),
        1,
        create.id(),
        vec![create.id()],
        dev.device_id(),
        dev.kem_public(),
        stolen_net,
        None,
    );
    assert!(matches!(
        claimed,
        Err(EpochError::Frame(FrameError::InvalidConsent))
    ));
    // Nor may an inviter swap the joiner's key after it signed.
    let mut swapped = sign_join_consent(&dev, &vault, &root_sk.device_id());
    swapped.net = other.net_public();
    swapped.net_proof = other.net_key().sign(&net_binding_message(&dev.device_id()));
    let swapped = build_add_frame(
        &root_sk,
        vault,
        &view(&[&create]),
        1,
        create.id(),
        vec![create.id()],
        dev.device_id(),
        dev.kem_public(),
        swapped,
        None,
    );
    assert!(matches!(
        swapped,
        Err(EpochError::Frame(FrameError::InvalidConsent))
    ));

    // Unsorted / duplicate deps rejected.
    let f_high = FrameId::from_bytes([0xff; 32]);
    let f_low = FrameId::from_bytes([0x01; 32]);
    let bad_deps = Frame::sign_member(
        &root_sk,
        vault,
        1,
        f_low,
        MemberBody {
            deps: vec![f_high, f_low],
            op: None,
            rotate: Some(Rotate {
                suite: SUITE_X25519_WRAP,
                parents: Vec::new(),
                commit: [0; 32],
                back: Vec::new(),
                wraps: vec![(root_sk.device_id(), [0; WRAP_LEN])],
            }),
        },
    );
    assert!(matches!(bad_deps, Err(FrameError::NotCanonical("deps"))));
}

#[test]
fn e2_bad_commit_and_graft1_recovery_repair_rewrap() {
    let rs = RecoverySecret::from_bytes([20; 32]);
    let root_sk = rs.signing_key();
    let root_id = rs.recovery_id();
    let root_kem = rs.kem_public();
    let a = DeviceKeys::from_seed(&[21; 32]);
    let b = DeviceKeys::from_seed(&[22; 32]);

    let k0 = EpochKey::from_bytes([23; 32]);
    let create = build_create_frame(&rs, [24; 32], &k0).unwrap();
    let vault = create.header().vault;
    let e0 = EpochId::from_frame_id(create.id());

    let add_a = build_add_frame(
        &root_sk,
        vault,
        &view(&[&create]),
        1,
        create.id(),
        vec![create.id()],
        a.device_id(),
        a.kem_public(),
        sign_join_consent(&a, &vault, &root_id),
        Some((e0, &k0)),
    )
    .unwrap();
    let add_b = build_add_frame(
        &root_sk,
        vault,
        &view(&[&create, &add_a]),
        2,
        add_a.id(),
        vec![add_a.id()],
        b.device_id(),
        b.kem_public(),
        sign_join_consent(&b, &vault, &root_id),
        Some((e0, &k0)),
    )
    .unwrap();

    // Malicious rotator A mints e1 with real k1 committed and wrapped to A & B, but wraps a
    // bogus key k_bogus (failing commit!) to recovery root R.
    let k1 = EpochKey::from_bytes([25; 32]);
    let k_bogus = EpochKey::from_bytes([26; 32]);
    let deps = vec![add_b.id()];
    let mut recipients = [
        (a.device_id(), a.kem_public(), &k1),
        (b.device_id(), b.kem_public(), &k1),
        (root_id, root_kem, &k_bogus),
    ];
    recipients.sort_by_key(|(id, _, _)| *id);
    let body_len = frame::member_body_wire_len(1, None, Some((1, 0, recipients.len())));
    let hdr = FrameHeader {
        kind: FrameKind::Member,
        vault,
        author: a.device_id(),
        seq: 0,
        prev: FrameId::ZERO,
        epoch: EpochId::ZERO,
        body_len: body_len as u32,
    }
    .encode();
    let aad = rotate_wrap_aad(&hdr);
    let wraps: Vec<_> = recipients
        .iter()
        .map(|(id, kem, key)| {
            let info = wrap_info(&vault, &a.device_id(), 0, id);
            (
                *id,
                wrap_epoch_key(SUITE_X25519_WRAP, kem, &info, &aad, key).unwrap(),
            )
        })
        .collect();
    let evil_rotate = Frame::sign_member(
        a.sign_key(),
        vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps,
            op: None,
            rotate: Some(Rotate {
                suite: SUITE_X25519_WRAP,
                parents: vec![e0],
                commit: k1.commit(&vault, &a.device_id(), 0),
                back: Vec::new(),
                wraps,
            }),
        },
    )
    .unwrap();
    let e1 = EpochId::from_frame_id(evil_rotate.id());

    let frames = vec![create, add_a, add_b, evil_rotate];
    let resolved = resolve(&vault, &frames, &[]);
    let graph = EpochGraph::build(vault, &frames, &resolved);

    // Recovery root rejects the forged key with BadCommit.
    let mut r_ring = EpochKeyring::new();
    let r_report = graph.unlock(&root_id, &rs.kem_secret(), &mut r_ring);
    assert!(!r_ring.contains(&e1));
    assert_eq!(r_report.bad_commits.len(), 1);
    assert_eq!(r_report.bad_commits[0].epoch, e1);

    // Honest recipient B unwraps k1 cleanly, verifies commit, and emits Graft 1 repair Rewrap to R.
    let mut b_ring = EpochKeyring::new();
    let b_report = graph.unlock(&b.device_id(), b.kem_key(), &mut b_ring);
    assert!(b_report.bad_commits.is_empty());
    let b_k1 = b_ring.get(&e1).unwrap().clone();
    assert_eq!(b_k1.as_bytes(), k1.as_bytes());

    // Repair refuses a wrong key.
    assert_eq!(
        build_recovery_repair_rewrap(
            &graph,
            &resolved,
            b.sign_key(),
            0,
            FrameId::ZERO,
            vec![frames[3].id()],
            e1,
            &k_bogus,
        )
        .unwrap_err(),
        EpochError::CommitMismatch(e1)
    );

    let repair = build_recovery_repair_rewrap(
        &graph,
        &resolved,
        b.sign_key(),
        0,
        FrameId::ZERO,
        vec![frames[3].id()],
        e1,
        &b_k1,
    )
    .unwrap();

    let mut frames_after = frames;
    frames_after.push(repair);
    let resolved2 = resolve(&vault, &frames_after, &[]);
    let graph2 = EpochGraph::build(vault, &frames_after, &resolved2);

    // Now recovery root skips the bad wrap and unwraps k1 cleanly from B's repair Rewrap!
    let mut r_ring2 = EpochKeyring::new();
    let r_report2 = graph2.unlock(&root_id, &rs.kem_secret(), &mut r_ring2);
    assert!(r_ring2.contains(&e1));
    assert_eq!(r_ring2.get(&e1).unwrap().as_bytes(), k1.as_bytes());
    assert_eq!(
        r_report2.bad_commits.len(),
        1,
        "still records the bad offer"
    );
}

#[test]
fn keyless_482_byte_fraud_proof_and_parking_rule() {
    let rs = RecoverySecret::from_bytes([30; 32]);
    let root_sk = rs.signing_key();
    let root_id = rs.recovery_id();
    let a = DeviceKeys::from_seed(&[31; 32]);
    let b = DeviceKeys::from_seed(&[32; 32]);

    let k0 = EpochKey::from_bytes([33; 32]);
    let create = build_create_frame(&rs, [34; 32], &k0).unwrap();
    let vault = create.header().vault;
    let e0 = EpochId::from_frame_id(create.id());

    let add_a = build_add_frame(
        &root_sk,
        vault,
        &view(&[&create]),
        1,
        create.id(),
        vec![create.id()],
        a.device_id(),
        a.kem_public(),
        sign_join_consent(&a, &vault, &root_id),
        Some((e0, &k0)),
    )
    .unwrap();
    let add_b = build_add_frame(
        &root_sk,
        vault,
        &view(&[&create, &add_a]),
        2,
        add_a.id(),
        vec![add_a.id()],
        b.device_id(),
        b.kem_public(),
        sign_join_consent(&b, &vault, &root_id),
        Some((e0, &k0)),
    )
    .unwrap();

    // Data equivocation produces an exact 482-byte keyless FraudProof.
    let d_a = Frame::seal_data(a.sign_key(), vault, 0, FrameId::ZERO, e0, &k0, b"v1").unwrap();
    let d_b = Frame::seal_data(a.sign_key(), vault, 0, FrameId::ZERO, e0, &k0, b"v2").unwrap();
    let proof = FraudProof::from_frames(&d_a, &d_b).unwrap();
    let raw = proof.encode();
    assert_eq!(raw.len(), 482);
    assert_eq!(FraudProof::decode(&raw).unwrap(), proof);
    assert_eq!(
        FraudProof::from_frames(&d_a, &d_a).unwrap_err(),
        FraudError::SameFrame
    );

    // Swapped witness order rejected on decode.
    let mut swapped = [0u8; FRAUD_PROOF_LEN];
    swapped[..WITNESS_LEN].copy_from_slice(&raw[WITNESS_LEN..]);
    swapped[WITNESS_LEN..].copy_from_slice(&raw[..WITNESS_LEN]);
    assert_eq!(
        FraudProof::decode(&swapped).unwrap_err(),
        FraudError::NotCanonical
    );

    // Parking rule: B removes A (e1), then stolen senior A back-dates Remove(B) (e2).
    let mut b_ring = EpochKeyring::new();
    b_ring.insert(e0, k0.clone());
    let k_b = EpochKey::from_bytes([35; 32]);
    let mut rec_b = BTreeMap::new();
    rec_b.insert(b.device_id(), b.kem_public());
    rec_b.insert(root_id, rs.kem_public());
    let rem_a = build_remove_frame(
        b.sign_key(),
        vault,
        &view(&[&create, &add_a, &add_b]),
        0,
        FrameId::ZERO,
        vec![add_b.id()],
        a.device_id(),
        None,
        &k_b,
        vec![e0],
        &b_ring,
        &rec_b,
    )
    .unwrap();
    let e_b = EpochId::from_frame_id(rem_a.id());
    b_ring.insert(e_b, k_b);

    // B saw A removed, so B records A in previously_removed.
    let mut previously_removed = BTreeSet::new();
    previously_removed.insert(a.device_id());

    // Stolen senior A back-dates Remove(B) using old parent add_b (ignoring rem_a).
    let k_a = EpochKey::from_bytes([36; 32]);
    let mut rec_a = BTreeMap::new();
    rec_a.insert(a.device_id(), a.kem_public());
    rec_a.insert(root_id, rs.kem_public());
    let rem_b = build_remove_frame(
        a.sign_key(),
        vault,
        &view(&[&create, &add_a, &add_b]),
        0,
        FrameId::ZERO,
        vec![add_b.id()],
        b.device_id(),
        None,
        &k_a,
        vec![e0],
        &b_ring,
        &rec_a,
    )
    .unwrap();

    let frames = vec![create, add_a, add_b, rem_a, rem_b];
    let resolved = resolve(&vault, &frames, &[]);
    let graph = EpochGraph::build(vault, &frames, &resolved);

    // Senior A wins resolution, BUT B's parking rule fires and refuses to adopt A's epoch!
    assert!(resolved.is_active_device(&a.device_id()));
    let decision = graph.select_write_epoch_with_parking(
        &resolved,
        &b_ring,
        &BTreeSet::new(),
        &previously_removed,
        Some(e_b),
    );
    match decision {
        WriteEpochDecision::Parked {
            current_epoch,
            reasons,
        } => {
            assert_eq!(current_epoch, Some(e_b));
            assert!(reasons.contains(&ParkingReason::ReinstatedRemovedDevice {
                device: a.device_id()
            }));
            assert!(
                reasons
                    .iter()
                    .any(|r| matches!(r, ParkingReason::MutualRemoval { .. }))
            );
        }
        other => panic!("expected Parked, got {other:?}"),
    }
}

#[test]
fn membership_rejects_non_contributory_kem_keys() {
    let p = model::pool();
    let root = &p.roots[0];
    let device = &p.devices[0];
    let create = build_create_frame(root, p.nonce, &EpochKey::from_bytes([1; 32])).unwrap();
    for bytes in LOW_ORDER_X25519_POINTS {
        let kem = KemPublic::from_bytes(bytes);
        let mut consent = sign_join_consent(device, &p.vault, &root.recovery_id());
        consent.consent = sign(
            device.sign_key(),
            &join_consent_message(
                &p.vault,
                &root.recovery_id(),
                &device.device_id(),
                &kem,
                &consent.net,
            ),
        );
        assert!(consent.verify(&p.vault, &root.recovery_id(), &device.device_id(), &kem));
        let body = MemberBody {
            deps: vec![create.id()],
            op: Some(MemberOp::Add {
                device: device.device_id(),
                kem,
                consent,
                rewrap: None,
            }),
            rotate: None,
        };
        assert!(Frame::sign_member(&p.root_sks[0], p.vault, 1, create.id(), body).is_err());
        let mut body = create.member_body().unwrap().clone();
        if let Some(MemberOp::Create { recovery_kem, .. }) = &mut body.op {
            *recovery_kem = kem;
        }
        assert!(Frame::sign_member(&p.root_sks[0], p.vault, 0, FrameId::ZERO, body).is_err());
        let body = MemberBody {
            deps: vec![create.id()],
            op: Some(MemberOp::RotateRecovery {
                new: p.roots[1].recovery_id(),
                new_kem: kem,
                consent: sign_rotate_recovery_consent(
                    &p.root_sks[1],
                    &p.vault,
                    &root.recovery_id(),
                    &kem,
                ),
            }),
            rotate: Some(model::dummy_rotate(vec![], p.roots[1].recovery_id(), 2)),
        };
        assert!(Frame::sign_member(&p.root_sks[0], p.vault, 1, create.id(), body).is_err());
    }
}
