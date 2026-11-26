//! Regression tests for cryptographic revocation (I3) from the model-based bug hunt: the epoch of an
//! unplaced `Remove` is never rewrapped, a removed device cannot be re-added through an inline
//! `Rewrap`, and builders refuse to cite frames their view could not place.

use std::collections::BTreeMap;

use super::super::*;
use super::epochs::{kem_map, pool};
use super::model::assert_matches_ref;

pub(super) struct Vault {
    pub(super) vault: crate::id::VaultId,
    pub(super) e0: EpochId,
    pub(super) k0: EpochKey,
    pub(super) frames: Vec<Frame>,
}

/// Genesis plus root-added devices `a`, `b`, `c` (each wrapped `e0` inline).
pub(super) fn vault_with(devices: &[&DeviceKeys]) -> Vault {
    let p = pool();
    let r0 = &p.roots[0];
    let k0 = EpochKey::from_bytes([0x71; 32]);
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
            sign_join_consent(dev.sign_key(), &vault, &r0.recovery_id(), &dev.kem_public()),
            Some((e0, &k0)),
        )
        .unwrap();
        frames.push(add);
    }
    Vault {
        vault,
        e0,
        k0,
        frames,
    }
}

/// Bug hunt #1: `A` adds `D`, then removes `C` with `Add(D)` among its deps, and writes under the
/// new epoch. `B` sees the `Remove(C)` and the data but not `Add(D)`, so it cannot place the
/// removal and still counts `C` as a member. Its reader duty must not rewrap the removal's
/// epoch, least of all to `C`.
#[test]
fn reader_duty_never_rewraps_an_unplaced_removal_epoch() {
    let p = pool();
    let (a, b, c, d) = (&p.devices[0], &p.devices[1], &p.devices[2], &p.devices[3]);
    let mut v = vault_with(&[a, b, c]);
    let vault = v.vault;
    let heads = vec![v.frames.last().unwrap().id()];
    let add_d = build_add_frame(
        a.sign_key(),
        vault,
        &resolve(&vault, &v.frames, &[]),
        0,
        FrameId::ZERO,
        heads,
        d.device_id(),
        d.kem_public(),
        sign_join_consent(d.sign_key(), &vault, &a.device_id(), &d.kem_public()),
        Some((v.e0, &v.k0)),
    )
    .unwrap();
    let mut a_view = v.frames.clone();
    a_view.push(add_d.clone());
    let res_a = resolve(&vault, &a_view, &[]);
    let mut recipients = kem_map(&res_a);
    recipients.remove(&c.device_id());
    let mut ring = EpochKeyring::new();
    ring.insert(v.e0, v.k0.clone());
    let k1 = EpochKey::from_bytes([0x72; 32]);
    let rem_c = build_remove_frame(
        a.sign_key(),
        vault,
        &res_a,
        1,
        add_d.id(),
        vec![add_d.id()],
        c.device_id(),
        None,
        &k1,
        vec![v.e0],
        &ring,
        &recipients,
    )
    .unwrap();
    let e1 = EpochId::from_frame_id(rem_c.id());
    let data = Frame::seal_data(a.sign_key(), vault, 0, FrameId::ZERO, e1, &k1, b"x").unwrap();

    // B's view: the removal and A's data, but not Add(D).
    v.frames.push(rem_c.clone());
    let res_b = resolve(&vault, &v.frames, &[]);
    assert!(res_b.unplaced_frames.contains(&rem_c.id()));
    assert!(!res_b.dag_frames.contains(&rem_c.id()));
    assert!(res_b.is_active_device(&c.device_id()));
    let graph_b = EpochGraph::build(vault, &v.frames, &res_b);
    assert!(!graph_b.get(&e1).unwrap().authorized);
    let mut b_ring = EpochKeyring::new();
    graph_b.unlock(&b.device_id(), b.kem_key(), &mut b_ring);
    assert!(b_ring.contains(&e1), "B was wrapped the removal epoch");
    assert_eq!(data.header().epoch, e1);

    let counted = [e1].into();
    let plan = graph_b.needed_rewraps(&b_ring, &res_b, &counted);
    assert!(
        plan.iter().all(|(epoch, _)| *epoch != e1),
        "the unplaced removal's epoch must never be rewrapped: {plan:?}"
    );
    assert_eq!(plan, Vec::new(), "every member already reaches e0");
}

/// Bug hunt #3: re-adding a removed device must not hand it the post-removal epoch through the
/// `Add`'s inline `Rewrap`. The builder refuses; a forged `Add` is never authorized.
#[test]
fn a_removed_device_cannot_be_readded_with_an_inline_rewrap() {
    let p = pool();
    let (a, c) = (&p.devices[0], &p.devices[2]);
    let mut v = vault_with(&[a, c]);
    let vault = v.vault;
    let res = resolve(&vault, &v.frames, &[]);
    let mut recipients = kem_map(&res);
    recipients.remove(&c.device_id());
    let mut ring = EpochKeyring::new();
    ring.insert(v.e0, v.k0.clone());
    let k1 = EpochKey::from_bytes([0x73; 32]);
    let last = v.frames.last().unwrap().id();
    let rem_c = build_remove_frame(
        a.sign_key(),
        vault,
        &res,
        0,
        FrameId::ZERO,
        vec![last],
        c.device_id(),
        None,
        &k1,
        vec![v.e0],
        &ring,
        &recipients,
    )
    .unwrap();
    let e1 = EpochId::from_frame_id(rem_c.id());
    v.frames.push(rem_c.clone());
    let after = resolve(&vault, &v.frames, &[]);
    let consent = sign_join_consent(c.sign_key(), &vault, &a.device_id(), &c.kem_public());
    let readd = |resolved: &ResolvedMembership| {
        build_add_frame(
            a.sign_key(),
            vault,
            resolved,
            1,
            rem_c.id(),
            vec![rem_c.id()],
            c.device_id(),
            c.kem_public(),
            consent,
            Some((e1, &k1)),
        )
    };
    assert_eq!(
        readd(&after).unwrap_err(),
        EpochError::CannotAdd(c.device_id())
    );

    // A buggy or malicious builder that forgot the removal still cannot leak e1.
    let mut lax = after.clone();
    lax.removed.clear();
    let forged = readd(&lax).unwrap();
    v.frames.push(forged.clone());
    let res = assert_matches_ref(vault, &v.frames, &[]);
    assert!(!res.authorized_frames.contains(&forged.id()));
    assert!(!res.is_active_device(&c.device_id()));
    assert!(res.removed.contains_key(&c.device_id()));
    let graph = EpochGraph::build(vault, &v.frames, &res);
    let mut c_ring = EpochKeyring::new();
    graph.unlock(&c.device_id(), c.kem_key(), &mut c_ring);
    assert!(c_ring.contains(&v.e0));
    assert!(!c_ring.contains(&e1), "I3: removed device unwrapped e1");
}

/// Bug hunt #4: `resolve` reports frames it could not place, and every builder refuses a `dep`
/// or `prev` outside the view's placed DAG, or a wrap set that is not exactly the view's
/// eligible recipients.
#[test]
fn builders_refuse_unplaced_deps_and_wrong_wrap_sets() {
    let p = pool();
    let (a, b) = (&p.devices[0], &p.devices[1]);
    let v = vault_with(&[a, b]);
    let vault = v.vault;
    let last = v.frames.last().unwrap().id();
    let ghost = FrameId::from_bytes([0x5a; 32]);

    // A frame naming a dep nobody has is held but unplaced.
    let orphan = Frame::sign_member(
        a.sign_key(),
        vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps: vec![ghost],
            op: None,
            rotate: Some(super::model::dummy_rotate(vec![v.e0], a.device_id(), 3)),
        },
    )
    .unwrap();
    let mut held = v.frames.clone();
    held.push(orphan.clone());
    let res = resolve(&vault, &held, &[]);
    assert_eq!(res.unplaced_frames, [orphan.id()].into());
    assert!(!res.dag_frames.contains(&orphan.id()));
    assert!(res.dag_frames.contains(&last));

    let mut ring = EpochKeyring::new();
    ring.insert(v.e0, v.k0.clone());
    let all = kem_map(&res);
    let k = EpochKey::from_bytes([0x74; 32]);
    let rotate = |prev: FrameId, deps: Vec<FrameId>, to: &BTreeMap<_, _>| {
        build_standalone_rotate_frame(
            b.sign_key(),
            vault,
            &res,
            u64::from(!prev.is_zero()),
            prev,
            deps,
            &k,
            vec![v.e0],
            &ring,
            to,
        )
    };
    assert_eq!(
        rotate(FrameId::ZERO, vec![orphan.id()], &all).unwrap_err(),
        EpochError::UnplacedDep(orphan.id())
    );
    assert_eq!(
        rotate(FrameId::ZERO, vec![last, ghost], &all).unwrap_err(),
        EpochError::UnplacedDep(ghost)
    );
    assert_eq!(
        rotate(ghost, vec![last], &all).unwrap_err(),
        EpochError::UnplacedDep(ghost)
    );
    let mut missing_a = all.clone();
    missing_a.remove(&a.device_id());
    assert_eq!(
        rotate(FrameId::ZERO, vec![last], &missing_a).unwrap_err(),
        EpochError::RecipientsMismatch
    );
    assert!(rotate(FrameId::ZERO, vec![last], &all).is_ok());

    let outsider = &p.devices[4];
    let to_outsider = [(outsider.device_id(), outsider.kem_public())].into();
    assert_eq!(
        build_rewrap_frame(
            b.sign_key(),
            vault,
            &res,
            0,
            FrameId::ZERO,
            vec![last],
            v.e0,
            &v.k0,
            &to_outsider,
        )
        .unwrap_err(),
        EpochError::IneligibleRecipient(outsider.device_id())
    );
}
