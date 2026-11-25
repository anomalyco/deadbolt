//! Multi-device epoch state machine tests and `DEADBOLT_MEMBERSHIP_CASES` property suite
//! proving invariants I1 (clean-tip convergence), I2 (decryptability), and I3 (cryptographic revocation).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use proptest::prelude::*;

use crate::id::{DeviceId, DeviceSecret};

use super::super::*;

pub(super) struct EpochPool {
    pub(super) roots: Vec<RecoverySecret>,
    pub(super) root_sks: Vec<DeviceSecret>,
    pub(super) root_kems: Vec<KemSecret>,
    pub(super) devices: Vec<DeviceKeys>,
    pub(super) nonce: [u8; 32],
}

pub(super) fn pool() -> &'static EpochPool {
    static POOL: OnceLock<EpochPool> = OnceLock::new();
    POOL.get_or_init(|| {
        let roots: Vec<_> = (0u8..2)
            .map(|i| RecoverySecret::from_bytes([40 + i; 32]))
            .collect();
        let root_sks: Vec<_> = roots.iter().map(RecoverySecret::signing_key).collect();
        let root_kems: Vec<_> = roots.iter().map(RecoverySecret::kem_secret).collect();
        let devices: Vec<_> = (0u8..5)
            .map(|i| DeviceKeys::from_seed(&[50 + i; 32]))
            .collect();
        EpochPool {
            roots,
            root_sks,
            root_kems,
            devices,
            nonce: [0x33; 32],
        }
    })
}

pub(super) fn kem_map(resolved: &ResolvedMembership) -> BTreeMap<DeviceId, KemPublic> {
    resolved
        .eligible_recipients()
        .into_iter()
        .filter_map(|id| resolved.kem_of(&id).map(|k| (id, k)))
        .collect()
}

pub(super) fn next_member_slot(frames: &[Frame], author: DeviceId) -> (u64, FrameId) {
    frames
        .iter()
        .filter(|f| f.header().kind == FrameKind::Member && f.header().author == author)
        .max_by_key(|f| f.header().seq)
        .map_or((0, FrameId::ZERO), |f| (f.header().seq + 1, f.id()))
}

fn next_data_slot(frames: &[Frame], author: DeviceId) -> (u64, FrameId) {
    frames
        .iter()
        .filter(|f| f.header().kind != FrameKind::Member && f.header().author == author)
        .max_by_key(|f| f.header().seq)
        .map_or((0, FrameId::ZERO), |f| (f.header().seq + 1, f.id()))
}

pub(super) fn member_heads(frames: &[Frame]) -> Vec<FrameId> {
    let mut referenced = BTreeSet::new();
    let mut all = BTreeSet::new();
    for f in frames {
        if let Some(body) = f.member_body() {
            all.insert(f.id());
            for &d in &body.deps {
                referenced.insert(d);
            }
        }
    }
    all.difference(&referenced).copied().collect()
}

pub(super) fn all_deps_with_prev(mut deps: Vec<FrameId>, prev: FrameId) -> Vec<FrameId> {
    if !prev.is_zero() {
        deps.push(prev);
    }
    deps.sort();
    deps.dedup();
    deps
}

/// Computes causal ancestors (inclusive) of every Member frame by FrameId.
fn member_causal_ancestors(frames: &[Frame]) -> BTreeMap<FrameId, BTreeSet<FrameId>> {
    let by_id: BTreeMap<FrameId, &Frame> = frames
        .iter()
        .filter(|f| f.header().kind == FrameKind::Member)
        .map(|f| (f.id(), f))
        .collect();
    let mut memo: BTreeMap<FrameId, BTreeSet<FrameId>> = BTreeMap::new();
    loop {
        let mut progress = false;
        for (&id, &f) in &by_id {
            if memo.contains_key(&id) {
                continue;
            }
            let body = f.member_body().unwrap();
            if body.deps.iter().all(|d| memo.contains_key(d)) {
                let mut set = BTreeSet::new();
                set.insert(id);
                for d in &body.deps {
                    set.extend(&memo[d]);
                }
                memo.insert(id, set);
                progress = true;
            }
        }
        if !progress {
            break;
        }
    }
    memo
}

// ============================================================================
// Named tests for I1, I2, I3
// ============================================================================

#[derive(Debug, Clone)]
struct EpochAction {
    actor: u8,
    target: u8,
    kind: u8,
    view_mask: u8,
}

fn action_strategy() -> impl Strategy<Value = EpochAction> {
    (0u8..5, 0u8..5, 0u8..8, 0u8..16).prop_map(|(actor, target, kind, view_mask)| EpochAction {
        actor,
        target,
        kind,
        view_mask,
    })
}

/// Selects a causally closed subset of `frames` (simulating a partitioned/offline peer view).
fn partial_view(frames: &[Frame], mask: u8) -> Vec<Frame> {
    // Always include bootstrap prefix frames[0..=3] so initial devices exist.
    let mut included = BTreeSet::new();
    for f in frames.iter().take(4) {
        included.insert(f.id());
    }
    for (i, f) in frames.iter().enumerate().skip(4) {
        if (mask >> (i % 4)) & 1 == 1 {
            let body = f.member_body().unwrap();
            if body.deps.iter().all(|d| included.contains(d)) {
                included.insert(f.id());
            }
        }
    }
    frames
        .iter()
        .filter(|f| included.contains(&f.id()))
        .cloned()
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: super::membership_cases(),
        ..ProptestConfig::default()
    })]

    #[test]
    fn prop_i1_i2_i3_epochs_converge_decrypt_and_revoke(
        actions in prop::collection::vec(action_strategy(), 1..=7),
    ) {
        let p = pool();
        let (r0, r1) = (&p.roots[0], &p.roots[1]);
        let (r0_sk, r1_sk) = (&p.root_sks[0], &p.root_sks[1]);
        let (r0_kem, r1_kem) = (&p.root_kems[0], &p.root_kems[1]);

        let k0 = EpochKey::from_bytes([0x61; 32]);
        let create = build_create_frame(r0, p.nonce, &k0).unwrap();
        let vault = create.header().vault;
        let e0 = EpochId::from_frame_id(create.id());

        // Bootstrap 3 initial devices (0, 1, 2) so concurrent offline removals & adds happen immediately.
        let mut m_frames = vec![create];
        for dev in p.devices.iter().take(3) {
            let (seq, prev) = next_member_slot(&m_frames, r0.recovery_id());
            let deps = all_deps_with_prev(member_heads(&m_frames), prev);
            let add = build_add_frame(
                r0_sk,
                vault,
                seq,
                prev,
                deps,
                dev.device_id(),
                dev.kem_public(),
                sign_join_consent(dev.sign_key(), &vault, &r0.recovery_id(), &dev.kem_public()),
                Some((e0, &k0)),
            )
            .unwrap();
            m_frames.push(add);
        }

        // Data frames written during the scenario: (Frame, expected plaintext).
        let mut data_frames: Vec<(Frame, Vec<u8>)> = Vec::new();
        let mut key_nonce = 1u8;
        let mut root_rotated = false;

        for action in &actions {
            key_nonce = key_nonce.wrapping_add(1).max(1);
            // Partitioned view for this actor (always includes author's own prior Member frames).
            let mut view = partial_view(&m_frames, action.view_mask);
            let actor_dev = &p.devices[(action.actor as usize) % p.devices.len()];
            // Ensure actor sees all its own prior Member frames (no accidental self-fork here).
            let view_ids: BTreeSet<FrameId> = view.iter().map(Frame::id).collect();
            let mut added_own = false;
            for f in &m_frames {
                if f.header().author == actor_dev.device_id() && !view_ids.contains(&f.id()) {
                    // Fall back to full view if actor's own frame depended on unincluded frames.
                    added_own = true;
                    break;
                }
            }
            if added_own {
                view = m_frames.clone();
            }

            let res_view = resolve(&vault, &view, &[]);
            let graph_view = EpochGraph::build(vault, &view, &res_view);

            match action.kind % 8 {
                // Honest Add of a not-yet-active, not-removed device.
                0..=1 => {
                    let target_dev = &p.devices[(action.target as usize) % p.devices.len()];
                    if !res_view.is_active_device(&actor_dev.device_id())
                        || res_view.is_active_device(&target_dev.device_id())
                        || res_view.removed.contains_key(&target_dev.device_id())
                    {
                        continue;
                    }
                    let mut ring = EpochKeyring::new();
                    graph_view.unlock(&actor_dev.device_id(), actor_dev.kem_key(), &mut ring);
                    let wrap_epoch = match graph_view.select_write_epoch(&res_view, &ring, &BTreeSet::new()) {
                        WriteEpochDecision::Use(ep) => ring.get(&ep).map(|k| (ep, k.clone())),
                        _ => ring.epoch_ids().into_iter().next().and_then(|ep| ring.get(&ep).map(|k| (ep, k.clone()))),
                    };
                    let (seq, prev) = next_member_slot(&m_frames, actor_dev.device_id());
                    let deps = all_deps_with_prev(member_heads(&view), prev);
                    let add = build_add_frame(
                        actor_dev.sign_key(),
                        vault,
                        seq,
                        prev,
                        deps,
                        target_dev.device_id(),
                        target_dev.kem_public(),
                        sign_join_consent(
                            target_dev.sign_key(),
                            &vault,
                            &actor_dev.device_id(),
                            &target_dev.kem_public(),
                        ),
                        wrap_epoch.as_ref().map(|(e, k)| (*e, k)),
                    )
                    .unwrap();
                    m_frames.push(add);
                }
                // Honest Remove (only if at least 2 active devices remain in view).
                2..=4 => {
                    let target_dev = &p.devices[(action.target as usize) % p.devices.len()];
                    if !res_view.is_active_device(&actor_dev.device_id())
                        || !res_view.is_active_device(&target_dev.device_id())
                        || actor_dev.device_id() == target_dev.device_id()
                        || res_view.devices.len() <= 2
                    {
                        continue;
                    }
                    let mut ring = EpochKeyring::new();
                    graph_view.unlock(&actor_dev.device_id(), actor_dev.kem_key(), &mut ring);
                    if ring.is_empty() {
                        continue;
                    }
                    let mut recipients = kem_map(&res_view);
                    recipients.remove(&target_dev.device_id());
                    let parents = graph_view.maximal_epochs_in(&ring.epoch_ids());
                    let new_key = EpochKey::from_bytes([key_nonce.wrapping_mul(17); 32]);
                    let (seq, prev) = next_member_slot(&m_frames, actor_dev.device_id());
                    let deps = all_deps_with_prev(member_heads(&view), prev);
                    let last_seen = data_frames
                        .iter()
                        .filter(|(df, _)| df.header().author == target_dev.device_id())
                        .map(|(df, _)| df.header().seq)
                        .max();
                    let rem = build_remove_frame(
                        actor_dev.sign_key(),
                        vault,
                        seq,
                        prev,
                        deps,
                        target_dev.device_id(),
                        last_seen,
                        &new_key,
                        parents,
                        &ring,
                        &recipients,
                    )
                    .unwrap();
                    m_frames.push(rem);
                }
                // Offline Data write under actor's current unlocked write epoch.
                5..=6 => {
                    if !res_view.is_active_device(&actor_dev.device_id()) {
                        continue;
                    }
                    let mut ring = EpochKeyring::new();
                    graph_view.unlock(&actor_dev.device_id(), actor_dev.kem_key(), &mut ring);
                    let ep = match graph_view.select_write_epoch(&res_view, &ring, &BTreeSet::new()) {
                        WriteEpochDecision::Use(e) => e,
                        _ => match ring.epoch_ids().into_iter().next() {
                            Some(e) => e,
                            None => continue,
                        },
                    };
                    let key = ring.get(&ep).unwrap();
                    let (d_seq, d_prev) = next_data_slot(
                        &data_frames.iter().map(|(f, _)| f.clone()).collect::<Vec<_>>(),
                        actor_dev.device_id(),
                    );
                    let pt = vec![action.actor, action.kind, key_nonce];
                    let df = Frame::seal_data(
                        actor_dev.sign_key(),
                        vault,
                        d_seq,
                        d_prev,
                        ep,
                        key,
                        &pt,
                    )
                    .unwrap();
                    data_frames.push((df, pt));
                }
                // RotateRecovery R0 -> R1 once.
                _ => {
                    if root_rotated {
                        continue;
                    }
                    let full_res = resolve(&vault, &m_frames, &[]);
                    if full_res.active_recovery != Some(r0.recovery_id()) {
                        continue;
                    }
                    let full_graph = EpochGraph::build(vault, &m_frames, &full_res);
                    let mut r0_ring = EpochKeyring::new();
                    full_graph.unlock(&r0.recovery_id(), r0_kem, &mut r0_ring);
                    if r0_ring.is_empty() {
                        continue;
                    }
                    let mut recipients = kem_map(&full_res);
                    recipients.remove(&r0.recovery_id());
                    recipients.insert(r1.recovery_id(), r1.kem_public());
                    let parents = full_graph.maximal_epochs_in(&r0_ring.epoch_ids());
                    let new_key = EpochKey::from_bytes([key_nonce.wrapping_mul(29); 32]);
                    let (seq, prev) = next_member_slot(&m_frames, r0.recovery_id());
                    let deps = all_deps_with_prev(member_heads(&m_frames), prev);
                    let rot = build_rotate_recovery_frame(
                        r0_sk,
                        vault,
                        seq,
                        prev,
                        deps,
                        r1.recovery_id(),
                        r1.kem_public(),
                        sign_rotate_recovery_consent(r1_sk, &vault, &r0.recovery_id(), &r1.kem_public()),
                        &new_key,
                        parents,
                        &r0_ring,
                        &recipients,
                    )
                    .unwrap();
                    m_frames.push(rot);
                    root_rotated = true;
                }
            }
        }

        // Quiescence phase 1: if no clean tip exists (e.g. concurrent offline removals),
        // active members mint clean-tip Rotate(s) (even two concurrently when possible!).
        let res_q1 = resolve(&vault, &m_frames, &[]);
        let g_q1 = EpochGraph::build(vault, &m_frames, &res_q1);
        if g_q1.clean_tips(&res_q1).is_empty() {
            let recipients = kem_map(&res_q1);
            let mut minted = 0usize;
            let snapshot_heads = member_heads(&m_frames);
            for dev in &p.devices {
                if !res_q1.is_active_device(&dev.device_id()) {
                    continue;
                }
                let mut ring = EpochKeyring::new();
                g_q1.unlock(&dev.device_id(), dev.kem_key(), &mut ring);
                if ring.is_empty() {
                    continue;
                }
                let WriteEpochDecision::MintRotate { parents } =
                    g_q1.select_write_epoch(&res_q1, &ring, &BTreeSet::new())
                else {
                    continue;
                };
                let (seq, prev) = next_member_slot(&m_frames, dev.device_id());
                let k_merge = EpochKey::from_bytes([0xd0 + (minted as u8); 32]);
                let frame = build_standalone_rotate_frame(
                    dev.sign_key(),
                    vault,
                    seq,
                    prev,
                    all_deps_with_prev(snapshot_heads.clone(), prev),
                    &k_merge,
                    parents,
                    &ring,
                    &recipients,
                )
                .unwrap();
                m_frames.push(frame);
                minted += 1;
                // Mint up to 2 concurrent clean-tip merges to stress min(EpochId) convergence.
                if minted >= 2 {
                    break;
                }
            }
        }

        // Quiescence phase 2: run E6 reader duty for every counted data epoch + clean tip.
        let res_q2 = resolve(&vault, &m_frames, &[]);
        let counted_epochs: BTreeSet<EpochId> = data_frames
            .iter()
            .filter(|(df, _)| res_q2.counted_through(&df.header().author, df.header().seq) == Some(df.header().seq))
            .map(|(df, _)| df.header().epoch)
            .collect();

        for _round in 0..2 {
            let res_now = resolve(&vault, &m_frames, &[]);
            let g_now = EpochGraph::build(vault, &m_frames, &res_now);
            let mut emitted = false;
            for dev in &p.devices {
                if !res_now.is_active_device(&dev.device_id()) {
                    continue;
                }
                let mut ring = EpochKeyring::new();
                g_now.unlock(&dev.device_id(), dev.kem_key(), &mut ring);
                let plan = g_now.needed_rewraps(&ring, &res_now, &counted_epochs);
                for (ep, missing) in plan {
                    let mut targets = BTreeMap::new();
                    for id in missing {
                        if let Some(kem) = res_now.kem_of(&id) {
                            targets.insert(id, kem);
                        }
                    }
                    if targets.is_empty() {
                        continue;
                    }
                    let (seq, prev) = next_member_slot(&m_frames, dev.device_id());
                    let rw = build_rewrap_frame(
                        dev.sign_key(),
                        vault,
                        seq,
                        prev,
                        all_deps_with_prev(member_heads(&m_frames), prev),
                        ep,
                        ring.get(&ep).unwrap(),
                        &targets,
                    )
                    .unwrap();
                    m_frames.push(rw);
                    emitted = true;
                }
            }
            if !emitted {
                break;
            }
        }

        // ====================================================================
        // Assert Invariants I1, I2, I3 at quiescence!
        // ====================================================================
        let res_final = resolve(&vault, &m_frames, &[]);
        let g_final = EpochGraph::build(vault, &m_frames, &res_final);
        let clean_tips = g_final.clean_tips(&res_final);
        prop_assert!(!clean_tips.is_empty(), "I1: must have at least one clean tip at quiescence");
        let expected_tip = clean_tips[0];
        let allowed = res_final.eligible_recipients();
        prop_assert!(
            g_final.get(&expected_tip).unwrap().recipients.is_subset(&allowed),
            "I1: selected write epoch must be clean"
        );

        // Active principals (active devices + active recovery root).
        let mut active_keys: Vec<(DeviceId, &KemSecret)> = p
            .devices
            .iter()
            .filter(|d| res_final.is_active_device(&d.device_id()))
            .map(|d| (d.device_id(), d.kem_key()))
            .collect();
        if res_final.active_recovery == Some(r0.recovery_id()) {
            active_keys.push((r0.recovery_id(), r0_kem));
        } else if res_final.active_recovery == Some(r1.recovery_id()) {
            active_keys.push((r1.recovery_id(), r1_kem));
        }

        for (id, kem) in active_keys {
            // Start from ZERO local keyring (proves zero-state recovery & 60-day offline catch-up!).
            let mut ring = EpochKeyring::new();
            let report = g_final.unlock(&id, kem, &mut ring);
            prop_assert!(report.bad_commits.is_empty());

            // I1: Every honest active principal selects the exact same clean write epoch.
            prop_assert_eq!(
                g_final.select_write_epoch(&res_final, &ring, &BTreeSet::new()),
                WriteEpochDecision::Use(expected_tip),
                "I1: principal diverged on clean write epoch"
            );

            // I2: Every counted Data frame is decryptable to its exact plaintext.
            for (df, expected_pt) in &data_frames {
                if res_final.counted_through(&df.header().author, df.header().seq) == Some(df.header().seq) {
                    let ep = df.header().epoch;
                    let key = ring.get(&ep);
                    prop_assert!(key.is_some(), "I2: active member missing key for counted epoch {ep}");
                    let opened = df.open_sealed(key.unwrap()).unwrap();
                    prop_assert_eq!(opened.as_slice(), expected_pt.as_slice());
                }
            }
        }

        // I3: Cryptographic revocation — a removed device CANNOT unwrap any epoch minted by a
        // frame that causally observed a winning removal of that device.
        let ancestors = member_causal_ancestors(&m_frames);
        for dev in &p.devices {
            let dev_id = dev.device_id();
            if !res_final.removed.contains_key(&dev_id) {
                continue;
            }
            let winning_removals: BTreeSet<FrameId> = m_frames
                .iter()
                .filter(|f| {
                    res_final.authorized_frames.contains(&f.id())
                        && matches!(
                            f.member_body().and_then(|b| b.op.as_ref()),
                            Some(MemberOp::Remove { device, .. }) if *device == dev_id
                        )
                })
                .map(Frame::id)
                .collect();

            let mut removed_ring = EpochKeyring::new();
            g_final.unlock(&dev_id, dev.kem_key(), &mut removed_ring);

            for f in &m_frames {
                if f.member_body().is_some_and(|b| b.rotate.is_some()) {
                    let saw_removal = ancestors
                        .get(&f.id())
                        .is_some_and(|anc| anc.iter().any(|a| winning_removals.contains(a)));
                    if saw_removal {
                        let ep = EpochId::from_frame_id(f.id());
                        prop_assert!(
                            !removed_ring.contains(&ep),
                            "I3 VIOLATION: removed device unwrapped post-removal epoch {ep}"
                        );
                    }
                }
            }
            // Also removed device must NEVER hold the final clean write epoch!
            prop_assert!(
                !removed_ring.contains(&expected_tip),
                "I3 VIOLATION: removed device unwrapped final clean tip"
            );
        }
    }
}
