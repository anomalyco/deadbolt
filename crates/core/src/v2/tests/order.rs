//! Randomized `DEADBOLT_MEMBERSHIP_CASES` property suite proving invariant I4
//! against the independent brute-force exponential reference model.

use std::collections::BTreeMap;

use proptest::prelude::*;

use crate::id::{DeviceId, DeviceSecret, VaultId};

use super::super::*;
use super::model::{assert_matches_ref, dummy_rotate, pool, shuffled};
use super::view;

#[derive(Debug, Clone)]
struct Step {
    actor: u8,
    target: u8,
    kind: u8,
    branch: u8,
    cutoff: u8,
}

fn step_strategy() -> impl Strategy<Value = Step> {
    (0u8..8, 0u8..8, 0u8..12, 0u8..32, 0u8..4).prop_map(|(actor, target, kind, branch, cutoff)| {
        Step {
            actor,
            target,
            kind,
            branch,
            cutoff,
        }
    })
}

fn build_random_history(steps: &[Step]) -> (VaultId, Vec<Frame>, Vec<FraudProof>) {
    let p = pool();
    let vault = p.vault;
    let k0 = EpochKey::from_bytes([0x55; 32]);
    let create = build_create_frame(&p.roots[0], p.nonce, &k0).unwrap();
    let e0 = EpochId::from_frame_id(create.id());

    // Bootstrap two initial devices so races, removals, and rotations happen immediately.
    let add0 = build_add_frame(
        &p.root_sks[0],
        vault,
        &view(&[&create]),
        1,
        create.id(),
        vec![create.id()],
        p.devices[0].device_id(),
        p.devices[0].kem_public(),
        sign_join_consent(&p.devices[0], &vault, &p.roots[0].recovery_id()),
        None,
    )
    .unwrap();
    let add1 = build_add_frame(
        &p.root_sks[0],
        vault,
        &view(&[&create, &add0]),
        2,
        add0.id(),
        vec![add0.id()],
        p.devices[1].device_id(),
        p.devices[1].kem_public(),
        sign_join_consent(&p.devices[1], &vault, &p.roots[0].recovery_id()),
        None,
    )
    .unwrap();

    let mut frames = vec![create, add0, add1];
    let mut proofs = Vec::new();
    let mut last_by_author: BTreeMap<DeviceId, (u64, FrameId)> = BTreeMap::new();
    last_by_author.insert(p.roots[0].recovery_id(), (2, frames[2].id()));
    let mut removal_count = 0usize;
    let mut tag_counter = 1u8;

    // Principals: 0..4 are roots, 4..9 are devices.
    let principal_sk = |idx: u8| -> (&DeviceSecret, DeviceId, KemPublic) {
        let i = (idx as usize) % 9;
        if i < 4 {
            (
                &p.root_sks[i],
                p.roots[i].recovery_id(),
                p.roots[i].kem_public(),
            )
        } else {
            let d = &p.devices[i - 4];
            (d.sign_key(), d.device_id(), d.kem_public())
        }
    };

    for step in steps {
        tag_counter = tag_counter.wrapping_add(1).max(1);
        let (author_sk, author_id, _) = principal_sk(step.actor);
        let (target_sk, target_id, target_kem) = principal_sk(step.target);

        // Pick a causal parent (deliberately allows old parents for back-dating tests!).
        let parent = frames[(step.branch as usize) % frames.len()].id();
        let (seq, prev, mut deps) = match last_by_author.get(&author_id) {
            Some(&(s, prev_id)) => (s + 1, prev_id, vec![parent, prev_id]),
            None => (0, FrameId::ZERO, vec![parent]),
        };
        deps.sort();
        deps.dedup();

        match step.kind % 12 {
            // Add device.
            0..=2 => {
                let dev = &p.devices[(step.target as usize) % p.devices.len()];
                let consent = sign_join_consent(dev, &vault, &author_id);
                // Signed directly, not through `build_add_frame`: the generator is adversarial
                // and must keep producing re-adds of removed devices for the resolver to judge.
                if let Ok(f) = Frame::sign_member(
                    author_sk,
                    vault,
                    seq,
                    prev,
                    MemberBody {
                        deps,
                        op: Some(MemberOp::Add {
                            device: dev.device_id(),
                            kem: dev.kem_public(),
                            consent,
                            rewrap: None,
                        }),
                        rotate: None,
                    },
                ) {
                    last_by_author.insert(author_id, (seq, f.id()));
                    frames.push(f);
                }
            }
            // Remove (cap at 10 total removals so exponential RefGraph stays instant).
            3..=6 => {
                if removal_count >= 10 {
                    continue;
                }
                let last_seen_seq = match step.cutoff % 4 {
                    0 => None,
                    n => Some(u64::from(n - 1)),
                };
                if let Ok(f) = Frame::sign_member(
                    author_sk,
                    vault,
                    seq,
                    prev,
                    MemberBody {
                        deps,
                        op: Some(MemberOp::Remove {
                            device: target_id,
                            last_seen_seq,
                        }),
                        rotate: Some(dummy_rotate(vec![e0], author_id, tag_counter)),
                    },
                ) {
                    removal_count += 1;
                    last_by_author.insert(author_id, (seq, f.id()));
                    frames.push(f);
                }
            }
            // RotateRecovery (by a root to another root).
            7..=8 => {
                let root_idx = (step.actor as usize) % 3;
                let next_idx = (root_idx + 1) % 4;
                let old_sk = &p.root_sks[root_idx];
                let old_id = p.roots[root_idx].recovery_id();
                let new_sk = &p.root_sks[next_idx];
                let new_id = p.roots[next_idx].recovery_id();
                let new_kem = p.roots[next_idx].kem_public();
                let (r_seq, r_prev, mut r_deps) = match last_by_author.get(&old_id) {
                    Some(&(s, prev_id)) => (s + 1, prev_id, vec![parent, prev_id]),
                    None => (0, FrameId::ZERO, vec![parent]),
                };
                r_deps.sort();
                r_deps.dedup();
                let consent = sign_rotate_recovery_consent(new_sk, &vault, &old_id, &new_kem);
                if let Ok(f) = Frame::sign_member(
                    old_sk,
                    vault,
                    r_seq,
                    r_prev,
                    MemberBody {
                        deps: r_deps,
                        op: Some(MemberOp::RotateRecovery {
                            new: new_id,
                            new_kem,
                            consent,
                        }),
                        rotate: Some(dummy_rotate(vec![e0], new_id, tag_counter)),
                    },
                ) {
                    last_by_author.insert(old_id, (r_seq, f.id()));
                    frames.push(f);
                }
            }
            // Standalone Rotate.
            9 => {
                if let Ok(f) = Frame::sign_member(
                    author_sk,
                    vault,
                    seq,
                    prev,
                    MemberBody {
                        deps,
                        op: None,
                        rotate: Some(dummy_rotate(vec![e0], author_id, tag_counter)),
                    },
                ) {
                    last_by_author.insert(author_id, (seq, f.id()));
                    frames.push(f);
                }
            }
            // Member fork (equivocation at an author's existing or fresh seq -> FraudProof).
            10 => {
                let (f_seq, f_prev, f_deps) = if let Some(&(prev_seq, _)) =
                    last_by_author.get(&author_id)
                    && prev_seq > 0
                {
                    // Fork at prev_seq by finding the frame before prev_seq.
                    let prior = frames
                        .iter()
                        .find(|f| f.header().author == author_id && f.header().seq == prev_seq - 1)
                        .map(Frame::id);
                    if let Some(p_id) = prior {
                        (prev_seq, p_id, vec![p_id])
                    } else {
                        (seq, prev, deps)
                    }
                } else {
                    (seq, prev, deps)
                };
                let f1 = Frame::sign_member(
                    author_sk,
                    vault,
                    f_seq,
                    f_prev,
                    MemberBody {
                        deps: f_deps.clone(),
                        op: None,
                        rotate: Some(dummy_rotate(vec![e0], author_id, tag_counter)),
                    },
                );
                let f2 = Frame::sign_member(
                    author_sk,
                    vault,
                    f_seq,
                    f_prev,
                    MemberBody {
                        deps: f_deps,
                        op: None,
                        rotate: Some(dummy_rotate(
                            vec![e0],
                            author_id,
                            tag_counter.wrapping_add(77),
                        )),
                    },
                );
                if let (Ok(a), Ok(b)) = (f1, f2) {
                    if let Ok(fp) = FraudProof::from_frames(&a, &b) {
                        proofs.push(fp);
                    }
                    if step.branch % 2 == 0 {
                        frames.push(a);
                    } else {
                        frames.push(a);
                        frames.push(b);
                    }
                }
            }
            // Data fork FraudProof.
            _ => {
                let _ = (target_sk, target_id, target_kem);
                let fork_seq = u64::from(step.cutoff % 3);
                let prev_id = if fork_seq == 0 {
                    FrameId::ZERO
                } else {
                    FrameId::from_bytes([tag_counter; 32])
                };
                let d1 = Frame::seal_data(author_sk, vault, fork_seq, prev_id, e0, &k0, b"a");
                let d2 = Frame::seal_data(author_sk, vault, fork_seq, prev_id, e0, &k0, b"b");
                if let (Ok(a), Ok(b)) = (d1, d2)
                    && let Ok(fp) = FraudProof::from_frames(&a, &b)
                {
                    proofs.push(fp);
                }
            }
        }
    }

    (vault, frames, proofs)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: super::membership_cases(),
        ..ProptestConfig::default()
    })]

    #[test]
    fn prop_i4_matches_reference_model_and_is_order_independent(
        steps in prop::collection::vec(step_strategy(), 1..=12),
        perm_seed in any::<u64>(),
    ) {
        let (vault, frames, proofs) = build_random_history(&steps);
        let baseline = assert_matches_ref(vault, &frames, &proofs);

        // I4: Arbitrary delivery permutations of frames and fraud proofs yield identical results.
        let shuf_frames = shuffled(&frames, perm_seed);
        let shuf_proofs = shuffled(&proofs, perm_seed.wrapping_add(1));
        let permuted = resolve(&vault, &shuf_frames, &shuf_proofs);
        prop_assert_eq!(baseline, permuted);
    }
}
