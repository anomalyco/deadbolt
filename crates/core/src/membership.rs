//! Membership resolution. Causality decides authorization; admission seniority
//! arbitrates conflicting removals, including cycles and delegated authority.
//! See `membership_tests` for the security specification and independent model.

use std::collections::{BTreeMap, BTreeSet};

use crate::entry::{MembershipOp, Payload};
use crate::id::{DeviceId, Hash, VaultId};
use crate::vault::Node;

/// The resolved member set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Membership {
    name: String,
    members: BTreeSet<DeviceId>,
    /// Removed devices and the highest data seq of theirs that still counts.
    removed: BTreeMap<DeviceId, Option<u64>>,
}

impl Membership {
    pub(crate) fn is_member(&self, device: &DeviceId) -> bool {
        self.members.contains(device)
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn members(&self) -> impl Iterator<Item = &DeviceId> {
        self.members.iter()
    }

    pub(crate) fn counts(&self, author: &DeviceId, seq: u64) -> bool {
        self.is_member(author)
            || self
                .removed
                .get(author)
                .is_some_and(|cutoff| cutoff.is_some_and(|c| seq <= c))
    }
}

/// Choose removals in author-seniority order. A candidate must leave itself and
/// all earlier winners authorized after its cuts. Replaying admissions under
/// those cuts checks arbitrary delegation chains without special-casing mutual
/// removals or cycles. A losing removal contributes no cuts whatsoever.
/// With fixed introductions, adding cuts can only invalidate authority. Greedy
/// selection therefore yields the seniority-first maximal authorized subset.
pub(crate) fn resolve(vault: &VaultId, mut ops: Vec<&Node>) -> Membership {
    ops.sort_by_key(|node| (node.depth, node.entry.hash()));
    // Fix each key's first authorized introduction before applying cuts. A cut
    // introduction cannot be resurrected through a different Add of that key.
    let admissions = replay(vault, &ops, &[], None).admissions;
    let mut candidates: Vec<_> = ops
        .iter()
        .copied()
        .filter(|node| {
            matches!(
                node.entry.payload(),
                Payload::Membership(MembershipOp::Remove { .. })
            )
        })
        .filter(|node| admissions.contains_key(&node.entry.author()))
        .collect();
    candidates.sort_by_key(|node| {
        let admission = admissions[&node.entry.author()];
        (
            admission.depth,
            admission.entry.hash(),
            node.depth,
            node.entry.hash(),
        )
    });
    let mut chosen = Vec::new();
    for candidate in candidates {
        chosen.push(candidate);
        let trial = replay(vault, &ops, &chosen, Some(&admissions));
        if !chosen
            .iter()
            .all(|node| trial.removals.contains(&node.entry.hash()))
        {
            chosen.pop();
        }
    }
    let state = replay(vault, &ops, &chosen, Some(&admissions));
    let mut members: BTreeSet<_> = state.admissions.into_keys().collect();
    let mut removed: BTreeMap<DeviceId, Option<u64>> = BTreeMap::new();
    for node in chosen {
        let Payload::Membership(MembershipOp::Remove {
            device,
            last_seen_seq,
        }) = node.entry.payload()
        else {
            unreachable!("only removals are chosen")
        };
        members.remove(device);
        let cutoff = removed.entry(*device).or_default();
        *cutoff = (*cutoff).max(*last_seen_seq);
    }
    let name = state
        .names
        .iter()
        .max_by_key(|node| node.entry.hash())
        .and_then(|node| match node.entry.payload() {
            Payload::Membership(
                MembershipOp::Create { name, .. } | MembershipOp::Rename { name },
            ) => Some(name.clone()),
            _ => None,
        })
        .unwrap_or_default();
    Membership {
        name,
        members,
        removed,
    }
}

#[derive(Default)]
struct Replay<'a> {
    admissions: BTreeMap<DeviceId, &'a Node>,
    removals: BTreeSet<Hash>,
    names: Vec<&'a Node>,
}

/// Replay introductions and names, retaining only operations observed by every
/// chosen removal of their author. Do not remove admissions mid-replay: earlier
/// operations by a removed author still count, and removals are checked together.
fn replay<'a>(
    vault: &VaultId,
    ops: &[&'a Node],
    chosen: &[&Node],
    canonical: Option<&BTreeMap<DeviceId, &Node>>,
) -> Replay<'a> {
    let mut state = Replay::default();
    for (rank, &node) in ops.iter().enumerate() {
        let author = node.entry.author();
        let Payload::Membership(op) = node.entry.payload() else {
            continue;
        };
        if let MembershipOp::Create { device, nonce, .. } = op {
            if rank == 0
                && *device == author
                && node.entry.deps().is_empty()
                && VaultId::derive(device, nonce) == *vault
            {
                state.admissions.insert(author, node);
                state.names.push(node);
            }
            continue;
        }
        if chosen.iter().any(|remove| {
            matches!(remove.entry.payload(), Payload::Membership(MembershipOp::Remove { device, .. }) if *device == author)
                && remove.entry.hash() != node.entry.hash() // self-removal
                && !remove.saw(node)
        }) {
            continue;
        }
        if !state
            .admissions
            .get(&author)
            .is_some_and(|own| node.saw(own))
        {
            continue;
        }
        match op {
            MembershipOp::Create { .. } => unreachable!("handled above"),
            MembershipOp::Add { device, .. } => {
                if canonical.is_none_or(|map| {
                    map.get(device)
                        .is_some_and(|op| op.entry.hash() == node.entry.hash())
                }) {
                    state.admissions.entry(*device).or_insert(node);
                }
            }
            MembershipOp::Rename { .. } => {
                state.names.retain(|seen| !node.saw(seen));
                state.names.push(node);
            }
            MembershipOp::Remove { device, .. } => {
                let admitted = state
                    .admissions
                    .get(device)
                    .is_some_and(|admission| node.saw(admission));
                let already_removed = chosen.iter().any(|remove| {
                    matches!(remove.entry.payload(), Payload::Membership(MembershipOp::Remove { device: target, .. }) if target == device)
                        && node.saw(remove)
                });
                if admitted && !already_removed {
                    state.removals.insert(node.entry.hash());
                }
            }
        }
    }
    state
}
