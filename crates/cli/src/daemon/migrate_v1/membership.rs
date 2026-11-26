//! DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2.
//!
//! v1 membership resolution, as `deadbolt-core` had it before v2, reduced
//! to what a migration needs from it: the vault's name, and which of a
//! removed device's data entries still count. Causality decides authority;
//! admission seniority arbitrates conflicting removals.

use std::collections::{BTreeMap, BTreeSet};

use deadbolt_core::{DeviceId, Hash};

use super::entry::{MembershipOp, Payload};
use super::replay::Node;

/// The resolved member set.
#[derive(Default)]
pub(super) struct Membership {
    pub name: String,
    members: BTreeSet<DeviceId>,
    /// Removed devices and the highest data seq of theirs that still counts.
    removed: BTreeMap<DeviceId, Option<u64>>,
}

impl Membership {
    /// Whether `author`'s data entry `seq` counts.
    pub fn counts(&self, author: &DeviceId, seq: u64) -> bool {
        self.members.contains(author)
            || self
                .removed
                .get(author)
                .copied()
                .flatten()
                .is_some_and(|cutoff| seq <= cutoff)
    }
}

/// Resolves a vault's membership entries; `genesis` is its first entry.
pub(super) fn resolve(genesis: &Hash, mut ops: Vec<&Node>) -> Membership {
    ops.retain(|node| matches!(node.entry.payload, Payload::Membership(_)));
    ops.sort_by_key(|node| (node.depth, node.entry.hash));
    let (chosen, authority) = choose_removals(genesis, &ops);
    let mut members: BTreeSet<_> = authority.admissions.into_keys().collect();
    let mut removed: BTreeMap<DeviceId, Option<u64>> = BTreeMap::new();
    for node in chosen {
        let Payload::Membership(MembershipOp::Remove {
            device,
            last_seen_seq,
        }) = &node.entry.payload
        else {
            continue;
        };
        members.remove(device);
        let cutoff = removed.entry(*device).or_default();
        *cutoff = (*cutoff).max(*last_seen_seq);
    }
    let name = authority
        .names
        .iter()
        .max_by_key(|node| node.entry.hash)
        .and_then(|node| match &node.entry.payload {
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

/// The winning removals: the greatest valid set in seniority order (the
/// author's first authorized admission, then the removal's own depth and
/// hash), kept greedily, with the authority they leave.
fn choose_removals<'a>(genesis: &Hash, ops: &[&'a Node]) -> (Vec<&'a Node>, Authority<'a>) {
    let structural = authorize(genesis, ops, &[]);
    let mut candidates: Vec<_> = ops
        .iter()
        .copied()
        .filter(|node| structural.removals.contains(&node.entry.hash))
        .collect();
    candidates.sort_by_key(|node| {
        let first = structural
            .admissions
            .get(&node.entry.author)
            .and_then(|adds| adds.first())
            .map(|first| (first.depth, first.entry.hash));
        (first, node.depth, node.entry.hash)
    });
    let mut chosen: Vec<&Node> = Vec::new();
    let mut current = structural;
    for candidate in candidates {
        let Some(victim) = target(candidate) else {
            continue;
        };
        if chosen
            .iter()
            .any(|winner| removes(winner, victim) && candidate.saw(winner))
        {
            continue;
        }
        // A removal that saw everything its target wrote cuts nothing.
        let cuts_nothing = ops.iter().all(|op| {
            op.entry.author != *victim || op.entry.hash == candidate.entry.hash || candidate.saw(op)
        });
        if cuts_nothing {
            if current.removals.contains(&candidate.entry.hash)
                && !chosen
                    .iter()
                    .any(|winner| removes(winner, victim) && winner.saw(candidate))
            {
                chosen.push(candidate);
            }
            continue;
        }
        chosen.push(candidate);
        let trial = authorize(genesis, ops, &chosen);
        let valid = chosen.iter().all(|winner| {
            trial.removals.contains(&winner.entry.hash)
                && target(winner).is_some_and(|victim| {
                    !chosen
                        .iter()
                        .any(|other| removes(other, victim) && winner.saw(other))
                })
        });
        if valid {
            current = trial;
        } else {
            chosen.pop();
        }
    }
    (chosen, current)
}

#[derive(Default)]
struct Authority<'a> {
    /// Each device's authorized `Create`/`Add`s, in seniority order.
    admissions: BTreeMap<DeviceId, Vec<&'a Node>>,
    /// Authorized removals whose target had an authorized admission they saw.
    removals: BTreeSet<Hash>,
    /// Authorized names no authorized rename replaced.
    names: Vec<&'a Node>,
}

impl Authority<'_> {
    fn admitted_before(&self, device: &DeviceId, node: &Node) -> bool {
        self.admissions
            .get(device)
            .is_some_and(|adds| adds.iter().any(|add| node.saw(add)))
    }
}

/// Which operations keep their authority under `chosen` removals.
fn authorize<'a>(genesis: &Hash, ops: &[&'a Node], chosen: &[&Node]) -> Authority<'a> {
    let mut state = Authority::default();
    let mut cuts: BTreeMap<DeviceId, Vec<&Node>> = BTreeMap::new();
    for &removal in chosen {
        if let Some(victim) = target(removal) {
            cuts.entry(*victim).or_default().push(removal);
        }
    }
    let Some(first) = ops.iter().copied().find(|node| node.entry.hash == *genesis) else {
        return state;
    };
    state.admissions.insert(first.entry.author, vec![first]);
    state.names.push(first);
    for &node in ops {
        if node.entry.hash == *genesis {
            continue;
        }
        let author = node.entry.author;
        let Payload::Membership(op) = &node.entry.payload else {
            continue;
        };
        let cut = cuts.get(&author).is_some_and(|removals| {
            removals
                .iter()
                .any(|removal| removal.entry.hash != node.entry.hash && !removal.saw(node))
        });
        if cut || !state.admitted_before(&author, node) {
            continue;
        }
        match op {
            MembershipOp::Create { .. } => {}
            MembershipOp::Add { device } => {
                state.admissions.entry(*device).or_default().push(node);
            }
            MembershipOp::Rename { .. } => {
                state.names.retain(|seen| !node.saw(seen));
                state.names.push(node);
            }
            MembershipOp::Remove { device, .. } => {
                if state.admitted_before(device, node) {
                    state.removals.insert(node.entry.hash);
                }
            }
        }
    }
    state
}

fn removes(node: &Node, device: &DeviceId) -> bool {
    target(node) == Some(device)
}

fn target(removal: &Node) -> Option<&DeviceId> {
    match &removal.entry.payload {
        Payload::Membership(MembershipOp::Remove { device, .. }) => Some(device),
        _ => None,
    }
}
