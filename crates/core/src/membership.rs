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

/// Resolves a causally closed set of entries; non-membership entries are ignored.
pub(crate) fn resolve(vault: &VaultId, mut ops: Vec<&Node>) -> Membership {
    ops.retain(|node| matches!(node.entry.payload(), Payload::Membership(_)));
    ops.sort_by_key(|node| (node.depth, node.entry.hash()));
    let (chosen, authority) = choose_removals(vault, &ops);
    let mut members: BTreeSet<_> = authority.admissions.into_keys().collect();
    let mut removed: BTreeMap<DeviceId, Option<u64>> = BTreeMap::new();
    for node in chosen {
        let Payload::Membership(MembershipOp::Remove {
            device,
            last_seen_seq,
        }) = node.entry.payload()
        else {
            unreachable!("only removals are chosen")
        };
        // A removed key's Adds never readmit it.
        members.remove(device);
        let cutoff = removed.entry(*device).or_default();
        *cutoff = (*cutoff).max(*last_seen_seq);
    }
    let name = authority
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

/// Chooses the winning removals, the lexicographically greatest valid set in
/// seniority order (author's first structurally authorized admission, then the
/// removal's own depth and hash), and returns them with the authority they leave.
///
/// A set is valid if each of its removals keeps its authority under the set's
/// cuts, its target keeps an admission it saw, and it saw no other removal of
/// that target in the set. Dropping a removal only drops cuts, and authority
/// only grows as cuts shrink, so every subset of a valid set is valid. The order
/// is fixed before any cut. Together these make the greedy pass exact: keeping
/// each candidate that leaves the chosen set valid yields the lexicographic
/// maximum. (At the first candidate where greedy and the maximum differ, the
/// shared prefix plus that candidate is a subset of whichever set holds it, so
/// it is valid, and greedy would have kept it, or the maximum was not maximal.)
fn choose_removals<'a>(vault: &VaultId, ops: &[&'a Node]) -> (Vec<&'a Node>, Authority<'a>) {
    // Seniority comes from authority with no cuts at all, so no choice of
    // removals can reorder the candidates.
    let structural = authorize(vault, ops, &[]);
    let mut candidates: Vec<_> = ops
        .iter()
        .copied()
        .filter(|node| structural.removals.contains(&node.entry.hash()))
        .collect();
    candidates.sort_by_key(|node| {
        let first = structural.admissions[&node.entry.author()][0];
        (
            first.depth,
            first.entry.hash(),
            node.depth,
            node.entry.hash(),
        )
    });
    let mut chosen: Vec<&Node> = Vec::new();
    // Authority under `chosen`.
    let mut current = structural;
    for candidate in candidates {
        let victim = target(candidate);
        if chosen
            .iter()
            .any(|winner| removes(winner, victim) && candidate.saw(winner))
        {
            continue;
        }
        // A removal that saw everything its target wrote cuts nothing, so it
        // changes no authority: only its own conditions need checking.
        let cuts_nothing = ops.iter().all(|op| {
            op.entry.author() != *victim
                || op.entry.hash() == candidate.entry.hash()
                || candidate.saw(op)
        });
        if cuts_nothing {
            if current.removals.contains(&candidate.entry.hash())
                && !chosen
                    .iter()
                    .any(|winner| removes(winner, victim) && winner.saw(candidate))
            {
                chosen.push(candidate);
            }
            continue;
        }
        chosen.push(candidate);
        let trial = authorize(vault, ops, &chosen);
        let valid = chosen.iter().all(|winner| {
            trial.removals.contains(&winner.entry.hash())
                && !chosen
                    .iter()
                    .any(|other| removes(other, target(winner)) && winner.saw(other))
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

/// Which operations keep their authority under `chosen` removals. The genesis
/// is authorized. Any other operation is authorized if no chosen removal of its
/// author cuts it (misses it) and it saw an authorized admission of its author.
/// Any surviving admission will do, so an extra `Add` can never take authority
/// away. Removed authors keep the operations their removals saw.
fn authorize<'a>(vault: &VaultId, ops: &[&'a Node], chosen: &[&Node]) -> Authority<'a> {
    let mut state = Authority::default();
    let mut cuts: BTreeMap<DeviceId, Vec<&Node>> = BTreeMap::new();
    for &removal in chosen {
        cuts.entry(*target(removal)).or_default().push(removal);
    }
    let Some(genesis) = ops.iter().copied().find(|node| is_genesis(vault, node)) else {
        return state;
    };
    state
        .admissions
        .insert(genesis.entry.author(), vec![genesis]);
    state.names.push(genesis);
    for &node in ops {
        if node.entry.hash() == genesis.entry.hash() {
            continue;
        }
        let author = node.entry.author();
        let Payload::Membership(op) = node.entry.payload() else {
            continue;
        };
        let cut = cuts.get(&author).is_some_and(|removals| {
            removals
                .iter()
                .any(|removal| removal.entry.hash() != node.entry.hash() && !removal.saw(node))
        });
        if cut || !state.admitted_before(&author, node) {
            continue;
        }
        match op {
            // Only the genesis creates.
            MembershipOp::Create { .. } => {}
            MembershipOp::Add { device, .. } => {
                state.admissions.entry(*device).or_default().push(node);
            }
            MembershipOp::Rename { .. } => {
                state.names.retain(|seen| !node.saw(seen));
                state.names.push(node);
            }
            MembershipOp::Remove { device, .. } => {
                if state.admitted_before(device, node) {
                    state.removals.insert(node.entry.hash());
                }
            }
        }
    }
    state
}

/// The vault's first entry: its creator's `Create`, with no deps, deriving this
/// vault's id.
fn is_genesis(vault: &VaultId, node: &Node) -> bool {
    matches!(
        node.entry.payload(),
        Payload::Membership(MembershipOp::Create { device, nonce, .. })
            if *device == node.entry.author()
                && node.entry.deps().is_empty()
                && VaultId::derive(device, nonce) == *vault
    )
}

fn removes(node: &Node, device: &DeviceId) -> bool {
    matches!(
        node.entry.payload(),
        Payload::Membership(MembershipOp::Remove { device: target, .. }) if target == device
    )
}

fn target(removal: &Node) -> &DeviceId {
    match removal.entry.payload() {
        Payload::Membership(MembershipOp::Remove { device, .. }) => device,
        _ => unreachable!("not a removal"),
    }
}
