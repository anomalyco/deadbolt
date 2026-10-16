//! Membership resolution.
//!
//! Membership ops form a DAG (each op's deps are the membership ops its author
//! had seen). The member set is computed by replaying the ops in a fixed
//! linearization — sorted by (depth, hash), which respects causality — while
//! checking each op against the state built so far:
//!
//! - The author must be a current member and the op must have seen the
//!   author's admission. `Add` targets must never have been members; `Remove`
//!   targets must be members whose admission the remover had seen.
//! - `Remove(B)` cuts B's membership ops the remover had not seen. If any of
//!   them were already replayed, the replay restarts with them ignored.
//! - Concurrent mutual removal (`A` removes `B` while `B` removes `A`): the
//!   device admitted earlier in the linearization wins; the loser's `Remove`
//!   is ignored and the replay restarts. Cuts made by an overruled `Remove`
//!   are lifted again.
//! - The name is a register over `Create` and applied `Rename` ops: a rename
//!   replaces the names it had seen; among concurrent ones the highest entry
//!   hash wins.
//!
//! The result depends only on the set of ops, never on arrival order.

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
    /// The security-critical check: is `device` currently a member?
    pub(crate) fn is_member(&self, device: &DeviceId) -> bool {
        self.members.contains(device)
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn members(&self) -> impl Iterator<Item = &DeviceId> {
        self.members.iter()
    }

    /// Whether `author`'s data entry at `seq` takes effect.
    pub(crate) fn counts(&self, author: &DeviceId, seq: u64) -> bool {
        self.is_member(author)
            || self
                .removed
                .get(author)
                .is_some_and(|cutoff| cutoff.is_some_and(|c| seq <= c))
    }
}

/// Why a replay must restart.
enum Restart {
    /// `by` removed a device whose already-replayed `ops` it had not seen.
    Cut { by: Hash, ops: Vec<Hash> },
    /// This `Remove` lost a concurrent mutual removal.
    Overrule(Hash),
}

pub(crate) fn resolve(vault: &VaultId, mut ops: Vec<&Node>) -> Membership {
    ops.sort_by_key(|node| (node.depth, node.entry.hash()));
    // Ignored op -> the `Remove` that cut it (None: overruled, permanent).
    let mut ignored: BTreeMap<Hash, Option<Hash>> = BTreeMap::new();
    loop {
        match Replay::run(vault, &ops, &ignored) {
            Ok(membership) => return membership,
            Err(Restart::Cut { by, ops }) => {
                ignored.extend(ops.into_iter().map(|op| (op, Some(by))));
            }
            Err(Restart::Overrule(remove)) => {
                ignored.retain(|_, cause| *cause != Some(remove));
                ignored.insert(remove, None);
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Admission<'a> {
    /// Position of the admitting op in the linearization; lower is earlier.
    rank: usize,
    op: &'a Node,
}

struct Removal<'a> {
    admission: Admission<'a>,
    by: &'a Node,
    data_cutoff: Option<u64>,
}

#[derive(Default)]
struct Replay<'a> {
    members: BTreeMap<DeviceId, Admission<'a>>,
    removed: BTreeMap<DeviceId, Removal<'a>>,
    applied: Vec<&'a Node>,
    /// `Create`/`Rename` ops no later rename was based on.
    names: Vec<&'a Node>,
}

impl<'a> Replay<'a> {
    fn run(
        vault: &VaultId,
        ops: &[&'a Node],
        ignored: &BTreeMap<Hash, Option<Hash>>,
    ) -> Result<Membership, Restart> {
        let mut state = Replay::default();
        for (rank, &node) in ops.iter().enumerate() {
            if !ignored.contains_key(&node.entry.hash()) && state.step(vault, rank, node)? {
                state.applied.push(node);
            }
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
        Ok(Membership {
            name,
            members: state.members.into_keys().collect(),
            removed: state
                .removed
                .into_iter()
                .map(|(d, r)| (d, r.data_cutoff))
                .collect(),
        })
    }

    /// Applies one op; `Ok(false)` if it has no effect.
    fn step(&mut self, vault: &VaultId, rank: usize, node: &'a Node) -> Result<bool, Restart> {
        let author = node.entry.author();
        let Payload::Membership(op) = node.entry.payload() else {
            return Ok(false);
        };
        if let MembershipOp::Create { device, nonce, .. } = op {
            let genesis = rank == 0
                && *device == author
                && node.entry.deps().is_empty()
                && VaultId::derive(device, nonce) == *vault;
            if genesis {
                self.members.insert(author, Admission { rank, op: node });
                self.names.push(node);
            }
            return Ok(genesis);
        }
        let Some(own) = self.members.get(&author) else {
            return self.contest(node).map(|()| false);
        };
        if !node.saw(own.op) {
            return Ok(false);
        }
        match *op {
            MembershipOp::Create { .. } => unreachable!("handled above"),
            MembershipOp::Rename { .. } => {
                // Names are validated when the entry is applied.
                self.names.retain(|seen| !node.saw(seen));
                self.names.push(node);
                Ok(true)
            }
            MembershipOp::Add { device, .. } => {
                // Consent signatures are verified when the entry is applied.
                if self.members.contains_key(&device) || self.removed.contains_key(&device) {
                    return Ok(false);
                }
                self.members.insert(device, Admission { rank, op: node });
                Ok(true)
            }
            MembershipOp::Remove {
                device,
                last_seen_seq,
            } => {
                if let Some(&admission) = self.members.get(&device) {
                    if !node.saw(admission.op) {
                        return Ok(false);
                    }
                    self.members.remove(&device);
                    let removal = Removal {
                        admission,
                        by: node,
                        data_cutoff: last_seen_seq,
                    };
                    self.removed.insert(device, removal);
                    let ops: Vec<Hash> = self
                        .applied
                        .iter()
                        .filter(|op| op.entry.author() == device && !node.saw(op))
                        .map(|op| op.entry.hash())
                        .collect();
                    if ops.is_empty() {
                        return Ok(true);
                    }
                    return Err(Restart::Cut {
                        by: node.entry.hash(),
                        ops,
                    });
                }
                // A second removal, concurrent with the first, may extend the data cutoff.
                match self.removed.get_mut(&device) {
                    Some(removal) if !node.saw(removal.by) && node.saw(removal.admission.op) => {
                        removal.data_cutoff = removal.data_cutoff.max(last_seen_seq);
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            }
        }
    }

    /// `node`'s author is not a member. If it was removed by the target of
    /// `node` (a `Remove`) concurrently, and was admitted earlier than that
    /// target, `node` wins and the other removal is overruled.
    fn contest(&self, node: &'a Node) -> Result<(), Restart> {
        let Payload::Membership(MembershipOp::Remove { device: target, .. }) = node.entry.payload()
        else {
            return Ok(());
        };
        let (Some(lost), Some(winner)) = (
            self.removed.get(&node.entry.author()),
            self.members.get(target),
        ) else {
            return Ok(());
        };
        let mutual = lost.by.entry.author() == *target && !node.saw(lost.by);
        let valid = node.saw(lost.admission.op) && node.saw(winner.op);
        if mutual && valid && lost.admission.rank < winner.rank {
            return Err(Restart::Overrule(lost.by.entry.hash()));
        }
        Ok(())
    }
}
