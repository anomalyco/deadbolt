//! Deadbolt v2 membership resolver with `class = 0` recovery lineage,
//! fraud-proof filtering, and the back-dating parking rule.

use std::collections::{BTreeMap, BTreeSet};

use crate::id::{DeviceId, VaultId};

use super::crypto::{EpochId, FrameId, KemPublic, NetPublic};
use super::dag::{DagNode, build_dag};
use super::frame::{Frame, FrameKind, LogKind, MemberOp};
pub use super::fraud::{
    FRAUD_PROOF_LEN, FraudError, FraudProof, VerifiedFraud, detect_fraud_in_frames,
};

/// Resolved v2 membership state after fraud filtering and `class = 0` recovery-lineage resolution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedMembership {
    /// Active ordinary device members (excludes removed devices and recovery roots).
    pub devices: BTreeSet<DeviceId>,
    /// Active recovery root, or `None` if no valid genesis exists or the recovery lineage is frozen.
    pub active_recovery: Option<DeviceId>,
    /// Ordered recovery root lineage `[R_0, R_1, ...]` from non-voided frames.
    pub recovery_lineage: Vec<DeviceId>,
    /// True iff a recovery-lineage principal forked in `Member` (or genesis forked at seq 0).
    pub recovery_frozen: bool,
    /// Removed ordinary devices and the highest data seq of theirs that still counts.
    pub removed: BTreeMap<DeviceId, Option<u64>>,
    /// Canonical X25519 KEM public keys for active devices and the active recovery root.
    pub kem_keys: BTreeMap<DeviceId, KemPublic>,
    /// Every admitted device's transport key (`D_net`), removed ones included, from its
    /// first authorized `Add`: signed by the device and by the key itself.
    pub nets: BTreeMap<DeviceId, NetPublic>,
    /// All authorized `Member` frame IDs (chosen removals + authorized non-removal ops).
    pub authorized_frames: BTreeSet<FrameId>,
    /// Structurally authorized mutual removal pairs `(a, b)` with `a < b`, for parking detection.
    pub mutual_removals: BTreeSet<(DeviceId, DeviceId)>,
    /// Minimum `Member` fork seq per author (from fraud proofs and observed forks).
    pub member_fork_seq: BTreeMap<DeviceId, u64>,
    /// Minimum `Data` fork seq per author (from fraud proofs and observed forks).
    pub data_fork_seq: BTreeMap<DeviceId, u64>,
    /// `Member` frames placed in the causal DAG (every `dep` and `prev` present, and `prev`
    /// continuing the author's own log). Builders only cite these.
    pub dag_frames: BTreeSet<FrameId>,
    /// `Member` frames held but not placed: a missing `dep` or `prev`, or a `prev` that does
    /// not continue the author's log. They count for nothing until they can be placed.
    pub unplaced_frames: BTreeSet<FrameId>,
    /// For each author that forked in `Member`, every `Member` frame ID equal to or
    /// causally descending from any voided fork frame of that author.
    fork_descendants: BTreeMap<DeviceId, BTreeSet<FrameId>>,
}

impl ResolvedMembership {
    pub fn is_active_device(&self, device: &DeviceId) -> bool {
        self.devices.contains(device)
    }

    pub fn is_authorized_principal(&self, id: &DeviceId) -> bool {
        self.devices.contains(id) || self.active_recovery == Some(*id)
    }

    /// Returns `members_now ∪ {recovery_now}` (eligible epoch wrap recipient set for E4).
    pub fn eligible_recipients(&self) -> BTreeSet<DeviceId> {
        let mut set = self.devices.clone();
        if let Some(root) = self.active_recovery {
            set.insert(root);
        }
        set
    }

    pub fn kem_of(&self, id: &DeviceId) -> Option<KemPublic> {
        self.kem_keys.get(id).copied()
    }

    /// Highest data seq of `author` that counts in a contiguous stream `0..=last`.
    pub fn counted_through(&self, author: &DeviceId, last: u64) -> Option<u64> {
        if let Some(&fork_seq) = self.data_fork_seq.get(author) {
            let cap = fork_seq.checked_sub(1)?;
            let base = if self.devices.contains(author) {
                Some(last)
            } else {
                self.removed.get(author).copied().flatten()
            }?;
            return Some(base.min(cap).min(last));
        }
        if self.devices.contains(author) {
            Some(last)
        } else {
            self.removed
                .get(author)
                .copied()
                .flatten()
                .map(|cutoff| cutoff.min(last))
        }
    }

    /// True iff `epoch` was minted by an authorized `Member` frame. Counted data must be sealed
    /// under one: reader duty rewraps only authorized epochs, so data under any other epoch (a
    /// `Remove` that lost its conflict, a rotation a root fork voided) could stay unreadable to a
    /// member forever.
    pub fn is_authorized_epoch(&self, epoch: &EpochId) -> bool {
        self.authorized_frames.contains(&epoch.as_frame_id())
    }

    /// True iff `frame` is a voided fork frame of a forked author, or descends
    /// from one: no honest frame may build on it.
    pub fn is_fork_void(&self, frame: &FrameId) -> bool {
        self.fork_descendants.values().any(|d| d.contains(frame))
    }

    /// True iff a data frame by `author` at `seq` with membership view `mheads` counts.
    ///
    /// For an author that forked in `Member`, every head must be a placed frame outside the
    /// fork's descendants: a head this peer cannot place may be a withheld fork-chain frame.
    pub fn counts_data(&self, author: &DeviceId, seq: u64, mheads: &[FrameId]) -> bool {
        if self.counted_through(author, seq) != Some(seq) {
            return false;
        }
        if self.member_fork_seq.contains_key(author) {
            let descendants = self.fork_descendants.get(author);
            return mheads.iter().all(|h| {
                self.dag_frames.contains(h) && descendants.is_none_or(|d| !d.contains(h))
            });
        }
        true
    }
}

/// Reasons a device must park and alert a human instead of auto-adopting a conflicting epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParkingReason {
    ReinstatedRemovedDevice { device: DeviceId },
    MutualRemoval { a: DeviceId, b: DeviceId },
    RecoveryLineageFrozen,
}

/// Result of the v2 parking rule check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParkingStatus {
    pub reasons: Vec<ParkingReason>,
}

impl ParkingStatus {
    pub fn should_park(&self) -> bool {
        !self.reasons.is_empty()
    }
}

/// Evaluates the parking rule against devices this peer had previously accepted as removed.
pub fn check_parking(
    previously_removed: &BTreeSet<DeviceId>,
    resolved: &ResolvedMembership,
) -> ParkingStatus {
    let mut reasons = Vec::new();
    if resolved.recovery_frozen {
        reasons.push(ParkingReason::RecoveryLineageFrozen);
    }
    for &device in previously_removed {
        if resolved.is_active_device(&device) {
            reasons.push(ParkingReason::ReinstatedRemovedDevice { device });
        }
    }
    for &(a, b) in &resolved.mutual_removals {
        reasons.push(ParkingReason::MutualRemoval { a, b });
    }
    ParkingStatus { reasons }
}

/// Resolves v2 membership from an unordered set of frames and keyless `FraudProof`s (invariant I4).
pub fn resolve<'a>(
    vault: &VaultId,
    frames: impl IntoIterator<Item = &'a Frame>,
    fraud_proofs: impl IntoIterator<Item = &'a FraudProof>,
) -> ResolvedMembership {
    resolve_checked(vault, frames, fraud_proofs, None, None)
}

type OuterForks<'a> = (&'a BTreeMap<DeviceId, u64>, &'a BTreeMap<DeviceId, u64>);

// A causal sub-view reuses coverage decisions already made in topological order.
fn resolve_checked<'a>(
    vault: &VaultId,
    frames: impl IntoIterator<Item = &'a Frame>,
    fraud_proofs: impl IntoIterator<Item = &'a FraudProof>,
    outer_forks: Option<OuterForks<'_>>,
    checked: Option<&BTreeMap<FrameId, bool>>,
) -> ResolvedMembership {
    let all_frames: Vec<&'a Frame> = frames
        .into_iter()
        .filter(|f| f.header().vault == *vault)
        .collect();

    let mut member_fork_seq: BTreeMap<DeviceId, u64> = outer_forks
        .map(|(member, _)| member.clone())
        .unwrap_or_default();
    let mut data_fork_seq: BTreeMap<DeviceId, u64> = outer_forks
        .map(|(_, data)| data.clone())
        .unwrap_or_default();
    let mut explicit_member_fork_ids: BTreeMap<DeviceId, BTreeSet<FrameId>> = BTreeMap::new();

    let implicit_proofs = detect_fraud_in_frames(all_frames.iter().copied());
    for verified in fraud_proofs
        .into_iter()
        .filter_map(|p| p.verify().ok())
        .chain(implicit_proofs.iter().filter_map(|p| p.verify().ok()))
    {
        if verified.vault != *vault {
            continue;
        }
        match verified.log {
            LogKind::Member => {
                member_fork_seq
                    .entry(verified.author)
                    .and_modify(|s| *s = (*s).min(verified.seq))
                    .or_insert(verified.seq);
                let set = explicit_member_fork_ids.entry(verified.author).or_default();
                set.insert(verified.id_a);
                set.insert(verified.id_b);
            }
            LogKind::Data => {
                data_fork_seq
                    .entry(verified.author)
                    .and_modify(|s| *s = (*s).min(verified.seq))
                    .or_insert(verified.seq);
            }
        }
    }

    let mut by_id: BTreeMap<FrameId, &'a Frame> = BTreeMap::new();
    for frame in all_frames {
        if frame.header().kind == FrameKind::Member {
            by_id.insert(frame.id(), frame);
        }
    }

    let dag = build_dag(&by_id, &member_fork_seq);
    let nodes = dag.nodes;
    let dag_frames: BTreeSet<FrameId> = nodes.iter().map(|n| n.frame.id()).collect();
    let mut fork_descendants = explicit_member_fork_ids;
    for (idx, node) in nodes.iter().enumerate() {
        if node.void {
            fork_descendants
                .entry(node.frame.header().author)
                .or_default()
                .insert(node.frame.id());
        }
        for (fork_author, &fork_seq) in &member_fork_seq {
            let descends = (0..nodes.len()).any(|ancestor| {
                nodes[ancestor].void
                    && nodes[ancestor].frame.header().author == *fork_author
                    && nodes[ancestor].frame.header().seq >= fork_seq
                    && (ancestor == idx || node.saw(ancestor))
            });
            if descends {
                fork_descendants
                    .entry(*fork_author)
                    .or_default()
                    .insert(node.frame.id());
            }
        }
    }

    let rotation_ok = match checked {
        Some(checked) => nodes.iter().map(|n| checked[&n.frame.id()]).collect(),
        None => rotation_coverage(vault, &nodes, &member_fork_seq, &data_fork_seq),
    };
    let structural_lineage = compute_recovery_lineage(vault, &nodes, &rotation_ok);
    let structural = authorize(vault, &nodes, &[], &structural_lineage, &rotation_ok);
    let genesis_creator_forked = nodes.iter().any(|n| {
        n.frame.header().seq == 0
            && matches!(
                n.frame.member_body().and_then(|b| b.op.as_ref()),
                Some(MemberOp::Create { .. })
            )
            && member_fork_seq.get(&n.frame.header().author) == Some(&0)
    });
    let mutual_removals = find_mutual_removals(&nodes, &structural, &structural_lineage);
    let (chosen, authority) =
        choose_removals(vault, &nodes, structural, &structural_lineage, &rotation_ok);

    // A retired root's handoff is a non-void frame, so any later `Member` fork of that root is
    // above its retire seq and cannot undo it; recovery roots never write counted data either.
    // Only the active root forking, or a root forking at or before its own handoff, freezes.
    let retired_root_forked = authority.retired_roots.iter().any(|(root, &ret_idx)| {
        let retire_seq = nodes[ret_idx].frame.header().seq;
        member_fork_seq.get(root).is_some_and(|&s| s <= retire_seq)
    });
    let active_root_forked = authority
        .lineage_order
        .last()
        .is_some_and(|root| member_fork_seq.contains_key(root) || data_fork_seq.contains_key(root));
    let recovery_frozen = genesis_creator_forked || retired_root_forked || active_root_forked;
    let active_recovery = if recovery_frozen {
        None
    } else {
        authority.lineage_order.last().copied()
    };

    let mut devices: BTreeSet<DeviceId> = authority
        .admissions
        .keys()
        .copied()
        .filter(|id| !authority.lineage.contains(id))
        .collect();
    let mut removed: BTreeMap<DeviceId, Option<u64>> = BTreeMap::new();
    let mut chosen_ids: BTreeSet<FrameId> = BTreeSet::new();
    for &idx in &chosen {
        let frame = nodes[idx].frame;
        chosen_ids.insert(frame.id());
        if let Some(MemberOp::Remove {
            device,
            last_seen_seq,
        }) = frame.member_body().and_then(|b| b.op.as_ref())
        {
            devices.remove(device);
            let cutoff = removed.entry(*device).or_default();
            *cutoff = (*cutoff).max(*last_seen_seq);
        }
    }

    for (&author, &fork_seq) in &data_fork_seq {
        if authority.lineage.contains(&author) {
            continue;
        }
        if devices.remove(&author) || removed.contains_key(&author) {
            let fork_cap = fork_seq.checked_sub(1);
            removed
                .entry(author)
                .and_modify(|existing| {
                    *existing = match (*existing, fork_cap) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        _ => None,
                    };
                })
                .or_insert(fork_cap);
        }
    }

    let mut authorized_frames = authority.non_removal_frames;
    authorized_frames.extend(chosen_ids);

    let mutual_removals: BTreeSet<(DeviceId, DeviceId)> = mutual_removals
        .into_iter()
        .filter(|(pair, between)| {
            !settled_by_root(
                &nodes,
                &authority.lineage,
                &authorized_frames,
                &devices,
                *pair,
                between,
            )
        })
        .map(|(pair, _)| pair)
        .collect();

    let mut kem_keys = BTreeMap::new();
    for &dev in &devices {
        if let Some(&kem) = authority.kem_keys.get(&dev) {
            kem_keys.insert(dev, kem);
        }
    }
    if let Some(root) = active_recovery
        && let Some(&kem) = authority.kem_keys.get(&root)
    {
        kem_keys.insert(root, kem);
    }

    ResolvedMembership {
        devices,
        active_recovery,
        recovery_lineage: authority.lineage_order,
        recovery_frozen,
        removed,
        kem_keys,
        nets: authority.nets,
        authorized_frames,
        mutual_removals,
        member_fork_seq,
        data_fork_seq,
        dag_frames,
        unplaced_frames: dag.unplaced,
        fork_descendants,
    }
}

#[derive(Default)]
struct Authority {
    admissions: BTreeMap<DeviceId, Vec<usize>>,
    lineage: BTreeSet<DeviceId>,
    lineage_order: Vec<DeviceId>,
    retired_roots: BTreeMap<DeviceId, usize>,
    kem_keys: BTreeMap<DeviceId, KemPublic>,
    nets: BTreeMap<DeviceId, NetPublic>,
    removals: BTreeSet<usize>,
    non_removal_frames: BTreeSet<FrameId>,
}

impl Authority {
    fn admitted_before(&self, device: &DeviceId, node_idx: usize, nodes: &[DagNode<'_>]) -> bool {
        self.admissions
            .get(device)
            .is_some_and(|adds| adds.iter().any(|&add_idx| nodes[node_idx].saw(add_idx)))
    }
}

/// Coverage depends on the membership the author saw, never on removals chosen
/// in the outer view. In particular, later equivocation cannot undo a removal
/// that another author relied on when choosing its recipients.
fn rotation_coverage(
    vault: &VaultId,
    nodes: &[DagNode<'_>],
    member_forks: &BTreeMap<DeviceId, u64>,
    data_forks: &BTreeMap<DeviceId, u64>,
) -> Vec<bool> {
    let mut checked = BTreeMap::new();
    let mut ok = Vec::with_capacity(nodes.len());
    for (idx, node) in nodes.iter().enumerate() {
        let Some(body) = node.frame.member_body() else {
            ok.push(false);
            checked.insert(node.frame.id(), false);
            continue;
        };
        let valid = match &body.rotate {
            None => true,
            Some(rot) => {
                let author = node.frame.header().author;
                let leaving = match &body.op {
                    Some(MemberOp::Remove { device, .. }) => Some(*device),
                    Some(MemberOp::RotateRecovery { .. }) => Some(author),
                    _ => None,
                };
                let covered = |device: &DeviceId| {
                    Some(*device) == leaving || rot.wraps.iter().any(|(id, _)| id == device)
                };
                let new_covered = match &body.op {
                    Some(MemberOp::Create { .. }) => is_genesis(vault, node.frame),
                    Some(MemberOp::RotateRecovery { new, .. }) => {
                        rot.wraps.iter().any(|(id, _)| id == new)
                    }
                    _ => true,
                };
                // A superset of past recipients makes the usual complete-wrap case cheap.
                let covers_all_admissions = (0..idx).filter(|&j| ok[j] && node.saw(j)).all(|j| {
                    match nodes[j]
                        .frame
                        .member_body()
                        .and_then(|body| body.op.as_ref())
                    {
                        Some(MemberOp::Create { .. }) => covered(&nodes[j].frame.header().author),
                        Some(MemberOp::Add { device, .. }) => covered(device),
                        Some(MemberOp::RotateRecovery { new, .. }) => covered(new),
                        _ => true,
                    }
                });
                new_covered
                    && (covers_all_admissions || {
                        // Keep rejected ancestors as chain links, but deny them authority.
                        // Neither a past removal nor a fork-voided admission requires a wrap.
                        let past: Vec<_> = (0..idx)
                            .filter(|&j| node.saw(j))
                            .map(|j| nodes[j].frame)
                            .collect();
                        let unforked =
                            resolve_checked(vault, past.iter().copied(), [], None, Some(&checked))
                                .eligible_recipients();
                        let with_forks =
                            (!member_forks.is_empty() || !data_forks.is_empty()).then(|| {
                                resolve_checked(
                                    vault,
                                    past.iter().copied(),
                                    [],
                                    Some((member_forks, data_forks)),
                                    Some(&checked),
                                )
                                .eligible_recipients()
                            });
                        unforked
                            .iter()
                            .filter(|id| with_forks.as_ref().is_none_or(|f| f.contains(id)))
                            .all(covered)
                    })
            }
        };
        ok.push(valid);
        checked.insert(node.frame.id(), valid);
    }
    ok
}

fn compute_recovery_lineage(
    vault: &VaultId,
    nodes: &[DagNode<'_>],
    rotation_ok: &[bool],
) -> BTreeSet<DeviceId> {
    let mut lineage = BTreeSet::new();
    let mut retired: BTreeMap<DeviceId, usize> = BTreeMap::new();
    let mut root_admitted: BTreeMap<DeviceId, usize> = BTreeMap::new();
    let Some(genesis_idx) = nodes
        .iter()
        .position(|n| !n.void && is_genesis(vault, n.frame))
    else {
        return lineage;
    };
    let genesis_author = nodes[genesis_idx].frame.header().author;
    lineage.insert(genesis_author);
    root_admitted.insert(genesis_author, genesis_idx);
    for (idx, node) in nodes.iter().enumerate() {
        if idx == genesis_idx || node.void || !rotation_ok[idx] {
            continue;
        }
        let author = node.frame.header().author;
        let Some(&admit_idx) = root_admitted.get(&author) else {
            continue;
        };
        if !node.saw(admit_idx) {
            continue;
        }
        if retired
            .get(&author)
            .is_some_and(|&ret_idx| ret_idx != idx && !nodes[ret_idx].saw(idx))
        {
            continue;
        }
        if let Some(MemberOp::RotateRecovery { new, .. }) =
            node.frame.member_body().and_then(|b| b.op.as_ref())
            && !retired.contains_key(&author)
            && !lineage.contains(new)
            && !added_as_device(nodes, new, idx)
        {
            lineage.insert(*new);
            retired.insert(author, idx);
            root_admitted.insert(*new, idx);
        }
    }
    lineage
}

fn authorize(
    vault: &VaultId,
    nodes: &[DagNode<'_>],
    chosen: &[usize],
    known_lineage: &BTreeSet<DeviceId>,
    rotation_ok: &[bool],
) -> Authority {
    let mut state = Authority::default();
    let mut cuts: BTreeMap<DeviceId, Vec<usize>> = BTreeMap::new();
    for &r_idx in chosen {
        if let Some(victim) = remove_target(nodes[r_idx].frame) {
            cuts.entry(victim).or_default().push(r_idx);
        }
    }
    let Some(genesis_idx) = nodes
        .iter()
        .position(|n| !n.void && is_genesis(vault, n.frame))
    else {
        return state;
    };
    let genesis = nodes[genesis_idx].frame;
    let genesis_author = genesis.header().author;
    let Some(MemberOp::Create { recovery_kem, .. }) =
        genesis.member_body().and_then(|b| b.op.as_ref())
    else {
        return state;
    };
    state.admissions.insert(genesis_author, vec![genesis_idx]);
    state.lineage.insert(genesis_author);
    state.lineage_order.push(genesis_author);
    state.kem_keys.insert(genesis_author, *recovery_kem);
    state.non_removal_frames.insert(genesis.id());

    for (idx, node) in nodes.iter().enumerate() {
        if idx == genesis_idx || node.void || !rotation_ok[idx] {
            continue;
        }
        let author = node.frame.header().author;
        let Some(body) = node.frame.member_body() else {
            continue;
        };
        let cut = cuts.get(&author).is_some_and(|removals| {
            removals
                .iter()
                .any(|&r_idx| r_idx != idx && !nodes[r_idx].saw(idx))
        });
        if cut {
            continue;
        }
        let retired = state
            .retired_roots
            .get(&author)
            .is_some_and(|&ret_idx| ret_idx != idx && !nodes[ret_idx].saw(idx));
        if retired || !state.admitted_before(&author, idx, nodes) {
            continue;
        }
        match &body.op {
            Some(MemberOp::Create { .. }) => {}
            Some(MemberOp::Add {
                device,
                kem,
                consent,
                ..
            }) => {
                // Re-adding a device whose removal this frame saw would hand the removed key
                // the post-removal epoch through the inline `Rewrap`.
                let readd = cuts
                    .get(device)
                    .is_some_and(|removals| removals.iter().any(|&r_idx| node.saw(r_idx)));
                if !known_lineage.contains(device) && !readd {
                    state.admissions.entry(*device).or_default().push(idx);
                    state.kem_keys.entry(*device).or_insert(*kem);
                    state.nets.entry(*device).or_insert(consent.net);
                    state.non_removal_frames.insert(node.frame.id());
                }
            }
            Some(MemberOp::Remove { device, .. }) => {
                if !known_lineage.contains(device) && state.admitted_before(device, idx, nodes) {
                    state.removals.insert(idx);
                }
            }
            Some(MemberOp::RotateRecovery { new, new_kem, .. }) => {
                if state.lineage.contains(&author)
                    && !state.retired_roots.contains_key(&author)
                    && !state.lineage.contains(new)
                    && !added_as_device(nodes, new, idx)
                {
                    state.lineage.insert(*new);
                    state.lineage_order.push(*new);
                    state.retired_roots.insert(author, idx);
                    state.admissions.entry(*new).or_default().push(idx);
                    state.kem_keys.insert(*new, *new_kem);
                    state.non_removal_frames.insert(node.frame.id());
                }
            }
            Some(MemberOp::Rewrap(_)) | None => {
                state.non_removal_frames.insert(node.frame.id());
            }
        }
    }
    state
}

fn choose_removals(
    vault: &VaultId,
    nodes: &[DagNode<'_>],
    structural: Authority,
    structural_lineage: &BTreeSet<DeviceId>,
    rotation_ok: &[bool],
) -> (Vec<usize>, Authority) {
    let mut candidates: Vec<usize> = structural.removals.iter().copied().collect();
    candidates.sort_by_key(|&idx| {
        let author = nodes[idx].frame.header().author;
        let class = u8::from(!structural_lineage.contains(&author));
        let first_idx = structural.admissions[&author][0];
        (
            class,
            nodes[first_idx].depth,
            nodes[first_idx].frame.id(),
            nodes[idx].depth,
            nodes[idx].frame.id(),
        )
    });
    let mut chosen: Vec<usize> = Vec::new();
    let mut current = structural;
    for candidate in candidates {
        let Some(victim) = remove_target(nodes[candidate].frame) else {
            continue;
        };
        if chosen.iter().any(|&winner| {
            remove_target(nodes[winner].frame) == Some(victim) && nodes[candidate].saw(winner)
        }) {
            continue;
        }
        let cuts_nothing = nodes.iter().enumerate().all(|(i, n)| {
            n.void
                || ((n.frame.header().author != victim
                    || i == candidate
                    || nodes[candidate].saw(i))
                    && !(n.saw(candidate) && adds_device(n.frame, &victim)))
        });
        if cuts_nothing {
            if current.removals.contains(&candidate)
                && !chosen.iter().any(|&winner| {
                    remove_target(nodes[winner].frame) == Some(victim)
                        && nodes[winner].saw(candidate)
                })
            {
                chosen.push(candidate);
            }
            continue;
        }
        chosen.push(candidate);
        let trial = authorize(vault, nodes, &chosen, structural_lineage, rotation_ok);
        let valid = chosen.iter().all(|&winner| {
            let Some(w_victim) = remove_target(nodes[winner].frame) else {
                return false;
            };
            trial.removals.contains(&winner)
                && !chosen.iter().any(|&other| {
                    other != winner
                        && remove_target(nodes[other].frame) == Some(w_victim)
                        && nodes[winner].saw(other)
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

/// Pairs of devices that removed each other, each with the removals between
/// them, unless a recovery-lineage (`class = 0`) removal of either one, made
/// after seeing every removal between them, has settled it.
fn find_mutual_removals(
    nodes: &[DagNode<'_>],
    structural: &Authority,
    lineage: &BTreeSet<DeviceId>,
) -> BTreeMap<(DeviceId, DeviceId), Vec<usize>> {
    let mut edges: BTreeMap<(DeviceId, DeviceId), Vec<usize>> = BTreeMap::new();
    let mut by_root: Vec<(usize, DeviceId)> = Vec::new();
    for &idx in &structural.removals {
        if let Some(victim) = remove_target(nodes[idx].frame) {
            let author = nodes[idx].frame.header().author;
            edges.entry((author, victim)).or_default().push(idx);
            if lineage.contains(&author) {
                by_root.push((idx, victim));
            }
        }
    }
    edges
        .keys()
        .copied()
        .filter(|&(a, b)| a < b && edges.contains_key(&(b, a)))
        .map(|(a, b)| {
            let between: Vec<usize> = edges[&(a, b)]
                .iter()
                .chain(&edges[&(b, a)])
                .copied()
                .collect();
            ((a, b), between)
        })
        .filter(|((a, b), between)| {
            !by_root.iter().any(|&(r, victim)| {
                (victim == *a || victim == *b) && between.iter().all(|&j| nodes[r].saw(j))
            })
        })
        .collect()
}

/// Whether the recovery root has acted since a mutual removal (a counted
/// `Add` or `Remove` by a lineage root that saw every removal `between`
/// the pair) and neither device of the pair is still active: no one is left
/// whose side needs a person to choose. A root's frame stays counted when it
/// hands the kit on, so a rotation never undoes the settlement.
fn settled_by_root(
    nodes: &[DagNode<'_>],
    lineage: &BTreeSet<DeviceId>,
    authorized: &BTreeSet<FrameId>,
    devices: &BTreeSet<DeviceId>,
    (a, b): (DeviceId, DeviceId),
    between: &[usize],
) -> bool {
    if devices.contains(&a) || devices.contains(&b) {
        return false;
    }
    nodes.iter().any(|n| {
        let author = n.frame.header().author;
        authorized.contains(&n.frame.id())
            && lineage.contains(&author)
            && matches!(
                n.frame.member_body().and_then(|b| b.op.as_ref()),
                Some(MemberOp::Add { .. } | MemberOp::Remove { .. })
            )
            && between.iter().all(|&j| n.saw(j))
    })
}

fn is_genesis(vault: &VaultId, frame: &Frame) -> bool {
    let h = frame.header();
    let Some(body) = frame.member_body() else {
        return false;
    };
    matches!(
        (&body.op, &body.rotate),
        (Some(MemberOp::Create { nonce, .. }), Some(rot))
            if h.seq == 0
                && h.prev.is_zero()
                && rot.wraps.iter().any(|(id, _)| *id == h.author)
                && body.deps.is_empty()
                && super::crypto::derive_vault_id(&h.author, nonce) == *vault
    )
}

fn adds_device(frame: &Frame, device: &DeviceId) -> bool {
    matches!(
        frame.member_body().and_then(|b| b.op.as_ref()),
        Some(MemberOp::Add { device: d, .. }) if d == device
    )
}

/// True iff some non-void `Add` of `device` as an ordinary device is in `past(idx)`: such a
/// device can never become a recovery root.
fn added_as_device(nodes: &[DagNode<'_>], device: &DeviceId, idx: usize) -> bool {
    nodes
        .iter()
        .enumerate()
        .any(|(j, n)| !n.void && nodes[idx].saw(j) && adds_device(n.frame, device))
}

fn remove_target(frame: &Frame) -> Option<DeviceId> {
    match frame.member_body().and_then(|b| b.op.as_ref()) {
        Some(MemberOp::Remove { device, .. }) => Some(*device),
        _ => None,
    }
}
