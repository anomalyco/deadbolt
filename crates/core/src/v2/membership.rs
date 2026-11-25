//! Deadbolt v2 membership resolver with `class = 0` recovery lineage,
//! fraud-proof filtering, and the back-dating parking rule.

use std::collections::{BTreeMap, BTreeSet};

use crate::id::{DeviceId, VaultId};

use super::crypto::{FrameId, KemPublic};
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
    /// All authorized `Member` frame IDs (chosen removals + authorized non-removal ops).
    pub authorized_frames: BTreeSet<FrameId>,
    /// Structurally authorized mutual removal pairs `(a, b)` with `a < b`, for parking detection.
    pub mutual_removals: BTreeSet<(DeviceId, DeviceId)>,
    /// Minimum `Member` fork seq per author (from fraud proofs and observed forks).
    pub member_fork_seq: BTreeMap<DeviceId, u64>,
    /// Minimum `Data` fork seq per author (from fraud proofs and observed forks).
    pub data_fork_seq: BTreeMap<DeviceId, u64>,
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

    /// True iff a data frame by `author` at `seq` with membership view `mheads` counts.
    pub fn counts_data(&self, author: &DeviceId, seq: u64, mheads: &[FrameId]) -> bool {
        if self.counted_through(author, seq) != Some(seq) {
            return false;
        }
        if let Some(descendants) = self.fork_descendants.get(author)
            && mheads.iter().any(|h| descendants.contains(h))
        {
            return false;
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

#[derive(Clone, Default)]
struct BitSet {
    words: Vec<u64>,
}

impl BitSet {
    fn new(bits: usize) -> Self {
        Self {
            words: vec![0u64; bits.div_ceil(64)],
        }
    }
    fn set(&mut self, bit: usize) {
        self.words[bit / 64] |= 1u64 << (bit % 64);
    }
    fn contains(&self, bit: usize) -> bool {
        (self.words[bit / 64] & (1u64 << (bit % 64))) != 0
    }
    fn union_with(&mut self, other: &Self) {
        for (dst, &src) in self.words.iter_mut().zip(other.words.iter()) {
            *dst |= src;
        }
    }
}

struct DagNode<'a> {
    frame: &'a Frame,
    depth: u64,
    past: BitSet,
    void: bool,
}

impl DagNode<'_> {
    fn saw(&self, other_idx: usize) -> bool {
        self.past.contains(other_idx)
    }
}

/// Resolves v2 membership from an unordered set of frames and keyless `FraudProof`s (invariant I4).
pub fn resolve<'a>(
    vault: &VaultId,
    frames: impl IntoIterator<Item = &'a Frame>,
    fraud_proofs: impl IntoIterator<Item = &'a FraudProof>,
) -> ResolvedMembership {
    let all_frames: Vec<&'a Frame> = frames
        .into_iter()
        .filter(|f| f.header().vault == *vault)
        .collect();

    let mut member_fork_seq: BTreeMap<DeviceId, u64> = BTreeMap::new();
    let mut data_fork_seq: BTreeMap<DeviceId, u64> = BTreeMap::new();
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

    let nodes = build_dag(&by_id, &member_fork_seq);
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

    let structural_lineage = compute_recovery_lineage(vault, &nodes);
    let structural = authorize(vault, &nodes, &[], &structural_lineage);
    let genesis_creator_forked = nodes.iter().any(|n| {
        n.frame.header().seq == 0
            && matches!(
                n.frame.member_body().and_then(|b| b.op.as_ref()),
                Some(MemberOp::Create { .. })
            )
            && member_fork_seq.get(&n.frame.header().author) == Some(&0)
    });
    let mutual_removals = find_mutual_removals(&nodes, &structural);
    let (chosen, authority) = choose_removals(vault, &nodes, structural, &structural_lineage);

    let recovery_frozen = genesis_creator_forked
        || authority
            .lineage_order
            .iter()
            .any(|root| member_fork_seq.contains_key(root) || data_fork_seq.contains_key(root));
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
        authorized_frames,
        mutual_removals,
        member_fork_seq,
        data_fork_seq,
        fork_descendants,
    }
}

fn build_dag<'a>(
    by_id: &BTreeMap<FrameId, &'a Frame>,
    member_fork_seq: &BTreeMap<DeviceId, u64>,
) -> Vec<DagNode<'a>> {
    let mut depth_map: BTreeMap<FrameId, u64> = BTreeMap::new();
    loop {
        let mut progress = false;
        for (&id, &frame) in by_id {
            if depth_map.contains_key(&id) {
                continue;
            }
            let Some(body) = frame.member_body() else {
                continue;
            };
            let mut max_dep = 0u64;
            let mut ready = true;
            for dep in &body.deps {
                if let Some(&d) = depth_map.get(dep) {
                    max_dep = max_dep.max(d + 1);
                } else {
                    ready = false;
                    break;
                }
            }
            if ready {
                depth_map.insert(id, max_dep);
                progress = true;
            }
        }
        if !progress {
            break;
        }
    }
    let mut ordered: Vec<(u64, FrameId, &'a Frame)> = depth_map
        .into_iter()
        .filter_map(|(id, depth)| by_id.get(&id).map(|&f| (depth, id, f)))
        .collect();
    ordered.sort_by_key(|&(depth, id, _)| (depth, id));

    let total = ordered.len();
    let mut index_of: BTreeMap<FrameId, usize> = BTreeMap::new();
    for (idx, &(_, id, _)) in ordered.iter().enumerate() {
        index_of.insert(id, idx);
    }
    let mut nodes: Vec<DagNode<'a>> = Vec::with_capacity(total);
    for (depth, _, frame) in ordered {
        let mut past = BitSet::new(total);
        if let Some(body) = frame.member_body() {
            for dep in &body.deps {
                if let Some(&dep_idx) = index_of.get(dep) {
                    past.set(dep_idx);
                    past.union_with(&nodes[dep_idx].past);
                }
            }
        }
        let h = frame.header();
        let void = member_fork_seq
            .get(&h.author)
            .is_some_and(|&fork_seq| h.seq >= fork_seq);
        nodes.push(DagNode {
            frame,
            depth,
            past,
            void,
        });
    }
    nodes
}

#[derive(Default)]
struct Authority {
    admissions: BTreeMap<DeviceId, Vec<usize>>,
    lineage: BTreeSet<DeviceId>,
    lineage_order: Vec<DeviceId>,
    retired_roots: BTreeMap<DeviceId, usize>,
    kem_keys: BTreeMap<DeviceId, KemPublic>,
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

fn compute_recovery_lineage(vault: &VaultId, nodes: &[DagNode<'_>]) -> BTreeSet<DeviceId> {
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
        if idx == genesis_idx || node.void {
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
        if idx == genesis_idx || node.void {
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
            Some(MemberOp::Add { device, kem, .. }) => {
                if !known_lineage.contains(device) {
                    state.admissions.entry(*device).or_default().push(idx);
                    state.kem_keys.entry(*device).or_insert(*kem);
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
            n.void || n.frame.header().author != victim || i == candidate || nodes[candidate].saw(i)
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
        let trial = authorize(vault, nodes, &chosen, structural_lineage);
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

fn find_mutual_removals(
    nodes: &[DagNode<'_>],
    structural: &Authority,
) -> BTreeSet<(DeviceId, DeviceId)> {
    let mut edges: BTreeSet<(DeviceId, DeviceId)> = BTreeSet::new();
    for &idx in &structural.removals {
        if let Some(victim) = remove_target(nodes[idx].frame) {
            edges.insert((nodes[idx].frame.header().author, victim));
        }
    }
    edges
        .iter()
        .copied()
        .filter(|&(a, b)| a < b && edges.contains(&(b, a)))
        .collect()
}

fn is_genesis(vault: &VaultId, frame: &Frame) -> bool {
    let h = frame.header();
    let Some(body) = frame.member_body() else {
        return false;
    };
    matches!(
        (&body.op, &body.rotate),
        (Some(MemberOp::Create { nonce, .. }), Some(_))
            if h.seq == 0
                && h.prev.is_zero()
                && body.deps.is_empty()
                && super::crypto::derive_vault_id(&h.author, nonce) == *vault
    )
}

fn remove_target(frame: &Frame) -> Option<DeviceId> {
    match frame.member_body().and_then(|b| b.op.as_ref()) {
        Some(MemberOp::Remove { device, .. }) => Some(*device),
        _ => None,
    }
}
