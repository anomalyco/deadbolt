//! Independent brute-force exponential reference model and `DEADBOLT_MEMBERSHIP_CASES`
//! property tests proving invariant I4 (order independence, `class = 0` recovery lineage,
//! `RotateRecovery`, and keyless `FraudProof` filtering).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use crate::id::{DeviceId, DeviceSecret, VaultId};

use super::super::*;

pub(super) struct TestPool {
    pub(super) roots: Vec<RecoverySecret>,
    pub(super) root_sks: Vec<DeviceSecret>,
    pub(super) devices: Vec<DeviceKeys>,
    pub(super) nonce: [u8; 32],
    pub(super) vault: VaultId,
}

pub(super) fn pool() -> &'static TestPool {
    static POOL: OnceLock<TestPool> = OnceLock::new();
    POOL.get_or_init(|| {
        let roots: Vec<_> = (0u8..4)
            .map(|i| RecoverySecret::from_bytes([100 + i; 32]))
            .collect();
        let root_sks: Vec<_> = roots.iter().map(RecoverySecret::signing_key).collect();
        let devices: Vec<_> = (0u8..5)
            .map(|i| DeviceKeys::from_seed(&[200 + i; 32]))
            .collect();
        let nonce = [0x77; 32];
        let vault = derive_vault_id(&roots[0].recovery_id(), &nonce);
        TestPool {
            roots,
            root_sks,
            devices,
            nonce,
            vault,
        }
    })
}

// ============================================================================
// Independent brute-force reference model (zero shared code with membership.rs)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
struct RefState {
    devices: BTreeSet<DeviceId>,
    active_recovery: Option<DeviceId>,
    recovery_frozen: bool,
    removed: BTreeMap<DeviceId, Option<u64>>,
    authorized_frames: BTreeSet<FrameId>,
}

struct RefGraph<'a> {
    frames: Vec<&'a Frame>,
    past: Vec<BTreeSet<usize>>,
    depth: Vec<u64>,
    void: Vec<bool>,
    rotation_ok: Vec<bool>,
    member_fork_seq: BTreeMap<DeviceId, u64>,
    data_fork_seq: BTreeMap<DeviceId, u64>,
    genesis: Option<usize>,
    lineage: BTreeSet<DeviceId>,
    lineage_order: Vec<DeviceId>,
    retired: BTreeMap<DeviceId, usize>,
}

type OuterForks<'a> = (&'a BTreeMap<DeviceId, u64>, &'a BTreeMap<DeviceId, u64>);

impl<'a> RefGraph<'a> {
    fn build(vault: VaultId, all_frames: &'a [Frame], proofs: &[FraudProof]) -> Self {
        Self::build_checked(
            vault,
            &all_frames.iter().collect::<Vec<_>>(),
            proofs,
            None,
            None,
        )
    }

    fn build_checked(
        vault: VaultId,
        all_frames: &[&'a Frame],
        proofs: &[FraudProof],
        outer_forks: Option<OuterForks<'_>>,
        checked: Option<&BTreeMap<FrameId, bool>>,
    ) -> Self {
        let mut member_fork_seq: BTreeMap<DeviceId, u64> = outer_forks
            .map(|(member, _)| member.clone())
            .unwrap_or_default();
        let mut data_fork_seq: BTreeMap<DeviceId, u64> = outer_forks
            .map(|(_, data)| data.clone())
            .unwrap_or_default();

        // Scan explicit proofs + all frame pairs directly (no detect_fraud_in_frames call).
        for p in proofs {
            if let Ok(v) = p.verify()
                && v.vault == vault
            {
                match v.log {
                    LogKind::Member => {
                        member_fork_seq
                            .entry(v.author)
                            .and_modify(|s| *s = (*s).min(v.seq))
                            .or_insert(v.seq);
                    }
                    LogKind::Data => {
                        data_fork_seq
                            .entry(v.author)
                            .and_modify(|s| *s = (*s).min(v.seq))
                            .or_insert(v.seq);
                    }
                }
            }
        }
        for i in 0..all_frames.len() {
            let hi = all_frames[i].header();
            if hi.vault != vault {
                continue;
            }
            for j in (i + 1)..all_frames.len() {
                let hj = all_frames[j].header();
                if hj.vault == vault
                    && hi.author == hj.author
                    && hi.kind.log_kind() == hj.kind.log_kind()
                    && hi.seq == hj.seq
                    && all_frames[i].id() != all_frames[j].id()
                {
                    match hi.kind.log_kind() {
                        LogKind::Member => {
                            member_fork_seq
                                .entry(hi.author)
                                .and_modify(|s| *s = (*s).min(hi.seq))
                                .or_insert(hi.seq);
                        }
                        LogKind::Data => {
                            data_fork_seq
                                .entry(hi.author)
                                .and_modify(|s| *s = (*s).min(hi.seq))
                                .or_insert(hi.seq);
                        }
                    }
                }
            }
        }

        // Deduplicate Member frames.
        let mut unique: BTreeMap<FrameId, &'a Frame> = BTreeMap::new();
        for f in all_frames {
            if f.header().vault == vault && f.header().kind == FrameKind::Member {
                unique.insert(f.id(), f);
            }
        }

        // Build causal graph directly by hash deps.
        let mut frames: Vec<&'a Frame> = Vec::new();
        let mut past: Vec<BTreeSet<usize>> = Vec::new();
        let mut depth: Vec<u64> = Vec::new();
        loop {
            let mut ready: Vec<&'a Frame> = unique
                .values()
                .copied()
                .filter(|f| !frames.iter().any(|x| x.id() == f.id()))
                .filter(|f| {
                    let h = f.header();
                    // Per-author continuity: seq 0, or `prev` is the same author's seq - 1,
                    // already placed (an implicit causal parent).
                    let prev_ok = h.seq == 0
                        || frames.iter().any(|x| {
                            x.id() == h.prev
                                && x.header().author == h.author
                                && x.header().seq.checked_add(1) == Some(h.seq)
                        });
                    prev_ok
                        && f.member_body().is_some_and(|b| {
                            b.deps.iter().all(|d| frames.iter().any(|x| x.id() == *d))
                        })
                })
                .collect();
            if ready.is_empty() {
                break;
            }
            ready.sort_by_key(|f| f.id());
            for f in ready {
                let body = f.member_body().unwrap();
                let mut pset = BTreeSet::new();
                let mut d = 0u64;
                let prev = (f.header().seq > 0).then_some(f.header().prev);
                for dep in body.deps.iter().chain(prev.iter()) {
                    let pidx = frames.iter().position(|x| x.id() == *dep).unwrap();
                    pset.insert(pidx);
                    pset.extend(&past[pidx]);
                    d = d.max(depth[pidx] + 1);
                }
                frames.push(f);
                past.push(pset);
                depth.push(d);
            }
        }

        let void: Vec<bool> = frames
            .iter()
            .map(|f| {
                member_fork_seq
                    .get(&f.header().author)
                    .is_some_and(|&s| f.header().seq >= s)
            })
            .collect();

        let genesis = (0..frames.len())
            .filter(|&i| {
                !void[i]
                    && frames[i].header().seq == 0
                    && frames[i].header().prev.is_zero()
                    && matches!(
                        frames[i].member_body(),
                        Some(MemberBody {
                            deps,
                            op: Some(MemberOp::Create { nonce, .. }),
                            rotate: Some(rot),
                        }) if rot.wraps.iter().any(|(id, _)| *id == frames[i].header().author)
                            && deps.is_empty() && derive_vault_id(&frames[i].header().author, nonce) == vault
                    )
            })
            .min_by_key(|&i| (depth[i], frames[i].id()));

        let rotation_ok = if let Some(checked) = checked {
            frames.iter().map(|f| checked[&f.id()]).collect::<Vec<_>>()
        } else {
            let mut checked = BTreeMap::new();
            let mut ok = Vec::new();
            for i in 0..frames.len() {
                let frame = frames[i];
                let body = frame.member_body().unwrap();
                let valid = if let Some(rot) = &body.rotate {
                    let leaving = match body.op {
                        Some(MemberOp::Remove { device, .. }) => Some(device),
                        Some(MemberOp::RotateRecovery { .. }) => Some(frame.header().author),
                        _ => None,
                    };
                    let covers_new = match body.op {
                        Some(MemberOp::Create { nonce, .. }) => {
                            frame.header().seq == 0
                                && frame.header().prev.is_zero()
                                && body.deps.is_empty()
                                && derive_vault_id(&frame.header().author, &nonce) == vault
                                && rot.wraps.iter().any(|(id, _)| *id == frame.header().author)
                        }
                        Some(MemberOp::RotateRecovery { new, .. }) => {
                            rot.wraps.iter().any(|(id, _)| *id == new)
                        }
                        _ => true,
                    };
                    let causal: Vec<_> = past[i].iter().map(|&j| frames[j]).collect();
                    let recipients = |state: RefState| {
                        state
                            .devices
                            .into_iter()
                            .chain(state.active_recovery)
                            .collect::<BTreeSet<_>>()
                    };
                    let unforked = recipients(
                        Self::build_checked(vault, &causal, &[], None, Some(&checked)).solve(),
                    );
                    let with_forks = (!member_fork_seq.is_empty() || !data_fork_seq.is_empty())
                        .then(|| {
                            recipients(
                                Self::build_checked(
                                    vault,
                                    &causal,
                                    &[],
                                    Some((&member_fork_seq, &data_fork_seq)),
                                    Some(&checked),
                                )
                                .solve(),
                            )
                        });
                    covers_new
                        && unforked
                            .iter()
                            .filter(|id| with_forks.as_ref().is_none_or(|f| f.contains(id)))
                            .all(|id| {
                                Some(*id) == leaving
                                    || rot.wraps.iter().any(|(recipient, _)| recipient == id)
                            })
                } else {
                    true
                };
                checked.insert(frame.id(), valid);
                ok.push(valid);
            }
            ok
        };

        // Compute pure recovery lineage chain in topological order.
        let mut lineage = BTreeSet::new();
        let mut lineage_order = Vec::new();
        let mut retired: BTreeMap<DeviceId, usize> = BTreeMap::new();
        let mut root_admit: BTreeMap<DeviceId, usize> = BTreeMap::new();
        if let Some(g) = genesis {
            let r0 = frames[g].header().author;
            lineage.insert(r0);
            lineage_order.push(r0);
            root_admit.insert(r0, g);
            let mut order: Vec<usize> = (0..frames.len()).collect();
            order.sort_by_key(|&i| (depth[i], frames[i].id()));
            for i in order {
                if i == g || void[i] || !rotation_ok[i] {
                    continue;
                }
                let author = frames[i].header().author;
                let Some(&admit) = root_admit.get(&author) else {
                    continue;
                };
                if !past[i].contains(&admit) {
                    continue;
                }
                if retired
                    .get(&author)
                    .is_some_and(|&r| r != i && !past[r].contains(&i))
                {
                    continue;
                }
                let added_as_device = |dev: &DeviceId| {
                    (0..frames.len()).any(|j| {
                        !void[j]
                            && past[i].contains(&j)
                            && matches!(
                                frames[j].member_body().and_then(|b| b.op.as_ref()),
                                Some(MemberOp::Add { device, .. }) if device == dev
                            )
                    })
                };
                if let Some(MemberOp::RotateRecovery { new, .. }) =
                    frames[i].member_body().and_then(|b| b.op.as_ref())
                    && !retired.contains_key(&author)
                    && !lineage.contains(new)
                    && !added_as_device(new)
                {
                    lineage.insert(*new);
                    lineage_order.push(*new);
                    retired.insert(author, i);
                    root_admit.insert(*new, i);
                }
            }
        }

        Self {
            frames,
            past,
            depth,
            void,
            rotation_ok,
            member_fork_seq,
            data_fork_seq,
            genesis,
            lineage,
            lineage_order,
            retired,
        }
    }

    fn op(&self, i: usize) -> Option<&MemberOp> {
        self.frames[i].member_body().and_then(|b| b.op.as_ref())
    }

    fn target(&self, r: usize) -> DeviceId {
        match self.op(r) {
            Some(MemberOp::Remove { device, .. }) => *device,
            _ => panic!("not a remove"),
        }
    }

    fn admissions(&self, dev: DeviceId) -> Vec<usize> {
        (0..self.frames.len())
            .filter(|&i| {
                if self.void[i] || !self.rotation_ok[i] {
                    return false;
                }
                match self.op(i) {
                    Some(MemberOp::Create { .. }) => {
                        self.genesis == Some(i) && self.frames[i].header().author == dev
                    }
                    Some(MemberOp::Add { device, .. }) => {
                        *device == dev && !self.lineage.contains(&dev)
                    }
                    Some(MemberOp::RotateRecovery { new, .. }) => {
                        *new == dev && self.lineage.contains(&dev)
                    }
                    _ => false,
                }
            })
            .collect()
    }

    fn authorized(&self, i: usize, chosen: &[usize]) -> bool {
        if self.void[i] || !self.rotation_ok[i] {
            return false;
        }
        if self.genesis == Some(i) {
            return true;
        }
        let author = self.frames[i].header().author;
        // Cut by chosen removal of author.
        if chosen
            .iter()
            .any(|&r| r != i && self.target(r) == author && !self.past[r].contains(&i))
        {
            return false;
        }
        // Self-retired recovery root.
        if self
            .retired
            .get(&author)
            .is_some_and(|&r| r != i && !self.past[r].contains(&i))
        {
            return false;
        }
        // Author must have an authorized admission in past(i).
        if !self.admitted(author, i, chosen) {
            return false;
        }
        match self.op(i) {
            Some(MemberOp::Create { .. }) => false,
            Some(MemberOp::Add { device, .. }) => {
                !self.lineage.contains(device)
                    && !chosen
                        .iter()
                        .any(|&r| self.target(r) == *device && self.past[i].contains(&r))
            }
            Some(MemberOp::Remove { device, .. }) => {
                !self.lineage.contains(device) && self.admitted(*device, i, chosen)
            }
            Some(MemberOp::RotateRecovery { new, .. }) => {
                self.retired.get(&author) == Some(&i) && self.lineage.contains(new)
            }
            Some(MemberOp::Rewrap(_)) | None => true,
        }
    }

    fn admitted(&self, dev: DeviceId, i: usize, chosen: &[usize]) -> bool {
        self.admissions(dev)
            .into_iter()
            .any(|a| self.past[i].contains(&a) && self.authorized(a, chosen))
    }

    fn seniority(&self, dev: DeviceId) -> Option<(u8, u64, FrameId)> {
        let class = u8::from(!self.lineage.contains(&dev));
        self.admissions(dev)
            .into_iter()
            .filter(|&a| self.authorized(a, &[]))
            .map(|a| (class, self.depth[a], self.frames[a].id()))
            .min()
    }

    fn valid(&self, removals: &[usize]) -> bool {
        removals.iter().all(|&r| {
            self.authorized(r, removals)
                && !removals.iter().any(|&other| {
                    other != r
                        && self.target(other) == self.target(r)
                        && self.past[r].contains(&other)
                })
        })
    }

    fn solve(&self) -> RefState {
        let mut order: Vec<usize> = (0..self.frames.len())
            .filter(|&i| {
                matches!(self.op(i), Some(MemberOp::Remove { .. })) && self.authorized(i, &[])
            })
            .collect();
        order.sort_by_key(|&r| {
            let rank = self.seniority(self.frames[r].header().author).unwrap();
            (rank, self.depth[r], self.frames[r].id())
        });
        assert!(order.len() <= 12, "reference model is exponential");
        let winners = (0..1usize << order.len())
            .rev()
            .map(|mask| {
                order
                    .iter()
                    .enumerate()
                    .filter(|(bit, _)| mask & (1 << (order.len() - 1 - bit)) != 0)
                    .map(|(_, &r)| r)
                    .collect::<Vec<_>>()
            })
            .find(|set| self.valid(set))
            .expect("empty set is always valid");

        let genesis_forked = (0..self.frames.len()).any(|i| {
            self.frames[i].header().seq == 0
                && matches!(self.op(i), Some(MemberOp::Create { .. }))
                && self.member_fork_seq.get(&self.frames[i].header().author) == Some(&0)
        });
        let retired_forked = self.retired.iter().any(|(root, &r)| {
            self.member_fork_seq
                .get(root)
                .is_some_and(|&s| s <= self.frames[r].header().seq)
        });
        let active_forked = self.lineage_order.last().is_some_and(|r| {
            self.member_fork_seq.contains_key(r) || self.data_fork_seq.contains_key(r)
        });
        let recovery_frozen = genesis_forked || retired_forked || active_forked;
        let active_recovery = if recovery_frozen {
            None
        } else {
            self.lineage_order.last().copied()
        };

        let mut devices: BTreeSet<DeviceId> = (0..self.frames.len())
            .filter(|&i| self.authorized(i, &winners))
            .filter_map(|i| match self.op(i) {
                Some(MemberOp::Add { device, .. }) => Some(*device),
                _ => None,
            })
            .collect();
        let mut removed: BTreeMap<DeviceId, Option<u64>> = BTreeMap::new();
        for &r in &winners {
            if let Some(MemberOp::Remove {
                device,
                last_seen_seq,
            }) = self.op(r)
            {
                devices.remove(device);
                let cutoff = removed.entry(*device).or_default();
                *cutoff = (*cutoff).max(*last_seen_seq);
            }
        }
        for (&author, &fork_seq) in &self.data_fork_seq {
            if self.lineage.contains(&author) {
                continue;
            }
            if devices.remove(&author) || removed.contains_key(&author) {
                let cap = fork_seq.checked_sub(1);
                removed
                    .entry(author)
                    .and_modify(|e| {
                        *e = match (*e, cap) {
                            (Some(a), Some(b)) => Some(a.min(b)),
                            _ => None,
                        };
                    })
                    .or_insert(cap);
            }
        }

        let mut authorized_frames = BTreeSet::new();
        for i in 0..self.frames.len() {
            match self.op(i) {
                Some(MemberOp::Remove { .. }) => {
                    if winners.contains(&i) {
                        authorized_frames.insert(self.frames[i].id());
                    }
                }
                _ => {
                    if self.authorized(i, &winners) {
                        authorized_frames.insert(self.frames[i].id());
                    }
                }
            }
        }

        RefState {
            devices,
            active_recovery,
            recovery_frozen,
            removed,
            authorized_frames,
        }
    }
}

pub(super) fn assert_matches_ref(
    vault: VaultId,
    frames: &[Frame],
    proofs: &[FraudProof],
) -> ResolvedMembership {
    let got = resolve(&vault, frames, proofs);
    let expected = RefGraph::build(vault, frames, proofs).solve();
    assert_eq!(got.devices, expected.devices, "devices mismatch");
    assert_eq!(
        got.active_recovery, expected.active_recovery,
        "active_recovery mismatch"
    );
    assert_eq!(
        got.recovery_frozen, expected.recovery_frozen,
        "recovery_frozen mismatch"
    );
    assert_eq!(got.removed, expected.removed, "removed mismatch");
    assert_eq!(
        got.authorized_frames, expected.authorized_frames,
        "authorized_frames mismatch"
    );
    got
}

pub(super) fn dummy_rotate(parents: Vec<EpochId>, recipient: DeviceId, tag: u8) -> Rotate {
    Rotate {
        suite: SUITE_X25519_WRAP,
        parents,
        commit: [tag; 32],
        back: Vec::new(),
        wraps: vec![(recipient, [tag; WRAP_LEN])],
    }
}

pub(super) fn shuffled<T: Clone>(items: &[T], mut seed: u64) -> Vec<T> {
    let mut out = items.to_vec();
    for i in (1..out.len()).rev() {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.swap(i, (seed as usize) % (i + 1));
    }
    out
}

// ============================================================================
// Named security tests for RotateRecovery, FraudProofs, and class = 0 lineage
// ============================================================================
