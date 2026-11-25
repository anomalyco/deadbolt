//! The causal DAG of `Member` frames: placement by hash `deps` plus the author's own `prev`,
//! per-author `(author, seq)` continuity, and each frame's transitive causal past.

use std::collections::{BTreeMap, BTreeSet};

use crate::id::DeviceId;

use super::crypto::FrameId;
use super::frame::Frame;

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

pub(super) struct DagNode<'a> {
    pub(super) frame: &'a Frame,
    pub(super) depth: u64,
    past: BitSet,
    pub(super) void: bool,
}

impl DagNode<'_> {
    pub(super) fn saw(&self, other_idx: usize) -> bool {
        self.past.contains(other_idx)
    }
}

/// The placed frames in canonical `(depth, id)` order, and the ids that could not be placed.
pub(super) struct Dag<'a> {
    pub(super) nodes: Vec<DagNode<'a>>,
    pub(super) unplaced: BTreeSet<FrameId>,
}

/// True iff `frame` continues its author's own log: seq 0, or `prev` names the same author's
/// frame at `seq - 1`. Without this a stolen key could sign many frames at unrelated seqs off
/// one old `prev` and never be caught equivocating.
fn continues_own_log(by_id: &BTreeMap<FrameId, &Frame>, frame: &Frame) -> bool {
    let h = frame.header();
    if h.seq == 0 {
        return true;
    }
    by_id.get(&h.prev).is_some_and(|prev| {
        let p = prev.header();
        p.author == h.author && p.seq.checked_add(1) == Some(h.seq)
    })
}

/// Hash `deps` plus, for `seq > 0`, the author's own `prev`.
fn causal_parents(frame: &Frame) -> impl Iterator<Item = &FrameId> {
    let h = frame.header();
    let prev = (h.seq > 0).then_some(&h.prev);
    frame
        .member_body()
        .into_iter()
        .flat_map(|b| b.deps.iter())
        .chain(prev)
}

/// Places every `Member` frame whose `deps` and `prev` are placed and whose `prev` continues
/// its author's log. A frame at or above its author's `Member` fork seq is `void`.
pub(super) fn build_dag<'a>(
    by_id: &BTreeMap<FrameId, &'a Frame>,
    member_fork_seq: &BTreeMap<DeviceId, u64>,
) -> Dag<'a> {
    let mut depth_map: BTreeMap<FrameId, u64> = BTreeMap::new();
    loop {
        let mut progress = false;
        for (&id, &frame) in by_id {
            if depth_map.contains_key(&id)
                || frame.member_body().is_none()
                || !continues_own_log(by_id, frame)
            {
                continue;
            }
            let mut depth = 0u64;
            let ready = causal_parents(frame).all(|dep| {
                depth_map.get(dep).is_some_and(|&d| {
                    depth = depth.max(d + 1);
                    true
                })
            });
            if ready {
                depth_map.insert(id, depth);
                progress = true;
            }
        }
        if !progress {
            break;
        }
    }
    let unplaced = by_id
        .keys()
        .filter(|id| !depth_map.contains_key(id))
        .copied()
        .collect();
    let mut ordered: Vec<(u64, FrameId, &'a Frame)> = depth_map
        .into_iter()
        .filter_map(|(id, depth)| by_id.get(&id).map(|&f| (depth, id, f)))
        .collect();
    ordered.sort_by_key(|&(depth, id, _)| (depth, id));

    let total = ordered.len();
    let index_of: BTreeMap<FrameId, usize> = ordered
        .iter()
        .enumerate()
        .map(|(idx, &(_, id, _))| (id, idx))
        .collect();
    let mut nodes: Vec<DagNode<'a>> = Vec::with_capacity(total);
    for (depth, _, frame) in ordered {
        let mut past = BitSet::new(total);
        for dep in causal_parents(frame) {
            if let Some(&dep_idx) = index_of.get(dep) {
                past.set(dep_idx);
                past.union_with(&nodes[dep_idx].past);
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
    Dag { nodes, unplaced }
}
