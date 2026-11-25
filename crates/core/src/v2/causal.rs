//! Causal closure of data frames.
//!
//! Rule E7 keeps a writer's `dclock` honest about what it decrypted, not causally closed: a
//! device can have read `b0` (which saw `a0`) without having read `a0` itself. Register
//! merges need the transitive "happened before", so every fold closes each frame's clock over
//! the closures of the frames it names:
//! `closure(f) = closure(prev) ⊔ dclock(f) ⊔ {author: seq + 1} ⊔ ⨆ closure(d, c - 1)`.
//!
//! A frame naming `(d, c)` only resolves once `(d, c - 1)` is compacted or resolved itself, so
//! a forged future count (`u64::MAX`) or a cycle never resolves and is never applied.
//!
//! A checkpoint drops the closures of compacted frames. A later frame that names a compacted
//! frame records it in `pre`; whether that frame saw a given frame is answered by the pack's
//! [`SeenBy`] thresholds, so folding from a pack and from genesis agree exactly.

use std::collections::BTreeMap;

use crate::id::DeviceId;

use super::clock::VectorClock;

/// A data frame's transitive causal past as one fold sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Closure {
    /// Join of the frame's own clock and the closures of every held frame in its past.
    pub clock: VectorClock,
    /// Per author, the highest compacted (at or below the pack frontier) frame in its past.
    pub pre: BTreeMap<DeviceId, u64>,
}

impl Closure {
    /// Joins `other` into this closure.
    pub fn join(&mut self, other: &Self) {
        self.clock.join(&other.clock);
        for (&author, &seq) in &other.pre {
            self.note_pre(author, seq);
        }
    }

    /// Records that compacted frame `(author, seq)` is in this closure's past.
    pub fn note_pre(&mut self, author: DeviceId, seq: u64) {
        let slot = self.pre.entry(author).or_insert(seq);
        *slot = (*slot).max(seq);
    }
}

/// For each frame a later fold may still ask about (a standing write's frame, or a tail frame a
/// compacted frame saw), per author, the lowest compacted seq of that author whose closure saw
/// it. Closures are monotone along a log, so one threshold per author suffices.
pub type SeenBy = BTreeMap<(DeviceId, u64), BTreeMap<DeviceId, u64>>;

/// Closures of the frames a fold holds, plus the pack's thresholds for compacted ones.
pub(crate) struct Book<'a> {
    closures: BTreeMap<(DeviceId, u64), Closure>,
    seen_by: &'a SeenBy,
}

impl<'a> Book<'a> {
    pub(crate) const fn new(seen_by: &'a SeenBy) -> Self {
        Self {
            closures: BTreeMap::new(),
            seen_by,
        }
    }

    pub(crate) fn insert(&mut self, key: (DeviceId, u64), closure: Closure) {
        self.closures.insert(key, closure);
    }

    pub(crate) fn get(&self, key: &(DeviceId, u64)) -> Option<&Closure> {
        self.closures.get(key)
    }

    /// True iff `closure` saw frame `target`.
    pub(crate) fn closure_covers(&self, closure: &Closure, target: (DeviceId, u64)) -> bool {
        closure.clock.covers(&target.0, target.1)
            || self.seen_by.get(&target).is_some_and(|thresholds| {
                closure
                    .pre
                    .iter()
                    .any(|(author, seq)| thresholds.get(author).is_some_and(|t| seq >= t))
            })
    }

    /// True iff frame `holder` saw frame `target`. A holder with no closure here is a
    /// compacted frame, judged by the pack's thresholds.
    pub(crate) fn covers(&self, holder: (DeviceId, u64), target: (DeviceId, u64)) -> bool {
        match self.closures.get(&holder) {
            Some(c) => self.closure_covers(c, target),
            None => self
                .seen_by
                .get(&target)
                .and_then(|thresholds| thresholds.get(&holder.0))
                .is_some_and(|t| holder.1 >= *t),
        }
    }
}
