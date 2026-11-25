//! Vector clocks, delta clocks (`dclock`), dots and strict causal comparison.
//!
//! Frame seqs start at 0, so a clock entry is a **count**: `clock[a] = n` means the clock
//! has seen data frames `0..n` of author `a`. Zero entries are omitted, so a missing
//! entry and "saw nothing" are the same thing. A frame `(a, s)` is covered by a clock iff
//! `clock[a] > s`, which is the plan's `clock[a] >= s` written for 0-based seqs.
//!
//! Reconstruction: `clock(f) = clock(prev) ⊔ dclock(f) ⊔ {f.author: f.seq + 1}`.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::id::DeviceId;

use super::crypto::FrameId;
use super::wire::{PayloadError, Reader, Writer, ascending};

/// A canonical full vector clock over the data streams of a vault.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct VectorClock(BTreeMap<DeviceId, u64>);

impl VectorClock {
    /// The empty clock (has seen nothing).
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Builds a clock from `(author, count)` pairs, dropping zero counts and keeping maxima.
    pub fn from_counts(entries: impl IntoIterator<Item = (DeviceId, u64)>) -> Self {
        let mut clock = Self::new();
        for (author, count) in entries {
            clock.raise(author, count);
        }
        clock
    }

    /// Number of frames of `author` this clock has seen (`0` if none).
    pub fn get(&self, author: &DeviceId) -> u64 {
        self.0.get(author).copied().unwrap_or(0)
    }

    /// True iff this clock has seen frame `(author, seq)`.
    pub fn covers(&self, author: &DeviceId, seq: u64) -> bool {
        self.get(author) > seq
    }

    /// Raises `author`'s entry to at least `count`.
    pub fn raise(&mut self, author: DeviceId, count: u64) {
        if count == 0 {
            return;
        }
        let slot = self.0.entry(author).or_insert(0);
        *slot = (*slot).max(count);
    }

    /// Marks frame `(author, seq)` as seen.
    pub fn observe(&mut self, author: DeviceId, seq: u64) {
        self.raise(author, seq.saturating_add(1));
    }

    /// Pointwise maximum with `other`.
    pub fn join(&mut self, other: &Self) {
        for (&author, &count) in &other.0 {
            self.raise(author, count);
        }
    }

    /// Pointwise maximum with a delta clock.
    pub fn join_delta(&mut self, delta: &DeltaClock) {
        for &(author, count) in delta.entries() {
            self.raise(author, count);
        }
    }

    /// True iff this clock is pointwise `>=` `other`.
    pub fn dominates(&self, other: &Self) -> bool {
        other.0.iter().all(|(a, &n)| self.get(a) >= n)
    }

    /// Canonical `(author, count)` entries in ascending author order.
    pub fn iter(&self) -> impl Iterator<Item = (&DeviceId, &u64)> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn encode(&self, w: &mut Writer) -> Result<(), PayloadError> {
        w.count(self.0.len(), "clock")?;
        for (author, &count) in &self.0 {
            w.device(author);
            w.u64(count);
        }
        Ok(())
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Self, PayloadError> {
        let entries = decode_entries(r, "clock")?;
        Ok(Self(entries.into_iter().collect()))
    }
}

/// The data streams that advanced since the author's `prev` frame: strictly sorted by
/// author, unique, and with non-zero counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct DeltaClock(Vec<(DeviceId, u64)>);

impl DeltaClock {
    /// Validates canonical form: strictly ascending authors and non-zero counts.
    pub fn new(entries: Vec<(DeviceId, u64)>) -> Result<Self, PayloadError> {
        let mut prev = None;
        for (author, count) in &entries {
            ascending(prev, author, "dclock")?;
            if *count == 0 {
                return Err(PayloadError::Invalid("dclock count must be non-zero"));
            }
            prev = Some(author);
        }
        Ok(Self(entries))
    }

    pub fn entries(&self) -> &[(DeviceId, u64)] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn encode(&self, w: &mut Writer) -> Result<(), PayloadError> {
        w.count(self.0.len(), "dclock")?;
        for (author, count) in &self.0 {
            w.device(author);
            w.u64(*count);
        }
        Ok(())
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Self, PayloadError> {
        Ok(Self(decode_entries(r, "dclock")?))
    }
}

fn decode_entries(
    r: &mut Reader<'_>,
    what: &'static str,
) -> Result<Vec<(DeviceId, u64)>, PayloadError> {
    let len = r.count(40, what)?;
    let mut out: Vec<(DeviceId, u64)> = Vec::with_capacity(len);
    for _ in 0..len {
        let author = r.device()?;
        ascending(out.last().map(|(a, _)| a), &author, what)?;
        let count = r.u64()?;
        if count == 0 {
            return Err(PayloadError::Invalid("clock count must be non-zero"));
        }
        out.push((author, count));
    }
    Ok(out)
}

/// The minimal delta a writer emits: every entry where `current` is ahead of `prev`.
pub fn diff_clock(prev: &VectorClock, current: &VectorClock) -> DeltaClock {
    DeltaClock(
        current
            .iter()
            .filter(|(a, n)| **n > prev.get(a))
            .map(|(a, n)| (*a, *n))
            .collect(),
    )
}

/// Full clock of a data frame: `clock(prev) ⊔ dclock ⊔ {author: seq + 1}`.
pub fn frame_clock(
    prev: &VectorClock,
    delta: &DeltaClock,
    author: DeviceId,
    seq: u64,
) -> VectorClock {
    let mut clock = prev.clone();
    clock.join_delta(delta);
    clock.observe(author, seq);
    clock
}

/// One data frame's position: its author, its seq in the author's data log, and its id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dot {
    pub author: DeviceId,
    pub seq: u64,
    pub frame: FrameId,
}

impl Dot {
    pub(crate) fn encode(&self, w: &mut Writer) {
        w.device(&self.author);
        w.u64(self.seq);
        w.frame_id(&self.frame);
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Self, PayloadError> {
        Ok(Self {
            author: r.device()?,
            seq: r.u64()?,
            frame: r.frame_id()?,
        })
    }
}

/// Strict causal relation between two dots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Causality {
    /// Same frame.
    Equal,
    /// The first dot happened before the second.
    Before,
    /// The first dot happened after the second.
    After,
    /// Neither saw the other.
    Concurrent,
}

/// True iff `a` strictly happened before `b`, using only `b`'s full clock.
pub fn happened_before(a: &Dot, b: &Dot, b_clock: &VectorClock) -> bool {
    !(a.author == b.author && a.seq == b.seq) && b_clock.covers(&a.author, a.seq)
}

/// Compares two dots given each one's full clock; needs no other frame.
pub fn compare(a: (&Dot, &VectorClock), b: (&Dot, &VectorClock)) -> Causality {
    if a.0.author == b.0.author && a.0.seq == b.0.seq {
        return Causality::Equal;
    }
    match (
        happened_before(a.0, b.0, b.1),
        happened_before(b.0, a.0, a.1),
    ) {
        (true, false) => Causality::Before,
        (false, true) => Causality::After,
        _ => Causality::Concurrent,
    }
}

/// Deterministic total order for concurrent dots: `(author, seq, frame_id)`.
pub fn tie_break(a: &Dot, b: &Dot) -> Ordering {
    a.cmp(b)
}
