//! Deterministic folds of data frames: from genesis, from a checkpoint pack, and compaction.
//!
//! Every fold walks each author's data log as a gap-free `prev` chain, closes each frame's
//! clock transitively over the frames it names (see `causal`), and applies the ops of frames
//! the resolved membership counts. A frame naming a frame the fold cannot resolve waits.
//! Register merges are order-independent, so delivery order never matters.

use std::collections::{BTreeMap, BTreeSet};

use crate::id::DeviceId;

use super::causal::{Book, Closure, SeenBy};
use super::checkpoint::CheckpointError;
use super::crypto::FrameId;
use super::data::{DataBody, DataFrame, DataOp};
use super::frame::{Frame, FrameKind, MemberOp};
use super::membership::ResolvedMembership;
use super::pack::{Pack, PackMeta};
use super::state::FoldedState;

/// What a fold needs from the membership plane.
#[derive(Debug, Clone, Copy)]
pub struct FoldContext<'a> {
    pub membership: &'a ResolvedMembership,
    /// Device to the author of the authorized `Add` that added it.
    pub adders: &'a BTreeMap<DeviceId, DeviceId>,
}

impl FoldContext<'_> {
    /// True iff the membership counts this data-log frame.
    pub fn counts(&self, frame: &DataFrame) -> bool {
        self.membership
            .counts_data(&frame.author, frame.seq, frame.body.mheads())
    }

    /// A `DeviceCard` for `device` is valid from `device` itself or from its adder.
    pub fn card_ok(&self, author: &DeviceId, device: &DeviceId) -> bool {
        author == device || self.adders.get(device) == Some(author)
    }

    /// True iff every `DeviceCard` in the frame can be judged now: a third-party card needs
    /// a known adder, or a checkpoint could freeze a verdict a later `Add` would flip.
    fn decidable(&self, frame: &DataFrame) -> bool {
        let DataBody::Data(p) = &frame.body else {
            return true;
        };
        p.ops.iter().all(|op| match op {
            DataOp::DeviceCard { device, .. } => {
                *device == frame.author || self.adders.contains_key(device)
            }
            _ => true,
        })
    }
}

/// Maps each device to the author of the authorized `Add` frame that added it (lowest
/// `FrameId` if several).
pub fn adders_from_frames<'a>(
    membership: &ResolvedMembership,
    frames: impl IntoIterator<Item = &'a Frame>,
) -> BTreeMap<DeviceId, DeviceId> {
    let mut adds: Vec<(FrameId, DeviceId, DeviceId)> = frames
        .into_iter()
        .filter(|f| f.header().kind == FrameKind::Member)
        .filter(|f| membership.authorized_frames.contains(&f.id()))
        .filter_map(|f| match f.member_body()?.op.as_ref()? {
            MemberOp::Add { device, .. } => Some((f.id(), *device, f.header().author)),
            _ => None,
        })
        .collect();
    adds.sort();
    let mut out = BTreeMap::new();
    for (_, device, adder) in adds {
        out.entry(device).or_insert(adder);
    }
    out
}

/// Where an author's chain resumes: its next seq, the frame it must chain from, that frame's
/// closure, and the author's compacted frontier seq.
#[derive(Debug, Clone)]
struct Start {
    next: u64,
    prev: FrameId,
    closure: Closure,
    frontier: Option<u64>,
}

impl Default for Start {
    fn default() -> Self {
        Self {
            next: 0,
            prev: FrameId::ZERO,
            closure: Closure::default(),
            frontier: None,
        }
    }
}

type Chains<'f> = BTreeMap<DeviceId, Vec<(&'f DataFrame, Closure)>>;

fn starts_of(meta: &PackMeta) -> BTreeMap<DeviceId, Start> {
    meta.frontier
        .iter()
        .map(|(author, (seq, id))| {
            let mut closure = Closure {
                clock: meta.stream_clocks.get(author).cloned().unwrap_or_default(),
                ..Closure::default()
            };
            closure.note_pre(*author, *seq);
            let start = Start {
                next: seq.saturating_add(1),
                prev: *id,
                closure,
                frontier: Some(*seq),
            };
            (*author, start)
        })
        .collect()
}

/// The `(author, count)` streams a frame claims to have seen: a `Data` frame's `dclock`, or a
/// `Checkpoint` frame's frontier.
fn refs(f: &DataFrame) -> Vec<(DeviceId, u64)> {
    match &f.body {
        DataBody::Data(p) => p.dclock.entries().to_vec(),
        DataBody::Checkpoint(c) => c
            .frontier
            .iter()
            .map(|(a, s, _)| (*a, s.saturating_add(1)))
            .collect(),
    }
}

/// `f`'s closure, or `None` while some frame it names is neither compacted nor resolved (a
/// gap, a forged future count, or a cycle back through `f`).
fn close(f: &DataFrame, starts: &BTreeMap<DeviceId, Start>, done: &Chains<'_>) -> Option<Closure> {
    let mut closure = match done.get(&f.author).and_then(|c| c.last()) {
        Some((_, c)) => c.clone(),
        None => starts
            .get(&f.author)
            .map(|s| s.closure.clone())
            .unwrap_or_default(),
    };
    for (author, count) in refs(f) {
        let seq = count.checked_sub(1)?;
        closure.clock.raise(author, count);
        let start = starts.get(&author);
        if let Some(frontier) = start.and_then(|s| s.frontier)
            && seq <= frontier
        {
            closure.note_pre(author, seq);
            if seq == frontier
                && let Some(s) = start
            {
                closure.join(&s.closure);
            }
            continue;
        }
        let idx = seq.checked_sub(start.map_or(0, |s| s.next))?;
        let (_, named) = done.get(&author)?.get(usize::try_from(idx).ok()?)?;
        closure.join(named);
    }
    closure.clock.observe(f.author, f.seq);
    Some(closure)
}

/// Per author, the gap-free, fork-free `prev` chain from its start, each frame with its causal
/// closure, cut at the first frame that cannot be resolved yet. Frames at or below an author's
/// start are skipped; two different frames at one seq end the chain there (the fraud filter
/// removes forked streams anyway).
fn chains<'f>(
    frames: impl IntoIterator<Item = &'f DataFrame>,
    starts: &BTreeMap<DeviceId, Start>,
) -> Chains<'f> {
    let mut by_author: BTreeMap<DeviceId, BTreeMap<u64, Option<&'f DataFrame>>> = BTreeMap::new();
    for f in frames {
        if f.seq < starts.get(&f.author).map_or(0, |s| s.next) {
            continue;
        }
        let slot = by_author
            .entry(f.author)
            .or_default()
            .entry(f.seq)
            .or_insert(Some(f));
        if slot.is_some_and(|g| g.id != f.id) {
            *slot = None;
        }
    }
    let empty = Start::default();
    let raw: BTreeMap<DeviceId, Vec<&'f DataFrame>> = by_author
        .into_iter()
        .map(|(author, seqs)| {
            let start = starts.get(&author).unwrap_or(&empty);
            let (mut seq, mut prev) = (start.next, start.prev);
            let mut chain = Vec::new();
            while let Some(Some(f)) = seqs.get(&seq) {
                if f.prev != prev {
                    break;
                }
                chain.push(*f);
                prev = f.id;
                seq += 1;
            }
            (author, chain)
        })
        .collect();
    let mut done: Chains<'f> = raw.keys().map(|a| (*a, Vec::new())).collect();
    loop {
        let mut progress = false;
        for (author, chain) in &raw {
            while let Some(&f) = chain.get(done[author].len()) {
                let Some(closure) = close(f, starts, &done) else {
                    break;
                };
                if let Some(c) = done.get_mut(author) {
                    c.push((f, closure));
                }
                progress = true;
            }
        }
        if !progress {
            return done;
        }
    }
}

fn apply_chains(
    ctx: &FoldContext<'_>,
    state: &mut FoldedState,
    book: &mut Book<'_>,
    chains: &Chains<'_>,
) {
    for (f, closure) in chains.values().flatten() {
        book.insert((f.author, f.seq), closure.clone());
    }
    for (f, _) in chains.values().flatten() {
        if let DataBody::Data(p) = &f.body
            && ctx.counts(f)
        {
            state.apply(f.dot(), p, book, |a, d| ctx.card_ok(a, d));
        }
    }
}

/// Folds every counted data frame from genesis.
pub fn fold_from_scratch<'f>(
    ctx: &FoldContext<'_>,
    frames: impl IntoIterator<Item = &'f DataFrame>,
) -> FoldedState {
    let chains = chains(frames, &BTreeMap::new());
    let mut state = FoldedState::default();
    let seen_by = SeenBy::new();
    apply_chains(ctx, &mut state, &mut Book::new(&seen_by), &chains);
    state
}

/// Folds from genesis applying only the frames in `apply` (each a prefix of its author's log),
/// with every clock closed over all of `frames`; `None` while any of them cannot be resolved.
pub(crate) fn fold_subset<'f>(
    ctx: &FoldContext<'_>,
    frames: impl IntoIterator<Item = &'f DataFrame>,
    apply: &BTreeSet<FrameId>,
) -> Option<FoldedState> {
    let mut chains = chains(frames, &BTreeMap::new());
    let resolved = chains
        .values()
        .flatten()
        .filter(|(f, _)| apply.contains(&f.id))
        .count();
    if resolved != apply.len() {
        return None;
    }
    let seen_by = SeenBy::new();
    let mut book = Book::new(&seen_by);
    for (f, closure) in chains.values().flatten() {
        book.insert((f.author, f.seq), closure.clone());
    }
    for chain in chains.values_mut() {
        chain.retain(|(f, _)| apply.contains(&f.id));
    }
    let mut state = FoldedState::default();
    apply_chains(ctx, &mut state, &mut book, &chains);
    Some(state)
}

/// Fails if the membership no longer counts what the checkpoint covered, or a covered
/// `DeviceCard` would now be judged against a different adder.
pub fn check_still_valid(ctx: &FoldContext<'_>, meta: &PackMeta) -> Result<(), CheckpointError> {
    for (author, (seq, _)) in &meta.frontier {
        let heads: Vec<FrameId> = meta
            .mheads
            .get(author)
            .map(|h| h.iter().copied().collect())
            .unwrap_or_default();
        if !ctx.membership.counts_data(author, *seq, &heads) {
            return Err(CheckpointError::Invalidated(*author));
        }
    }
    for (device, adder) in &meta.card_adders {
        if ctx.adders.get(device) != Some(adder) {
            return Err(CheckpointError::AdderChanged(*device));
        }
    }
    Ok(())
}

/// Folds post-frontier and late frames onto a checkpoint pack. Frames at or below the
/// frontier are skipped, so the tail may include them or not.
pub fn fold_from_checkpoint<'f>(
    ctx: &FoldContext<'_>,
    pack: &Pack,
    tail: impl IntoIterator<Item = &'f DataFrame>,
) -> Result<FoldedState, CheckpointError> {
    pack.meta.validate(&pack.state)?;
    check_still_valid(ctx, &pack.meta)?;
    let chains = chains(tail, &starts_of(&pack.meta));
    let mut state = pack.state.clone();
    apply_chains(ctx, &mut state, &mut Book::new(&pack.meta.seen_by), &chains);
    Ok(state)
}

/// Compacts `base` (or genesis) plus the frames in `view` into a new pack. Each author's
/// frontier stops before its first frame that does not count or cannot be judged yet; those
/// frames stay in the tail.
pub fn compact<'f>(
    ctx: &FoldContext<'_>,
    base: Option<&Pack>,
    view: impl IntoIterator<Item = &'f DataFrame>,
) -> Result<Pack, CheckpointError> {
    let (mut state, mut meta) = match base {
        Some(pack) => {
            pack.meta.validate(&pack.state)?;
            check_still_valid(ctx, &pack.meta)?;
            (pack.state.clone(), pack.meta.clone())
        }
        None => (FoldedState::default(), PackMeta::default()),
    };
    let resolved = chains(view, &starts_of(&meta));
    let mut chains = resolved.clone();
    for chain in chains.values_mut() {
        let keep = chain
            .iter()
            .position(|(f, _)| !ctx.counts(f) || !ctx.decidable(f))
            .unwrap_or(chain.len());
        chain.truncate(keep);
    }
    let base_meta = meta.clone();
    let mut book = Book::new(&base_meta.seen_by);
    apply_chains(ctx, &mut state, &mut book, &chains);
    // Book closures for resolved frames left in the tail, so compacted frames' coverage of
    // them is recorded below.
    for (f, closure) in resolved.values().flatten() {
        book.insert((f.author, f.seq), closure.clone());
    }
    for (author, chain) in &chains {
        let Some((last, closure)) = chain.last() else {
            continue;
        };
        meta.frontier.insert(*author, (last.seq, last.id));
        meta.stream_clocks.insert(*author, closure.clock.clone());
        let heads = meta.mheads.entry(*author).or_default();
        for (f, _) in chain {
            heads.extend(f.body.mheads().iter().copied());
            if let DataBody::Data(p) = &f.body {
                for op in &p.ops {
                    if let DataOp::DeviceCard { device, .. } = op
                        && *device != f.author
                        && let Some(adder) = ctx.adders.get(device)
                    {
                        meta.card_adders.insert(*device, *adder);
                    }
                }
            }
        }
        if heads.is_empty() {
            meta.mheads.remove(author);
        }
    }
    let standing: BTreeSet<(DeviceId, u64)> = state.dots();
    meta.dots = standing
        .iter()
        .filter_map(|key| {
            let clock = match book.get(key) {
                Some(closure) => closure.clock.clone(),
                None => base_meta.dots.get(key)?.clone(),
            };
            Some((*key, clock))
        })
        .collect();
    let above =
        |(author, seq): &(DeviceId, u64)| meta.frontier.get(author).is_none_or(|(f, _)| seq > f);
    // Thresholds for every frame a later fold may still ask about: standing writes, resolved
    // tail frames, and earlier packs' tail frames still above the frontier.
    let targets: BTreeSet<(DeviceId, u64)> = standing
        .iter()
        .copied()
        .chain(resolved.values().flatten().map(|(f, _)| (f.author, f.seq)))
        .chain(base_meta.seen_by.keys().copied())
        .filter(|key| standing.contains(key) || above(key))
        .collect();
    meta.seen_by = targets
        .iter()
        .filter_map(|key| {
            let mut thresholds = base_meta.seen_by.get(key).cloned().unwrap_or_default();
            for (author, chain) in &chains {
                if thresholds.contains_key(author) {
                    continue;
                }
                if let Some((f, _)) = chain.iter().find(|(_, c)| book.closure_covers(c, *key)) {
                    thresholds.insert(*author, f.seq);
                }
            }
            (!thresholds.is_empty()).then_some((*key, thresholds))
        })
        .collect();
    meta.tombstones = state.tombstones();
    let pack = Pack { state, meta };
    pack.meta.validate(&pack.state)?;
    Ok(pack)
}
