//! Deterministic folds of data frames: from genesis, from a checkpoint pack, and compaction.
//!
//! Every fold walks each author's data log as a gap-free `prev` chain, rebuilds each frame's
//! full clock from its `dclock`, and applies the ops of frames the resolved membership
//! counts. Register merges are order-independent, so delivery order never matters.

use std::collections::BTreeMap;

use crate::id::DeviceId;

use super::checkpoint::CheckpointError;
use super::clock::VectorClock;
use super::crypto::FrameId;
use super::data::{DataBody, DataFrame, DataOp};
use super::frame::{Frame, FrameKind, MemberOp};
use super::membership::ResolvedMembership;
use super::pack::{Pack, PackMeta};
use super::state::{ClockBook, FoldedState};

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

/// Where an author's chain resumes: its next seq, the frame it must chain from, and that
/// frame's full clock.
#[derive(Debug, Clone)]
struct Start {
    next: u64,
    prev: FrameId,
    clock: VectorClock,
}

impl Default for Start {
    fn default() -> Self {
        Self {
            next: 0,
            prev: FrameId::ZERO,
            clock: VectorClock::new(),
        }
    }
}

type Chains<'f> = BTreeMap<DeviceId, Vec<(&'f DataFrame, VectorClock)>>;

fn starts_of(meta: &PackMeta) -> BTreeMap<DeviceId, Start> {
    meta.frontier
        .iter()
        .map(|(author, (seq, id))| {
            let start = Start {
                next: seq.saturating_add(1),
                prev: *id,
                clock: meta.stream_clocks.get(author).cloned().unwrap_or_default(),
            };
            (*author, start)
        })
        .collect()
}

/// Per author, the gap-free, fork-free `prev` chain from its start, each with its full clock.
/// Frames at or below an author's start are skipped; two different frames at one seq end the
/// chain there (the fraud filter removes forked streams anyway).
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
    by_author
        .into_iter()
        .map(|(author, seqs)| {
            let start = starts.get(&author).unwrap_or(&empty);
            let (mut seq, mut prev, mut clock) = (start.next, start.prev, start.clock.clone());
            let mut chain = Vec::new();
            while let Some(Some(f)) = seqs.get(&seq) {
                if f.prev != prev {
                    break;
                }
                clock = f.clock_after(&clock);
                chain.push((*f, clock.clone()));
                prev = f.id;
                seq += 1;
            }
            (author, chain)
        })
        .collect()
}

fn apply_chains(
    ctx: &FoldContext<'_>,
    state: &mut FoldedState,
    book: &mut ClockBook,
    chains: &Chains<'_>,
) {
    for (f, clock) in chains.values().flatten() {
        book.insert((f.author, f.seq), clock.clone());
    }
    for (f, clock) in chains.values().flatten() {
        if let DataBody::Data(p) = &f.body
            && ctx.counts(f)
        {
            state.apply(f.dot(), p, clock, book, |a, d| ctx.card_ok(a, d));
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
    apply_chains(ctx, &mut state, &mut ClockBook::new(), &chains);
    state
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
    let mut book = pack.meta.dots.clone();
    apply_chains(ctx, &mut state, &mut book, &chains);
    Ok(state)
}

/// Compacts `base` (or genesis) plus the frames in `view` into a new pack. Each author's
/// frontier stops before its first frame that does not count or cannot be judged yet;
/// those frames stay in the tail.
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
    let mut chains = chains(view, &starts_of(&meta));
    for chain in chains.values_mut() {
        let keep = chain
            .iter()
            .position(|(f, _)| !ctx.counts(f) || !ctx.decidable(f))
            .unwrap_or(chain.len());
        chain.truncate(keep);
    }
    let mut book = std::mem::take(&mut meta.dots);
    apply_chains(ctx, &mut state, &mut book, &chains);
    for (author, chain) in &chains {
        let Some((last, clock)) = chain.last() else {
            continue;
        };
        meta.frontier.insert(*author, (last.seq, last.id));
        meta.stream_clocks.insert(*author, clock.clone());
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
    meta.dots = state
        .dots()
        .into_iter()
        .filter_map(|key| Some((key, book.remove(&key)?)))
        .collect();
    meta.tombstones = state.tombstones();
    let pack = Pack { state, meta };
    pack.meta.validate(&pack.state)?;
    Ok(pack)
}
