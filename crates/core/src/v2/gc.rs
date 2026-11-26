//! When to checkpoint, and the implicit-ack GC planner.
//!
//! There is no ack object: a member's data clock covering a checkpoint frame is its ack.
//! An undisputed checkpoint becomes GC-eligible once every current member's clock covers
//! it, or once this peer has known it for `GC_GRACE_MS` so a lost device never wedges
//! compaction. A checkpoint any current member disputed is never eligible.
//!
//! Every time here is this peer's own clock: an author's wire `timestamp_ms` could be forged
//! to `0` (instant GC) or `u64::MAX` (pinned forever), so it never decides grace or the base.
//! Callers pass only checkpoints they verified (`CheckpointVerdict::Agreed`); the planner
//! re-checks each against the current membership, since a later removal, fork or voided epoch
//! invalidates a checkpoint that was agreed when it was verified.
//!
//! Deleting frames is the one step no peer can undo, so the base must also cover every frame
//! any earlier GC (by this or any other device) may already have collected, and a `Remove`
//! built after a GC must not cut its victim below what was collected
//! ([`removal_last_seen`]).

use std::collections::{BTreeMap, BTreeSet};

use crate::id::{DeviceId, ItemId};

use super::clock::VectorClock;
use super::crypto::FrameId;
use super::fold::check_counts;
use super::membership::ResolvedMembership;
use super::pack::PackMeta;
use super::state::{DisputeRecord, Tombstone};

/// Checkpoint once the uncompacted tail reaches 1 MiB…
pub const CHECKPOINT_TRIGGER_BYTES: u64 = 1_048_576;
/// …or 500 frames.
pub const CHECKPOINT_TRIGGER_FRAMES: u64 = 500;
/// Dispute window and GC fallback: 30 days.
pub const GC_GRACE_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// True iff the tail is big enough to compact.
pub const fn should_checkpoint(tail_bytes: u64, tail_frames: u64) -> bool {
    tail_bytes >= CHECKPOINT_TRIGGER_BYTES || tail_frames >= CHECKPOINT_TRIGGER_FRAMES
}

/// A checkpoint as the GC planner sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcCheckpoint {
    pub id: FrameId,
    pub author: DeviceId,
    pub seq: u64,
    /// When this peer first saw the checkpoint, on its own clock.
    pub first_seen_ms: u64,
    /// Its pack's meta: the frontier, the tombstones it carries, and the membership heads and
    /// epochs its covered frames relied on.
    pub meta: PackMeta,
}

/// A remote data-log object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GcFrame {
    pub id: FrameId,
    pub author: DeviceId,
    pub seq: u64,
}

/// Why a checkpoint is GC-eligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eligibility {
    /// Every current member's clock covers it.
    Covered,
    /// This peer has known it for at least `GC_GRACE_MS`.
    Grace,
}

/// What may be deleted now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcPlan {
    /// Checkpoints some current member disputed: never covered, adopted or collected.
    pub disputed: BTreeSet<FrameId>,
    /// Checkpoints the current membership no longer counts (`check_counts`): never a base.
    pub invalidated: BTreeSet<FrameId>,
    /// Undisputed, still-valid checkpoints that are GC-eligible, and why.
    pub eligible: BTreeMap<FrameId, Eligibility>,
    /// The eligible checkpoint covering the most frames, by `(covered frames, id)`, among those
    /// whose frontier covers everything already collected: the new base.
    pub base: Option<FrameId>,
    /// Frames at or below the base's frontier, safe to delete.
    pub delete_frames: Vec<FrameId>,
    /// Collected floors (`author -> seq`) that no undisputed, still-valid checkpoint covers:
    /// frames already deleted that no surviving checkpoint can rebuild, after two devices
    /// collected behind different bases or a removal cut its victim below what was collected.
    /// Nothing is deleted; raise it for a human.
    pub stranded: BTreeMap<DeviceId, u64>,
    /// Tombstones in the base pack past their grace (`GC_GRACE_MS` since the delete and since
    /// this peer first saw the base). Candidates only: nothing prunes folded state locally, so
    /// `state_mac` stays a pure function of the log until a logged purge op exists.
    pub expired_tombstones: BTreeMap<ItemId, Tombstone>,
}

/// Frames a frontier covers, for choosing the base without trusting any timestamp.
fn covered_frames(c: &GcCheckpoint) -> u128 {
    c.meta
        .frontier
        .values()
        .map(|(s, _)| u128::from(*s) + 1)
        .sum()
}

/// True iff the checkpoint's frontier reaches `seq` of `author`.
fn reaches(c: &GcCheckpoint, author: &DeviceId, seq: u64) -> bool {
    c.meta.frontier.get(author).is_some_and(|(f, _)| *f >= seq)
}

/// The `last_seen_seq` for a `Remove` of `victim`: the highest of its frames this device
/// holds, raised to what any GC already collected (`collected`, as for [`plan_gc`]). A device
/// that collected a victim's frames no longer holds them, and a lower cutoff would invalidate
/// every checkpoint covering them after the frames themselves are gone.
pub fn removal_last_seen(
    victim: &DeviceId,
    held: Option<u64>,
    collected: &BTreeMap<DeviceId, u64>,
) -> Option<u64> {
    held.max(collected.get(victim).copied())
}

/// Plans GC from what this peer knows. The current members are `membership.devices`; with
/// none, nothing is eligible, since an empty "every member covered it" must never be vacuously
/// true. `collected` is the highest data seq per author that any earlier GC may already have
/// deleted (this peer's adopted base frontier and the store's compacted floors).
pub fn plan_gc(
    now_ms: u64,
    membership: &ResolvedMembership,
    member_clocks: &BTreeMap<DeviceId, VectorClock>,
    checkpoints: &[GcCheckpoint],
    disputes: &BTreeSet<DisputeRecord>,
    frames: &[GcFrame],
    collected: &BTreeMap<DeviceId, u64>,
) -> GcPlan {
    let current_members = &membership.devices;
    let disputed: BTreeSet<FrameId> = disputes
        .iter()
        .filter(|d| current_members.contains(&d.author))
        .map(|d| d.checkpoint)
        .filter(|id| checkpoints.iter().any(|c| c.id == *id))
        .collect();
    let invalidated: BTreeSet<FrameId> = checkpoints
        .iter()
        .filter(|c| check_counts(membership, &c.meta).is_err())
        .map(|c| c.id)
        .collect();
    let standing = |c: &&GcCheckpoint| !disputed.contains(&c.id) && !invalidated.contains(&c.id);
    let stranded: BTreeMap<DeviceId, u64> = collected
        .iter()
        .filter(|(author, seq)| {
            !checkpoints
                .iter()
                .filter(standing)
                .any(|c| reaches(c, author, **seq))
        })
        .map(|(a, s)| (*a, *s))
        .collect();
    let mut plan = GcPlan {
        disputed: disputed.clone(),
        invalidated: invalidated.clone(),
        stranded,
        ..GcPlan::default()
    };
    if current_members.is_empty() {
        return plan;
    }
    for c in checkpoints.iter().filter(standing) {
        let covered = current_members.iter().all(|m| {
            member_clocks
                .get(m)
                .is_some_and(|clock| clock.covers(&c.author, c.seq))
        });
        if covered {
            plan.eligible.insert(c.id, Eligibility::Covered);
        } else if now_ms.saturating_sub(c.first_seen_ms) >= GC_GRACE_MS {
            plan.eligible.insert(c.id, Eligibility::Grace);
        }
    }
    let base = checkpoints
        .iter()
        .filter(|c| plan.eligible.contains_key(&c.id))
        .filter(|c| collected.iter().all(|(a, s)| reaches(c, a, *s)))
        .max_by_key(|c| (covered_frames(c), c.id));
    let Some(base) = base else {
        return plan;
    };
    let protected: BTreeSet<FrameId> = disputed.iter().copied().chain([base.id]).collect();
    let mut delete_frames: Vec<FrameId> = frames
        .iter()
        .filter(|f| !protected.contains(&f.id))
        .filter(|f| reaches(base, &f.author, f.seq))
        .map(|f| f.id)
        .collect();
    delete_frames.sort();
    delete_frames.dedup();
    let base_aged = now_ms.saturating_sub(base.first_seen_ms) >= GC_GRACE_MS;
    plan.expired_tombstones = base
        .meta
        .tombstones
        .iter()
        .filter(|(_, t)| {
            base_aged
                && now_ms.saturating_sub(t.at_ms) >= GC_GRACE_MS
                && reaches(base, &t.dot.author, t.dot.seq)
        })
        .map(|(id, t)| (*id, *t))
        .collect();
    plan.base = Some(base.id);
    plan.delete_frames = delete_frames;
    plan
}
