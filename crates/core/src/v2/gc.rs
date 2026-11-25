//! When to checkpoint, and the implicit-ack GC planner.
//!
//! There is no ack object: a member's data clock covering a checkpoint frame is its ack.
//! An undisputed checkpoint becomes GC-eligible once every current member's clock covers
//! it, or once this peer has known it for `GC_GRACE_MS` so a lost device never wedges
//! compaction. A checkpoint any current member disputed is never eligible.
//!
//! Every time here is this peer's own clock: an author's wire `timestamp_ms` could be forged
//! to `0` (instant GC) or `u64::MAX` (pinned forever), so it never decides grace or the base.
//! Callers pass only checkpoints they verified (`CheckpointVerdict::Agreed`).

use std::collections::{BTreeMap, BTreeSet};

use crate::id::{DeviceId, ItemId};

use super::clock::VectorClock;
use super::crypto::FrameId;
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
    pub frontier: BTreeMap<DeviceId, (u64, FrameId)>,
    /// The tombstones its pack carries.
    pub tombstones: BTreeMap<ItemId, Tombstone>,
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
    /// Undisputed checkpoints that are GC-eligible, and why.
    pub eligible: BTreeMap<FrameId, Eligibility>,
    /// The eligible checkpoint covering the most frames, by `(covered frames, id)`: the new base.
    pub base: Option<FrameId>,
    /// Frames at or below the base's frontier, safe to delete.
    pub delete_frames: Vec<FrameId>,
    /// Tombstones in the base pack past their grace (`GC_GRACE_MS` since the delete and since
    /// this peer first saw the base). Candidates only: nothing prunes folded state locally, so
    /// `state_mac` stays a pure function of the log until a logged purge op exists.
    pub expired_tombstones: BTreeMap<ItemId, Tombstone>,
}

/// Frames a frontier covers, for choosing the base without trusting any timestamp.
fn covered_frames(c: &GcCheckpoint) -> u128 {
    c.frontier.values().map(|(s, _)| u128::from(*s) + 1).sum()
}

/// Plans GC from what this peer knows. With no current members nothing is eligible: an empty
/// "every member covered it" must never be vacuously true.
pub fn plan_gc(
    now_ms: u64,
    current_members: &BTreeSet<DeviceId>,
    member_clocks: &BTreeMap<DeviceId, VectorClock>,
    checkpoints: &[GcCheckpoint],
    disputes: &BTreeSet<DisputeRecord>,
    frames: &[GcFrame],
) -> GcPlan {
    let disputed: BTreeSet<FrameId> = disputes
        .iter()
        .filter(|d| current_members.contains(&d.author))
        .map(|d| d.checkpoint)
        .filter(|id| checkpoints.iter().any(|c| c.id == *id))
        .collect();
    let mut eligible = BTreeMap::new();
    if current_members.is_empty() {
        return GcPlan {
            disputed,
            ..GcPlan::default()
        };
    }
    for c in checkpoints {
        if disputed.contains(&c.id) {
            continue;
        }
        let covered = current_members.iter().all(|m| {
            member_clocks
                .get(m)
                .is_some_and(|clock| clock.covers(&c.author, c.seq))
        });
        if covered {
            eligible.insert(c.id, Eligibility::Covered);
        } else if now_ms.saturating_sub(c.first_seen_ms) >= GC_GRACE_MS {
            eligible.insert(c.id, Eligibility::Grace);
        }
    }
    let base = checkpoints
        .iter()
        .filter(|c| eligible.contains_key(&c.id))
        .max_by_key(|c| (covered_frames(c), c.id));
    let Some(base) = base else {
        return GcPlan {
            disputed,
            eligible,
            ..GcPlan::default()
        };
    };
    let protected: BTreeSet<FrameId> = disputed.iter().copied().chain([base.id]).collect();
    let mut delete_frames: Vec<FrameId> = frames
        .iter()
        .filter(|f| !protected.contains(&f.id))
        .filter(|f| {
            base.frontier
                .get(&f.author)
                .is_some_and(|(s, _)| f.seq <= *s)
        })
        .map(|f| f.id)
        .collect();
    delete_frames.sort();
    delete_frames.dedup();
    let base_aged = now_ms.saturating_sub(base.first_seen_ms) >= GC_GRACE_MS;
    let expired_tombstones = base
        .tombstones
        .iter()
        .filter(|(_, t)| {
            base_aged
                && now_ms.saturating_sub(t.at_ms) >= GC_GRACE_MS
                && base
                    .frontier
                    .get(&t.dot.author)
                    .is_some_and(|(s, _)| t.dot.seq <= *s)
        })
        .map(|(id, t)| (*id, *t))
        .collect();
    GcPlan {
        disputed,
        eligible,
        base: Some(base.id),
        delete_frames,
        expired_tombstones,
    }
}
