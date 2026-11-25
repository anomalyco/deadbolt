//! When to checkpoint, and the implicit-ack GC planner.
//!
//! There is no ack object: a member's data clock covering a checkpoint frame is its ack.
//! An undisputed checkpoint becomes GC-eligible once every current member's clock covers
//! it, or once it is `GC_GRACE_MS` old so a lost device never wedges compaction. A
//! checkpoint any current member disputed is never eligible.

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
    pub timestamp_ms: u64,
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
    /// It is at least `GC_GRACE_MS` old.
    Grace,
}

/// What may be deleted now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcPlan {
    /// Checkpoints some current member disputed: never covered, adopted or collected.
    pub disputed: BTreeSet<FrameId>,
    /// Undisputed checkpoints that are GC-eligible, and why.
    pub eligible: BTreeMap<FrameId, Eligibility>,
    /// The newest eligible checkpoint, by `(timestamp_ms, id)`: the new base.
    pub base: Option<FrameId>,
    /// Frames at or below the base's frontier, safe to delete.
    pub delete_frames: Vec<FrameId>,
    /// Tombstones in the base pack that may be pruned.
    pub expired_tombstones: BTreeMap<ItemId, Tombstone>,
}

/// Plans GC from what this peer knows.
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
        } else if now_ms.saturating_sub(c.timestamp_ms) >= GC_GRACE_MS {
            eligible.insert(c.id, Eligibility::Grace);
        }
    }
    let base = checkpoints
        .iter()
        .filter(|c| eligible.contains_key(&c.id))
        .max_by_key(|c| (c.timestamp_ms, c.id));
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
    let expired_tombstones = base
        .tombstones
        .iter()
        .filter(|(_, t)| {
            base.frontier
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
