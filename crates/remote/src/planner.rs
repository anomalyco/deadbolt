//! The sync planner (Fable §3.3–3.4): what to push and pull, in which
//! order, and what a store's answers prove about it.
//!
//! - [`SyncAnchor`] remembers the newest `(seq, FrameId)` this device has
//!   accepted from every stream, advancing only along verified `prev`
//!   links or to a verified checkpoint's frontier. A LIST that shows less
//!   (and a direct GET that agrees: [`confirm_missing`], since a LIST can lag
//!   a PUT it acknowledged), or a different frame at that `seq`, is
//!   [`RemoteAnomaly::RemoteRegressed`].
//! - [`check_withholding`]: a decrypted clock citing `(B, s)` while the
//!   store lists B only below `s` is [`RemoteAnomaly::Withheld`].
//! - [`check_self_rollback`], [`check_fetched_as`] and [`push`]: a device
//!   restored from a backup finds its own stream ahead of it or missing its
//!   acknowledged tip, or its own name holding another frame.
//!
//! A zero-state device still cannot tell one store rolling the whole vault
//! back to an older consistent cut; recovery shows the newest signed state
//! for the human to judge.

mod anchor;
mod index;
mod probe;
mod pull;
mod push;
mod recovery;
mod verify;

pub use anchor::SyncAnchor;
pub use index::{RemoteIndex, Spellings};
pub use probe::confirm_missing;
pub use pull::{PullPlan, Regressions, check_regressions, plan_pull};
pub use push::{
    Outbox, PushPlan, PushReport, PushStep, SelfRollback, check_self_rollback, plan_push, push,
};
pub use recovery::{RecoveryPlan, Tail, plan_recovery_bootstrap};
pub use verify::{
    CitedCounts, Twin, check_fetched, check_fetched_as, check_fetched_fraud, check_withholding,
    resolve_twin,
};

use deadbolt_core::DeviceId;
use deadbolt_core::v2::{FrameId, LogKind};

/// One author's append-only stream in one log.
pub type StreamKey = (LogKind, DeviceId);

/// What the store showed where the anchor expected a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    /// The stream lists nothing at the anchored `seq`; `max_seq` is the
    /// highest it does list.
    Missing { max_seq: Option<u64> },
    /// The object at the anchored `seq` is another valid frame.
    Different(FrameId),
}

/// Something a store did that an honest store never does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteAnomaly {
    /// A stream lost frames this device had accepted, or swapped one: the
    /// store was rolled back or wiped. Alarm, then re-push from the replica.
    RemoteRegressed {
        log: LogKind,
        author: DeviceId,
        expected_seq: u64,
        expected_id: FrameId,
        observed: Observed,
    },
    /// A frame cites `(author, required_seq)` but the store lists the
    /// author's data stream only up to `remote_max_seq`.
    Withheld {
        author: DeviceId,
        required_seq: u64,
        remote_max_seq: Option<u64>,
    },
    /// A stream lists frames above `missing_seq` but not `missing_seq`
    /// itself, where nothing may legitimately be missing (a Member stream,
    /// or a data tail above a checkpoint's frontier).
    StreamHole {
        log: LogKind,
        author: DeviceId,
        missing_seq: u64,
        max_seq: u64,
    },
    /// A frame arrived that does not extend the anchored tip by one:
    /// accepting it would skip frames the store never showed.
    StreamGap {
        log: LogKind,
        author: DeviceId,
        anchored_seq: Option<u64>,
        observed_seq: u64,
    },
    /// The next frame of a stream does not link to the anchored tip.
    ChainBroken {
        log: LogKind,
        author: DeviceId,
        seq: u64,
        expected_prev: FrameId,
        observed_prev: FrameId,
    },
    /// A fraud proof this device had accepted is no longer listed.
    FraudWiped { hash: [u8; 32] },
    /// The object under `name` is not what its name says: it fails to
    /// verify, is truncated, or names another vault, author, kind or `seq`.
    Mismatched { name: String, reason: &'static str },
    /// This device's own stream on the store moved without it: a backup
    /// restore, or a second device sharing its keys. Never accept or build on
    /// the store's frames there.
    SelfRollback(SelfRollback),
}
