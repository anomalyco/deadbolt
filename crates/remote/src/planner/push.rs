//! Push: blobs, then packs, then fraud proofs, then Member frames, then
//! Data and Checkpoint frames, each stream in ascending `seq`, every PUT
//! create-only. A crash leaves a causally closed prefix on the store.

use std::collections::BTreeMap;

use deadbolt_core::v2::{Frame, FrameId, FraudProof, LogKind};
use deadbolt_core::{DeviceId, VaultId};

use super::RemoteAnomaly;
use crate::error::RemoteError;
use crate::path::{RemotePath, stream_cursor, stream_prefix};
use crate::store::{ObjStore, PutOutcome};

/// Everything waiting to leave this device.
#[derive(Debug, Clone, Default)]
pub struct Outbox {
    /// Attachments by content hash.
    pub blobs: Vec<([u8; 32], Vec<u8>)>,
    /// Checkpoint packs by `pack_hash`.
    pub packs: Vec<([u8; 32], Vec<u8>)>,
    /// Fraud proofs to publish.
    pub frauds: Vec<FraudProof>,
    /// Frames, own or (when re-seeding a wiped store) any member's.
    pub frames: Vec<Frame>,
}

/// One create-only PUT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushStep {
    pub path: RemotePath,
    pub bytes: Vec<u8>,
    /// The frame's id, for telling an idempotent retry from a fork.
    pub frame_id: Option<FrameId>,
}

/// The ordered PUTs of one push.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushPlan {
    pub steps: Vec<PushStep>,
}

/// Orders an outbox for pushing to `vault`. Refuses anything of another
/// vault, an invalid fraud proof, and two different local frames at one
/// stream position (a local fork must never reach the store).
pub fn plan_push(vault: &VaultId, outbox: Outbox) -> Result<PushPlan, RemoteError> {
    let mut steps = Vec::new();
    let content = |path: RemotePath, bytes: Vec<u8>| PushStep {
        path,
        bytes,
        frame_id: None,
    };
    let mut blobs = outbox.blobs;
    blobs.sort_by_key(|a| a.0);
    blobs.dedup_by(|a, b| a.0 == b.0);
    for (hash, bytes) in blobs {
        steps.push(content(
            RemotePath::Blob {
                vault: *vault,
                hash,
            },
            bytes,
        ));
    }
    let mut packs = outbox.packs;
    packs.sort_by_key(|a| a.0);
    packs.dedup_by(|a, b| a.0 == b.0);
    for (hash, bytes) in packs {
        steps.push(content(
            RemotePath::Pack {
                vault: *vault,
                hash,
            },
            bytes,
        ));
    }
    let mut frauds = BTreeMap::new();
    for proof in outbox.frauds {
        let verified = proof
            .verify()
            .map_err(|e| RemoteError::Plan(format!("fraud proof: {e}")))?;
        if verified.vault != *vault {
            return Err(RemoteError::Plan("fraud proof of another vault".into()));
        }
        frauds.insert(proof.proof_hash(), proof.encode().to_vec());
    }
    for (hash, bytes) in frauds {
        steps.push(content(
            RemotePath::Fraud {
                vault: *vault,
                hash,
            },
            bytes,
        ));
    }
    let mut frames: BTreeMap<(LogKind, DeviceId, u64), &Frame> = BTreeMap::new();
    for frame in &outbox.frames {
        let h = frame.header();
        if h.vault != *vault {
            return Err(RemoteError::Plan("frame of another vault".into()));
        }
        let key = (h.kind.log_kind(), h.author, h.seq);
        if let Some(other) = frames.insert(key, frame)
            && other.id() != frame.id()
        {
            return Err(RemoteError::Plan(format!(
                "two local frames at {:?} seq {}",
                key.0, key.2
            )));
        }
    }
    // LogKind orders Member before Data, so membership lands first.
    for ((_, author, seq), frame) in frames {
        steps.push(PushStep {
            path: RemotePath::frame(*vault, frame.header().kind, author, seq),
            bytes: frame.encode(),
            frame_id: Some(frame.id()),
        });
    }
    Ok(PushPlan { steps })
}

/// This device's own stream on the store has moved without it: a backup
/// restore, or a second device sharing its keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfRollback {
    pub log: LogKind,
    /// Own frames the store holds above the local tip. Import them, then
    /// re-sign unpushed local edits at `remote_max + 1`.
    pub remote_ahead_seqs: Vec<u64>,
    /// The `seq` where the store holds another own frame than the local one.
    pub conflicting_seq: Option<u64>,
}

/// Why a push stopped before its last step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushStop {
    /// An own name already holds a different valid frame.
    SelfRollback(SelfRollback),
    /// An own name holds something that is not a valid frame, or vanished
    /// between a 412 and the GET.
    Anomaly(RemoteAnomaly),
}

/// What a push did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushReport {
    /// PUTs that stored new objects.
    pub created: usize,
    /// PUTs that found the identical object already there (a retry).
    pub already_present: usize,
    /// Set when the push stopped early; later steps were not attempted.
    pub stopped: Option<PushStop>,
}

/// Runs a plan in order. A transport error returns `Err` with the steps
/// before it landed; running the same plan again is safe, since a step that
/// already landed answers `AlreadyExists` with identical bytes.
pub async fn push<S: ObjStore>(store: &S, plan: &PushPlan) -> Result<PushReport, RemoteError> {
    let mut report = PushReport::default();
    for step in &plan.steps {
        let name = step.path.to_name();
        match store.put(&name, &step.bytes, true).await? {
            PutOutcome::Created => report.created += 1,
            PutOutcome::AlreadyExists if step.path.is_content_addressed() => {
                // The name is the content's hash; readers verify it.
                report.already_present += 1;
            }
            PutOutcome::AlreadyExists => match judge_existing(store, step, &name).await? {
                None => report.already_present += 1,
                Some(stop) => {
                    report.stopped = Some(stop);
                    return Ok(report);
                }
            },
        }
    }
    Ok(report)
}

/// A create-only PUT of a frame found its name taken: same frame (a retry
/// after a lost response) or a fork of this device's own stream.
async fn judge_existing<S: ObjStore>(
    store: &S,
    step: &PushStep,
    name: &str,
) -> Result<Option<PushStop>, RemoteError> {
    let anomaly = |reason| {
        Some(PushStop::Anomaly(RemoteAnomaly::Mismatched {
            name: name.to_owned(),
            reason,
        }))
    };
    let Some(existing) = store.get(name, None).await? else {
        return Ok(anomaly("create-only PUT refused but GET finds nothing"));
    };
    if existing == step.bytes {
        return Ok(None);
    }
    let RemotePath::Frame {
        kind, author, seq, ..
    } = step.path
    else {
        return Ok(anomaly("not a frame name"));
    };
    let Ok(remote) = Frame::decode(&existing) else {
        return Ok(anomaly("does not verify as a frame"));
    };
    let h = remote.header();
    if h.author != author || h.seq != seq || h.kind.log_kind() != kind.log_kind() {
        return Ok(anomaly("frame header disagrees with its name"));
    }
    if Some(remote.id()) == step.frame_id {
        return Ok(None);
    }
    Ok(Some(PushStop::SelfRollback(SelfRollback {
        log: kind.log_kind(),
        remote_ahead_seqs: Vec::new(),
        conflicting_seq: Some(seq),
    })))
}

/// The newest `seq` this device holds of its own streams (`None`: empty).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OwnTips {
    pub member: Option<u64>,
    pub data: Option<u64>,
}

/// Lists this device's own streams before its first push of a session. Any
/// own frame above the local tip means the device was restored from an older
/// state: import those frames and re-sign the unpushed suffix above them.
pub async fn check_self_rollback<S: ObjStore>(
    store: &S,
    vault: &VaultId,
    me: &DeviceId,
    local: OwnTips,
) -> Result<Vec<SelfRollback>, RemoteError> {
    let mut found = Vec::new();
    for (log, tip) in [(LogKind::Member, local.member), (LogKind::Data, local.data)] {
        let Some(from) = tip.map_or(Some(0), |t| t.checked_add(1)) else {
            continue;
        };
        let after = stream_cursor(vault, log, me, from);
        let names = store
            .list(&stream_prefix(vault, log, me), after.as_deref())
            .await?;
        let ahead: Vec<u64> = names
            .iter()
            .filter_map(|name| match RemotePath::parse(name) {
                Ok(RemotePath::Frame { seq, author, .. }) if author == *me && seq >= from => {
                    Some(seq)
                }
                _ => None,
            })
            .collect();
        if !ahead.is_empty() {
            found.push(SelfRollback {
                log,
                remote_ahead_seqs: ahead,
                conflicting_seq: None,
            });
        }
    }
    Ok(found)
}
