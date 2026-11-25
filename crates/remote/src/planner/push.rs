//! Push: blobs, then packs, then fraud proofs, then Member frames, then
//! Data and Checkpoint frames, each stream in ascending `seq`, every PUT
//! create-only. A crash leaves a causally closed prefix on the store.

use std::collections::BTreeMap;

use deadbolt_core::v2::{Frame, FrameId, FraudProof, LogKind};
use deadbolt_core::{DeviceId, VaultId};

use super::{Observed, RemoteAnomaly, SyncAnchor, confirm_missing};
use crate::error::RemoteError;
use crate::path::{RemotePath, hex, stream_cursor, stream_prefix};
use crate::store::{ObjStore, PutOutcome};

/// Everything waiting to leave this device.
#[derive(Debug, Clone, Default)]
pub struct Outbox {
    /// Attachments by content hash (BLAKE3 of the stored bytes).
    pub blobs: Vec<([u8; 32], Vec<u8>)>,
    /// Checkpoint packs by `pack_hash` (BLAKE3 of the stored bytes).
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
/// vault, a blob or pack whose bytes do not hash to its name, an invalid
/// fraud proof, and two different local frames at one stream position (a
/// local fork must never reach the store).
pub fn plan_push(vault: &VaultId, outbox: Outbox) -> Result<PushPlan, RemoteError> {
    let mut steps = Vec::new();
    let content = |path: RemotePath, bytes: Vec<u8>| PushStep {
        path,
        bytes,
        frame_id: None,
    };
    let checked = |what: &str, mut objects: Vec<([u8; 32], Vec<u8>)>| {
        objects.sort_by_key(|a| a.0);
        objects.dedup_by(|a, b| a.0 == b.0);
        for (hash, bytes) in &objects {
            if blake3::hash(bytes).as_bytes() != hash {
                return Err(RemoteError::Plan(format!(
                    "{what} {} does not hash to its name",
                    hex(hash)
                )));
            }
        }
        Ok(objects)
    };
    for (hash, bytes) in checked("blob", outbox.blobs)? {
        let path = RemotePath::Blob {
            vault: *vault,
            hash,
        };
        steps.push(content(path, bytes));
    }
    for (hash, bytes) in checked("pack", outbox.packs)? {
        let path = RemotePath::Pack {
            vault: *vault,
            hash,
        };
        steps.push(content(path, bytes));
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
        let path = RemotePath::Fraud {
            vault: *vault,
            hash,
        };
        steps.push(content(path, bytes));
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
    /// Own frames the store holds above the acknowledged tip that the local
    /// replica lacks, `<seq>` and `<seq>.c` kept apart. GET them: those equal
    /// to local frames only advance the anchor; import the rest, then re-sign
    /// unpushed local edits above them.
    pub remote_ahead: Vec<RemotePath>,
    /// The own name where the store holds another frame than the local one.
    pub conflicting: Option<RemotePath>,
}

/// What a push did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushReport {
    /// PUTs that stored new objects.
    pub created: usize,
    /// PUTs that found the identical object already there (a retry).
    pub already_present: usize,
    /// Content-addressed names that held other bytes (a torn upload or
    /// planted garbage) and were overwritten with the verified content.
    pub repaired: usize,
    /// Set when the push stopped early; later steps were not attempted:
    /// [`RemoteAnomaly::SelfRollback`] when an own name already holds a
    /// different valid frame, [`RemoteAnomaly::Mismatched`] when it holds
    /// something that is not the frame its name says or vanished between a
    /// 412 and the GET.
    pub stopped: Option<RemoteAnomaly>,
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
                // The plan verified these bytes against the name, so the
                // stored object must be the same bytes; anything else is
                // overwritten with them.
                if store.get(&name, None).await?.as_deref() == Some(&step.bytes[..]) {
                    report.already_present += 1;
                } else {
                    store.put(&name, &step.bytes, false).await?;
                    report.repaired += 1;
                }
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
) -> Result<Option<RemoteAnomaly>, RemoteError> {
    let anomaly = |reason| {
        Some(RemoteAnomaly::Mismatched {
            name: name.to_owned(),
            reason,
        })
    };
    let Some(existing) = store.get(name, None).await? else {
        return Ok(anomaly("create-only PUT refused but GET finds nothing"));
    };
    if existing == step.bytes {
        return Ok(None);
    }
    let RemotePath::Frame {
        vault,
        kind,
        author,
        seq,
    } = step.path
    else {
        return Ok(anomaly("not a frame name"));
    };
    let Ok(remote) = Frame::decode(&existing) else {
        return Ok(anomaly("does not verify as a frame"));
    };
    let h = remote.header();
    if h.vault != vault || h.author != author || h.seq != seq || h.kind != kind {
        return Ok(anomaly("frame header disagrees with its name"));
    }
    if Some(remote.id()) == step.frame_id {
        return Ok(None);
    }
    Ok(Some(RemoteAnomaly::SelfRollback(SelfRollback {
        log: kind.log_kind(),
        remote_ahead: Vec::new(),
        conflicting: Some(step.path),
    })))
}

/// Lists this device's own streams before its first push of a session,
/// from the tips the store last acknowledged (the anchor's own entries,
/// never the local tip: unpushed local edits must not hide a restore).
///
/// - Any own frame above the acknowledged tip is
///   [`RemoteAnomaly::SelfRollback`]: the device was restored from an older
///   state, or its keys are in use elsewhere. Catch it before pushing, since a
///   WebDAV server that ignores `If-None-Match` would let a push overwrite it.
/// - The acknowledged tip itself missing (and not collectable behind an
///   adopted checkpoint) is [`RemoteAnomaly::RemoteRegressed`], once a direct
///   GET agrees: listing only above it would let the next push land on a
///   stream the store had wiped.
pub async fn check_self_rollback<S: ObjStore>(
    store: &S,
    vault: &VaultId,
    me: &DeviceId,
    anchor: &SyncAnchor,
) -> Result<Vec<RemoteAnomaly>, RemoteError> {
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for log in [LogKind::Member, LogKind::Data] {
        let tip = anchor.tip(log, me);
        let from = tip.map_or(0, |(seq, _)| seq);
        let after = stream_cursor(vault, log, me, from);
        let names = store
            .list(&stream_prefix(vault, log, me), after.as_deref())
            .await?;
        let listed: Vec<(u64, RemotePath)> = names
            .iter()
            .filter_map(|name| match RemotePath::parse(name) {
                Ok(
                    path @ RemotePath::Frame {
                        vault: v,
                        kind,
                        author,
                        seq,
                    },
                ) if v == *vault && author == *me && kind.log_kind() == log && seq >= from => {
                    Some((seq, path))
                }
                _ => None,
            })
            .collect();
        if let Some((seq, id)) = tip
            && !listed.iter().any(|(s, _)| *s == seq)
            && !anchor.may_be_gone(log, me, seq)
        {
            missing.push(RemoteAnomaly::RemoteRegressed {
                log,
                author: *me,
                expected_seq: seq,
                expected_id: id,
                observed: Observed::Missing {
                    max_seq: listed.iter().map(|(s, _)| *s).max(),
                },
            });
        }
        let remote_ahead: Vec<RemotePath> = listed
            .into_iter()
            .filter(|(seq, _)| tip.is_none_or(|(t, _)| *seq > t))
            .map(|(_, path)| path)
            .collect();
        if !remote_ahead.is_empty() {
            found.push(RemoteAnomaly::SelfRollback(SelfRollback {
                log,
                remote_ahead,
                conflicting: None,
            }));
        }
    }
    found.extend(confirm_missing(store, vault, missing).await?);
    Ok(found)
}
