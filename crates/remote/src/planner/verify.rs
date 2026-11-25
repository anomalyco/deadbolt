//! Checks on what a GET returned and on what decrypted frames cite.

use std::collections::BTreeMap;

use deadbolt_core::v2::{DeltaClock, Frame, FraudProof, VectorClock};
use deadbolt_core::{DeviceId, VaultId};

use super::{Observed, RemoteAnomaly, SyncAnchor};
use crate::path::RemotePath;

/// Checks a fetched object against its name and the anchor: it must be a
/// verifying frame of this vault, author, log, kind and `seq`, and the
/// anchored frame where the anchor has one at that `seq`.
pub fn check_fetched(
    anchor: &SyncAnchor,
    path: &RemotePath,
    bytes: &[u8],
) -> Result<Frame, RemoteAnomaly> {
    let frame = verify_named(path, bytes)?;
    let h = frame.header();
    match anchor.tip(h.kind.log_kind(), &h.author) {
        Some((anchored, id)) if anchored == h.seq && id != frame.id() => {
            Err(RemoteAnomaly::RemoteRegressed {
                log: h.kind.log_kind(),
                author: h.author,
                expected_seq: h.seq,
                expected_id: id,
                observed: Observed::Different(frame.id()),
            })
        }
        _ => Ok(frame),
    }
}

/// A frame that verifies and whose header matches its name exactly.
fn verify_named(path: &RemotePath, bytes: &[u8]) -> Result<Frame, RemoteAnomaly> {
    let mismatched = |reason| RemoteAnomaly::Mismatched {
        name: path.to_name(),
        reason,
    };
    let RemotePath::Frame {
        vault,
        kind,
        author,
        seq,
    } = *path
    else {
        return Err(mismatched("not a frame name"));
    };
    let frame = Frame::decode(bytes).map_err(|_| mismatched("does not verify as a frame"))?;
    let h = frame.header();
    if h.vault != vault || h.author != author || h.seq != seq || h.kind != kind {
        return Err(mismatched("frame header disagrees with its name"));
    }
    Ok(frame)
}

/// Checks a fetched `x/<hash>` object: a strictly verifying fraud proof of
/// this vault whose `proof_hash` is its name. Record it with
/// [`SyncAnchor::note_fraud`] once acted on.
pub fn check_fetched_fraud(
    vault: &VaultId,
    path: &RemotePath,
    bytes: &[u8],
) -> Result<FraudProof, RemoteAnomaly> {
    let mismatched = |reason| RemoteAnomaly::Mismatched {
        name: path.to_name(),
        reason,
    };
    let RemotePath::Fraud {
        vault: named_vault,
        hash,
    } = *path
    else {
        return Err(mismatched("not a fraud proof name"));
    };
    if named_vault != *vault {
        return Err(mismatched("fraud proof name of another vault"));
    }
    let proof =
        FraudProof::decode(bytes).map_err(|_| mismatched("does not verify as a fraud proof"))?;
    if proof.proof_hash() != hash {
        return Err(mismatched("fraud proof hash disagrees with its name"));
    }
    let verified = proof
        .verify()
        .map_err(|_| mismatched("does not verify as a fraud proof"))?;
    if verified.vault != *vault {
        return Err(mismatched("fraud proof of another vault"));
    }
    Ok(proof)
}

/// What a position listed as both `<seq>` and `<seq>.c` turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Twin {
    /// The author signed both: equivocation. Publish the proof.
    Fraud(Box<FraudProof>),
    /// Only this one verifies under its name; the other is junk the store
    /// planted and is ignored.
    One(Box<Frame>),
}

/// Judges a twin from both fetched objects. Fails only when neither
/// verifies under its name (the bare name's reason is reported).
pub fn resolve_twin(
    bare: (&RemotePath, &[u8]),
    checkpoint: (&RemotePath, &[u8]),
) -> Result<Twin, RemoteAnomaly> {
    match (
        verify_named(bare.0, bare.1),
        verify_named(checkpoint.0, checkpoint.1),
    ) {
        (Ok(a), Ok(b)) => FraudProof::from_frames(&a, &b)
            .map(|proof| Twin::Fraud(Box::new(proof)))
            .map_err(|_| RemoteAnomaly::Mismatched {
                name: bare.0.to_name(),
                reason: "twin frames do not form a fraud proof",
            }),
        (Ok(frame), Err(_)) | (Err(_), Ok(frame)) => Ok(Twin::One(Box::new(frame))),
        (Err(e), Err(_)) => Err(e),
    }
}

/// A clock whose entries are frame **counts**, as `core::v2` keeps them:
/// `n` means frames `0..n` were seen, so the newest cited `seq` is `n - 1`.
pub trait CitedCounts {
    /// `(author, count)` entries; zero counts cite nothing.
    fn cited_counts(&self) -> Vec<(DeviceId, u64)>;
}

impl CitedCounts for VectorClock {
    fn cited_counts(&self) -> Vec<(DeviceId, u64)> {
        self.iter().map(|(a, n)| (*a, *n)).collect()
    }
}

impl CitedCounts for DeltaClock {
    fn cited_counts(&self) -> Vec<(DeviceId, u64)> {
        self.entries().to_vec()
    }
}

/// Every `(author, seq)` a decrypted clock cites must be listed by the
/// store (or compacted). Clock entries are counts; `remote_listed_tips`
/// and `compacted` are 0-based `seq`s. A peer relaying over iroh can
/// legitimately run ahead of the store for a moment, so callers re-list
/// before alarming.
pub fn check_withholding(
    cited: &impl CitedCounts,
    remote_listed_tips: &BTreeMap<DeviceId, u64>,
    compacted: &BTreeMap<DeviceId, u64>,
) -> Vec<RemoteAnomaly> {
    cited
        .cited_counts()
        .into_iter()
        .filter_map(|(author, count)| {
            let required_seq = count.checked_sub(1)?;
            let listed = remote_listed_tips
                .get(&author)
                .is_some_and(|&tip| tip >= required_seq);
            let collected = compacted
                .get(&author)
                .is_some_and(|&floor| floor >= required_seq);
            (!listed && !collected).then(|| RemoteAnomaly::Withheld {
                author,
                required_seq,
                remote_max_seq: remote_listed_tips.get(&author).copied(),
            })
        })
        .collect()
}
