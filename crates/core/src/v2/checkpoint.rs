//! `Checkpoint` frames: their sealed payload, building one from a pack, and a full peer's
//! verification that emits a `Dispute` on a `state_mac` mismatch.
//!
//! A checkpoint's `pack_hash`/`pack_len` commit to the **encrypted** `DBPK` file that
//! `deadbolt-pack` sealed the plaintext [`Pack`] into: that is what peers fetch, so it is what
//! they can check before decrypting.

use std::collections::{BTreeMap, BTreeSet};

use crate::id::{DeviceId, DeviceSecret, VaultId};

use super::crypto::{EpochId, EpochKey, FrameId};
use super::data::{DataFrame, DataOp, decode_mheads, encode_mheads};
use super::fold::{FoldContext, fold_subset};
use super::frame::Frame;
use super::pack::Pack;
use super::state::{FoldedState, state_mac};
use super::wire::{PayloadError, Reader, Writer, ascending};

/// Errors folding from or building a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointError {
    #[error("membership no longer counts frames of {0} that the checkpoint covers")]
    Invalidated(DeviceId),
    #[error("epoch {0}, which sealed frames the checkpoint covers, is no longer authorized")]
    Deauthorized(EpochId),
    #[error("the adder of {0} changed since the checkpoint judged its device card")]
    AdderChanged(DeviceId),
    #[error("payload error: {0}")]
    Payload(#[from] PayloadError),
}

/// The encrypted pack file a checkpoint commits to: `BLAKE3` and length of the sealed `DBPK`
/// bytes, never of the plaintext pack inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackCommitment {
    pub hash: [u8; 32],
    pub len: u64,
}

impl PackCommitment {
    /// Commits to the sealed pack file bytes as stored and fetched.
    pub fn of(sealed: &[u8]) -> Self {
        Self {
            hash: blake3::hash(sealed).into(),
            len: sealed.len() as u64,
        }
    }
}

/// Decrypted plaintext of a `Checkpoint` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointPayload {
    /// Highest covered `(author, seq, frame)` per stream, strictly sorted by author.
    pub frontier: Vec<(DeviceId, u64, FrameId)>,
    pub mheads: Vec<FrameId>,
    pub timestamp_ms: u64,
    /// `BLAKE3::keyed_hash(K_mac(epoch), canonical fold at frontier)`.
    pub state_mac: [u8; 32],
    /// Keyed commitment to the canonical causal metadata.
    pub meta_mac: [u8; 32],
    /// `BLAKE3` of the encrypted `DBPK` pack file.
    pub pack_hash: [u8; 32],
    /// Byte length of the encrypted `DBPK` pack file.
    pub pack_len: u64,
}

impl CheckpointPayload {
    /// Canonical plaintext bytes.
    pub fn encode(&self) -> Result<Vec<u8>, PayloadError> {
        let mut w = Writer::new();
        w.count(self.frontier.len(), "frontier")?;
        let mut prev = None;
        for (author, seq, id) in &self.frontier {
            ascending(prev, author, "frontier")?;
            prev = Some(author);
            w.device(author);
            w.u64(*seq);
            w.frame_id(id);
        }
        encode_mheads(&mut w, &self.mheads)?;
        w.u64(self.timestamp_ms);
        w.bytes(&self.state_mac);
        w.bytes(&self.meta_mac);
        w.bytes(&self.pack_hash);
        w.u64(self.pack_len);
        Ok(w.into_bytes())
    }

    /// Strict canonical decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, PayloadError> {
        let mut r = Reader::new(bytes);
        let n = r.count(72, "frontier")?;
        let mut frontier: Vec<(DeviceId, u64, FrameId)> = Vec::with_capacity(n);
        for _ in 0..n {
            let author = r.device()?;
            ascending(frontier.last().map(|(a, _, _)| a), &author, "frontier")?;
            frontier.push((author, r.u64()?, r.frame_id()?));
        }
        let payload = Self {
            frontier,
            mheads: decode_mheads(&mut r)?,
            timestamp_ms: r.u64()?,
            state_mac: r.array::<32>()?,
            meta_mac: r.array::<32>()?,
            pack_hash: r.array::<32>()?,
            pack_len: r.u64()?,
        };
        r.finish()?;
        Ok(payload)
    }

    /// The encrypted pack file this checkpoint commits to.
    pub const fn pack_commitment(&self) -> PackCommitment {
        PackCommitment {
            hash: self.pack_hash,
            len: self.pack_len,
        }
    }

    /// The frontier as a map.
    pub fn frontier_map(&self) -> BTreeMap<DeviceId, (u64, FrameId)> {
        self.frontier
            .iter()
            .map(|(a, s, id)| (*a, (*s, *id)))
            .collect()
    }

    /// Seals this payload as a signed `Checkpoint` frame.
    pub fn seal(
        &self,
        author: &DeviceSecret,
        vault: VaultId,
        seq: u64,
        prev: FrameId,
        epoch: EpochId,
        epoch_key: &EpochKey,
    ) -> Result<Frame, PayloadError> {
        let pt = zeroize::Zeroizing::new(self.encode()?);
        Ok(Frame::seal_checkpoint(
            author, vault, seq, prev, epoch, epoch_key, &pt,
        )?)
    }
}

/// Builds a checkpoint payload for a compacted `pack` that `deadbolt-pack` has already sealed
/// into the encrypted file `sealed` commits to.
pub fn build_checkpoint(
    k_mac: &[u8; 32],
    pack: &Pack,
    sealed: PackCommitment,
    mheads: Vec<FrameId>,
    timestamp_ms: u64,
) -> Result<CheckpointPayload, PayloadError> {
    pack.meta.validate(&pack.state)?;
    Ok(CheckpointPayload {
        frontier: pack
            .meta
            .frontier
            .iter()
            .map(|(a, (s, id))| (*a, *s, *id))
            .collect(),
        mheads,
        timestamp_ms,
        state_mac: state_mac(k_mac, &pack.state)?,
        meta_mac: meta_mac(k_mac, pack)?,
        pack_hash: sealed.hash,
        pack_len: sealed.len,
    })
}

/// A full peer's verdict on a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointVerdict {
    /// Recomputed fold matches; the peer may cover it and fold on top of it.
    Agreed,
    /// Mismatch: emit `dispute` and never cover, adopt or GC behind this checkpoint.
    Disputed { dispute: DataOp },
    /// The membership no longer counts a frame the checkpoint covered (a later removal), so
    /// the folds differ without anyone cheating: do not adopt it, and do not dispute it.
    Invalidated,
    /// This peer lacks frames up to the frontier, so it cannot judge.
    Unverifiable,
}

/// Every held frame on each author's unique `prev` chain `0..=seq` ending at the frontier's
/// frame, or `None` if any link is missing. Fork siblings off the chain are ignored.
fn frontier_chains<'f>(
    frames: impl IntoIterator<Item = &'f DataFrame>,
    frontier: &BTreeMap<DeviceId, (u64, FrameId)>,
) -> Option<Vec<&'f DataFrame>> {
    let by_id: BTreeMap<FrameId, &DataFrame> = frames
        .into_iter()
        .filter(|f| frontier.get(&f.author).is_some_and(|(s, _)| f.seq <= *s))
        .map(|f| (f.id, f))
        .collect();
    let mut out = Vec::new();
    for (author, (seq, id)) in frontier {
        let (mut cur, mut expect) = (*id, *seq);
        loop {
            let f = *by_id.get(&cur)?;
            if f.author != *author || f.seq != expect {
                return None;
            }
            out.push(f);
            if expect == 0 {
                break;
            }
            (cur, expect) = (f.prev, expect - 1);
        }
    }
    Some(out)
}

/// The canonical fold at `frontier`: exactly each author's frames on its unbroken `prev` chain
/// up to the frontier frame, with clocks closed over every held frame (a covered frame may
/// have seen a frame above the frontier). `None` if any covered frame is missing or cannot be
/// resolved yet.
pub fn fold_at_frontier<'f>(
    ctx: &FoldContext<'_>,
    frames: impl IntoIterator<Item = &'f DataFrame>,
    frontier: &BTreeMap<DeviceId, (u64, FrameId)>,
) -> Option<FoldedState> {
    fold_covered(ctx, frames, frontier).map(|(state, _)| state)
}

/// [`fold_at_frontier`] plus the covered frames.
fn fold_covered<'f>(
    ctx: &FoldContext<'_>,
    frames: impl IntoIterator<Item = &'f DataFrame>,
    frontier: &BTreeMap<DeviceId, (u64, FrameId)>,
) -> Option<(FoldedState, Vec<&'f DataFrame>)> {
    let all: Vec<&DataFrame> = frames.into_iter().collect();
    let covered = frontier_chains(all.iter().copied(), frontier)?;
    let ids: BTreeSet<FrameId> = covered.iter().map(|f| f.id).collect();
    // Fork siblings at or below the frontier are left out; frames above it only close clocks.
    let usable = all
        .into_iter()
        .filter(|f| ids.contains(&f.id) || frontier.get(&f.author).is_none_or(|(s, _)| f.seq > *s));
    Some((fold_subset(ctx, usable, &ids)?, covered))
}

/// Verifies a checkpoint as a full peer holding `frames`. `k_mac` is `K_mac` of the checkpoint
/// frame's own epoch (`DataFrame::epoch`). `pack` is the decrypted pack, if fetched, with the
/// commitment observed over its encrypted bytes; a pack that disagrees with the payload is
/// disputed.
pub fn verify_checkpoint<'f>(
    k_mac: &[u8; 32],
    ctx: &FoldContext<'_>,
    checkpoint: FrameId,
    payload: &CheckpointPayload,
    pack: Option<(&Pack, PackCommitment)>,
    frames: impl IntoIterator<Item = &'f DataFrame>,
) -> Result<CheckpointVerdict, PayloadError> {
    let frontier = payload.frontier_map();
    let frames: Vec<_> = frames.into_iter().collect();
    let Some((ours, covered)) = fold_covered(ctx, frames.iter().copied(), &frontier) else {
        return Ok(CheckpointVerdict::Unverifiable);
    };
    let expected_state_mac = state_mac(k_mac, &ours)?;
    let pack_ok = pack.is_none_or(|(p, seen)| pack_matches(k_mac, payload, p, seen));
    let ids: BTreeSet<_> = covered.iter().map(|f| f.id).collect();
    let usable = frames.iter().copied().filter(|f| {
        ids.contains(&f.id) || frontier.get(&f.author).is_none_or(|(seq, _)| f.seq > *seq)
    });
    let meta_ok = super::fold::compact_at(ctx, None, usable, Some(&frontier))
        .ok()
        .and_then(|ours| meta_mac(k_mac, &ours).ok())
        .is_some_and(|mac| mac == payload.meta_mac);
    if expected_state_mac == payload.state_mac && meta_ok && pack_ok {
        return Ok(CheckpointVerdict::Agreed);
    }
    if pack_ok && covered.iter().any(|f| !ctx.counts(f)) {
        return Ok(CheckpointVerdict::Invalidated);
    }
    Ok(CheckpointVerdict::Disputed {
        dispute: DataOp::Dispute {
            checkpoint,
            expected_state_mac,
        },
    })
}

/// Whether `pack`, whose encrypted file hashed to `seen`, is the one `payload` commits to:
/// same file, a consistent meta, the same frontier and the same `state_mac`. What a peer
/// holding none of the covered frames can check.
pub fn pack_matches(
    k_mac: &[u8; 32],
    payload: &CheckpointPayload,
    pack: &Pack,
    seen: PackCommitment,
) -> bool {
    seen == payload.pack_commitment() && content_matches(k_mac, payload, pack)
}

fn meta_mac(k_mac: &[u8; 32], pack: &Pack) -> Result<[u8; 32], PayloadError> {
    let mut hash = blake3::Hasher::new_keyed(k_mac);
    hash.update(b"checkpoint metadata");
    hash.update(&pack.meta.encode()?);
    Ok(hash.finalize().into())
}

/// [`pack_matches`] without the file: `pack` holds what `payload` commits to, however it
/// was sealed (this device re-seals a pack its store couldn't take byte for byte).
pub fn content_matches(k_mac: &[u8; 32], payload: &CheckpointPayload, pack: &Pack) -> bool {
    pack.meta.validate(&pack.state).is_ok()
        && pack.meta.frontier == payload.frontier_map()
        && meta_mac(k_mac, pack).is_ok_and(|mac| mac == payload.meta_mac)
        && state_mac(k_mac, &pack.state).is_ok_and(|mac| mac == payload.state_mac)
}
