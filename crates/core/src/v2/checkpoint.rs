//! `Checkpoint` frames: their sealed payload, building one from a pack, and a full peer's
//! verification that emits a `Dispute` on a `state_mac` mismatch.

use std::collections::BTreeMap;

use crate::id::{DeviceId, DeviceSecret, VaultId};

use super::crypto::{EpochId, EpochKey, FrameId};
use super::data::{DataFrame, DataOp, decode_mheads, encode_mheads};
use super::fold::{FoldContext, fold_from_scratch};
use super::frame::Frame;
use super::pack::{Pack, pack_hash};
use super::state::{FoldedState, state_mac};
use super::wire::{PayloadError, Reader, Writer, ascending};

/// Errors folding from or building a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointError {
    #[error("membership no longer counts frames of {0} that the checkpoint covers")]
    Invalidated(DeviceId),
    #[error("the adder of {0} changed since the checkpoint judged its device card")]
    AdderChanged(DeviceId),
    #[error("payload error: {0}")]
    Payload(#[from] PayloadError),
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
    pub pack_hash: [u8; 32],
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
            pack_hash: r.array::<32>()?,
            pack_len: r.u64()?,
        };
        r.finish()?;
        Ok(payload)
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

/// Builds a checkpoint payload and its pack bytes from a compacted pack.
pub fn build_checkpoint(
    k_mac: &[u8; 32],
    pack: &Pack,
    mheads: Vec<FrameId>,
    timestamp_ms: u64,
) -> Result<(CheckpointPayload, Vec<u8>), PayloadError> {
    let bytes = pack.encode()?;
    let payload = CheckpointPayload {
        frontier: pack
            .meta
            .frontier
            .iter()
            .map(|(a, (s, id))| (*a, *s, *id))
            .collect(),
        mheads,
        timestamp_ms,
        state_mac: state_mac(k_mac, &pack.state)?,
        pack_hash: pack_hash(&bytes),
        pack_len: bytes.len() as u64,
    };
    Ok((payload, bytes))
}

/// A full peer's verdict on a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointVerdict {
    /// Recomputed fold matches; the peer may cover it and fold on top of it.
    Agreed,
    /// Mismatch: emit `dispute` and never cover, adopt or GC behind this checkpoint.
    Disputed { dispute: DataOp },
    /// This peer lacks frames up to the frontier, so it cannot judge.
    Unverifiable,
}

/// The canonical fold at `frontier`: every held frame at or below it, or `None` if any
/// frame up to the frontier is missing.
pub fn fold_at_frontier<'f>(
    ctx: &FoldContext<'_>,
    frames: impl IntoIterator<Item = &'f DataFrame>,
    frontier: &BTreeMap<DeviceId, (u64, FrameId)>,
) -> Option<FoldedState> {
    let covered: Vec<&DataFrame> = frames
        .into_iter()
        .filter(|f| frontier.get(&f.author).is_some_and(|(s, _)| f.seq <= *s))
        .collect();
    for (author, (seq, id)) in frontier {
        let mut have: Vec<&DataFrame> = covered
            .iter()
            .copied()
            .filter(|f| f.author == *author)
            .collect();
        have.sort_by_key(|f| f.seq);
        have.dedup_by_key(|f| f.seq);
        let complete =
            have.len() as u64 == seq.saturating_add(1) && have.last().is_some_and(|f| f.id == *id);
        if !complete {
            return None;
        }
    }
    Some(fold_from_scratch(ctx, covered))
}

/// Verifies a checkpoint as a full peer holding `frames`. `pack` is the checkpoint's pack
/// bytes if fetched; a pack that disagrees with its own payload is disputed too.
pub fn verify_checkpoint<'f>(
    k_mac: &[u8; 32],
    ctx: &FoldContext<'_>,
    checkpoint: FrameId,
    payload: &CheckpointPayload,
    pack: Option<&[u8]>,
    frames: impl IntoIterator<Item = &'f DataFrame>,
) -> Result<CheckpointVerdict, PayloadError> {
    let frontier = payload.frontier_map();
    let Some(ours) = fold_at_frontier(ctx, frames, &frontier) else {
        return Ok(CheckpointVerdict::Unverifiable);
    };
    let expected_state_mac = state_mac(k_mac, &ours)?;
    let pack_ok = pack.is_none_or(|bytes| pack_matches(k_mac, payload, bytes));
    if expected_state_mac == payload.state_mac && pack_ok {
        return Ok(CheckpointVerdict::Agreed);
    }
    Ok(CheckpointVerdict::Disputed {
        dispute: DataOp::Dispute {
            checkpoint,
            expected_state_mac,
        },
    })
}

fn pack_matches(k_mac: &[u8; 32], payload: &CheckpointPayload, bytes: &[u8]) -> bool {
    if bytes.len() as u64 != payload.pack_len || pack_hash(bytes) != payload.pack_hash {
        return false;
    }
    let Ok(pack) = Pack::decode(bytes) else {
        return false;
    };
    pack.meta.frontier == payload.frontier_map()
        && state_mac(k_mac, &pack.state).is_ok_and(|mac| mac == payload.state_mac)
}
