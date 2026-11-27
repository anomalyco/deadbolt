//! A checkpoint pack: the folded state at a frontier plus the `PackMeta` that lets later and
//! late frames merge into it with zero pre-frontier frames.
//!
//! [`Pack`] is the plaintext payload that `deadbolt-pack` seals into its encrypted `DBPK` file.
//! A checkpoint commits to that encrypted file (see `checkpoint::PackCommitment`), never to
//! these plaintext bytes.

mod records;

use std::collections::{BTreeMap, BTreeSet};

use crate::id::{DeviceId, ItemId};

use super::causal::SeenBy;
use super::clock::{Dot, VectorClock};
use super::crypto::{EpochId, FrameId};
use super::state::{FoldedState, Tombstone};
use super::wire::{PayloadError, Reader, Writer, ascending};

pub use records::{
    FILL_COPIES, ItemHead, ItemRecords, ItemSecret, PackRecords, is_secret_register,
};

/// What a checkpoint keeps besides the state so its pre-frontier frames can be deleted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackMeta {
    /// Highest covered seq (and its frame) per data stream.
    pub frontier: BTreeMap<DeviceId, (u64, FrameId)>,
    /// Each stream's clock projected onto this frontier. Causal dependencies on
    /// uncompacted frames are retained in `seen_by`, never credited as compacted counts.
    pub stream_clocks: BTreeMap<DeviceId, VectorClock>,
    /// Frontier-bounded clock of every standing register write or tombstone.
    pub dots: BTreeMap<(DeviceId, u64), VectorClock>,
    /// Deleted items and their winning delete.
    pub tombstones: BTreeMap<ItemId, Tombstone>,
    /// Per author, every membership head its covered frames named. A later membership
    /// change that voids any of them invalidates this checkpoint.
    pub mheads: BTreeMap<DeviceId, BTreeSet<FrameId>>,
    /// Adder used to judge each third-party `DeviceCard` the fold covered.
    pub card_adders: BTreeMap<DeviceId, DeviceId>,
    /// Every epoch a covered frame was sealed under. One the membership stops authorizing
    /// invalidates this checkpoint, as a fold from genesis would stop counting its frames.
    pub epochs: BTreeSet<EpochId>,
    /// For each standing dot and each tail frame a compacted frame saw, the lowest compacted
    /// seq per author whose closure saw it, so a late frame naming a compacted frame is judged
    /// exactly as a fold from genesis would.
    pub seen_by: SeenBy,
}

impl PackMeta {
    /// Checks the meta is internally consistent with `state`.
    pub fn validate(&self, state: &FoldedState) -> Result<(), PayloadError> {
        if !self.frontier.keys().eq(self.stream_clocks.keys()) {
            return Err(PayloadError::Invalid("stream clocks must match frontier"));
        }
        for (author, (seq, _)) in &self.frontier {
            if *seq >= u64::MAX - 1 || self.stream_clocks[author].get(author) != seq + 1 {
                return Err(PayloadError::Invalid("stream clock must end at frontier"));
            }
        }
        for clock in self.stream_clocks.values().chain(self.dots.values()) {
            for (author, count) in clock.iter() {
                if *count == u64::MAX
                    || self
                        .frontier
                        .get(author)
                        .is_none_or(|(seq, _)| *count > seq + 1)
                {
                    return Err(PayloadError::Invalid("clock above frontier"));
                }
            }
        }
        for ((author, seq), clock) in &self.dots {
            if self.frontier.get(author).is_none_or(|(f, _)| seq > f)
                || clock.get(author) != seq.saturating_add(1)
            {
                return Err(PayloadError::Invalid("invalid dot clock"));
            }
        }
        for (author, seq) in state.dots() {
            if !self.dots.contains_key(&(author, seq)) {
                return Err(PayloadError::Invalid("missing clock for a standing dot"));
            }
            if self.frontier.get(&author).is_none_or(|(f, _)| seq > *f) {
                return Err(PayloadError::Invalid("dot above frontier"));
            }
        }
        if self.tombstones != state.tombstones() {
            return Err(PayloadError::Invalid("tombstones disagree with state"));
        }
        for (key, thresholds) in &self.seen_by {
            if key.1 >= u64::MAX - 1 {
                return Err(PayloadError::Invalid("invalid seen-by sequence"));
            }
            let above = self.frontier.get(&key.0).is_none_or(|(f, _)| key.1 > *f);
            if !(self.dots.contains_key(key) || above) || thresholds.is_empty() {
                return Err(PayloadError::Invalid(
                    "seen-by must name a standing or tail frame",
                ));
            }
            for (author, seq) in thresholds {
                if self.frontier.get(author).is_none_or(|(f, _)| seq > f) {
                    return Err(PayloadError::Invalid("seen-by above frontier"));
                }
            }
        }
        Ok(())
    }

    /// Canonical metadata bytes authenticated by the checkpoint.
    pub fn encode(&self) -> Result<Vec<u8>, PayloadError> {
        let mut w = Writer::new();
        self.encode_into(&mut w)?;
        Ok(w.into_bytes())
    }

    fn encode_into(&self, w: &mut Writer) -> Result<(), PayloadError> {
        w.count(self.frontier.len(), "frontier")?;
        for (author, (seq, id)) in &self.frontier {
            w.device(author);
            w.u64(*seq);
            w.frame_id(id);
            self.stream_clocks
                .get(author)
                .ok_or(PayloadError::Invalid("stream clocks must match frontier"))?
                .encode(w)?;
        }
        w.count(self.dots.len(), "dots")?;
        for ((author, seq), clock) in &self.dots {
            w.device(author);
            w.u64(*seq);
            clock.encode(w)?;
        }
        w.count(self.tombstones.len(), "tombstones")?;
        for (item, t) in &self.tombstones {
            w.item(item);
            t.dot.encode(w);
            w.u64(t.at_ms);
        }
        w.count(self.mheads.len(), "mheads")?;
        for (author, heads) in &self.mheads {
            w.device(author);
            w.count(heads.len(), "mheads")?;
            for h in heads {
                w.frame_id(h);
            }
        }
        w.count(self.card_adders.len(), "card adders")?;
        for (device, adder) in &self.card_adders {
            w.device(device);
            w.device(adder);
        }
        w.count(self.seen_by.len(), "seen by")?;
        for ((author, seq), thresholds) in &self.seen_by {
            w.device(author);
            w.u64(*seq);
            w.count(thresholds.len(), "seen by")?;
            for (by, at) in thresholds {
                w.device(by);
                w.u64(*at);
            }
        }
        w.count(self.epochs.len(), "epochs")?;
        for epoch in &self.epochs {
            w.frame_id(&epoch.as_frame_id());
        }
        Ok(())
    }

    fn decode_from(r: &mut Reader<'_>) -> Result<Self, PayloadError> {
        let mut meta = Self::default();
        let n = r.count(76, "frontier")?;
        for _ in 0..n {
            let author = r.device()?;
            ascending(meta.frontier.keys().next_back(), &author, "frontier")?;
            let seq = r.u64()?;
            let id = r.frame_id()?;
            meta.frontier.insert(author, (seq, id));
            meta.stream_clocks.insert(author, VectorClock::decode(r)?);
        }
        let n = r.count(44, "dots")?;
        for _ in 0..n {
            let key = (r.device()?, r.u64()?);
            ascending(meta.dots.keys().next_back(), &key, "dots")?;
            meta.dots.insert(key, VectorClock::decode(r)?);
        }
        let n = r.count(96, "tombstones")?;
        for _ in 0..n {
            let item = r.item()?;
            ascending(meta.tombstones.keys().next_back(), &item, "tombstones")?;
            let dot = Dot::decode(r)?;
            let at_ms = r.u64()?;
            meta.tombstones.insert(item, Tombstone { dot, at_ms });
        }
        let n = r.count(36, "mheads")?;
        for _ in 0..n {
            let author = r.device()?;
            ascending(meta.mheads.keys().next_back(), &author, "mheads")?;
            let m = r.count(32, "mheads")?;
            let mut heads = BTreeSet::new();
            for _ in 0..m {
                let h = r.frame_id()?;
                ascending(heads.last(), &h, "mheads")?;
                heads.insert(h);
            }
            meta.mheads.insert(author, heads);
        }
        let n = r.count(64, "card adders")?;
        for _ in 0..n {
            let device = r.device()?;
            ascending(meta.card_adders.keys().next_back(), &device, "card adders")?;
            meta.card_adders.insert(device, r.device()?);
        }
        let n = r.count(44, "seen by")?;
        for _ in 0..n {
            let key = (r.device()?, r.u64()?);
            ascending(meta.seen_by.keys().next_back(), &key, "seen by")?;
            let m = r.count(40, "seen by")?;
            let mut thresholds = BTreeMap::new();
            for _ in 0..m {
                let by = r.device()?;
                ascending(thresholds.keys().next_back(), &by, "seen by")?;
                thresholds.insert(by, r.u64()?);
            }
            meta.seen_by.insert(key, thresholds);
        }
        let n = r.count(32, "epochs")?;
        for _ in 0..n {
            let epoch = EpochId::from_frame_id(r.frame_id()?);
            ascending(meta.epochs.last(), &epoch, "epochs")?;
            meta.epochs.insert(epoch);
        }
        Ok(meta)
    }
}

/// A checkpoint's plaintext pack: state plus meta, sealed by `deadbolt-pack` before upload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pack {
    pub state: FoldedState,
    pub meta: PackMeta,
}
