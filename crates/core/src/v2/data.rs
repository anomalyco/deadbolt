//! Data-plane payloads sealed inside `FrameKind::Data` bodies, their ops, opened data
//! frames, and rule E7 (frontier honesty).
//!
//! `pt = mheads:[FrameId] ‖ dclock:[(DeviceId, count)] ‖ timestamp_ms ‖ ops`, sealed under
//! `K_data(epoch)` with Padmé padding and `aad = hdr` by [`Frame::seal_data`].

use std::collections::BTreeMap;

use crate::id::{DeviceId, DeviceSecret, ItemId, VaultId};

use super::checkpoint::CheckpointPayload;
use super::clock::{DeltaClock, VectorClock, diff_clock, frame_clock};
use super::crypto::{EpochId, EpochKey, FrameId, NetPublic};
use super::frame::{Frame, FrameKind, MAX_DEPS};
use super::wire::{PayloadError, Reader, Writer, ascending};

/// Longest item kind, field name, field kind, vault name or device label, in bytes.
pub const MAX_LABEL_LEN: usize = 1024;
/// Longest inline field value, in bytes (larger fields become blob objects).
pub const MAX_FIELD_VALUE_LEN: usize = 64 * 1024;
/// Most ops in one data frame.
pub const MAX_OPS: usize = 4096;

/// A typed field value. The type travels with the value in the register.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldValue {
    pub kind: String,
    pub value: String,
}

/// One data-plane operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataOp {
    /// Creates (or re-types) an item; also revives it.
    PutItem { item: ItemId, kind: String },
    /// Sets one field; also revives the item.
    SetField {
        item: ItemId,
        field: String,
        value: FieldValue,
    },
    /// Clears one field; also revives the item.
    ClearField { item: ItemId, field: String },
    /// Tombstones the item at the frame's `timestamp_ms`. A concurrent edit wins.
    DeleteItem { item: ItemId },
    /// Brings a deleted item back.
    RestoreItem { item: ItemId },
    /// The vault's human name (moved out of the plaintext membership log).
    VaultMeta { name: String },
    /// A device's transport key and label. Valid only from the device itself or its adder.
    DeviceCard {
        device: DeviceId,
        net_pk: NetPublic,
        label: String,
    },
    /// A full peer's recomputed fold disagrees with `checkpoint`'s `state_mac`.
    Dispute {
        checkpoint: FrameId,
        expected_state_mac: [u8; 32],
    },
}

/// Decrypted plaintext of a `Data` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPayload {
    /// Membership view the write was made under, strictly sorted.
    pub mheads: Vec<FrameId>,
    /// Data streams that advanced since the author's `prev` frame.
    pub dclock: DeltaClock,
    /// Author's wall clock; only used for tombstone times and GC grace.
    pub timestamp_ms: u64,
    pub ops: Vec<DataOp>,
}

pub(crate) fn encode_mheads(w: &mut Writer, mheads: &[FrameId]) -> Result<(), PayloadError> {
    let mut prev = None;
    for head in mheads {
        ascending(prev, head, "mheads")?;
        prev = Some(head);
    }
    w.count(mheads.len(), "mheads")?;
    for head in mheads {
        w.frame_id(head);
    }
    Ok(())
}

pub(crate) fn decode_mheads(r: &mut Reader<'_>) -> Result<Vec<FrameId>, PayloadError> {
    let len = r.count(32, "mheads")?;
    if len > MAX_DEPS {
        return Err(PayloadError::TooLarge {
            what: "mheads",
            len,
            max: MAX_DEPS,
        });
    }
    let mut out: Vec<FrameId> = Vec::with_capacity(len);
    for _ in 0..len {
        let head = r.frame_id()?;
        ascending(out.last(), &head, "mheads")?;
        out.push(head);
    }
    Ok(out)
}

impl FieldValue {
    pub(crate) fn encode(&self, w: &mut Writer) -> Result<(), PayloadError> {
        w.str(&self.kind, MAX_LABEL_LEN, "field kind")?;
        w.str(&self.value, MAX_FIELD_VALUE_LEN, "field value")
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Self, PayloadError> {
        Ok(Self {
            kind: r.str(MAX_LABEL_LEN, "field kind")?,
            value: r.str(MAX_FIELD_VALUE_LEN, "field value")?,
        })
    }
}

fn field_name(r: &mut Reader<'_>) -> Result<String, PayloadError> {
    let name = r.str(MAX_LABEL_LEN, "field name")?;
    if name.is_empty() {
        return Err(PayloadError::Invalid("field name must be non-empty"));
    }
    Ok(name)
}

fn write_field_name(w: &mut Writer, name: &str) -> Result<(), PayloadError> {
    if name.is_empty() {
        return Err(PayloadError::Invalid("field name must be non-empty"));
    }
    w.str(name, MAX_LABEL_LEN, "field name")
}

impl DataOp {
    /// The item this op touches, if any.
    pub fn item(&self) -> Option<ItemId> {
        match self {
            Self::PutItem { item, .. }
            | Self::SetField { item, .. }
            | Self::ClearField { item, .. }
            | Self::DeleteItem { item }
            | Self::RestoreItem { item } => Some(*item),
            _ => None,
        }
    }

    pub(crate) fn encode(&self, w: &mut Writer) -> Result<(), PayloadError> {
        match self {
            Self::PutItem { item, kind } => {
                w.u8(0);
                w.item(item);
                w.str(kind, MAX_LABEL_LEN, "item kind")?;
            }
            Self::SetField { item, field, value } => {
                w.u8(1);
                w.item(item);
                write_field_name(w, field)?;
                value.encode(w)?;
            }
            Self::ClearField { item, field } => {
                w.u8(2);
                w.item(item);
                write_field_name(w, field)?;
            }
            Self::DeleteItem { item } => {
                w.u8(3);
                w.item(item);
            }
            Self::RestoreItem { item } => {
                w.u8(4);
                w.item(item);
            }
            Self::VaultMeta { name } => {
                w.u8(5);
                w.str(name, MAX_LABEL_LEN, "vault name")?;
            }
            Self::DeviceCard {
                device,
                net_pk,
                label,
            } => {
                w.u8(6);
                w.device(device);
                w.bytes(net_pk.as_bytes());
                w.str(label, MAX_LABEL_LEN, "device label")?;
            }
            Self::Dispute {
                checkpoint,
                expected_state_mac,
            } => {
                w.u8(7);
                w.frame_id(checkpoint);
                w.bytes(expected_state_mac);
            }
        }
        Ok(())
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Self, PayloadError> {
        Ok(match r.u8()? {
            0 => Self::PutItem {
                item: r.item()?,
                kind: r.str(MAX_LABEL_LEN, "item kind")?,
            },
            1 => Self::SetField {
                item: r.item()?,
                field: field_name(r)?,
                value: FieldValue::decode(r)?,
            },
            2 => Self::ClearField {
                item: r.item()?,
                field: field_name(r)?,
            },
            3 => Self::DeleteItem { item: r.item()? },
            4 => Self::RestoreItem { item: r.item()? },
            5 => Self::VaultMeta {
                name: r.str(MAX_LABEL_LEN, "vault name")?,
            },
            6 => Self::DeviceCard {
                device: r.device()?,
                net_pk: NetPublic::from_bytes(r.array::<32>()?),
                label: r.str(MAX_LABEL_LEN, "device label")?,
            },
            7 => Self::Dispute {
                checkpoint: r.frame_id()?,
                expected_state_mac: r.array::<32>()?,
            },
            tag => {
                return Err(PayloadError::InvalidTag {
                    what: "data op",
                    tag,
                });
            }
        })
    }
}

impl DataPayload {
    /// Canonical plaintext bytes.
    pub fn encode(&self) -> Result<Vec<u8>, PayloadError> {
        let mut w = Writer::new();
        encode_mheads(&mut w, &self.mheads)?;
        self.dclock.encode(&mut w)?;
        w.u64(self.timestamp_ms);
        if self.ops.len() > MAX_OPS {
            return Err(PayloadError::TooLarge {
                what: "ops",
                len: self.ops.len(),
                max: MAX_OPS,
            });
        }
        w.count(self.ops.len(), "ops")?;
        for op in &self.ops {
            op.encode(&mut w)?;
        }
        Ok(w.into_bytes())
    }

    /// Strict canonical decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, PayloadError> {
        let mut r = Reader::new(bytes);
        let mheads = decode_mheads(&mut r)?;
        let dclock = DeltaClock::decode(&mut r)?;
        let timestamp_ms = r.u64()?;
        // Smallest op: a tag and an empty vault name.
        let len = r.count(5, "ops")?;
        if len > MAX_OPS {
            return Err(PayloadError::TooLarge {
                what: "ops",
                len,
                max: MAX_OPS,
            });
        }
        let mut ops = Vec::with_capacity(len);
        for _ in 0..len {
            ops.push(DataOp::decode(&mut r)?);
        }
        r.finish()?;
        Ok(Self {
            mheads,
            dclock,
            timestamp_ms,
            ops,
        })
    }

    /// Seals this payload as a signed `Data` frame.
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
        Ok(Frame::seal_data(
            author, vault, seq, prev, epoch, epoch_key, &pt,
        )?)
    }
}

/// The decrypted body of a data-log frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataBody {
    Data(DataPayload),
    Checkpoint(CheckpointPayload),
}

impl DataBody {
    pub fn mheads(&self) -> &[FrameId] {
        match self {
            Self::Data(p) => &p.mheads,
            Self::Checkpoint(c) => &c.mheads,
        }
    }

    pub fn timestamp_ms(&self) -> u64 {
        match self {
            Self::Data(p) => p.timestamp_ms,
            Self::Checkpoint(c) => c.timestamp_ms,
        }
    }
}

/// A verified, decrypted data-log frame (`Data` or `Checkpoint`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFrame {
    pub id: FrameId,
    pub author: DeviceId,
    pub seq: u64,
    pub prev: FrameId,
    /// The epoch the frame was sealed under: a checkpoint's `K_mac` comes from this epoch.
    pub epoch: EpochId,
    pub body: DataBody,
}

impl DataFrame {
    /// Opens a verified `Data` or `Checkpoint` frame with its epoch key and decodes it.
    pub fn open(frame: &Frame, epoch_key: &EpochKey) -> Result<Self, PayloadError> {
        let hdr = frame.header();
        let pt = frame.open_sealed(epoch_key)?;
        let body = match hdr.kind {
            FrameKind::Data => DataBody::Data(DataPayload::decode(&pt)?),
            FrameKind::Checkpoint => DataBody::Checkpoint(CheckpointPayload::decode(&pt)?),
            FrameKind::Member => return Err(PayloadError::WrongKind),
        };
        Ok(Self {
            id: frame.id(),
            author: hdr.author,
            seq: hdr.seq,
            prev: hdr.prev,
            epoch: hdr.epoch,
            body,
        })
    }

    pub fn dot(&self) -> super::clock::Dot {
        super::clock::Dot {
            author: self.author,
            seq: self.seq,
            frame: self.id,
        }
    }

    /// This frame's full clock given its `prev` frame's full clock.
    ///
    /// A `Checkpoint` frame carries no `dclock`; its frontier is what it saw.
    pub fn clock_after(&self, prev: &VectorClock) -> VectorClock {
        match &self.body {
            DataBody::Data(p) => frame_clock(prev, &p.dclock, self.author, self.seq),
            DataBody::Checkpoint(c) => {
                let mut clock = prev.clone();
                for (author, seq, _) in &c.frontier {
                    clock.observe(*author, *seq);
                }
                clock.observe(self.author, self.seq);
                clock
            }
        }
    }
}

/// Rule E7 (frontier honesty): the clock a device may claim, given every data frame it holds
/// as `(author, seq, readable)`. A stream advances only through a gap-free prefix of frames
/// that decrypted, were not disputed and that the fold resolved causally (pass `false` for a
/// frame still waiting on a frame it names); an undecryptable frame stops its stream there.
/// The result need not be causally closed: the fold closes every clock itself.
pub fn honest_clock(observed: impl IntoIterator<Item = (DeviceId, u64, bool)>) -> VectorClock {
    let mut streams: BTreeMap<DeviceId, BTreeMap<u64, bool>> = BTreeMap::new();
    for (author, seq, readable) in observed {
        let slot = streams
            .entry(author)
            .or_default()
            .entry(seq)
            .or_insert(true);
        *slot &= readable;
    }
    VectorClock::from_counts(streams.into_iter().map(|(author, seqs)| {
        let mut count = 0u64;
        for (seq, readable) in seqs {
            if seq != count || !readable {
                break;
            }
            count += 1;
        }
        (author, count)
    }))
}

/// The `dclock` a writer emits: what its honest clock gained since its own `prev` frame,
/// minus its own stream (implied by `seq`).
pub fn next_dclock(
    prev_clock: &VectorClock,
    honest: &VectorClock,
    author: &DeviceId,
) -> DeltaClock {
    let others = VectorClock::from_counts(
        honest
            .iter()
            .filter(|(a, _)| *a != author)
            .map(|(a, n)| (*a, *n)),
    );
    diff_clock(prev_clock, &others)
}
