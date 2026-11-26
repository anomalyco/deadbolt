//! The folded data-plane state, its multi-value registers, and the deterministic `state_mac`.
//!
//! Like v1's `data.rs`, every field, an item's kind, its tombstone, the vault name and each
//! device card is a register holding the frontier of writes no other write was based on.
//! A new write drops the frontier writes it causally follows. Several concurrent writes stay
//! in the frontier (a conflict); the winner is the highest `(author, seq, frame_id, index)`.
//! Any change but a delete revives an item, so a concurrent edit beats a delete.
//!
//! Inserting into a register only needs the causal closures (see `causal`) of the new write and
//! of the writes still standing, which is why a checkpoint keeps exactly those clocks (`dots`)
//! and the thresholds at which later frames saw them (`seen_by`).

use std::collections::{BTreeMap, BTreeSet};

use crate::id::{DeviceId, ItemId};

use super::causal::Book;
use super::clock::{Dot, VectorClock};
use super::crypto::{FrameId, NetPublic};
use super::data::{DataOp, DataPayload, FieldValue, MAX_LABEL_LEN};
use super::wire::{PayloadError, Reader, Writer, ascending};

/// Full clocks of data frames by `(author, seq)`.
pub type ClockBook = BTreeMap<(DeviceId, u64), VectorClock>;

const STATE_DOMAIN: &[u8] = b"deadbolt/v2 state\0";

/// One write to a register: the frame that made it and the op's index in that frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Write<V> {
    pub dot: Dot,
    pub index: u32,
    pub value: V,
}

impl<V> Write<V> {
    fn key(&self) -> (Dot, u32) {
        (self.dot, self.index)
    }

    /// True iff this write was based on `other` (`other` happened before it), judged on the
    /// transitive closures in `book`.
    fn follows<U>(&self, other: &Write<U>, book: &Book<'_>) -> bool {
        if self.dot.author == other.dot.author && self.dot.seq == other.dot.seq {
            other.index < self.index
        } else {
            book.covers(
                (self.dot.author, self.dot.seq),
                (other.dot.author, other.dot.seq),
            )
        }
    }
}

/// A multi-value register: the antichain of writes no other write followed, sorted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register<V> {
    writes: Vec<Write<V>>,
}

impl<V> Default for Register<V> {
    fn default() -> Self {
        Self { writes: Vec::new() }
    }
}

impl<V> Register<V> {
    /// Every concurrent write still standing, in canonical order.
    pub fn writes(&self) -> &[Write<V>] {
        &self.writes
    }

    /// The current value's write: the highest `(author, seq, frame_id, index)`.
    pub fn winner(&self) -> Option<&Write<V>> {
        self.writes.last()
    }

    /// True iff concurrent writes disagree about who won.
    pub fn is_conflicted(&self) -> bool {
        self.writes.len() > 1
    }

    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Inserts `write`; `book` holds the causal closures of its frame and of the writes
    /// already standing. Order-independent because `follows` is transitive: the result is the
    /// antichain of maximal writes.
    pub(crate) fn insert(&mut self, write: Write<V>, book: &Book<'_>) {
        let key = write.key();
        if self.writes.iter().any(|e| e.key() == key) {
            return;
        }
        if self.writes.iter().any(|e| e.follows(&write, book)) {
            return;
        }
        self.writes.retain(|e| !write.follows(e, book));
        let at = self.writes.partition_point(|e| e.key() < key);
        self.writes.insert(at, write);
    }

    fn dots(&self) -> impl Iterator<Item = &Dot> {
        self.writes.iter().map(|w| &w.dot)
    }
}

/// Whether an item is alive, as one write to its tombstone register says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Life {
    Alive,
    Deleted { at_ms: u64 },
}

/// A device's transport key and label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCardValue {
    pub net_pk: NetPublic,
    pub label: String,
}

/// A `Dispute` op seen in a counted frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DisputeRecord {
    pub checkpoint: FrameId,
    pub author: DeviceId,
    pub expected_state_mac: [u8; 32],
}

/// A deleted item's winning delete: its dot and time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tombstone {
    pub dot: Dot,
    pub at_ms: u64,
}

/// Which ops one fold pass applies: all of them, or one of `of` disjoint
/// shards split by item, with the vault-wide ops in shard 0. Items fold
/// independently, so shards can fold in parallel and merge by union.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Shard {
    pub k: usize,
    pub of: usize,
}

impl Shard {
    pub const ALL: Self = Self { k: 0, of: 1 };

    fn takes(self, op: &DataOp) -> bool {
        let item = match op {
            DataOp::PutItem { item, .. }
            | DataOp::SetField { item, .. }
            | DataOp::ClearField { item, .. }
            | DataOp::DeleteItem { item }
            | DataOp::RestoreItem { item } => item,
            DataOp::VaultMeta { .. } | DataOp::DeviceCard { .. } | DataOp::Dispute { .. } => {
                return self.k == 0;
            }
        };
        usize::from(item.as_bytes()[0]) % self.of == self.k
    }
}

/// `field`'s register, cloning its name only the first time: unlock folds
/// every op, and most fields already exist by their second write.
fn field_register<'a>(
    fields: &'a mut BTreeMap<String, Register<Option<FieldValue>>>,
    field: &str,
) -> &'a mut Register<Option<FieldValue>> {
    if !fields.contains_key(field) {
        fields.insert(field.to_owned(), Register::default());
    }
    #[expect(clippy::expect_used, reason = "inserted just above")]
    fields.get_mut(field).expect("present")
}

/// One item's registers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemState {
    pub kind: Register<String>,
    /// `None` is a cleared field.
    pub fields: BTreeMap<String, Register<Option<FieldValue>>>,
    pub life: Register<Life>,
}

impl ItemState {
    /// Deleted unless some standing write to the tombstone register is an edit or restore.
    pub fn deleted(&self) -> bool {
        !self.life.writes().iter().any(|w| w.value == Life::Alive)
    }

    /// The latest standing delete, if the item is deleted.
    pub fn tombstone(&self) -> Option<Tombstone> {
        if !self.deleted() {
            return None;
        }
        self.life
            .writes()
            .iter()
            .filter_map(|w| match w.value {
                Life::Deleted { at_ms } => Some((at_ms, w.dot)),
                Life::Alive => None,
            })
            .max()
            .map(|(at_ms, dot)| Tombstone { dot, at_ms })
    }

    /// Created, not deleted, with its current field values.
    pub fn live_fields(&self) -> Option<BTreeMap<&str, &FieldValue>> {
        if self.kind.is_empty() || self.deleted() {
            return None;
        }
        Some(
            self.fields
                .iter()
                .filter_map(|(name, reg)| Some((name.as_str(), reg.winner()?.value.as_ref()?)))
                .collect(),
        )
    }
}

/// The deterministic fold of every counted data frame.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FoldedState {
    pub items: BTreeMap<ItemId, ItemState>,
    pub vault_meta: Register<String>,
    pub device_cards: BTreeMap<DeviceId, Register<DeviceCardValue>>,
    pub disputes: BTreeSet<DisputeRecord>,
}

impl FoldedState {
    /// The vault's current name.
    pub fn vault_name(&self) -> Option<&str> {
        self.vault_meta.winner().map(|w| w.value.as_str())
    }

    /// Every currently deleted item and its winning delete.
    pub fn tombstones(&self) -> BTreeMap<ItemId, Tombstone> {
        self.items
            .iter()
            .filter_map(|(id, item)| Some((*id, item.tombstone()?)))
            .collect()
    }

    /// Every dot that owns a standing register write.
    pub fn dots(&self) -> BTreeSet<(DeviceId, u64)> {
        let mut out = BTreeSet::new();
        let mut add = |d: &Dot| {
            out.insert((d.author, d.seq));
        };
        for item in self.items.values() {
            item.kind.dots().for_each(&mut add);
            item.life.dots().for_each(&mut add);
            item.fields
                .values()
                .flat_map(Register::dots)
                .for_each(&mut add);
        }
        self.vault_meta.dots().for_each(&mut add);
        self.device_cards
            .values()
            .flat_map(Register::dots)
            .for_each(&mut add);
        out
    }

    /// True iff a dispute naming `checkpoint` came from one of `members`.
    pub fn is_disputed(&self, checkpoint: &FrameId, members: &BTreeSet<DeviceId>) -> bool {
        self.disputes
            .iter()
            .any(|d| d.checkpoint == *checkpoint && members.contains(&d.author))
    }

    /// Applies the ops of one counted data frame whose closure is already in `book`.
    /// `card_ok(author, device)` decides `DeviceCard` authority.
    ///
    /// The state only ever changes through logged ops, so `state_mac` stays a pure function of
    /// the counted frames; there is deliberately no local tombstone pruning.
    pub(crate) fn apply(
        &mut self,
        dot: Dot,
        payload: &DataPayload,
        book: &Book<'_>,
        card_ok: impl Fn(&DeviceId, &DeviceId) -> bool,
        shard: Shard,
    ) {
        for (index, op) in payload.ops.iter().enumerate() {
            if !shard.takes(op) {
                continue;
            }
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            let alive = Write {
                dot,
                index,
                value: Life::Alive,
            };
            match op {
                DataOp::PutItem { item, kind } => {
                    let state = self.items.entry(*item).or_default();
                    let write = Write {
                        dot,
                        index,
                        value: kind.clone(),
                    };
                    state.kind.insert(write, book);
                    state.life.insert(alive, book);
                }
                DataOp::SetField { item, field, value } => {
                    let state = self.items.entry(*item).or_default();
                    let write = Write {
                        dot,
                        index,
                        value: Some(value.clone()),
                    };
                    field_register(&mut state.fields, field).insert(write, book);
                    state.life.insert(alive, book);
                }
                DataOp::ClearField { item, field } => {
                    let state = self.items.entry(*item).or_default();
                    let write = Write {
                        dot,
                        index,
                        value: None,
                    };
                    field_register(&mut state.fields, field).insert(write, book);
                    state.life.insert(alive, book);
                }
                DataOp::DeleteItem { item } => {
                    let at_ms = payload.timestamp_ms;
                    let write = Write {
                        dot,
                        index,
                        value: Life::Deleted { at_ms },
                    };
                    self.items
                        .entry(*item)
                        .or_default()
                        .life
                        .insert(write, book);
                }
                DataOp::RestoreItem { item } => {
                    self.items
                        .entry(*item)
                        .or_default()
                        .life
                        .insert(alive, book);
                }
                DataOp::VaultMeta { name } => {
                    let write = Write {
                        dot,
                        index,
                        value: name.clone(),
                    };
                    self.vault_meta.insert(write, book);
                }
                DataOp::DeviceCard {
                    device,
                    net_pk,
                    label,
                } => {
                    if !card_ok(&dot.author, device) {
                        continue;
                    }
                    let value = DeviceCardValue {
                        net_pk: *net_pk,
                        label: label.clone(),
                    };
                    let write = Write { dot, index, value };
                    let reg = self.device_cards.entry(*device).or_default();
                    reg.insert(write, book);
                }
                DataOp::Dispute {
                    checkpoint,
                    expected_state_mac,
                } => {
                    self.disputes.insert(DisputeRecord {
                        checkpoint: *checkpoint,
                        author: dot.author,
                        expected_state_mac: *expected_state_mac,
                    });
                }
            }
        }
    }

    /// Canonical, architecture-independent bytes: sorted items, fields, writes, cards and
    /// disputes with fixed-width big-endian integers.
    pub fn encode(&self) -> Result<Vec<u8>, PayloadError> {
        let mut w = Writer::new();
        self.encode_into(&mut w)?;
        Ok(w.into_bytes())
    }

    pub(crate) fn encode_into(&self, w: &mut Writer) -> Result<(), PayloadError> {
        w.bytes(STATE_DOMAIN);
        w.count(self.items.len(), "items")?;
        for (id, item) in &self.items {
            w.item(id);
            encode_register(w, &item.kind)?;
            w.count(item.fields.len(), "fields")?;
            for (name, reg) in &item.fields {
                w.str(name, MAX_LABEL_LEN, "field name")?;
                encode_register(w, reg)?;
            }
            encode_register(w, &item.life)?;
        }
        encode_register(w, &self.vault_meta)?;
        w.count(self.device_cards.len(), "device cards")?;
        for (device, reg) in &self.device_cards {
            w.device(device);
            encode_register(w, reg)?;
        }
        w.count(self.disputes.len(), "disputes")?;
        for d in &self.disputes {
            w.frame_id(&d.checkpoint);
            w.device(&d.author);
            w.bytes(&d.expected_state_mac);
        }
        Ok(())
    }

    /// Strict canonical decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, PayloadError> {
        let mut r = Reader::new(bytes);
        let state = Self::decode_from(&mut r)?;
        r.finish()?;
        Ok(state)
    }

    pub(crate) fn decode_from(r: &mut Reader<'_>) -> Result<Self, PayloadError> {
        if r.take(STATE_DOMAIN.len())? != STATE_DOMAIN {
            return Err(PayloadError::Invalid("state domain"));
        }
        let mut state = Self::default();
        let n = r.count(16 + 12, "items")?;
        let mut prev_item = None;
        for _ in 0..n {
            let id = r.item()?;
            ascending(prev_item.as_ref(), &id, "items")?;
            prev_item = Some(id);
            let kind = decode_register(r)?;
            let mut fields = BTreeMap::new();
            let nf = r.count(8, "fields")?;
            let mut prev_name: Option<String> = None;
            for _ in 0..nf {
                let name = r.str(MAX_LABEL_LEN, "field name")?;
                if name.is_empty() {
                    return Err(PayloadError::Invalid("field name must be non-empty"));
                }
                ascending(prev_name.as_ref(), &name, "fields")?;
                prev_name = Some(name.clone());
                fields.insert(name, non_empty(decode_register(r)?)?);
            }
            let life = non_empty(decode_register(r)?)?;
            state.items.insert(id, ItemState { kind, fields, life });
        }
        state.vault_meta = decode_register(r)?;
        let nc = r.count(36, "device cards")?;
        let mut prev_dev = None;
        for _ in 0..nc {
            let device = r.device()?;
            ascending(prev_dev.as_ref(), &device, "device cards")?;
            prev_dev = Some(device);
            state
                .device_cards
                .insert(device, non_empty(decode_register(r)?)?);
        }
        let nd = r.count(96, "disputes")?;
        let mut prev_d = None;
        for _ in 0..nd {
            let d = DisputeRecord {
                checkpoint: r.frame_id()?,
                author: r.device()?,
                expected_state_mac: r.array::<32>()?,
            };
            ascending(prev_d.as_ref(), &d, "disputes")?;
            prev_d = Some(d);
            state.disputes.insert(d);
        }
        Ok(state)
    }
}

/// `BLAKE3::keyed_hash(K_mac(epoch), canonical_bytes(state))`.
pub fn state_mac(k_mac: &[u8; 32], state: &FoldedState) -> Result<[u8; 32], PayloadError> {
    Ok(blake3::keyed_hash(k_mac, &state.encode()?).into())
}

pub(crate) fn non_empty<V>(reg: Register<V>) -> Result<Register<V>, PayloadError> {
    if reg.is_empty() {
        Err(PayloadError::Invalid("empty register"))
    } else {
        Ok(reg)
    }
}

/// A register value with a canonical encoding.
pub(crate) trait RegValue: Sized {
    fn encode(&self, w: &mut Writer) -> Result<(), PayloadError>;
    fn decode(r: &mut Reader<'_>) -> Result<Self, PayloadError>;
}

impl RegValue for String {
    fn encode(&self, w: &mut Writer) -> Result<(), PayloadError> {
        w.str(self, MAX_LABEL_LEN, "register string")
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self, PayloadError> {
        r.str(MAX_LABEL_LEN, "register string")
    }
}

impl RegValue for Option<FieldValue> {
    fn encode(&self, w: &mut Writer) -> Result<(), PayloadError> {
        match self {
            None => w.u8(0),
            Some(v) => {
                w.u8(1);
                v.encode(w)?;
            }
        }
        Ok(())
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self, PayloadError> {
        match r.u8()? {
            0 => Ok(None),
            1 => Ok(Some(FieldValue::decode(r)?)),
            tag => Err(PayloadError::InvalidTag { what: "field", tag }),
        }
    }
}

impl RegValue for Life {
    fn encode(&self, w: &mut Writer) -> Result<(), PayloadError> {
        match self {
            Self::Alive => w.u8(0),
            Self::Deleted { at_ms } => {
                w.u8(1);
                w.u64(*at_ms);
            }
        }
        Ok(())
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self, PayloadError> {
        match r.u8()? {
            0 => Ok(Self::Alive),
            1 => Ok(Self::Deleted { at_ms: r.u64()? }),
            tag => Err(PayloadError::InvalidTag { what: "life", tag }),
        }
    }
}

impl RegValue for DeviceCardValue {
    fn encode(&self, w: &mut Writer) -> Result<(), PayloadError> {
        w.bytes(self.net_pk.as_bytes());
        w.str(&self.label, MAX_LABEL_LEN, "device label")
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self, PayloadError> {
        Ok(Self {
            net_pk: NetPublic::from_bytes(r.array::<32>()?),
            label: r.str(MAX_LABEL_LEN, "device label")?,
        })
    }
}

pub(crate) fn encode_register<V: RegValue>(
    w: &mut Writer,
    reg: &Register<V>,
) -> Result<(), PayloadError> {
    w.count(reg.writes.len(), "register")?;
    for write in &reg.writes {
        write.dot.encode(w);
        w.u32(write.index);
        write.value.encode(w)?;
    }
    Ok(())
}

pub(crate) fn decode_register<V: RegValue>(
    r: &mut Reader<'_>,
) -> Result<Register<V>, PayloadError> {
    let n = r.count(77, "register")?;
    let mut writes: Vec<Write<V>> = Vec::with_capacity(n);
    for _ in 0..n {
        let dot = Dot::decode(r)?;
        let index = r.u32()?;
        let key = (dot, index);
        ascending(writes.last().map(|w| w.key()).as_ref(), &key, "register")?;
        writes.push(Write {
            dot,
            index,
            value: V::decode(r)?,
        });
    }
    Ok(Register { writes })
}
