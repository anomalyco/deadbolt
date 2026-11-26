//! A pack as `deadbolt-pack` records: the canonical layout every
//! `gen-<n>.pack` and remote `p/<pack_hash>` uses.
//!
//! ```text
//! Meta   = "deadbolt/v2 pack meta\0" || vault_meta register || device cards || disputes
//!          || PackMeta || item count u32
//! Head   = "deadbolt/v2 pack head\0" || item id || kind register || life register
//!          || public fields (name, register)… || secret fields (name, winning kind)…
//! Secret = "deadbolt/v2 pack secret\0" || item id || secret fields (name, register)…
//!          || fill copies (name, winning value)…
//! ```
//!
//! Items go in ascending id order, one Head and one Secret each. Every
//! register is written once, whole (every standing write, its dot and
//! index), so [`Pack::join`] rebuilds the [`FoldedState`] bit for bit and
//! `fold_from_checkpoint` merges later frames into it. A field is secret
//! when any standing write to it has a secret type
//! ([`is_secret_register`]); its name and winning type stay in the Head so
//! a picker can say "has a password" without opening the Secret.
//!
//! The Secret also repeats the winning values of [`FILL_COPIES`] (a
//! passkey's credential id and user handle), so a fill reads one record.
//! [`Pack::join`] checks each copy against the Head's register, so the
//! copies can't disagree with what they copy.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::id::ItemId;
use crate::item::FieldType;

use super::super::data::{FieldValue, MAX_FIELD_VALUE_LEN, MAX_LABEL_LEN};
use super::super::state::{
    DeviceCardValue, FoldedState, ItemState, Life, Register, decode_register, encode_register,
    non_empty,
};
use super::super::wire::{PayloadError, Reader, Writer, ascending};
use super::{Pack, PackMeta};

const META_DOMAIN: &[u8] = b"deadbolt/v2 pack meta\0";
const HEAD_DOMAIN: &[u8] = b"deadbolt/v2 pack head\0";
const SECRET_DOMAIN: &[u8] = b"deadbolt/v2 pack secret\0";

/// Head fields whose winning value the Secret repeats for a one-record fill.
pub const FILL_COPIES: [&str; 2] = ["credential-id", "user-handle"];

/// One item's two records.
pub struct ItemRecords {
    pub id: ItemId,
    pub head: Vec<u8>,
    pub secret: Zeroizing<Vec<u8>>,
}

/// A pack split into its records, items in id order.
pub struct PackRecords {
    pub meta: Zeroizing<Vec<u8>>,
    pub items: Vec<ItemRecords>,
}

/// An item's Head record, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemHead {
    pub id: ItemId,
    pub kind: Register<String>,
    pub life: Register<Life>,
    /// Fields no write gave a secret type.
    pub fields: BTreeMap<String, Register<Option<FieldValue>>>,
    /// The Secret's fields: name and its winning write's type (empty when
    /// the winner cleared it).
    pub secret_fields: BTreeMap<String, String>,
}

/// An item's Secret record, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSecret {
    pub id: ItemId,
    pub fields: BTreeMap<String, Register<Option<FieldValue>>>,
    /// Winning values of [`FILL_COPIES`] the Head holds.
    pub fill: BTreeMap<String, String>,
}

/// Whether a field register belongs in the Secret: any standing write
/// with a secret type (`FieldType::is_secret`). Reserved `@` registers
/// never are.
pub fn is_secret_register(name: &str, reg: &Register<Option<FieldValue>>) -> bool {
    !name.starts_with('@')
        && reg.writes().iter().any(|w| {
            w.value
                .as_ref()
                .is_some_and(|v| FieldType::parse(&v.kind).is_secret())
        })
}

fn winner_value(reg: &Register<Option<FieldValue>>) -> Option<&FieldValue> {
    reg.winner()?.value.as_ref()
}

impl Pack {
    /// The pack as Meta plus each item's Head and Secret.
    pub fn split(&self) -> Result<PackRecords, PayloadError> {
        let mut w = Writer::new();
        w.bytes(META_DOMAIN);
        encode_register(&mut w, &self.state.vault_meta)?;
        w.count(self.state.device_cards.len(), "device cards")?;
        for (device, reg) in &self.state.device_cards {
            w.device(device);
            encode_register(&mut w, reg)?;
        }
        w.count(self.state.disputes.len(), "disputes")?;
        for d in &self.state.disputes {
            w.frame_id(&d.checkpoint);
            w.device(&d.author);
            w.bytes(&d.expected_state_mac);
        }
        self.meta.encode_into(&mut w)?;
        w.count(self.state.items.len(), "items")?;
        let meta = Zeroizing::new(w.into_bytes());
        let items = self
            .state
            .items
            .iter()
            .map(|(id, item)| split_item(id, item))
            .collect::<Result<_, _>>()?;
        Ok(PackRecords { meta, items })
    }

    /// Rebuilds a pack from its Meta and each item's (Head, Secret), in
    /// order. Refuses anything [`Pack::split`] would not have written.
    pub fn join<'a>(
        meta: &[u8],
        items: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    ) -> Result<Self, PayloadError> {
        let mut r = Reader::new(meta);
        if r.take(META_DOMAIN.len())? != META_DOMAIN {
            return Err(PayloadError::Invalid("pack meta domain"));
        }
        let mut state = FoldedState {
            vault_meta: decode_register(&mut r)?,
            ..FoldedState::default()
        };
        let nc = r.count(36, "device cards")?;
        for _ in 0..nc {
            let device = r.device()?;
            ascending(
                state.device_cards.keys().next_back(),
                &device,
                "device cards",
            )?;
            let reg: Register<DeviceCardValue> = non_empty(decode_register(&mut r)?)?;
            state.device_cards.insert(device, reg);
        }
        let nd = r.count(96, "disputes")?;
        for _ in 0..nd {
            let d = super::super::state::DisputeRecord {
                checkpoint: r.frame_id()?,
                author: r.device()?,
                expected_state_mac: r.array::<32>()?,
            };
            ascending(state.disputes.last(), &d, "disputes")?;
            state.disputes.insert(d);
        }
        let meta = PackMeta::decode_from(&mut r)?;
        let count = r.count(0, "items")?;
        r.finish()?;
        for (head, secret) in items {
            let head = ItemHead::decode(head)?;
            let secret = ItemSecret::decode(secret)?;
            ascending(state.items.keys().next_back(), &head.id, "items")?;
            state.items.insert(head.id, join_item(head, secret)?);
        }
        if state.items.len() != count {
            return Err(PayloadError::Invalid("pack item count"));
        }
        meta.validate(&state)?;
        Ok(Self { state, meta })
    }
}

fn split_item(id: &ItemId, item: &ItemState) -> Result<ItemRecords, PayloadError> {
    let (secret, public): (Vec<_>, Vec<_>) = item
        .fields
        .iter()
        .partition(|(name, reg)| is_secret_register(name, reg));
    let mut w = Writer::new();
    w.bytes(HEAD_DOMAIN);
    w.item(id);
    encode_register(&mut w, &item.kind)?;
    encode_register(&mut w, &item.life)?;
    w.count(public.len(), "fields")?;
    for (name, reg) in &public {
        w.str(name, MAX_LABEL_LEN, "field name")?;
        encode_register(&mut w, reg)?;
    }
    w.count(secret.len(), "secret fields")?;
    for (name, reg) in &secret {
        w.str(name, MAX_LABEL_LEN, "field name")?;
        let kind = winner_value(reg).map_or("", |v| v.kind.as_str());
        w.str(kind, MAX_LABEL_LEN, "field type")?;
    }
    let head = w.into_bytes();
    let mut w = Writer::new();
    w.bytes(SECRET_DOMAIN);
    w.item(id);
    w.count(secret.len(), "secret fields")?;
    for (name, reg) in &secret {
        w.str(name, MAX_LABEL_LEN, "field name")?;
        encode_register(&mut w, reg)?;
    }
    let copies: Vec<(&str, &str)> = FILL_COPIES
        .iter()
        .filter_map(|name| {
            let value = winner_value(item.fields.get(*name)?)?;
            (!is_secret_register(name, &item.fields[*name]))
                .then_some((*name, value.value.as_str()))
        })
        .collect();
    w.count(copies.len(), "fill copies")?;
    for (name, value) in copies {
        w.str(name, MAX_LABEL_LEN, "field name")?;
        w.str(value, MAX_FIELD_VALUE_LEN, "fill copy")?;
    }
    Ok(ItemRecords {
        id: *id,
        head,
        secret: Zeroizing::new(w.into_bytes()),
    })
}

fn join_item(head: ItemHead, secret: ItemSecret) -> Result<ItemState, PayloadError> {
    if head.id != secret.id {
        return Err(PayloadError::Invalid(
            "head and secret name different items",
        ));
    }
    if !head.secret_fields.keys().eq(secret.fields.keys()) {
        return Err(PayloadError::Invalid("head and secret disagree on fields"));
    }
    for (name, reg) in &secret.fields {
        let kind = winner_value(reg).map_or("", |v| v.kind.as_str());
        if !is_secret_register(name, reg) || head.secret_fields[name] != kind {
            return Err(PayloadError::Invalid("a secret field is not secret"));
        }
    }
    for (name, reg) in &head.fields {
        if is_secret_register(name, reg) {
            return Err(PayloadError::Invalid("a public field is secret"));
        }
    }
    let expected: BTreeMap<String, String> = FILL_COPIES
        .iter()
        .filter_map(|name| {
            let value = winner_value(head.fields.get(*name)?)?;
            Some(((*name).to_owned(), value.value.clone()))
        })
        .collect();
    if secret.fill != expected {
        return Err(PayloadError::Invalid(
            "a fill copy disagrees with its field",
        ));
    }
    let mut fields = head.fields;
    fields.extend(secret.fields);
    Ok(ItemState {
        kind: head.kind,
        fields,
        life: non_empty(head.life)?,
    })
}

fn decode_fields(
    r: &mut Reader<'_>,
    what: &'static str,
) -> Result<BTreeMap<String, Register<Option<FieldValue>>>, PayloadError> {
    let n = r.count(8, what)?;
    let mut fields = BTreeMap::new();
    for _ in 0..n {
        let name = field_name(r, fields.keys().next_back())?;
        fields.insert(name, non_empty(decode_register(r)?)?);
    }
    Ok(fields)
}

fn field_name(r: &mut Reader<'_>, prev: Option<&String>) -> Result<String, PayloadError> {
    let name = r.str(MAX_LABEL_LEN, "field name")?;
    if name.is_empty() {
        return Err(PayloadError::Invalid("field name must be non-empty"));
    }
    ascending(prev, &name, "fields")?;
    Ok(name)
}

impl ItemHead {
    /// Strict decode of a Head record.
    pub fn decode(bytes: &[u8]) -> Result<Self, PayloadError> {
        let mut r = Reader::new(bytes);
        if r.take(HEAD_DOMAIN.len())? != HEAD_DOMAIN {
            return Err(PayloadError::Invalid("pack head domain"));
        }
        let id = r.item()?;
        let kind = decode_register(&mut r)?;
        let life = decode_register(&mut r)?;
        let fields = decode_fields(&mut r, "fields")?;
        let n = r.count(8, "secret fields")?;
        let mut secret_fields = BTreeMap::new();
        for _ in 0..n {
            let name = field_name(&mut r, secret_fields.keys().next_back())?;
            if fields.contains_key(&name) {
                return Err(PayloadError::Invalid("a field is both public and secret"));
            }
            secret_fields.insert(name, r.str(MAX_LABEL_LEN, "field type")?);
        }
        r.finish()?;
        Ok(Self {
            id,
            kind,
            life,
            fields,
            secret_fields,
        })
    }

    /// The item's winning kind, if it has one.
    pub fn kind(&self) -> Option<&str> {
        self.kind.winner().map(|w| w.value.as_str())
    }

    /// Deleted unless a standing write to its life is an edit or restore.
    pub fn deleted(&self) -> bool {
        !self.life.writes().iter().any(|w| w.value == Life::Alive)
    }

    /// A public field's winning value.
    pub fn value(&self, name: &str) -> Option<&FieldValue> {
        winner_value(self.fields.get(name)?)
    }
}

impl ItemSecret {
    /// Strict decode of a Secret record.
    pub fn decode(bytes: &[u8]) -> Result<Self, PayloadError> {
        let mut r = Reader::new(bytes);
        if r.take(SECRET_DOMAIN.len())? != SECRET_DOMAIN {
            return Err(PayloadError::Invalid("pack secret domain"));
        }
        let id = r.item()?;
        let fields = decode_fields(&mut r, "secret fields")?;
        let n = r.count(4, "fill copies")?;
        let mut fill = BTreeMap::new();
        for _ in 0..n {
            let name = field_name(&mut r, fill.keys().next_back())?;
            if !FILL_COPIES.contains(&name.as_str()) {
                return Err(PayloadError::Invalid("not a fill copy"));
            }
            fill.insert(name, r.str(MAX_FIELD_VALUE_LEN, "fill copy")?);
        }
        r.finish()?;
        Ok(Self { id, fields, fill })
    }

    /// A secret field's winning value.
    pub fn value(&self, name: &str) -> Option<&FieldValue> {
        winner_value(self.fields.get(name)?)
    }
}
