//! Items as the v2 fold holds them, and item edits as v2 data ops.
//!
//! An item's own fields are registers under their names (always lowercase
//! ASCII, see [`crate::item::valid_field_name`]). Everything else about an
//! item sits in registers under reserved names starting with `@`, which no
//! field name can: `@name`, `@source`, `@favorite`, `@password-changed`,
//! `@tag/<folded tag>` and `@ignore/<kind>`. Every register write but a
//! delete revives the item, so a concurrent edit beats a delete, as before.
//! A tag is present while any standing write to its register adds it (an
//! add-wins set).

use std::collections::{BTreeMap, BTreeSet};

use crate::id::{Hash, ItemId};
use crate::item::{self, Field, FieldType, ItemError};
use crate::ops::{Change, DataOp, Source};
use crate::tag;
use crate::v2::{self, FieldValue, ItemState, Register};

const NAME: &str = "@name";
const SOURCE: &str = "@source";
const FAVORITE: &str = "@favorite";
const PASSWORD_CHANGED: &str = "@password-changed";
const TAG: &str = "@tag/";
const IGNORE: &str = "@ignore/";

/// An item's current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub id: ItemId,
    /// The item type.
    pub kind: String,
    /// An optional label; not unique, not an identifier.
    pub name: Option<String>,
    pub fields: BTreeMap<String, Field>,
    /// Where the item is mirrored from; `None` for the user's own.
    pub source: Option<Source>,
    /// Whether the item is starred so clients rank it first.
    pub favorite: bool,
    /// Organizational tags (`work`, `work/aws`).
    pub tags: BTreeSet<String>,
    /// The frame that wrote the winning `password` (or `passphrase`) field.
    pub password_entry: Option<Hash>,
    /// UTC date (`YYYY-MM-DD`) the item's password last changed, if recorded.
    pub password_changed: Option<String>,
    /// Ignored health findings (`kind` -> frame id, or `[0; 32]` item-wide).
    pub ignored: BTreeMap<String, Hash>,
    /// Tombstone. Fields are kept so the item can be restored.
    pub deleted: bool,
}

/// A deleted item and when it was deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deleted {
    pub item: Item,
    /// Seconds since the Unix epoch, on the deleting device's clock.
    pub at: Option<u64>,
}

fn value(reg: &Register<Option<FieldValue>>) -> Option<&FieldValue> {
    reg.winner()?.value.as_ref()
}

/// Whether the fold's `state` is a visible item: created with a type this
/// version knows.
pub(crate) fn known(state: &ItemState) -> bool {
    state
        .kind
        .winner()
        .is_some_and(|w| item::schema(&w.value).is_some())
}

fn kind(state: &ItemState) -> &str {
    state.kind.winner().map_or("", |w| w.value.as_str())
}

fn password_field(state: &ItemState) -> &'static str {
    if kind(state) == "ssh" {
        "passphrase"
    } else {
        "password"
    }
}

/// The item's own fields' winning values, without projecting anything else.
pub(crate) fn fields(state: &ItemState) -> impl Iterator<Item = (&str, &FieldValue)> {
    state
        .fields
        .iter()
        .filter(|(name, _)| !name.starts_with('@'))
        .filter_map(|(name, reg)| Some((name.as_str(), value(reg)?)))
}

pub(crate) fn field(value: &FieldValue) -> Field {
    Field::new(FieldType::parse(&value.kind), value.value.clone())
}

/// Projects one item from its registers.
pub(crate) fn item(id: ItemId, state: &ItemState) -> Item {
    let mut out = Item {
        id,
        kind: kind(state).to_owned(),
        name: None,
        fields: BTreeMap::new(),
        source: None,
        favorite: false,
        tags: BTreeSet::new(),
        password_entry: None,
        password_changed: None,
        ignored: BTreeMap::new(),
        deleted: state.deleted(),
    };
    let password = password_field(state);
    for (name, reg) in &state.fields {
        if let Some(tag) = name.strip_prefix(TAG) {
            // Add wins: any standing add keeps the tag; the latest add spells it.
            let _ = tag;
            if let Some(spelling) = reg.writes().iter().rev().find_map(|w| w.value.as_ref()) {
                out.tags.insert(spelling.value.clone());
            }
            continue;
        }
        let Some(v) = value(reg) else { continue };
        match name.as_str() {
            NAME => out.name = Some(v.value.clone()),
            SOURCE => {
                out.source = Some(Source {
                    id: v.kind.clone(),
                    version: v.value.clone(),
                })
            }
            FAVORITE => out.favorite = true,
            PASSWORD_CHANGED => out.password_changed = Some(v.value.clone()),
            _ if name.starts_with(IGNORE) => {
                if let Some(hash) = unhex32(&v.value) {
                    out.ignored
                        .insert(name[IGNORE.len()..].to_owned(), Hash::from_bytes(hash));
                }
            }
            _ if name.starts_with('@') => {}
            _ => {
                if name == password {
                    out.password_entry = reg
                        .winner()
                        .map(|w| Hash::from_bytes(*w.dot.frame.as_bytes()));
                }
                out.fields.insert(name.clone(), field(v));
            }
        }
    }
    out
}

/// When a deleted item was deleted, in seconds.
pub(crate) fn deleted_at(state: &ItemState) -> Option<u64> {
    state.tombstone().map(|t| t.at_ms / 1000)
}

fn unhex32(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks(2).enumerate() {
        let s = std::str::from_utf8(pair).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

fn set(item: ItemId, field: impl Into<String>, kind: &str, value: impl Into<String>) -> v2::DataOp {
    v2::DataOp::SetField {
        item,
        field: field.into(),
        value: FieldValue {
            kind: kind.into(),
            value: value.into(),
        },
    }
}

fn clear(item: ItemId, field: impl Into<String>) -> v2::DataOp {
    v2::DataOp::ClearField {
        item,
        field: field.into(),
    }
}

/// The v2 ops for one change to `item`.
pub(crate) fn translate_change(item: ItemId, change: &Change, out: &mut Vec<v2::DataOp>) {
    out.push(match change {
        Change::Set { field, value } => set(item, field, value.kind.as_str(), value.value.clone()),
        Change::Remove { field } => clear(item, field),
        Change::Name(Some(name)) => set(item, NAME, "name", name.clone()),
        Change::Name(None) => clear(item, NAME),
        Change::Delete { .. } => v2::DataOp::DeleteItem { item },
        Change::Restore => v2::DataOp::RestoreItem { item },
        Change::Source(Some(s)) => set(item, SOURCE, &s.id, s.version.clone()),
        Change::Source(None) => clear(item, SOURCE),
        Change::Favorite(true) => set(item, FAVORITE, "flag", "1"),
        Change::Favorite(false) => clear(item, FAVORITE),
        Change::TagAdd(t) => set(item, format!("{TAG}{}", tag::fold_tag(t)), "tag", t.clone()),
        Change::TagRemove(t) => clear(item, format!("{TAG}{}", tag::fold_tag(t))),
        Change::Ignore { kind, at: Some(at) } => {
            set(item, format!("{IGNORE}{kind}"), "hash", at.to_string())
        }
        Change::Ignore { kind, at: None } => clear(item, format!("{IGNORE}{kind}")),
        Change::PasswordChanged(Some(d)) => set(item, PASSWORD_CHANGED, "date", d.clone()),
        Change::PasswordChanged(None) => clear(item, PASSWORD_CHANGED),
    });
}

/// The v2 ops for `op`, creating new items under `new_id`.
pub(crate) fn translate(op: &DataOp, new_id: ItemId, out: &mut Vec<v2::DataOp>) -> ItemId {
    match op {
        DataOp::Create {
            kind,
            name,
            fields,
            source,
            favorite,
            tags,
        } => {
            out.push(v2::DataOp::PutItem {
                item: new_id,
                kind: kind.clone(),
            });
            for (name, value) in fields {
                translate_change(
                    new_id,
                    &Change::Set {
                        field: name.clone(),
                        value: value.clone(),
                    },
                    out,
                );
            }
            if name.is_some() {
                translate_change(new_id, &Change::Name(name.clone()), out);
            }
            if source.is_some() {
                translate_change(new_id, &Change::Source(source.clone()), out);
            }
            if *favorite {
                translate_change(new_id, &Change::Favorite(true), out);
            }
            for t in tags {
                translate_change(new_id, &Change::TagAdd(t.clone()), out);
            }
            new_id
        }
        DataOp::Edit { item, change } => {
            translate_change(*item, change, out);
            *item
        }
    }
}

/// An edited item as a batch leaves it: file sizes by field, folded tags,
/// whether the tag set grew, and the last file field set.
type Edited = (BTreeMap<String, usize>, BTreeSet<String>, bool, Option<String>);

/// Checks a batch of ops written now against the items they touch: every
/// op on its own, the files cap and the tag cap on the batch as a whole.
pub(crate) fn check<'a>(
    items: impl Fn(&ItemId) -> Option<&'a ItemState>,
    ops: &[DataOp],
) -> Result<(), ItemError> {
    let mut after: BTreeMap<ItemId, Edited> = BTreeMap::new();
    for op in ops {
        match op {
            DataOp::Create {
                kind,
                name,
                fields,
                source,
                tags,
                ..
            } => item::check_create_with(kind, name.as_deref(), fields, source.as_ref(), tags)?,
            DataOp::Edit { item: id, change } => {
                let state = items(id)
                    .filter(|s| !kind(s).is_empty())
                    .ok_or(ItemError::NoSuchItem)?;
                item::check_change(kind(state), change)?;
                let (sizes, tags, tag_grew, file_grew) = after.entry(*id).or_insert_with(|| {
                    let it = item(*id, state);
                    let sizes = it
                        .fields
                        .iter()
                        .map(|(n, f)| (n.clone(), item::files_size([f])))
                        .collect();
                    let tags = it.tags.iter().map(|t| tag::fold_tag(t)).collect();
                    (sizes, tags, false, None)
                });
                match change {
                    Change::Set { field, value } => {
                        if value.kind == FieldType::File {
                            *file_grew = Some(field.clone());
                        }
                        sizes.insert(field.clone(), item::files_size([value]));
                    }
                    Change::Remove { field } => {
                        sizes.remove(field);
                    }
                    Change::TagAdd(t) => *tag_grew |= tags.insert(tag::fold_tag(t)),
                    Change::TagRemove(t) => {
                        tags.remove(&tag::fold_tag(t));
                    }
                    _ => {}
                }
            }
        }
    }
    for (sizes, tags, tag_grew, file_grew) in after.values() {
        if let Some(field) = file_grew
            && sizes.values().sum::<usize>() > item::MAX_FILE
        {
            return Err(item::too_many_files(field));
        }
        if *tag_grew && tags.len() > tag::MAX_TAGS {
            return Err(ItemError::TooManyTags);
        }
    }
    Ok(())
}
