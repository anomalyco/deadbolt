//! The item edit vocabulary: what a device asks to change in a vault.
//!
//! A [`crate::Vault`] checks each op against the item rules ([`crate::item`])
//! and translates it into v2 data-plane ops ([`crate::v2::DataOp`]): an
//! item's name, source, favorite flag, tags, ignored findings and password
//! date are registers under reserved field names, so they merge exactly like
//! fields do.

use std::collections::{BTreeMap, BTreeSet};

use crate::id::{Hash, ItemId};
use crate::item::Field;

/// Whether `name` is a valid vault name: 1–64 characters of lowercase ASCII
/// letters, digits, `-` and `_`, starting with a letter.
pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

/// One data op. See [`crate::item`] for the rules ops must follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataOp {
    /// Creates an item of type `kind` with all its required fields. The new
    /// item's id is [`ItemId::of_create`] of the entry hash and op index.
    Create {
        kind: String,
        name: Option<String>,
        fields: BTreeMap<String, Field>,
        /// Set when the item mirrors one held elsewhere.
        source: Option<Source>,
        favorite: bool,
        tags: BTreeSet<String>,
    },
    /// Changes an existing item.
    Edit { item: ItemId, change: Change },
}

/// Where a mirrored item comes from: its id in another password manager
/// and the version mirrored, both opaque here. Kept apart from the fields,
/// so it is never shown, copied or edited as one. An item without a source
/// is the user's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub id: String,
    pub version: String,
}

/// A change to an existing item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Sets a field's type and value.
    Set { field: String, value: Field },
    /// Removes a field that is not required.
    Remove { field: String },
    /// Sets or clears the item's name.
    Name(Option<String>),
    /// Marks the item deleted, keeping its fields. `at` is when, in seconds
    /// since the Unix epoch on the deleting device's clock, for showing and
    /// ordering deleted items; `None` in deletes written before it was kept.
    /// A later [`Change::Restore`] or edit brings the item back.
    Delete { at: Option<u64> },
    /// Sets or clears where the item is mirrored from.
    Source(Option<Source>),
    /// Brings a deleted item back as it was. Like any edit, it beats a
    /// delete it didn't see and loses to one that saw it.
    Restore,
    /// Stars or unstars the item.
    Favorite(bool),
    /// Adds a tag (`work`, `work/aws`).
    TagAdd(String),
    /// Removes a tag (matched case-insensitively).
    TagRemove(String),
    /// Marks or clears an ignored health finding (`kind`, such as `"weak"`).
    /// `Some(hash)` ignores it (`Hash::from_bytes([0; 32])` for item-wide
    /// findings; a `password` write's entry hash for password findings);
    /// `None` restores the warning.
    Ignore { kind: String, at: Option<Hash> },
    /// Records or clears the UTC date (`YYYY-MM-DD`) the item's password
    /// last changed, kept apart from `fields`.
    PasswordChanged(Option<String>),
}

impl DataOp {
    pub fn create(
        kind: impl Into<String>,
        name: Option<String>,
        fields: impl IntoIterator<Item = (String, Field)>,
    ) -> Self {
        Self::Create {
            kind: kind.into(),
            name,
            fields: fields.into_iter().collect(),
            source: None,
            favorite: false,
            tags: BTreeSet::new(),
        }
    }

    /// A `Create` that mirrors an item held elsewhere.
    pub fn create_mirror(
        kind: impl Into<String>,
        name: Option<String>,
        fields: impl IntoIterator<Item = (String, Field)>,
        source: Source,
    ) -> Self {
        Self::Create {
            kind: kind.into(),
            name,
            fields: fields.into_iter().collect(),
            source: Some(source),
            favorite: false,
            tags: BTreeSet::new(),
        }
    }

    /// A `Create` carrying optional mirror provenance, favorite flag, and tags.
    pub fn create_with(
        kind: impl Into<String>,
        name: Option<String>,
        fields: impl IntoIterator<Item = (String, Field)>,
        source: Option<Source>,
        favorite: bool,
        tags: impl IntoIterator<Item = String>,
    ) -> Self {
        Self::Create {
            kind: kind.into(),
            name,
            fields: fields.into_iter().collect(),
            source,
            favorite,
            tags: tags.into_iter().collect(),
        }
    }

    pub fn source(item: ItemId, source: Option<Source>) -> Self {
        Self::edit(item, Change::Source(source))
    }

    pub fn favorite(item: ItemId, favorite: bool) -> Self {
        Self::edit(item, Change::Favorite(favorite))
    }

    pub fn tag_add(item: ItemId, tag: impl Into<String>) -> Self {
        Self::edit(item, Change::TagAdd(tag.into()))
    }

    pub fn tag_remove(item: ItemId, tag: impl Into<String>) -> Self {
        Self::edit(item, Change::TagRemove(tag.into()))
    }

    pub fn set(item: ItemId, field: impl Into<String>, value: Field) -> Self {
        let field = field.into();
        Self::edit(item, Change::Set { field, value })
    }

    pub fn remove(item: ItemId, field: impl Into<String>) -> Self {
        let field = field.into();
        Self::edit(item, Change::Remove { field })
    }

    pub fn name(item: ItemId, name: Option<String>) -> Self {
        Self::edit(item, Change::Name(name))
    }

    /// Deletes `item` at `at` (seconds since the Unix epoch).
    pub fn delete(item: ItemId, at: u64) -> Self {
        Self::edit(item, Change::Delete { at: Some(at) })
    }

    pub fn restore(item: ItemId) -> Self {
        Self::edit(item, Change::Restore)
    }

    pub fn ignore(item: ItemId, kind: impl Into<String>, at: Option<Hash>) -> Self {
        Self::edit(
            item,
            Change::Ignore {
                kind: kind.into(),
                at,
            },
        )
    }

    pub fn password_changed(item: ItemId, date: Option<String>) -> Self {
        Self::edit(item, Change::PasswordChanged(date))
    }

    fn edit(item: ItemId, change: Change) -> Self {
        Self::Edit { item, change }
    }

    /// About how many bytes this op takes in a frame: what batching counts.
    pub fn encoded_len(&self) -> usize {
        let field = |name: &str, f: &Field| 16 + name.len() + f.kind.as_str().len() + f.value.len();
        match self {
            Self::Create {
                kind,
                name,
                fields,
                source,
                tags,
                ..
            } => {
                32 + kind.len()
                    + name.as_ref().map_or(0, |n| 32 + n.len())
                    + fields.iter().map(|(n, f)| 16 + field(n, f)).sum::<usize>()
                    + source
                        .as_ref()
                        .map_or(0, |s| 48 + s.id.len() + s.version.len())
                    + tags.iter().map(|t| 48 + 2 * t.len()).sum::<usize>()
            }
            Self::Edit { change, .. } => {
                32 + match change {
                    Change::Set { field: name, value } => field(name, value),
                    Change::Source(Some(s)) => 32 + s.id.len() + s.version.len(),
                    Change::Name(Some(s)) | Change::TagAdd(s) | Change::TagRemove(s) => {
                        32 + 2 * s.len()
                    }
                    _ => 64,
                }
            }
        }
    }
}
