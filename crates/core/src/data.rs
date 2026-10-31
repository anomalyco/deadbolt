//! Item state.
//!
//! Every field, the name, the source and the item's tombstone are registers holding the
//! frontier of writes that no other write was based on. A new write drops the
//! frontier writes it causally follows. If several concurrent writes remain,
//! the one with the highest entry hash wins and the rest are reported as
//! [`VersionStatus::Conflicted`] in the item's history. A field's register
//! holds its type together with its value, so the type travels with the
//! winning value.
//!
//! Ops that break the item rules (see [`crate::item`]) are skipped one by
//! one; the rest of the entry still applies. An edit only counts if the
//! item's `Create` is in its causal past.

use std::collections::{BTreeMap, BTreeSet};

use crate::entry::{Change, DataOp, LogId, Payload, Source};
use crate::id::{DeviceId, Hash, ItemId};
use crate::item::{self, Field, ItemError};
use crate::tag;
use crate::vault::Node;

/// An item's current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub id: ItemId,
    /// The item type, fixed at creation.
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
    /// The entry that wrote the winning `password` (or `passphrase`) field.
    pub password_entry: Option<Hash>,
    /// UTC date (`YYYY-MM-DD`) the item's password last changed, if recorded.
    pub password_changed: Option<String>,
    /// Ignored health findings (`kind` -> entry hash, or `[0; 32]` item-wide).
    pub ignored: BTreeMap<String, Hash>,
    /// Tombstone. Fields are kept so the item can be restored.
    pub deleted: bool,
}

/// A deleted item and when it was deleted, from [`crate::Vault::deleted`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deleted {
    pub item: Item,
    /// Seconds since the Unix epoch, on the deleting device's clock: the
    /// latest of the deletes that count, or `None` if none of them said.
    pub at: Option<u64>,
}

/// Whether an item is alive, as one write to its tombstone register says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Life {
    /// Any change but a delete: an edit or a restore.
    Alive,
    /// A delete, and when it was made.
    Deleted(Option<u64>),
}

/// One past change to an item, from [`crate::Vault::history`]. An item's
/// `Create` appears as one `Set` per field (and a `Name` and a `Source` if
/// it had them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub entry: Hash,
    pub author: DeviceId,
    pub change: Change,
    pub status: VersionStatus,
}

/// Whether a [`Version`] is reflected in the item's current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionStatus {
    /// The current value.
    Current,
    /// Lost a tie-break against a concurrent edit.
    Conflicted,
    /// Replaced by a later edit that was based on it.
    Superseded,
}

/// Identifies one op within one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct OpRef {
    entry: Hash,
    index: usize,
}

#[derive(Debug, Clone)]
struct Write<T> {
    at: OpRef,
    log: LogId,
    seq: u64,
    value: T,
}

impl<T> Write<T> {
    fn new(node: &Node, at: OpRef, value: T) -> Self {
        Self {
            at,
            log: node.entry.log_id(),
            seq: node.entry.seq(),
            value,
        }
    }

    /// Whether op `at` of `node` was based on this write.
    fn superseded_by(&self, node: &Node, at: OpRef) -> bool {
        if self.at.entry == at.entry {
            self.at.index < at.index
        } else {
            node.clock
                .get(&self.log)
                .is_some_and(|&seq| seq >= self.seq)
        }
    }
}

fn write<T>(frontier: &mut Vec<Write<T>>, node: &Node, at: OpRef, value: T) {
    frontier.retain(|w| !w.superseded_by(node, at));
    frontier.push(Write::new(node, at, value));
}

fn winner<T>(frontier: &[Write<T>]) -> Option<&Write<T>> {
    frontier.iter().max_by_key(|w| w.at)
}

#[derive(Debug, Clone)]
struct Record {
    depth: u64,
    at: OpRef,
    author: DeviceId,
    change: Change,
}

#[derive(Debug, Clone)]
pub(crate) struct ItemState {
    kind: String,
    created: Write<()>,
    name: Vec<Write<Option<String>>>,
    source: Vec<Write<Option<Source>>>,
    favorite: Vec<Write<bool>>,
    /// Per case-folded tag: `Some(spelling)` is an add, `None` a remove.
    tags: BTreeMap<String, Vec<Write<Option<String>>>>,
    password_changed: Vec<Write<Option<String>>>,
    ignored: BTreeMap<String, Vec<Write<Option<Hash>>>>,
    fields: BTreeMap<String, Vec<Write<Option<Field>>>>,
    /// Deletes, and every other change (which brings the item back).
    alive: Vec<Write<Life>>,
    history: Vec<Record>,
}

impl ItemState {
    /// Concurrent edit (or restore) and delete: the edit wins.
    fn deleted(&self) -> bool {
        !self.alive.iter().any(|w| w.value == Life::Alive)
    }

    /// When a deleted item was deleted: the latest time among the deletes
    /// left in the frontier, which every device holding the same entries
    /// agrees on.
    pub(crate) fn deleted_at(&self) -> Option<u64> {
        self.alive
            .iter()
            .filter_map(|w| match w.value {
                Life::Deleted(at) => at,
                Life::Alive => None,
            })
            .max()
    }

    pub(crate) fn item(&self, id: ItemId) -> Item {
        let fields = self
            .fields
            .iter()
            .filter_map(|(name, frontier)| {
                let value = winner(frontier)?.value.clone()?;
                Some((name.clone(), value))
            })
            .collect();
        let tags = self
            .tags
            .values()
            .filter_map(|frontier| {
                // Add-wins Observed-Remove Set: any live add beats a concurrent
                // remove; the highest `(entry, index)` add chooses display case.
                frontier
                    .iter()
                    .filter_map(|w| Some((w.at, w.value.as_ref()?)))
                    .max_by_key(|(at, _)| *at)
                    .map(|(_, t)| t.clone())
            })
            .collect();
        let pw_field = if self.kind == "ssh" {
            "passphrase"
        } else {
            "password"
        };
        let password_entry = self
            .fields
            .get(pw_field)
            .and_then(|frontier| winner(frontier))
            .filter(|w| w.value.is_some())
            .map(|w| w.at.entry);
        let ignored = self
            .ignored
            .iter()
            .filter_map(|(kind, frontier)| Some((kind.clone(), winner(frontier)?.value?)))
            .collect();
        Item {
            id,
            kind: self.kind.clone(),
            name: winner(&self.name).and_then(|w| w.value.clone()),
            fields,
            source: winner(&self.source).and_then(|w| w.value.clone()),
            favorite: winner(&self.favorite).is_some_and(|w| w.value),
            tags,
            password_entry,
            password_changed: winner(&self.password_changed).and_then(|w| w.value.clone()),
            ignored,
            deleted: self.deleted(),
        }
    }

    pub(crate) fn history(&self) -> Vec<Version> {
        let mut records: Vec<&Record> = self.history.iter().collect();
        records.sort_by_key(|r| (r.depth, r.at));
        records
            .into_iter()
            .map(|r| Version {
                entry: r.at.entry,
                author: r.author,
                change: r.change.clone(),
                status: self.status(r),
            })
            .collect()
    }

    fn status(&self, record: &Record) -> VersionStatus {
        fn of<T>(frontier: &[Write<T>], at: OpRef) -> (bool, bool) {
            let live = frontier.iter().any(|w| w.at == at);
            (live, winner(frontier).is_some_and(|w| w.at == at))
        }
        let (live, current) = match &record.change {
            Change::Set { field, .. } | Change::Remove { field } => {
                of(&self.fields[field], record.at)
            }
            Change::Name(_) => of(&self.name, record.at),
            Change::Source(_) => of(&self.source, record.at),
            Change::Favorite(_) => of(&self.favorite, record.at),
            Change::TagAdd(t) => {
                let frontier = &self.tags[&tag::fold_tag(t)];
                let live = frontier.iter().any(|w| w.at == record.at);
                (live, live)
            }
            Change::TagRemove(t) => {
                let frontier = &self.tags[&tag::fold_tag(t)];
                let live = frontier.iter().any(|w| w.at == record.at);
                let present = frontier.iter().any(|w| w.value.is_some());
                (live, live && !present)
            }
            Change::Ignore { kind, .. } => of(&self.ignored[kind], record.at),
            Change::PasswordChanged(_) => of(&self.password_changed, record.at),
            Change::Delete { .. } => {
                let live = self.alive.iter().any(|w| w.at == record.at);
                (live, live && self.deleted())
            }
            Change::Restore => {
                let live = self.alive.iter().any(|w| w.at == record.at);
                (live, live && !self.deleted())
            }
        };
        match (live, current) {
            (_, true) => VersionStatus::Current,
            (true, false) => VersionStatus::Conflicted,
            (false, _) => VersionStatus::Superseded,
        }
    }

    fn change(&mut self, node: &Node, at: OpRef, change: &Change) {
        self.history.push(Record {
            depth: node.depth,
            at,
            author: node.entry.author(),
            change: change.clone(),
        });
        match change {
            Change::Set { field, value } => {
                let frontier = self.fields.entry(field.clone()).or_default();
                write(frontier, node, at, Some(value.clone()));
            }
            Change::Remove { field } => {
                write(
                    self.fields.entry(field.clone()).or_default(),
                    node,
                    at,
                    None,
                );
            }
            Change::Name(name) => write(&mut self.name, node, at, name.clone()),
            Change::Source(source) => write(&mut self.source, node, at, source.clone()),
            Change::Favorite(fav) => write(&mut self.favorite, node, at, *fav),
            Change::TagAdd(t) => {
                let frontier = self.tags.entry(tag::fold_tag(t)).or_default();
                write(frontier, node, at, Some(t.clone()));
            }
            Change::TagRemove(t) => {
                let frontier = self.tags.entry(tag::fold_tag(t)).or_default();
                write(frontier, node, at, None);
            }
            Change::Ignore { kind, at: target } => {
                write(
                    self.ignored.entry(kind.clone()).or_default(),
                    node,
                    at,
                    *target,
                );
            }
            Change::PasswordChanged(date) => {
                write(&mut self.password_changed, node, at, date.clone());
            }
            Change::Delete { .. } | Change::Restore => {}
        }
        let life = match change {
            Change::Delete { at } => Life::Deleted(*at),
            _ => Life::Alive,
        };
        write(&mut self.alive, node, at, life);
    }
}

/// Checks a data op against the current items, as of a new local entry.
pub(crate) fn check<'a>(
    items: impl Fn(&ItemId) -> Option<&'a ItemState>,
    op: &DataOp,
) -> Result<(), ItemError> {
    match op {
        DataOp::Create {
            kind,
            name,
            fields,
            source,
            tags,
            ..
        } => item::check_create_with(kind, name.as_deref(), fields, source.as_ref(), tags),
        DataOp::Edit { item, change } => {
            let state = items(item).ok_or(ItemError::NoSuchItem)?;
            item::check_change(&state.kind, change)
        }
    }
}

/// The files rule for a new local entry: an item one of its ops gives a
/// file holds at most [`item::MAX_FILE`] in files once the entry is
/// applied. Only writes are held to it: concurrent changes on two devices
/// can't see each other, so applying stays order-independent and ignores it.
pub(crate) fn check_files<'a>(
    items: impl Fn(&ItemId) -> Option<&'a ItemState>,
    ops: &[DataOp],
) -> Result<(), ItemError> {
    let mut after: BTreeMap<ItemId, (BTreeMap<String, usize>, Option<String>)> = BTreeMap::new();
    // Only a file write can trigger the cap. Collect those items first so
    // removals earlier in the batch still make room for later file writes.
    for op in ops {
        let DataOp::Edit {
            item,
            change: Change::Set { value, .. },
        } = op
        else {
            continue;
        };
        if value.kind != crate::FieldType::File {
            continue;
        }
        let Some(state) = items(item) else {
            continue;
        };
        after.entry(*item).or_insert_with(|| {
            let sizes = state
                .fields
                .iter()
                .filter_map(|(name, frontier)| {
                    let field = winner(frontier)?.value.as_ref()?;
                    Some((name.clone(), item::files_size([field])))
                })
                .collect();
            (sizes, None)
        });
    }
    for op in ops {
        let DataOp::Edit { item, change } = op else {
            continue;
        };
        let Some((sizes, grew)) = after.get_mut(item) else {
            continue;
        };
        match change {
            Change::Set { field, value } => {
                if value.kind == crate::FieldType::File {
                    *grew = Some(field.clone());
                }
                sizes.insert(field.clone(), item::files_size([value]));
            }
            Change::Remove { field } => {
                sizes.remove(field);
            }
            _ => {}
        }
    }
    for (sizes, grew) in after.values() {
        if let Some(field) = grew
            && sizes.values().sum::<usize>() > item::MAX_FILE
        {
            return Err(item::too_many_files(field));
        }
    }
    Ok(())
}

/// The tag-count rule for a new local entry: an item whose tag set grows in
/// this entry holds at most [`tag::MAX_TAGS`] tags once applied. Only local
/// writes enforce this cap so `apply` remains order-independent across
/// concurrent additions on different devices.
pub(crate) fn check_tags<'a>(
    items: impl Fn(&ItemId) -> Option<&'a ItemState>,
    ops: &[DataOp],
) -> Result<(), ItemError> {
    let mut after: BTreeMap<ItemId, (BTreeSet<String>, bool)> = BTreeMap::new();
    for op in ops {
        let DataOp::Edit { item, change } = op else {
            continue;
        };
        if !matches!(change, Change::TagAdd(_) | Change::TagRemove(_)) {
            continue;
        }
        let Some(state) = items(item) else {
            continue;
        };
        let (tags, grew) = after.entry(*item).or_insert_with(|| {
            let folded = state
                .tags
                .iter()
                .filter(|(_, frontier)| frontier.iter().any(|w| w.value.is_some()))
                .map(|(folded, _)| folded.clone())
                .collect();
            (folded, false)
        });
        match change {
            Change::TagAdd(t) => {
                if tags.insert(tag::fold_tag(t)) {
                    *grew = true;
                }
            }
            Change::TagRemove(t) => {
                tags.remove(&tag::fold_tag(t));
            }
            _ => {}
        }
    }
    for (tags, grew) in after.values() {
        if *grew && tags.len() > tag::MAX_TAGS {
            return Err(ItemError::TooManyTags);
        }
    }
    Ok(())
}

/// Applies a data entry, in causal order, to the item states. Invalid ops
/// are skipped.
pub(crate) fn apply(
    items: &mut BTreeMap<ItemId, ItemState>,
    inherited: Option<&BTreeMap<ItemId, ItemState>>,
    node: &Node,
) {
    let Payload::Data(ops) = node.entry.payload() else {
        return;
    };
    for (index, op) in ops.iter().enumerate() {
        let at = OpRef {
            entry: node.entry.hash(),
            index,
        };
        match op {
            DataOp::Create {
                kind,
                name,
                fields,
                source,
                favorite,
                tags,
            } => {
                if item::check_create_with(kind, name.as_deref(), fields, source.as_ref(), tags)
                    .is_err()
                {
                    continue;
                }
                let id = ItemId::of_create(&node.entry.hash(), index);
                if inherited.is_some_and(|base| base.contains_key(&id)) {
                    continue;
                }
                let mut state = ItemState {
                    kind: kind.clone(),
                    created: Write::new(node, at, ()),
                    name: Vec::new(),
                    source: Vec::new(),
                    favorite: Vec::new(),
                    tags: BTreeMap::new(),
                    password_changed: Vec::new(),
                    ignored: BTreeMap::new(),
                    fields: BTreeMap::new(),
                    alive: Vec::new(),
                    history: Vec::new(),
                };
                for (field, value) in fields {
                    let value = value.clone();
                    let field = field.clone();
                    state.change(node, at, &Change::Set { field, value });
                }
                if name.is_some() {
                    state.change(node, at, &Change::Name(name.clone()));
                }
                if source.is_some() {
                    state.change(node, at, &Change::Source(source.clone()));
                }
                if *favorite {
                    state.change(node, at, &Change::Favorite(true));
                }
                for tag in tags {
                    state.change(node, at, &Change::TagAdd(tag.clone()));
                }
                items.entry(id).or_insert(state);
            }
            DataOp::Edit { item, change } => {
                if let Some(base) = inherited
                    && !items.contains_key(item)
                    && let Some(state) = base.get(item)
                {
                    items.insert(*item, state.clone());
                }
                let Some(state) = items.get_mut(item) else {
                    continue;
                };
                if !state.created.superseded_by(node, at)
                    || item::check_change(&state.kind, change).is_err()
                {
                    continue;
                }
                state.change(node, at, change);
            }
        }
    }
}
