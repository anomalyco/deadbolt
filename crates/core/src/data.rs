//! Item state.
//!
//! Every field, the name and the item's tombstone are registers holding the
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

use std::collections::BTreeMap;

use crate::entry::{Change, DataOp, LogId, Payload};
use crate::id::{DeviceId, Hash, ItemId};
use crate::item::{self, Field, ItemError};
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
    /// Tombstone. Fields are kept so the item can be restored by a later edit.
    pub deleted: bool,
}

/// One past change to an item, from [`crate::Vault::history`]. An item's
/// `Create` appears as one `Set` per field (and a `Name` if it had one).
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
    fields: BTreeMap<String, Vec<Write<Option<Field>>>>,
    /// `true` writes are edits, `false` writes are deletions.
    alive: Vec<Write<bool>>,
    history: Vec<Record>,
}

impl ItemState {
    /// Concurrent edit and delete: the edit wins.
    fn deleted(&self) -> bool {
        !self.alive.iter().any(|w| w.value)
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
        Item {
            id,
            kind: self.kind.clone(),
            name: winner(&self.name).and_then(|w| w.value.clone()),
            fields,
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
            Change::Delete => {
                let live = self.alive.iter().any(|w| w.at == record.at);
                (live, live && self.deleted())
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
            Change::Delete => {}
        }
        let alive = *change != Change::Delete;
        write(&mut self.alive, node, at, alive);
    }
}

/// Checks a data op against the current items, as of a new local entry.
pub(crate) fn check(items: &BTreeMap<ItemId, ItemState>, op: &DataOp) -> Result<(), ItemError> {
    match op {
        DataOp::Create { kind, name, fields } => item::check_create(kind, name.as_deref(), fields),
        DataOp::Edit { item, change } => {
            let state = items.get(item).ok_or(ItemError::NoSuchItem)?;
            item::check_change(&state.kind, change)
        }
    }
}

/// Applies a data entry, in causal order, to the item states. Invalid ops
/// are skipped.
pub(crate) fn apply(items: &mut BTreeMap<ItemId, ItemState>, node: &Node) {
    let Payload::Data(ops) = node.entry.payload() else {
        return;
    };
    for (index, op) in ops.iter().enumerate() {
        let at = OpRef {
            entry: node.entry.hash(),
            index,
        };
        match op {
            DataOp::Create { kind, name, fields } => {
                if item::check_create(kind, name.as_deref(), fields).is_err() {
                    continue;
                }
                let id = ItemId::of_create(&node.entry.hash(), index);
                let mut state = ItemState {
                    kind: kind.clone(),
                    created: Write::new(node, at, ()),
                    name: Vec::new(),
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
                items.entry(id).or_insert(state);
            }
            DataOp::Edit { item, change } => {
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
