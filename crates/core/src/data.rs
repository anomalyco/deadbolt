//! Item state.
//!
//! Every field (and the item's tombstone) is a register holding the frontier
//! of writes that no other write was based on. A new write drops the frontier
//! writes it causally follows. If several concurrent writes remain, the one
//! with the highest entry hash wins and the rest are reported as
//! [`VersionStatus::Conflicted`] in the item's history.

use std::collections::BTreeMap;

use crate::entry::{Change, LogId, Payload};
use crate::id::{DeviceId, Hash, ItemId};
use crate::vault::Node;

/// An item's current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub id: ItemId,
    pub fields: BTreeMap<String, String>,
    /// Tombstone. Fields are kept so the item can be restored by a later edit.
    pub deleted: bool,
}

/// One past change to an item, from [`crate::Vault::history`].
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
    /// Whether `new` (op `at` of `node`) was based on this write.
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
    let (log, seq) = (node.entry.log_id(), node.entry.seq());
    frontier.push(Write {
        at,
        log,
        seq,
        value,
    });
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

#[derive(Debug, Clone, Default)]
pub(crate) struct ItemState {
    fields: BTreeMap<String, Vec<Write<Option<String>>>>,
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
        let (live, current) = match &record.change {
            Change::Set { field, .. } | Change::DeleteField { field } => {
                let frontier = &self.fields[field];
                let live = frontier.iter().any(|w| w.at == record.at);
                (live, winner(frontier).is_some_and(|w| w.at == record.at))
            }
            Change::DeleteItem => {
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
}

/// Applies a data entry, in causal order, to the item states.
pub(crate) fn apply(items: &mut BTreeMap<ItemId, ItemState>, node: &Node) {
    let Payload::Data(ops) = node.entry.payload() else {
        return;
    };
    for (index, op) in ops.iter().enumerate() {
        let at = OpRef {
            entry: node.entry.hash(),
            index,
        };
        let state = items.entry(op.item).or_default();
        state.history.push(Record {
            depth: node.depth,
            at,
            author: node.entry.author(),
            change: op.change.clone(),
        });
        match &op.change {
            Change::Set { field, value } => {
                let frontier = state.fields.entry(field.clone()).or_default();
                write(frontier, node, at, Some(value.clone()));
                write(&mut state.alive, node, at, true);
            }
            Change::DeleteField { field } => {
                write(
                    state.fields.entry(field.clone()).or_default(),
                    node,
                    at,
                    None,
                );
                write(&mut state.alive, node, at, true);
            }
            Change::DeleteItem => write(&mut state.alive, node, at, false),
        }
    }
}
