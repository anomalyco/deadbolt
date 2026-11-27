//! DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2.
//!
//! Replays a v1 store's entries into each vault's final state, as v1's
//! `Vault` resolved them: every field, the name, the source, the favorite
//! flag, each tag, each ignored finding, the password date and the
//! tombstone is a register holding the writes no other write was based on;
//! among concurrent writes the highest `(entry hash, op index)` wins (any
//! live add wins a tag). An edit counts only if the item's `Create` is in
//! its causal past, ops breaking the item rules are skipped one by one, and
//! a removed device's data counts only up to its removal's cutoff.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{Result, bail};
use deadbolt_core::item::{check_change, check_create_with};
use deadbolt_core::{Change, DataOp, DeviceId, Field, Hash, ItemId, Source, tag};
use indexmap::IndexMap;

use super::entry::{Entry, MembershipOp, Payload};
use super::membership;

const ITEM_ID_CONTEXT: &str = "deadbolt 2026-10-15 item id v1";

/// An entry and its causal past.
pub(super) struct Node {
    pub entry: Entry,
    /// Longest dependency path from the genesis.
    pub depth: u64,
    /// Per (author, data log?), the highest seq in the causal past, inclusive.
    clock: BTreeMap<(DeviceId, bool), u64>,
}

impl Node {
    /// Whether `other` is in this entry's strict causal past.
    pub fn saw(&self, other: &Node) -> bool {
        self.entry.hash != other.entry.hash
            && self
                .clock
                .get(&(other.entry.author, other.entry.is_data()))
                .is_some_and(|&seq| seq >= other.entry.seq)
    }
}

/// One v1 vault as its entries left it.
pub(super) struct V1Vault {
    pub id: [u8; 32],
    pub name: String,
    /// Every item, deleted ones included, by id.
    pub items: BTreeMap<ItemId, V1Item>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct V1Item {
    pub kind: String,
    pub name: Option<String>,
    pub fields: BTreeMap<String, Field>,
    pub source: Option<Source>,
    pub favorite: bool,
    pub tags: BTreeSet<String>,
    pub password_changed: Option<String>,
    /// Ignored health findings: kind -> entry hash (`[0; 32]` item-wide).
    pub ignored: BTreeMap<String, Hash>,
    /// The entry that wrote the winning `password` (`passphrase` for SSH).
    pub password_entry: Option<Hash>,
    /// `Some(when)` once deleted.
    pub deleted: Option<Option<u64>>,
}

/// Every vault in `entries` (the store's append order, causal within each
/// vault), in the order the store first holds them.
pub(super) fn vaults(entries: Vec<Entry>) -> Result<Vec<V1Vault>> {
    let mut grouped: IndexMap<[u8; 32], Vec<Entry>> = IndexMap::new();
    for entry in entries {
        grouped.entry(entry.vault).or_default().push(entry);
    }
    grouped
        .into_iter()
        .map(|(id, entries)| vault(id, entries))
        .collect()
}

fn vault(id: [u8; 32], entries: Vec<Entry>) -> Result<V1Vault> {
    let mut nodes: Vec<Node> = Vec::with_capacity(entries.len());
    let mut at: HashMap<Hash, usize> = HashMap::new();
    for entry in entries {
        let mut clock = BTreeMap::new();
        let mut depth = 0;
        for dep in &entry.deps {
            let Some(&i) = at.get(dep) else {
                bail!("a v1 entry depends on one the store doesn't hold");
            };
            for (log, &seq) in &nodes[i].clock {
                let max = clock.entry(*log).or_insert(seq);
                *max = (*max).max(seq);
            }
            depth = depth.max(nodes[i].depth + 1);
        }
        clock.insert((entry.author, entry.is_data()), entry.seq);
        at.insert(entry.hash, nodes.len());
        nodes.push(Node {
            entry,
            depth,
            clock,
        });
    }
    let Some(genesis) = nodes.first() else {
        bail!("an empty v1 vault");
    };
    if !matches!(
        &genesis.entry.payload,
        Payload::Membership(MembershipOp::Create { device, .. }) if *device == genesis.entry.author
    ) {
        bail!("a v1 vault doesn't start with its genesis");
    }
    let membership = membership::resolve(&genesis.entry.hash, nodes.iter().collect());
    let mut items: BTreeMap<ItemId, ItemState> = BTreeMap::new();
    for node in &nodes {
        if node.entry.is_data() && membership.counts(&node.entry.author, node.entry.seq) {
            apply(&mut items, node);
        }
    }
    Ok(V1Vault {
        id,
        name: membership.name,
        items: items
            .into_iter()
            .map(|(id, state)| (id, state.item()))
            .collect(),
    })
}

/// v1's item id: the first 16 bytes of a hash of the creating entry and op.
pub(super) fn item_id(entry: &Hash, index: usize) -> ItemId {
    let mut material = [0; 40];
    material[..32].copy_from_slice(entry.as_bytes());
    material[32..].copy_from_slice(&(index as u64).to_be_bytes());
    let key = blake3::derive_key(ITEM_ID_CONTEXT, &material);
    let mut id = [0; 16];
    id.copy_from_slice(&key[..16]);
    ItemId::from_bytes(id)
}

/// Identifies one op within one entry.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct OpRef {
    entry: Hash,
    index: usize,
}

struct Write<T> {
    at: OpRef,
    author: DeviceId,
    seq: u64,
    value: T,
}

impl<T> Write<T> {
    /// Whether op `at` of `node` was based on this write.
    fn superseded_by(&self, node: &Node, at: OpRef) -> bool {
        if self.at.entry == at.entry {
            self.at.index < at.index
        } else {
            node.clock
                .get(&(self.author, true))
                .is_some_and(|&seq| seq >= self.seq)
        }
    }
}

type Register<T> = Vec<Write<T>>;

fn write<T>(frontier: &mut Register<T>, node: &Node, at: OpRef, value: T) {
    frontier.retain(|w| !w.superseded_by(node, at));
    frontier.push(Write {
        at,
        author: node.entry.author,
        seq: node.entry.seq,
        value,
    });
}

fn winner<T>(frontier: &[Write<T>]) -> Option<&Write<T>> {
    frontier.iter().max_by_key(|w| w.at)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Life {
    Alive,
    Deleted(Option<u64>),
}

struct ItemState {
    kind: String,
    created: Write<()>,
    name: Register<Option<String>>,
    source: Register<Option<Source>>,
    favorite: Register<bool>,
    /// Per case-folded tag: `Some(spelling)` adds, `None` removes.
    tags: BTreeMap<String, Register<Option<String>>>,
    password_changed: Register<Option<String>>,
    ignored: BTreeMap<String, Register<Option<Hash>>>,
    fields: BTreeMap<String, Register<Option<Field>>>,
    alive: Register<Life>,
}

impl ItemState {
    fn change(&mut self, node: &Node, at: OpRef, change: &Change) {
        match change {
            Change::Set { field, value } => write(
                self.fields.entry(field.clone()).or_default(),
                node,
                at,
                Some(value.clone()),
            ),
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
            Change::Favorite(favorite) => write(&mut self.favorite, node, at, *favorite),
            Change::TagAdd(t) => write(
                self.tags.entry(tag::fold_tag(t)).or_default(),
                node,
                at,
                Some(t.clone()),
            ),
            Change::TagRemove(t) => {
                write(
                    self.tags.entry(tag::fold_tag(t)).or_default(),
                    node,
                    at,
                    None,
                );
            }
            Change::Ignore { kind, at: target } => write(
                self.ignored.entry(kind.clone()).or_default(),
                node,
                at,
                *target,
            ),
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

    fn item(&self) -> V1Item {
        let fields: BTreeMap<String, Field> = self
            .fields
            .iter()
            .filter_map(|(name, frontier)| Some((name.clone(), winner(frontier)?.value.clone()?)))
            .collect();
        let tags = self
            .tags
            .values()
            .filter_map(|frontier| {
                frontier
                    .iter()
                    .filter_map(|w| Some((w.at, w.value.as_ref()?)))
                    .max_by_key(|(at, _)| *at)
                    .map(|(_, t)| t.clone())
            })
            .collect();
        let password = if self.kind == "ssh" {
            "passphrase"
        } else {
            "password"
        };
        let password_entry = self
            .fields
            .get(password)
            .and_then(|frontier| winner(frontier))
            .filter(|w| w.value.is_some())
            .map(|w| w.at.entry);
        let deleted = (!self.alive.iter().any(|w| w.value == Life::Alive)).then(|| {
            self.alive
                .iter()
                .filter_map(|w| match w.value {
                    Life::Deleted(at) => at,
                    Life::Alive => None,
                })
                .max()
        });
        V1Item {
            kind: self.kind.clone(),
            name: winner(&self.name).and_then(|w| w.value.clone()),
            fields,
            source: winner(&self.source).and_then(|w| w.value.clone()),
            favorite: winner(&self.favorite).is_some_and(|w| w.value),
            tags,
            password_changed: winner(&self.password_changed).and_then(|w| w.value.clone()),
            ignored: self
                .ignored
                .iter()
                .filter_map(|(kind, frontier)| Some((kind.clone(), winner(frontier)?.value?)))
                .collect(),
            password_entry,
            deleted,
        }
    }
}

/// Applies one counted data entry, in causal order.
fn apply(items: &mut BTreeMap<ItemId, ItemState>, node: &Node) {
    let Payload::Data(ops) = &node.entry.payload else {
        return;
    };
    for (index, op) in ops.iter().enumerate() {
        let at = OpRef {
            entry: node.entry.hash,
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
                if check_create_with(kind, name.as_deref(), fields, source.as_ref(), tags).is_err()
                {
                    continue;
                }
                let mut state = ItemState {
                    kind: kind.clone(),
                    created: Write {
                        at,
                        author: node.entry.author,
                        seq: node.entry.seq,
                        value: (),
                    },
                    name: Vec::new(),
                    source: Vec::new(),
                    favorite: Vec::new(),
                    tags: BTreeMap::new(),
                    password_changed: Vec::new(),
                    ignored: BTreeMap::new(),
                    fields: BTreeMap::new(),
                    alive: Vec::new(),
                };
                for (field, value) in fields {
                    let set = Change::Set {
                        field: field.clone(),
                        value: value.clone(),
                    };
                    state.change(node, at, &set);
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
                for t in tags {
                    state.change(node, at, &Change::TagAdd(t.clone()));
                }
                items
                    .entry(item_id(&node.entry.hash, index))
                    .or_insert(state);
            }
            DataOp::Edit { item, change } => {
                let Some(state) = items.get_mut(item) else {
                    continue;
                };
                if !state.created.superseded_by(node, at)
                    || check_change(&state.kind, change).is_err()
                {
                    continue;
                }
                state.change(node, at, change);
            }
        }
    }
}
