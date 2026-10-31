use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::data::{self, Deleted, Item, ItemState, Version};
use crate::encoding::{Reader, Writer};
use crate::entry::{
    DataOp, Entry, Log, LogId, MembershipOp, Payload, consent_message, data_entry_len, valid_name,
};
use crate::error::{DecodeError, Error};
use crate::id::{DeviceId, DeviceSecret, Hash, ItemId, Signature, VaultId};
use crate::item::{Field, ItemError};
use crate::membership::{self, Membership};

/// Encoded ops per entry written by [`Vault::create_items`] (a single op may
/// exceed it), well under [`MAX_ENTRY_LEN`].
pub const CREATE_BATCH_BYTES: usize = 1024 * 1024;

/// The largest encoded entry [`Vault::commit`] accepts: one sync frame
/// (deadbolt-net's 16 MiB `DEFAULT_MAX_FRAME_LEN`, which covers a tag byte
/// and the body) minus its tag. A larger entry could be stored but never
/// sent to another device.
pub const MAX_ENTRY_LEN: usize = 16 * 1024 * 1024 - 1;

/// Maximum non-removal membership entries per author per vault, including the
/// creator's genesis. Removes remain available after this budget is exhausted.
/// Membership is re-resolved on every insert; this bounds each author's
/// non-removal contribution, not the total history or Sybil growth.
/// Data entries have a separate sequence and do not consume this budget.
pub const MAX_MEMBERSHIP_ENTRIES: u64 = 1000;

const _: () = assert!(CREATE_BATCH_BYTES * 8 < MAX_ENTRY_LEN);

/// Per log, the highest seq in an entry's causal past (inclusive).
pub(crate) type Clock = BTreeMap<LogId, u64>;

/// A stored entry plus derived causal metadata.
#[derive(Clone)]
pub(crate) struct Node {
    pub(crate) entry: Entry,
    /// Longest dependency path from the genesis.
    pub(crate) depth: u64,
    pub(crate) clock: Clock,
}

impl Node {
    /// Whether `other` is in this entry's strict causal past.
    pub(crate) fn saw(&self, other: &Node) -> bool {
        self.entry.hash() != other.entry.hash()
            && self
                .clock
                .get(&other.entry.log_id())
                .is_some_and(|&seq| seq >= other.entry.seq())
    }
}

/// The latest seq per log a device holds; the sync frontier.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Heads(BTreeMap<LogId, u64>);

impl Heads {
    /// Latest seq held for `log`.
    pub fn get(&self, log: &LogId) -> Option<u64> {
        self.0.get(log).copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (LogId, u64)> + '_ {
        self.0.iter().map(|(log, seq)| (*log, *seq))
    }

    /// Canonical encoding: count, then (author, log tag, seq) in ascending order.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new(Vec::new());
        w.len(self.0.len());
        for (log, seq) in &self.0 {
            w.bytes(log.author.as_bytes());
            w.u8(match log.log {
                Log::Membership => 0,
                Log::Data => 1,
            });
            w.u64(*seq);
        }
        w.finish()
    }

    /// Strictly decodes [`Heads::encode`] output.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let mut heads = BTreeMap::new();
        let mut last: Option<LogId> = None;
        for _ in 0..r.u32()? {
            let author = DeviceId(r.array()?);
            let log = match r.u8()? {
                0 => Log::Membership,
                1 => Log::Data,
                tag => return Err(DecodeError::InvalidTag(tag)),
            };
            let log = LogId { author, log };
            if last.is_some_and(|last| last >= log) {
                return Err(DecodeError::NotCanonical);
            }
            last = Some(log);
            heads.insert(log, r.u64()?);
        }
        r.finish()?;
        Ok(Self(heads))
    }
}

impl FromIterator<(LogId, u64)> for Heads {
    fn from_iter<I: IntoIterator<Item = (LogId, u64)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// A vault's entries and the state derived from them.
pub type Vault = VaultState<()>;

/// Candidate changes in a durable transaction. The prefix is borrowed, never
/// modified, and the suffix cannot be published against another vault.
pub type VaultWrite<'a> = VaultState<&'a Vault>;

// Static dispatch keeps the normal owned/replay path free of overlay lookups.
pub trait Prefix {
    fn base(&self) -> Option<&Vault>;
}
impl Prefix for () {
    fn base(&self) -> Option<&Vault> {
        None
    }
}
impl Prefix for &Vault {
    fn base(&self) -> Option<&Vault> {
        Some(self)
    }
}

#[derive(Clone)]
pub struct VaultState<P> {
    prefix: P,
    // Only compound local edits need item projections during staging. A
    // single write or incoming batch can project once, after persistence.
    projected: usize,
    rebuild_projection: bool,
    inherit_items: bool,
    id: VaultId,
    nodes: HashMap<Hash, Node>,
    /// Per-author sequence → offset in the corresponding causal arrival order.
    logs: BTreeMap<LogId, Vec<usize>>,
    /// Arrival order, which is always causal.
    membership_order: Vec<Hash>,
    /// Non-removal entries in each author's validated membership chain.
    membership_writes: BTreeMap<DeviceId, u64>,
    data_order: Vec<Hash>,
    /// Membership entries no membership entry depends on.
    membership_tips: BTreeSet<Hash>,
    /// Entries no entry depends on.
    tips: BTreeSet<Hash>,
    membership: Membership,
    /// Memberships of causal pasts behind the current membership heads, keyed by
    /// the membership heads they contain. Cleared on every membership insert.
    past_memberships: HashMap<Frontier, Membership>,
    items: BTreeMap<ItemId, ItemState>,
}

/// The latest membership seq per author in a causal past.
type Frontier = Vec<(DeviceId, u64)>;

fn frontier(clock: &Clock) -> Frontier {
    clock
        .iter()
        .filter(|(log, _)| log.log == Log::Membership)
        .map(|(log, seq)| (log.author, *seq))
        .collect()
}

impl Vault {
    /// Creates a new vault with `secret`'s device as its only member.
    /// Returns the vault and its genesis entry.
    pub fn create(secret: &DeviceSecret, name: impl Into<String>) -> Result<(Self, Entry), Error> {
        let name = name.into();
        if !valid_name(&name) {
            return Err(Error::InvalidName);
        }
        let nonce = crate::id::random();
        let device = secret.device_id();
        let vault = VaultId::derive(&device, &nonce);
        let op = MembershipOp::Create {
            device,
            nonce,
            name,
        };
        let genesis = Entry::sign(secret, vault, 0, [], Payload::Membership(op));
        let vault = Self::from_genesis(genesis.clone())?;
        Ok((vault, genesis))
    }

    /// Starts a vault from its genesis entry.
    pub fn from_genesis(genesis: Entry) -> Result<Self, Error> {
        let Payload::Membership(MembershipOp::Create {
            device,
            nonce,
            name,
        }) = genesis.payload()
        else {
            return Err(Error::InvalidGenesis);
        };
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        let valid = *device == genesis.author()
            && genesis.seq() == 0
            && genesis.deps().is_empty()
            && VaultId::derive(device, nonce) == genesis.vault();
        if !valid {
            return Err(Error::InvalidGenesis);
        }
        genesis.verify()?;
        let mut vault = Self::empty(genesis.vault(), ());
        let clock = Clock::from([(genesis.log_id(), 0)]);
        vault.insert(Node {
            entry: genesis,
            depth: 0,
            clock,
        });
        Ok(vault)
    }

    /// Rebuilds a vault from stored entries in causal order, genesis first
    /// (e.g. the output of [`Vault::entries`]).
    pub fn load(entries: impl IntoIterator<Item = Entry>) -> Result<Self, Error> {
        let mut entries = entries.into_iter();
        let mut vault = Self::from_genesis(entries.next().ok_or(Error::InvalidGenesis)?)?;
        for entry in entries {
            vault.apply(entry)?;
        }
        Ok(vault)
    }

    /// Persist exactly the validated delta (membership before data), then
    /// publish its already verified nodes. On either error the base has not
    /// been touched. The adapter must quarantine it on an uncertain commit.
    pub fn transact<T, E>(
        &mut self,
        change: impl FnOnce(&mut VaultWrite<'_>) -> Result<T, E>,
        persist: impl FnOnce(&[&Entry]) -> Result<(), E>,
    ) -> Result<T, E> {
        let mut write = VaultWrite::empty(self.id, &*self);
        write.inherit_items = true;
        write.membership = self.membership.clone();
        write.membership_tips = self.membership_tips.clone();
        write.tips = self.tips.clone();
        write.membership_writes = self.membership_writes.clone();
        // Include prefix log IDs so frontier iteration sees all authors. Do
        // not copy their (potentially very large) sequence-offset arrays.
        write.logs = self.logs.keys().map(|id| (*id, Vec::new())).collect();
        let result = change(&mut write)?;
        // Compound reads may have needed temporary item projections. They are
        // not part of the durable delta or of the publication recipe.
        drop(write.items);
        if write.nodes.is_empty() {
            return Ok(result);
        }
        let entries: Vec<_> = write
            .membership_order
            .iter()
            .chain(&write.data_order)
            .map(|hash| &write.nodes[hash].entry)
            .collect();
        persist(&entries)?;

        // No fallible validation after the commit. Move verified nodes and
        // their resolved membership; offsets were relative to the suffix.
        let VaultState {
            nodes,
            logs,
            membership_order,
            data_order,
            membership_tips,
            tips,
            membership_writes,
            membership,
            past_memberships,
            ..
        } = write;
        // Only the committed prefix has been projected here. The suffix will
        // be projected below under the final membership either way.
        let rebuild = !membership_order.is_empty() && self.needs_reprojection(&membership);
        let start = self.data_order.len();
        for (id, offsets) in logs.into_iter().filter(|(_, v)| !v.is_empty()) {
            let prefix = self.order(id.log).len();
            self.logs
                .entry(id)
                .or_default()
                .extend(offsets.into_iter().map(|pos| prefix + pos));
        }
        self.nodes.extend(nodes);
        self.tips = tips;
        if !membership_order.is_empty() {
            self.membership_order.extend(membership_order);
            self.membership = membership;
            self.membership_tips = membership_tips;
            self.membership_writes = membership_writes;
            self.past_memberships.clear();
        }
        self.past_memberships.extend(past_memberships);
        self.data_order.extend(data_order);
        if rebuild {
            self.items.clear();
        }
        self.project_suffix(if rebuild { 0 } else { start });
        Ok(result)
    }
}

impl VaultWrite<'_> {
    /// Read your own prior appends during a compound local operation (e.g. an
    /// import linking two newly created items). Not needed to receive sync.
    pub fn item(&mut self, id: &ItemId) -> Option<Item> {
        self.project_pending();
        self.items
            .get(id)
            .or_else(|| self.inherited_items()?.get(id))
            .map(|state| state.item(*id))
    }
}

impl<P: Prefix> VaultState<P> {
    fn empty(id: VaultId, prefix: P) -> Self {
        Self {
            prefix,
            projected: 0,
            rebuild_projection: false,
            inherit_items: false,
            id,
            nodes: HashMap::new(),
            logs: BTreeMap::new(),
            membership_order: Vec::new(),
            membership_writes: BTreeMap::new(),
            data_order: Vec::new(),
            membership_tips: BTreeSet::new(),
            tips: BTreeSet::new(),
            membership: Membership::default(),
            past_memberships: HashMap::new(),
            items: BTreeMap::new(),
        }
    }

    pub fn id(&self) -> VaultId {
        self.id
    }

    /// The vault's current name.
    pub fn name(&self) -> &str {
        self.membership.name()
    }

    /// The security-critical membership check. Apply it to every connection,
    /// accepted or dialed.
    pub fn is_member(&self, device: &DeviceId) -> bool {
        self.membership.is_member(device)
    }

    /// Whether `device` was removed from this vault. Removed keys can never rejoin.
    pub fn was_removed(&self, device: &DeviceId) -> bool {
        self.membership.was_removed(device)
    }

    /// Current members.
    pub fn members(&self) -> impl Iterator<Item = DeviceId> + '_ {
        self.membership.members().copied()
    }

    /// Validates and stores an entry. Returns `Ok(false)` if it was already present.
    ///
    /// Entries must arrive in causal order. Acceptance depends only on the
    /// entry and its ancestors: an author must be an active member in the entry's
    /// causal past. Entries that are valid but no longer count (a removed
    /// device's writes past its cutoff) are stored but have no effect.
    pub fn apply(&mut self, entry: Entry) -> Result<bool, Error> {
        if entry.vault() != self.id {
            return Err(Error::WrongVault {
                expected: self.id,
                found: entry.vault(),
            });
        }
        if self.node(&entry.hash()).is_some() {
            return Ok(false);
        }
        let log_id = entry.log_id();
        let next = self.next_seq(log_id);
        if entry.seq() > next {
            return Err(Error::SeqGap {
                expected: next,
                got: entry.seq(),
            });
        }
        if entry.seq() < next {
            return Err(Error::Fork { seq: entry.seq() });
        }
        // With a contiguous, fork-rejecting chain, this count covers exactly
        // the author's predecessors, independent of other authors' arrival.
        self.check_membership_budget(entry.author(), entry.payload())?;
        let mut deps = Vec::with_capacity(entry.deps().len());
        let mut missing = Vec::new();
        for dep in entry.deps() {
            match self.node(dep) {
                Some(node) => deps.push(node),
                None => missing.push(*dep),
            }
        }
        if !missing.is_empty() {
            return Err(Error::MissingDeps(missing));
        }
        if entry.log() == Log::Membership
            && deps.iter().any(|dep| dep.entry.log() != Log::Membership)
        {
            return Err(Error::InvalidDeps);
        }
        if self
            .previous(log_id)
            .is_some_and(|prev| !entry.deps().contains(prev))
        {
            return Err(Error::InvalidDeps);
        }
        entry.verify()?;
        match entry.payload() {
            Payload::Membership(MembershipOp::Create { .. }) => return Err(Error::InvalidGenesis),
            Payload::Membership(MembershipOp::Rename { name }) if !valid_name(name) => {
                return Err(Error::InvalidName);
            }
            Payload::Membership(MembershipOp::Add { device, consent })
                if !device.verify(&consent_message(&self.id, &entry.author(), device), consent) =>
            {
                return Err(Error::InvalidConsent);
            }
            _ => {}
        }
        let mut clock = Clock::new();
        let mut depth = 0;
        for dep in &deps {
            for (log, &seq) in &dep.clock {
                let max = clock.entry(*log).or_insert(seq);
                *max = (*max).max(seq);
            }
            depth = depth.max(dep.depth + 1);
        }
        let past = self.past_membership(&clock);
        if !past.is_member(&entry.author()) {
            return Err(Error::NotMember);
        }
        match entry.payload() {
            Payload::Membership(MembershipOp::Add { device, .. }) if past.was_removed(device) => {
                return Err(Error::AddRemovedDevice);
            }
            Payload::Membership(MembershipOp::Remove { device, .. }) if !past.is_member(device) => {
                return Err(Error::RemoveNonMember);
            }
            _ => {}
        }
        clock.insert(log_id, entry.seq());
        self.insert(Node {
            entry,
            depth,
            clock,
        });
        Ok(true)
    }

    /// Signs `payload` as the next entry in `secret`'s log, applies it, and
    /// returns it for sending to peers.
    pub fn commit(&mut self, secret: &DeviceSecret, payload: Payload) -> Result<Entry, Error> {
        let author = secret.device_id();
        if !self.is_member(&author) {
            return Err(Error::NotMember);
        }
        let log_id = LogId {
            author,
            log: payload.log(),
        };
        self.check_membership_budget(author, &payload)?;
        if let Payload::Data(ops) = &payload {
            if self.prefix.base().is_some()
                && ops.iter().any(|op| matches!(op, DataOp::Edit { .. }))
            {
                self.project_pending();
            }
            let items = |id: &ItemId| {
                self.items
                    .get(id)
                    .or_else(|| self.inherited_items()?.get(id))
            };
            for op in ops {
                data::check(items, op)?;
            }
            data::check_files(items, ops)?;
            data::check_tags(items, ops)?;
        }
        let tips = match log_id.log {
            Log::Membership => &self.membership_tips,
            Log::Data => &self.tips,
        };
        let prev = self.previous(log_id);
        let deps: Vec<Hash> = tips.iter().chain(prev).copied().collect();
        let entry = Entry::sign(secret, self.id, self.next_seq(log_id), deps, payload);
        let len = entry.encoded_len();
        if len > MAX_ENTRY_LEN {
            return Err(Error::TooLarge {
                len,
                max: MAX_ENTRY_LEN,
            });
        }
        self.apply(entry.clone())?;
        Ok(entry)
    }

    /// Adds `device`, given its [`DeviceSecret::join_consent`] for this vault and
    /// `secret`'s device.
    pub fn add(
        &mut self,
        secret: &DeviceSecret,
        device: DeviceId,
        consent: Signature,
    ) -> Result<Entry, Error> {
        if self.was_removed(&device) {
            return Err(Error::AddRemovedDevice);
        }
        self.commit(
            secret,
            Payload::Membership(MembershipOp::Add { device, consent }),
        )
    }

    /// Removes `device`. Its data entries this vault already holds keep counting.
    pub fn remove(&mut self, secret: &DeviceSecret, device: DeviceId) -> Result<Entry, Error> {
        let last_seen_seq = self
            .next_seq(LogId {
                author: device,
                log: Log::Data,
            })
            .checked_sub(1);
        self.commit(
            secret,
            Payload::Membership(MembershipOp::Remove {
                device,
                last_seen_seq,
            }),
        )
    }

    /// Renames the vault.
    pub fn rename(
        &mut self,
        secret: &DeviceSecret,
        name: impl Into<String>,
    ) -> Result<Entry, Error> {
        let name = name.into();
        if !valid_name(&name) {
            return Err(Error::InvalidName);
        }
        self.commit(secret, Payload::Membership(MembershipOp::Rename { name }))
    }

    /// Writes data ops as one entry. Fails if any op breaks the item rules
    /// (see [`crate::item`]).
    pub fn write(&mut self, secret: &DeviceSecret, ops: Vec<DataOp>) -> Result<Entry, Error> {
        self.commit(secret, Payload::Data(ops))
    }

    /// Creates an item and returns its id.
    pub fn create_item(
        &mut self,
        secret: &DeviceSecret,
        kind: impl Into<String>,
        name: Option<String>,
        fields: impl IntoIterator<Item = (String, Field)>,
    ) -> Result<(ItemId, Entry), Error> {
        let entry = self.write(secret, vec![DataOp::create(kind, name, fields)])?;
        Ok((ItemId::of_create(&entry.hash(), 0), entry))
    }

    /// Creates an item with initial `favorite` and `tags`, returning its id.
    pub fn create_item_with(
        &mut self,
        secret: &DeviceSecret,
        kind: impl Into<String>,
        name: Option<String>,
        fields: impl IntoIterator<Item = (String, Field)>,
        favorite: bool,
        tags: impl IntoIterator<Item = String>,
    ) -> Result<(ItemId, Entry), Error> {
        let op = DataOp::create_with(kind, name, fields, None, favorite, tags);
        let entry = self.write(secret, vec![op])?;
        Ok((ItemId::of_create(&entry.hash(), 0), entry))
    }

    /// Creates many items (an import) in as few entries as fit
    /// [`CREATE_BATCH_BYTES`] of encoded ops each. Every op must be a
    /// [`DataOp::Create`] (an edit fails as [`ItemError::NoSuchItem`]). Every
    /// item is checked before anything is written, so either all are
    /// created or none; one too large to sync even in an entry of its own
    /// fails as [`Error::TooLarge`].
    pub fn create_items(
        &mut self,
        secret: &DeviceSecret,
        items: impl IntoIterator<Item = DataOp>,
    ) -> Result<(Vec<ItemId>, Vec<Entry>), Error> {
        if !self.is_member(&secret.device_id()) {
            return Err(Error::NotMember);
        }
        // The first entry depends on every tip and this device's previous
        // entry; later ones only on the entry before.
        let deps = self.tips.len() + 1;
        let mut batches: Vec<Vec<DataOp>> = Vec::new();
        let mut size = 0;
        for op in items {
            if !matches!(op, DataOp::Create { .. }) {
                return Err(ItemError::NoSuchItem.into());
            }
            let bytes = op.encoded_len();
            let len = data_entry_len(deps, bytes);
            if len > MAX_ENTRY_LEN {
                return Err(Error::TooLarge {
                    len,
                    max: MAX_ENTRY_LEN,
                });
            }
            data::check(|id| self.items.get(id), &op)?;
            match batches.last_mut() {
                Some(batch) if size + bytes <= CREATE_BATCH_BYTES => batch.push(op),
                _ => {
                    batches.push(vec![op]);
                    size = 0;
                }
            }
            size += bytes;
        }
        let mut ids = Vec::new();
        let mut entries = Vec::new();
        for ops in batches {
            let count = ops.len();
            let entry = self.write(secret, ops)?;
            ids.extend((0..count).map(|i| ItemId::of_create(&entry.hash(), i)));
            entries.push(entry);
        }
        Ok((ids, entries))
    }
}

impl Vault {
    /// An item, including deleted ones.
    pub fn item(&self, id: &ItemId) -> Option<Item> {
        self.items.get(id).map(|state| state.item(*id))
    }

    /// Closest live item ids on either side of `id`, for unique display
    /// prefixes. Tombstones do not compete with live items for a prefix.
    pub fn live_neighbors(&self, id: ItemId) -> [Option<ItemId>; 2] {
        use std::ops::Bound::{Excluded, Unbounded};
        [
            self.items
                .range(..id)
                .rev()
                .find(|(_, state)| !state.deleted())
                .map(|(id, _)| *id),
            self.items
                .range((Excluded(id), Unbounded))
                .find(|(_, state)| !state.deleted())
                .map(|(id, _)| *id),
        ]
    }

    /// Live items in id order, materialized one at a time.
    pub fn iter_items(&self) -> impl Iterator<Item = Item> + '_ {
        self.items
            .iter()
            .map(|(id, state)| state.item(*id))
            .filter(|item| !item.deleted)
    }

    /// Live logins for a page's registrable domain, in item-id order. Check
    /// the winning URL fields before materializing any of an item's values.
    pub fn site_logins<'a>(
        &'a self,
        site: &'a crate::site::Site,
    ) -> impl Iterator<Item = Item> + 'a {
        self.items
            .iter()
            .filter(|(_, state)| state.login_on(site))
            .map(|(id, state)| state.item(*id))
    }

    /// All items that are not deleted, ordered by id.
    pub fn items(&self) -> Vec<Item> {
        self.iter_items().collect()
    }

    /// Deleted items, newest first: by when they were deleted, then those
    /// that don't say when, by id.
    pub fn deleted(&self) -> Vec<Deleted> {
        let mut deleted: Vec<Deleted> = self
            .items
            .iter()
            .map(|(id, state)| (state.item(*id), state))
            .filter(|(item, _)| item.deleted)
            .map(|(item, state)| Deleted {
                at: state.deleted_at(),
                item,
            })
            .collect();
        deleted.sort_by(|a, b| b.at.cmp(&a.at).then(a.item.id.cmp(&b.item.id)));
        deleted
    }

    /// Every change to an item in causal order, with whether it is current.
    pub fn history(&self, id: &ItemId) -> Vec<Version> {
        self.items
            .get(id)
            .map(ItemState::history)
            .unwrap_or_default()
    }

    /// The latest seq held per log.
    pub fn heads(&self) -> Heads {
        self.logs
            .iter()
            .map(|(log, offsets)| (*log, offsets.len() as u64 - 1))
            .collect()
    }

    /// Entries a peer holding `peer` heads lacks, in an order it can apply:
    /// all membership entries before any data entry.
    pub fn missing_for(&self, peer: &Heads) -> Vec<&Entry> {
        if peer.0.is_empty() {
            return self.entries();
        }
        // A log's sequence is contiguous and its offsets are increasing. The
        // earliest first-missing offset is the start of the only suffix that
        // could contain a delta. Still filter interleaved, already-known logs.
        let mut membership = self.membership_order.len();
        let mut data = self.data_order.len();
        for (id, offsets) in &self.logs {
            let next = peer.get(id).map_or(0, |seq| seq.saturating_add(1));
            let Some(&pos) = usize::try_from(next).ok().and_then(|n| offsets.get(n)) else {
                continue;
            };
            let start = match id.log {
                Log::Membership => &mut membership,
                Log::Data => &mut data,
            };
            *start = (*start).min(pos);
        }
        self.membership_order[membership..]
            .iter()
            .chain(&self.data_order[data..])
            .map(|hash| &self.nodes[hash].entry)
            .filter(|entry| {
                peer.get(&entry.log_id())
                    .is_none_or(|seq| entry.seq() > seq)
            })
            .collect()
    }

    /// Every stored entry, in an order [`Vault::load`] accepts.
    pub fn entries(&self) -> Vec<&Entry> {
        self.membership_order
            .iter()
            .chain(&self.data_order)
            .map(|hash| &self.nodes[hash].entry)
            .collect()
    }
}

impl<P: Prefix> VaultState<P> {
    fn node(&self, hash: &Hash) -> Option<&Node> {
        self.nodes
            .get(hash)
            .or_else(|| self.prefix.base()?.nodes.get(hash))
    }

    fn previous(&self, log: LogId) -> Option<&Hash> {
        self.logs
            .get(&log)
            .and_then(|offsets| offsets.last())
            .map(|&i| &self.order(log.log)[i])
            .or_else(|| {
                let base = self.prefix.base()?;
                let &i = base.logs.get(&log)?.last()?;
                Some(&base.order(log.log)[i])
            })
    }

    fn order(&self, log: Log) -> &[Hash] {
        match log {
            Log::Membership => &self.membership_order,
            Log::Data => &self.data_order,
        }
    }

    fn check_membership_budget(&self, author: DeviceId, payload: &Payload) -> Result<(), Error> {
        if matches!(payload, Payload::Membership(op) if !matches!(op, MembershipOp::Remove { .. }))
            && self.membership_writes.get(&author).copied().unwrap_or(0) >= MAX_MEMBERSHIP_ENTRIES
        {
            return Err(Error::MembershipLimit {
                max: MAX_MEMBERSHIP_ENTRIES,
            });
        }
        Ok(())
    }

    fn next_seq(&self, log: LogId) -> u64 {
        self.log_len(log, self.logs.get(&log).map_or(0, Vec::len))
    }

    fn log_len(&self, log: LogId, suffix: usize) -> u64 {
        (suffix
            + self
                .prefix
                .base()
                .and_then(|v| v.logs.get(&log))
                .map_or(0, Vec::len)) as u64
    }

    /// Resolves the membership of the causal past `clock` covers, excluding the
    /// entry being applied.
    fn past_membership(&mut self, clock: &Clock) -> &Membership {
        let frontier = frontier(clock);
        let current = self
            .logs
            .iter()
            .filter(|(log, _)| log.log == Log::Membership)
            .map(|(log, offsets)| (log.author, self.log_len(*log, offsets.len()) - 1));
        if frontier.iter().copied().eq(current) {
            return &self.membership;
        }
        let nodes = &self.nodes;
        let ops = &self.membership_order;
        let base = self.prefix.base();
        // A cached frontier names only immutable, fork-checked prefix nodes.
        if let Some(past) = base.and_then(|v| v.past_memberships.get(&frontier)) {
            return past;
        }
        let id = &self.id;
        self.past_memberships
            .entry(frontier)
            .or_insert_with_key(|frontier| {
                let covered: BTreeMap<_, _> = frontier.iter().copied().collect();
                let past = membership_nodes(base, ops, nodes)
                    .filter(|node| {
                        covered
                            .get(&node.entry.author())
                            .is_some_and(|&seq| seq >= node.entry.seq())
                    })
                    .collect();
                membership::resolve(id, past)
            })
    }

    fn insert(&mut self, node: Node) {
        let entry = &node.entry;
        let hash = entry.hash();
        let offset = self.order(entry.log()).len();
        self.logs.entry(entry.log_id()).or_default().push(offset);
        for dep in entry.deps() {
            self.tips.remove(dep);
        }
        self.tips.insert(hash);
        let log = entry.log();
        if log == Log::Membership {
            if !matches!(
                entry.payload(),
                Payload::Membership(MembershipOp::Remove { .. })
            ) {
                *self.membership_writes.entry(entry.author()).or_default() += 1;
            }
            for dep in entry.deps() {
                self.membership_tips.remove(dep);
            }
            self.membership_tips.insert(hash);
            self.membership_order.push(hash);
        } else {
            self.data_order.push(hash);
        }
        self.nodes.insert(hash, node);
        match log {
            Log::Membership => {
                let ops = membership_nodes(self.prefix.base(), &self.membership_order, &self.nodes)
                    .collect();
                let membership = membership::resolve(&self.id, ops);
                self.past_memberships.clear();
                let rebuild = self.needs_reprojection(&membership);
                self.membership = membership;
                if rebuild && self.prefix.base().is_some() {
                    self.rebuild_projection = true;
                } else if rebuild {
                    self.items.clear();
                    self.project_suffix(0);
                }
            }
            Log::Data if self.prefix.base().is_some() => {} // projected lazily for subsequent local edits
            Log::Data => {
                let node = &self.nodes[&hash];
                if self
                    .membership
                    .counts(&node.entry.author(), node.entry.seq())
                {
                    data::apply(&mut self.items, None, node);
                }
            }
        }
    }

    /// Compare effective cutoffs only for data already visited by the projection.
    /// A fresh Add has no such data, but an author whose earlier admission was
    /// cut can have stored, ignored entries without appearing in `removed`.
    fn needs_reprojection(&self, next: &Membership) -> bool {
        self.logs.iter().any(|(log, offsets)| {
            if log.log != Log::Data {
                return false;
            }
            let suffix = if self.prefix.base().is_some() {
                offsets.partition_point(|&i| i < self.projected)
            } else {
                offsets.len()
            };
            self.log_len(*log, suffix)
                .checked_sub(1)
                .is_some_and(|last| {
                    self.membership.counted_through(&log.author, last)
                        != next.counted_through(&log.author, last)
                })
        })
    }

    fn inherited_items(&self) -> Option<&BTreeMap<ItemId, ItemState>> {
        self.prefix
            .base()
            .filter(|_| self.inherit_items)
            .map(|v| &v.items)
    }

    fn project_pending(&mut self) {
        let Some(base) = self.prefix.base() else {
            return;
        };
        if self.rebuild_projection {
            // An effective cutoff can hide or restore older data. Only local
            // reads and edits need this intermediate projection.
            self.items.clear();
            self.inherit_items = false;
            project(
                &mut self.items,
                None,
                &self.membership,
                base.data_order.iter().map(|h| &base.nodes[h]),
            );
            self.projected = 0;
            self.rebuild_projection = false;
        }
        // Split the immutable prefix borrow from the mutable projection.
        let inherited = self.inherit_items.then_some(&base.items);
        project(
            &mut self.items,
            inherited,
            &self.membership,
            self.data_order[self.projected..]
                .iter()
                .map(|h| &self.nodes[h]),
        );
        self.projected = self.data_order.len();
    }

    fn project_suffix(&mut self, start: usize) {
        project(
            &mut self.items,
            None,
            &self.membership,
            self.data_order[start..].iter().map(|h| &self.nodes[h]),
        );
    }
}

fn project<'a>(
    items: &mut BTreeMap<ItemId, ItemState>,
    inherited: Option<&BTreeMap<ItemId, ItemState>>,
    membership: &Membership,
    nodes: impl Iterator<Item = &'a Node>,
) {
    for node in nodes {
        if membership.counts(&node.entry.author(), node.entry.seq()) {
            data::apply(items, inherited, node);
        }
    }
}

fn membership_nodes<'a>(
    base: Option<&'a Vault>,
    order: &'a [Hash],
    nodes: &'a HashMap<Hash, Node>,
) -> impl Iterator<Item = &'a Node> {
    base.into_iter()
        .flat_map(|v| v.membership_order.iter().map(|h| &v.nodes[h]))
        .chain(order.iter().map(|h| &nodes[h]))
}
