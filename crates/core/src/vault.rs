use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::data::{self, Item, ItemState, Version};
use crate::encoding::{Reader, Writer};
use crate::entry::{DataOp, Entry, Log, LogId, MembershipOp, Payload, consent_message, valid_name};
use crate::error::{DecodeError, Error};
use crate::id::{DeviceId, DeviceSecret, Hash, ItemId, Signature, VaultId};
use crate::item::Field;
use crate::membership::{self, Membership};

/// Approximate field data per entry written by [`Vault::create_items`],
/// well under the sync frame limit.
pub const CREATE_BATCH_BYTES: usize = 1024 * 1024;

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
        let mut w = Writer::default();
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
#[derive(Clone)]
pub struct Vault {
    id: VaultId,
    nodes: HashMap<Hash, Node>,
    /// Entry hashes per log, indexed by seq.
    logs: BTreeMap<LogId, Vec<Hash>>,
    /// Arrival order, which is always causal.
    membership_order: Vec<Hash>,
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
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).expect("OS random number generator failed");
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
        let mut vault = Self {
            id: genesis.vault(),
            nodes: HashMap::new(),
            logs: BTreeMap::new(),
            membership_order: Vec::new(),
            data_order: Vec::new(),
            membership_tips: BTreeSet::new(),
            tips: BTreeSet::new(),
            membership: Membership::default(),
            past_memberships: HashMap::new(),
            items: BTreeMap::new(),
        };
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
        if self.nodes.contains_key(&entry.hash()) {
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
        let missing: Vec<Hash> = entry
            .deps()
            .iter()
            .filter(|dep| !self.nodes.contains_key(dep))
            .copied()
            .collect();
        if !missing.is_empty() {
            return Err(Error::MissingDeps(missing));
        }
        let deps: Vec<&Node> = entry.deps().iter().map(|dep| &self.nodes[dep]).collect();
        if entry.log() == Log::Membership
            && deps.iter().any(|dep| dep.entry.log() != Log::Membership)
        {
            return Err(Error::InvalidDeps);
        }
        if let Some(prev) = entry.seq().checked_sub(1) {
            let prev = self.logs[&log_id][prev as usize];
            if !entry.deps().contains(&prev) {
                return Err(Error::InvalidDeps);
            }
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
        if let Payload::Membership(MembershipOp::Remove { device, .. }) = entry.payload()
            && !past.is_member(device)
        {
            return Err(Error::RemoveNonMember);
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
        if let Payload::Data(ops) = &payload {
            for op in ops {
                data::check(&self.items, op)?;
            }
        }
        let tips = match log_id.log {
            Log::Membership => &self.membership_tips,
            Log::Data => &self.tips,
        };
        let prev = self.logs.get(&log_id).and_then(|log| log.last());
        let deps: Vec<Hash> = tips.iter().chain(prev).copied().collect();
        let entry = Entry::sign(secret, self.id, self.next_seq(log_id), deps, payload);
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

    /// Creates many items (an import) in as few entries as fit about
    /// [`CREATE_BATCH_BYTES`] of field data each. Every item is checked
    /// before anything is written, so either all are created or none.
    pub fn create_items(
        &mut self,
        secret: &DeviceSecret,
        items: impl IntoIterator<Item = (String, Option<String>, Vec<(String, Field)>)>,
    ) -> Result<(Vec<ItemId>, Vec<Entry>), Error> {
        if !self.is_member(&secret.device_id()) {
            return Err(Error::NotMember);
        }
        let mut batches: Vec<Vec<DataOp>> = Vec::new();
        let mut size = 0;
        for (kind, name, fields) in items {
            let bytes = kind.len()
                + name.as_ref().map_or(0, String::len)
                + fields
                    .iter()
                    .map(|(n, f)| n.len() + f.kind.as_str().len() + f.value.len() + 16)
                    .sum::<usize>();
            let op = DataOp::create(kind, name, fields);
            data::check(&self.items, &op)?;
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

    /// An item, including deleted ones.
    pub fn item(&self, id: &ItemId) -> Option<Item> {
        self.items.get(id).map(|state| state.item(*id))
    }

    /// All items that are not deleted, ordered by id.
    pub fn items(&self) -> Vec<Item> {
        self.items
            .iter()
            .map(|(id, state)| state.item(*id))
            .filter(|item| !item.deleted)
            .collect()
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
            .map(|(log, hashes)| (*log, hashes.len() as u64 - 1))
            .collect()
    }

    /// Entries a peer holding `peer` heads lacks, in an order it can apply:
    /// all membership entries before any data entry.
    pub fn missing_for(&self, peer: &Heads) -> Vec<&Entry> {
        self.membership_order
            .iter()
            .chain(&self.data_order)
            .map(|hash| &self.nodes[hash].entry)
            .filter(|entry| {
                peer.get(&entry.log_id())
                    .is_none_or(|seq| entry.seq() > seq)
            })
            .collect()
    }

    /// Every stored entry, in an order [`Vault::load`] accepts.
    pub fn entries(&self) -> Vec<&Entry> {
        self.missing_for(&Heads::default())
    }

    fn next_seq(&self, log: LogId) -> u64 {
        self.logs.get(&log).map_or(0, |hashes| hashes.len() as u64)
    }

    /// Resolves the membership of the causal past `clock` covers, excluding the
    /// entry being applied.
    fn past_membership(&mut self, clock: &Clock) -> &Membership {
        let frontier = frontier(clock);
        let current = self
            .logs
            .iter()
            .filter(|(log, _)| log.log == Log::Membership)
            .map(|(log, hashes)| (log.author, hashes.len() as u64 - 1));
        if frontier.iter().copied().eq(current) {
            return &self.membership;
        }
        let nodes = &self.nodes;
        let ops = &self.membership_order;
        let id = &self.id;
        self.past_memberships
            .entry(frontier)
            .or_insert_with_key(|frontier| {
                let covered: BTreeMap<_, _> = frontier.iter().copied().collect();
                let past = ops
                    .iter()
                    .map(|hash| &nodes[hash])
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
        self.logs.entry(entry.log_id()).or_default().push(hash);
        for dep in entry.deps() {
            self.tips.remove(dep);
        }
        self.tips.insert(hash);
        let log = entry.log();
        if log == Log::Membership {
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
                let ops = self
                    .membership_order
                    .iter()
                    .map(|hash| &self.nodes[hash])
                    .collect();
                let membership = membership::resolve(&self.id, ops);
                self.past_memberships.clear();
                let rebuild = !membership.counts_like(&self.membership);
                self.membership = membership;
                if rebuild {
                    self.rebuild_items();
                }
            }
            Log::Data => {
                let node = &self.nodes[&hash];
                if self
                    .membership
                    .counts(&node.entry.author(), node.entry.seq())
                {
                    data::apply(&mut self.items, node);
                }
            }
        }
    }

    fn rebuild_items(&mut self) {
        let mut items = BTreeMap::new();
        for hash in &self.data_order {
            let node = &self.nodes[hash];
            if self
                .membership
                .counts(&node.entry.author(), node.entry.seq())
            {
                data::apply(&mut items, node);
            }
        }
        self.items = items;
    }
}
