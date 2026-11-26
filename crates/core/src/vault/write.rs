//! Writing to a vault: who signs ([`Author`]) and what a transaction can
//! do ([`VaultWrite`]). Every write signs its frames, applies them and
//! stages them for the transaction's commit.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, DerefMut};

use crate::error::Error;
use crate::id::{DeviceId, DeviceSecret, ItemId, Signature};
use crate::item::{Field, ItemError};
use crate::ops::{DataOp, valid_name};
use crate::v2::{
    self, DataPayload, DeviceKeys, EpochId, EpochKey, Frame, FrameId, KemPublic, LogKind,
    NetPublic, RecoverySecret, VectorClock, WriteEpochDecision, honest_clock, next_dclock,
};

use super::{Vault, view};

/// v2 ops per data frame, under [`v2::MAX_OPS`].
const OPS_PER_FRAME: usize = 4000;
/// Bytes of ops per data frame, about.
const BYTES_PER_FRAME: usize = 1024 * 1024;
/// The largest one op may be, leaving room for padding and the frame's header.
const MAX_OP_LEN: usize = 14 * 1024 * 1024;
/// The largest frame a vault writes, encoded: what one sync message and one
/// log record hold.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Who signs a write, and when (Unix milliseconds on this device's clock).
pub struct Author {
    keys: DeviceKeys,
    now_ms: u64,
}

impl Author {
    pub fn new(keys: DeviceKeys, now_ms: u64) -> Self {
        Self { keys, now_ms }
    }

    pub fn id(&self) -> DeviceId {
        self.keys.device_id()
    }

    pub fn keys(&self) -> &DeviceKeys {
        &self.keys
    }

    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// This device's consent to join `vault` through `inviter`.
    pub fn join_consent(&self, vault: &crate::VaultId, inviter: &DeviceId) -> Signature {
        v2::sign_join_consent(
            self.keys.sign_key(),
            vault,
            inviter,
            &self.keys.kem_public(),
        )
    }
}

/// A vault inside [`Vault::transact`]: reads see every write made so far.
pub struct VaultWrite<'a> {
    vault: &'a mut Vault,
}

impl Deref for VaultWrite<'_> {
    type Target = Vault;
    fn deref(&self) -> &Vault {
        self.vault
    }
}

impl DerefMut for VaultWrite<'_> {
    fn deref_mut(&mut self) -> &mut Vault {
        self.vault
    }
}

fn frame_err(e: impl std::fmt::Display) -> Error {
    Error::Frame(e.to_string())
}

impl Vault {
    /// A new vault whose recovery root is `recovery`, holding `author`'s
    /// device as its first member under `label`. Returns the vault and its
    /// first frames: `Create`+`Rotate` and `Add` by the root, then the
    /// device's name and card.
    pub fn create(
        recovery: &RecoverySecret,
        author: &Author,
        name: &str,
        label: &str,
    ) -> Result<(Self, Vec<Frame>), Error> {
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        let k0 = EpochKey::generate().map_err(frame_err)?;
        let create =
            v2::build_create_frame(recovery, crate::id::random(), &k0).map_err(frame_err)?;
        let id = create.header().vault;
        let e0 = EpochId::from_frame_id(create.id());
        let mut vault = Vault::empty(id, author.id(), author.keys.kem_key());
        vault.insert([create.clone()])?;
        vault.refresh();
        let root = recovery.signing_key();
        let consent = author.join_consent(&id, &root.device_id());
        let add = v2::build_add_frame(
            &root,
            id,
            &vault.resolved,
            1,
            create.id(),
            vec![create.id()],
            author.id(),
            author.keys.kem_public(),
            consent,
            Some((e0, &k0)),
        )
        .map_err(frame_err)?;
        vault.insert([add.clone()])?;
        vault.refresh();
        let mut frames = vec![create, add];
        vault.transact(
            |v| {
                let card = v2::DataOp::DeviceCard {
                    device: author.id(),
                    net_pk: author.keys.net_public(),
                    label: label.chars().take(64).collect(),
                };
                let name = v2::DataOp::VaultMeta { name: name.into() };
                v.seal(author, vec![name, card]).map(drop)
            },
            |_, made| {
                frames.extend(made.iter().map(|f| (*f).clone()));
                Ok(())
            },
        )?;
        Ok((vault, frames))
    }
}

impl<'a> VaultWrite<'a> {
    pub(super) fn new(vault: &'a mut Vault) -> Self {
        Self { vault }
    }

    fn stage(&mut self, frames: Vec<Frame>) -> Result<Vec<FrameId>, Error> {
        let new = self.vault.insert(frames)?;
        self.vault.staged.extend(&new);
        self.vault.refresh();
        Ok(new)
    }

    /// Applies frames from a peer. Returns how many were new.
    pub fn apply(&mut self, frames: Vec<Frame>) -> Result<usize, Error> {
        Ok(self.stage(frames)?.len())
    }

    /// Where `author`'s next frame in `log` goes: its seq and `prev`.
    fn position(&self, author: &DeviceId, log: LogKind) -> (u64, FrameId) {
        let frames = match log {
            LogKind::Member => &self.members,
            LogKind::Data => &self.data,
        };
        frames
            .values()
            .filter(|f| f.header().author == *author)
            .max_by_key(|f| f.header().seq)
            .map_or((0, FrameId::ZERO), |f| (f.header().seq + 1, f.id()))
    }

    /// The membership frames no placed frame names: what a new frame depends on.
    pub(super) fn mheads_excluding(&self, skip: &BTreeSet<FrameId>) -> Vec<FrameId> {
        let dag: Vec<&Frame> = self
            .resolved
            .dag_frames
            .iter()
            .filter(|id| !skip.contains(id))
            .filter_map(|id| self.members.get(id))
            .collect();
        let mut cited = BTreeSet::new();
        for f in &dag {
            cited.extend(f.member_body().map(|b| b.deps.clone()).unwrap_or_default());
            cited.insert(f.header().prev);
        }
        dag.iter()
            .map(|f| f.id())
            .filter(|id| !cited.contains(id))
            .collect()
    }

    fn mheads(&self) -> Vec<FrameId> {
        self.mheads_excluding(&BTreeSet::new())
    }

    /// A member frame's deps: `heads`, plus its author's `prev` (which a
    /// later frame may already cite, hiding it from the heads).
    fn member_deps(prev: FrameId, mut heads: Vec<FrameId>) -> Vec<FrameId> {
        if !prev.is_zero() && !heads.contains(&prev) {
            heads.push(prev);
            heads.sort();
        }
        heads
    }

    /// Eligible wrap recipients and their keys, minus `leaving` and plus `joining`.
    fn recipients(
        &self,
        leaving: Option<DeviceId>,
        joining: Option<(DeviceId, KemPublic)>,
    ) -> BTreeMap<DeviceId, KemPublic> {
        let mut out: BTreeMap<_, _> = self
            .resolved
            .eligible_recipients()
            .into_iter()
            .filter_map(|id| Some((id, self.resolved.kem_of(&id)?)))
            .collect();
        if let Some(id) = leaving {
            out.remove(&id);
        }
        out.extend(joining);
        out
    }

    /// The newest authorized epochs this device holds keys for.
    fn parents(&self) -> Vec<EpochId> {
        let held: BTreeSet<EpochId> = self
            .keyring
            .epoch_ids()
            .into_iter()
            .filter(|e| self.graph().get(e).is_some_and(|i| i.authorized))
            .collect();
        self.graph().maximal_epochs_in(&held)
    }

    /// The epoch `author` writes under now (rule E4), minting a `Rotate`
    /// first if there is no clean tip.
    fn write_epoch(&mut self, author: &DeviceSecret) -> Result<(EpochId, EpochKey), Error> {
        let me = author.device_id();
        let current = self
            .data
            .values()
            .filter(|f| f.header().author == me)
            .max_by_key(|f| f.header().seq)
            .map(|f| f.header().epoch);
        let decision = self.graph().select_write_epoch_with_parking(
            &self.resolved,
            &self.keyring,
            &self.bad_epochs,
            &self.previously_removed,
            current,
        );
        let epoch = match decision {
            WriteEpochDecision::Use(e) => e,
            WriteEpochDecision::Parked {
                current_epoch: Some(e),
                ..
            } if self.keyring.contains(&e) => e,
            WriteEpochDecision::Parked { reasons, .. } => {
                return Err(Error::Parked(describe_parking(&reasons)));
            }
            WriteEpochDecision::AwaitingRewrap(_) => return Err(Error::AwaitingKeys),
            WriteEpochDecision::MintRotate { parents } => {
                let key = EpochKey::generate().map_err(frame_err)?;
                let (seq, prev) = self.position(&me, LogKind::Member);
                let recipients = self.recipients(None, None);
                let frame = v2::build_standalone_rotate_frame(
                    author,
                    self.id,
                    &self.resolved,
                    seq,
                    prev,
                    Self::member_deps(prev, self.mheads()),
                    &key,
                    parents,
                    &self.keyring,
                    &recipients,
                )
                .map_err(frame_err)?;
                let epoch = EpochId::from_frame_id(frame.id());
                self.keyring.insert(epoch, key);
                self.stage(vec![frame])?;
                epoch
            }
        };
        // Parked writes stay in the current epoch, which a lost membership
        // conflict can leave unauthorized: data sealed there counts for no one.
        if !self.graph().get(&epoch).is_some_and(|i| i.authorized) {
            return Err(Error::AwaitingKeys);
        }
        let key = self
            .keyring
            .get(&epoch)
            .cloned()
            .ok_or(Error::AwaitingKeys)?;
        Ok((epoch, key))
    }

    /// Seals `ops` as `author`'s next data frame.
    fn seal(&mut self, author: &Author, ops: Vec<v2::DataOp>) -> Result<FrameId, Error> {
        let me = author.id();
        if !self.is_member(&me) {
            return Err(Error::NotMember);
        }
        let (epoch, key) = self.write_epoch(author.keys.sign_key())?;
        let (seq, prev) = self.position(&me, LogKind::Data);
        let mut mine: Vec<&v2::DataFrame> =
            self.opened.values().filter(|f| f.author == me).collect();
        mine.sort_by_key(|f| f.seq);
        let prev_clock = mine
            .iter()
            .fold(VectorClock::new(), |clock, f| f.clock_after(&clock));
        // Claim only frames the fold resolved: naming one still waiting on
        // a frame this device lacks would leave this write waiting too.
        let resolved = v2::resolved_frames(&self.resolved, self.opened.values());
        let honest = honest_clock(self.data.values().map(|f| {
            let h = f.header();
            (h.author, h.seq, resolved.contains(&f.id()))
        }));
        let payload = DataPayload {
            mheads: self.mheads(),
            dclock: next_dclock(&prev_clock, &honest, &me),
            timestamp_ms: author.now_ms,
            ops,
        };
        let frame = payload
            .seal(author.keys.sign_key(), self.id, seq, prev, epoch, &key)
            .map_err(frame_err)?;
        let len = frame.encode().len();
        if len > MAX_FRAME_LEN {
            return Err(Error::TooLarge {
                len,
                max: MAX_FRAME_LEN,
            });
        }
        let id = frame.id();
        self.stage(vec![frame])?;
        Ok(id)
    }

    /// Writes item ops as one frame. Fails if any op breaks the item rules.
    pub fn write(&mut self, author: &Author, ops: Vec<DataOp>) -> Result<FrameId, Error> {
        let (_, frames) = self.write_ops(author, ops)?;
        frames.last().copied().ok_or(Error::Item(ItemError::Empty))
    }

    /// Writes item ops, in as many frames as they need, returning the item
    /// each op touched (new ids for creates) and the frames.
    fn write_ops(
        &mut self,
        author: &Author,
        ops: Vec<DataOp>,
    ) -> Result<(Vec<ItemId>, Vec<FrameId>), Error> {
        view::check(|id| self.state.items.get(id), &ops)?;
        let mut ids = Vec::with_capacity(ops.len());
        let mut batches: Vec<Vec<v2::DataOp>> = vec![Vec::new()];
        let mut bytes = 0;
        for op in &ops {
            let mut out = Vec::new();
            ids.push(view::translate(op, ItemId::random(), &mut out));
            let len = op.encoded_len();
            if len > MAX_OP_LEN {
                return Err(Error::TooLarge {
                    len,
                    max: MAX_OP_LEN,
                });
            }
            let full = batches.last().is_some_and(|b| {
                !b.is_empty()
                    && (b.len() + out.len() > OPS_PER_FRAME || bytes + len > BYTES_PER_FRAME)
            });
            if full {
                batches.push(Vec::new());
                bytes = 0;
            }
            bytes += len;
            if let Some(batch) = batches.last_mut() {
                batch.extend(out);
            }
        }
        let mut frames = Vec::new();
        for batch in batches.into_iter().filter(|b| !b.is_empty()) {
            frames.push(self.seal(author, batch)?);
        }
        Ok((ids, frames))
    }

    /// Creates an item and returns its id.
    pub fn create_item(
        &mut self,
        author: &Author,
        kind: impl Into<String>,
        name: Option<String>,
        fields: impl IntoIterator<Item = (String, Field)>,
    ) -> Result<(ItemId, FrameId), Error> {
        self.create_item_with(author, kind, name, fields, false, [])
    }

    /// Creates an item with initial `favorite` and `tags`, returning its id.
    pub fn create_item_with(
        &mut self,
        author: &Author,
        kind: impl Into<String>,
        name: Option<String>,
        fields: impl IntoIterator<Item = (String, Field)>,
        favorite: bool,
        tags: impl IntoIterator<Item = String>,
    ) -> Result<(ItemId, FrameId), Error> {
        let op = DataOp::create_with(kind, name, fields, None, favorite, tags);
        let (ids, frames) = self.write_ops(author, vec![op])?;
        match (ids.first(), frames.last()) {
            (Some(id), Some(frame)) => Ok((*id, *frame)),
            _ => Err(Error::Item(ItemError::Empty)),
        }
    }

    /// Creates many items (an import), all or none. Every op must be a
    /// [`DataOp::Create`].
    pub fn create_items(
        &mut self,
        author: &Author,
        items: impl IntoIterator<Item = DataOp>,
    ) -> Result<(Vec<ItemId>, Vec<FrameId>), Error> {
        let ops: Vec<DataOp> = items.into_iter().collect();
        if ops.iter().any(|op| !matches!(op, DataOp::Create { .. })) {
            return Err(ItemError::NoSuchItem.into());
        }
        if ops.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        self.write_ops(author, ops)
    }

    /// Renames the vault.
    pub fn rename(&mut self, author: &Author, name: impl Into<String>) -> Result<FrameId, Error> {
        let name = name.into();
        if !valid_name(&name) {
            return Err(Error::InvalidName);
        }
        self.seal(author, vec![v2::DataOp::VaultMeta { name }])
    }

    /// Writes `device`'s transport key and label (as the device or its adder).
    pub fn card(
        &mut self,
        author: &Author,
        device: DeviceId,
        net_pk: NetPublic,
        label: &str,
    ) -> Result<FrameId, Error> {
        let label: String = label.chars().take(64).collect();
        self.seal(
            author,
            vec![v2::DataOp::DeviceCard {
                device,
                net_pk,
                label,
            }],
        )
    }

    /// Adds `device` with its KEM key and consent, rewrapping the current
    /// write epoch to it.
    pub fn add(
        &mut self,
        author: &Author,
        device: DeviceId,
        kem: KemPublic,
        consent: Signature,
    ) -> Result<FrameId, Error> {
        if !self.is_member(&author.id()) {
            return Err(Error::NotMember);
        }
        self.add_signed(author.keys.sign_key(), device, kem, consent)
    }

    /// [`VaultWrite::add`] signed by any principal: a device or the recovery root.
    pub fn add_signed(
        &mut self,
        signer: &DeviceSecret,
        device: DeviceId,
        kem: KemPublic,
        consent: Signature,
    ) -> Result<FrameId, Error> {
        if self.was_removed(&device) {
            return Err(Error::AddRemovedDevice);
        }
        let (epoch, key) = self.write_epoch(signer)?;
        let me = signer.device_id();
        let (seq, prev) = self.position(&me, LogKind::Member);
        let frame = v2::build_add_frame(
            signer,
            self.id,
            &self.resolved,
            seq,
            prev,
            Self::member_deps(prev, self.mheads()),
            device,
            kem,
            consent,
            Some((epoch, &key)),
        )
        .map_err(frame_err)?;
        Ok(self.stage(vec![frame])?[0])
    }

    /// Removes `device` with an atomic `Rotate`. Its data frames this
    /// vault holds keep counting.
    pub fn remove(&mut self, author: &Author, device: DeviceId) -> Result<FrameId, Error> {
        if !self.is_member(&author.id()) {
            return Err(Error::NotMember);
        }
        self.remove_signed(author.keys.sign_key(), device, None)
    }

    /// Removes a stolen `device`: only its data frames written before
    /// `since_ms` keep counting, and the removal depends on none of the
    /// membership frames it wrote that no other principal has built on.
    pub fn remove_stolen(
        &mut self,
        signer: &DeviceSecret,
        device: DeviceId,
        since_ms: Option<u64>,
    ) -> Result<FrameId, Error> {
        self.remove_signed(signer, device, Some(since_ms))
    }

    /// Removes `device` as the recovery root.
    pub fn remove_by_root(
        &mut self,
        root: &RecoverySecret,
        device: DeviceId,
    ) -> Result<FrameId, Error> {
        if self.recovery_root() != Some(root.recovery_id()) {
            return Err(Error::NotRecoveryRoot);
        }
        self.remove_signed(&root.signing_key(), device, None)
    }

    fn remove_signed(
        &mut self,
        signer: &DeviceSecret,
        device: DeviceId,
        stolen: Option<Option<u64>>,
    ) -> Result<FrameId, Error> {
        if !self.is_member(&device) {
            return Err(Error::RemoveNonMember);
        }
        let mut counted = 0u64;
        while let Some(f) = self
            .data
            .values()
            .find(|f| f.header().author == device && f.header().seq == counted)
        {
            let before = match stolen {
                Some(Some(since)) => self
                    .opened
                    .get(&f.id())
                    .is_some_and(|o| o.body.timestamp_ms() < since),
                _ => true,
            };
            if !before {
                break;
            }
            counted += 1;
        }
        let last_seen_seq = counted.checked_sub(1);
        let deps = match stolen {
            Some(_) => self.mheads_excluding(&self.pre_theft_exclusions(&device)),
            None => self.mheads(),
        };
        let key = EpochKey::generate().map_err(frame_err)?;
        let me = signer.device_id();
        let (seq, prev) = self.position(&me, LogKind::Member);
        let recipients = self.recipients(Some(device), None);
        let parents = self.parents();
        let frame = v2::build_remove_frame(
            signer,
            self.id,
            &self.resolved,
            seq,
            prev,
            Self::member_deps(prev, deps),
            device,
            last_seen_seq,
            &key,
            parents,
            &self.keyring,
            &recipients,
        )
        .map_err(frame_err)?;
        self.keyring.insert(EpochId::from_frame_id(frame.id()), key);
        Ok(self.stage(vec![frame])?[0])
    }

    /// What a removal of a stolen `device` must not depend on: the removals
    /// it signed that nobody else has built on, and everything after them.
    fn pre_theft_exclusions(&self, device: &DeviceId) -> BTreeSet<FrameId> {
        let mut built: BTreeSet<FrameId> = BTreeSet::new();
        let mut stack: Vec<FrameId> = self
            .members
            .values()
            .filter(|f| f.header().author != *device)
            .map(|f| f.id())
            .collect();
        while let Some(id) = stack.pop() {
            if !built.insert(id) {
                continue;
            }
            if let Some(f) = self.members.get(&id) {
                stack.extend(f.member_body().map(|b| b.deps.clone()).unwrap_or_default());
                if !f.header().prev.is_zero() {
                    stack.push(f.header().prev);
                }
            }
        }
        let mut out: BTreeSet<FrameId> = self
            .members
            .values()
            .filter(|f| f.header().author == *device && !built.contains(&f.id()))
            .filter(|f| {
                matches!(
                    f.member_body().and_then(|b| b.op.as_ref()),
                    Some(v2::MemberOp::Remove { .. })
                )
            })
            .map(|f| f.id())
            .collect();
        loop {
            let more: Vec<FrameId> = self
                .members
                .values()
                .filter(|f| !out.contains(&f.id()))
                .filter(|f| {
                    out.contains(&f.header().prev)
                        || f.member_body()
                            .is_some_and(|b| b.deps.iter().any(|d| out.contains(d)))
                })
                .map(|f| f.id())
                .collect();
            if more.is_empty() {
                return out;
            }
            out.extend(more);
        }
    }

    /// Hands the recovery root from `old` to `new` (`RotateRecovery`+`Rotate`).
    pub fn rotate_recovery(
        &mut self,
        old: &RecoverySecret,
        new: &RecoverySecret,
    ) -> Result<FrameId, Error> {
        let signer = old.signing_key();
        let me = signer.device_id();
        if self.recovery_root() != Some(me) {
            return Err(Error::NotRecoveryRoot);
        }
        let new_id = new.recovery_id();
        let consent =
            v2::sign_rotate_recovery_consent(&new.signing_key(), &self.id, &me, &new.kem_public());
        let key = EpochKey::generate().map_err(frame_err)?;
        let (seq, prev) = self.position(&me, LogKind::Member);
        let recipients = self.recipients(Some(me), Some((new_id, new.kem_public())));
        let parents = self.parents();
        let frame = v2::build_rotate_recovery_frame(
            &signer,
            self.id,
            &self.resolved,
            seq,
            prev,
            Self::member_deps(prev, self.mheads()),
            new_id,
            new.kem_public(),
            consent,
            &key,
            parents,
            &self.keyring,
            &recipients,
        )
        .map_err(frame_err)?;
        self.keyring.insert(EpochId::from_frame_id(frame.id()), key);
        Ok(self.stage(vec![frame])?[0])
    }
}

/// One line about why writes are parked.
pub(crate) fn describe_parking(reasons: &[v2::ParkingReason]) -> String {
    reasons
        .iter()
        .map(|r| match r {
            v2::ParkingReason::ReinstatedRemovedDevice { device } => {
                format!("device {device} was removed and is back: confirm it, or contest it with the recovery kit")
            }
            v2::ParkingReason::MutualRemoval { a, b } => {
                format!("devices {a} and {b} removed each other: settle it with the recovery kit")
            }
            v2::ParkingReason::RecoveryLineageFrozen => {
                "the recovery kit was used twice at once: the vault has no recovery root".to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}
