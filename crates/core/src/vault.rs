//! A vault as one device holds it: every signed v2 [`Frame`] it has, the
//! epoch keys it can reach, and the fold of the data frames that count.
//!
//! Membership is the plaintext member log, resolved with no key
//! ([`v2::resolve`]). Data frames are sealed under epoch keys; this device
//! opens the ones whose epoch it can reach through a wrap to its KEM key or a
//! back-link, and folds every opened frame the membership counts. A frame it
//! can't open yet waits; a later wrap or back-link opens it.
//!
//! Writes happen in a transaction ([`Vault::transact`]): each one signs its
//! frames as this device, applies them, and hands them to a commit step that
//! makes them durable before anyone sees them. If the change or the commit
//! fails, the frames are taken back out.

mod checkpoint;
mod duty;
mod remove;
mod sync;
mod view;
mod write;

use std::collections::{BTreeMap, BTreeSet};

use crate::error::Error;
use crate::id::{DeviceId, ItemId, VaultId};
use crate::v2::{
    self, DataFrame, DeviceKeys, EpochGraph, EpochId, EpochKeyring, FoldContext, FoldedState,
    Frame, FrameId, FrameKind, FraudProof, KemSecret, LogKind, MemberOp, NetPublic, Pack,
    ParkingReason, ResolvedMembership, check_parking,
};

pub use checkpoint::{Checkpointed, PackSite};
pub use sync::Heads;
pub use view::{Deleted, Item};
#[cfg(test)]
pub(crate) use write::MAX_REMOVED_UNAUTHORIZED;
pub use write::{Author, MAX_FRAME_LEN, VaultWrite, parking_message};

/// The most frames one vault accepts: a bound on what a member can make
/// every device hold.
pub const MAX_FRAMES: usize = 1 << 20;

/// What a frame changed, for telling watchers.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Touch {
    pub items: bool,
    pub name: bool,
    pub devices: bool,
}

/// A vault on this device. See the module docs.
#[derive(Clone)]
pub struct Vault {
    id: VaultId,
    me: DeviceId,
    members: BTreeMap<FrameId, Frame>,
    data: BTreeMap<FrameId, Frame>,
    opened: BTreeMap<FrameId, DataFrame>,
    /// Header-only stand-ins for frames sealed under an epoch the membership
    /// placed but doesn't authorize, which this device can't open: they count
    /// for no one, and folding them keeps their author's later frames chained.
    unreadable: BTreeMap<FrameId, DataFrame>,
    proofs: Vec<FraudProof>,
    keyring: EpochKeyring,
    bad_epochs: BTreeSet<EpochId>,
    resolved: ResolvedMembership,
    graph: Option<EpochGraph>,
    adders: BTreeMap<DeviceId, DeviceId>,
    state: FoldedState,
    /// Devices this device has seen removed: the parking rule's memory.
    previously_removed: BTreeSet<DeviceId>,
    parked: Vec<ParkingReason>,
    /// The checkpoint pack the fold starts from, when one is installed:
    /// frames at or below its frontier may be gone (a recovered vault).
    base: Option<Pack>,
    /// The checkpoint frame `base` belongs to.
    base_checkpoint: Option<FrameId>,
    /// Checkpoints by others this session has judged (`judge_checkpoints`).
    judged: BTreeSet<FrameId>,
    /// Frames the open transaction added.
    staged: Vec<FrameId>,
}

impl Vault {
    fn empty(id: VaultId, me: DeviceId) -> Self {
        Self {
            id,
            me,
            members: BTreeMap::new(),
            data: BTreeMap::new(),
            opened: BTreeMap::new(),
            unreadable: BTreeMap::new(),
            proofs: Vec::new(),
            keyring: EpochKeyring::new(),
            bad_epochs: BTreeSet::new(),
            resolved: ResolvedMembership::default(),
            graph: None,
            adders: BTreeMap::new(),
            state: FoldedState::default(),
            previously_removed: BTreeSet::new(),
            parked: Vec::new(),
            base: None,
            base_checkpoint: None,
            judged: BTreeSet::new(),
            staged: Vec::new(),
        }
    }

    /// Rebuilds a vault from its frames, as the device `me`.
    pub fn open(me: &DeviceKeys, frames: impl IntoIterator<Item = Frame>) -> Result<Self, Error> {
        Self::open_as(me.device_id(), me.kem_key(), frames)
    }

    /// Rebuilds a vault as any principal holding `kem`: a device, or the
    /// recovery root during recovery.
    pub fn open_as(
        me: DeviceId,
        kem: &KemSecret,
        frames: impl IntoIterator<Item = Frame>,
    ) -> Result<Self, Error> {
        let frames: Vec<Frame> = frames.into_iter().collect();
        let genesis = frames
            .iter()
            .find(|f| {
                f.header().kind == FrameKind::Member
                    && f.header().seq == 0
                    && matches!(
                        f.member_body().and_then(|b| b.op.as_ref()),
                        Some(MemberOp::Create { .. })
                    )
            })
            .ok_or(Error::InvalidGenesis)?;
        let mut vault = Self::empty(genesis.header().vault, me);
        vault.insert(frames)?;
        vault.refresh(Some(kem));
        if vault.resolved.recovery_lineage.is_empty() {
            return Err(Error::InvalidGenesis);
        }
        Ok(vault)
    }

    /// Adds frames without refreshing. Returns the ids that were new.
    fn insert(&mut self, frames: impl IntoIterator<Item = Frame>) -> Result<Vec<FrameId>, Error> {
        let mut new = Vec::new();
        for frame in frames {
            let h = frame.header();
            if h.vault != self.id {
                return Err(Error::WrongVault {
                    expected: self.id,
                    found: h.vault,
                });
            }
            let id = frame.id();
            let log = match h.kind.log_kind() {
                LogKind::Member => &mut self.members,
                LogKind::Data => &mut self.data,
            };
            if log.contains_key(&id) {
                continue;
            }
            if self.members.len() + self.data.len() >= MAX_FRAMES {
                return Err(Error::TooManyFrames);
            }
            let twin = match h.kind.log_kind() {
                LogKind::Member => &self.members,
                LogKind::Data => &self.data,
            }
            .values()
            .find(|f| f.header().author == h.author && f.header().seq == h.seq);
            if let Some(twin) = twin
                && let Ok(proof) = FraudProof::from_frames(twin, &frame)
            {
                self.proofs.push(proof);
            }
            match h.kind.log_kind() {
                LogKind::Member => self.members.insert(id, frame),
                LogKind::Data => self.data.insert(id, frame),
            };
            new.push(id);
        }
        Ok(new)
    }

    /// Takes frames back out (a failed transaction), restores the keys held
    /// before it, and refreshes.
    fn remove_frames(&mut self, ids: &[FrameId], keyring: EpochKeyring) {
        for id in ids {
            self.members.remove(id);
            self.data.remove(id);
            self.opened.remove(id);
        }
        self.keyring = keyring;
        self.refresh(None);
    }

    /// Re-resolves membership, unlocks every epoch this device can reach,
    /// opens what it can and refolds. Without `kem` (this device's own
    /// writes, which wrap nothing new to it) only back-links are walked; the
    /// KEM secret is never kept between calls.
    fn refresh(&mut self, kem: Option<&KemSecret>) {
        let frames = self.members.values().chain(self.data.values());
        self.resolved = v2::resolve(&self.id, frames, &self.proofs);
        let graph = EpochGraph::build(self.id, self.members.values(), &self.resolved);
        match kem {
            Some(kem) => {
                let report = graph.unlock(&self.me, kem, &mut self.keyring);
                self.bad_epochs = report.bad_epochs();
            }
            None => {
                let report = graph.unlock_back_links(&mut self.keyring);
                self.bad_epochs.extend(report.bad_epochs());
            }
        }
        let unopened: Vec<_> = self
            .data
            .iter()
            .filter(|(id, _)| !self.opened.contains_key(id))
            .filter_map(|(id, f)| Some((*id, f, self.keyring.get(&f.header().epoch)?)))
            .collect();
        let opened = crate::par::map(&unopened, |(id, f, key)| {
            DataFrame::open(f, key).ok().map(|opened| (*id, opened))
        });
        self.opened.extend(opened.into_iter().flatten());
        self.unreadable = self
            .data
            .iter()
            .filter(|(id, _)| !self.opened.contains_key(id))
            .filter(|(_, f)| self.void_epoch(&f.header().epoch))
            .filter_map(|(id, f)| Some((*id, DataFrame::unreadable(f).ok()?)))
            .collect();
        self.graph = Some(graph);
        self.adders = v2::adders_from_frames(&self.resolved, self.members.values());
        let ctx = FoldContext {
            membership: &self.resolved,
            adders: &self.adders,
        };
        self.state = match &self.base {
            // A base the membership no longer counts falls back to genesis.
            Some(base) => v2::fold_from_checkpoint(&ctx, base, self.fold_inputs())
                .unwrap_or_else(|_| v2::fold_from_scratch(&ctx, self.fold_inputs())),
            None => v2::fold_from_scratch(&ctx, self.fold_inputs()),
        };
        // A base whose checkpoint was disputed (the dispute may be in the
        // fold it fed) is never folded from again.
        if self.drop_untrusted_base() {
            let ctx = FoldContext {
                membership: &self.resolved,
                adders: &self.adders,
            };
            self.state = v2::fold_from_scratch(&ctx, self.fold_inputs());
        }
        self.note_removed();
    }

    /// True iff `epoch`'s `Rotate` is placed in the membership DAG but not
    /// authorized: a losing or voided epoch, which never will count. One
    /// merely not placed yet may still, so its frames wait instead.
    fn void_epoch(&self, epoch: &EpochId) -> bool {
        self.resolved.dag_frames.contains(&epoch.as_frame_id())
            && !self.resolved.is_authorized_epoch(epoch)
    }

    /// What the fold sees: every opened frame, and a stand-in for each
    /// unreadable one under a void epoch.
    fn fold_inputs(&self) -> impl Iterator<Item = &DataFrame> {
        self.opened.values().chain(self.unreadable.values())
    }

    /// Parking-rule bookkeeping after a refresh. This device's own removal
    /// is never a reason to park: being reinstated (by the recovery root) is
    /// what it wants.
    fn note_removed(&mut self) {
        self.previously_removed.remove(&self.me);
        self.parked = check_parking(&self.previously_removed, &self.resolved).reasons;
        let me = self.me;
        self.previously_removed
            .extend(self.resolved.removed.keys().copied().filter(|d| *d != me));
    }

    fn graph(&self) -> &EpochGraph {
        #[expect(clippy::expect_used, reason = "every constructor refreshes")]
        self.graph.as_ref().expect("refreshed")
    }

    pub fn id(&self) -> VaultId {
        self.id
    }

    /// Who this vault was opened as.
    pub fn me(&self) -> DeviceId {
        self.me
    }

    /// The vault's name: its latest `VaultMeta`, or its id while none
    /// has been read.
    pub fn name(&self) -> &str {
        match self.state.vault_name() {
            Some(name) if crate::ops::valid_name(name) => name,
            _ => "vault",
        }
    }

    pub fn is_member(&self, device: &DeviceId) -> bool {
        self.resolved.is_active_device(device)
    }

    pub fn was_removed(&self, device: &DeviceId) -> bool {
        self.resolved.removed.contains_key(device)
    }

    /// Current member devices, in id order. The recovery root is not one.
    pub fn members(&self) -> impl Iterator<Item = DeviceId> + '_ {
        self.resolved.devices.iter().copied()
    }

    /// The active recovery root, if the lineage isn't frozen.
    pub fn recovery_root(&self) -> Option<DeviceId> {
        self.resolved.active_recovery
    }

    pub fn membership(&self) -> &ResolvedMembership {
        &self.resolved
    }

    /// Why this device won't adopt the current membership's epochs, if it won't.
    pub fn parked(&self) -> &[ParkingReason] {
        &self.parked
    }

    /// Devices this device has seen removed.
    pub fn previously_removed(&self) -> &BTreeSet<DeviceId> {
        &self.previously_removed
    }

    /// Restores the parking rule's memory, saved from an earlier session.
    pub fn remember_removed(&mut self, devices: impl IntoIterator<Item = DeviceId>) {
        self.previously_removed.extend(devices);
        self.note_removed();
    }

    /// Accepts that `device` is back: the human confirmed a reinstatement.
    pub fn confirm_reinstated(&mut self, device: &DeviceId) {
        self.previously_removed.remove(device);
        self.parked = check_parking(&self.previously_removed, &self.resolved).reasons;
    }

    /// A device's label: its own word once it has written a card, its adder's
    /// before. Transport keys come from [`Vault::device_net`].
    pub fn device_label(&self, device: &DeviceId) -> Option<&str> {
        let card = &self.state.device_cards.get(device)?.winner()?.value;
        Some(card.label.as_str())
    }

    /// The transport key `device` signed into its `Add`, for a member or a
    /// removed device: never anyone else's word, so no card can claim it.
    pub fn device_net(&self, device: &DeviceId) -> Option<NetPublic> {
        self.resolved.nets.get(device).copied()
    }

    /// The member whose transport key is `net`.
    pub fn device_for_net(&self, net: &[u8; 32]) -> Option<DeviceId> {
        self.device_with_net(net).filter(|d| self.is_member(d))
    }

    /// The device, member or removed, whose transport key is `net`. Only
    /// the key's holder can bind it (its `Add` carries the key's signature),
    /// so two devices naming one key are one holder: a member wins.
    pub fn device_with_net(&self, net: &[u8; 32]) -> Option<DeviceId> {
        let mut found = self
            .resolved
            .nets
            .iter()
            .filter(|(_, pk)| pk.as_bytes() == net)
            .map(|(d, _)| *d);
        let first = found.next()?;
        Some(
            std::iter::once(first)
                .chain(found)
                .find(|d| self.is_member(d))
                .unwrap_or(first),
        )
    }

    /// Devices this vault's membership removed.
    pub fn removed_devices(&self) -> impl Iterator<Item = DeviceId> + '_ {
        self.resolved.removed.keys().copied()
    }

    /// Every frame, membership first.
    pub fn frames(&self) -> impl Iterator<Item = &Frame> {
        self.members.values().chain(self.data.values())
    }

    pub fn frame(&self, id: &FrameId) -> Option<&Frame> {
        self.members.get(id).or_else(|| self.data.get(id))
    }

    pub fn proofs(&self) -> &[FraudProof] {
        &self.proofs
    }

    /// Data frames held but not opened: their epoch isn't reachable yet.
    pub fn sealed_count(&self) -> usize {
        self.data.len() - self.opened.len()
    }

    /// What `frame` changed.
    pub fn touched(&self, frame: &Frame) -> Touch {
        match frame.header().kind {
            FrameKind::Member => Touch {
                items: matches!(
                    frame.member_body().and_then(|b| b.op.as_ref()),
                    Some(MemberOp::Remove { .. })
                ),
                name: false,
                devices: true,
            },
            FrameKind::Checkpoint => Touch::default(),
            FrameKind::Data => {
                let Some(opened) = self.opened.get(&frame.id()) else {
                    return Touch::default();
                };
                let v2::DataBody::Data(p) = &opened.body else {
                    return Touch::default();
                };
                let mut touch = Touch::default();
                for op in &p.ops {
                    match op {
                        v2::DataOp::VaultMeta { .. } => touch.name = true,
                        v2::DataOp::DeviceCard { .. } => touch.devices = true,
                        v2::DataOp::Dispute { .. } => {}
                        _ => touch.items = true,
                    }
                }
                touch
            }
        }
    }

    /// An item, including deleted ones.
    pub fn item(&self, id: &ItemId) -> Option<Item> {
        let state = self.state.items.get(id).filter(|s| view::known(s))?;
        Some(view::item(*id, state))
    }

    /// Closest live item ids on either side of `id`, for unique display prefixes.
    pub fn live_neighbors(&self, id: ItemId) -> [Option<ItemId>; 2] {
        use std::ops::Bound::{Excluded, Unbounded};
        let live = |(_, s): &(&ItemId, &v2::ItemState)| view::known(s) && !s.deleted();
        [
            self.state
                .items
                .range(..id)
                .rev()
                .find(live)
                .map(|(id, _)| *id),
            self.state
                .items
                .range((Excluded(id), Unbounded))
                .find(live)
                .map(|(id, _)| *id),
        ]
    }

    /// Live items in id order, materialized one at a time.
    pub fn iter_items(&self) -> impl Iterator<Item = Item> + '_ {
        self.state
            .items
            .iter()
            .filter(|(_, s)| view::known(s) && !s.deleted())
            .map(|(id, s)| view::item(*id, s))
    }

    /// Live logins for a page's registrable domain or a site sharing its
    /// credentials ([`crate::site::shared`]), in item-id order. Checks
    /// the URL fields before materializing anything else.
    pub fn site_logins<'a>(
        &'a self,
        site: &'a crate::site::Site,
    ) -> impl Iterator<Item = Item> + 'a {
        self.state
            .items
            .iter()
            .filter(|(_, s)| {
                view::known(s)
                    && !s.deleted()
                    && s.kind.winner().is_some_and(|w| w.value == "login")
                    && site.matches(crate::autofill::field_urls(
                        view::fields(s)
                            .map(|(_, v)| view::field(v))
                            .collect::<Vec<_>>()
                            .iter(),
                    ))
            })
            .map(|(id, s)| view::item(*id, s))
    }

    /// All items that are not deleted, ordered by id.
    pub fn items(&self) -> Vec<Item> {
        self.iter_items().collect()
    }

    /// Deleted items, newest first, then by id.
    pub fn deleted(&self) -> Vec<Deleted> {
        let mut deleted: Vec<Deleted> = self
            .state
            .items
            .iter()
            .filter(|(_, s)| view::known(s) && s.deleted())
            .map(|(id, s)| Deleted {
                item: view::item(*id, s),
                at: view::deleted_at(s),
            })
            .collect();
        deleted.sort_by(|a, b| b.at.cmp(&a.at).then(a.item.id.cmp(&b.item.id)));
        deleted
    }

    /// Runs `change` against this vault, then `commit`s the frames it made.
    /// On an error from either, the vault is as it was.
    pub fn transact<T, E: From<Error>>(
        &mut self,
        change: impl FnOnce(&mut VaultWrite<'_>) -> Result<T, E>,
        commit: impl FnOnce(&Vault, &[&Frame]) -> Result<(), E>,
    ) -> Result<T, E> {
        self.staged.clear();
        let keyring = self.keyring.clone();
        let result = change(&mut VaultWrite::new(self));
        let staged = std::mem::take(&mut self.staged);
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                if !staged.is_empty() {
                    self.remove_frames(&staged, keyring);
                }
                return Err(error);
            }
        };
        if staged.is_empty() {
            return Ok(value);
        }
        let frames: Vec<&Frame> = staged.iter().filter_map(|id| self.frame(id)).collect();
        match commit(self, &frames) {
            Ok(()) => Ok(value),
            Err(error) => {
                self.remove_frames(&staged, keyring);
                Err(error)
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::v2::RecoverySecret;

    /// 2023-11-14, a fixed now for tests.
    pub const NOW_MS: u64 = 1_700_000_000_000;

    pub fn author(seed: u8) -> Author {
        Author::new(DeviceKeys::from_seed(&[seed; 32]), NOW_MS)
    }

    pub fn recovery() -> RecoverySecret {
        RecoverySecret::from_bytes([0xee; 32])
    }

    pub fn vault(author: &Author, name: &str) -> (Vault, Vec<Frame>) {
        Vault::create(&recovery(), author, name, "test").unwrap()
    }

    /// Writes outside a host transaction, for tests.
    impl Vault {
        /// The epoch graph, membership and keys, for checking epoch rules.
        pub(crate) fn epoch_parts(&self) -> (&EpochGraph, &ResolvedMembership, &EpochKeyring) {
            (self.graph(), &self.resolved, &self.keyring)
        }

        pub(crate) fn create_item(
            &mut self,
            a: &Author,
            kind: &str,
            name: Option<String>,
            fields: impl IntoIterator<Item = (String, crate::Field)>,
        ) -> Result<(ItemId, FrameId), Error> {
            self.transact(|v| v.create_item(a, kind, name, fields), |_, _| Ok(()))
        }

        pub(crate) fn create_item_with(
            &mut self,
            a: &Author,
            kind: &str,
            name: Option<String>,
            fields: impl IntoIterator<Item = (String, crate::Field)>,
            favorite: bool,
            tags: impl IntoIterator<Item = String>,
        ) -> Result<(ItemId, FrameId), Error> {
            self.transact(
                |v| v.create_item_with(a, kind, name, fields, favorite, tags),
                |_, _| Ok(()),
            )
        }

        pub(crate) fn create_items(
            &mut self,
            a: &Author,
            ops: impl IntoIterator<Item = crate::DataOp>,
        ) -> Result<(Vec<ItemId>, Vec<FrameId>), Error> {
            self.transact(|v| v.create_items(a, ops), |_, _| Ok(()))
        }

        pub(crate) fn write(
            &mut self,
            a: &Author,
            ops: Vec<crate::DataOp>,
        ) -> Result<FrameId, Error> {
            self.transact(|v| v.write(a, ops), |_, _| Ok(()))
        }
    }
}
