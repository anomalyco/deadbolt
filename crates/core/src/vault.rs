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

mod sync;
mod view;
mod write;

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::error::Error;
use crate::id::{DeviceId, ItemId, VaultId};
use crate::v2::{
    self, DataFrame, DeviceKeys, EpochGraph, EpochId, EpochKeyring, FoldContext, FoldedState,
    Frame, FrameId, FrameKind, FraudProof, KemSecret, LogKind, MemberOp, NetPublic, ParkingReason,
    ResolvedMembership, check_parking,
};

pub use sync::Heads;
pub use view::{Deleted, Item};
pub use write::{Author, MAX_FRAME_LEN, VaultWrite};

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
pub struct Vault {
    id: VaultId,
    me: DeviceId,
    kem: Zeroizing<[u8; 32]>,
    members: BTreeMap<FrameId, Frame>,
    data: BTreeMap<FrameId, Frame>,
    opened: BTreeMap<FrameId, DataFrame>,
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
    /// Frames the open transaction added.
    staged: Vec<FrameId>,
}

impl Vault {
    fn empty(id: VaultId, me: DeviceId, kem: &KemSecret) -> Self {
        Self {
            id,
            me,
            kem: kem.to_bytes(),
            members: BTreeMap::new(),
            data: BTreeMap::new(),
            opened: BTreeMap::new(),
            proofs: Vec::new(),
            keyring: EpochKeyring::new(),
            bad_epochs: BTreeSet::new(),
            resolved: ResolvedMembership::default(),
            graph: None,
            adders: BTreeMap::new(),
            state: FoldedState::default(),
            previously_removed: BTreeSet::new(),
            parked: Vec::new(),
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
        let mut vault = Self::empty(genesis.header().vault, me, kem);
        vault.insert(frames)?;
        vault.refresh();
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

    /// Takes frames back out (a failed transaction) and refreshes.
    fn remove_frames(&mut self, ids: &[FrameId]) {
        for id in ids {
            self.members.remove(id);
            self.data.remove(id);
            self.opened.remove(id);
        }
        self.keyring = EpochKeyring::new();
        self.refresh();
    }

    /// Re-resolves membership, unlocks every epoch this device can reach,
    /// opens what it can and refolds.
    fn refresh(&mut self) {
        let frames = self.members.values().chain(self.data.values());
        self.resolved = v2::resolve(&self.id, frames, &self.proofs);
        let graph = EpochGraph::build(self.id, self.members.values(), &self.resolved);
        let kem = KemSecret::from_bytes(&self.kem);
        let report = graph.unlock(&self.me, &kem, &mut self.keyring);
        self.bad_epochs = report.bad_epochs();
        for (id, frame) in &self.data {
            if self.opened.contains_key(id) {
                continue;
            }
            if let Some(key) = self.keyring.get(&frame.header().epoch)
                && let Ok(opened) = DataFrame::open(frame, key)
            {
                self.opened.insert(*id, opened);
            }
        }
        self.graph = Some(graph);
        self.adders = v2::adders_from_frames(&self.resolved, self.members.values());
        let ctx = FoldContext {
            membership: &self.resolved,
            adders: &self.adders,
        };
        self.state = v2::fold_from_scratch(&ctx, self.opened.values());
        self.note_removed();
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

    /// A device's transport key and label, from its `DeviceCard`.
    pub fn device_card(&self, device: &DeviceId) -> Option<(NetPublic, &str)> {
        let card = &self.state.device_cards.get(device)?.winner()?.value;
        Some((card.net_pk, card.label.as_str()))
    }

    /// The member whose `DeviceCard` names `net` as its transport key.
    pub fn device_for_net(&self, net: &[u8; 32]) -> Option<DeviceId> {
        self.members().find(|d| {
            self.device_card(d)
                .is_some_and(|(pk, _)| pk.as_bytes() == net)
        })
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
            self.state.items.range(..id).rev().find(live).map(|(id, _)| *id),
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

    /// Live logins for a page's registrable domain, in item-id order. Checks
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
                        view::fields(s).map(|(_, v)| view::field(v)).collect::<Vec<_>>().iter(),
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
        let result = change(&mut VaultWrite::new(self));
        let staged = std::mem::take(&mut self.staged);
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                if !staged.is_empty() {
                    self.remove_frames(&staged);
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
                self.remove_frames(&staged);
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
        #[expect(clippy::unwrap_used, reason = "test")]
        Vault::create(&recovery(), author, name, "test").unwrap()
    }

    /// Writes outside a host transaction, for tests.
    impl Vault {
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

        pub(crate) fn write(&mut self, a: &Author, ops: Vec<crate::DataOp>) -> Result<FrameId, Error> {
            self.transact(|v| v.write(a, ops), |_, _| Ok(()))
        }
    }
}
