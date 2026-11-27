//! Deadbolt v2 epoch graph, `commit` verification, clean-tip selection (E2–E6),
//! encrypted back-link traversal, and reader-duty `Rewrap` planning.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::id::{DeviceId, VaultId};

pub use super::builder::{
    back_link_aad, build_add_frame, build_create_frame, build_recovery_repair_rewrap,
    build_remove_frame, build_rewrap_frame, build_rotate_recovery_frame,
    build_standalone_rotate_frame, rewrap_wrap_aad, rotate_wrap_aad,
};
use super::crypto::{
    BACK_LINK_LEN, CryptoError, EpochId, EpochKey, FrameId, KemPublic, KemSecret, WRAP_LEN,
    open_back_link, unwrap_epoch_key, verify_recovery_wrap, wrap_info,
};
use super::frame::{Frame, FrameError, FrameKind, HEADER_LEN, MemberOp};
use super::membership::{ParkingReason, ResolvedMembership, check_parking};

/// Errors returned by v2 epoch operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EpochError {
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("recipients map must not be empty")]
    EmptyRecipients,
    #[error("unknown epoch {0}")]
    UnknownEpoch(EpochId),
    #[error("epoch key does not match epoch commit for {0}")]
    CommitMismatch(EpochId),
    #[error("dep or prev {0} is not placed in the resolved membership DAG")]
    UnplacedDep(FrameId),
    #[error("device {0} was removed or is a recovery root and cannot be added")]
    CannotAdd(DeviceId),
    #[error("rotate wraps must go to exactly the eligible recipients of the frame's view")]
    RecipientsMismatch,
    #[error("{0} is not an eligible wrap recipient in the frame's view")]
    IneligibleRecipient(DeviceId),
    #[error("the recovery lineage is frozen; there is no active recovery root to repair")]
    NoActiveRecovery,
}

/// In-memory cache of unlocked symmetric epoch keys (`EpochId -> K_e`).
#[derive(Debug, Clone, Default)]
pub struct EpochKeyring {
    keys: BTreeMap<EpochId, EpochKey>,
}

impl EpochKeyring {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, epoch: EpochId, key: EpochKey) {
        self.keys.insert(epoch, key);
    }
    pub fn get(&self, epoch: &EpochId) -> Option<&EpochKey> {
        self.keys.get(epoch)
    }
    pub fn contains(&self, epoch: &EpochId) -> bool {
        self.keys.contains_key(epoch)
    }
    pub fn len(&self) -> usize {
        self.keys.len()
    }
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
    pub fn epoch_ids(&self) -> BTreeSet<EpochId> {
        self.keys.keys().copied().collect()
    }
}

/// A single wrap offer for `(epoch, recipient)` carried by a `Rotate` or authorized `Rewrap`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapOffer {
    pub frame_id: FrameId,
    pub author: DeviceId,
    pub seq: u64,
    pub header_bytes: [u8; HEADER_LEN],
    pub suite: u8,
    pub is_rewrap: bool,
    pub wrap: [u8; WRAP_LEN],
}

/// Plaintext metadata for one minted epoch in the membership log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochInfo {
    pub id: EpochId,
    pub author: DeviceId,
    pub seq: u64,
    pub header_bytes: [u8; HEADER_LEN],
    pub authorized: bool,
    pub suite: u8,
    pub parents: Vec<EpochId>,
    pub commit: [u8; 32],
    pub back: Vec<(EpochId, [u8; BACK_LINK_LEN])>,
    /// Rule E3: plaintext union of creation wraps and authorized `Rewrap`s.
    pub recipients: BTreeSet<DeviceId>,
    /// All wrap offers per recipient (multiple offers allow Graft 1 recovery repair-wraps).
    pub wrap_offers: BTreeMap<DeviceId, Vec<WrapOffer>>,
}

/// A wrap or back-link whose decrypted key failed E2 `commit` verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadCommit {
    pub epoch: EpochId,
    pub offer_frame: FrameId,
}

/// Summary returned by [`EpochGraph::unlock`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnlockReport {
    pub newly_unlocked: BTreeSet<EpochId>,
    /// Offers and back-links that opened to a key failing the epoch's E2 `commit`.
    pub bad_commits: Vec<BadCommit>,
    /// Offers to this device that did not open at all (junk bytes, wrong key, bad suite).
    pub bad_offers: Vec<BadCommit>,
    /// Back-links `(child, parent)` that opened to the parent's `commit`-verified key.
    pub verified_back: BTreeSet<(EpochId, EpochId)>,
    /// Back-links that did not open (`epoch` is the parent, `offer_frame` the child's frame).
    pub bad_back_links: Vec<BadCommit>,
}

impl UnlockReport {
    /// Epochs with an offer to this device that failed to open or failed `commit`: pass them
    /// to [`EpochGraph::select_write_epoch`] so a junk wrap mints a fresh `Rotate` instead of
    /// waiting forever for a rewrap.
    pub fn bad_epochs(&self) -> BTreeSet<EpochId> {
        self.bad_commits
            .iter()
            .chain(&self.bad_offers)
            .map(|b| b.epoch)
            .collect()
    }
}

/// Result of rule E4 clean-tip write epoch selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteEpochDecision {
    Use(EpochId),
    MintRotate {
        parents: Vec<EpochId>,
    },
    AwaitingRewrap(EpochId),
    Parked {
        current_epoch: Option<EpochId>,
        reasons: Vec<ParkingReason>,
    },
}

/// Plaintext epoch DAG constructed from `Member` frames and [`ResolvedMembership`].
#[derive(Debug, Clone)]
pub struct EpochGraph {
    vault: VaultId,
    epochs: BTreeMap<EpochId, EpochInfo>,
}

impl EpochGraph {
    pub const fn vault(&self) -> VaultId {
        self.vault
    }
    pub fn get(&self, epoch: &EpochId) -> Option<&EpochInfo> {
        self.epochs.get(epoch)
    }
    pub fn epochs(&self) -> impl Iterator<Item = &EpochInfo> {
        self.epochs.values()
    }

    /// Builds the epoch graph from verified `Member` frames and resolved membership.
    pub fn build<'a>(
        vault: VaultId,
        frames: impl IntoIterator<Item = &'a Frame>,
        resolved: &ResolvedMembership,
    ) -> Self {
        let mut by_id: BTreeMap<FrameId, &'a Frame> = BTreeMap::new();
        for frame in frames {
            let h = frame.header();
            if h.vault == vault && h.kind == FrameKind::Member {
                by_id.insert(frame.id(), frame);
            }
        }
        let mut epochs: BTreeMap<EpochId, EpochInfo> = BTreeMap::new();
        for (&fid, &frame) in &by_id {
            let Some(rot) = frame.member_body().and_then(|b| b.rotate.as_ref()) else {
                continue;
            };
            let h = frame.header();
            let epoch_id = EpochId::from_frame_id(fid);
            let mut recipients = BTreeSet::new();
            let mut wrap_offers: BTreeMap<DeviceId, Vec<WrapOffer>> = BTreeMap::new();
            for &(recipient, wrap) in &rot.wraps {
                recipients.insert(recipient);
                wrap_offers.entry(recipient).or_default().push(WrapOffer {
                    frame_id: fid,
                    author: h.author,
                    seq: h.seq,
                    header_bytes: *frame.header_bytes(),
                    suite: rot.suite,
                    is_rewrap: false,
                    wrap,
                });
            }
            epochs.insert(
                epoch_id,
                EpochInfo {
                    id: epoch_id,
                    author: h.author,
                    seq: h.seq,
                    header_bytes: *frame.header_bytes(),
                    authorized: resolved.authorized_frames.contains(&fid),
                    suite: rot.suite,
                    parents: rot.parents.clone(),
                    commit: rot.commit,
                    back: rot.back.clone(),
                    recipients,
                    wrap_offers,
                },
            );
        }
        for (&fid, &frame) in &by_id {
            if !resolved.authorized_frames.contains(&fid) {
                continue;
            }
            let rewrap = match frame.member_body().and_then(|b| b.op.as_ref()) {
                Some(MemberOp::Rewrap(r)) => Some(r),
                Some(MemberOp::Add { rewrap, .. }) => rewrap.as_ref(),
                _ => None,
            };
            let Some(r) = rewrap else { continue };
            let Some(info) = epochs.get_mut(&r.epoch) else {
                continue;
            };
            let h = frame.header();
            for &(recipient, wrap) in &r.wraps {
                info.recipients.insert(recipient);
                info.wrap_offers
                    .entry(recipient)
                    .or_default()
                    .push(WrapOffer {
                        frame_id: fid,
                        author: h.author,
                        seq: h.seq,
                        header_bytes: *frame.header_bytes(),
                        suite: r.suite,
                        is_rewrap: true,
                        wrap,
                    });
            }
        }
        Self { vault, epochs }
    }

    /// Verifies that `key` matches the recorded E2 `commit` for `epoch`.
    pub fn verify_epoch_key(&self, epoch: EpochId, key: &EpochKey) -> bool {
        self.epochs.get(&epoch).is_some_and(|info| {
            key.verify_commit(&self.vault, &info.author, info.seq, &info.commit)
        })
    }

    /// Rules E2 + E5: unwraps direct offers (verifying `commit` and trying subsequent repair
    /// offers on mismatch), then walks encrypted `back` links recursively.
    pub fn unlock(
        &self,
        my_id: &DeviceId,
        my_kem: &KemSecret,
        keyring: &mut EpochKeyring,
    ) -> UnlockReport {
        let mut report = UnlockReport::default();
        self.unlock_direct(my_id, my_kem, keyring, &mut report);
        self.walk_back_links(keyring, &mut report);
        report
    }

    /// Rule E5 alone: the back-links of the keys `keyring` already holds, for
    /// a holder that has no KEM secret at hand (none of its own frames wraps
    /// a key to it that it didn't make).
    pub fn unlock_back_links(&self, keyring: &mut EpochKeyring) -> UnlockReport {
        let mut report = UnlockReport::default();
        self.walk_back_links(keyring, &mut report);
        report
    }

    fn unlock_direct(
        &self,
        my_id: &DeviceId,
        my_kem: &KemSecret,
        keyring: &mut EpochKeyring,
        report: &mut UnlockReport,
    ) {
        for (&epoch_id, info) in &self.epochs {
            if keyring.contains(&epoch_id) {
                continue;
            }
            let Some(offers) = info.wrap_offers.get(my_id) else {
                continue;
            };
            for offer in offers {
                let w_info = wrap_info(&self.vault, &offer.author, offer.seq, my_id);
                let unwrapped = if offer.is_rewrap {
                    let aad = rewrap_wrap_aad(&offer.header_bytes, &epoch_id);
                    unwrap_epoch_key(offer.suite, my_kem, &w_info, &aad, &offer.wrap)
                } else {
                    let aad = rotate_wrap_aad(&offer.header_bytes);
                    unwrap_epoch_key(offer.suite, my_kem, &w_info, &aad, &offer.wrap)
                };
                let bad = BadCommit {
                    epoch: epoch_id,
                    offer_frame: offer.frame_id,
                };
                match unwrapped {
                    Ok(candidate)
                        if candidate.verify_commit(
                            &self.vault,
                            &info.author,
                            info.seq,
                            &info.commit,
                        ) =>
                    {
                        keyring.insert(epoch_id, candidate);
                        report.newly_unlocked.insert(epoch_id);
                        break;
                    }
                    Ok(_) => report.bad_commits.push(bad),
                    Err(_) => report.bad_offers.push(bad),
                }
            }
        }
    }

    fn walk_back_links(&self, keyring: &mut EpochKeyring, report: &mut UnlockReport) {
        let mut queue: VecDeque<EpochId> = keyring.epoch_ids().into_iter().collect();
        let mut visited: BTreeSet<EpochId> = BTreeSet::new();
        while let Some(epoch_id) = queue.pop_front() {
            if !visited.insert(epoch_id) {
                continue;
            }
            let (Some(info), Some(k_e)) =
                (self.epochs.get(&epoch_id), keyring.get(&epoch_id).cloned())
            else {
                continue;
            };
            // Every back-link is checked whenever the child key is known, even when the
            // parent is already unlocked, so a fake link is never trusted for reachability.
            for (parent_id, sealed) in &info.back {
                let bad = BadCommit {
                    epoch: *parent_id,
                    offer_frame: epoch_id.as_frame_id(),
                };
                match self.open_back(info, &k_e, *parent_id, sealed) {
                    BackLink::Verified(parent_key) => {
                        report.verified_back.insert((epoch_id, *parent_id));
                        if !keyring.contains(parent_id) {
                            keyring.insert(*parent_id, parent_key);
                            report.newly_unlocked.insert(*parent_id);
                            queue.push_back(*parent_id);
                        }
                    }
                    BackLink::BadCommit => report.bad_commits.push(bad),
                    BackLink::Unopenable => report.bad_back_links.push(bad),
                }
            }
        }
    }

    /// Opens one back-link of the epoch `info` (whose key is `k_child`) and checks the parent's
    /// `commit`.
    fn open_back(
        &self,
        info: &EpochInfo,
        k_child: &EpochKey,
        parent: EpochId,
        sealed: &[u8; BACK_LINK_LEN],
    ) -> BackLink {
        let k_back = k_child.back_key(&self.vault, &info.author, info.seq);
        let aad = back_link_aad(&info.header_bytes, &parent);
        let Ok(parent_key) = open_back_link(&k_back, &aad, sealed) else {
            return BackLink::Unopenable;
        };
        match self.epochs.get(&parent) {
            Some(p) if parent_key.verify_commit(&self.vault, &p.author, p.seq, &p.commit) => {
                BackLink::Verified(parent_key)
            }
            Some(_) => BackLink::BadCommit,
            None => BackLink::Unopenable,
        }
    }

    /// Back-links `child -> [parent]` this keyring can open and verify against the parent's
    /// `commit`. Unverifiable links are never trusted for reachability.
    fn verified_back_links(&self, keyring: &EpochKeyring) -> BTreeMap<EpochId, Vec<EpochId>> {
        let mut out: BTreeMap<EpochId, Vec<EpochId>> = BTreeMap::new();
        for (&child, info) in &self.epochs {
            let Some(k_child) = keyring.get(&child) else {
                continue;
            };
            for (parent, sealed) in &info.back {
                if matches!(
                    self.open_back(info, k_child, *parent, sealed),
                    BackLink::Verified(_)
                ) {
                    out.entry(child).or_default().push(*parent);
                }
            }
        }
        out
    }

    /// True iff an offer matches the deterministic wrap of the known key to this recipient,
    /// checkable by any key holder without the recipient's secret.
    fn recipient_wrap_ok(
        &self,
        info: &EpochInfo,
        root: &DeviceId,
        kem: &KemPublic,
        k_e: &EpochKey,
    ) -> bool {
        info.wrap_offers.get(root).is_some_and(|offers| {
            offers.iter().any(|offer| {
                let w_info = wrap_info(&self.vault, &offer.author, offer.seq, root);
                let ok = |aad: &[u8]| verify_recovery_wrap(k_e, kem, &w_info, aad, &offer.wrap);
                offer.suite == super::crypto::SUITE_X25519_WRAP
                    && if offer.is_rewrap {
                        ok(&rewrap_wrap_aad(&offer.header_bytes, &info.id))
                    } else {
                        ok(&rotate_wrap_aad(&offer.header_bytes))
                    }
            })
        })
    }

    /// All authorized epochs that no other authorized epoch names as a parent.
    pub fn authorized_tips(&self) -> Vec<EpochId> {
        let mut superseded: BTreeSet<EpochId> = BTreeSet::new();
        for info in self.epochs.values() {
            if info.authorized {
                superseded.extend(&info.parents);
            }
        }
        self.epochs
            .values()
            .filter(|info| info.authorized && !superseded.contains(&info.id))
            .map(|info| info.id)
            .collect()
    }

    /// Rule E4: authorized tips whose recipient set is a subset of `members_now ∪ {recovery_now}`.
    pub fn clean_tips(&self, resolved: &ResolvedMembership) -> Vec<EpochId> {
        let allowed = resolved.eligible_recipients();
        self.authorized_tips()
            .into_iter()
            .filter(|id| {
                self.epochs
                    .get(id)
                    .is_some_and(|i| i.recipients.is_subset(&allowed))
            })
            .collect()
    }

    /// Transitive parent ancestors of `epoch` in the epoch DAG.
    pub fn ancestors_of(&self, epoch: EpochId) -> BTreeSet<EpochId> {
        let mut out = BTreeSet::new();
        let mut stack = vec![epoch];
        while let Some(cur) = stack.pop() {
            if let Some(info) = self.epochs.get(&cur) {
                for &p in &info.parents {
                    if out.insert(p) {
                        stack.push(p);
                    }
                }
            }
        }
        out
    }

    /// Every epoch in `set` that is not a strict ancestor of another epoch in `set`.
    pub fn maximal_epochs_in(&self, set: &BTreeSet<EpochId>) -> Vec<EpochId> {
        let mut covered: BTreeSet<EpochId> = BTreeSet::new();
        for &e in set {
            for anc in self.ancestors_of(e) {
                if anc != e {
                    covered.insert(anc);
                }
            }
        }
        set.iter()
            .copied()
            .filter(|e| !covered.contains(e))
            .collect()
    }

    /// Rule E4 write-epoch selection. `bad_commit_epochs` is [`UnlockReport::bad_epochs`]: a
    /// clean tip whose offer to this device was junk or failed `commit` is replaced by a fresh
    /// `Rotate` rather than awaited forever.
    pub fn select_write_epoch(
        &self,
        resolved: &ResolvedMembership,
        keyring: &EpochKeyring,
        bad_commit_epochs: &BTreeSet<EpochId>,
    ) -> WriteEpochDecision {
        let clean = self.clean_tips(resolved);
        if let Some(&target) = clean.first() {
            if keyring.contains(&target) {
                return WriteEpochDecision::Use(target);
            }
            if !bad_commit_epochs.contains(&target) {
                return WriteEpochDecision::AwaitingRewrap(target);
            }
            let mut parent_pool = self.authorized_held(keyring);
            parent_pool.insert(target);
            return WriteEpochDecision::MintRotate {
                parents: self.maximal_epochs_in(&parent_pool),
            };
        }
        let mut parent_pool = self.authorized_held(keyring);
        for &b in bad_commit_epochs {
            if self.epochs.get(&b).is_some_and(|e| e.authorized) {
                parent_pool.insert(b);
            }
        }
        WriteEpochDecision::MintRotate {
            parents: self.maximal_epochs_in(&parent_pool),
        }
    }

    /// The authorized epochs `keyring` holds: what a new `Rotate` may name as
    /// parents and seal back-links to. A voided or losing epoch's key never
    /// travels forward.
    fn authorized_held(&self, keyring: &EpochKeyring) -> BTreeSet<EpochId> {
        keyring
            .epoch_ids()
            .into_iter()
            .filter(|e| self.epochs.get(e).is_some_and(|i| i.authorized))
            .collect()
    }

    /// Rule E4 write-epoch selection guarded by the parking rule.
    pub fn select_write_epoch_with_parking(
        &self,
        resolved: &ResolvedMembership,
        keyring: &EpochKeyring,
        bad_commit_epochs: &BTreeSet<EpochId>,
        previously_removed: &BTreeSet<DeviceId>,
        current_write_epoch: Option<EpochId>,
    ) -> WriteEpochDecision {
        let parking = check_parking(previously_removed, resolved);
        if parking.should_park() {
            return WriteEpochDecision::Parked {
                current_epoch: current_write_epoch,
                reasons: parking.reasons,
            };
        }
        self.select_write_epoch(resolved, keyring, bad_commit_epochs)
    }

    /// Epochs `recipient` can unlock, as far as `keyring` can check: direct wraps plus E5
    /// back-links this keyring verified. Every direct offer must match the deterministic
    /// wrap of a held key, so naming a recipient alone never proves delivery.
    pub fn reachable_by(
        &self,
        recipient: &DeviceId,
        keyring: &EpochKeyring,
        resolved: &ResolvedMembership,
    ) -> BTreeSet<EpochId> {
        let back = self.verified_back_links(keyring);
        let kem = resolved.kem_of(recipient);
        let direct = self.epochs.values().filter(|info| {
            kem.as_ref().is_some_and(|kem| {
                keyring
                    .get(&info.id)
                    .is_some_and(|key| self.recipient_wrap_ok(info, recipient, kem, key))
            })
        });
        back_closure(direct.map(|info| info.id), &back)
    }

    /// Rule E6 (Reader duty): minimal `(EpochId, Vec<DeviceId>)` plan for epochs missing a
    /// recipient reachability path among `members_now ∪ {recovery_now}`.
    pub fn needed_rewraps(
        &self,
        keyring: &EpochKeyring,
        resolved: &ResolvedMembership,
        epochs_with_counted_data: &BTreeSet<EpochId>,
    ) -> Vec<(EpochId, Vec<DeviceId>)> {
        let eligible = resolved.eligible_recipients();
        let mut target_epochs: BTreeSet<EpochId> = epochs_with_counted_data.clone();
        target_epochs.extend(self.clean_tips(resolved));
        // Only authorized epochs: the epoch of an unplaced or unauthorized `Remove` must never be
        // rewrapped, least of all to the device that `Remove` targets.
        target_epochs.retain(|e| {
            keyring.contains(e) && self.epochs.get(e).is_some_and(|info| info.authorized)
        });
        let back = self.verified_back_links(keyring);

        let mut candidates: Vec<(usize, EpochId)> = target_epochs
            .iter()
            .map(|&e| (back_closure([e], &back).len(), e))
            .collect();
        candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

        let mut per_recipient_reached: BTreeMap<DeviceId, BTreeSet<EpochId>> = eligible
            .iter()
            .map(|&r| (r, self.reachable_by(&r, keyring, resolved)))
            .collect();

        let mut plan: BTreeMap<EpochId, Vec<DeviceId>> = BTreeMap::new();
        for (_, epoch) in candidates {
            let back_cover = back_closure([epoch], &back);
            let mut missing = Vec::new();
            for (&recipient, reached) in &mut per_recipient_reached {
                if !reached.contains(&epoch) {
                    missing.push(recipient);
                    reached.extend(&back_cover);
                }
            }
            if !missing.is_empty() {
                missing.sort();
                plan.insert(epoch, missing);
            }
        }
        plan.into_iter().collect()
    }
}

enum BackLink {
    Verified(EpochKey),
    BadCommit,
    Unopenable,
}

/// `start` plus every epoch reachable from it through `back` links.
fn back_closure(
    start: impl IntoIterator<Item = EpochId>,
    back: &BTreeMap<EpochId, Vec<EpochId>>,
) -> BTreeSet<EpochId> {
    let mut reached = BTreeSet::new();
    let mut queue = VecDeque::new();
    for id in start {
        if reached.insert(id) {
            queue.push_back(id);
        }
    }
    while let Some(cur) = queue.pop_front() {
        for &parent in back.get(&cur).into_iter().flatten() {
            if reached.insert(parent) {
                queue.push_back(parent);
            }
        }
    }
    reached
}
