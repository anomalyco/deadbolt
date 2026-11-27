//! Removing devices (by a member, by the recovery root, or a stolen one)
//! and handing the recovery root on.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::Error;
use crate::id::{DeviceId, DeviceSecret};
use crate::v2::{
    self, EpochGraph, EpochId, EpochKey, Frame, FrameId, KemPublic, LogKind, RecoverySecret,
    ResolvedMembership,
};

use super::write::{Author, VaultWrite, frame_err, member_heads};

impl VaultWrite<'_> {
    /// Removes `device` with an atomic `Rotate`. Its data frames this
    /// vault holds keep counting.
    pub fn remove(&mut self, author: &Author, device: DeviceId) -> Result<FrameId, Error> {
        if !self.is_member(&author.id()) {
            return Err(Error::NotMember);
        }
        self.remove_signed(author.keys().sign_key(), device, None)
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
        // Frames behind the base checkpoint may be gone (a store collected
        // them): they count as held, or every checkpoint covering them would
        // be invalidated after the frames themselves are lost
        // (`v2::removal_last_seen`).
        let collected = self
            .base
            .as_ref()
            .and_then(|b| b.meta.frontier.get(&device))
            .map_or(0, |(seq, _)| seq.saturating_add(1));
        let mut counted = 0u64;
        loop {
            let Some(f) = self
                .data
                .values()
                .find(|f| f.header().author == device && f.header().seq == counted)
            else {
                if counted < collected {
                    counted = collected;
                    continue;
                }
                break;
            };
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
        // A stolen device's removal is judged as of before the theft: its
        // unbuilt-on membership frames (devices it added, devices it
        // removed) are left out of the view the removal is built in, so the
        // new key skips whoever it added and reaches whoever it removed.
        let view = stolen.map(|_| self.pre_theft_view(&device));
        let (resolved, deps, parents) = match &view {
            Some((resolved, graph, skip)) => (
                resolved,
                member_heads(&self.members, resolved, skip),
                self.held_tips(graph),
            ),
            None => (&self.resolved, self.mheads(), self.parents()),
        };
        let mut recipients: BTreeMap<DeviceId, KemPublic> = resolved
            .eligible_recipients()
            .into_iter()
            .filter_map(|id| Some((id, resolved.kem_of(&id)?)))
            .collect();
        recipients.remove(&device);
        let key = EpochKey::generate().map_err(frame_err)?;
        let me = signer.device_id();
        let (seq, prev) = self.position(&me, LogKind::Member);
        let frame = v2::build_remove_frame(
            signer,
            self.id,
            resolved,
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
        let id = self.stage(vec![frame], None)?[0];
        if view.is_some() {
            // Undoing the thief's removals is the human confirming them back.
            let back: Vec<DeviceId> = self
                .previously_removed
                .iter()
                .filter(|d| self.resolved.is_active_device(d))
                .copied()
                .collect();
            for device in &back {
                self.confirm_reinstated(device);
            }
        }
        Ok(id)
    }

    /// Membership resolved without `skip` (see [`Self::pre_theft_exclusions`]),
    /// its epoch graph, and `skip`.
    fn pre_theft_view(
        &self,
        device: &DeviceId,
    ) -> (ResolvedMembership, EpochGraph, BTreeSet<FrameId>) {
        let skip = self.pre_theft_exclusions(device);
        let members: Vec<&Frame> = self
            .members
            .values()
            .filter(|f| !skip.contains(&f.id()))
            .collect();
        let frames = members.iter().copied().chain(self.data.values());
        let resolved = v2::resolve(&self.id, frames, &self.proofs);
        let graph = EpochGraph::build(self.id, members.iter().copied(), &resolved);
        (resolved, graph, skip)
    }

    /// The newest epochs `graph` authorizes that this device holds keys for.
    fn held_tips(&self, graph: &EpochGraph) -> Vec<EpochId> {
        let held: BTreeSet<EpochId> = self
            .keyring
            .epoch_ids()
            .into_iter()
            .filter(|e| graph.get(e).is_some_and(|i| i.authorized))
            .collect();
        graph.maximal_epochs_in(&held)
    }

    /// What a removal of a stolen `device` must not depend on: every
    /// membership frame it signed that nobody else has built on (adds,
    /// removals, rotations), and everything after them. This device vouches
    /// for its own admission, so the frame that added it counts as built on.
    fn pre_theft_exclusions(&self, device: &DeviceId) -> BTreeSet<FrameId> {
        let mut built: BTreeSet<FrameId> = BTreeSet::new();
        let mut stack: Vec<FrameId> = self
            .members
            .values()
            .filter(|f| {
                f.header().author != *device
                    || matches!(
                        f.member_body().and_then(|b| b.op.as_ref()),
                        Some(v2::MemberOp::Add { device: added, .. }) if *added == self.me
                    )
            })
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
        Ok(self.stage(vec![frame], None)?[0])
    }
}
