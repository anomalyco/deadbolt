//! Rule E6, reader duty: a member holding an epoch's key rewraps it to
//! members who can't reach it, so a device added concurrently with a
//! rotation isn't left without the keys to read or write.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::Error;
use crate::id::{DeviceId, DeviceSecret};
use crate::v2::{self, EpochId, FoldContext, FrameId, KemPublic, LogKind, RecoverySecret};

use super::write::{Author, VaultWrite, frame_err};

impl VaultWrite<'_> {
    /// Rewraps every epoch that counted data or the write epoch needs to the
    /// current members (and recovery root) who can't reach it, as `author`.
    /// Does nothing unless `author` is a member and isn't parked. Returns the
    /// `Rewrap` frames made.
    pub fn fulfill_reader_duty(&mut self, author: &Author) -> Result<Vec<FrameId>, Error> {
        if !self.is_member(&author.id()) || !self.parked.is_empty() {
            return Ok(Vec::new());
        }
        self.rewrap_missing(author.keys().sign_key())
    }

    /// Reader duty as the recovery root `root`, which holds every epoch's
    /// key: after a recovery, the new device must reach every clean tip and
    /// every epoch with counted data, however many concurrent ones there
    /// are. Only a frozen lineage stops it, never a device parking.
    pub fn root_reader_duty(&mut self, root: &RecoverySecret) -> Result<Vec<FrameId>, Error> {
        if self.recovery_root() != Some(root.recovery_id()) {
            return Err(Error::NotRecoveryRoot);
        }
        self.rewrap_missing(&root.signing_key())
    }

    fn rewrap_missing(&mut self, signer: &DeviceSecret) -> Result<Vec<FrameId>, Error> {
        let me = signer.device_id();
        let ctx = FoldContext {
            membership: &self.resolved,
            adders: &self.adders,
        };
        let counted: BTreeSet<EpochId> = self
            .opened
            .values()
            .filter(|f| ctx.counts(f))
            .map(|f| f.epoch)
            .collect();
        let plan = self
            .graph()
            .needed_rewraps(&self.keyring, &self.resolved, &counted);
        let mut made = Vec::new();
        for (epoch, missing) in plan {
            let Some(key) = self.keyring.get(&epoch).cloned() else {
                continue;
            };
            let recipients: BTreeMap<DeviceId, KemPublic> = missing
                .into_iter()
                .filter(|d| *d != me)
                .filter_map(|d| Some((d, self.resolved.kem_of(&d)?)))
                .collect();
            if recipients.is_empty() {
                continue;
            }
            let (seq, prev) = self.position(&me, LogKind::Member);
            let frame = v2::build_rewrap_frame(
                signer,
                self.id,
                &self.resolved,
                seq,
                prev,
                Self::member_deps(prev, self.mheads()),
                epoch,
                &key,
                &recipients,
            )
            .map_err(frame_err)?;
            made.extend(self.stage(vec![frame], None)?);
        }
        Ok(made)
    }
}
