//! Checkpoints: when the uncompacted tail reaches 1 MiB or 500 frames
//! (`should_checkpoint`), this device compacts its fold into a pack, the
//! store seals it as the next `gen-<n>.pack`, a `Checkpoint` frame
//! commits to those bytes, and the pack becomes the fold's base. Other
//! devices' checkpoints are judged as they arrive; a dishonest one gets a
//! `Dispute`.

use anyhow::{Context, Result};
use deadbolt_core::VaultId;
use deadbolt_core::v2::FrameId;

use crate::Engine;

impl Engine {
    /// Checkpoints `vault` if its tail is due and this device may write.
    /// A failure is logged, never raised: the write that triggered it has
    /// already committed.
    pub fn maybe_checkpoint(&mut self, vault: VaultId) -> Option<FrameId> {
        let due = self.store().keeps_packs()
            && self.vaults.get(&vault).is_some_and(|v| {
                v.is_member(&self.id) && v.parked().is_empty() && v.checkpoint_due()
            });
        if !due {
            return None;
        }
        match self.checkpoint(vault) {
            Ok(frame) => Some(frame),
            Err(error) => {
                tracing::warn!(vault = %vault, %error, "checkpoint failed");
                None
            }
        }
    }

    /// Compacts `vault` into a new local pack and signs its checkpoint.
    pub fn checkpoint(&mut self, vault: VaultId) -> Result<FrameId> {
        self.available(vault)?;
        let author = self.author();
        let store = &self.store;
        let changes = &mut self.changes;
        let held = self.vaults.get_mut(&vault).context("vault not held")?;
        let result = held.transact(
            |w| {
                w.checkpoint(&author, |pack, site| {
                    store.seal_pack(pack, site).map_err(|e| format!("{e:#}"))
                })
                .map_err(anyhow::Error::from)
            },
            |v, frames| {
                store.append(vault, &mut frames.iter().copied())?;
                changes.committed(vault, v, frames);
                Ok(())
            },
        );
        let made = self.check_append(result)?;
        let installed = self.store.install_pack(vault, &made.sealed);
        if let Some(v) = self.vaults.get_mut(&vault) {
            v.set_base(made.frame, made.pack);
        }
        installed?;
        Ok(made.frame)
    }

    /// Judges other devices' checkpoints in `vault`, disputing any whose
    /// state disagrees with this device's fold. Returns how many.
    pub fn judge_checkpoints(&mut self, vault: VaultId) -> Result<usize> {
        if !self
            .vaults
            .get(&vault)
            .is_some_and(|v| v.is_member(&self.id))
        {
            return Ok(0);
        }
        self.update(vault, |w, a| Ok(w.judge_checkpoints(a)?))
    }

    /// Installs the local pack the store holds for `vault`, if any, as its
    /// fold's base: only while a counted, undisputed checkpoint commits to
    /// it and the membership still counts what it covers.
    pub(crate) fn load_base(&mut self, vault: VaultId) -> Result<()> {
        let Some(sealed) = self.store().load_pack(vault)? else {
            return Ok(());
        };
        let held = &self.vaults[&vault];
        let pack = self
            .store()
            .open_pack(&sealed, vault, &|epoch| held.epoch_key(epoch).cloned())?;
        if let Some(v) = self.vaults.get_mut(&vault)
            && v.adopt_local_base(pack).is_none()
        {
            tracing::warn!(vault = %vault, "no counted, undisputed checkpoint holds the local pack; folding from genesis");
        }
        Ok(())
    }
}
