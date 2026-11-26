//! What the recovery kit and the parking rule let a person do: hand the
//! recovery root on to a new kit, take a stolen device out as of before the
//! theft, accept a removed device that is back, and see why a vault is
//! parked.

use anyhow::{Context, Result, anyhow, bail};
use deadbolt_core::v2::{
    DeviceKeys, FRAUD_PROOF_LEN, Frame, FrameId, FraudProof, Pack, ParkingReason, RecoverySecret,
};
use deadbolt_core::{DeviceId, PackSite, Vault, VaultId, parking_message, recovery};
use deadbolt_proto::daemon::{ParkedReason, VaultState};
use zeroize::Zeroizing;

use crate::Engine;

/// Per vault: fraud proofs fetched from a store.
fn meta_proofs(vault: &VaultId) -> String {
    format!("vault/{vault}/proofs")
}

impl Engine {
    /// Hands `vault`'s recovery root from the kit `words` to `new`
    /// (`RotateRecovery` + `Rotate`, signed by the old root), returning the
    /// new kit's 24 words. Both secrets are wiped when the caller drops them;
    /// the words are shown once and never stored.
    pub fn rotate_recovery(
        &mut self,
        vault: VaultId,
        words: &str,
        new: &RecoverySecret,
    ) -> Result<Zeroizing<String>> {
        let old = recovery::decode(words).map_err(|e| anyhow!("reading the recovery kit: {e}"))?;
        self.update(vault, |v, _| {
            v.rotate_recovery(&old, new)
                .context("rotating the recovery kit")
        })?;
        Ok(recovery::encode(new))
    }

    /// Removes the stolen `device` from `vault`: only its data frames made
    /// before `since_ms` (all of them for `None`) keep counting, and the
    /// removal is built as of before the theft (`VaultWrite::remove_stolen`).
    pub fn remove_stolen(
        &mut self,
        vault: VaultId,
        device: DeviceId,
        since_ms: Option<u64>,
    ) -> Result<()> {
        self.update(vault, |v, a| {
            v.remove_stolen(a.keys().sign_key(), device, since_ms)
                .context("removing the stolen device")
        })?;
        // Undoing the thief's removals confirms those devices back.
        self.save_removed(&vault)?;
        Ok(())
    }

    /// The person confirmed that `device`, once removed and now back,
    /// belongs: `vault` stops being parked on it.
    pub fn confirm_reinstated(&mut self, vault: VaultId, device: DeviceId) -> Result<()> {
        let held = self.vaults.get_mut(&vault).context("vault not held")?;
        let reinstated = held.parked().iter().any(
            |r| matches!(r, ParkingReason::ReinstatedRemovedDevice { device: d } if *d == device),
        );
        if !reinstated {
            anyhow::bail!(
                "{device} is not a removed device that is back in {}",
                held.name()
            );
        }
        held.confirm_reinstated(&device);
        self.save_removed(&vault)?;
        self.changes.vaults = true;
        Ok(())
    }

    /// Saves `vault`'s fraud proofs, so ones fetched from a store (whose
    /// frames this device may never hold) survive a lock.
    pub fn save_proofs(&self, vault: &VaultId) -> Result<()> {
        let bytes: Vec<u8> = self.vaults[vault]
            .proofs()
            .iter()
            .flat_map(|p| p.encode())
            .collect();
        self.store().meta_set(&meta_proofs(vault), &bytes)
    }

    /// Restores the proofs [`Engine::save_proofs`] kept.
    pub(crate) fn load_proofs(&mut self, vault: &VaultId) -> Result<()> {
        let Some(bytes) = self.store().meta_get(&meta_proofs(vault))? else {
            return Ok(());
        };
        let proofs: Vec<FraudProof> = bytes
            .chunks(FRAUD_PROOF_LEN)
            .filter_map(|chunk| FraudProof::decode(chunk).ok())
            .collect();
        if let Some(v) = self.vaults.get_mut(vault) {
            v.add_proofs(proofs);
        }
        Ok(())
    }

    /// Applies frames and fraud proofs fetched from a blind store. Returns
    /// how many frames were new.
    pub fn apply_fetched(
        &mut self,
        vault: VaultId,
        frames: Vec<Frame>,
        proofs: Vec<FraudProof>,
    ) -> Result<usize> {
        let keys = self.keys();
        if let Some(v) = self.vaults.get_mut(&vault) {
            v.add_proofs(proofs);
        }
        self.update(vault, |w, _| Ok(w.apply(keys.kem_key(), frames)?))
    }

    /// Installs a checkpoint pack fetched whole (its `sealed` bytes, which
    /// `site` names) as `vault`'s base, re-sealing it as this device's own
    /// generation if the store can't take it byte for byte. Refuses a pack
    /// that `checkpoint` (counted, undisputed, still valid) doesn't commit
    /// to.
    pub fn adopt_pack(
        &mut self,
        vault: VaultId,
        checkpoint: FrameId,
        pack: Pack,
        sealed: &[u8],
        site: &PackSite,
    ) -> Result<()> {
        let held = self.vaults.get(&vault).context("vault not held")?;
        if !held.verify_base(&checkpoint, &pack, sealed) {
            bail!("the checkpoint is disputed, no longer counts, or does not commit to that pack");
        }
        if self.store().keeps_packs() && self.store().install_pack(vault, sealed).is_err() {
            let fresh = self.store().seal_pack(&pack, site)?;
            self.store().install_pack(vault, &fresh)?;
        }
        self.vaults
            .get_mut(&vault)
            .context("vault not held")?
            .set_base(checkpoint, pack);
        self.changes.vaults = true;
        self.changes.items.insert(vault);
        Ok(())
    }

    /// Takes on a vault rebuilt from its recovery kit: `frames` hold this
    /// device's admission by the root, `base` the checkpoint (and its pack)
    /// its folded state starts from (when the store collected older frames),
    /// `proofs` the store's fraud proofs. Stores it, then signs this
    /// device's card.
    pub fn adopt_recovered(
        &mut self,
        frames: Vec<Frame>,
        base: Option<(FrameId, Pack, Vec<u8>, PackSite)>,
        proofs: Vec<FraudProof>,
    ) -> Result<VaultId> {
        let id = frames
            .first()
            .map(|f| f.header().vault)
            .context("no frames")?;
        self.available(id)?;
        if self.contains_vault(&id) {
            bail!("this device already holds that vault");
        }
        let keys: DeviceKeys = self.keys();
        let mut vault = Vault::open(&keys, frames.iter().cloned())?;
        // Proofs first: an equivocating author must be judged before this
        // device signs anything on the fold.
        vault.add_proofs(proofs);
        if !vault.is_member(&self.id) {
            bail!("the recovered vault does not admit this device");
        }
        let result = self.store.append(id, &mut frames.iter());
        self.check_append(result)?;
        self.vaults.insert(id, vault);
        self.save_proofs(&id)?;
        self.save_removed(&id)?;
        if let Some((checkpoint, pack, sealed, site)) = base {
            self.adopt_pack(id, checkpoint, pack, &sealed, &site)?;
        }
        let label = self.meta.device_name.clone();
        self.update(id, |w, a| {
            Ok(w.card(a, a.id(), a.keys().net_public(), &label)?)
        })?;
        if self.meta.default_vault.is_none() {
            self.meta.default_vault = Some(id);
            self.save_meta()?;
        }
        self.changes.vaults = true;
        Ok(id)
    }

    /// `vault`'s state beyond its [`deadbolt_proto::daemon::VaultInfo`]: why
    /// it is parked and how many frames no key opens yet. The host adds
    /// what only it knows (pack generation, remote).
    pub fn vault_state(&self, vault: &VaultId) -> VaultState {
        let held = &self.vaults[vault];
        VaultState {
            vault: self.vault_info(vault),
            parked: held.parked().iter().map(parked_reason).collect(),
            sealed: held.sealed_count(),
            generation: None,
            remote: None,
        }
    }
}

fn parked_reason(reason: &ParkingReason) -> ParkedReason {
    let (kind, devices) = match reason {
        ParkingReason::ReinstatedRemovedDevice { device } => ("reinstated", vec![*device]),
        ParkingReason::MutualRemoval { a, b } => ("mutual-removal", vec![*a, *b]),
        ParkingReason::RecoveryLineageFrozen => ("recovery-frozen", Vec::new()),
    };
    ParkedReason {
        kind: kind.into(),
        devices: devices.iter().map(ToString::to_string).collect(),
        message: parking_message(reason),
    }
}
