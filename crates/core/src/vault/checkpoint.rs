//! Checkpoints: compacting the fold into a pack, signing the `Checkpoint`
//! frame that commits to its sealed bytes, judging other devices'
//! checkpoints, and folding from an installed pack.
//!
//! The pack's sealed bytes come from the host (`deadbolt-pack` lays out
//! the DBPK file), so the frame commits to exactly what is stored locally
//! as `gen-<n>.pack` and remotely as `p/<pack_hash>`.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::Error;
use crate::id::{DeviceId, VaultId};
use crate::v2::{
    self, CheckpointVerdict, DataBody, EpochId, EpochKey, FoldContext, FrameId, FraudProof,
    LogKind, Pack, PackCommitment, VectorClock, build_checkpoint, should_checkpoint,
};

use super::Vault;
use super::write::{Author, VaultWrite, frame_err};

/// Where a checkpoint's pack sits: the checkpoint frame it belongs to, and
/// the epoch key its records are sealed under.
pub struct PackSite {
    pub vault: VaultId,
    pub author: DeviceId,
    pub seq: u64,
    pub epoch: EpochId,
    pub key: EpochKey,
}

/// A checkpoint made in a transaction. Install `pack` as the base
/// ([`Vault::set_base`]) once the frame is committed.
pub struct Checkpointed {
    pub frame: FrameId,
    pub pack: Pack,
    /// The sealed DBPK bytes the frame commits to.
    pub sealed: Vec<u8>,
}

impl Vault {
    /// The installed checkpoint pack, if any.
    pub fn base(&self) -> Option<&Pack> {
        self.base.as_ref()
    }

    /// Folds from `pack` from now on. A pack the membership no longer
    /// counts is kept but folded around (from genesis).
    pub fn set_base(&mut self, pack: Pack) {
        self.base = Some(pack);
        self.refresh(None);
    }

    /// The epoch key this device holds for `epoch`.
    pub fn epoch_key(&self, epoch: &EpochId) -> Option<&EpochKey> {
        self.keyring.get(epoch)
    }

    /// Data frames above the base's frontier: how many, and their bytes.
    pub fn tail_size(&self) -> (u64, u64) {
        let frontier = self.base.as_ref().map(|b| &b.meta.frontier);
        self.data
            .values()
            .filter(|f| {
                let h = f.header();
                frontier
                    .and_then(|fr| fr.get(&h.author))
                    .is_none_or(|(seq, _)| h.seq > *seq)
            })
            .fold((0, 0), |(n, bytes), f| {
                (n + 1, bytes + f.encode().len() as u64)
            })
    }

    /// Whether the tail has grown enough to checkpoint (1 MiB or 500 frames).
    pub fn checkpoint_due(&self) -> bool {
        let (frames, bytes) = self.tail_size();
        should_checkpoint(bytes, frames)
    }

    /// Every checkpoint frame this vault holds and opened, with its payload.
    pub fn checkpoints(&self) -> impl Iterator<Item = (&v2::DataFrame, &v2::CheckpointPayload)> {
        self.opened.values().filter_map(|f| match &f.body {
            DataBody::Checkpoint(p) => Some((f, p)),
            DataBody::Data(_) => None,
        })
    }

    /// Whether `pack`, with `sealed` its encrypted bytes, is what
    /// checkpoint `frame` commits to: same file, same frontier, same
    /// `state_mac`. What a device with none of the covered frames (a
    /// recovery) can check.
    pub fn pack_matches(&self, frame: &FrameId, pack: &Pack, sealed: &[u8]) -> bool {
        let Some(f) = self.opened.get(frame) else {
            return false;
        };
        let DataBody::Checkpoint(payload) = &f.body else {
            return false;
        };
        let Some(key) = self.keyring.get(&f.epoch) else {
            return false;
        };
        let k_mac = key.mac_key(&self.id, &f.epoch);
        v2::checkpoint::pack_matches(&k_mac, payload, pack, PackCommitment::of(sealed))
    }

    /// Accepts fraud proofs of this vault (fetched from a store): each
    /// equivocating author is judged as if both its frames were held.
    /// Returns how many were new.
    pub fn add_proofs(&mut self, proofs: impl IntoIterator<Item = FraudProof>) -> usize {
        let mut added = 0;
        for proof in proofs {
            let ours = proof.verify().is_ok_and(|v| v.vault == self.id);
            if ours && !self.proofs.contains(&proof) {
                self.proofs.push(proof);
                added += 1;
            }
        }
        if added > 0 {
            self.refresh(None);
        }
        added
    }

    /// Whether this vault holds every data frame at or below `frontier`,
    /// so it can judge a checkpoint there without its pack.
    pub fn holds_frontier(&self, frontier: &BTreeMap<DeviceId, (u64, FrameId)>) -> bool {
        frontier.iter().all(|(author, (seq, _))| {
            let held = self
                .data
                .values()
                .filter(|f| f.header().author == *author && f.header().seq <= *seq)
                .map(|f| f.header().seq)
                .collect::<BTreeSet<_>>();
            held.len() as u64 == seq.saturating_add(1)
        })
    }

    /// Each member's data clock: what its newest opened frame had seen,
    /// the implicit ack GC counts.
    pub fn member_clocks(&self) -> BTreeMap<DeviceId, VectorClock> {
        let mut out = BTreeMap::new();
        for member in self.resolved.devices.iter() {
            let mut frames: Vec<&v2::DataFrame> = self
                .opened
                .values()
                .filter(|f| f.author == *member)
                .collect();
            frames.sort_by_key(|f| f.seq);
            let clock = frames
                .iter()
                .fold(VectorClock::new(), |clock, f| f.clock_after(&clock));
            out.insert(*member, clock);
        }
        out
    }

    /// Every `Dispute` a counted frame made.
    pub fn disputes(&self) -> &BTreeSet<v2::DisputeRecord> {
        &self.state.disputes
    }

    /// Whether a current member disputed `checkpoint`.
    pub fn is_disputed(&self, checkpoint: &FrameId) -> bool {
        self.state.is_disputed(checkpoint, &self.resolved.devices)
    }
}

impl VaultWrite<'_> {
    /// Compacts everything this device has folded into a pack, has `seal`
    /// lay it out and encrypt it, and signs the `Checkpoint` frame that
    /// commits to those bytes as `author`'s next data frame.
    pub fn checkpoint(
        &mut self,
        author: &Author,
        seal: impl FnOnce(&Pack, &PackSite) -> Result<Vec<u8>, String>,
    ) -> Result<Checkpointed, Error> {
        let me = author.id();
        if !self.is_member(&me) {
            return Err(Error::NotMember);
        }
        let (epoch, key) = self.write_epoch(author.keys().sign_key())?;
        let (seq, prev) = self.position(&me, LogKind::Data);
        let ctx = FoldContext {
            membership: &self.resolved,
            adders: &self.adders,
        };
        let pack = v2::compact(&ctx, self.base.as_ref(), self.fold_inputs()).map_err(frame_err)?;
        let site = PackSite {
            vault: self.id,
            author: me,
            seq,
            epoch,
            key: key.clone(),
        };
        let sealed = seal(&pack, &site).map_err(Error::Frame)?;
        let k_mac = key.mac_key(&self.id, &epoch);
        let payload = build_checkpoint(
            &k_mac,
            &pack,
            PackCommitment::of(&sealed),
            self.mheads(),
            author.now_ms(),
        )
        .map_err(frame_err)?;
        let frame = payload
            .seal(author.keys().sign_key(), self.id, seq, prev, epoch, &key)
            .map_err(frame_err)?;
        let id = self.stage(vec![frame], None)?[0];
        Ok(Checkpointed {
            frame: id,
            pack,
            sealed,
        })
    }

    /// Judges every other device's checkpoint this device can: one whose
    /// `state_mac` disagrees with this device's own fold at its frontier
    /// gets a `Dispute`, so no member covers, adopts or collects behind it.
    /// Returns how many were disputed.
    pub fn judge_checkpoints(&mut self, author: &Author) -> Result<usize, Error> {
        let me = author.id();
        if !self.is_member(&me) {
            return Ok(0);
        }
        let candidates: Vec<(v2::DataFrame, v2::CheckpointPayload)> = self
            .checkpoints()
            .filter(|(f, _)| f.author != me && !self.judged.contains(&f.id))
            .map(|(f, p)| (f.clone(), p.clone()))
            .collect();
        let mut disputes = Vec::new();
        for (f, payload) in candidates {
            let Some(key) = self.keyring.get(&f.epoch) else {
                continue;
            };
            let k_mac = key.mac_key(&self.id, &f.epoch);
            let ctx = FoldContext {
                membership: &self.resolved,
                adders: &self.adders,
            };
            let verdict =
                v2::verify_checkpoint(&k_mac, &ctx, f.id, &payload, None, self.fold_inputs());
            match verdict {
                Ok(CheckpointVerdict::Unverifiable) => continue,
                Ok(CheckpointVerdict::Disputed { dispute }) => {
                    let mine = self
                        .state
                        .disputes
                        .iter()
                        .any(|d| d.checkpoint == f.id && d.author == me);
                    if !mine {
                        disputes.push(dispute);
                    }
                }
                Ok(CheckpointVerdict::Agreed | CheckpointVerdict::Invalidated) | Err(_) => {}
            }
            self.judged.insert(f.id);
        }
        let made = disputes.len();
        if made > 0 {
            self.seal(author, disputes)?;
        }
        Ok(made)
    }
}

#[cfg(test)]
mod tests;
