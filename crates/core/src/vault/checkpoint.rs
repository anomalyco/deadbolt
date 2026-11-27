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

    /// The checkpoint frame the installed pack belongs to.
    pub fn base_checkpoint(&self) -> Option<FrameId> {
        self.base_checkpoint
    }

    /// Folds from `pack`, which `checkpoint` (this device's own, just
    /// committed) commits to, from now on. A pack the membership no longer
    /// counts is kept but folded around (from genesis); one whose checkpoint
    /// is disputed or stops counting is dropped.
    pub fn set_base(&mut self, checkpoint: FrameId, pack: Pack) {
        self.base = Some(pack);
        self.base_checkpoint = Some(checkpoint);
        self.refresh(None);
    }

    /// Installs a pack from elsewhere (disk, a store) as the base, if it
    /// is what a checkpoint this vault counts and no member disputed
    /// commits to, `sealed` its encrypted bytes, and the membership still
    /// counts what it covers. Returns whether it was installed.
    pub fn adopt_base(&mut self, checkpoint: FrameId, pack: Pack, sealed: &[u8]) -> bool {
        if !self.verify_base(&checkpoint, &pack, sealed) {
            return false;
        }
        self.set_base(checkpoint, pack);
        true
    }

    /// Whether [`Vault::adopt_base`] would take `pack` for `checkpoint`.
    pub fn verify_base(&self, checkpoint: &FrameId, pack: &Pack, sealed: &[u8]) -> bool {
        let ctx = FoldContext {
            membership: &self.resolved,
            adders: &self.adders,
        };
        self.checkpoints().any(|(f, _)| f.id == *checkpoint)
            && !self.is_disputed(checkpoint)
            && self.pack_matches(checkpoint, pack, sealed)
            && v2::check_still_valid(&ctx, &pack.meta).is_ok()
    }

    /// Installs this device's own stored pack as the base: the one a
    /// counted, undisputed checkpoint commits to the contents of (the file
    /// may be this device's re-sealing), while the membership still counts
    /// what it covers. Returns the checkpoint, or None (nothing installed).
    pub fn adopt_local_base(&mut self, pack: Pack) -> Option<FrameId> {
        let ctx = FoldContext {
            membership: &self.resolved,
            adders: &self.adders,
        };
        if v2::check_still_valid(&ctx, &pack.meta).is_err() {
            return None;
        }
        let checkpoint = self
            .checkpoints()
            .filter(|(f, _)| !self.is_disputed(&f.id))
            .find(|(f, payload)| {
                self.keyring.get(&f.epoch).is_some_and(|key| {
                    let k_mac = key.mac_key(&self.id, &f.epoch);
                    v2::checkpoint::content_matches(&k_mac, payload, &pack)
                })
            })
            .map(|(f, _)| f.id)?;
        self.set_base(checkpoint, pack);
        Some(checkpoint)
    }

    /// Drops a base whose checkpoint a member disputed or the membership no
    /// longer counts, refolding from genesis. Returns whether it did.
    pub(super) fn drop_untrusted_base(&mut self) -> bool {
        let Some(id) = self.base_checkpoint else {
            return false;
        };
        let counted = self.checkpoints().any(|(f, _)| f.id == id);
        // A base the membership stopped counting is only folded around; a
        // device holding every frame it covers drops it outright, so its
        // next checkpoint compacts from genesis in this session.
        let stale = self.live_base().is_none()
            && self
                .base
                .as_ref()
                .is_some_and(|b| self.holds_frontier(&b.meta.frontier));
        if counted && !self.is_disputed(&id) && !stale {
            return false;
        }
        self.base = None;
        self.base_checkpoint = None;
        true
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

    /// Every checkpoint frame this vault holds, opened and counts (signed
    /// by a principal at a seq its membership counts, under an authorized
    /// epoch), with its payload. A removed device's later checkpoint, or
    /// one sealed under a throwaway key, is never among them.
    pub fn checkpoints(&self) -> impl Iterator<Item = (&v2::DataFrame, &v2::CheckpointPayload)> {
        let ctx = FoldContext {
            membership: &self.resolved,
            adders: &self.adders,
        };
        self.opened.values().filter_map(move |f| match &f.body {
            DataBody::Checkpoint(p) if ctx.counts(f) => Some((f, p)),
            _ => None,
        })
    }

    /// Whether `frontier` contradicts what this device knows for certain
    /// about its own log: a seq past its tip, or a frame other than the one
    /// it wrote there.
    pub fn contradicts(&self, frontier: &BTreeMap<DeviceId, (u64, FrameId)>) -> bool {
        let Some((seq, id)) = frontier.get(&self.me) else {
            return false;
        };
        let held = self
            .data
            .values()
            .find(|f| f.header().author == self.me && f.header().seq == *seq);
        match held {
            Some(f) => f.id() != *id,
            None => self.position_of(&self.me).is_none_or(|tip| *seq > tip),
        }
    }

    /// The highest data seq `author` has here.
    fn position_of(&self, author: &DeviceId) -> Option<u64> {
        self.data
            .values()
            .filter(|f| f.header().author == *author)
            .map(|f| f.header().seq)
            .max()
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

    /// Each member's data clock: what its newest resolved frame had seen,
    /// the implicit ack GC counts. Starts from the base's stream clock (its
    /// frames below the frontier may be gone) and only follows the chain
    /// the fold resolved, so an unchained or forked frame can't inflate it.
    pub fn member_clocks(&self) -> BTreeMap<DeviceId, VectorClock> {
        let resolved = self.resolved_data();
        self.resolved
            .devices
            .iter()
            .map(|member| {
                let clock = self.clock_of(member, |f| resolved.contains(&f.id));
                (*member, clock)
            })
            .collect()
    }

    /// Whether `by`'s own signed frames say it saw `author`'s frame `seq`:
    /// its clock along the resolved chain, or any of its opened frames
    /// naming it (a device behind a compaction gap can't chain `by`'s
    /// stream, but its signature still vouches). No one else can forge it.
    pub fn acked(&self, by: &DeviceId, author: &DeviceId, seq: u64) -> bool {
        if *by == *author && self.position_of(by).is_some_and(|tip| tip >= seq) {
            return true;
        }
        if self.live_base().is_none_or(|base| {
            base.meta
                .frontier
                .get(author)
                .is_some_and(|(at, _)| seq <= *at)
        }) && self
            .member_clocks()
            .get(by)
            .is_some_and(|c| c.get(author) > seq)
        {
            return true;
        }
        let ctx = FoldContext {
            membership: &self.resolved,
            adders: &self.adders,
        };
        self.opened
            .values()
            .filter(|f| f.author == *by && ctx.counts(f))
            .any(|f| match &f.body {
                DataBody::Data(p) => p
                    .dclock
                    .entries()
                    .iter()
                    .any(|(a, n)| a == author && *n > seq),
                DataBody::Checkpoint(p) => {
                    p.frontier_map().get(author).is_some_and(|(s, _)| *s >= seq)
                }
            })
    }

    /// The current members whose admission checkpoint `f`'s membership
    /// heads already depend on (the creator included): who existed when it
    /// was written. None when those heads can't be the ones it was written
    /// on: they must reach the frame that minted its epoch and a counted
    /// admission of its author and of every author its frontier names, so
    /// empty or backdated heads never shrink who must have acked it.
    pub fn members_before(
        &self,
        f: &v2::DataFrame,
        payload: &v2::CheckpointPayload,
    ) -> Option<BTreeSet<DeviceId>> {
        let mut seen: BTreeSet<FrameId> = BTreeSet::new();
        let mut todo: Vec<FrameId> = payload.mheads.clone();
        while let Some(id) = todo.pop() {
            if !seen.insert(id) {
                continue;
            }
            if let Some(frame) = self.members.get(&id) {
                let h = frame.header();
                todo.extend((h.seq > 0).then_some(h.prev));
                if let Some(body) = frame.member_body() {
                    todo.extend(body.deps.iter().copied());
                }
            }
        }
        let admits = |m: &DeviceId| {
            seen.iter().any(|id| {
                let Some(frame) = self.members.get(id) else {
                    return false;
                };
                let admission = match frame.member_body().and_then(|b| b.op.as_ref()) {
                    Some(v2::MemberOp::Add { device, .. }) => device == m,
                    Some(v2::MemberOp::Create { .. }) => frame.header().author == *m,
                    _ => false,
                };
                admission && self.resolved.authorized_frames.contains(id)
            })
        };
        let plausible = seen.contains(&f.epoch.as_frame_id())
            && admits(&f.author)
            && payload.frontier.iter().all(|(a, _, _)| admits(a));
        plausible.then(|| {
            self.resolved
                .devices
                .iter()
                .copied()
                .filter(|m| admits(m))
                .collect()
        })
    }

    /// The installed base while the membership still counts what it covers.
    pub(super) fn live_base(&self) -> Option<&Pack> {
        let ctx = FoldContext {
            membership: &self.resolved,
            adders: &self.adders,
        };
        self.base
            .as_ref()
            .filter(|b| v2::check_still_valid(&ctx, &b.meta).is_ok())
    }

    /// The data frames the fold resolved causally, from the live base on.
    pub(super) fn resolved_data(&self) -> BTreeSet<FrameId> {
        let ctx = FoldContext {
            membership: &self.resolved,
            adders: &self.adders,
        };
        v2::resolved_frames_from(&ctx, self.base.as_ref(), self.fold_inputs())
    }

    /// The clock after `author`'s newest frame: its stream clock in the live
    /// base, then each of its opened frames above the frontier that `take`
    /// keeps, in order.
    pub(super) fn clock_of(
        &self,
        author: &DeviceId,
        take: impl Fn(&v2::DataFrame) -> bool,
    ) -> VectorClock {
        let base = self.live_base();
        let floor = base
            .and_then(|b| b.meta.frontier.get(author))
            .map(|(s, _)| *s);
        let start = base
            .and_then(|b| b.meta.stream_clocks.get(author))
            .filter(|_| floor.is_some())
            .cloned()
            .unwrap_or_default();
        let mut frames: Vec<&v2::DataFrame> = self
            .opened
            .values()
            .filter(|f| f.author == *author && floor.is_none_or(|s| f.seq > s) && take(f))
            .collect();
        frames.sort_by_key(|f| f.seq);
        frames.iter().fold(start, |clock, f| f.clock_after(&clock))
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
            // A frontier past this device's own tip, or naming a frame it
            // knows is another, is disputed at once: no fold can agree.
            if self.contradicts(&payload.frontier_map()) {
                let mine = self
                    .state
                    .disputes
                    .iter()
                    .any(|d| d.checkpoint == f.id && d.author == me);
                if !mine {
                    disputes.push(v2::DataOp::Dispute {
                        checkpoint: f.id,
                        expected_state_mac: v2::state_mac(&k_mac, &self.state)
                            .map_err(frame_err)?,
                    });
                }
                self.judged.insert(f.id);
                continue;
            }
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
