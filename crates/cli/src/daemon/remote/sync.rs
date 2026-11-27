//! `remote-sync`: one pass of the blind-store protocol for one vault.
//!
//! ```text
//! check_self_rollback      own streams moved without us? then pull only
//! plan_pull                LIST m/, d/, x/ against the anchor
//!   judge                  GET everything planned: check_fetched_as every frame,
//!                          resolve_twin each <seq>/<seq>.c pair, check_fetched_fraud
//!                          every new x/<proof_hash>
//!   apply                  frames and proofs, then judge their checkpoints
//!   adopt                  each undisputed checkpoint's frontier into the anchor;
//!                          its pack too when this device lacks the covered frames
//!   observe                every applied frame, in order
//! plan_push + push         own frames above the anchor, their packs, every proof
//! plan_gc                  delete what every member's clock covers behind the base
//! ```

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use deadbolt_core::v2::{
    FrameId, FrameKind, FraudProof, GcCheckpoint, GcFrame, LogKind, PackCommitment, plan_gc,
};
use deadbolt_core::{DeviceId, PackSite, VaultId};
use deadbolt_proto::daemon::RemoteReport;
use deadbolt_remote::path::area_prefix;
use deadbolt_remote::{
    Area, ObjStore, Outbox, RemoteAnomaly, RemotePath, SyncAnchor, check_fetched_as,
    check_self_rollback, plan_pull, plan_push, push, withheld,
};

use super::{Daemon, Remote, load, load_anchor, save, save_anchor};
use crate::config::now;

/// One line for a person about what the store did.
pub(super) fn describe(anomaly: &RemoteAnomaly) -> String {
    match anomaly {
        RemoteAnomaly::RemoteRegressed { log, author, expected_seq, .. } => {
            format!("the store lost or swapped {author}'s {log:?} frame {expected_seq}: it was rolled back or wiped")
        }
        RemoteAnomaly::Withheld { author, required_seq, .. } => {
            format!("the store withholds {author}'s data frame {required_seq}")
        }
        RemoteAnomaly::StreamHole { log, author, missing_seq, .. } => {
            format!("{author}'s {log:?} stream skips frame {missing_seq}")
        }
        RemoteAnomaly::StreamGap { log, author, observed_seq, .. } => {
            format!("{author}'s {log:?} frame {observed_seq} skips frames the store never showed")
        }
        RemoteAnomaly::ChainBroken { log, author, seq, .. } => {
            format!("{author}'s {log:?} frame {seq} does not follow the one before it")
        }
        RemoteAnomaly::FraudWiped { .. } => "the store deleted a fraud proof".into(),
        RemoteAnomaly::Mismatched { name, reason } => format!("{name}: {reason}"),
        RemoteAnomaly::SelfRollback(_) => {
            "this device's own stream moved on the store without it (restored from a backup, or its keys are in use elsewhere): not pushing".into()
        }
    }
}

impl Daemon {
    /// Pulls from and pushes to `vault`'s remote, then collects behind its
    /// base checkpoint, and persists the anchor.
    pub(in crate::daemon) async fn remote_sync(&self, vault: VaultId) -> Result<RemoteReport> {
        let (saved, mut anchor, me) = self.with(|s| {
            let saved = load(s, &vault)?.ok_or_else(|| {
                anyhow::anyhow!("no remote for this vault: run `deadbolt remote set`")
            })?;
            Ok((saved, load_anchor(s, &vault)?, s.id))
        })?;
        let store = Remote::open(&saved.remote)?;
        let report = self.sync_with(&store, vault, me, &mut anchor).await;
        self.with(|s| {
            // Whatever was accepted stays accepted, even when a step failed.
            save_anchor(s, &vault, &anchor)?;
            if report.is_ok()
                && let Some(mut saved) = load(s, &vault)?
            {
                saved.last_sync = Some(now());
                save(s, &vault, Some(&saved))?;
            }
            Ok(())
        })?;
        report
    }

    pub(in crate::daemon) async fn sync_with<S: ObjStore + Sync>(
        &self,
        store: &S,
        vault: VaultId,
        me: DeviceId,
        anchor: &mut SyncAnchor,
    ) -> Result<RemoteReport> {
        let mut report = RemoteReport {
            vault: vault.to_string(),
            ..RemoteReport::default()
        };
        let own: BTreeMap<(LogKind, u64), FrameId> = self.with(|s| {
            let v = s
                .vaults
                .get(&vault)
                .ok_or_else(|| anyhow::anyhow!("vault not held"))?;
            Ok(v.frames()
                .filter(|f| f.header().author == me)
                .map(|f| ((f.header().kind.log_kind(), f.header().seq), f.id()))
                .collect())
        })?;
        let mut anomalies = Vec::new();
        let mut rolled_back = false;
        for anomaly in check_self_rollback(store, &vault, &me, anchor).await? {
            // Own frames above the acknowledged tip that are this replica's
            // (a lost acknowledgement, or a peer pushing them on our behalf)
            // only advance the anchor in the pull below.
            if let RemoteAnomaly::SelfRollback(r) = &anomaly
                && r.conflicting.is_none()
                && self_frames_match(store, anchor, &me, &own, &r.remote_ahead).await?
            {
                continue;
            }
            rolled_back |= matches!(anomaly, RemoteAnomaly::SelfRollback(_));
            anomalies.push(anomaly);
        }
        let plan = plan_pull(store, &vault, anchor, None).await?;
        anomalies.extend(plan.anomalies.iter().cloned());
        let mut fetched = BTreeMap::new();
        for path in plan.fetch.iter().chain(&plan.verify) {
            if let Some(bytes) = store.get(&path.to_name(), None).await? {
                fetched.insert(*path, bytes);
            }
        }
        let local = |log, seq| own.get(&(log, seq)).copied();
        let judged = plan.judge(&vault, anchor, &me, local, &fetched);
        anomalies.extend(judged.anomalies.iter().cloned());
        let (frames, proofs) = (&judged.frames, &judged.proofs);
        report.proofs = proofs.len();

        let checkpoints: Vec<FrameId> = frames
            .iter()
            .filter(|f| f.header().kind == FrameKind::Checkpoint)
            .map(|f| f.id())
            .collect();
        let before = frames.len();
        let applied = self.with(|s| {
            let n = s.apply_fetched(vault, frames.clone(), proofs.clone())?;
            s.save_proofs(&vault)?;
            s.judge_checkpoints(vault)?;
            self.refresh(s);
            Ok(n)
        })?;
        report.pulled = applied.min(before);

        // Checkpoints: adopt each undisputed frontier, and the pack when the
        // covered frames are gone from this device and the store.
        for id in checkpoints {
            let found = self.with(|s| {
                let v = &s.vaults[&vault];
                let Some((f, payload)) = v.checkpoints().find(|(f, _)| f.id == id) else {
                    return Ok(None);
                };
                let frontier = payload.frontier_map();
                if v.is_disputed(&id) || v.contradicts(&frontier) {
                    return Ok(None);
                }
                let needs_pack = !v.holds_frontier(&frontier);
                let site = PackSite {
                    vault,
                    author: f.author,
                    seq: f.seq,
                    epoch: f.epoch,
                    key: v
                        .epoch_key(&f.epoch)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("no key"))?,
                };
                let collected =
                    !needs_pack || collected_behind(v, &plan.index, anchor, f, payload, me);
                Ok(Some((
                    frontier.clone(),
                    payload.pack_hash,
                    needs_pack,
                    collected,
                    site,
                )))
            })?;
            let Some((frontier, pack_hash, needs_pack, collected, site)) = found else {
                continue;
            };
            if needs_pack {
                let name = RemotePath::Pack {
                    vault,
                    hash: pack_hash,
                }
                .to_name();
                if !collected {
                    anomalies.push(RemoteAnomaly::Mismatched {
                        name,
                        reason: "a checkpoint covers frames the store still lists or never showed",
                    });
                    continue;
                }
                let Some(sealed) = store.get(&name, None).await? else {
                    anomalies.push(RemoteAnomaly::Mismatched {
                        name,
                        reason: "a checkpoint's pack is missing",
                    });
                    continue;
                };
                let adopted = self.with(|s| {
                    let pack = crate::disk::open_pack(&sealed, vault, &|e| {
                        s.vaults[&vault].epoch_key(e).cloned()
                    })?;
                    if !s.vaults[&vault].verify_base(&id, &pack, &sealed) {
                        return Ok(false);
                    }
                    s.adopt_pack(vault, id, pack, &sealed, &site)?;
                    Ok(true)
                })?;
                if !adopted {
                    anomalies.push(RemoteAnomaly::Mismatched {
                        name,
                        reason: "a pack its checkpoint does not commit to",
                    });
                    continue;
                }
            }
            match anchor.adopt_checkpoint(&frontier) {
                Ok(()) => report.checkpoints += 1,
                Err(anomaly) => anomalies.push(anomaly),
            }
        }
        // Only what the vault took: a frame it refused (its signer not yet
        // admitted, say) must be fetched again once it can be.
        let held: BTreeSet<FrameId> = self.with(|s| {
            let v = &s.vaults[&vault];
            Ok(frames
                .iter()
                .map(|f| f.id())
                .filter(|id| v.frame(id).is_some())
                .collect())
        })?;
        for frame in frames.iter().filter(|f| held.contains(&f.id())) {
            if let Err(anomaly) = anchor.observe(frame) {
                anomalies.push(anomaly);
            }
        }
        for proof in proofs {
            anchor.note_fraud(proof.proof_hash());
        }
        anomalies.extend(plan.confirm_deferred(anchor));
        anomalies.extend(judged.confirm_deferred(anchor));

        if !rolled_back {
            self.publish(store, vault, anchor, &mut report, &mut anomalies)
                .await?;
            // What the store holds now, the push included.
            let missing: BTreeSet<String> = plan
                .fetch
                .iter()
                .chain(&plan.verify)
                .filter(|path| !fetched.contains_key(path))
                .map(RemotePath::to_name)
                .collect();
            let names: Vec<String> = store
                .list(&area_prefix(&vault, Area::Data), None)
                .await?
                .into_iter()
                .filter(|name| !missing.contains(name))
                .collect();
            let index = deadbolt_remote::RemoteIndex::from_names(&vault, &names);
            anomalies.extend(self.with(|s| {
                let clocks = s.vaults[&vault].member_clocks();
                Ok(withheld(clocks.values(), &index, &anchor.compacted))
            })?);
            report.collected = self.collect(store, vault, anchor, &index).await?;
        }
        report.anomalies = anomalies.iter().map(describe).collect();
        Ok(report)
    }

    /// Pushes every frame the store hasn't shown above its anchored tip
    /// (this device's, and any other member's it holds: the root's genesis,
    /// a peer that never reaches the store), never one behind a collected
    /// checkpoint, plus the local pack a pushed checkpoint commits to and
    /// every fraud proof the store lacks.
    async fn publish<S: ObjStore + Sync>(
        &self,
        store: &S,
        vault: VaultId,
        anchor: &mut SyncAnchor,
        report: &mut deadbolt_proto::daemon::RemoteReport,
        anomalies: &mut Vec<RemoteAnomaly>,
    ) -> Result<()> {
        let listed: BTreeSet<String> = store
            .list(&area_prefix(&vault, Area::Pack), None)
            .await?
            .into_iter()
            .collect();
        let pack_listed =
            |hash: [u8; 32]| listed.contains(&RemotePath::Pack { vault, hash }.to_name());
        // A base the store lacks the pack of (a fresh store, a recovered
        // vault whose pack this device re-sealed): the frames it covers are
        // gone from here, so cover them with a checkpoint of this device's
        // own, whose pack it holds byte for byte.
        self.with(|s| {
            let v = &s.vaults[&vault];
            let Some(base) = base_pack_hash(v) else {
                return Ok(());
            };
            let local = s
                .store
                .load_pack(vault)?
                .map(|b| PackCommitment::of(&b).hash);
            if !pack_listed(base) && local != Some(base) && v.is_member(&s.id) {
                s.checkpoint(vault)?;
            }
            Ok(())
        })?;
        let outbox = self.with(|s| {
            let v = &s.vaults[&vault];
            let local = s.store.load_pack(vault)?;
            let local_hash = local.as_ref().map(|b| PackCommitment::of(b).hash);
            // This device's own older checkpoints its base covers, whose packs
            // are gone: the base stands in for them, so they aren't pushed.
            let base_me = v
                .base_checkpoint()
                .and_then(|id| v.checkpoints().find(|(f, _)| f.id == id))
                .and_then(|(_, p)| p.frontier_map().get(&s.id).map(|(seq, _)| *seq));
            let superseded: BTreeSet<FrameId> = v
                .checkpoints()
                .filter(|(f, p)| {
                    f.author == s.id
                        && Some(p.pack_hash) != local_hash
                        && !pack_listed(p.pack_hash)
                        && base_me.is_some_and(|seq| f.seq <= seq)
                })
                .map(|(f, _)| f.id)
                .collect();
            let frames: Vec<_> = v
                .frames()
                .filter(|f| {
                    let h = f.header();
                    let log = h.kind.log_kind();
                    let collected = log == LogKind::Data
                        && anchor.compacted.get(&h.author).is_some_and(|c| h.seq <= *c);
                    !collected
                        && !superseded.contains(&f.id())
                        && anchor
                            .tip(log, &h.author)
                            .is_none_or(|(seq, _)| h.seq > seq)
                })
                .cloned()
                .collect();
            // The pack of every checkpoint pushed, and the base's if the
            // store lacks it.
            let mut wanted: BTreeSet<[u8; 32]> = v
                .checkpoints()
                .filter(|(f, _)| frames.iter().any(|x| x.id() == f.id))
                .map(|(_, p)| p.pack_hash)
                .collect();
            wanted.extend(base_pack_hash(v).filter(|h| !pack_listed(*h)));
            let mut packs = Vec::new();
            if let (Some(sealed), Some(hash)) = (local, local_hash)
                && wanted.contains(&hash)
            {
                packs.push((hash, sealed));
            }
            let frauds = v
                .proofs()
                .iter()
                .filter(|p| !anchor.frauds.contains(&p.proof_hash()))
                .cloned()
                .collect();
            Ok(Outbox {
                blobs: Vec::new(),
                packs,
                frauds,
                frames,
            })
        })?;
        let frames = outbox.frames.clone();
        let frauds: Vec<[u8; 32]> = outbox.frauds.iter().map(FraudProof::proof_hash).collect();
        let plan = plan_push(&vault, outbox)?;
        let pushed = push(store, &plan).await?;
        report.pushed = pushed.created + pushed.repaired;
        if let Some(stop) = pushed.stopped {
            anomalies.push(stop);
            return Ok(());
        }
        let mut frames = frames;
        frames.sort_by_key(|f| {
            let h = f.header();
            (h.kind.log_kind(), h.author, h.seq)
        });
        for frame in &frames {
            if let Err(anomaly) = anchor.observe(frame) {
                anomalies.push(anomaly);
            }
        }
        for hash in frauds {
            anchor.note_fraud(hash);
        }
        Ok(())
    }

    /// Deletes the store's data frames behind the base checkpoint once
    /// every current member's clock covers it (`plan_gc`). Only the base's
    /// own checkpoint can be the GC base: counted, undisputed, and with its
    /// pack on the store, so whoever recovers later can fold from it.
    async fn collect<S: ObjStore + Sync>(
        &self,
        store: &S,
        vault: VaultId,
        anchor: &mut SyncAnchor,
        index: &deadbolt_remote::RemoteIndex,
    ) -> Result<usize> {
        let now_ms = now().saturating_mul(1000);
        let packs = store.list(&area_prefix(&vault, Area::Pack), None).await?;
        let gc = self.with(|s| {
            let v = &s.vaults[&vault];
            let (Some(base), Some(base_id)) = (v.base(), v.base_checkpoint()) else {
                return Ok(None);
            };
            let stored =
                |hash: [u8; 32]| packs.contains(&RemotePath::Pack { vault, hash }.to_name());
            let checkpoints: Vec<GcCheckpoint> = v
                .checkpoints()
                .filter(|(f, p)| f.id == base_id && !v.is_disputed(&f.id) && stored(p.pack_hash))
                .filter(|(_, p)| p.frontier_map() == base.meta.frontier)
                .map(|(f, _)| GcCheckpoint {
                    id: f.id,
                    author: f.author,
                    seq: f.seq,
                    // No grace: only full coverage collects.
                    first_seen_ms: now_ms,
                    meta: base.meta.clone(),
                })
                .collect();
            let listed = |author: &DeviceId, seq: u64| {
                index
                    .streams
                    .get(&(LogKind::Data, *author))
                    .is_some_and(|s| s.contains_key(&seq))
            };
            let frames: Vec<(GcFrame, FrameKind)> = v
                .frames()
                .filter(|f| f.header().kind.log_kind() == LogKind::Data)
                .filter(|f| listed(&f.header().author, f.header().seq))
                .map(|f| {
                    let h = f.header();
                    (
                        GcFrame {
                            id: f.id(),
                            author: h.author,
                            seq: h.seq,
                        },
                        h.kind,
                    )
                })
                .collect();
            let gc_frames: Vec<GcFrame> = frames.iter().map(|(f, _)| *f).collect();
            let plan = plan_gc(
                now_ms,
                v.membership(),
                &v.member_clocks(),
                &checkpoints,
                v.disputes(),
                &gc_frames,
                &anchor.compacted,
            );
            if plan.base.is_none() {
                return Ok(None);
            }
            let delete: BTreeSet<FrameId> = plan.delete_frames.into_iter().collect();
            let names: Vec<String> = frames
                .iter()
                .filter(|(f, _)| delete.contains(&f.id))
                .map(|(f, kind)| RemotePath::frame(vault, *kind, f.author, f.seq).to_name())
                .collect();
            Ok(Some((base.meta.frontier.clone(), names)))
        })?;
        let Some((frontier, names)) = gc else {
            return Ok(0);
        };
        // Adopt first: once deleted, their absence must be no alarm.
        if anchor.adopt_checkpoint(&frontier).is_err() {
            return Ok(0);
        }
        for name in &names {
            store.delete(name).await?;
        }
        Ok(names.len())
    }
}

/// Whether a pack may stand in for the data frames checkpoint `f` covers:
/// the store shows some covered frame this device lacks is gone (collected),
/// every frontier seq is evidenced by something the checkpoint's author
/// doesn't control (the store's listing of another author's stream, the
/// anchor, this device's frames, another member's clock), and every member
/// that already existed when it was made, this device included once it has
/// synced, has signed that it saw it (GC never collects before they all
/// have). Membership heads that can't be the checkpoint's own refuse it. A full replica whose covered frames are
/// all still listed never trades its history for a pack.
pub(super) fn collected_behind(
    v: &deadbolt_core::Vault,
    index: &deadbolt_remote::RemoteIndex,
    anchor: &SyncAnchor,
    f: &deadbolt_core::v2::DataFrame,
    payload: &deadbolt_core::v2::CheckpointPayload,
    me: DeviceId,
) -> bool {
    let author = f.author;
    let frontier = payload.frontier_map();
    let held: BTreeSet<(DeviceId, u64)> = v
        .frames()
        .filter(|f| f.header().kind.log_kind() == LogKind::Data)
        .map(|f| (f.header().author, f.header().seq))
        .collect();
    let listed = |a: &DeviceId, seq: u64| {
        index
            .streams
            .get(&(LogKind::Data, *a))
            .is_some_and(|s| s.contains_key(&seq))
    };
    let clocks = v.member_clocks();
    let cited = |a: &DeviceId| {
        clocks
            .iter()
            .filter(|(m, _)| **m != author)
            .filter_map(|(_, c)| c.get(a).checked_sub(1))
            .max()
    };
    let evidenced = frontier.iter().all(|(a, (seq, _))| {
        [
            // The author lists its own stream as it likes: no evidence.
            index.tip(LogKind::Data, a).filter(|_| *a != author),
            anchor.tip(LogKind::Data, a).map(|(s, _)| s),
            anchor.compacted.get(a).copied(),
            held.iter().filter(|(x, _)| x == a).map(|(_, s)| *s).max(),
            cited(a),
        ]
        .into_iter()
        .flatten()
        .any(|bound| bound >= *seq)
    });
    let gone = frontier
        .iter()
        .any(|(a, (seq, _))| (0..=*seq).any(|s| !held.contains(&(*a, s)) && !listed(a, s)));
    let Some(before) = v.members_before(f, payload) else {
        return false;
    };
    let acked = before
        .iter()
        .filter(|m| **m != author)
        .all(|m| v.acked(m, &author, f.seq));
    // Once this device has synced with the store, GC can't collect behind
    // the checkpoint until this device itself has acked it.
    let mine = anchor.seen.is_empty() || !v.is_member(&me) || v.acked(&me, &author, f.seq);
    evidenced && gone && acked && mine
}

/// The pack hash of the checkpoint `v`'s base belongs to.
fn base_pack_hash(v: &deadbolt_core::Vault) -> Option<[u8; 32]> {
    let id = v.base_checkpoint()?;
    v.checkpoints()
        .find(|(f, _)| f.id == id)
        .map(|(_, p)| p.pack_hash)
}

/// Whether every own frame the store holds above the anchor is this
/// replica's own.
async fn self_frames_match<S: ObjStore + Sync>(
    store: &S,
    anchor: &SyncAnchor,
    me: &DeviceId,
    own: &BTreeMap<(LogKind, u64), FrameId>,
    ahead: &[RemotePath],
) -> Result<bool> {
    for path in ahead {
        let Some(bytes) = store.get(&path.to_name(), None).await? else {
            continue;
        };
        let local = |log, seq| own.get(&(log, seq)).copied();
        if check_fetched_as(anchor, me, local, path, &bytes).is_err() {
            return Ok(false);
        }
    }
    Ok(true)
}
