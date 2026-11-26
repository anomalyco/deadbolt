//! `remote-sync`: one pass of the blind-store protocol for one vault.
//!
//! ```text
//! check_self_rollback      own streams moved without us? then pull only
//! plan_pull                LIST m/, d/, x/ against the anchor
//!   GET + check_fetched_as every frame; resolve_twin each <seq>/<seq>.c pair
//!   check_fetched_fraud    every new x/<proof_hash>
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
    Area, ObjStore, Outbox, RemoteAnomaly, RemotePath, SyncAnchor, Twin, check_fetched,
    check_fetched_as, check_fetched_fraud, check_self_rollback, plan_pull, plan_push, push,
    resolve_twin,
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
        let mut frames = Vec::new();
        let mut proofs: Vec<FraudProof> = Vec::new();
        let twinned: BTreeSet<RemotePath> = plan.twins.iter().flat_map(|(a, b)| [*a, *b]).collect();
        for (bare, checkpoint) in &plan.twins {
            let (Some(a), Some(b)) = (fetched.get(bare), fetched.get(checkpoint)) else {
                continue;
            };
            match resolve_twin((bare, a), (checkpoint, b)) {
                Ok(Twin::Fraud(proof)) => proofs.push(*proof),
                Ok(Twin::One(frame)) => frames.push(*frame),
                Err(anomaly) => anomalies.push(anomaly),
            }
        }
        for path in &plan.fetch {
            let Some(bytes) = fetched.get(path) else {
                continue;
            };
            if twinned.contains(path) {
                continue;
            }
            match path {
                RemotePath::Fraud { .. } => match check_fetched_fraud(&vault, path, bytes) {
                    Ok(proof) => proofs.push(proof),
                    Err(anomaly) => anomalies.push(anomaly),
                },
                _ => match check_fetched_as(
                    anchor,
                    &me,
                    |log, seq| own.get(&(log, seq)).copied(),
                    path,
                    bytes,
                ) {
                    Ok(frame) => frames.push(frame),
                    Err(anomaly) => anomalies.push(anomaly),
                },
            }
        }
        for path in &plan.verify {
            if let Some(bytes) = fetched.get(path)
                && !twinned.contains(path)
                && let Err(anomaly) = check_fetched(anchor, path, bytes)
            {
                anomalies.push(anomaly);
            }
        }
        // Member frames first, then each data stream ascending, as listed.
        frames.sort_by_key(|f| {
            let h = f.header();
            (h.kind.log_kind(), h.author, h.seq)
        });
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
                if v.is_disputed(&id) {
                    return Ok(None);
                }
                let frontier = payload.frontier_map();
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
                Ok(Some((
                    frontier.clone(),
                    payload.pack_hash,
                    !v.holds_frontier(&frontier),
                    site,
                )))
            })?;
            let Some((frontier, pack_hash, needs_pack, site)) = found else {
                continue;
            };
            if needs_pack {
                let name = RemotePath::Pack {
                    vault,
                    hash: pack_hash,
                }
                .to_name();
                let Some(sealed) = store.get(&name, None).await? else {
                    anomalies.push(RemoteAnomaly::Mismatched {
                        name,
                        reason: "a checkpoint's pack is missing",
                    });
                    continue;
                };
                let adopted = self.with(|s| {
                    let pack = crate::disk::open_pack(&sealed, &|e| {
                        s.vaults[&vault].epoch_key(e).cloned()
                    })?;
                    if !s.vaults[&vault].pack_matches(&id, &pack, &sealed) {
                        return Ok(false);
                    }
                    s.adopt_pack(vault, pack, &sealed, &site)?;
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
        for frame in &frames {
            if let Err(anomaly) = anchor.observe(frame) {
                anomalies.push(anomaly);
            }
        }
        for proof in &proofs {
            anchor.note_fraud(proof.proof_hash());
        }
        anomalies.extend(plan.confirm_deferred(anchor));

        if !rolled_back {
            self.publish(store, vault, anchor, &mut report, &mut anomalies)
                .await?;
            report.collected = self.collect(store, vault, anchor).await?;
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
        let outbox = self.with(|s| {
            let v = &s.vaults[&vault];
            let frames: Vec<_> = v
                .frames()
                .filter(|f| {
                    let h = f.header();
                    let log = h.kind.log_kind();
                    let collected = log == LogKind::Data
                        && anchor.compacted.get(&h.author).is_some_and(|c| h.seq <= *c);
                    !collected
                        && anchor
                            .tip(log, &h.author)
                            .is_none_or(|(seq, _)| h.seq > seq)
                })
                .cloned()
                .collect();
            let wanted: BTreeSet<[u8; 32]> = v
                .checkpoints()
                .filter(|(f, _)| frames.iter().any(|x| x.id() == f.id))
                .map(|(_, p)| p.pack_hash)
                .collect();
            let mut packs = Vec::new();
            if !wanted.is_empty()
                && let Some(sealed) = s.store.load_pack(vault)?
            {
                let hash = PackCommitment::of(&sealed).hash;
                if wanted.contains(&hash) {
                    packs.push((hash, sealed));
                }
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
    /// every current member's clock covers it (`plan_gc`). Only a
    /// checkpoint whose pack this device holds can be the base.
    async fn collect<S: ObjStore + Sync>(
        &self,
        store: &S,
        vault: VaultId,
        anchor: &mut SyncAnchor,
    ) -> Result<usize> {
        let now_ms = now().saturating_mul(1000);
        // What the store holds now, the push included.
        let names = store.list(&area_prefix(&vault, Area::Data), None).await?;
        let index = &deadbolt_remote::RemoteIndex::from_names(&vault, &names);
        let gc = self.with(|s| {
            let v = &s.vaults[&vault];
            let Some(base) = v.base() else {
                return Ok(None);
            };
            let checkpoints: Vec<GcCheckpoint> = v
                .checkpoints()
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
