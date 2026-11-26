//! `recover`: rebuilding a vault on this device from its 24 words and its
//! store alone (Fable §2.5), with no other device and no local state.
//!
//! ```text
//! LIST m/ d/ x/ -> plan_recovery_bootstrap     no Member holes, or refuse
//! GET every Member frame and fraud proof
//! for each checkpoint, newest first:
//!   open it as the root (R_kem unwraps its epoch), GET p/<pack_hash>,
//!   keep it if the pack is what it commits to and no member disputed it
//! GET the data tail above its frontier (everything with no checkpoint)
//! the root must be these words' (R_sign), never a rotated-away kit
//! as the root: Add(this device), then Remove(old)+Rotate for every member
//! push the root's frames                 a failure installs nothing: run it again
//! save the remote, and an anchor of every frame above seen
//! store it, sign this device's card, remote-sync
//! ```
//!
//! A push that failed part way leaves some of the root's frames on the
//! store: the next attempt folds them in and builds on them (an `Add`
//! already there isn't made twice).

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use deadbolt_core::v2::{Frame, FrameId, FraudProof, Pack};
use deadbolt_core::{DeviceId, PackSite, Vault, VaultId, recovery};
use deadbolt_proto::daemon::RemoteInput;
use deadbolt_remote::path::area_prefix;
use deadbolt_remote::{
    Area, ObjStore, Outbox, RemoteIndex, RemotePath, SyncAnchor, check_fetched,
    check_fetched_fraud, plan_push, plan_recovery_bootstrap, push, withheld,
};

use super::super::session::unhex;
use super::sync::describe;
use super::{Daemon, Remote, Saved, save, save_anchor};
use crate::protocol::{Reply, Secret};

/// A checkpoint chosen as the recovered vault's base.
struct Base {
    checkpoint: FrameId,
    /// What it covers: every author's newest frame in its pack.
    frontier: BTreeMap<DeviceId, (u64, FrameId)>,
    pack: Pack,
    sealed: Vec<u8>,
    site: PackSite,
}

impl Daemon {
    pub(super) async fn recover(
        &self,
        vault: &str,
        words: &Secret,
        remote: RemoteInput,
    ) -> Result<Reply> {
        let id = self.install_recovered(vault, words, remote).await?;
        match self.remote_sync(id).await {
            Ok(report) => {
                for line in &report.anomalies {
                    tracing::warn!(vault = %id, "{line}");
                }
            }
            // The vault is installed: the background sync tries again,
            // unless this session can no longer trust what it committed.
            Err(error) => {
                self.with(|s| s.ensure_usable())?;
                tracing::warn!(vault = %id, "the first sync after recovery failed: {error:#}");
            }
        }
        self.sync_now.notify_one();
        Ok(Reply::Vault {
            vault: self.with(|s| Ok(s.vault_info(&id)))?,
        })
    }

    /// `recover` up to its first remote sync: rebuilds the vault from the
    /// store, publishes the root's frames, then installs it here with its
    /// remote and an anchor of everything the store showed.
    pub(super) async fn install_recovered(
        &self,
        vault: &str,
        words: &Secret,
        remote: RemoteInput,
    ) -> Result<VaultId> {
        let vault = VaultId::from_bytes(unhex(vault).context("a vault id is 64 hex digits")?);
        let root = recovery::decode(words.expose())
            .map_err(|e| anyhow!("reading the recovery kit: {e}"))?;
        let held = |s: &super::Session| {
            s.available(vault)?;
            if s.contains_vault(&vault) {
                bail!("this device already holds that vault");
            }
            Ok(())
        };
        self.with(|s| held(s))?;
        let store = Remote::open(&remote)?;
        let (frames, base, proofs) = rebuild(&store, vault, &root).await?;
        let mut v = Vault::open_as(root.recovery_id(), &root.kem_secret(), frames)
            .context("the store's frames do not open as this vault")?;
        // Proofs before anything is judged or signed on this fold.
        v.add_proofs(proofs.iter().cloned());
        if v.recovery_root() != Some(root.recovery_id()) {
            bail!("these words are not this vault's current recovery kit");
        }
        if let Some(base) = &base
            && !v.adopt_base(base.checkpoint, base.pack.clone(), &base.sealed)
        {
            bail!("the store's checkpoint does not hold for this vault");
        }

        let root_frames = self.with(|s| {
            let author = s.author();
            let me = author.id();
            let kem = author.keys().kem_public();
            let consent = author.join_consent(&vault, &root.recovery_id());
            // An earlier attempt's push may have admitted this device already.
            let admitted = v.is_member(&me);
            let old: Vec<_> = v.members().filter(|d| *d != me).collect();
            let mut made = Vec::new();
            v.transact(
                |w| {
                    if !admitted {
                        w.add_signed(&root.signing_key(), me, kem, consent)?;
                    }
                    for device in old {
                        w.remove_by_root(&root, device)?;
                    }
                    // Every epoch this device must read, from the root
                    // (several concurrent tips when no member was left).
                    w.root_reader_duty(&root)?;
                    Ok::<_, anyhow::Error>(())
                },
                |_, frames| {
                    made.extend(frames.iter().map(|f| (*f).clone()));
                    Ok(())
                },
            )?;
            Ok(made)
        })?;
        // The root's frames are no device's own stream: push them here, and
        // before anything is stored, so a failure leaves nothing to undo.
        if !root_frames.is_empty() {
            let plan = plan_push(
                &vault,
                Outbox {
                    frames: root_frames,
                    ..Outbox::default()
                },
            )?;
            let pushed = push(&store, &plan).await?;
            if let Some(stop) = pushed.stopped {
                bail!("publishing the recovery: {}", describe(&stop));
            }
        }
        let anchor = seen(&v, base.as_ref().map(|b| &b.frontier), &proofs);

        self.with(|s| {
            held(s)?;
            // The remote and its anchor first: once the frames are stored,
            // everything a sync needs to carry on is too.
            let saved = Saved {
                remote,
                last_sync: None,
            };
            save(s, &vault, Some(&saved))?;
            save_anchor(s, &vault, &anchor)?;
            let frames: Vec<Frame> = v.frames().cloned().collect();
            let base = base.map(|b| (b.checkpoint, b.pack, b.sealed, b.site));
            let adopted = s.adopt_recovered(frames, base, proofs);
            // Nothing stored (certainly: an uncertain append may have
            // landed): forget the remote too, for a clean retry.
            if adopted.is_err() && !s.append_uncertain && !s.contains_vault(&vault) {
                let forgot = save(s, &vault, None)
                    .and_then(|()| save_anchor(s, &vault, &SyncAnchor::default()));
                if let Err(error) = forgot {
                    tracing::warn!(vault = %vault, "{error:#}");
                }
            }
            let id = adopted?;
            self.refresh(s);
            Ok(id)
        })
    }
}

/// What the store showed this recovery, as a sync anchor: the base's
/// frontier, then every frame of the rebuilt fold (the root's, just
/// pushed, too), stream by stream, and every proof. The first sync then
/// fetches only what is new.
fn seen(
    v: &Vault,
    frontier: Option<&BTreeMap<DeviceId, (u64, FrameId)>>,
    proofs: &[FraudProof],
) -> SyncAnchor {
    let mut anchor = SyncAnchor::default();
    if let Some(frontier) = frontier
        && let Err(anomaly) = anchor.adopt_checkpoint(frontier)
    {
        tracing::warn!(vault = %v.id(), "{}", describe(&anomaly));
    }
    let mut frames: Vec<&Frame> = v.frames().collect();
    frames.sort_by_key(|f| {
        let h = f.header();
        (h.kind.log_kind(), h.author, h.seq)
    });
    for frame in frames {
        // A stream that doesn't chain is left for the sync to fetch.
        if let Err(anomaly) = anchor.observe(frame) {
            tracing::debug!(vault = %v.id(), "{}", describe(&anomaly));
        }
    }
    for proof in proofs {
        anchor.note_fraud(proof.proof_hash());
    }
    anchor
}

/// Every frame a recovery needs from `store`, and the base checkpoint
/// they fold onto.
async fn rebuild<S: ObjStore + Sync>(
    store: &S,
    vault: VaultId,
    root: &deadbolt_core::v2::RecoverySecret,
) -> Result<(Vec<Frame>, Option<Base>, Vec<FraudProof>)> {
    let list = |area| async move { store.list(&area_prefix(&vault, area), None).await };
    let (m, d, x) = (
        list(Area::Member).await?,
        list(Area::Data).await?,
        list(Area::Fraud).await?,
    );
    let plan = plan_recovery_bootstrap(&vault, &m, &d, &x)?;
    let index = RemoteIndex::from_names(&vault, &d);
    if let Some(hole) = plan.anomalies.first() {
        bail!("the store is withholding membership: {}", describe(hole));
    }
    let empty = SyncAnchor::default();
    let mut members = Vec::new();
    for path in &plan.members {
        members.push(fetch_frame(store, &empty, path).await?);
    }
    let mut proofs: Vec<FraudProof> = Vec::new();
    for path in &plan.frauds {
        if let Some(bytes) = store.get(&path.to_name(), None).await?
            && let Ok(proof) = check_fetched_fraud(&vault, path, &bytes)
        {
            proofs.push(proof);
        }
    }
    let open = |frames: Vec<Frame>| -> Result<Vault> {
        let mut v = Vault::open_as(root.recovery_id(), &root.kem_secret(), frames)?;
        v.add_proofs(proofs.iter().cloned());
        Ok(v)
    };
    for path in &plan.checkpoints {
        let Ok(checkpoint) = fetch_frame(store, &empty, path).await else {
            continue;
        };
        let id = checkpoint.id();
        let mut probe = members.clone();
        probe.push(checkpoint);
        let v = open(probe)?;
        let Some((f, payload)) = v.checkpoints().find(|(f, _)| f.id == id) else {
            continue;
        };
        let Some(key) = v.epoch_key(&f.epoch).cloned() else {
            continue;
        };
        let site = PackSite {
            vault,
            author: f.author,
            seq: f.seq,
            epoch: f.epoch,
            key,
        };
        let covered = payload.frontier_map();
        let frontier: BTreeMap<_, _> = covered.iter().map(|(a, (seq, _))| (*a, *seq)).collect();
        let name = RemotePath::Pack {
            vault,
            hash: payload.pack_hash,
        }
        .to_name();
        let Some(sealed) = store.get(&name, None).await? else {
            continue;
        };
        let Ok(pack) = crate::disk::open_pack(&sealed, vault, &|e| v.epoch_key(e).cloned()) else {
            continue;
        };
        if !v.pack_matches(&id, &pack, &sealed) {
            continue;
        }
        // A tail the store hides part of (a `Dispute`, say) can't vouch
        // for this checkpoint: try an older one.
        let tail = plan.tail(&frontier);
        if let Some(hole) = tail.holes.first() {
            tracing::warn!(vault = %vault, "{}", describe(hole));
            continue;
        }
        let mut frames = members.clone();
        let mut torn = false;
        for path in &tail.frames {
            match fetch_frame(store, &empty, path).await {
                Ok(frame) => frames.push(frame),
                Err(error) => {
                    tracing::warn!(vault = %vault, "{error:#}");
                    torn = true;
                    break;
                }
            }
        }
        if torn {
            continue;
        }
        let mut whole = open(frames.clone())?;
        if !whole.adopt_base(id, pack.clone(), &sealed) {
            continue;
        }
        if let Some(withheld) = withheld(whole.member_clocks().values(), &index, &frontier).first()
        {
            tracing::warn!(vault = %vault, "{}", describe(withheld));
            continue;
        }
        let base = Base {
            checkpoint: id,
            frontier: covered,
            pack,
            sealed,
            site,
        };
        return Ok((frames, Some(base), proofs));
    }
    // No usable checkpoint: everything from genesis.
    let tail = plan.tail(&BTreeMap::new());
    if let Some(hole) = tail.holes.first() {
        bail!("the store is withholding data: {}", describe(hole));
    }
    let mut frames = members;
    for path in &tail.frames {
        frames.push(fetch_frame(store, &empty, path).await?);
    }
    let whole = open(frames.clone())?;
    if let Some(withheld) =
        withheld(whole.member_clocks().values(), &index, &BTreeMap::new()).first()
    {
        bail!("the store is withholding data: {}", describe(withheld));
    }
    Ok((frames, None, proofs))
}

async fn fetch_frame<S: ObjStore + Sync>(
    store: &S,
    anchor: &SyncAnchor,
    path: &RemotePath,
) -> Result<Frame> {
    let bytes = store
        .get(&path.to_name(), None)
        .await?
        .with_context(|| format!("{} is listed but gone", path.to_name()))?;
    check_fetched(anchor, path, &bytes).map_err(|a| anyhow!(describe(&a)))
}
