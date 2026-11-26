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
//! store it, sign this device's card, push the root's frames, remote-sync
//! ```

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use deadbolt_core::v2::{Frame, FraudProof, Pack};
use deadbolt_core::{PackSite, Vault, VaultId, recovery};
use deadbolt_proto::daemon::RemoteInput;
use deadbolt_remote::path::area_prefix;
use deadbolt_remote::{
    Area, ObjStore, Outbox, RemotePath, SyncAnchor, check_fetched, check_fetched_fraud, plan_push,
    plan_recovery_bootstrap, push,
};

use super::super::session::unhex;
use super::sync::describe;
use super::{Daemon, Remote, Saved, save, save_anchor};
use crate::protocol::{Reply, Secret};

/// A checkpoint chosen as the recovered vault's base.
struct Base {
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
        let vault = VaultId::from_bytes(unhex(vault).context("a vault id is 64 hex digits")?);
        let root = recovery::decode(words.expose())
            .map_err(|e| anyhow!("reading the recovery kit: {e}"))?;
        self.with(|s| {
            if s.vaults.contains_key(&vault) {
                bail!("this device already holds that vault");
            }
            Ok(())
        })?;
        let store = Remote::open(&remote)?;
        let (frames, base, proofs) = rebuild(&store, vault, &root).await?;
        let mut v = Vault::open_as(root.recovery_id(), &root.kem_secret(), frames)
            .context("the store's frames do not open as this vault")?;
        if v.recovery_root() != Some(root.recovery_id()) {
            bail!("these words are not this vault's current recovery kit");
        }
        if let Some(base) = &base {
            v.set_base(base.pack.clone());
        }

        let (id, root_frames) = self.with(|s| {
            let author = s.author();
            let me = author.id();
            let kem = author.keys().kem_public();
            let consent = author.join_consent(&vault, &root.recovery_id());
            let old: Vec<_> = v.members().filter(|d| *d != me).collect();
            let mut made = Vec::new();
            v.transact(
                |w| {
                    w.add_signed(&root.signing_key(), me, kem, consent)?;
                    for device in old {
                        w.remove_by_root(&root, device)?;
                    }
                    Ok::<_, anyhow::Error>(())
                },
                |_, frames| {
                    made.extend(frames.iter().map(|f| (*f).clone()));
                    Ok(())
                },
            )?;
            let frames: Vec<Frame> = v.frames().cloned().collect();
            let id = s.adopt_recovered(frames, base.map(|b| (b.pack, b.sealed, b.site)))?;
            if let Some(held) = s.vaults.get_mut(&id) {
                held.add_proofs(proofs);
            }
            s.save_proofs(&id)?;
            save(
                s,
                &id,
                Some(&Saved {
                    remote,
                    last_sync: None,
                }),
            )?;
            save_anchor(s, &id, &SyncAnchor::default())?;
            self.refresh(s);
            Ok((id, made))
        })?;
        // The root's frames are no device's own stream: push them here.
        let plan = plan_push(
            &id,
            Outbox {
                frames: root_frames,
                ..Outbox::default()
            },
        )?;
        let pushed = push(&store, &plan).await?;
        if let Some(stop) = pushed.stopped {
            bail!("publishing the recovery: {}", describe(&stop));
        }
        let report = self.remote_sync(id).await?;
        for line in &report.anomalies {
            tracing::warn!(vault = %id, "{line}");
        }
        self.sync_now.notify_one();
        Ok(Reply::Vault {
            vault: self.with(|s| Ok(s.vault_info(&id)))?,
        })
    }
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
        let frontier: BTreeMap<_, _> = payload
            .frontier_map()
            .into_iter()
            .map(|(a, (seq, _))| (a, seq))
            .collect();
        let name = RemotePath::Pack {
            vault,
            hash: payload.pack_hash,
        }
        .to_name();
        let Some(sealed) = store.get(&name, None).await? else {
            continue;
        };
        let Ok(pack) = crate::disk::open_pack(&sealed, &|e| v.epoch_key(e).cloned()) else {
            continue;
        };
        if !v.pack_matches(&id, &pack, &sealed) {
            continue;
        }
        let tail = plan.tail(&frontier);
        let mut frames = members.clone();
        for path in &tail.frames {
            if let Ok(frame) = fetch_frame(store, &empty, path).await {
                frames.push(frame);
            }
        }
        let mut whole = open(frames.clone())?;
        whole.set_base(pack.clone());
        if whole.is_disputed(&id) {
            continue;
        }
        for hole in &tail.holes {
            tracing::warn!(vault = %vault, "{}", describe(hole));
        }
        return Ok((frames, Some(Base { pack, sealed, site }), proofs));
    }
    // No usable checkpoint: everything from genesis.
    let tail = plan.tail(&BTreeMap::new());
    let mut frames = members;
    for path in &tail.frames {
        frames.push(fetch_frame(store, &empty, path).await?);
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
