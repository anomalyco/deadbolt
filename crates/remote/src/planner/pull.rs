//! Pull: list `m/`, then `d/`, then `x/` (the membership-before-data
//! barrier), compare with the anchor, and name the frames to fetch. Also
//! the zero-state recovery bootstrap, which needs nothing but LIST.

use std::collections::{BTreeMap, BTreeSet};

use deadbolt_core::v2::{FrameKind, LogKind};
use deadbolt_core::{DeviceId, VaultId};

use super::{RemoteAnomaly, RemoteIndex, SyncAnchor, check_regressions};
use crate::error::RemoteError;
use crate::path::{Area, RemotePath, area_prefix, stream_cursor, stream_prefix};
use crate::store::ObjStore;

/// What one pull found and what to fetch next.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullPlan {
    /// Everything the LISTs returned.
    pub index: RemoteIndex,
    /// Frames newer than the anchor, to GET and apply in this order: every
    /// Member frame, then every Data and Checkpoint frame, each stream
    /// ascending, then the fraud proofs.
    pub fetch: Vec<RemotePath>,
    /// The anchored tip of every listed stream, to GET and pass through
    /// [`check_fetched`](super::check_fetched) when the caller wants proof
    /// the store did not swap it.
    pub verify: Vec<RemotePath>,
    /// What the LISTs already prove.
    pub anomalies: Vec<RemoteAnomaly>,
}

/// Lists the store and plans a pull.
///
/// `m/` and `x/` are always listed whole (Member frames are few and never
/// compacted). `d/` is listed whole when `data_authors` is `None`, the
/// discovery pull; otherwise only those authors' streams, plus every data
/// stream the anchor knows, each from its anchored `seq` on, so a steady
/// pull costs one LIST page per stream.
pub async fn plan_pull<S: ObjStore>(
    store: &S,
    vault: &VaultId,
    anchor: &SyncAnchor,
    data_authors: Option<&BTreeSet<DeviceId>>,
) -> Result<PullPlan, RemoteError> {
    let mut index = RemoteIndex::default();
    for name in store.list(&area_prefix(vault, Area::Member), None).await? {
        index.add(vault, &name);
    }
    match data_authors {
        None => {
            for name in store.list(&area_prefix(vault, Area::Data), None).await? {
                index.add(vault, &name);
            }
        }
        Some(authors) => {
            let known = anchor
                .seen
                .keys()
                .filter(|(log, _)| *log == LogKind::Data)
                .map(|(_, author)| author);
            let streams: BTreeSet<&DeviceId> = authors.iter().chain(known).collect();
            for author in streams {
                let from = anchor.tip(LogKind::Data, author).map_or(0, |(seq, _)| seq);
                let after = stream_cursor(vault, LogKind::Data, author, from);
                let prefix = stream_prefix(vault, LogKind::Data, author);
                for name in store.list(&prefix, after.as_deref()).await? {
                    index.add(vault, &name);
                }
            }
        }
    }
    for name in store.list(&area_prefix(vault, Area::Fraud), None).await? {
        index.add(vault, &name);
    }

    // Every stream the anchor knows was listed: Member and fraud areas
    // whole, and each anchored data stream from its anchored seq.
    let anomalies = check_regressions(anchor, &index, |_| true);
    let mut fetch = Vec::new();
    let mut verify = Vec::new();
    for (&(log, author), seqs) in &index.streams {
        let anchored = anchor.tip(log, &author).map(|(seq, _)| seq);
        for (&seq, &kind) in seqs {
            let path = RemotePath::frame(*vault, kind, author, seq);
            match anchored {
                Some(a) if seq < a => {}
                Some(a) if seq == a => verify.push(path),
                _ => fetch.push(path),
            }
        }
    }
    // LogKind orders Member before Data in the index, so `fetch` is
    // already m/ then d/; proofs go last.
    fetch.extend(index.frauds.iter().copied());
    Ok(PullPlan {
        index,
        fetch,
        verify,
        anomalies,
    })
}

/// What a device with zero local state fetches to rebuild a vault from the
/// recovery words and the store (Fable §2.5 steps 2–4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryPlan {
    /// Every Member frame, each stream ascending: resolve these first.
    pub members: Vec<RemotePath>,
    /// Each author's newest checkpoint, highest `seq` first. The caller
    /// opens them, keeps the newest undisputed frontier and fetches its pack.
    pub checkpoints: Vec<RemotePath>,
    /// Holes in Member streams (never compacted, so a hole is withholding).
    pub anomalies: Vec<RemoteAnomaly>,
    data: BTreeMap<DeviceId, BTreeMap<u64, FrameKind>>,
    vault: Option<VaultId>,
}

impl RecoveryPlan {
    /// The first checkpoint candidate.
    pub fn checkpoint(&self) -> Option<&RemotePath> {
        self.checkpoints.first()
    }

    /// The data tail above a checkpoint's frontier (every frame when the
    /// frontier omits an author), each stream ascending.
    pub fn tail(&self, frontier: &BTreeMap<DeviceId, u64>) -> Vec<RemotePath> {
        let Some(vault) = self.vault else {
            return Vec::new();
        };
        self.data
            .iter()
            .flat_map(|(author, seqs)| {
                let floor = frontier.get(author).copied();
                seqs.iter()
                    .filter(move |(seq, _)| floor.is_none_or(|f| **seq > f))
                    .map(move |(&seq, &kind)| RemotePath::frame(vault, kind, *author, seq))
            })
            .collect()
    }
}

/// Plans a zero-state recovery from `LIST <vault>/m/` and `LIST <vault>/d/`
/// alone: no head pointer, device id or locator secret.
pub fn plan_recovery_bootstrap(
    vault: &VaultId,
    listed_m: &[String],
    listed_d: &[String],
) -> Result<RecoveryPlan, RemoteError> {
    let index = RemoteIndex::from_names(vault, listed_m.iter().chain(listed_d));
    let mut plan = RecoveryPlan {
        vault: Some(*vault),
        ..RecoveryPlan::default()
    };
    for (&(log, author), seqs) in &index.streams {
        match log {
            LogKind::Member => {
                let max = seqs.keys().next_back().copied().unwrap_or_default();
                if let Some(hole) = (0..=max).find(|s| !seqs.contains_key(s)) {
                    plan.anomalies.push(RemoteAnomaly::Withheld {
                        author,
                        required_seq: hole,
                        remote_max_seq: Some(max),
                    });
                }
                plan.members.extend(
                    seqs.iter()
                        .map(|(&seq, &kind)| RemotePath::frame(*vault, kind, author, seq)),
                );
            }
            LogKind::Data => {
                if let Some((&seq, _)) = seqs
                    .iter()
                    .rev()
                    .find(|(_, kind)| **kind == FrameKind::Checkpoint)
                {
                    plan.checkpoints.push(RemotePath::frame(
                        *vault,
                        FrameKind::Checkpoint,
                        author,
                        seq,
                    ));
                }
                plan.data.insert(author, seqs.clone());
            }
        }
    }
    if plan.members.is_empty() {
        return Err(RemoteError::Plan(
            "no Member frames under this vault: wrong vault id, bucket or root".into(),
        ));
    }
    plan.checkpoints
        .sort_by(|a, b| seq_of(b).cmp(&seq_of(a)).then(a.cmp(b)));
    Ok(plan)
}

fn seq_of(path: &RemotePath) -> u64 {
    match path {
        RemotePath::Frame { seq, .. } => *seq,
        _ => 0,
    }
}
