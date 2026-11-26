//! Pull: list `m/`, then `d/`, then `x/` (the membership-before-data
//! barrier), compare with the anchor, and name the objects to fetch.

use std::collections::{BTreeMap, BTreeSet};

use deadbolt_core::v2::{Frame, FrameId, FraudProof, LogKind};
use deadbolt_core::{DeviceId, VaultId};

use super::index::first_hole;
use super::{
    Observed, RemoteAnomaly, RemoteIndex, StreamKey, SyncAnchor, Twin, check_fetched,
    check_fetched_as, check_fetched_fraud, confirm_missing, resolve_twin,
};
use crate::error::RemoteError;
use crate::path::{Area, RemotePath, area_prefix, stream_cursor, stream_prefix};
use crate::store::ObjStore;

/// What one pull found and what to fetch next.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullPlan {
    /// Everything the LISTs returned.
    pub index: RemoteIndex,
    /// Objects newer than the anchor, to GET and apply in this order: every
    /// Member frame, then every Data and Checkpoint frame, each stream
    /// ascending (a twin's `<seq>` before its `<seq>.c`), then the fraud
    /// proofs the anchor does not know yet.
    pub fetch: Vec<RemotePath>,
    /// The anchored tip of every listed stream, to GET and pass through
    /// [`check_fetched`](super::check_fetched) when the caller wants proof
    /// the store did not swap it.
    pub verify: Vec<RemotePath>,
    /// Positions listed as both `<seq>` and `<seq>.c`: both names are in
    /// `fetch` or `verify`; judge each pair with
    /// [`resolve_twin`](super::resolve_twin) instead of applying both.
    pub twins: Vec<(RemotePath, RemotePath)>,
    /// What the LISTs already prove, an anchored frame missing from them only
    /// once a direct GET agrees ([`confirm_missing`]).
    pub anomalies: Vec<RemoteAnomaly>,
    /// Missing anchored data frames that a checkpoint in `fetch` may have
    /// let the store collect. Adopt the checkpoints that verify, then call
    /// [`confirm_deferred`](Self::confirm_deferred).
    pub deferred: Vec<RemoteAnomaly>,
}

/// What a pull's fetched objects turned out to be ([`PullPlan::judge`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Judged {
    /// Frames that verify under their names, to apply in this order: every
    /// Member frame, then each data stream ascending.
    pub frames: Vec<Frame>,
    /// Fetched fraud proofs, and each twin's whose frames both verify.
    pub proofs: Vec<FraudProof>,
    pub anomalies: Vec<RemoteAnomaly>,
}

impl PullPlan {
    /// Judges what was fetched for this plan by `me` (`fetched`, by name;
    /// what the store no longer had is skipped): each twin folds to one
    /// frame or a fraud proof ([`resolve_twin`]), every other frame passes
    /// [`check_fetched_as`] (`local` as there), every proof
    /// [`check_fetched_fraud`], and every anchored tip in `verify`
    /// [`check_fetched`].
    pub fn judge(
        &self,
        vault: &VaultId,
        anchor: &SyncAnchor,
        me: &DeviceId,
        local: impl Fn(LogKind, u64) -> Option<FrameId>,
        fetched: &BTreeMap<RemotePath, Vec<u8>>,
    ) -> Judged {
        let mut out = Judged::default();
        let twinned: BTreeSet<RemotePath> = self.twins.iter().flat_map(|(a, b)| [*a, *b]).collect();
        for (bare, checkpoint) in &self.twins {
            let (Some(a), Some(b)) = (fetched.get(bare), fetched.get(checkpoint)) else {
                continue;
            };
            match resolve_twin((bare, a), (checkpoint, b)) {
                Ok(Twin::Fraud(proof)) => out.proofs.push(*proof),
                Ok(Twin::One(frame)) => out.frames.push(*frame),
                Err(anomaly) => out.anomalies.push(anomaly),
            }
        }
        for path in self.fetch.iter().filter(|p| !twinned.contains(p)) {
            let Some(bytes) = fetched.get(path) else {
                continue;
            };
            let judged = match path {
                RemotePath::Fraud { .. } => {
                    check_fetched_fraud(vault, path, bytes).map(|proof| out.proofs.push(proof))
                }
                _ => check_fetched_as(anchor, me, &local, path, bytes)
                    .map(|frame| out.frames.push(frame)),
            };
            if let Err(anomaly) = judged {
                out.anomalies.push(anomaly);
            }
        }
        for path in self.verify.iter().filter(|p| !twinned.contains(p)) {
            if let Some(bytes) = fetched.get(path)
                && let Err(anomaly) = check_fetched(anchor, path, bytes)
            {
                out.anomalies.push(anomaly);
            }
        }
        out.frames.sort_by_key(|f| {
            let h = f.header();
            (h.kind.log_kind(), h.author, h.seq)
        });
        out
    }

    /// The deferred regressions no adopted checkpoint explains.
    pub fn confirm_deferred(&self, anchor: &SyncAnchor) -> Vec<RemoteAnomaly> {
        self.deferred
            .iter()
            .filter(|anomaly| match anomaly {
                RemoteAnomaly::RemoteRegressed {
                    log,
                    author,
                    expected_seq,
                    ..
                } => !anchor.may_be_gone(*log, author, *expected_seq),
                _ => true,
            })
            .cloned()
            .collect()
    }
}

/// The two halves of [`check_regressions`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Regressions {
    /// Regressions nothing listed can explain.
    pub anomalies: Vec<RemoteAnomaly>,
    /// Missing data frames an unseen listed checkpoint might cover.
    pub deferred: Vec<RemoteAnomaly>,
}

/// Compares listed streams with the anchor: every anchored frame must
/// still be listed, unless an accepted checkpoint let it be collected. A LIST
/// can lag a PUT the store acknowledged, so pass both halves through
/// [`confirm_missing`] before alarming ([`plan_pull`] does).
/// A missing data frame is deferred, not alarmed, while the index lists a
/// checkpoint this device has not seen yet, since that checkpoint may
/// legitimately cover it. `listed` says which streams the LISTs covered.
pub fn check_regressions(
    anchor: &SyncAnchor,
    index: &RemoteIndex,
    listed: impl Fn(&StreamKey) -> bool,
) -> Regressions {
    let unseen_checkpoint = index.streams.iter().any(|(&(log, author), seqs)| {
        log == LogKind::Data
            && seqs.iter().any(|(&seq, s)| {
                s.checkpoint && anchor.tip(log, &author).is_none_or(|(a, _)| seq > a)
            })
    });
    let mut out = Regressions::default();
    for (&(log, author), &(seq, id)) in &anchor.seen {
        if !listed(&(log, author)) {
            continue;
        }
        let seqs = index.streams.get(&(log, author));
        if seqs.is_some_and(|s| s.contains_key(&seq)) || anchor.may_be_gone(log, &author, seq) {
            continue;
        }
        let anomaly = RemoteAnomaly::RemoteRegressed {
            log,
            author,
            expected_seq: seq,
            expected_id: id,
            observed: Observed::Missing {
                max_seq: index.tip(log, &author),
            },
        };
        if log == LogKind::Data && unseen_checkpoint {
            out.deferred.push(anomaly);
        } else {
            out.anomalies.push(anomaly);
        }
    }
    out
}

/// Lists the store and plans a pull.
///
/// `m/` and `x/` are always listed whole (Member frames are few and never
/// compacted, so a hole in one is an anomaly). `d/` is listed whole when
/// `data_authors` is `None`, the discovery pull; otherwise only those
/// authors' streams, plus every data stream the anchor knows, each from its
/// anchored `seq` on, so a steady pull costs one LIST page per stream.
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
    let Regressions {
        anomalies,
        deferred,
    } = check_regressions(anchor, &index, |_| true);
    let mut anomalies = confirm_missing(store, vault, anomalies).await?;
    // A GET that finds another frame is a swap no checkpoint explains.
    let (swapped, deferred): (Vec<_>, Vec<_>) = confirm_missing(store, vault, deferred)
        .await?
        .into_iter()
        .partition(|a| {
            matches!(
                a,
                RemoteAnomaly::RemoteRegressed {
                    observed: Observed::Different(_),
                    ..
                }
            )
        });
    anomalies.extend(swapped);
    for (&(log, author), seqs) in &index.streams {
        if log != LogKind::Member {
            continue;
        }
        if let Some(missing_seq) = first_hole(seqs.keys().copied(), 0) {
            anomalies.push(RemoteAnomaly::StreamHole {
                log,
                author,
                missing_seq,
                max_seq: seqs.keys().next_back().copied().unwrap_or_default(),
            });
        }
    }
    let listed_frauds: BTreeSet<[u8; 32]> = index
        .frauds
        .iter()
        .filter_map(|p| match p {
            RemotePath::Fraud { hash, .. } => Some(*hash),
            _ => None,
        })
        .collect();
    anomalies.extend(
        anchor
            .frauds
            .difference(&listed_frauds)
            .map(|&hash| RemoteAnomaly::FraudWiped { hash }),
    );

    let mut fetch = Vec::new();
    let mut verify = Vec::new();
    let mut twins = Vec::new();
    for (&(log, author), seqs) in &index.streams {
        let anchored = anchor.tip(log, &author).map(|(seq, _)| seq);
        for (&seq, spellings) in seqs {
            if anchored.is_some_and(|a| seq < a) {
                continue;
            }
            let paths = spellings.paths(*vault, log, author, seq);
            if let [bare, checkpoint] = paths[..] {
                twins.push((bare, checkpoint));
            }
            if anchored == Some(seq) {
                verify.extend(paths);
            } else {
                fetch.extend(paths);
            }
        }
    }
    // LogKind orders Member before Data in the index, so `fetch` is
    // already m/ then d/; new proofs go last.
    fetch.extend(index.frauds.iter().copied().filter(|p| match p {
        RemotePath::Fraud { hash, .. } => !anchor.frauds.contains(hash),
        _ => false,
    }));
    Ok(PullPlan {
        index,
        fetch,
        verify,
        twins,
        anomalies,
        deferred,
    })
}
