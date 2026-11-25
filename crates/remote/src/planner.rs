//! The sync planner (Fable §3.3–3.4): what to push and pull, in which
//! order, and what a store's answers prove about it.
//!
//! - [`SyncAnchor`] remembers the newest `(seq, FrameId)` this device has
//!   accepted from every stream. A LIST that shows less, or a different
//!   frame at that `seq`, is [`RemoteAnomaly::RemoteRegressed`].
//! - [`check_withholding`]: a decrypted clock citing `(B, s)` while the
//!   store lists B only below `s` is [`RemoteAnomaly::Withheld`].
//! - [`check_self_rollback`] and [`push`]: a device restored from a backup
//!   finds its own stream ahead of it, or its own name holding another frame.
//!
//! A zero-state device still cannot tell one store rolling the whole vault
//! back to an older consistent cut; recovery shows the newest signed state
//! for the human to judge.

mod pull;
mod push;

pub use pull::{PullPlan, RecoveryPlan, plan_pull, plan_recovery_bootstrap};
pub use push::{
    Outbox, OwnTips, PushPlan, PushReport, PushStep, PushStop, SelfRollback, check_self_rollback,
    plan_push, push,
};

use std::collections::BTreeMap;

use deadbolt_core::v2::{Frame, FrameId, FrameKind, LogKind};
use deadbolt_core::{DeviceId, VaultId};

use crate::error::RemoteError;
use crate::path::RemotePath;

/// One author's append-only stream in one log.
pub type StreamKey = (LogKind, DeviceId);

/// What this device has accepted from the remote, persisted with its sealed
/// local state so a rolled-back store is caught on the next pull.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncAnchor {
    /// The newest accepted frame of every stream.
    pub seen: BTreeMap<StreamKey, (u64, FrameId)>,
    /// Data frames at or below these seqs are covered by an accepted
    /// checkpoint and may be garbage-collected, so their absence is no alarm.
    pub compacted: BTreeMap<DeviceId, u64>,
}

const ANCHOR_VERSION: u8 = 1;

impl SyncAnchor {
    /// The newest accepted frame of a stream.
    pub fn tip(&self, log: LogKind, author: &DeviceId) -> Option<(u64, FrameId)> {
        self.seen.get(&(log, *author)).copied()
    }

    /// Records an accepted frame. A frame at the anchored `seq` with another
    /// id is refused as a regression; older frames leave the anchor alone.
    pub fn observe(&mut self, frame: &Frame) -> Result<(), RemoteAnomaly> {
        let header = frame.header();
        let key = (header.kind.log_kind(), header.author);
        match self.seen.get(&key) {
            Some(&(seq, id)) if seq == header.seq && id != frame.id() => {
                Err(RemoteAnomaly::RemoteRegressed {
                    log: key.0,
                    author: key.1,
                    expected_seq: seq,
                    expected_id: id,
                    observed: Observed::Different(frame.id()),
                })
            }
            Some(&(seq, _)) if seq >= header.seq => Ok(()),
            _ => {
                self.seen.insert(key, (header.seq, frame.id()));
                Ok(())
            }
        }
    }

    /// Raises the compaction floor to an accepted checkpoint's frontier.
    pub fn note_compacted(&mut self, frontier: impl IntoIterator<Item = (DeviceId, u64)>) {
        for (author, seq) in frontier {
            let floor = self.compacted.entry(author).or_insert(seq);
            *floor = (*floor).max(seq);
        }
    }

    fn may_be_gone(&self, log: LogKind, author: &DeviceId, seq: u64) -> bool {
        log == LogKind::Data
            && self
                .compacted
                .get(author)
                .is_some_and(|&floor| seq <= floor)
    }

    /// A compact binary encoding for the sealed local state.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.seen.len() * 73 + self.compacted.len() * 40);
        out.push(ANCHOR_VERSION);
        out.extend_from_slice(&(self.seen.len() as u32).to_be_bytes());
        for ((log, author), (seq, id)) in &self.seen {
            out.push(match log {
                LogKind::Member => 0,
                LogKind::Data => 1,
            });
            out.extend_from_slice(author.as_bytes());
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(id.as_bytes());
        }
        out.extend_from_slice(&(self.compacted.len() as u32).to_be_bytes());
        for (author, seq) in &self.compacted {
            out.extend_from_slice(author.as_bytes());
            out.extend_from_slice(&seq.to_be_bytes());
        }
        out
    }

    /// Decodes [`encode`](Self::encode)'s output.
    pub fn decode(bytes: &[u8]) -> Result<Self, RemoteError> {
        let bad = || RemoteError::Protocol("malformed sync anchor".into());
        let mut r = Cursor(bytes);
        if r.take::<1>().ok_or_else(bad)?[0] != ANCHOR_VERSION {
            return Err(bad());
        }
        let mut anchor = Self::default();
        for _ in 0..u32::from_be_bytes(r.take().ok_or_else(bad)?) {
            let log = match r.take::<1>().ok_or_else(bad)?[0] {
                0 => LogKind::Member,
                1 => LogKind::Data,
                _ => return Err(bad()),
            };
            let author = DeviceId::from_bytes(r.take().ok_or_else(bad)?);
            let seq = u64::from_be_bytes(r.take().ok_or_else(bad)?);
            let id = FrameId::from_bytes(r.take().ok_or_else(bad)?);
            anchor.seen.insert((log, author), (seq, id));
        }
        for _ in 0..u32::from_be_bytes(r.take().ok_or_else(bad)?) {
            let author = DeviceId::from_bytes(r.take().ok_or_else(bad)?);
            let seq = u64::from_be_bytes(r.take().ok_or_else(bad)?);
            anchor.compacted.insert(author, seq);
        }
        if !r.0.is_empty() {
            return Err(bad());
        }
        Ok(anchor)
    }
}

struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*head)
    }
}

/// What the store showed where the anchor expected a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    /// The stream lists nothing at the anchored `seq`; `max_seq` is the
    /// highest it does list.
    Missing { max_seq: Option<u64> },
    /// The object at the anchored `seq` is another valid frame.
    Different(FrameId),
}

/// Something a store did that an honest store never does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteAnomaly {
    /// A stream lost frames this device had accepted, or swapped one: the
    /// store was rolled back or wiped. Alarm, then re-push from the replica.
    RemoteRegressed {
        log: LogKind,
        author: DeviceId,
        expected_seq: u64,
        expected_id: FrameId,
        observed: Observed,
    },
    /// A frame cites `(author, required_seq)` but the store lists the
    /// author's data stream only up to `remote_max_seq`.
    Withheld {
        author: DeviceId,
        required_seq: u64,
        remote_max_seq: Option<u64>,
    },
    /// The object under `name` is not the frame its name says: it fails
    /// to verify, is truncated, or names another vault, author or `seq`.
    Mismatched { name: String, reason: &'static str },
}

/// Every frame name a set of LISTs returned, by stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteIndex {
    /// Listed `seq`s of every stream, with the frame kind the name implies.
    pub streams: BTreeMap<StreamKey, BTreeMap<u64, FrameKind>>,
    /// Listed fraud proofs.
    pub frauds: Vec<RemotePath>,
    /// Listed names that are not canonical objects of this vault.
    pub ignored: Vec<String>,
}

impl RemoteIndex {
    /// Sorts listed names by stream.
    pub fn from_names<'a>(vault: &VaultId, names: impl IntoIterator<Item = &'a String>) -> Self {
        let mut index = Self::default();
        for name in names {
            index.add(vault, name);
        }
        index
    }

    pub(crate) fn add(&mut self, vault: &VaultId, name: &str) {
        match RemotePath::parse(name) {
            Ok(path) if path.vault() != vault => self.ignored.push(name.to_owned()),
            Ok(RemotePath::Frame {
                kind, author, seq, ..
            }) => {
                self.streams
                    .entry((kind.log_kind(), author))
                    .or_default()
                    .insert(seq, kind);
            }
            Ok(path @ RemotePath::Fraud { .. }) => self.frauds.push(path),
            Ok(_) | Err(_) => self.ignored.push(name.to_owned()),
        }
    }

    /// The highest listed `seq` of a stream.
    pub fn tip(&self, log: LogKind, author: &DeviceId) -> Option<u64> {
        self.streams
            .get(&(log, *author))
            .and_then(|seqs| seqs.keys().next_back().copied())
    }

    /// The highest listed `seq` of every stream in one log.
    pub fn tips(&self, log: LogKind) -> BTreeMap<DeviceId, u64> {
        self.streams
            .iter()
            .filter(|((l, _), _)| *l == log)
            .filter_map(|((_, author), seqs)| Some((*author, *seqs.keys().next_back()?)))
            .collect()
    }

    /// The name of a listed frame.
    pub fn path(
        &self,
        vault: &VaultId,
        log: LogKind,
        author: &DeviceId,
        seq: u64,
    ) -> Option<RemotePath> {
        let kind = *self.streams.get(&(log, *author))?.get(&seq)?;
        Some(RemotePath::frame(*vault, kind, *author, seq))
    }
}

/// Compares listed streams with the anchor: every anchored frame must
/// still be listed, unless a checkpoint let it be collected. `listed`
/// says which streams the LISTs covered.
pub fn check_regressions(
    anchor: &SyncAnchor,
    index: &RemoteIndex,
    listed: impl Fn(&StreamKey) -> bool,
) -> Vec<RemoteAnomaly> {
    anchor
        .seen
        .iter()
        .filter(|(key, _)| listed(key))
        .filter_map(|(&(log, author), &(seq, id))| {
            let seqs = index.streams.get(&(log, author));
            if seqs.is_some_and(|s| s.contains_key(&seq)) || anchor.may_be_gone(log, &author, seq) {
                return None;
            }
            Some(RemoteAnomaly::RemoteRegressed {
                log,
                author,
                expected_seq: seq,
                expected_id: id,
                observed: Observed::Missing {
                    max_seq: index.tip(log, &author),
                },
            })
        })
        .collect()
}

/// Checks a fetched object against its name and the anchor: it must be a
/// verifying frame of this vault, author, log, kind and `seq`, and the
/// anchored frame where the anchor has one at that `seq`.
pub fn check_fetched(
    anchor: &SyncAnchor,
    path: &RemotePath,
    bytes: &[u8],
) -> Result<Frame, RemoteAnomaly> {
    let mismatched = |reason| RemoteAnomaly::Mismatched {
        name: path.to_name(),
        reason,
    };
    let RemotePath::Frame {
        vault,
        kind,
        author,
        seq,
    } = *path
    else {
        return Err(mismatched("not a frame name"));
    };
    let frame = Frame::decode(bytes).map_err(|_| mismatched("does not verify as a frame"))?;
    let h = frame.header();
    if h.vault != vault || h.author != author || h.seq != seq || h.kind != kind {
        return Err(mismatched("frame header disagrees with its name"));
    }
    match anchor.tip(kind.log_kind(), &author) {
        Some((anchored, id)) if anchored == seq && id != frame.id() => {
            Err(RemoteAnomaly::RemoteRegressed {
                log: kind.log_kind(),
                author,
                expected_seq: seq,
                expected_id: id,
                observed: Observed::Different(frame.id()),
            })
        }
        _ => Ok(frame),
    }
}

/// Every `(author, seq)` a decrypted clock cites must be listed by the
/// store (or compacted). A peer relaying over iroh can legitimately run
/// ahead of the store for a moment, so callers re-list before alarming.
pub fn check_withholding(
    referenced_clock: impl IntoIterator<Item = (DeviceId, u64)>,
    remote_listed_tips: &BTreeMap<DeviceId, u64>,
    compacted: &BTreeMap<DeviceId, u64>,
) -> Vec<RemoteAnomaly> {
    referenced_clock
        .into_iter()
        .filter(|(author, seq)| {
            let listed = remote_listed_tips.get(author).is_some_and(|tip| tip >= seq);
            let collected = compacted.get(author).is_some_and(|floor| floor >= seq);
            !listed && !collected
        })
        .map(|(author, required_seq)| RemoteAnomaly::Withheld {
            author,
            required_seq,
            remote_max_seq: remote_listed_tips.get(&author).copied(),
        })
        .collect()
}
