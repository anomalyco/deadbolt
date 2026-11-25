//! [`SyncAnchor`]: what this device has accepted from the remote.

use std::collections::{BTreeMap, BTreeSet};

use deadbolt_core::DeviceId;
use deadbolt_core::v2::{Frame, FrameId, LogKind};

use super::{Observed, RemoteAnomaly, StreamKey};
use crate::error::RemoteError;

/// What this device has accepted from the remote, persisted with its sealed
/// local state so a rolled-back store is caught on the next pull.
///
/// Own frames count too: observe every own frame once its push lands, so
/// [`check_self_rollback`](super::check_self_rollback) compares the store
/// with what it acknowledged rather than with unpushed local edits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncAnchor {
    /// The newest accepted frame of every stream.
    pub seen: BTreeMap<StreamKey, (u64, FrameId)>,
    /// Data frames at or below these seqs are covered by an accepted
    /// checkpoint and may be garbage-collected, so their absence is no alarm.
    pub compacted: BTreeMap<DeviceId, u64>,
    /// `proof_hash`es of every accepted fraud proof (`x/<hash>`): known
    /// proofs are not fetched again, and one that vanishes is an alarm.
    pub frauds: BTreeSet<[u8; 32]>,
}

const ANCHOR_VERSION: u8 = 2;

impl SyncAnchor {
    /// The newest accepted frame of a stream.
    pub fn tip(&self, log: LogKind, author: &DeviceId) -> Option<(u64, FrameId)> {
        self.seen.get(&(log, *author)).copied()
    }

    /// Records a verified frame. The anchor only moves one `seq` at a time
    /// along `prev`: an unanchored stream starts at `seq` 0, and the next
    /// frame must sit at `anchored + 1` and link to the anchored id. A
    /// different frame at the anchored `seq` is a regression; an older frame
    /// leaves the anchor alone. A stream whose prefix was collected starts
    /// from [`adopt_checkpoint`](Self::adopt_checkpoint) instead.
    pub fn observe(&mut self, frame: &Frame) -> Result<(), RemoteAnomaly> {
        let h = frame.header();
        let (log, author) = (h.kind.log_kind(), h.author);
        let id = frame.id();
        let anchored = self.tip(log, &author);
        match anchored {
            Some((seq, expected)) if seq == h.seq => {
                if expected == id {
                    Ok(())
                } else {
                    Err(RemoteAnomaly::RemoteRegressed {
                        log,
                        author,
                        expected_seq: seq,
                        expected_id: expected,
                        observed: Observed::Different(id),
                    })
                }
            }
            Some((seq, _)) if h.seq < seq => Ok(()),
            Some((seq, expected)) if seq.checked_add(1) == Some(h.seq) => {
                if h.prev != expected {
                    return Err(RemoteAnomaly::ChainBroken {
                        log,
                        author,
                        seq: h.seq,
                        expected_prev: expected,
                        observed_prev: h.prev,
                    });
                }
                self.seen.insert((log, author), (h.seq, id));
                Ok(())
            }
            None if h.seq == 0 => {
                self.seen.insert((log, author), (0, id));
                Ok(())
            }
            _ => Err(RemoteAnomaly::StreamGap {
                log,
                author,
                anchored_seq: anchored.map(|(seq, _)| seq),
                observed_seq: h.seq,
            }),
        }
    }

    /// Adopts a verified checkpoint's frontier (`PackMeta::frontier`):
    /// every data stream it covers is anchored at its frontier frame, and
    /// frames at or below it may be collected from now on. Refuses, and
    /// changes nothing, when the frontier names another frame at a `seq`
    /// this anchor already holds.
    pub fn adopt_checkpoint(
        &mut self,
        frontier: &BTreeMap<DeviceId, (u64, FrameId)>,
    ) -> Result<(), RemoteAnomaly> {
        for (&author, &(seq, id)) in frontier {
            if let Some((anchored, expected)) = self.tip(LogKind::Data, &author)
                && anchored == seq
                && expected != id
            {
                return Err(RemoteAnomaly::RemoteRegressed {
                    log: LogKind::Data,
                    author,
                    expected_seq: seq,
                    expected_id: expected,
                    observed: Observed::Different(id),
                });
            }
        }
        for (&author, &(seq, id)) in frontier {
            let floor = self.compacted.entry(author).or_insert(seq);
            *floor = (*floor).max(seq);
            let tip = self
                .seen
                .entry((LogKind::Data, author))
                .or_insert((seq, id));
            if tip.0 < seq {
                *tip = (seq, id);
            }
        }
        Ok(())
    }

    /// Records an accepted fraud proof's `proof_hash`.
    pub fn note_fraud(&mut self, hash: [u8; 32]) {
        self.frauds.insert(hash);
    }

    pub(crate) fn may_be_gone(&self, log: LogKind, author: &DeviceId, seq: u64) -> bool {
        log == LogKind::Data
            && self
                .compacted
                .get(author)
                .is_some_and(|&floor| seq <= floor)
    }

    /// A compact binary encoding for the sealed local state.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            13 + self.seen.len() * 73 + self.compacted.len() * 40 + self.frauds.len() * 32,
        );
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
        out.extend_from_slice(&(self.frauds.len() as u32).to_be_bytes());
        for hash in &self.frauds {
            out.extend_from_slice(hash);
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
        for _ in 0..u32::from_be_bytes(r.take().ok_or_else(bad)?) {
            anchor.frauds.insert(r.take().ok_or_else(bad)?);
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
