//! What a peer lacks: per-stream heads and the frames above them.

use std::collections::BTreeMap;

use crate::error::DecodeError;
use crate::id::DeviceId;
use crate::v2::{Frame, FrameId, LogKind};

use super::Vault;

/// Bytes of one encoded stream head: log, author, count and tip.
const ENTRY_LEN: usize = 1 + 32 + 8 + 32;

/// How many frames this device holds from the start of each author's
/// membership and data streams, without a gap, and the id of the last of
/// them (its tip). Two devices holding the same count with different tips
/// hold different frames at one seq: an equivocation, which each must see.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Heads(BTreeMap<(LogKind, DeviceId), (u64, FrameId)>);

impl Heads {
    pub fn get(&self, log: LogKind, author: &DeviceId) -> u64 {
        self.0.get(&(log, *author)).map_or(0, |(n, _)| *n)
    }

    /// The id of the last frame counted in `author`'s `log` stream.
    pub fn tip(&self, log: LogKind, author: &DeviceId) -> Option<FrameId> {
        self.0.get(&(log, *author)).map(|(_, tip)| *tip)
    }

    /// The membership streams alone: what a peer that may only push
    /// membership is told.
    pub fn members_only(&self) -> Self {
        Self(
            self.0
                .iter()
                .filter(|((log, _), _)| *log == LogKind::Member)
                .map(|(k, v)| (*k, *v))
                .collect(),
        )
    }

    pub fn iter(&self) -> impl Iterator<Item = (LogKind, DeviceId, u64)> + '_ {
        self.0
            .iter()
            .map(|((log, author), (n, _))| (*log, *author, *n))
    }

    /// `n:u32 (log:u8 author:32 count:u64 tip:32)*`, sorted.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.0.len() * ENTRY_LEN);
        out.extend_from_slice(&(self.0.len() as u32).to_be_bytes());
        for ((log, author), (n, tip)) in &self.0 {
            out.push(match log {
                LogKind::Member => 0,
                LogKind::Data => 1,
            });
            out.extend_from_slice(author.as_bytes());
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(tip.as_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (n, mut rest) = bytes
            .split_first_chunk::<4>()
            .ok_or(DecodeError::UnexpectedEnd)?;
        let n = u32::from_be_bytes(*n) as usize;
        let want = n.checked_mul(ENTRY_LEN).ok_or(DecodeError::UnexpectedEnd)?;
        if rest.len() != want {
            return Err(if rest.len() < want {
                DecodeError::UnexpectedEnd
            } else {
                DecodeError::TrailingBytes
            });
        }
        let mut out = BTreeMap::new();
        let mut last = None;
        for _ in 0..n {
            let (head, tail) = rest.split_at(ENTRY_LEN);
            rest = tail;
            let log = match head[0] {
                0 => LogKind::Member,
                1 => LogKind::Data,
                tag => return Err(DecodeError::InvalidTag(tag)),
            };
            let mut author = [0; 32];
            author.copy_from_slice(&head[1..33]);
            let mut count = [0; 8];
            count.copy_from_slice(&head[33..41]);
            let mut tip = [0; 32];
            tip.copy_from_slice(&head[41..73]);
            let key = (log, DeviceId::from_bytes(author));
            if last.is_some_and(|l| l >= key) {
                return Err(DecodeError::NotCanonical);
            }
            last = Some(key);
            out.insert(key, (u64::from_be_bytes(count), FrameId::from_bytes(tip)));
        }
        Ok(Self(out))
    }
}

impl Vault {
    /// This device's heads.
    pub fn heads(&self) -> Heads {
        let mut streams: BTreeMap<(LogKind, DeviceId), BTreeMap<u64, FrameId>> = BTreeMap::new();
        for f in self.frames() {
            let h = f.header();
            let at = streams
                .entry((h.kind.log_kind(), h.author))
                .or_default()
                .entry(h.seq)
                .or_insert(f.id());
            // Holding both sides of a fork: name the lower id, as a peer would.
            *at = (*at).min(f.id());
        }
        Heads(
            streams
                .into_iter()
                .filter_map(|(key, seqs)| {
                    let mut tip = None;
                    for ((seq, id), want) in seqs.iter().zip(0u64..) {
                        if *seq != want {
                            break;
                        }
                        tip = Some((want + 1, *id));
                    }
                    Some((key, tip?))
                })
                .collect(),
        )
    }

    /// The frames a peer at `peer` heads lacks in `log`, in stream order.
    ///
    /// Two devices can hold different frames at one seq (an equivocation).
    /// Where the peer's tip isn't a frame this device holds at that seq, the
    /// streams split somewhere below it: send the whole stream. Below the
    /// peer's count, also send both sides of any fork this device holds, so
    /// the peer holds them too and cuts the stream where this device does.
    pub fn missing(&self, peer: &Heads, log: LogKind) -> Vec<&Frame> {
        let mut streams: BTreeMap<DeviceId, BTreeMap<u64, Vec<&Frame>>> = BTreeMap::new();
        for f in self.frames().filter(|f| f.header().kind.log_kind() == log) {
            let h = f.header();
            streams
                .entry(h.author)
                .or_default()
                .entry(h.seq)
                .or_default()
                .push(f);
        }
        let mut out = Vec::new();
        for (author, seqs) in &streams {
            let count = peer.get(log, author);
            let split = peer.tip(log, author).is_some_and(|tip| {
                count > 0
                    && seqs
                        .get(&(count - 1))
                        .is_some_and(|at| at.iter().all(|f| f.id() != tip))
            });
            for (seq, at) in seqs {
                if split || *seq >= count || at.len() > 1 {
                    out.extend(at.iter().copied());
                }
            }
        }
        out.sort_by_key(|f| (f.header().author, f.header().seq, f.id()));
        out
    }
}
