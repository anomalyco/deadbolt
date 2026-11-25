//! What a peer lacks: per-stream heads and the frames above them.

use std::collections::BTreeMap;

use crate::error::DecodeError;
use crate::id::DeviceId;
use crate::v2::{Frame, LogKind};

use super::Vault;

/// How many frames this device holds from the start of each author's
/// membership and data streams, without a gap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Heads(BTreeMap<(LogKind, DeviceId), u64>);

impl Heads {
    pub fn get(&self, log: LogKind, author: &DeviceId) -> u64 {
        self.0.get(&(log, *author)).copied().unwrap_or(0)
    }

    pub fn iter(&self) -> impl Iterator<Item = (LogKind, DeviceId, u64)> + '_ {
        self.0.iter().map(|((log, author), n)| (*log, *author, *n))
    }

    /// `n:u32 (log:u8 author:32 count:u64)*`, sorted.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.0.len() * 41);
        out.extend_from_slice(&(self.0.len() as u32).to_be_bytes());
        for ((log, author), n) in &self.0 {
            out.push(match log {
                LogKind::Member => 0,
                LogKind::Data => 1,
            });
            out.extend_from_slice(author.as_bytes());
            out.extend_from_slice(&n.to_be_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (n, mut rest) = bytes
            .split_first_chunk::<4>()
            .ok_or(DecodeError::UnexpectedEnd)?;
        let n = u32::from_be_bytes(*n) as usize;
        if rest.len() != n.checked_mul(41).ok_or(DecodeError::UnexpectedEnd)? {
            return Err(if rest.len() < n * 41 {
                DecodeError::UnexpectedEnd
            } else {
                DecodeError::TrailingBytes
            });
        }
        let mut out = BTreeMap::new();
        let mut last = None;
        for _ in 0..n {
            let (head, tail) = rest.split_at(41);
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
            let key = (log, DeviceId::from_bytes(author));
            if last.is_some_and(|l| l >= key) {
                return Err(DecodeError::NotCanonical);
            }
            last = Some(key);
            out.insert(key, u64::from_be_bytes(count));
        }
        Ok(Self(out))
    }
}

impl Vault {
    /// This device's heads.
    pub fn heads(&self) -> Heads {
        let mut seqs: BTreeMap<(LogKind, DeviceId), Vec<u64>> = BTreeMap::new();
        for f in self.frames() {
            let h = f.header();
            seqs.entry((h.kind.log_kind(), h.author))
                .or_default()
                .push(h.seq);
        }
        Heads(
            seqs.into_iter()
                .map(|(key, mut s)| {
                    s.sort_unstable();
                    s.dedup();
                    let n = s.iter().zip(0u64..).take_while(|(a, b)| *a == b).count();
                    (key, n as u64)
                })
                .collect(),
        )
    }

    /// The frames a peer at `peer` heads lacks in `log`, in stream order.
    pub fn missing(&self, peer: &Heads, log: LogKind) -> Vec<&Frame> {
        let mut out: Vec<&Frame> = self
            .frames()
            .filter(|f| {
                let h = f.header();
                h.kind.log_kind() == log && h.seq >= peer.get(log, &h.author)
            })
            .collect();
        out.sort_by_key(|f| (f.header().author, f.header().seq, f.id()));
        out
    }
}
