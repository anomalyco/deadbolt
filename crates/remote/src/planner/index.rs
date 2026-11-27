//! [`RemoteIndex`]: every frame name a set of LISTs returned, by stream.

use std::collections::BTreeMap;

use deadbolt_core::v2::{FrameKind, LogKind};
use deadbolt_core::{DeviceId, VaultId};

use super::StreamKey;
use crate::path::RemotePath;

/// Which spellings of one `(stream, seq)` the store listed. A data stream
/// position can be listed as both `<seq>` and `<seq>.c`: only one is the
/// author's, unless the author signed both (equivocation), so neither may
/// shadow the other.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Spellings {
    /// `<seq>`: a Member or Data frame.
    pub bare: bool,
    /// `<seq>.c`: a Checkpoint frame.
    pub checkpoint: bool,
}

impl Spellings {
    /// Both `<seq>` and `<seq>.c` are listed.
    pub const fn is_twin(self) -> bool {
        self.bare && self.checkpoint
    }

    /// The listed names, bare first (their name order).
    pub fn paths(
        self,
        vault: VaultId,
        log: LogKind,
        author: DeviceId,
        seq: u64,
    ) -> Vec<RemotePath> {
        let bare = match log {
            LogKind::Member => FrameKind::Member,
            LogKind::Data => FrameKind::Data,
        };
        let mut out = Vec::with_capacity(2);
        if self.bare {
            out.push(RemotePath::frame(vault, bare, author, seq));
        }
        if self.checkpoint {
            out.push(RemotePath::frame(vault, FrameKind::Checkpoint, author, seq));
        }
        out
    }
}

/// Every frame name a set of LISTs returned, by stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteIndex {
    /// Listed `seq`s of every stream, with the spellings listed at each.
    pub streams: BTreeMap<StreamKey, BTreeMap<u64, Spellings>>,
    /// Listed fraud proofs.
    pub frauds: Vec<RemotePath>,
    /// Listed names that are not canonical objects of this vault.
    pub ignored: Vec<String>,
}

impl RemoteIndex {
    /// Removes a listed object disproved by GET, preserving the other
    /// spelling of a twin when only one of its objects is missing.
    pub fn remove(&mut self, path: &RemotePath) {
        match path {
            RemotePath::Frame {
                kind, author, seq, ..
            } => {
                let stream = (kind.log_kind(), *author);
                if let Some(seqs) = self.streams.get_mut(&stream) {
                    if let Some(spellings) = seqs.get_mut(seq) {
                        if *kind == FrameKind::Checkpoint {
                            spellings.checkpoint = false;
                        } else {
                            spellings.bare = false;
                        }
                        if !spellings.bare && !spellings.checkpoint {
                            seqs.remove(seq);
                        }
                    }
                    if seqs.is_empty() {
                        self.streams.remove(&stream);
                    }
                }
            }
            RemotePath::Fraud { .. } => self.frauds.retain(|p| p != path),
            _ => {}
        }
    }

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
                let spellings = self
                    .streams
                    .entry((kind.log_kind(), author))
                    .or_default()
                    .entry(seq)
                    .or_default();
                if kind == FrameKind::Checkpoint {
                    spellings.checkpoint = true;
                } else {
                    spellings.bare = true;
                }
            }
            Ok(path @ RemotePath::Fraud { .. }) => {
                if !self.frauds.contains(&path) {
                    self.frauds.push(path);
                }
            }
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

    /// Every listed name of one stream position: none, one, or both
    /// `<seq>` and `<seq>.c`.
    pub fn paths(
        &self,
        vault: &VaultId,
        log: LogKind,
        author: &DeviceId,
        seq: u64,
    ) -> Vec<RemotePath> {
        self.streams
            .get(&(log, *author))
            .and_then(|seqs| seqs.get(&seq))
            .map(|s| s.paths(*vault, log, *author, seq))
            .unwrap_or_default()
    }
}

/// The first `seq` at or above `from` missing from an ascending listing,
/// if any listed `seq` lies above it. Walks the listing, never the range,
/// so a hostile `ffff...` name cannot spin it.
pub(crate) fn first_hole(seqs: impl IntoIterator<Item = u64>, from: u64) -> Option<u64> {
    let mut expect = from;
    for seq in seqs {
        if seq < expect {
            continue;
        }
        if seq != expect {
            return Some(expect);
        }
        expect = seq.checked_add(1)?;
    }
    None
}
