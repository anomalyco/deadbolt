//! The zero-state recovery bootstrap (Fable §2.5 steps 2–4), which needs
//! nothing but LIST.

use std::collections::BTreeMap;

use deadbolt_core::v2::LogKind;
use deadbolt_core::{DeviceId, VaultId};

use super::index::first_hole;
use super::{RemoteAnomaly, RemoteIndex, Spellings};
use crate::error::RemoteError;
use crate::path::RemotePath;

/// What a device with zero local state fetches to rebuild a vault from the
/// recovery words and the store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryPlan {
    /// Every Member frame, each stream ascending: resolve these first.
    pub members: Vec<RemotePath>,
    /// Every listed checkpoint, highest `seq` first. The caller opens them
    /// in order and keeps the newest undisputed one that verifies, so a
    /// disputed or torn newest checkpoint falls back to an older GC base.
    pub checkpoints: Vec<RemotePath>,
    /// Every listed fraud proof: fetch and apply them before trusting any
    /// checkpoint or stream they implicate.
    pub frauds: Vec<RemotePath>,
    /// Holes in Member streams (never compacted, so a hole is withholding).
    pub anomalies: Vec<RemoteAnomaly>,
    data: BTreeMap<DeviceId, BTreeMap<u64, Spellings>>,
    vault: Option<VaultId>,
}

/// The data frames above a checkpoint's frontier.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tail {
    /// Every listed frame above the frontier, each stream ascending (a
    /// twin's `<seq>` before its `<seq>.c`).
    pub frames: Vec<RemotePath>,
    /// Streams that skip a `seq` above the frontier: a store hiding one
    /// frame (a `Dispute`, say) in the middle of the tail.
    pub holes: Vec<RemoteAnomaly>,
}

impl RecoveryPlan {
    /// The first checkpoint candidate.
    pub fn checkpoint(&self) -> Option<&RemotePath> {
        self.checkpoints.first()
    }

    /// The data tail above a checkpoint's frontier (every frame when the
    /// frontier omits an author), and any hole in it.
    pub fn tail(&self, frontier: &BTreeMap<DeviceId, u64>) -> Tail {
        let mut tail = Tail::default();
        let Some(vault) = self.vault else {
            return tail;
        };
        for (&author, seqs) in &self.data {
            let from = match frontier.get(&author) {
                Some(&floor) => match floor.checked_add(1) {
                    Some(from) => from,
                    None => continue,
                },
                None => 0,
            };
            for (&seq, spellings) in seqs.range(from..) {
                tail.frames
                    .extend(spellings.paths(vault, LogKind::Data, author, seq));
            }
            if let Some(missing_seq) = first_hole(seqs.range(from..).map(|(s, _)| *s), from) {
                tail.holes.push(RemoteAnomaly::StreamHole {
                    log: LogKind::Data,
                    author,
                    missing_seq,
                    max_seq: seqs.keys().next_back().copied().unwrap_or_default(),
                });
            }
        }
        tail
    }
}

/// Plans a zero-state recovery from `LIST <vault>/m/`, `LIST <vault>/d/`
/// and `LIST <vault>/x/` alone: no head pointer, device id or locator
/// secret.
pub fn plan_recovery_bootstrap(
    vault: &VaultId,
    listed_m: &[String],
    listed_d: &[String],
    listed_x: &[String],
) -> Result<RecoveryPlan, RemoteError> {
    let index = RemoteIndex::from_names(vault, listed_m.iter().chain(listed_d).chain(listed_x));
    let mut plan = RecoveryPlan {
        vault: Some(*vault),
        frauds: index.frauds.clone(),
        ..RecoveryPlan::default()
    };
    for (&(log, author), seqs) in &index.streams {
        match log {
            LogKind::Member => {
                if let Some(missing_seq) = first_hole(seqs.keys().copied(), 0) {
                    plan.anomalies.push(RemoteAnomaly::StreamHole {
                        log,
                        author,
                        missing_seq,
                        max_seq: seqs.keys().next_back().copied().unwrap_or_default(),
                    });
                }
                for (&seq, spellings) in seqs {
                    plan.members
                        .extend(spellings.paths(*vault, log, author, seq));
                }
            }
            LogKind::Data => {
                for (&seq, spellings) in seqs {
                    let checkpoint = Spellings {
                        bare: false,
                        checkpoint: spellings.checkpoint,
                    };
                    plan.checkpoints
                        .extend(checkpoint.paths(*vault, log, author, seq));
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
