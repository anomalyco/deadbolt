use std::io;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{name}: not found")]
    NotFound { name: String },
    #[error("{name}: already exists")]
    AlreadyExists { name: String },
    #[error("invalid block name {name:?}")]
    InvalidName { name: String },
    #[error("{name}: reading {len} bytes at offset {offset} runs past the end")]
    OutOfRange { name: String, offset: u64, len: u64 },
    #[error("{name}: truncating to {len} bytes would grow it")]
    InvalidTruncate { name: String, len: u64 },
    #[error("another writer holds the vault lock")]
    Locked,
    #[error("{name}: {source}")]
    Io { name: String, source: io::Error },
    /// [`crate::MemBlocks`] simulated a power cut; the instance is dead until
    /// [`crate::MemBlocks::reboot`].
    #[error("simulated crash")]
    Crashed,
    /// A bad record with valid records after it: not a torn append, so the
    /// caller quarantines the file and refills it from a replica.
    #[error("{file}: corrupt record at offset {offset}")]
    CorruptLog { file: String, offset: u64 },
    #[error("record of {len} bytes exceeds the {max}-byte limit")]
    RecordTooLarge { len: usize, max: usize },
    #[error("{file}: corrupt pack ({reason})")]
    CorruptPack { file: String, reason: &'static str },
    #[error("{file}: corrupt local state ({reason})")]
    CorruptLocal { file: String, reason: &'static str },
    #[error("{name}: content does not match its hash")]
    CorruptBlob { name: String },
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    /// A frame to carry into the new WAL isn't in any WAL on disk: only the
    /// old WALs, kept until the new generation is durable, make carrying it
    /// crash-safe.
    #[error("compaction carries {count} frame(s) that no WAL on disk holds")]
    InvalidCompactionInput { count: usize },
    #[error("authentication failed: wrong key, or the bytes were altered")]
    Decrypt,
    /// The newest local state on disk is older than, newer than, or forked
    /// from what the rollback anchor last recorded.
    #[error("rollback detected: local state on disk is at {disk:?}, the anchor at {anchor}")]
    RollbackDetected { disk: Option<u64>, anchor: u64 },
    #[error("rollback anchor: {0}")]
    Anchor(String),
    #[error("random number generator failed: {0}")]
    Rng(getrandom::Error),
}

impl Error {
    pub(crate) fn corrupt_pack(file: &str, reason: &'static str) -> Self {
        Self::CorruptPack {
            file: file.to_owned(),
            reason,
        }
    }

    pub(crate) fn corrupt_local(file: &str, reason: &'static str) -> Self {
        Self::CorruptLocal {
            file: file.to_owned(),
            reason,
        }
    }

    pub(crate) fn not_found(name: &str) -> Self {
        Self::NotFound {
            name: name.to_owned(),
        }
    }

    pub(crate) fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }
}
