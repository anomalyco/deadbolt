use crate::id::{Hash, VaultId};

/// Why an entry or operation was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("entry is for vault {found}, expected {expected}")]
    WrongVault { expected: VaultId, found: VaultId },
    #[error("invalid signature")]
    BadSignature,
    #[error("sequence gap: expected seq {expected}, got {got}")]
    SeqGap { expected: u64, got: u64 },
    #[error("author already has a different entry at seq {seq}")]
    Fork { seq: u64 },
    #[error("missing {} dependencies", .0.len())]
    MissingDeps(Vec<Hash>),
    #[error("invalid dependencies")]
    InvalidDeps,
    #[error("join consent signature is invalid")]
    InvalidConsent,
    #[error("author is not a member")]
    NotMember,
    #[error("invalid vault name")]
    InvalidName,
    #[error("not a valid genesis entry")]
    InvalidGenesis,
}

/// Why bytes failed to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("unexpected end of input")]
    UnexpectedEnd,
    #[error("trailing bytes")]
    TrailingBytes,
    #[error("invalid tag {0}")]
    InvalidTag(u8),
    #[error("invalid utf-8")]
    InvalidUtf8,
    #[error("non-canonical ordering")]
    NotCanonical,
}
