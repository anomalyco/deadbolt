use crate::id::{Hash, VaultId};
use crate::item::ItemError;

/// Why an entry or operation was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("entry is for vault {found}, expected {expected}")]
    WrongVault { expected: VaultId, found: VaultId },
    #[error("the selected history is no longer available")]
    HistoryChanged,
    #[error("invalid signature")]
    BadSignature,
    #[error("sequence gap: expected seq {expected}, got {got}")]
    SeqGap { expected: u64, got: u64 },
    #[error("author already has a different entry at seq {seq}")]
    Fork { seq: u64 },
    #[error("author reached the limit of {max} non-removal membership entries in this vault")]
    MembershipLimit { max: u64 },
    #[error("missing {} dependencies", .0.len())]
    MissingDeps(Vec<Hash>),
    #[error("invalid dependencies")]
    InvalidDeps,
    #[error("join consent signature is invalid")]
    InvalidConsent,
    #[error("author is not a member")]
    NotMember,
    #[error("device to add was removed")]
    AddRemovedDevice,
    #[error("device to remove is not a member")]
    RemoveNonMember,
    #[error("invalid vault name")]
    InvalidName,
    #[error("not a valid genesis entry")]
    InvalidGenesis,
    /// A change whose entry could never be sent to another device.
    #[error(
        "too large to sync to other devices: {len} bytes in one change, the limit is {max} bytes"
    )]
    TooLarge { len: usize, max: usize },
    #[error(transparent)]
    Item(#[from] ItemError),
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
