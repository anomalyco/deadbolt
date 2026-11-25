use crate::id::VaultId;
use crate::item::ItemError;

/// Why a frame or operation was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("entry is for vault {found}, expected {expected}")]
    WrongVault { expected: VaultId, found: VaultId },
    #[error("this vault holds the most frames it can")]
    TooManyFrames,
    #[error("invalid frame: {0}")]
    Frame(String),
    #[error("waiting for another device to share this vault's current key")]
    AwaitingKeys,
    #[error("writes are parked: {0}")]
    Parked(String),
    #[error("that recovery kit is not this vault's current recovery root")]
    NotRecoveryRoot,
    #[error("author is not a member")]
    NotMember,
    #[error("device to add was removed")]
    AddRemovedDevice,
    #[error("device to remove is not a member")]
    RemoveNonMember,
    #[error("invalid vault name")]
    InvalidName,
    #[error("not a valid vault genesis")]
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
