use std::path::PathBuf;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The passphrase did not decrypt the key set. A tampered key set or KDF
    /// header is indistinguishable from a wrong passphrase and also lands here.
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// The biometric key did not decrypt the biometric key set, or no biometric
    /// key set is enrolled.
    #[error("biometric unlock is not enrolled or its key was rejected")]
    InvalidBiometric,
    #[error("a store already exists at {}", .0.display())]
    AlreadyExists(PathBuf),
    #[error("no store at {}", .0.display())]
    NotInitialized(PathBuf),
    /// The database file is locked by another handle in this process or by
    /// another process.
    #[error("store is already open")]
    InUse,
    #[error("unsupported store format version {0}")]
    UnsupportedFormat(u32),
    /// Authenticated data failed to verify, or the structure on disk is
    /// inconsistent. Never returned for a wrong passphrase.
    #[error("store is corrupted or was tampered with: {0}")]
    Corrupt(String),
    #[error("invalid KDF parameters: {0}")]
    InvalidKdfParams(String),
    #[error("system random number generator failed: {0}")]
    Rng(getrandom::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Db(redb::Error),
}

impl Error {
    pub(crate) fn corrupt(msg: impl Into<String>) -> Self {
        Error::Corrupt(msg.into())
    }
}

impl From<redb::Error> for Error {
    fn from(err: redb::Error) -> Self {
        match err {
            redb::Error::DatabaseAlreadyOpen => Error::InUse,
            redb::Error::Corrupted(msg) => Error::Corrupt(msg),
            err => Error::Db(err),
        }
    }
}

macro_rules! from_redb {
    ($($ty:ty),*) => {$(
        impl From<$ty> for Error {
            fn from(err: $ty) -> Self {
                redb::Error::from(err).into()
            }
        }
    )*};
}

from_redb!(
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);
