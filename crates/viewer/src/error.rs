use deadbolt_core::v2::CryptoError;
use deadbolt_pack::Error as PackError;

pub type Result<T, E = ViewerError> = std::result::Result<T, E>;

/// Why the viewer refused. Every variant fails closed: nothing is shown or
/// filled. Swift answers most of them by asking the user to open the app.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "ffi", derive(uniffi::Error))]
pub enum ViewerError {
    /// The key bundle is past its expiry; the app writes a fresh one on its
    /// next unlock.
    #[error("the viewer keys expired at {expires_unix}")]
    Expired { expires_unix: u64 },
    #[error("the viewer key bundle is malformed")]
    InvalidBundle,
    /// No `gen-<n>.pack` on disk has the bundle's `PackId`: the app
    /// compacted since it wrote the bundle.
    #[error("the pack these keys open is not on disk")]
    PackNotFound,
    /// Authentication failed: the wrong key, or bytes that were altered.
    #[error("wrong key, or the bytes were altered")]
    WrongKey,
    #[error("corrupt: {message}")]
    Corrupt { message: String },
    #[error("no such item")]
    NotFound,
    #[error("invalid input: {message}")]
    InvalidInput { message: String },
    #[error("I/O: {message}")]
    Io { message: String },
}

impl ViewerError {
    pub(crate) fn corrupt(message: impl Into<String>) -> Self {
        Self::Corrupt {
            message: message.into(),
        }
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }
}

impl From<PackError> for ViewerError {
    fn from(err: PackError) -> Self {
        match err {
            PackError::Decrypt => Self::WrongKey,
            PackError::CorruptPack { .. } | PackError::OutOfRange { .. } => {
                Self::corrupt(err.to_string())
            }
            PackError::InvalidInput(message) => Self::invalid(message),
            other => Self::Io {
                message: other.to_string(),
            },
        }
    }
}

impl From<CryptoError> for ViewerError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::DecryptFailed
            | CryptoError::NonContributoryKey
            | CryptoError::UnsupportedSuite(_) => Self::WrongKey,
            CryptoError::InvalidPadding => Self::corrupt(err.to_string()),
            other => Self::invalid(other.to_string()),
        }
    }
}
