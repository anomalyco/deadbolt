/// What went wrong with a send. [`Error::kind`] names it for the receive page.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid link: {0}")]
    InvalidLink(String),
    /// The sender's daemon can't be reached: it stopped, went offline, or the link
    /// is from an earlier run of it.
    #[error("the sender is offline: {0}")]
    Offline(String),
    #[error("this link has expired")]
    Expired,
    #[error("this link was already used")]
    Used,
    #[error("the sender revoked this link")]
    Revoked,
    /// The sender serves no share with this link's secret (any more).
    #[error("the sender doesn't recognize this link")]
    Unknown,
    #[error("the bundle could not be decrypted: {0}")]
    Corrupt(String),
    #[error("the bundle is too large ({len} bytes, at most {max})")]
    TooLarge { len: usize, max: usize },
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("failed to bind endpoint: {0}")]
    Bind(String),
    #[error("random number generator failed: {0}")]
    Rng(String),
}

impl Error {
    /// A stable short name: `invalid-link`, `offline`, `expired`, `used`,
    /// `revoked`, `unknown`, `corrupt`, `too-large`, `protocol`, `bind`, `rng`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::InvalidLink(_) => "invalid-link",
            Self::Offline(_) => "offline",
            Self::Expired => "expired",
            Self::Used => "used",
            Self::Revoked => "revoked",
            Self::Unknown => "unknown",
            Self::Corrupt(_) => "corrupt",
            Self::TooLarge { .. } => "too-large",
            Self::Protocol(_) => "protocol",
            Self::Bind(_) => "bind",
            Self::Rng(_) => "rng",
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
