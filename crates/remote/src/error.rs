use crate::path::PathError;

/// Everything an [`ObjStore`](crate::ObjStore) call or a sync step can fail with.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RemoteError {
    /// The name or prefix was refused before any request was sent.
    #[error("invalid object name: {0}")]
    InvalidName(#[from] PathError),
    /// The store answered with a status the verb does not accept.
    #[error("{verb} {name}: HTTP {status}")]
    Status {
        verb: &'static str,
        name: String,
        status: u16,
    },
    /// The store answered with a redirect, which is never followed: the next
    /// host would receive the credentials.
    #[error("{verb} {name}: refused to follow an HTTP {status} redirect")]
    Redirect {
        verb: &'static str,
        name: String,
        status: u16,
    },
    /// The request never completed (connection, TLS, timeout or body).
    #[error("{verb} {name}: transport error: {detail}")]
    Transport {
        verb: &'static str,
        name: String,
        detail: String,
    },
    /// The store answered with a body this crate cannot read.
    #[error("malformed store response: {0}")]
    Protocol(String),
    /// The backend configuration is unusable.
    #[error("invalid remote configuration: {0}")]
    Config(String),
    /// The sync planner refused its input.
    #[error("sync plan refused: {0}")]
    Plan(String),
    /// A fault a [`FaultyObjStore`](crate::FaultyObjStore) injected.
    #[error("injected fault: {0}")]
    Injected(&'static str),
}
