use iroh::endpoint::{Connection, ConnectionError, VarInt};

/// Error returned by caller-supplied handlers ([`crate::SyncHandler`], [`crate::Joiner`],
/// [`crate::Inviter`]).
pub type HandlerError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to bind endpoint: {0}")]
    Bind(String),
    #[error("peer {} is not a member", crate::fmt_id(.0))]
    NotAMember(crate::PeerId),
    #[error("connection rejected by peer: {0}")]
    Rejected(String),
    /// The remote membership gate refused this device.
    #[error("membership rejected by peer: {0}")]
    MembershipRejected(String),
    #[error("failed to connect: {0}")]
    Connect(String),
    #[error("connection closed: {0}")]
    Closed(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol violation: {0}")]
    Protocol(String),
    #[error("frame of {len} bytes exceeds limit of {max} bytes")]
    FrameTooLarge { len: usize, max: usize },
    #[error("handler error: {0}")]
    Handler(HandlerError),
    #[error("peer reported an error: {0}")]
    Remote(String),
    #[error("invalid pairing code: {0}")]
    InvalidCode(String),
    #[error("invalid relay url: {0}")]
    InvalidRelayUrl(String),
    #[error("cannot render qr code: {0}")]
    Qr(String),
    #[error("rendezvous: {0}")]
    Rendezvous(String),
    #[error("the pairing code expired")]
    PairingExpired,
    /// The PAKE's confirmation failed: the other side doesn't hold this code.
    #[error("a wrong pairing code was tried")]
    PairingCodeMismatch,
    /// The code was already used, or a wrong code was tried with it.
    #[error("the pairing code was already used")]
    PairingCodeUsed,
    /// No device is waiting for the code: never was, expired or stopped.
    #[error("no device is waiting for that pairing code")]
    PairingNotFound,
    /// The code was made on this device.
    #[error("that pairing code is from this device")]
    OwnCode,
    #[error("pairing was cancelled")]
    PairingCancelled,
    #[error("timed out")]
    Timeout,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// QUIC application close codes used by deadbolt.
pub(crate) mod close {
    use super::VarInt;

    pub const DONE: VarInt = VarInt::from_u32(0);
    pub const NOT_MEMBER: VarInt = VarInt::from_u32(1);
    pub const PAIRING_UNAVAILABLE: VarInt = VarInt::from_u32(3);
    pub const PAIRING_PROOF_FAILED: VarInt = VarInt::from_u32(4);
    pub const ABORTED: VarInt = VarInt::from_u32(6);
    pub const PROTOCOL: VarInt = VarInt::from_u32(7);
    pub const PAIRING_USED: VarInt = VarInt::from_u32(8);
}

/// Like [`from_conn`], but for I/O failures on a still-open connection waits briefly for
/// the close reason: a peer that aborts may finish its stream just before its
/// `CONNECTION_CLOSE` arrives.
pub(crate) async fn settle(conn: &Connection, err: Error) -> Error {
    if matches!(err, Error::Io(_) | Error::Closed(_)) && conn.close_reason().is_none() {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "best-effort settling ends on either peer close or its deadline"
        )]
        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), conn.closed()).await;
    }
    from_conn(conn, err)
}

/// Turns an I/O-level failure into a more specific error if the connection was closed
/// with a known reason.
pub(crate) fn from_conn(conn: &Connection, fallback: Error) -> Error {
    match conn.close_reason() {
        Some(ConnectionError::ApplicationClosed(ac)) => {
            let reason = String::from_utf8_lossy(&ac.reason).into_owned();
            match ac.error_code {
                c if c == close::NOT_MEMBER => Error::MembershipRejected(reason),
                c if c == close::PAIRING_UNAVAILABLE => Error::Rejected(reason),
                c if c == close::PAIRING_PROOF_FAILED => Error::PairingCodeMismatch,
                c if c == close::PAIRING_USED => Error::PairingCodeUsed,
                c if c == close::ABORTED => Error::Remote(reason),
                c if c == close::PROTOCOL => Error::Protocol(format!("peer: {reason}")),
                _ => Error::Closed(format!("closed by peer: {reason}")),
            }
        }
        Some(ConnectionError::LocallyClosed) => Error::Closed("closed locally".into()),
        Some(other) => Error::Closed(other.to_string()),
        None => fallback,
    }
}
