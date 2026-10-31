//! The sync protocol (`deadbolt/sync/1`).
//!
//! One session runs on one bidirectional QUIC stream opened by the initiator. Both sides
//! run the same steps, writing and reading concurrently:
//!
//! 1. send `HEADS(my heads)`, receive `HEADS(peer heads)`
//! 2. send `ENTRY(blob)`* `DONE` for `missing_for(peer heads)`, receive the peer's entries
//! 3. hand the received entries, in order, to [`SyncHandler::receive`]: in batches of
//!    bounded size and count while they arrive, the last one (possibly empty) after
//!    `DONE`
//! 4. the responder sends `RESULT` (empty = ok, otherwise an error message) once its
//!    `receive` returned; the initiator waits for it, so a completed session means both
//!    sides processed everything.
//!
//! Entries are delivered in the order the sender produced them. Ordering membership
//! entries before the data that depends on them is the [`SyncHandler`]'s job.
//!
//! An inbound session must finish within [`crate::NodeConfig::inbound_sync_timeout`].
//! The same timeout independently bounds idle waits for the first or next stream.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use iroh::endpoint::Connection;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::{
    Blob, PeerId,
    error::{Error, HandlerError, Result, close, from_conn, settle},
    fmt_id,
    frame::{self, tag},
};

/// Default for how long a session a peer opened may take, from accepting its stream to
/// our `RESULT`, before the connection is closed ([`crate::NodeConfig`]). Generous: the
/// CLI gives up on a session it opened after 15 seconds, including the dial.
/// Also bounds each idle wait for the first or next stream, independently.
pub const INBOUND_SYNC_TIMEOUT: Duration = Duration::from_secs(60);

/// Application side of the sync protocol. Heads and entries are opaque bytes.
///
/// Implementations can use `async fn` for each method.
pub trait SyncHandler: Send + Sync + 'static {
    /// A summary of what this device has (e.g. the heads of each device log).
    fn heads(&self, peer: PeerId) -> impl Future<Output = Result<Vec<u8>, HandlerError>> + Send;

    /// The entries `peer` is missing given its heads, in the order they should be applied
    /// (membership ops first).
    fn missing_for(
        &self,
        peer: PeerId,
        peer_heads: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<Blob>, HandlerError>> + Send;

    /// Entries received from `peer`, in the order it sent them. One session may call
    /// this several times, with consecutive batches; the last call (after the peer's
    /// `DONE`, possibly with no entries) always happens unless an earlier one failed.
    fn receive(
        &self,
        peer: PeerId,
        entries: Vec<Blob>,
    ) -> impl Future<Output = Result<(), HandlerError>> + Send;
}

impl<T: SyncHandler> SyncHandler for Arc<T> {
    fn heads(&self, peer: PeerId) -> impl Future<Output = Result<Vec<u8>, HandlerError>> + Send {
        (**self).heads(peer)
    }

    fn missing_for(
        &self,
        peer: PeerId,
        peer_heads: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<Blob>, HandlerError>> + Send {
        (**self).missing_for(peer, peer_heads)
    }

    fn receive(
        &self,
        peer: PeerId,
        entries: Vec<Blob>,
    ) -> impl Future<Output = Result<(), HandlerError>> + Send {
        (**self).receive(peer, entries)
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub(crate) trait DynSyncHandler: Send + Sync + 'static {
    fn heads(&self, peer: PeerId) -> BoxFuture<'_, Result<Vec<u8>, HandlerError>>;
    fn missing_for(
        &self,
        peer: PeerId,
        peer_heads: Vec<u8>,
    ) -> BoxFuture<'_, Result<Vec<Blob>, HandlerError>>;
    fn receive(&self, peer: PeerId, entries: Vec<Blob>) -> BoxFuture<'_, Result<(), HandlerError>>;
}

impl<T: SyncHandler> DynSyncHandler for T {
    fn heads(&self, peer: PeerId) -> BoxFuture<'_, Result<Vec<u8>, HandlerError>> {
        Box::pin(SyncHandler::heads(self, peer))
    }

    fn missing_for(
        &self,
        peer: PeerId,
        peer_heads: Vec<u8>,
    ) -> BoxFuture<'_, Result<Vec<Blob>, HandlerError>> {
        Box::pin(SyncHandler::missing_for(self, peer, peer_heads))
    }

    fn receive(&self, peer: PeerId, entries: Vec<Blob>) -> BoxFuture<'_, Result<(), HandlerError>> {
        Box::pin(SyncHandler::receive(self, peer, entries))
    }
}

/// Result of a completed sync session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Entries sent to the peer.
    pub sent: usize,
    /// Entries received from the peer (and accepted by [`SyncHandler::receive`]).
    pub received: usize,
}

/// An open sync connection to a member, created by [`crate::Node::connect`].
///
/// The connection stays open until dropped, [`SyncConnection::close`]d, or closed by the
/// gate ([`crate::Node::enforce_membership`]), or the responder closes it after its
/// idle deadline. Dial again after closure to start another session.
pub struct SyncConnection {
    conn: Connection,
    handler: Arc<dyn DynSyncHandler>,
    max_frame_len: usize,
}

impl std::fmt::Debug for SyncConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncConnection")
            .field("peer", &fmt_id(&self.peer()))
            .finish_non_exhaustive()
    }
}

impl SyncConnection {
    pub(crate) fn new(
        conn: Connection,
        handler: Arc<dyn DynSyncHandler>,
        max_frame_len: usize,
    ) -> Self {
        Self {
            conn,
            handler,
            max_frame_len,
        }
    }

    pub fn peer(&self) -> PeerId {
        *self.conn.remote_id().as_bytes()
    }

    /// Runs one sync session on a new stream.
    pub async fn sync(&self) -> Result<SyncOutcome> {
        let (mut send, mut recv) = match self.conn.open_bi().await {
            Ok(streams) => streams,
            Err(e) => return Err(settle(&self.conn, Error::Closed(e.to_string())).await),
        };
        let result = run_session(
            &*self.handler,
            self.peer(),
            &mut send,
            &mut recv,
            self.max_frame_len,
            true,
        )
        .await;
        match result {
            Ok(outcome) => Ok(outcome),
            // Close before the streams drop, so the peer sees the reason rather than an
            // implicitly finished stream.
            Err(err) => Err(fail(&self.conn, err).await),
        }
    }

    /// Whether the connection has been closed (by either side or by the gate).
    pub fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    /// Resolves once the connection is closed, with the reason.
    pub async fn closed(&self) -> Error {
        self.conn.closed().await;
        from_conn(&self.conn, Error::Closed("closed".into()))
    }

    /// Gracefully closes the connection.
    pub fn close(self) {
        self.conn.close(close::DONE, b"done");
    }
}

/// Serves inbound sessions on an accepted (already gated) sync connection.
pub(crate) async fn serve_sync(
    conn: Connection,
    handler: Arc<dyn DynSyncHandler>,
    max_frame_len: usize,
    timeout: Duration,
) {
    let peer = *conn.remote_id().as_bytes();
    loop {
        let (mut send, mut recv) = match n0_future::time::timeout(timeout, conn.accept_bi()).await {
            Ok(Ok(streams)) => streams,
            Ok(Err(_)) => break,
            Err(_) => {
                conn.close(close::DONE, b"idle timeout");
                debug!(peer = %fmt_id(&peer), "idle sync connection closed");
                break;
            }
        };
        let session = run_session(&*handler, peer, &mut send, &mut recv, max_frame_len, false);
        match n0_future::time::timeout(timeout, session).await {
            Ok(Ok(outcome)) => debug!(peer = %fmt_id(&peer), ?outcome, "served sync session"),
            Ok(Err(err)) => {
                let err = fail(&conn, err).await;
                debug!(peer = %fmt_id(&peer), "sync session failed: {err}");
            }
            Err(_) => {
                conn.close(close::PROTOCOL, b"timeout");
                debug!(peer = %fmt_id(&peer), "sync session timed out");
            }
        }
    }
}

/// Runs the wire protocol on an authenticated, membership-gated byte stream.
/// The transport adapter supplies the peer identity and closes both halves on failure.
#[cfg(feature = "sim")]
pub async fn run_sync_session(
    handler: &impl SyncHandler,
    peer: PeerId,
    send: &mut (impl AsyncWrite + Unpin),
    recv: &mut (impl AsyncRead + Unpin),
    max: usize,
    initiator: bool,
) -> Result<SyncOutcome> {
    run_session(handler, peer, send, recv, max, initiator).await
}

async fn run_session(
    handler: &dyn DynSyncHandler,
    peer: PeerId,
    send: &mut (impl AsyncWrite + Unpin),
    recv: &mut (impl AsyncRead + Unpin),
    max: usize,
    initiator: bool,
) -> Result<SyncOutcome> {
    let heads = handler.heads(peer).await.map_err(Error::Handler)?;
    let ((), mut peer_heads) = tokio::try_join!(
        frame::write(send, tag::HEADS, &heads),
        frame::expect(recv, tag::HEADS, max),
    )?;

    let missing = handler
        .missing_for(peer, std::mem::take(&mut *peer_heads))
        .await
        .map_err(Error::Handler)?;
    let ((), (received, local)) = tokio::try_join!(
        frame::write_entries(send, &missing),
        receive_entries(handler, peer, recv, max),
    )?;
    let outcome = SyncOutcome {
        sent: missing.len(),
        received,
    };

    if initiator {
        if let Err(error) = send.shutdown().await {
            tracing::debug!(%error, "sync send closed; peer result determines success");
        }
        let remote = frame::read_result(recv, max).await;
        local.map_err(Error::Handler)?;
        remote?;
    } else {
        let report = local.as_ref().map(|_| ()).map_err(|e| e.to_string());
        frame::write_result(send, &report).await?;
        if let Err(error) = send.shutdown().await {
            tracing::debug!(%error, "sync send closed after reporting result");
        }
        local.map_err(Error::Handler)?;
    }
    Ok(outcome)
}

/// Reads the peer's entries, handing them on in bounded batches as they arrive so a
/// session never buffers more than one batch. Once a batch fails, the rest are read
/// and dropped, so the failure is reported in `RESULT` as before. Returns how many
/// entries were read and the handler's result.
async fn receive_entries(
    handler: &dyn DynSyncHandler,
    peer: PeerId,
    recv: &mut (impl AsyncRead + Unpin),
    max: usize,
) -> Result<(usize, Result<(), HandlerError>)> {
    let mut received = 0;
    let mut result = Ok(());
    // Do not wait for DONE or a full-size batch before acknowledging *any* prefix
    // to storage. On a slow path the session deadline could otherwise discard the
    // same thousands of complete frames on every retry. Start with one frame so
    // even the shortest useful exchange can advance heads, then double so a fast
    // stream needs logarithmically many prefix commits before the normal cap.
    let mut entry_limit = 1;
    loop {
        let (batch, done) = frame::read_prefix(recv, max, entry_limit).await?;
        entry_limit = (entry_limit * 2).min(frame::BATCH_ENTRIES);
        received += batch.len();
        if result.is_ok() {
            result = handler.receive(peer, batch).await;
        }
        if done {
            return Ok((received, result));
        }
    }
}

/// Closes the connection for locally detected failures and maps I/O failures to the
/// connection's close reason.
pub(crate) async fn fail(conn: &Connection, err: Error) -> Error {
    match &err {
        Error::Handler(e) => conn.close(close::ABORTED, truncate(&e.to_string())),
        Error::Protocol(m) => conn.close(close::PROTOCOL, truncate(m)),
        Error::FrameTooLarge { .. } => conn.close(close::PROTOCOL, b"frame too large"),
        Error::Io(_) | Error::Closed(_) => return settle(conn, err).await,
        _ => {}
    }
    err
}

pub(crate) fn truncate(s: &str) -> &[u8] {
    let b = s.as_bytes();
    &b[..b.len().min(256)]
}
