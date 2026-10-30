//! Pairing (`deadbolt/pair/3`).
//!
//! The new device ("listener") makes a [`PairingCode`] and calls [`Node::start_pairing`],
//! which publishes its address under the code's rendezvous key (`rendezvous.rs`). The
//! existing device ("dialer") calls [`Node::pair`] with the same code: it derives the
//! key, resolves the address and dials. On one bidirectional stream opened by the dialer:
//!
//! ```text
//! dialer -> listener  PAKE(rendezvous key || SPAKE2 message A)
//! listener -> dialer  PAKE(SPAKE2 message B)
//! dialer -> listener  CONFIRM(HMAC(K, "dialer-confirm"))
//! listener -> dialer  CONFIRM(HMAC(K, "listener-confirm"))     (code consumed)
//! dialer -> listener  OFFER(blob)
//! listener -> dialer  JOIN(blob)
//! dialer -> listener  ENTRY(blob)* DONE
//! listener -> dialer  RESULT
//! ```
//!
//! SPAKE2 (Ed25519 group) runs on the code, with the dialer's and the listener's endpoint
//! ids as identities A and B. `K = HMAC-SHA256(SPAKE2 key, "deadbolt/pair/3" || listener
//! id || dialer id || TLS exporter)`, so the confirmations hold only on this QUIC
//! connection between these two keys. Nothing but PAKE messages and confirmations flows
//! before both confirmations check out, so a party without the code learns nothing about
//! the vault or the inviter, and gets one guess per attempt.
//!
//! The rendezvous key in the first frame names the code the dialer resolved. A dialer
//! holding an older code of this device is refused as `used` without spending the
//! current one. The first dialer whose confirmation fails ends the code ("burns" it):
//! the legitimate dialer never fails it, because one that typed a wrong code finds no
//! device at all, so a failed confirmation means someone is guessing.

use std::{convert::Infallible, fmt, sync::Arc, time::Duration};

use hmac::{Hmac, KeyInit, Mac};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use n0_future::{task::JoinSet, time::Instant};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::{
    Blob, Node, PAIR_ALPN, PairingCode, PeerAddr, PeerId,
    error::{Error, HandlerError, Result, close, from_conn},
    frame::{self, tag},
    rendezvous::{Client, Lookup, Record, current_bucket},
    sync::{fail, truncate},
};

/// How long a pairing code works.
pub const DEFAULT_PAIRING_TTL: Duration = Duration::from_secs(5 * 60);

const PROOF_TIMEOUT: Duration = Duration::from_secs(30);
/// Pairing connections waiting to be proved, and proofs running at once. Only one
/// dialer is legitimate; the rest are refused as busy until a slot frees up, at the
/// latest after [`PROOF_TIMEOUT`].
const MAX_PROVING: usize = 16;
const LINGER_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the dialer looks for the new device's record and retries dialing it.
pub const DEFAULT_FIND_TIMEOUT: Duration = Duration::from_secs(30);
const FIND_INTERVAL: Duration = Duration::from_millis(500);
/// Records older than this are ignored: a code's lifetime plus clock skew.
const RECORD_MAX_AGE: Duration = Duration::from_secs(10 * 60);
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(2);
const FINAL_PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);
const EXPORTER_LABEL: &[u8] = b"EXPORTER-deadbolt-pair-v3";
const TRANSCRIPT_LABEL: &[u8] = b"deadbolt/pair/3";
const DIALER_LABEL: &[u8] = b"dialer-confirm";
const LISTENER_LABEL: &[u8] = b"listener-confirm";
/// A frame carrying the rendezvous key and a SPAKE2 message.
const MAX_PAKE_FRAME: usize = 128;

/// What both sides know once the code was confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingContext {
    pub local: PeerId,
    pub remote: PeerId,
}

/// Result of a successful pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingOutcome {
    pub peer: PeerId,
}

/// New-device side of pairing.
pub trait Joiner: Send + Sync {
    /// Produce the join blob (e.g. the new device's signed consent to join the vault named
    /// in `offer`). Runs only after both devices proved the code; an error ends the
    /// pairing and is reported to the inviter.
    fn join(
        &self,
        ctx: &PairingContext,
        offer: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, HandlerError>> + Send;

    /// The existing device's welcome blobs (e.g. the `Add` op, membership log and data).
    /// The result is reported back, so the inviter learns whether they were accepted.
    fn receive(
        &self,
        ctx: &PairingContext,
        welcome: Vec<Blob>,
    ) -> impl Future<Output = Result<(), HandlerError>> + Send;
}

/// Existing-device side of pairing.
pub trait Inviter: Send + Sync {
    /// The offer blob sent to the new device (e.g. the vault id it is asked to join).
    /// Runs only after both devices proved the code.
    fn offer(
        &self,
        ctx: &PairingContext,
    ) -> impl Future<Output = Result<Vec<u8>, HandlerError>> + Send;

    /// Verify the new device's join blob and produce the welcome blobs, in the order the
    /// new device should apply them (membership first).
    fn welcome(
        &self,
        ctx: &PairingContext,
        join: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<Blob>, HandlerError>> + Send;
}

/// Options for [`Node::start_pairing`] and [`Node::pair`].
#[derive(Clone, Copy, Debug)]
pub struct PairingOptions {
    /// How long the code works. Default 5 minutes.
    pub ttl: Duration,
    /// How long [`Node::pair`] looks for the device waiting with the code. Default 30
    /// seconds.
    pub find_timeout: Duration,
}

impl Default for PairingOptions {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_PAIRING_TTL,
            find_timeout: DEFAULT_FIND_TIMEOUT,
        }
    }
}

/// An outstanding pairing code on the new device. Dropping it ends the code.
pub struct PairingListener {
    node: Node,
    code: PairingCode,
    lookup: Arc<Lookup>,
    slot: u64,
    expires_at: Instant,
    rx: mpsc::Receiver<Connection>,
    publication: Publication,
}

impl fmt::Debug for PairingListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingListener")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl Drop for PairingListener {
    fn drop(&mut self) {
        self.node.inner.gate.close_pairing(self.slot);
        self.publication.finish(Record::Closed);
    }
}

/// Keeps the new device's record current until the code ends, then replaces it with
/// the final one.
struct Publication {
    client: Client,
    lookup: Arc<Lookup>,
    task: Option<n0_future::task::JoinHandle<()>>,
}

impl Publication {
    fn start(node: &Node, client: Client, lookup: Arc<Lookup>) -> Self {
        let task = n0_future::task::spawn({
            let node = node.clone();
            let client = client.clone();
            let lookup = lookup.clone();
            async move {
                let mut published: Option<PeerAddr> = None;
                loop {
                    let addr = node.addr();
                    if published.as_ref() != Some(&addr) {
                        match client
                            .publish(&lookup, &Record::Waiting(addr.clone()))
                            .await
                        {
                            Ok(()) => published = Some(addr),
                            Err(error) => warn!(%error, "publishing the pairing record"),
                        }
                    }
                    n0_future::time::sleep(REPUBLISH_INTERVAL).await;
                }
            }
        });
        Self {
            client,
            lookup,
            task: Some(task),
        }
    }

    /// Stops republishing and publishes `record` in the background. Only the first call
    /// does anything.
    fn finish(&mut self, record: Record) {
        let Some(task) = self.task.take() else { return };
        task.abort();
        let client = self.client.clone();
        let lookup = self.lookup.clone();
        n0_future::task::spawn(async move {
            // The aborted task may be mid-publish; the final record must land last.
            #[expect(
                clippy::let_underscore_must_use,
                reason = "an aborted task's join error is the expected outcome"
            )]
            let _ = task.await;
            match n0_future::time::timeout(FINAL_PUBLISH_TIMEOUT, client.publish(&lookup, &record))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => debug!(%error, "publishing the final pairing record"),
                Err(_) => debug!("publishing the final pairing record timed out"),
            }
        });
    }
}

struct Proven {
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    pairing: ProvenPairing,
}

/// Pairing over an authenticated stream. `transcript` must bind both identities and
/// unique transport keying material; iroh obtains it from its TLS exporter.
/// The adapter owns rendezvous, code expiry, single use and connection cancellation.
pub struct PairingStream {
    local: PeerId,
    remote: PeerId,
    listener: bool,
    password: Zeroizing<String>,
    lookup: PeerId,
    transcript: Vec<u8>,
    seed: Zeroizing<[u8; 32]>,
}

impl PairingStream {
    /// Both sides supply the same code, rendezvous key and exporter. `seed` stands in
    /// for the OS randomness of the SPAKE2 scalar so runs replay byte for byte.
    /// Simulation-only: bypasses the iroh adapter's exporter binding, rendezvous and
    /// code checks.
    #[cfg(feature = "sim")]
    pub fn new(
        local: PeerId,
        remote: PeerId,
        code: &PairingCode,
        lookup: [u8; 32],
        exporter: [u8; 32],
        listener: bool,
        seed: [u8; 32],
    ) -> Self {
        let (listener_id, dialer_id) = if listener {
            (local, remote)
        } else {
            (remote, local)
        };
        Self {
            local,
            remote,
            listener,
            password: code.text(),
            lookup,
            transcript: transcript_bytes(&listener_id, &dialer_id, &exporter),
            seed: Zeroizing::new(seed),
        }
    }

    fn context(&self) -> PairingContext {
        PairingContext {
            local: self.local,
            remote: self.remote,
        }
    }

    fn start(&self) -> (Spake2<Ed25519Group>, Vec<u8>) {
        let (dialer, listener) = if self.listener {
            (self.remote, self.local)
        } else {
            (self.local, self.remote)
        };
        let password = Password::new(self.password.as_bytes());
        let a = Identity::new(&dialer);
        let b = Identity::new(&listener);
        let rng = SeedRng::new(&self.seed);
        if self.listener {
            Spake2::<Ed25519Group>::start_b_with_rng(&password, &a, &b, rng)
        } else {
            Spake2::<Ed25519Group>::start_a_with_rng(&password, &a, &b, rng)
        }
    }

    /// Runs the PAKE as the listener and checks the dialer's confirmation. No
    /// application callback runs and nothing about the vault is sent until this
    /// succeeds. [`Error::PairingCodeUsed`] means the dialer named another code;
    /// [`Error::PairingCodeMismatch`] that it doesn't hold this one.
    pub async fn prove(
        self,
        send: &mut (impl AsyncWrite + Unpin),
        recv: &mut (impl AsyncRead + Unpin),
    ) -> Result<ProvenPairing> {
        let first = frame::expect(recv, tag::PAKE, MAX_PAKE_FRAME).await?;
        if first.len() < 32 {
            return Err(Error::Protocol("short pake frame".into()));
        }
        let (lookup, message) = first.split_at(32);
        if lookup != self.lookup {
            return Err(Error::PairingCodeUsed);
        }
        let (spake, reply) = self.start();
        frame::write(send, tag::PAKE, &reply).await?;
        let key = session_key(spake, message, &self.transcript)?;
        let confirm = frame::expect(recv, tag::CONFIRM, 64).await?;
        if !verify(&key, DIALER_LABEL, &confirm) {
            return Err(Error::PairingCodeMismatch);
        }
        Ok(ProvenPairing { stream: self, key })
    }

    /// Existing-device exchange. Close the stream on error; cancel this future if the
    /// authenticated connection closes meanwhile.
    pub async fn invite(
        self,
        send: &mut (impl AsyncWrite + Unpin),
        recv: &mut (impl AsyncRead + Unpin),
        max: usize,
        inviter: &impl Inviter,
    ) -> Result<PairingOutcome> {
        let (spake, message) = self.start();
        let mut first = self.lookup.to_vec();
        first.extend_from_slice(&message);
        frame::write(send, tag::PAKE, &first).await?;
        let reply = frame::expect(recv, tag::PAKE, MAX_PAKE_FRAME).await?;
        let key = session_key(spake, &reply, &self.transcript)?;
        frame::write(send, tag::CONFIRM, &mac(&key, DIALER_LABEL)).await?;
        let confirm = frame::expect(recv, tag::CONFIRM, 64).await?;
        if !verify(&key, LISTENER_LABEL, &confirm) {
            return Err(Error::PairingCodeMismatch);
        }
        let ctx = self.context();
        let offer = inviter.offer(&ctx).await.map_err(Error::Handler)?;
        frame::write(send, tag::OFFER, &offer).await?;
        let mut join = frame::expect(recv, tag::JOIN, max).await?;
        let join = std::mem::take(&mut *join);
        let welcome = inviter.welcome(&ctx, join).await.map_err(Error::Handler)?;
        frame::write_entries(send, &welcome).await?;
        if let Err(error) = send.shutdown().await {
            debug!(%error, "pairing send closed; peer result determines success");
        }
        frame::read_result(recv, max).await?;
        Ok(PairingOutcome { peer: ctx.remote })
    }
}

/// A dialer proved the code. Consume the code before calling `complete`.
pub struct ProvenPairing {
    stream: PairingStream,
    key: Zeroizing<[u8; 32]>,
}

impl ProvenPairing {
    /// New-device exchange, after the transport adapter consumed the code.
    pub async fn complete(
        self,
        send: &mut (impl AsyncWrite + Unpin),
        recv: &mut (impl AsyncRead + Unpin),
        max: usize,
        joiner: &impl Joiner,
    ) -> Result<PairingOutcome> {
        let ctx = self.stream.context();
        frame::write(send, tag::CONFIRM, &mac(&self.key, LISTENER_LABEL)).await?;
        let mut offer = frame::expect(recv, tag::OFFER, max).await?;
        let offer = std::mem::take(&mut *offer);
        let join = joiner.join(&ctx, offer).await.map_err(Error::Handler)?;
        frame::write(send, tag::JOIN, &join).await?;
        let welcome = frame::read_entries(recv, max).await?;
        let received = joiner.receive(&ctx, welcome).await;
        let report = received.as_ref().map(|_| ()).map_err(|e| e.to_string());
        frame::write_result(send, &report).await?;
        if let Err(error) = send.shutdown().await {
            debug!(%error, "pairing send closed after reporting result");
        }
        received.map_err(Error::Handler)?;
        Ok(PairingOutcome { peer: ctx.remote })
    }
}

impl PairingListener {
    pub fn code(&self) -> &PairingCode {
        &self.code
    }

    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    /// Waits for an existing device to dial with the code and runs the pairing. Dialers
    /// naming another code, or failing before the PAKE, are dropped without spending
    /// the code. The first one that completes the PAKE ends it: with a pairing if its
    /// confirmation holds, with [`Error::PairingCodeMismatch`] if not.
    pub async fn complete(mut self, joiner: &impl Joiner) -> Result<PairingOutcome> {
        let local = self.node.id();
        let mut proving = JoinSet::new();
        let proven = loop {
            tokio::select! {
                _ = n0_future::time::sleep_until(self.expires_at) => return Err(Error::PairingExpired),
                conn = self.rx.recv(), if proving.len() < MAX_PROVING => {
                    let Some(conn) = conn else { return Err(Error::PairingCancelled) };
                    proving.spawn(listener_prove(
                        conn,
                        local,
                        self.code.text(),
                        self.lookup.public,
                    ));
                }
                Some(res) = proving.join_next(), if !proving.is_empty() => match res {
                    Ok(Ok(proven)) if Instant::now() < self.expires_at => break proven,
                    Ok(Ok(proven)) => {
                        proven.conn.close(close::PAIRING_UNAVAILABLE, b"expired");
                        return Err(Error::PairingExpired);
                    }
                    Ok(Err(Error::PairingCodeMismatch)) => {
                        self.node.inner.gate.consume_pairing(self.slot);
                        self.publication.finish(Record::Used);
                        return Err(Error::PairingCodeMismatch);
                    }
                    Ok(Err(err)) => warn!("pairing attempt failed: {err}"),
                    Err(err) => warn!("pairing attempt panicked: {err}"),
                },
            }
        };
        // Single use: nobody else can reach the pairing protocol from here on.
        self.node.inner.gate.consume_pairing(self.slot);
        self.publication.finish(Record::Used);
        drop(proving);

        let Proven {
            conn,
            mut send,
            mut recv,
            pairing,
        } = proven;
        let remote = *conn.remote_id().as_bytes();
        let max = self.node.inner.max_frame_len;
        let result = tokio::select! {
            result = pairing.complete(&mut send, &mut recv, max, joiner) => result,
            _ = conn.closed() => Err(from_conn(&conn, Error::Closed("closed".into()))),
        };
        match result {
            Ok(outcome) => {
                // Let the dialer read RESULT; it closes the connection once it has.
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "best-effort linger ends on either peer close or its deadline"
                )]
                let _ = n0_future::time::timeout(LINGER_TIMEOUT, conn.closed()).await;
                debug!(peer = %crate::fmt_id(&remote), "paired");
                Ok(outcome)
            }
            Err(err) => Err(fail_pairing(&conn, err).await),
        }
    }
}

async fn listener_prove(
    conn: Connection,
    local: PeerId,
    password: Zeroizing<String>,
    lookup: PeerId,
) -> Result<Proven> {
    let remote = *conn.remote_id().as_bytes();
    let (mut send, mut recv) = match n0_future::time::timeout(PROOF_TIMEOUT, conn.accept_bi()).await
    {
        Ok(Ok(streams)) => streams,
        Ok(Err(e)) => return Err(fail_pairing(&conn, Error::Closed(e.to_string())).await),
        Err(_) => {
            conn.close(close::PROTOCOL, b"timeout");
            return Err(Error::Timeout);
        }
    };
    let attempt = async {
        let stream = PairingStream {
            local,
            remote,
            listener: true,
            password,
            lookup,
            transcript: transcript(&conn, &local, &remote)?,
            seed: random_seed()?,
        };
        stream.prove(&mut send, &mut recv).await
    };
    match n0_future::time::timeout(PROOF_TIMEOUT, attempt).await {
        Ok(Ok(pairing)) => Ok(Proven {
            conn,
            send,
            recv,
            pairing,
        }),
        Ok(Err(err)) => Err(fail_pairing(&conn, err).await),
        Err(_) => {
            conn.close(close::PROTOCOL, b"timeout");
            Err(Error::Timeout)
        }
    }
}

impl Node {
    /// Starts waiting for an existing device to pair with `code` (new-device side):
    /// publishes this node's address under the code's rendezvous key and accepts
    /// pairing connections until the code is used, expires or the listener is dropped.
    /// Replaces any previous outstanding code.
    pub async fn start_pairing(
        &self,
        code: &PairingCode,
        options: PairingOptions,
    ) -> Result<PairingListener> {
        self.start_pairing_in(code, options, current_bucket()).await
    }

    async fn start_pairing_in(
        &self,
        code: &PairingCode,
        options: PairingOptions,
        bucket: u64,
    ) -> Result<PairingListener> {
        let lookup = Arc::new(Lookup::derive_async(code, bucket).await?);
        let client = Client::new(&self.inner.rendezvous, &self.inner.endpoint)?;
        let expires_at = Instant::now() + options.ttl;
        let (tx, rx) = mpsc::channel(MAX_PROVING);
        let slot = self.inner.gate.open_pairing(expires_at, tx);
        let publication = Publication::start(self, client, lookup.clone());
        Ok(PairingListener {
            node: self.clone(),
            code: code.clone(),
            lookup,
            slot,
            expires_at,
            rx,
            publication,
        })
    }

    /// Pairs with the new device showing `code` (existing-device side): finds it
    /// through the rendezvous record and runs the pairing.
    pub async fn pair(
        &self,
        code: &PairingCode,
        options: PairingOptions,
        inviter: &impl Inviter,
    ) -> Result<PairingOutcome> {
        self.pair_in(code, options, inviter, current_bucket()).await
    }

    async fn pair_in(
        &self,
        code: &PairingCode,
        options: PairingOptions,
        inviter: &impl Inviter,
        bucket: u64,
    ) -> Result<PairingOutcome> {
        let mut lookups = Vec::new();
        let client = Client::new(&self.inner.rendezvous, &self.inner.endpoint)?;
        let deadline = Instant::now() + options.find_timeout;
        loop {
            let found = n0_future::time::timeout(
                deadline.saturating_duration_since(Instant::now()),
                client.resolve_code(code, bucket, &mut lookups, RECORD_MAX_AGE),
            )
            .await
            .map_err(|_| Error::PairingNotFound)??;
            match found {
                Some((lookup, Record::Waiting(addr))) => {
                    if addr.id == self.id() {
                        return Err(Error::OwnCode);
                    }
                    // A native joiner can publish its direct addresses before
                    // iroh selects a home relay. A browser cannot dial that
                    // record: wait for the republished relay address rather
                    // than spend the whole find deadline on an impossible dial.
                    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
                    if addr.relay_url.is_none() {
                        if Instant::now() >= deadline {
                            return Err(Error::PairingNotFound);
                        }
                        n0_future::time::sleep(FIND_INTERVAL).await;
                        continue;
                    }
                    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
                    let attempt = tokio::time::timeout_at(
                        deadline,
                        self.pair_with(&addr, code, lookup, inviter),
                    );
                    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
                    let attempt = n0_future::time::timeout(
                        deadline.saturating_duration_since(Instant::now()),
                        self.pair_with(&addr, code, lookup, inviter),
                    );
                    let attempt = attempt.await.unwrap_or(Err(Error::PairingNotFound));
                    match attempt {
                        // The record may still carry an address the device has left.
                        Err(Error::Connect(error)) if Instant::now() < deadline => {
                            debug!(%error, "dialing the new device");
                        }
                        Err(Error::Connect(_)) => return Err(Error::PairingNotFound),
                        Err(Error::Rejected(reason)) if reason == "not pairing" => {
                            return Err(Error::PairingNotFound);
                        }
                        other => return other,
                    }
                }
                Some((_, Record::Used)) => return Err(Error::PairingCodeUsed),
                Some((_, Record::Closed)) => return Err(Error::PairingNotFound),
                None if Instant::now() >= deadline => return Err(Error::PairingNotFound),
                None => {}
            }
            n0_future::time::sleep(FIND_INTERVAL).await;
        }
    }

    async fn pair_with(
        &self,
        addr: &PeerAddr,
        code: &PairingCode,
        lookup: PeerId,
        inviter: &impl Inviter,
    ) -> Result<PairingOutcome> {
        let local = self.id();
        let conn = self
            .inner
            .endpoint
            .connect(addr.to_endpoint_addr()?, PAIR_ALPN)
            .await
            .map_err(|e| Error::Connect(e.to_string()))?;
        if *conn.remote_id().as_bytes() != addr.id {
            conn.close(close::PROTOCOL, b"unexpected peer");
            return Err(Error::Protocol("connected to unexpected peer".into()));
        }
        let max = self.inner.max_frame_len;
        let (mut send, mut recv) = match conn.open_bi().await {
            Ok(streams) => streams,
            Err(e) => return Err(fail_pairing(&conn, Error::Closed(e.to_string())).await),
        };
        // Streams outlive the block so a failure closes the connection (with its reason)
        // before they are dropped.
        let result = async {
            let stream = PairingStream {
                local,
                remote: addr.id,
                listener: false,
                password: code.text(),
                lookup,
                transcript: transcript(&conn, &addr.id, &local)?,
                seed: random_seed()?,
            };
            tokio::select! {
                result = stream.invite(&mut send, &mut recv, max, inviter) => result,
                _ = conn.closed() => Err(from_conn(&conn, Error::Closed("closed".into()))),
            }
        }
        .await;
        match result {
            Ok(outcome) => {
                conn.close(close::DONE, b"paired");
                Ok(outcome)
            }
            Err(err) => Err(fail_pairing(&conn, err).await),
        }
    }
}

async fn fail_pairing(conn: &Connection, err: Error) -> Error {
    match &err {
        Error::PairingCodeMismatch => conn.close(close::PAIRING_PROOF_FAILED, b"wrong code"),
        Error::PairingCodeUsed => conn.close(close::PAIRING_USED, b"code already used"),
        Error::Remote(m) => conn.close(close::ABORTED, truncate(m)),
        _ => return fail(conn, err).await,
    }
    err
}

/// `"deadbolt/pair/3" || listener id || dialer id || TLS exporter(32)`. The exporter value
/// is unique to this QUIC connection, binding the confirmations to it.
fn transcript(conn: &Connection, listener: &PeerId, dialer: &PeerId) -> Result<Vec<u8>> {
    let mut ekm = Zeroizing::new([0u8; 32]);
    conn.export_keying_material(ekm.as_mut(), EXPORTER_LABEL, b"")
        .map_err(|_| Error::Protocol("keying material export failed".into()))?;
    Ok(transcript_bytes(listener, dialer, &ekm))
}

fn transcript_bytes(listener: &PeerId, dialer: &PeerId, ekm: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(TRANSCRIPT_LABEL.len() + 96);
    t.extend_from_slice(TRANSCRIPT_LABEL);
    t.extend_from_slice(listener);
    t.extend_from_slice(dialer);
    t.extend_from_slice(ekm);
    t
}

fn random_seed() -> Result<Zeroizing<[u8; 32]>> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|e| Error::Io(std::io::Error::other(e)))?;
    Ok(seed)
}

/// Finishes SPAKE2 with the peer's message and binds the result to the connection.
/// A malformed message counts as a wrong code.
fn session_key(
    spake: Spake2<Ed25519Group>,
    peer: &[u8],
    transcript: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let shared = Zeroizing::new(spake.finish(peer).map_err(|_| Error::PairingCodeMismatch)?);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(
        &hmac(&shared, b"session", transcript)
            .finalize()
            .into_bytes(),
    );
    Ok(key)
}

#[expect(clippy::expect_used, reason = "HMAC accepts keys of every length")]
fn hmac(key: &[u8], label: &[u8], data: &[u8]) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key length");
    m.update(label);
    m.update(&[0]);
    m.update(data);
    m
}

fn mac(key: &[u8; 32], label: &[u8]) -> Vec<u8> {
    hmac(key, label, &[]).finalize().into_bytes().to_vec()
}

fn verify(key: &[u8; 32], label: &[u8], tag: &[u8]) -> bool {
    hmac(key, label, &[]).verify_slice(tag).is_ok()
}

/// SHA-256 in counter mode over a 32-byte seed: the SPAKE2 scalar's randomness, from the
/// OS in production and from the simulation's seed under test.
struct SeedRng {
    seed: Zeroizing<[u8; 32]>,
    counter: u64,
    block: Zeroizing<[u8; 32]>,
    used: usize,
}

impl SeedRng {
    fn new(seed: &[u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(*seed),
            counter: 0,
            block: Zeroizing::new([0; 32]),
            used: 32,
        }
    }
}

impl spake2::rand_core::TryRng for SeedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for byte in dst {
            if self.used == 32 {
                let mut h = Sha256::new();
                h.update(self.seed.as_ref());
                h.update(self.counter.to_be_bytes());
                self.block.copy_from_slice(&h.finalize());
                self.counter += 1;
                self.used = 0;
            }
            *byte = self.block[self.used];
            self.used += 1;
        }
        Ok(())
    }
}

impl spake2::rand_core::TryCryptoRng for SeedRng {}

#[cfg(test)]
mod tests {
    use super::*;

    fn code() -> PairingCode {
        "violin-garden-tiger-lamp-zoo".parse().unwrap()
    }

    fn stream(code: &PairingCode, exporter: [u8; 32], listener: bool) -> PairingStream {
        let (local, remote) = if listener {
            ([2; 32], [1; 32])
        } else {
            ([1; 32], [2; 32])
        };
        let (listener_id, dialer_id) = if listener {
            (local, remote)
        } else {
            (remote, local)
        };
        PairingStream {
            local,
            remote,
            listener,
            password: code.text(),
            lookup: [5; 32],
            transcript: transcript_bytes(&listener_id, &dialer_id, &exporter),
            seed: random_seed().unwrap(),
        }
    }

    /// Runs the PAKE and confirmations only: what each side concludes.
    fn exchange(dialer: PairingStream, listener: PairingStream) -> (bool, bool) {
        let (spake_a, msg_a) = dialer.start();
        let (spake_b, msg_b) = listener.start();
        let key_a = session_key(spake_a, &msg_b, &dialer.transcript).unwrap();
        let key_b = session_key(spake_b, &msg_a, &listener.transcript).unwrap();
        let listener_ok = verify(&key_b, DIALER_LABEL, &mac(&key_a, DIALER_LABEL));
        let dialer_ok = verify(&key_a, LISTENER_LABEL, &mac(&key_b, LISTENER_LABEL));
        (dialer_ok, listener_ok)
    }

    #[test]
    fn the_same_code_on_the_same_connection_confirms() {
        let code = code();
        assert_eq!(
            exchange(stream(&code, [9; 32], false), stream(&code, [9; 32], true)),
            (true, true)
        );
    }

    #[test]
    fn a_wrong_code_fails_both_confirmations() {
        let other: PairingCode = "violin-garden-tiger-lady-zoo".parse().unwrap();
        assert_eq!(
            exchange(
                stream(&code(), [9; 32], false),
                stream(&other, [9; 32], true)
            ),
            (false, false)
        );
    }

    /// A relay of the PAKE messages onto another connection (another exporter) or
    /// between other keys fails: the key is bound to the transcript.
    #[test]
    fn confirmations_are_bound_to_the_connection_and_keys() {
        let code = code();
        assert_eq!(
            exchange(stream(&code, [9; 32], false), stream(&code, [8; 32], true)),
            (false, false)
        );
        let mut swapped = stream(&code, [9; 32], true);
        swapped.local = [3; 32];
        assert_eq!(
            exchange(stream(&code, [9; 32], false), swapped),
            (false, false)
        );
        // Labels keep a dialer's confirmation from passing as the listener's.
        let key = Zeroizing::new([4; 32]);
        assert!(!verify(&key, LISTENER_LABEL, &mac(&key, DIALER_LABEL)));
    }

    #[test]
    fn a_seed_replays_the_same_pake_message() {
        let code = code();
        let mut a = stream(&code, [9; 32], false);
        let mut b = stream(&code, [9; 32], false);
        a.seed = Zeroizing::new([6; 32]);
        b.seed = Zeroizing::new([6; 32]);
        assert_eq!(a.start().1, b.start().1);
        b.seed = Zeroizing::new([7; 32]);
        assert_ne!(a.start().1, b.start().1);
    }

    struct Joins;

    impl Joiner for Joins {
        async fn join(&self, _: &PairingContext, _: Vec<u8>) -> Result<Vec<u8>, HandlerError> {
            Ok(b"join".to_vec())
        }
        async fn receive(&self, _: &PairingContext, _: Vec<Blob>) -> Result<(), HandlerError> {
            Ok(())
        }
    }

    struct Invites;

    impl Inviter for Invites {
        async fn offer(&self, _: &PairingContext) -> Result<Vec<u8>, HandlerError> {
            Ok(b"offer".to_vec())
        }
        async fn welcome(&self, _: &PairingContext, _: Vec<u8>) -> Result<Vec<Blob>, HandlerError> {
            Ok(vec![Blob::new(b"entry".to_vec())])
        }
    }

    async fn spawn(dir: &std::path::Path) -> Node {
        let key = iroh::SecretKey::generate().to_bytes();
        let mut config = crate::NodeConfig::local_only(key);
        config.rendezvous = crate::Rendezvous::Dir(dir.to_path_buf());
        Node::spawn(
            config,
            std::sync::Arc::new(|_: &PeerId| false),
            crate::node::tests::Nothing,
        )
        .await
        .unwrap()
    }

    async fn within<F: Future>(fut: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(20), fut)
            .await
            .expect("timed out")
    }

    #[tokio::test]
    async fn the_old_pairing_alpn_is_rejected_without_waiting_for_a_code() {
        let dir = tempfile::tempdir().unwrap();
        let new = spawn(dir.path()).await;
        let old = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let addr = new.addr().to_endpoint_addr().unwrap();
        let control = within(old.connect(addr.clone(), PAIR_ALPN)).await.unwrap();
        within(control.closed()).await;
        let error = within(old.connect(addr, b"deadbolt/pair/2"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("protocol"), "{error:?}");
        old.close().await;
        new.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pairing_uses_the_resolved_adjacent_bucket_in_the_pake() {
        use crate::code::{LOOKUP_BUCKET_SECONDS, lookup_bucket};
        let boundary = 1234 * LOOKUP_BUCKET_SECONDS;
        let before = lookup_bucket(boundary - 1);
        let after = lookup_bucket(boundary);
        for (listener_bucket, dialer_bucket) in [(before, after), (after, before)] {
            let dir = tempfile::tempdir().unwrap();
            let new = spawn(dir.path()).await;
            let existing = spawn(dir.path()).await;
            let code = code();
            let options = PairingOptions::default();
            let listener = new
                .start_pairing_in(&code, options, listener_bucket)
                .await
                .unwrap();
            let (joined, invited) = within(async {
                tokio::join!(
                    listener.complete(&Joins),
                    existing.pair_in(&code, options, &Invites, dialer_bucket),
                )
            })
            .await;
            assert_eq!(joined.unwrap().peer, existing.id());
            assert_eq!(invited.unwrap().peer, new.id());
            new.shutdown().await;
            existing.shutdown().await;
        }
    }

    /// Someone who found the new device (its address leaked) but guesses the code gets
    /// one try: the new device fails loudly and the code is spent, so the real
    /// existing device hears that it was used.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_wrong_guess_burns_the_code() {
        let dir = tempfile::tempdir().unwrap();
        let new = spawn(dir.path()).await;
        let attacker = spawn(dir.path()).await;
        let existing = spawn(dir.path()).await;
        let code = PairingCode::generate().unwrap();
        let lookup = Lookup::derive(&code, current_bucket()).unwrap().public;
        let listener = new
            .start_pairing(&code, PairingOptions::default())
            .await
            .unwrap();
        let waiting = tokio::spawn(async move { listener.complete(&Joins).await });
        let guess = PairingCode::generate().unwrap();
        let attempt = within(attacker.pair_with(&new.addr(), &guess, lookup, &Invites)).await;
        assert!(
            matches!(attempt, Err(Error::PairingCodeMismatch)),
            "{attempt:?}"
        );
        let joined = within(waiting).await.unwrap();
        assert!(
            matches!(joined, Err(Error::PairingCodeMismatch)),
            "{joined:?}"
        );
        let late = within(existing.pair(&code, PairingOptions::default(), &Invites)).await;
        assert!(matches!(late, Err(Error::PairingCodeUsed)), "{late:?}");
    }

    /// A dialer naming another code (an old one of this device) is refused without
    /// spending the current code.
    #[tokio::test(flavor = "multi_thread")]
    async fn another_codes_dialer_does_not_spend_this_one() {
        let dir = tempfile::tempdir().unwrap();
        let new = spawn(dir.path()).await;
        let stale = spawn(dir.path()).await;
        let existing = spawn(dir.path()).await;
        let old = PairingCode::generate().unwrap();
        let old_lookup = Lookup::derive(&old, current_bucket()).unwrap().public;
        let code = PairingCode::generate().unwrap();
        let listener = new
            .start_pairing(&code, PairingOptions::default())
            .await
            .unwrap();
        let waiting = tokio::spawn(async move { listener.complete(&Joins).await });
        let attempt = within(stale.pair_with(&new.addr(), &old, old_lookup, &Invites)).await;
        assert!(
            matches!(attempt, Err(Error::PairingCodeUsed)),
            "{attempt:?}"
        );
        let paired = within(existing.pair(&code, PairingOptions::default(), &Invites)).await;
        assert_eq!(paired.unwrap().peer, new.id());
        assert_eq!(within(waiting).await.unwrap().unwrap().peer, existing.id());
    }

    struct NeverJoins;

    impl Joiner for NeverJoins {
        async fn join(&self, _: &PairingContext, _: Vec<u8>) -> Result<Vec<u8>, HandlerError> {
            Err("unused".into())
        }
        async fn receive(&self, _: &PairingContext, _: Vec<Blob>) -> Result<(), HandlerError> {
            Err("unused".into())
        }
    }

    /// Dialers that never run the PAKE hold at most `MAX_PROVING` proof tasks and
    /// `MAX_PROVING` queue slots; the next one is refused as busy.
    #[tokio::test(flavor = "multi_thread")]
    async fn proofs_in_flight_are_capped() {
        let dir = tempfile::tempdir().unwrap();
        let new = spawn(dir.path()).await;
        let dialer = spawn(dir.path()).await;
        let listener = new
            .start_pairing(&code(), PairingOptions::default())
            .await
            .unwrap();
        let waiting = tokio::spawn(async move { listener.complete(&NeverJoins).await });
        let addr = new.addr().to_endpoint_addr().unwrap();
        let mut conns = Vec::new();
        for _ in 0..=2 * MAX_PROVING {
            let conn = dialer.inner.endpoint.connect(addr.clone(), PAIR_ALPN);
            let conn = tokio::time::timeout(Duration::from_secs(10), conn).await;
            conns.push(conn.unwrap().unwrap());
        }
        let mut closed = JoinSet::new();
        for (index, conn) in conns.iter().enumerate() {
            let conn = conn.clone();
            closed.spawn(async move {
                conn.closed().await;
                index
            });
        }
        let index = tokio::time::timeout(Duration::from_secs(10), closed.join_next())
            .await
            .expect("one dialer is refused")
            .unwrap()
            .unwrap();
        assert!(matches!(
            from_conn(&conns[index], Error::Timeout),
            Error::Rejected(reason) if reason == "busy"
        ));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let open = conns.iter().filter(|c| c.close_reason().is_none()).count();
        assert_eq!(open, 2 * MAX_PROVING);
        waiting.abort();
    }
}
