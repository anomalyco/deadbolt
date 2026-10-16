//! Pairing (`deadbolt/pair/1`).
//!
//! The new device ("listener") calls [`Node::start_pairing`] and shows the
//! [`PairingTicket`] (QR or text). The existing device ("dialer") calls [`Node::pair`]
//! with it. On one bidirectional stream opened by the dialer:
//!
//! ```text
//! dialer -> listener  PROOF(HMAC(secret, "dialer"   || transcript))
//! listener -> dialer  PROOF(HMAC(secret, "listener" || transcript))   (ticket consumed)
//! both                CONFIRM([1]) once the local user confirmed the code
//! dialer -> listener  OFFER(blob)
//! listener -> dialer  JOIN(blob)
//! dialer -> listener  ENTRY(blob)* DONE
//! listener -> dialer  RESULT
//! ```

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use sha2::Sha256;
use tokio::{sync::mpsc, task::JoinSet, time::Instant};
use tracing::{debug, warn};

use crate::{
    Node, PAIR_ALPN, PeerAddr, PeerId,
    error::{Error, HandlerError, Result, close, from_conn},
    frame::{self, tag},
    sync::{fail, truncate},
};

/// Default lifetime of a pairing ticket.
pub const DEFAULT_PAIRING_TTL: Duration = Duration::from_secs(10 * 60);

const TICKET_PREFIX: &str = "DBPAIR";
const TICKET_VERSION: u8 = 1;
const MAX_TICKET_ADDRS: usize = 8;
const PROOF_TIMEOUT: Duration = Duration::from_secs(30);
const LINGER_TIMEOUT: Duration = Duration::from_secs(5);
const EXPORTER_LABEL: &[u8] = b"EXPORTER-deadbolt-pair-v1";
const TRANSCRIPT_LABEL: &[u8] = b"deadbolt/pair/1";
const DIALER_LABEL: &[u8] = b"dialer-proof";
const LISTENER_LABEL: &[u8] = b"listener-proof";
const CODE_LABEL: &[u8] = b"confirmation-code";

/// A one-time pairing ticket created by the new device.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingTicket {
    id: PeerId,
    secret: [u8; 32],
    relay_url: Option<String>,
    direct_addrs: Vec<SocketAddr>,
}

impl fmt::Debug for PairingTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingTicket")
            .field("id", &crate::fmt_id(&self.id))
            .field("secret", &"<redacted>")
            .field("relay_url", &self.relay_url)
            .field("direct_addrs", &self.direct_addrs)
            .finish()
    }
}

impl PairingTicket {
    /// The new device's id.
    pub fn peer_id(&self) -> PeerId {
        self.id
    }

    /// How to reach the new device.
    pub fn addr(&self) -> PeerAddr {
        PeerAddr {
            id: self.id,
            relay_url: self.relay_url.clone(),
            direct_addrs: self.direct_addrs.clone(),
        }
    }

    /// Binary form: `version(1) || id(32) || secret(32) || relay_len(1) || relay_url ||
    /// addr_count(1) || addr*`, each addr `4 || ipv4(4) || port(2)` or
    /// `6 || ipv6(16) || port(2)`, integers big-endian.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.push(TICKET_VERSION);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.secret);
        let relay = self.relay_url.as_deref().unwrap_or("").as_bytes();
        out.push(relay.len() as u8);
        out.extend_from_slice(relay);
        out.push(self.direct_addrs.len() as u8);
        for addr in &self.direct_addrs {
            match addr.ip() {
                IpAddr::V4(ip) => {
                    out.push(4);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(6);
                    out.extend_from_slice(&ip.octets());
                }
            }
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        if r.take(1)?[0] != TICKET_VERSION {
            return Err(Error::InvalidTicket("unsupported version".into()));
        }
        let id: PeerId = r.take(32)?.try_into().expect("32 bytes");
        let secret: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        let relay_len = r.take(1)?[0] as usize;
        let relay_url = match relay_len {
            0 => None,
            n => Some(
                String::from_utf8(r.take(n)?.to_vec())
                    .map_err(|_| Error::InvalidTicket("relay url is not utf-8".into()))?,
            ),
        };
        let count = r.take(1)?[0] as usize;
        let mut direct_addrs = Vec::with_capacity(count);
        for _ in 0..count {
            let ip = match r.take(1)?[0] {
                4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(r.take(4)?).expect("4"))),
                6 => IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(r.take(16)?).expect("16"),
                )),
                _ => return Err(Error::InvalidTicket("bad address family".into())),
            };
            let port = u16::from_be_bytes(r.take(2)?.try_into().expect("2"));
            direct_addrs.push(SocketAddr::new(ip, port));
        }
        if !r.0.is_empty() {
            return Err(Error::InvalidTicket("trailing bytes".into()));
        }
        iroh::PublicKey::from_bytes(&id)
            .map_err(|_| Error::InvalidTicket("invalid endpoint id".into()))?;
        Ok(Self {
            id,
            secret,
            relay_url,
            direct_addrs,
        })
    }

    /// Terminal QR code (unicode half blocks) of the ticket string.
    pub fn to_qr(&self, style: crate::QrStyle) -> Result<String> {
        crate::render_qr(&self.to_string(), style)
    }
}

/// `DBPAIR` followed by the unpadded uppercase RFC 4648 base32 of [`PairingTicket::to_bytes`].
/// Only uses QR alphanumeric characters, so QR codes encode it compactly.
impl fmt::Display for PairingTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{TICKET_PREFIX}{}",
            BASE32_NOPAD.encode(&self.to_bytes())
        )
    }
}

/// Case-insensitive; ignores whitespace and `-` so the string survives copy/paste and
/// manual grouping.
impl FromStr for PairingTicket {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let cleaned: String = s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let body = cleaned
            .strip_prefix(TICKET_PREFIX)
            .ok_or_else(|| Error::InvalidTicket("missing DBPAIR prefix".into()))?;
        let bytes = BASE32_NOPAD
            .decode(body.as_bytes())
            .map_err(|e| Error::InvalidTicket(format!("bad base32: {e}")))?;
        Self::from_bytes(&bytes)
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::InvalidTicket("truncated".into()));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
}

/// Six-digit code both devices display so the user can confirm they are talking to each
/// other.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConfirmationCode(u32);

impl ConfirmationCode {
    pub fn value(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for ConfirmationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:06}", self.0)
    }
}

impl fmt::Debug for ConfirmationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConfirmationCode({self})")
    }
}

/// What both sides know once the pairing proofs succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingContext {
    pub local: PeerId,
    pub remote: PeerId,
    pub code: ConfirmationCode,
}

/// Result of a successful pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingOutcome {
    pub peer: PeerId,
    pub code: ConfirmationCode,
}

/// New-device side of pairing.
pub trait Joiner: Send + Sync {
    /// Called once both sides proved the ticket secret. Show `ctx.code` and return whether
    /// the user confirmed it matches the other screen. Return `true` without asking when
    /// the ticket was scanned from a QR code shown by this device.
    fn confirm(&self, ctx: &PairingContext) -> impl Future<Output = bool> + Send;

    /// Produce the join blob (e.g. the new device's signed consent to join the vault named
    /// in `offer`).
    fn join(
        &self,
        ctx: &PairingContext,
        offer: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, HandlerError>> + Send;

    /// The existing device's welcome blobs (e.g. the `Add` op, membership log and data).
    fn receive(
        &self,
        ctx: &PairingContext,
        welcome: Vec<Vec<u8>>,
    ) -> impl Future<Output = Result<(), HandlerError>> + Send;
}

/// Existing-device side of pairing.
pub trait Inviter: Send + Sync {
    /// See [`Joiner::confirm`].
    fn confirm(&self, ctx: &PairingContext) -> impl Future<Output = bool> + Send;

    /// The offer blob sent to the new device (e.g. the vault id it is asked to join).
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
    ) -> impl Future<Output = Result<Vec<Vec<u8>>, HandlerError>> + Send;
}

/// Options for [`Node::start_pairing`].
#[derive(Clone, Copy, Debug)]
pub struct PairingOptions {
    /// How long the ticket is valid. Default 10 minutes.
    pub ttl: Duration,
    /// How long to wait for a home relay before creating the ticket, so it carries a relay
    /// hint. Ignored when relays are disabled. Default 10 seconds.
    pub online_timeout: Duration,
}

impl Default for PairingOptions {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_PAIRING_TTL,
            online_timeout: Duration::from_secs(10),
        }
    }
}

/// An outstanding pairing ticket on the new device. Dropping it invalidates the ticket.
pub struct PairingListener {
    node: Node,
    ticket: PairingTicket,
    slot: u64,
    expires_at: Instant,
    rx: mpsc::Receiver<Connection>,
}

impl fmt::Debug for PairingListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingListener")
            .field("ticket", &self.ticket)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl Drop for PairingListener {
    fn drop(&mut self) {
        self.node.inner.gate.close_pairing(self.slot);
    }
}

struct Proven {
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    transcript: Vec<u8>,
}

impl PairingListener {
    pub fn ticket(&self) -> &PairingTicket {
        &self.ticket
    }

    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    /// Waits for an existing device to dial with the ticket and runs the pairing. Dialers
    /// that fail the proof are dropped without consuming the ticket; the first one that
    /// passes consumes it, whatever happens afterwards.
    pub async fn complete(mut self, joiner: &impl Joiner) -> Result<PairingOutcome> {
        let local = self.node.id();
        let secret = self.ticket.secret;
        let mut proving = JoinSet::new();
        let proven = loop {
            tokio::select! {
                _ = tokio::time::sleep_until(self.expires_at) => return Err(Error::PairingExpired),
                conn = self.rx.recv() => {
                    let Some(conn) = conn else { return Err(Error::PairingCancelled) };
                    proving.spawn(listener_prove(conn, local, secret));
                }
                Some(res) = proving.join_next(), if !proving.is_empty() => match res {
                    Ok(Ok(proven)) if Instant::now() < self.expires_at => break proven,
                    Ok(Ok(proven)) => {
                        proven.conn.close(close::PAIRING_UNAVAILABLE, b"expired");
                        return Err(Error::PairingExpired);
                    }
                    Ok(Err(err)) => warn!("pairing attempt failed: {err}"),
                    Err(err) => warn!("pairing attempt panicked: {err}"),
                },
            }
        };
        // Single use: nobody else can reach the pairing protocol from here on.
        self.node.inner.gate.close_pairing(self.slot);
        drop(proving);

        let Proven {
            conn,
            mut send,
            mut recv,
            transcript,
        } = proven;
        let remote = *conn.remote_id().as_bytes();
        let ctx = PairingContext {
            local,
            remote,
            code: confirmation_code(&secret, &transcript),
        };
        let max = self.node.inner.max_frame_len;
        let result = async {
            let proof = mac(&secret, LISTENER_LABEL, &transcript);
            frame::write(&mut send, tag::PROOF, &proof).await?;
            confirm_exchange(&conn, &mut send, &mut recv, joiner.confirm(&ctx)).await?;

            let offer = frame::expect(&mut recv, tag::OFFER, max).await?;
            let join = joiner.join(&ctx, offer).await.map_err(Error::Handler)?;
            frame::write(&mut send, tag::JOIN, &join).await?;
            let welcome = frame::read_entries(&mut recv, max).await?;
            let received = joiner.receive(&ctx, welcome).await;
            let report = received.as_ref().map(|_| ()).map_err(|e| e.to_string());
            frame::write_result(&mut send, &report).await?;
            let _ = send.finish();
            received.map_err(Error::Handler)
        }
        .await;
        match result {
            Ok(()) => {
                // Let the dialer read RESULT; it closes the connection once it has.
                let _ = tokio::time::timeout(LINGER_TIMEOUT, conn.closed()).await;
                debug!(peer = %crate::fmt_id(&remote), "paired");
                Ok(PairingOutcome {
                    peer: remote,
                    code: ctx.code,
                })
            }
            Err(err) => Err(fail_pairing(&conn, err).await),
        }
    }
}

async fn listener_prove(conn: Connection, local: PeerId, secret: [u8; 32]) -> Result<Proven> {
    let remote = *conn.remote_id().as_bytes();
    let (send, mut recv) = match tokio::time::timeout(PROOF_TIMEOUT, conn.accept_bi()).await {
        Ok(Ok(streams)) => streams,
        Ok(Err(e)) => return Err(fail_pairing(&conn, Error::Closed(e.to_string())).await),
        Err(_) => {
            conn.close(close::PROTOCOL, b"timeout");
            return Err(Error::Timeout);
        }
    };
    let attempt = async {
        let proof = frame::expect(&mut recv, tag::PROOF, 64).await?;
        let transcript = transcript(&conn, &local, &remote)?;
        if !verify(&secret, DIALER_LABEL, &transcript, &proof) {
            return Err(Error::PairingProofFailed);
        }
        Ok(transcript)
    };
    match tokio::time::timeout(PROOF_TIMEOUT, attempt).await {
        Ok(Ok(transcript)) => Ok(Proven {
            conn,
            send,
            recv,
            transcript,
        }),
        Ok(Err(err)) => Err(fail_pairing(&conn, err).await),
        Err(_) => {
            conn.close(close::PROTOCOL, b"timeout");
            Err(Error::Timeout)
        }
    }
}

impl Node {
    /// Creates a one-time pairing ticket for this (new) device and starts accepting pairing
    /// connections for it. Replaces any previous outstanding ticket.
    pub async fn start_pairing(&self, options: PairingOptions) -> Result<PairingListener> {
        if self.inner.relays_enabled {
            let _ =
                tokio::time::timeout(options.online_timeout, self.inner.endpoint.online()).await;
        }
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|e| Error::Io(std::io::Error::other(e)))?;
        let addr = self.addr();
        let ticket = PairingTicket {
            id: addr.id,
            secret,
            relay_url: addr.relay_url.filter(|u| u.len() <= u8::MAX as usize),
            direct_addrs: addr
                .direct_addrs
                .into_iter()
                .take(MAX_TICKET_ADDRS)
                .collect(),
        };
        let expires_at = Instant::now() + options.ttl;
        let (tx, rx) = mpsc::channel(16);
        let slot = self.inner.gate.open_pairing(expires_at, tx);
        Ok(PairingListener {
            node: self.clone(),
            ticket,
            slot,
            expires_at,
            rx,
        })
    }

    /// Pairs with a new device using its ticket (existing-device side).
    pub async fn pair(
        &self,
        ticket: &PairingTicket,
        inviter: &impl Inviter,
    ) -> Result<PairingOutcome> {
        let local = self.id();
        let addr = ticket.addr().to_endpoint_addr()?;
        let conn = self
            .inner
            .endpoint
            .connect(addr, PAIR_ALPN)
            .await
            .map_err(|e| Error::Connect(e.to_string()))?;
        if *conn.remote_id().as_bytes() != ticket.id {
            conn.close(close::PROTOCOL, b"unexpected peer");
            return Err(Error::Protocol("connected to unexpected peer".into()));
        }
        let max = self.inner.max_frame_len;
        let secret = ticket.secret;
        let (mut send, mut recv) = match conn.open_bi().await {
            Ok(streams) => streams,
            Err(e) => return Err(fail_pairing(&conn, Error::Closed(e.to_string())).await),
        };
        // Streams outlive the block so a failure closes the connection (with its reason)
        // before they are dropped.
        let result = async {
            let transcript = transcript(&conn, &ticket.id, &local)?;
            frame::write(
                &mut send,
                tag::PROOF,
                &mac(&secret, DIALER_LABEL, &transcript),
            )
            .await?;
            let proof = frame::expect(&mut recv, tag::PROOF, 64).await?;
            if !verify(&secret, LISTENER_LABEL, &transcript, &proof) {
                return Err(Error::PairingProofFailed);
            }
            let ctx = PairingContext {
                local,
                remote: ticket.id,
                code: confirmation_code(&secret, &transcript),
            };
            confirm_exchange(&conn, &mut send, &mut recv, inviter.confirm(&ctx)).await?;

            let offer = inviter.offer(&ctx).await.map_err(Error::Handler)?;
            frame::write(&mut send, tag::OFFER, &offer).await?;
            let join = frame::expect(&mut recv, tag::JOIN, max).await?;
            let welcome = inviter.welcome(&ctx, join).await.map_err(Error::Handler)?;
            frame::write_entries(&mut send, &welcome).await?;
            let _ = send.finish();
            frame::read_result(&mut recv, max).await?;
            Ok(PairingOutcome {
                peer: ticket.id,
                code: ctx.code,
            })
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

/// Runs the local confirmation (aborting if the peer goes away meanwhile), then exchanges
/// `CONFIRM` frames.
async fn confirm_exchange(
    conn: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    confirm: impl Future<Output = bool>,
) -> Result<()> {
    let confirmed = tokio::select! {
        ok = confirm => ok,
        _ = conn.closed() => return Err(from_conn(conn, Error::Closed("closed".into()))),
    };
    if !confirmed {
        return Err(Error::PairingDeclined);
    }
    let ((), peer) = tokio::try_join!(
        frame::write(send, tag::CONFIRM, &[1]),
        frame::expect(recv, tag::CONFIRM, 64),
    )?;
    if peer != [1] {
        return Err(Error::PairingDeclined);
    }
    Ok(())
}

async fn fail_pairing(conn: &Connection, err: Error) -> Error {
    match &err {
        Error::PairingProofFailed => conn.close(close::PAIRING_PROOF_FAILED, b"proof failed"),
        Error::PairingDeclined => conn.close(close::PAIRING_DECLINED, b"declined"),
        Error::Remote(m) => conn.close(close::ABORTED, truncate(m)),
        _ => return fail(conn, err).await,
    }
    err
}

/// `"deadbolt/pair/1" || listener id || dialer id || TLS exporter(32)`. The exporter value
/// is unique to this QUIC connection, binding the proofs and the confirmation code to it.
fn transcript(conn: &Connection, listener: &PeerId, dialer: &PeerId) -> Result<Vec<u8>> {
    let mut ekm = [0u8; 32];
    conn.export_keying_material(&mut ekm, EXPORTER_LABEL, b"")
        .map_err(|_| Error::Protocol("keying material export failed".into()))?;
    let mut t = Vec::with_capacity(TRANSCRIPT_LABEL.len() + 96);
    t.extend_from_slice(TRANSCRIPT_LABEL);
    t.extend_from_slice(listener);
    t.extend_from_slice(dialer);
    t.extend_from_slice(&ekm);
    Ok(t)
}

fn hmac(secret: &[u8; 32], label: &[u8], transcript: &[u8]) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("any key length");
    m.update(label);
    m.update(&[0]);
    m.update(transcript);
    m
}

fn mac(secret: &[u8; 32], label: &[u8], transcript: &[u8]) -> Vec<u8> {
    hmac(secret, label, transcript)
        .finalize()
        .into_bytes()
        .to_vec()
}

fn verify(secret: &[u8; 32], label: &[u8], transcript: &[u8], tag: &[u8]) -> bool {
    hmac(secret, label, transcript).verify_slice(tag).is_ok()
}

fn confirmation_code(secret: &[u8; 32], transcript: &[u8]) -> ConfirmationCode {
    let out = mac(secret, CODE_LABEL, transcript);
    let n = u64::from_be_bytes(out[..8].try_into().expect("8 bytes"));
    ConfirmationCode((n % 1_000_000) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket() -> PairingTicket {
        PairingTicket {
            id: *iroh::SecretKey::from_bytes(&[7; 32]).public().as_bytes(),
            secret: [9; 32],
            relay_url: Some("https://relay.example.com./".into()),
            direct_addrs: vec![
                "127.0.0.1:4242".parse().unwrap(),
                "[fe80::1]:9".parse().unwrap(),
            ],
        }
    }

    #[test]
    fn ticket_roundtrip() {
        let t = ticket();
        let s = t.to_string();
        assert!(s.starts_with("DBPAIR"));
        assert!(
            s.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        );
        assert_eq!(s.parse::<PairingTicket>().unwrap(), t);
        // copy/paste tolerant
        let messy = format!("  {}\n{} ", &s[..20].to_lowercase(), &s[20..]);
        assert_eq!(messy.parse::<PairingTicket>().unwrap(), t);

        let bare = PairingTicket {
            relay_url: None,
            direct_addrs: vec![],
            ..t.clone()
        };
        assert_eq!(bare.to_string().parse::<PairingTicket>().unwrap(), bare);
        assert!(!format!("{t:?}").contains("9, 9"));
    }

    #[test]
    fn ticket_rejects_garbage() {
        let s = ticket().to_string();
        assert!("".parse::<PairingTicket>().is_err());
        assert!(s[6..].parse::<PairingTicket>().is_err());
        assert!(s[..s.len() - 3].parse::<PairingTicket>().is_err());
        assert!(format!("{s}AA").parse::<PairingTicket>().is_err());
        let mut bytes = ticket().to_bytes();
        bytes[0] = 2;
        assert!(PairingTicket::from_bytes(&bytes).is_err());
    }

    #[test]
    fn ticket_qr_renders() {
        let qr = ticket().to_qr(crate::QrStyle::LightOnDark).unwrap();
        assert!(qr.lines().count() > 10);
    }

    #[test]
    fn proofs_are_bound_to_labels_and_transcript() {
        let secret = [1; 32];
        let a = mac(&secret, DIALER_LABEL, b"t");
        assert!(verify(&secret, DIALER_LABEL, b"t", &a));
        assert!(!verify(&secret, LISTENER_LABEL, b"t", &a));
        assert!(!verify(&secret, DIALER_LABEL, b"u", &a));
        assert!(!verify(&[2; 32], DIALER_LABEL, b"t", &a));
        assert!(confirmation_code(&secret, b"t").value() < 1_000_000);
        assert_eq!(ConfirmationCode(42).to_string(), "000042");
    }
}
