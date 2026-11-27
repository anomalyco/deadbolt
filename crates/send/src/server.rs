//! The sending side: an iroh endpoint of its own serving shares from memory.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use iroh::{
    Endpoint, RelayMode, SecretKey,
    endpoint::{Connection, Incoming, PortmapperConfig, presets},
};
use tokio::{
    sync::{Semaphore, watch},
    task::JoinHandle,
};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::{
    MAX_SEALED_LEN, Network, Policy, Refusal, SEND_ALPN, SenderAddr, Share, State, close,
    error::{Error, Result},
    proof, receive, status,
};

const ONLINE_TIMEOUT: Duration = Duration::from_secs(10);
const STEP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const SWEEP_EVERY: Duration = Duration::from_secs(30);
/// How long a finished share stays listed after it expires.
const KEEP_FINISHED: u64 = 24 * 60 * 60;

/// The current time in Unix seconds.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// A share to serve.
pub struct ShareRequest {
    /// The access secret receivers prove.
    pub secret: Zeroizing<[u8; 32]>,
    /// The bundle, already sealed with the content key (which the server never
    /// sees).
    pub sealed: Vec<u8>,
    pub policy: Policy,
    /// What the sender sees in lists, e.g. the file names.
    pub label: String,
}

/// A share as the sender sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareInfo {
    pub id: String,
    pub label: String,
    /// Sealed bytes.
    pub size: usize,
    pub created: u64,
    pub state: State,
    pub share: Share,
}

struct Hosted {
    label: String,
    size: usize,
    created: u64,
    secret: Zeroizing<[u8; 32]>,
    /// Dropped once the share can't be opened any more.
    sealed: Option<Arc<Vec<u8>>>,
    share: Share,
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Inner {
    endpoint: Endpoint,
    network: Network,
    clock: Clock,
    shares: Mutex<BTreeMap<String, Hosted>>,
    changed: watch::Sender<u64>,
}

/// Serves shares on [`SEND_ALPN`] until dropped. Cheap to clone.
#[derive(Clone)]
pub struct Server {
    inner: Arc<Inner>,
    _accept: Arc<AbortOnDrop>,
}

impl Server {
    /// Binds an endpoint with a fresh random key: links don't reveal the
    /// device, and stop working when this server goes away.
    pub async fn spawn(network: Network, clock: Clock) -> Result<Self> {
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .alpns(vec![SEND_ALPN.to_vec()]);
        let builder = match network {
            Network::Relays => builder.relay_mode(iroh::endpoint::default_relay_mode()),
            Network::Local => receive::local(
                builder
                    .relay_mode(RelayMode::Disabled)
                    .portmapper_config(PortmapperConfig::Disabled),
            )?,
        };
        let endpoint = builder
            .bind()
            .await
            .map_err(|e| Error::Bind(e.to_string()))?;
        let inner = Arc::new(Inner {
            endpoint,
            network,
            clock,
            shares: Mutex::default(),
            changed: watch::channel(0).0,
        });
        let accept = AbortOnDrop(tokio::spawn(accept_loop(inner.clone())));
        Ok(Self {
            inner,
            _accept: Arc::new(accept),
        })
    }

    /// How receivers reach this server. Waits briefly for a home relay so links
    /// work from browsers; without one the address has none.
    pub async fn addr(&self) -> SenderAddr {
        if self.inner.network == Network::Relays
            && tokio::time::timeout(ONLINE_TIMEOUT, self.inner.endpoint.online())
                .await
                .is_err()
        {
            warn!("no home relay yet; the link will only work outside browsers");
        }
        let addr = self.inner.endpoint.addr();
        let relay_url = addr.relay_urls().next().map(|u| u.to_string());
        // Browsers only use the relay. Direct addresses would only lengthen the link
        // and tell its holder this computer's network addresses, so they go in only
        // without a relay (local networks, tests).
        let direct_addrs = match relay_url {
            Some(_) => Vec::new(),
            None => addr.ip_addrs().copied().collect(),
        };
        SenderAddr {
            id: *addr.id.as_bytes(),
            relay_url,
            direct_addrs,
        }
    }

    /// Starts serving a share.
    pub fn add(&self, request: ShareRequest) -> Result<ShareInfo> {
        if request.sealed.len() > MAX_SEALED_LEN {
            return Err(Error::TooLarge {
                len: request.sealed.len(),
                max: MAX_SEALED_LEN,
            });
        }
        let mut id_bytes = [0u8; 5];
        getrandom::fill(&mut id_bytes).map_err(|e| Error::Rng(e.to_string()))?;
        let id = data_encoding::BASE32_NOPAD
            .encode(&id_bytes)
            .to_ascii_lowercase();
        let hosted = Hosted {
            label: request.label,
            size: request.sealed.len(),
            created: self.now(),
            secret: request.secret,
            sealed: Some(Arc::new(request.sealed)),
            share: Share::new(request.policy),
        };
        let info = self.inner.info(&id, &hosted);
        self.inner.lock().insert(id, hosted);
        self.inner.notify();
        Ok(info)
    }

    /// Every share, oldest first.
    pub fn list(&self) -> Vec<ShareInfo> {
        self.inner.sweep();
        let shares = self.inner.lock();
        let mut list: Vec<ShareInfo> = shares
            .iter()
            .map(|(id, h)| self.inner.info(id, h))
            .collect();
        list.sort_by_key(|s| s.created);
        list
    }

    /// The share with this id, or the only one whose id starts with it.
    pub fn get(&self, id: &str) -> Option<ShareInfo> {
        self.inner.sweep();
        let shares = self.inner.lock();
        let id = find(&shares, id)?;
        Some(self.inner.info(&id, &shares[&id]))
    }

    /// Stops a share being opened.
    pub fn revoke(&self, id: &str) -> Option<ShareInfo> {
        let now = self.now();
        let info = {
            let mut shares = self.inner.lock();
            let id = find(&shares, id)?;
            let hosted = shares.get_mut(&id)?;
            hosted.share.revoke(now);
            if hosted.share.is_done(now) {
                hosted.sealed = None;
            }
            self.inner.info(&id, hosted)
        };
        self.inner.notify();
        Some(info)
    }

    /// Waits until the share can't be opened any more: picked up, expired or
    /// revoked.
    pub async fn wait(&self, id: &str) -> Option<ShareInfo> {
        let mut changed = self.inner.changed.subscribe();
        loop {
            changed.borrow_and_update();
            let info = self.get(id)?;
            if info.state != State::Open {
                return Some(info);
            }
            // Expiry isn't an event: check every second (the clock may not be tokio's).
            tokio::select! {
                _ = changed.changed() => {}
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    }

    /// Closes the endpoint; links stop working.
    pub async fn shutdown(&self) {
        self.inner.endpoint.close().await;
    }

    fn now(&self) -> u64 {
        (self.inner.clock)()
    }
}

/// The exact id, else the only id it prefixes.
fn find(shares: &BTreeMap<String, Hosted>, id: &str) -> Option<String> {
    if shares.contains_key(id) {
        return Some(id.to_string());
    }
    let mut matches = shares.keys().filter(|k| k.starts_with(id));
    let first = matches.next()?;
    matches.next().is_none().then(|| first.clone())
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Hosted>> {
        self.shares.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn notify(&self) {
        self.changed.send_modify(|n| *n += 1);
    }

    fn info(&self, id: &str, h: &Hosted) -> ShareInfo {
        ShareInfo {
            id: id.to_string(),
            label: h.label.clone(),
            size: h.size,
            created: h.created,
            state: h.share.state((self.clock)()),
            share: h.share.clone(),
        }
    }

    /// Drops the bundles of finished shares and forgets old ones.
    fn sweep(&self) {
        let now = (self.clock)();
        let mut expired = false;
        self.lock().retain(|_, h| {
            if h.share.is_done(now) && h.share.in_flight == 0 && h.sealed.take().is_some() {
                expired = true;
            }
            h.share.policy.expires_at.saturating_add(KEEP_FINISHED) > now
        });
        if expired {
            self.notify();
        }
    }
}

async fn accept_loop(inner: Arc<Inner>) {
    let mut sweep = tokio::time::interval(SWEEP_EVERY);
    let mut tasks = tokio::task::JoinSet::new();
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            incoming = inner.endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                if !incoming.remote_addr_validated() {
                    if let Err(error) = incoming.retry() {
                        error.into_incoming().refuse();
                    }
                    continue;
                }
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let inner = inner.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    serve(inner, incoming).await;
                });
            }
            _ = sweep.tick() => inner.sweep(),
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

async fn serve(inner: Arc<Inner>, incoming: Incoming) {
    let conn = match tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(error)) => {
            debug!(%error, "send connection failed");
            return;
        }
        Err(_) => return,
    };
    if let Err(error) = exchange(&inner, &conn).await {
        debug!(%error, "send exchange failed");
        conn.close(close::PROTOCOL, b"failed");
    }
}

async fn exchange(inner: &Inner, conn: &Connection) -> Result<()> {
    let timeout = |what: &'static str| move |_| Error::Protocol(format!("timed out {what}"));
    let (mut send, mut recv) = tokio::time::timeout(STEP_TIMEOUT, conn.accept_bi())
        .await
        .map_err(timeout("waiting for a stream"))?
        .map_err(|e| Error::Protocol(e.to_string()))?;
    let local = *inner.endpoint.id().as_bytes();
    let remote = *conn.remote_id().as_bytes();
    let transcript = proof::transcript(conn, &local, &remote)?;
    let mut proof = [0u8; proof::PROOF_LEN];
    tokio::time::timeout(STEP_TIMEOUT, recv.read_exact(&mut proof))
        .await
        .map_err(timeout("waiting for the proof"))?
        .map_err(|e| Error::Protocol(e.to_string()))?;

    let now = (inner.clock)();
    let found = {
        let mut shares = inner.lock();
        shares
            .iter_mut()
            .find(|(_, h)| proof::verify(&h.secret, &transcript, &proof))
            .map(|(id, h)| (id.clone(), h.share.begin(now).map(|()| h.sealed.clone())))
    };
    let (id, sealed) = match found {
        None => {
            conn.close(close::UNKNOWN, b"unknown link");
            return Ok(());
        }
        Some((id, Ok(Some(sealed)))) => (id, sealed),
        Some((id, Ok(None))) => {
            // Open but already swept; can't happen, but never serve nothing.
            finish(inner, &id, false);
            return Err(Error::Protocol("share has no bundle".into()));
        }
        Some((_, Err(refusal))) => {
            let code = match refusal {
                Refusal::Expired => status::EXPIRED,
                Refusal::Used => status::USED,
                Refusal::Revoked => status::REVOKED,
            };
            tokio::time::timeout(STEP_TIMEOUT, send.write_all(&[code]))
                .await
                .map_err(timeout("writing the refusal"))?
                .map_err(|e| Error::Protocol(e.to_string()))?;
            send.finish().map_err(|e| Error::Protocol(e.to_string()))?;
            #[expect(
                clippy::let_underscore_must_use,
                reason = "best effort: let the refusal arrive before closing"
            )]
            let _ = tokio::time::timeout(STEP_TIMEOUT, conn.closed()).await;
            return Ok(());
        }
    };

    let mut transfer = Transfer {
        inner,
        id: &id,
        finished: false,
    };
    let mut head = Vec::with_capacity(9);
    head.push(status::OK);
    head.extend_from_slice(&(sealed.len() as u64).to_be_bytes());
    // Reset the deadline for each bounded chunk: a large bundle may take minutes,
    // but a receiver that stops draining cannot reserve an open indefinitely.
    for chunk in std::iter::once(head.as_slice()).chain(sealed.chunks(64 * 1024)) {
        tokio::time::timeout(STEP_TIMEOUT, send.write_all(chunk))
            .await
            .map_err(timeout("writing the bundle"))?
            .map_err(|e| Error::Protocol(e.to_string()))?;
    }
    // The receiver may have the whole bundle even without acknowledging it.
    transfer.complete();
    send.finish().map_err(|e| Error::Protocol(e.to_string()))?;
    let mut ack = [0u8; 1];
    match tokio::time::timeout(STEP_TIMEOUT, recv.read_exact(&mut ack)).await {
        Ok(Ok(())) => conn.close(close::DONE, b"done"),
        _ => debug!(share = %id, "no acknowledgement from the receiver"),
    }
    Ok(())
}

fn finish(inner: &Inner, id: &str, delivered: bool) {
    let now = (inner.clock)();
    if let Some(h) = inner.lock().get_mut(id) {
        h.share.finish(now, delivered);
        if h.share.is_done(now) && h.share.in_flight == 0 {
            h.sealed = None;
        }
    }
    inner.notify();
}

/// An acquired open belongs to the exchange future, including cancellation.
struct Transfer<'a> {
    inner: &'a Inner,
    id: &'a str,
    finished: bool,
}

impl Transfer<'_> {
    fn complete(&mut self) {
        finish(self.inner, self.id, true);
        self.finished = true;
    }
}

impl Drop for Transfer<'_> {
    fn drop(&mut self) {
        if !self.finished {
            finish(self.inner, self.id, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Bundle, Entry, Node, PolicyHeader, SendTicket};

    #[tokio::test]
    async fn cancelling_a_reserved_transfer_releases_a_single_open_link() {
        let server = Server::spawn(Network::Local, Arc::new(|| 1000))
            .await
            .unwrap();
        let secret = crate::random_secret().unwrap();
        let key = crate::random_secret().unwrap();
        let bundle = Bundle {
            title: None,
            note: None,
            entries: vec![Node::Entry(Entry {
                name: "large.bin".into(),
                data: vec![0x5a; 16 * 1024 * 1024],
                mime: None,
                sensitive: false,
            })],
        };
        let sealed = crate::seal(
            &key,
            &PolicyHeader {
                expires_unix: 2000,
                multi_open: false,
            },
            &bundle.encode(),
        )
        .unwrap();
        let info = server
            .add(ShareRequest {
                secret: secret.clone(),
                sealed,
                policy: Policy {
                    opens: 1,
                    expires_at: 2000,
                },
                label: "test".into(),
            })
            .unwrap();
        let ticket = SendTicket::new(server.addr().await, secret, key);
        let receiver = receive::local(
            Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Disabled)
                .portmapper_config(PortmapperConfig::Disabled)
                .transport_config(
                    iroh::endpoint::QuicTransportConfig::builder()
                        .stream_receive_window(1024u32.into())
                        .receive_window(1024u32.into())
                        .build(),
                ),
        )
        .unwrap()
        .bind()
        .await
        .unwrap();
        let conn = receiver
            .connect(ticket.endpoint_addr().unwrap(), SEND_ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let transcript = proof::transcript(&conn, &ticket.id, receiver.id().as_bytes()).unwrap();
        send.write_all(&proof::prove(&ticket.secret, &transcript))
            .await
            .unwrap();
        let mut header = [0u8; 9];
        tokio::time::timeout(STEP_TIMEOUT, recv.read_exact(&mut header))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(header[0], status::OK);
        assert_eq!(server.get(&info.id).unwrap().share.in_flight, 1);
        // The receiver stops draining. Cancelling the server drops its real exchange future.
        let mut changed = server.inner.changed.subscribe();
        server._accept.0.abort();
        tokio::time::timeout(STEP_TIMEOUT, async {
            while server.get(&info.id).unwrap().share.in_flight != 0 {
                changed.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        conn.close(close::DONE, b"test complete");
        receiver.close().await;
        let _restarted = AbortOnDrop(tokio::spawn(accept_loop(server.inner.clone())));
        let receiver = crate::receiver_endpoint(Network::Local).await.unwrap();
        assert_eq!(
            crate::receive(&receiver, &ticket, |_| {}).await.unwrap(),
            bundle
        );
        assert_eq!(server.get(&info.id).unwrap().state, State::PickedUp);
        receiver.close().await;
        server.shutdown().await;
    }
}
