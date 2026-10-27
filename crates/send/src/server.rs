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
use tokio::{sync::watch, task::JoinHandle};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::{
    MAX_SEALED_LEN, Network, Policy, Refusal, SEND_ALPN, SenderAddr, Share, State, close,
    error::{Error, Result},
    proof, receive, status,
};

const ONLINE_TIMEOUT: Duration = Duration::from_secs(10);
const STEP_TIMEOUT: Duration = Duration::from_secs(30);
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
    loop {
        tokio::select! {
            incoming = inner.endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                tasks.spawn(serve(inner.clone(), incoming));
            }
            _ = sweep.tick() => inner.sweep(),
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

async fn serve(inner: Arc<Inner>, incoming: Incoming) {
    let conn = match incoming.await {
        Ok(conn) => conn,
        Err(error) => {
            debug!(%error, "send connection failed");
            return;
        }
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
            send.write_all(&[code])
                .await
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

    let mut head = Vec::with_capacity(9);
    head.push(status::OK);
    head.extend_from_slice(&(sealed.len() as u64).to_be_bytes());
    let sent = async {
        send.write_all(&head).await?;
        send.write_all(&sealed).await?;
        Ok::<_, iroh::endpoint::WriteError>(())
    }
    .await;
    // Once the whole bundle went out the open counts, acknowledged or not: the
    // receiver may have it.
    finish(inner, &id, sent.is_ok());
    sent.map_err(|e| Error::Protocol(e.to_string()))?;
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
