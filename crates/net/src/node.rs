use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use iroh::{
    Endpoint, EndpointAddr, PublicKey, RelayMode, RelayUrl, SecretKey,
    address_lookup::{PkarrPublisher, PkarrResolver},
    endpoint::{
        AfterHandshakeOutcome, BeforeConnectOutcome, ConnectError, ConnectingError, Connection,
        ConnectionError, EndpointHooks, Side, TransportErrorCode, WeakConnectionHandle, presets,
    },
};
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
use iroh::{address_lookup::DnsAddressLookup, endpoint::PortmapperConfig};
use n0_future::{
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use tokio::sync::{Semaphore, mpsc};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::{
    Membership, PAIR_ALPN, PeerId, Rendezvous, SYNC_ALPN,
    error::{Error, Result, close},
    fmt_id,
    sync::{
        DynSyncHandler, INBOUND_SYNC_TIMEOUT, SyncConnection, SyncHandler, SyncOutcome, serve_sync,
    },
};

/// Default maximum size of one frame (one heads blob or one entry).
pub const DEFAULT_MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Default for how many inbound sync connections one peer may hold open at once.
pub const DEFAULT_MAX_INBOUND_PER_PEER: usize = 2;

/// Default for how many authenticated inbound sync connections the node serves at once.
pub const DEFAULT_MAX_INBOUND: usize = 32;

/// How long an inbound connection may take to finish its handshake (and the gate).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Separate from authenticated sync slots: an unidentified peer cannot consume those.
const MAX_INBOUND_HANDSHAKES: usize = 256;

/// Which relay servers the node uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Relays {
    /// n0's public relays.
    N0,
    /// No relays: only direct addresses.
    Disabled,
    /// Custom relay URLs.
    Custom(Vec<String>),
}

/// Configuration for [`Node::spawn`].
#[derive(Clone)]
pub struct NodeConfig {
    /// The device's Ed25519 secret key. Its public key is the node's [`PeerId`].
    pub secret_key: Zeroizing<[u8; 32]>,
    pub relays: Relays,
    /// Publish this node's address to, and resolve peers' addresses from, n0's DNS/pkarr
    /// servers. Required to dial a peer by id alone. Note that it makes the device id
    /// resolvable by anyone who knows it.
    pub address_lookup: bool,
    /// Bind only this socket instead of all interfaces (IPv4 and IPv6). Native only;
    /// browsers use relay connections and ignore this setting.
    pub bind_addr: Option<SocketAddr>,
    /// UPnP/PCP/NAT-PMP port mapping. Native only; ignored in browsers.
    pub portmapper: bool,
    /// Maximum size of a single frame accepted from a peer.
    pub max_frame_len: usize,
    /// How long an inbound sync connection may wait for a stream, and how long each
    /// session may take, before the connection is closed. Each gets its own deadline.
    pub inbound_sync_timeout: Duration,
    /// How many inbound sync connections one peer may hold at once; more are closed as
    /// busy. Connections this node dialed don't count.
    pub max_inbound_per_peer: usize,
    /// How many authenticated inbound sync connections the node serves at once; more
    /// are closed as busy after membership admission. Handshakes have a separate cap.
    pub max_inbound: usize,
    /// Where a new device publishes its pairing record.
    pub rendezvous: Rendezvous,
}

impl NodeConfig {
    /// n0 defaults: public relays and DNS/pkarr address lookup.
    pub fn new(secret_key: [u8; 32]) -> Self {
        Self {
            secret_key: Zeroizing::new(secret_key),
            relays: Relays::N0,
            address_lookup: true,
            bind_addr: None,
            portmapper: true,
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
            inbound_sync_timeout: INBOUND_SYNC_TIMEOUT,
            max_inbound_per_peer: DEFAULT_MAX_INBOUND_PER_PEER,
            max_inbound: DEFAULT_MAX_INBOUND,
            rendezvous: Rendezvous::N0,
        }
    }

    /// No relays, no address lookup, no port mapping, bound to `127.0.0.1:0`, pairing
    /// records in a directory under the system's temporary one. Peers must be dialed with
    /// a [`PeerAddr`] carrying direct addresses. Intended for tests.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    pub fn local_only(secret_key: [u8; 32]) -> Self {
        Self {
            secret_key: Zeroizing::new(secret_key),
            relays: Relays::Disabled,
            address_lookup: false,
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            portmapper: false,
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
            inbound_sync_timeout: INBOUND_SYNC_TIMEOUT,
            max_inbound_per_peer: DEFAULT_MAX_INBOUND_PER_PEER,
            max_inbound: DEFAULT_MAX_INBOUND,
            rendezvous: Rendezvous::Dir(std::env::temp_dir().join("deadbolt-rendezvous")),
        }
    }
}

impl fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeConfig")
            .field("secret_key", &"<redacted>")
            .field("relays", &self.relays)
            .field("address_lookup", &self.address_lookup)
            .field("bind_addr", &self.bind_addr)
            .field("portmapper", &self.portmapper)
            .field("max_frame_len", &self.max_frame_len)
            .field("inbound_sync_timeout", &self.inbound_sync_timeout)
            .field("max_inbound_per_peer", &self.max_inbound_per_peer)
            .field("max_inbound", &self.max_inbound)
            .field("rendezvous", &self.rendezvous)
            .finish()
    }
}

/// How to reach a peer. With only an `id`, the node relies on address lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerAddr {
    pub id: PeerId,
    pub relay_url: Option<String>,
    pub direct_addrs: Vec<SocketAddr>,
}

impl From<PeerId> for PeerAddr {
    fn from(id: PeerId) -> Self {
        Self {
            id,
            relay_url: None,
            direct_addrs: Vec::new(),
        }
    }
}

impl PeerAddr {
    pub(crate) fn to_endpoint_addr(&self) -> Result<EndpointAddr> {
        let id = PublicKey::from_bytes(&self.id)
            .map_err(|_| Error::Connect(format!("invalid peer id {}", fmt_id(&self.id))))?;
        let mut addr = EndpointAddr::new(id);
        if let Some(url) = &self.relay_url {
            let url: RelayUrl = url
                .parse()
                .map_err(|_| Error::InvalidRelayUrl(url.clone()))?;
            addr = addr.with_relay_url(url);
        }
        // Browsers cannot use IP transports. Supplying an unusable direct
        // address would also suppress address lookup when no relay is known.
        #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
        for ip in &self.direct_addrs {
            addr = addr.with_ip_addr(*ip);
        }
        Ok(addr)
    }

    pub(crate) fn from_endpoint_addr(addr: &EndpointAddr) -> Self {
        Self {
            id: *addr.id.as_bytes(),
            relay_url: addr.relay_urls().next().map(|u| u.to_string()),
            direct_addrs: addr.ip_addrs().copied().collect(),
        }
    }
}

/// A deadbolt network node: an iroh endpoint serving the sync and pairing protocols, with
/// the membership gate installed as an endpoint hook.
///
/// Cloning is cheap; the node shuts down when the last clone is dropped (or on
/// [`Node::shutdown`]).
#[derive(Clone)]
pub struct Node {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub(crate) endpoint: Endpoint,
    pub(crate) gate: Arc<Gate>,
    pub(crate) handler: Arc<dyn DynSyncHandler>,
    pub(crate) max_frame_len: usize,
    pub(crate) relays_enabled: bool,
    pub(crate) rendezvous: Rendezvous,
    accept_task: AbortOnDrop,
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("id", &fmt_id(&self.id()))
            .finish_non_exhaustive()
    }
}

impl Node {
    /// Binds the endpoint and starts accepting connections.
    ///
    /// `membership` is consulted for every sync connection, inbound and outbound. It is
    /// called while an internal lock is held, so it must be fast and must not call back
    /// into the [`Node`].
    pub async fn spawn(
        config: NodeConfig,
        membership: Arc<dyn Membership>,
        handler: impl SyncHandler,
    ) -> Result<Self> {
        let gate = Arc::new(Gate::new(membership));
        let relays_enabled = config.relays != Relays::Disabled;
        let relay_mode = match &config.relays {
            Relays::N0 => iroh::endpoint::default_relay_mode(),
            Relays::Disabled => RelayMode::Disabled,
            Relays::Custom(urls) => RelayMode::custom(
                urls.iter()
                    .map(|u| {
                        u.parse::<RelayUrl>()
                            .map_err(|_| Error::InvalidRelayUrl(u.clone()))
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
        };
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&config.secret_key))
            .alpns(vec![SYNC_ALPN.to_vec(), PAIR_ALPN.to_vec()])
            .relay_mode(relay_mode)
            .hooks(GateHook(gate.clone()));
        #[cfg(all(
            feature = "private-relay-fixture",
            debug_assertions,
            target_os = "linux"
        ))]
        if let Some(path) = std::env::var_os("DEADBOLT_RELAY_FIXTURE_CA") {
            let cert = tokio::fs::read(path)
                .await
                .map_err(|e| Error::Bind(e.to_string()))?;
            // Only one regional name exists inside the no-uplink namespace. Do not
            // let a randomly selected, nonexistent home relay make this CLI appear
            // undialable to the browser. Retain QUIC address discovery on loopback.
            let relay: RelayUrl = "https://use1-1.relay.n0.iroh.link./"
                .parse()
                .map_err(|_| Error::Bind("invalid fixture relay URL".into()))?;
            builder = builder
                .ca_tls_config(iroh::tls::CaTlsConfig::custom_roots([cert.into()]))
                .relay_mode(RelayMode::custom([relay]))
                .portmapper_config(PortmapperConfig::Disabled);
        }
        if config.address_lookup {
            builder = builder
                .address_lookup(PkarrPublisher::n0_dns())
                .address_lookup(PkarrResolver::n0_dns());
            #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
            {
                builder = builder.address_lookup(DnsAddressLookup::n0_dns());
            }
        }
        #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
        if !config.portmapper {
            builder = builder.portmapper_config(PortmapperConfig::Disabled);
        }
        #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
        if let Some(addr) = config.bind_addr {
            builder = builder
                .clear_ip_transports()
                .bind_addr(addr)
                .map_err(|e| Error::Bind(e.to_string()))?;
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|e| Error::Bind(e.to_string()))?;

        let handler: Arc<dyn DynSyncHandler> = Arc::new(handler);
        let accept_task = AbortOnDrop(n0_future::task::spawn(accept_loop(
            endpoint.clone(),
            gate.clone(),
            handler.clone(),
            Limits {
                max_frame_len: config.max_frame_len,
                session_timeout: config.inbound_sync_timeout,
                per_peer: config.max_inbound_per_peer,
                total: config.max_inbound,
            },
        )));
        Ok(Self {
            inner: Arc::new(Inner {
                endpoint,
                gate,
                handler,
                max_frame_len: config.max_frame_len,
                relays_enabled,
                rendezvous: config.rendezvous,
                accept_task,
            }),
        })
    }

    /// This node's id (the device's Ed25519 public key).
    pub fn id(&self) -> PeerId {
        *self.inner.endpoint.id().as_bytes()
    }

    /// This node's current address (home relay and direct addresses).
    pub fn addr(&self) -> PeerAddr {
        PeerAddr::from_endpoint_addr(&self.inner.endpoint.addr())
    }

    /// Waits until connected to a home relay. Returns `false` on timeout or if relays are
    /// disabled.
    pub async fn online(&self, timeout: Duration) -> bool {
        self.inner.relays_enabled
            && n0_future::time::timeout(timeout, self.inner.endpoint.online())
                .await
                .is_ok()
    }

    /// Opens a sync connection to a member. Refuses to dial non-members.
    pub async fn connect(&self, peer: impl Into<PeerAddr>) -> Result<SyncConnection> {
        let peer = peer.into();
        self.inner.gate.check_dial(&peer.id)?;
        let addr = peer.to_endpoint_addr()?;
        let conn = match self.inner.endpoint.connect(addr, SYNC_ALPN).await {
            Ok(conn) => conn,
            Err(err) => {
                // The gate may have changed while connecting (checked again after the
                // handshake); report that precisely.
                self.inner.gate.check_dial(&peer.id)?;
                if refused(&err) {
                    // The peer or its QUIC stack refused admission: retry, not unreachable.
                    return Err(Error::Rejected(BUSY_REASON.into()));
                }
                return Err(Error::Connect(err.to_string()));
            }
        };
        Ok(SyncConnection::new(
            conn,
            self.inner.handler.clone(),
            self.inner.max_frame_len,
        ))
    }

    /// Connects, runs one sync session and closes the connection.
    pub async fn sync(&self, peer: impl Into<PeerAddr>) -> Result<SyncOutcome> {
        let conn = self.connect(peer).await?;
        let outcome = conn.sync().await;
        conn.close();
        outcome
    }

    /// Closes every open sync connection to a peer that [`Membership::is_member`] no longer
    /// accepts. Call this after updating membership. Returns the number of connections
    /// closed.
    pub fn enforce_membership(&self) -> usize {
        self.inner.gate.enforce_membership()
    }

    /// Peers with an open sync connection (either direction).
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.inner.gate.connected_peers()
    }

    /// Closes all connections and the endpoint.
    pub async fn shutdown(&self) {
        self.inner.endpoint.close().await;
        self.inner.accept_task.0.abort();
    }
}

/// Why a sync connection over a peer's inbound limits was turned away.
const BUSY_REASON: &str = "too many connections";

/// Whether the peer refused the connection before its handshake (QUIC
/// `CONNECTION_REFUSED`). Either our handshake cap or the transport itself can
/// cause this; it does not prove which limit the peer reached.
fn refused(err: &ConnectError) -> bool {
    let source = match err {
        ConnectError::Connecting {
            source: ConnectingError::ConnectionError { source, .. },
            ..
        }
        | ConnectError::Connection { source, .. } => source,
        _ => return false,
    };
    matches!(
        source,
        ConnectionError::ConnectionClosed(close)
            if close.error_code == TransportErrorCode::CONNECTION_REFUSED
    )
}

struct Limits {
    max_frame_len: usize,
    session_timeout: Duration,
    per_peer: usize,
    total: usize,
}

async fn accept_loop(
    endpoint: Endpoint,
    gate: Arc<Gate>,
    handler: Arc<dyn DynSyncHandler>,
    limits: Limits,
) {
    let Limits {
        max_frame_len,
        session_timeout,
        per_peer,
        total,
    } = limits;
    // Reserve sync capacity for authenticated members, independently of unfinished
    // handshakes. Pairing has its own bounds after handoff.
    let handshakes = Arc::new(Semaphore::new(MAX_INBOUND_HANDSHAKES));
    let syncs = Arc::new(Semaphore::new(total));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                // Make the sender prove it receives at its source address (QUIC Retry)
                // before it can hold a permit, so spoofed Initials can't fill them.
                // Over a relay the relay already vouches for the sender; there it only
                // costs a round trip.
                if !incoming.remote_addr_validated() {
                    if let Err(err) = incoming.retry() {
                        err.into_incoming().refuse();
                    }
                    continue;
                }
                let Ok(handshake) = handshakes.clone().try_acquire_owned() else {
                    debug!("refusing inbound connection: handshake limit reached");
                    incoming.refuse();
                    continue;
                };
                let gate = gate.clone();
                let handler = handler.clone();
                let syncs = syncs.clone();
                tasks.spawn(async move {
                    // The gate hook runs inside this await; a rejected peer never gets here.
                    let conn = match n0_future::time::timeout(HANDSHAKE_TIMEOUT, incoming).await {
                        Ok(Ok(conn)) => conn,
                        Ok(Err(err)) => {
                            debug!("incoming connection failed: {err}");
                            return;
                        }
                        Err(_) => {
                            debug!("incoming connection timed out in its handshake");
                            return;
                        }
                    };
                    drop(handshake);
                    match conn.alpn() {
                        SYNC_ALPN => {
                            let Ok(_permit) = syncs.try_acquire_owned() else {
                                conn.close(close::BUSY, BUSY_REASON.as_bytes());
                                return;
                            };
                            let peer = *conn.remote_id().as_bytes();
                            let Some(_slot) = gate.claim_inbound(peer, per_peer) else {
                                debug!(peer = %fmt_id(&peer), "refusing sync connection: too many open");
                                conn.close(close::BUSY, BUSY_REASON.as_bytes());
                                return;
                            };
                            serve_sync(conn, handler, max_frame_len, session_timeout).await;
                        }
                        PAIR_ALPN => gate.route_pairing(conn),
                        _ => conn.close(close::PROTOCOL, b"unknown alpn"),
                    }
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

/// One inbound sync connection counted against its peer's limit, released on drop.
struct InboundSlot {
    gate: Arc<Gate>,
    peer: PeerId,
}

impl Drop for InboundSlot {
    fn drop(&mut self) {
        let mut st = self.gate.lock();
        if let Some(n) = st.inbound.get_mut(&self.peer) {
            *n -= 1;
            if *n == 0 {
                st.inbound.remove(&self.peer);
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ConnKind {
    Sync,
    Pair,
}

struct Tracked {
    kind: ConnKind,
    handle: WeakConnectionHandle,
}

impl Tracked {
    fn live(&self) -> Option<Connection> {
        self.handle
            .upgrade()
            .filter(|conn| conn.close_reason().is_none())
    }
}

pub(crate) struct PairingSlot {
    pub(crate) id: u64,
    pub(crate) expires_at: Instant,
    pub(crate) tx: mpsc::Sender<Connection>,
}

impl PairingSlot {
    fn open(&self) -> bool {
        Instant::now() < self.expires_at && !self.tx.is_closed()
    }
}

#[derive(Default)]
struct GateState {
    conns: HashMap<PeerId, Vec<Tracked>>,
    /// Inbound sync connections being served, per peer ([`InboundSlot`]).
    inbound: HashMap<PeerId, usize>,
    pairing: Option<PairingSlot>,
    next_slot: u64,
    /// The last code was used (or burnt by a wrong guess), and no new one opened since:
    /// late dialers hear so rather than "not pairing".
    used: bool,
}

impl GateState {
    /// Why a pairing connection can't be taken, if it can't.
    fn pairing_refusal(&self) -> Option<(iroh::endpoint::VarInt, &'static [u8])> {
        if self.pairing.as_ref().is_some_and(PairingSlot::open) {
            None
        } else if self.used {
            Some((close::PAIRING_USED, b"code already used"))
        } else {
            Some((close::PAIRING_UNAVAILABLE, b"not pairing"))
        }
    }
}

/// The membership gate. Shared by the endpoint hook and the [`Node`].
pub struct Gate {
    membership: Arc<dyn Membership>,
    state: Mutex<GateState>,
}

impl fmt::Debug for Gate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gate").finish_non_exhaustive()
    }
}

impl Gate {
    /// Creates a gate without opening a transport endpoint.
    pub fn new(membership: Arc<dyn Membership>) -> Self {
        Self {
            membership,
            state: Mutex::default(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Checks current membership before opening a sync stream.
    pub fn check_dial(&self, peer: &PeerId) -> Result<()> {
        if !self.membership.is_member(peer) {
            return Err(Error::NotAMember(*peer));
        }
        Ok(())
    }

    fn allow_dial(&self, peer: &PeerId, alpn: &[u8]) -> bool {
        match alpn {
            SYNC_ALPN => self.check_dial(peer).is_ok(),
            PAIR_ALPN => true,
            _ => false,
        }
    }

    /// Decides whether a connection whose TLS handshake just completed may proceed, and
    /// registers it for revocation. The membership check and the registration happen
    /// under one lock, and [`Gate::enforce_membership`] takes the same lock after the
    /// caller updates [`Membership`], so a connection admitted concurrently with a
    /// removal is always either rejected here or closed there. No sticky revocation set is
    /// needed, so a device removed from one vault can still pair into another vault later.
    fn admit(
        &self,
        conn: &Connection,
    ) -> std::result::Result<(), (iroh::endpoint::VarInt, &'static [u8])> {
        let peer = *conn.remote_id().as_bytes();
        let mut st = self.lock();
        let kind = match conn.alpn() {
            SYNC_ALPN => {
                if !self.membership.is_member(&peer) {
                    return Err((close::NOT_MEMBER, b"not a member"));
                }
                ConnKind::Sync
            }
            PAIR_ALPN => {
                if conn.side() == Side::Server
                    && let Some(refusal) = st.pairing_refusal()
                {
                    return Err(refusal);
                }
                ConnKind::Pair
            }
            _ => return Err((close::PROTOCOL, b"unknown alpn")),
        };
        let list = st.conns.entry(peer).or_default();
        list.retain(|t| t.live().is_some());
        list.push(Tracked {
            kind,
            handle: conn.weak_handle(),
        });
        Ok(())
    }

    /// Closes every tracked sync connection to a peer that [`Membership::is_member`] no
    /// longer accepts.
    pub fn enforce_membership(&self) -> usize {
        let mut st = self.lock();
        let mut closed = 0;
        for (peer, list) in st.conns.iter_mut() {
            if self.membership.is_member(peer) {
                continue;
            }
            list.retain(|t| {
                if t.kind != ConnKind::Sync {
                    return true;
                }
                if let Some(conn) = t.live() {
                    conn.close(close::NOT_MEMBER, b"not a member");
                    closed += 1;
                }
                false
            });
        }
        st.conns.retain(|_, list| !list.is_empty());
        closed
    }

    fn connected_peers(&self) -> Vec<PeerId> {
        let mut st = self.lock();
        st.conns.retain(|_, list| {
            list.retain(|t| t.live().is_some());
            !list.is_empty()
        });
        st.conns
            .iter()
            .filter(|(_, list)| list.iter().any(|t| t.kind == ConnKind::Sync))
            .map(|(peer, _)| *peer)
            .collect()
    }

    /// Counts one more inbound sync connection from `peer`, unless it already has `max`.
    fn claim_inbound(self: &Arc<Self>, peer: PeerId, max: usize) -> Option<InboundSlot> {
        let mut st = self.lock();
        let n = st.inbound.get(&peer).copied().unwrap_or(0);
        if n >= max {
            return None;
        }
        st.inbound.insert(peer, n + 1);
        drop(st);
        Some(InboundSlot {
            gate: self.clone(),
            peer,
        })
    }

    pub(crate) fn open_pairing(&self, expires_at: Instant, tx: mpsc::Sender<Connection>) -> u64 {
        let mut st = self.lock();
        st.next_slot += 1;
        let id = st.next_slot;
        st.pairing = Some(PairingSlot { id, expires_at, tx });
        st.used = false;
        id
    }

    pub(crate) fn close_pairing(&self, id: u64) {
        let mut st = self.lock();
        if st.pairing.as_ref().is_some_and(|s| s.id == id) {
            st.pairing = None;
        }
    }

    /// Closes the slot because its code was used up.
    pub(crate) fn consume_pairing(&self, id: u64) {
        let mut st = self.lock();
        if st.pairing.as_ref().is_some_and(|s| s.id == id) {
            st.pairing = None;
            st.used = true;
        }
    }

    fn route_pairing(&self, conn: Connection) {
        let route = {
            let st = self.lock();
            match st.pairing_refusal() {
                None => st
                    .pairing
                    .as_ref()
                    .map(|s| s.tx.clone())
                    .ok_or((close::PAIRING_UNAVAILABLE, &b"not pairing"[..])),
                Some(refusal) => Err(refusal),
            }
        };
        match route {
            Ok(tx) => {
                if let Err(err) = tx.try_send(conn) {
                    warn!("dropping pairing connection: {err}");
                    let (mpsc::error::TrySendError::Full(conn)
                    | mpsc::error::TrySendError::Closed(conn)) = err;
                    conn.close(close::PAIRING_UNAVAILABLE, b"busy");
                }
            }
            Err((code, reason)) => conn.close(code, reason),
        }
    }
}

#[derive(Debug)]
struct GateHook(Arc<Gate>);

impl EndpointHooks for GateHook {
    fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> impl Future<Output = BeforeConnectOutcome> + Send + 'a {
        let allowed = self.0.allow_dial(remote_addr.id.as_bytes(), alpn);
        async move {
            if allowed {
                BeforeConnectOutcome::Accept
            } else {
                debug!(peer = %remote_addr.id.fmt_short(), "refusing to dial");
                BeforeConnectOutcome::Reject
            }
        }
    }

    fn after_handshake<'a>(
        &'a self,
        conn: &'a Connection,
    ) -> impl Future<Output = AfterHandshakeOutcome> + Send + 'a {
        let outcome = match self.0.admit(conn) {
            Ok(()) => AfterHandshakeOutcome::Accept,
            Err((error_code, reason)) => {
                debug!(
                    peer = %conn.remote_id().fmt_short(),
                    reason = %String::from_utf8_lossy(reason),
                    "rejecting connection"
                );
                AfterHandshakeOutcome::Reject {
                    error_code,
                    reason: reason.to_vec(),
                }
            }
        };
        async move { outcome }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{HandlerError, SyncHandler};

    pub(crate) struct Nothing;

    impl SyncHandler for Nothing {
        type ReceiveState = ();

        async fn heads(&self, _: PeerId) -> Result<Vec<u8>, HandlerError> {
            Ok(vec![])
        }
        async fn missing_for(
            &self,
            _: PeerId,
            _: Vec<u8>,
        ) -> Result<crate::Outgoing<'_>, HandlerError> {
            Ok(Box::new(std::iter::empty()))
        }
        async fn receive(
            &self,
            _: PeerId,
            _: Vec<crate::Blob>,
            _: &mut (),
            _: bool,
        ) -> Result<(), HandlerError> {
            Ok(())
        }
    }

    async fn node(membership: impl Membership + 'static) -> Node {
        let key = SecretKey::generate().to_bytes();
        Node::spawn(NodeConfig::local_only(key), Arc::new(membership), Nothing)
            .await
            .unwrap()
    }

    /// The endpoint hook itself refuses to dial non-members, independent of the check in
    /// `Node::connect`.
    #[tokio::test]
    async fn endpoint_hook_refuses_raw_dial_to_non_member() {
        let a = node(|_: &PeerId| false).await;
        let b = node(|_: &PeerId| true).await;
        let addr = b.addr().to_endpoint_addr().unwrap();
        let err = a.inner.endpoint.connect(addr.clone(), SYNC_ALPN).await;
        assert!(err.is_err());
        assert!(b.connected_peers().is_empty());
        // The pairing ALPN is not membership-gated on dial (the remote decides).
        let conn = a.inner.endpoint.connect(addr, PAIR_ALPN).await;
        if let Ok(conn) = conn {
            // b has no outstanding code, so it closes the connection.
            conn.closed().await;
            assert!(matches!(
                crate::error::from_conn(&conn, Error::Timeout),
                Error::Rejected(_)
            ));
        }
    }

    /// The accept-side hook rejects a raw sync connection from a non-member before the
    /// accept loop ever sees it.
    #[tokio::test]
    async fn endpoint_hook_rejects_raw_inbound_non_member() {
        let a = node(|_: &PeerId| false).await;
        let b = node(|_: &PeerId| true).await;
        let conn = b
            .inner
            .endpoint
            .connect(a.addr().to_endpoint_addr().unwrap(), SYNC_ALPN)
            .await
            .unwrap();
        conn.closed().await;
        assert!(matches!(
            crate::error::from_conn(&conn, Error::Timeout),
            Error::MembershipRejected(r) if r == "not a member"
        ));
        assert!(a.connected_peers().is_empty());
    }

    /// QUIC itself can refuse a handshake, independently of our established sync
    /// cap. Keep the typed mapping that makes startup retry rather than skip it.
    #[tokio::test]
    async fn transport_refusal_is_reported_as_busy() {
        let server = Endpoint::builder(presets::Minimal)
            .alpns(vec![SYNC_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let client = node(|_: &PeerId| true).await;
        let addr = PeerAddr::from_endpoint_addr(&server.addr());
        let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(client.connect(addr), async {
                server.accept().await.unwrap().refuse();
            })
        })
        .await
        .unwrap();
        assert!(matches!(result, Err(Error::Rejected(r)) if r == BUSY_REASON));
        server.close().await;
        client.shutdown().await;
    }

    #[tokio::test]
    async fn sync_preserves_remote_membership_refusal() {
        let a = node(|_: &PeerId| false).await;
        let b = node(|_: &PeerId| true).await;
        let conn = b.connect(a.addr()).await.unwrap();
        let error = conn.sync().await.unwrap_err();
        assert!(matches!(error, Error::MembershipRejected(_)), "{error:?}");
    }
}
