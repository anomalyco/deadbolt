use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use iroh::{
    Endpoint, EndpointAddr, PublicKey, RelayMode, RelayUrl, SecretKey,
    address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver},
    endpoint::{
        AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, PortmapperConfig,
        Side, WeakConnectionHandle, presets,
    },
};
use tokio::{
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::{
    Membership, PAIR_ALPN, PeerId, SYNC_ALPN,
    error::{Error, Result, close},
    fmt_id,
    sync::{DynSyncHandler, SyncConnection, SyncHandler, SyncOutcome, serve_sync},
};

/// Default maximum size of one frame (one heads blob or one entry).
pub const DEFAULT_MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

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
    /// Bind only this socket instead of all interfaces (IPv4 and IPv6).
    pub bind_addr: Option<SocketAddr>,
    /// UPnP/PCP/NAT-PMP port mapping.
    pub portmapper: bool,
    /// Maximum size of a single frame accepted from a peer.
    pub max_frame_len: usize,
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
        }
    }

    /// No relays, no address lookup, no port mapping, bound to `127.0.0.1:0`. Peers must be
    /// dialed with a [`PeerAddr`] carrying direct addresses. Intended for tests.
    pub fn local_only(secret_key: [u8; 32]) -> Self {
        Self {
            secret_key: Zeroizing::new(secret_key),
            relays: Relays::Disabled,
            address_lookup: false,
            bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            portmapper: false,
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
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
        if config.address_lookup {
            builder = builder
                .address_lookup(PkarrPublisher::n0_dns())
                .address_lookup(PkarrResolver::n0_dns())
                .address_lookup(DnsAddressLookup::n0_dns());
        }
        if !config.portmapper {
            builder = builder.portmapper_config(PortmapperConfig::Disabled);
        }
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
        let accept_task = AbortOnDrop(tokio::spawn(accept_loop(
            endpoint.clone(),
            gate.clone(),
            handler.clone(),
            config.max_frame_len,
        )));
        Ok(Self {
            inner: Arc::new(Inner {
                endpoint,
                gate,
                handler,
                max_frame_len: config.max_frame_len,
                relays_enabled,
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
            && tokio::time::timeout(timeout, self.inner.endpoint.online())
                .await
                .is_ok()
    }

    /// Opens a sync connection to a member. Refuses to dial non-members and revoked peers.
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

    /// Permanently refuses `peer` on this node (for its lifetime) and immediately closes
    /// every open connection to it, on any ALPN. Call this as soon as a `Remove` for the
    /// peer is applied. Returns the number of connections closed.
    pub fn revoke(&self, peer: &PeerId) -> usize {
        self.inner.gate.revoke(peer)
    }

    /// Closes every open sync connection to a peer that [`Membership::is_member`] no longer
    /// accepts. Call this after applying membership changes received from a peer. Returns
    /// the number of connections closed.
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

async fn accept_loop(
    endpoint: Endpoint,
    gate: Arc<Gate>,
    handler: Arc<dyn DynSyncHandler>,
    max_frame_len: usize,
) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let gate = gate.clone();
                let handler = handler.clone();
                tasks.spawn(async move {
                    // The gate hook runs inside this await; a rejected peer never gets here.
                    let conn = match incoming.await {
                        Ok(conn) => conn,
                        Err(err) => {
                            debug!("incoming connection failed: {err}");
                            return;
                        }
                    };
                    match conn.alpn() {
                        SYNC_ALPN => serve_sync(conn, handler, max_frame_len).await,
                        PAIR_ALPN => gate.route_pairing(conn),
                        _ => conn.close(close::PROTOCOL, b"unknown alpn"),
                    }
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
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
    revoked: HashSet<PeerId>,
    pairing: Option<PairingSlot>,
    next_slot: u64,
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

    /// Checks current membership and explicit revocations before opening a stream.
    pub fn check_dial(&self, peer: &PeerId) -> Result<()> {
        let st = self.lock();
        if st.revoked.contains(peer) {
            return Err(Error::Revoked(*peer));
        }
        if !self.membership.is_member(peer) {
            return Err(Error::NotAMember(*peer));
        }
        Ok(())
    }

    fn allow_dial(&self, peer: &PeerId, alpn: &[u8]) -> bool {
        match alpn {
            SYNC_ALPN => self.check_dial(peer).is_ok(),
            PAIR_ALPN => !self.lock().revoked.contains(peer),
            _ => false,
        }
    }

    /// Decides whether a connection whose TLS handshake just completed may proceed, and
    /// registers it for revocation. The membership check and the registration happen
    /// under one lock, and [`Gate::revoke`] takes the same lock, so a connection admitted
    /// concurrently with a revocation is always either rejected here or closed there.
    fn admit(
        &self,
        conn: &Connection,
    ) -> std::result::Result<(), (iroh::endpoint::VarInt, &'static [u8])> {
        let peer = *conn.remote_id().as_bytes();
        let mut st = self.lock();
        if st.revoked.contains(&peer) {
            return Err((close::REVOKED, b"revoked"));
        }
        let kind = match conn.alpn() {
            SYNC_ALPN => {
                if !self.membership.is_member(&peer) {
                    return Err((close::NOT_MEMBER, b"not a member"));
                }
                ConnKind::Sync
            }
            PAIR_ALPN => {
                if conn.side() == Side::Server
                    && !st.pairing.as_ref().is_some_and(PairingSlot::open)
                {
                    return Err((close::PAIRING_UNAVAILABLE, b"not pairing"));
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

    /// Permanently refuses this peer and closes its tracked iroh connections.
    /// Other transport adapters must cancel their streams when this gate refuses them.
    pub fn revoke(&self, peer: &PeerId) -> usize {
        let mut st = self.lock();
        st.revoked.insert(*peer);
        let closed = st
            .conns
            .remove(peer)
            .unwrap_or_default()
            .iter()
            .filter_map(Tracked::live)
            .map(|conn| conn.close(close::REVOKED, b"revoked"))
            .count();
        debug!(peer = %fmt_id(peer), closed, "revoked");
        closed
    }

    fn enforce_membership(&self) -> usize {
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

    pub(crate) fn open_pairing(&self, expires_at: Instant, tx: mpsc::Sender<Connection>) -> u64 {
        let mut st = self.lock();
        st.next_slot += 1;
        let id = st.next_slot;
        st.pairing = Some(PairingSlot { id, expires_at, tx });
        id
    }

    pub(crate) fn close_pairing(&self, id: u64) {
        let mut st = self.lock();
        if st.pairing.as_ref().is_some_and(|s| s.id == id) {
            st.pairing = None;
        }
    }

    fn route_pairing(&self, conn: Connection) {
        let tx = {
            let st = self.lock();
            st.pairing
                .as_ref()
                .filter(|s| s.open())
                .map(|s| s.tx.clone())
        };
        match tx {
            Some(tx) => {
                if let Err(err) = tx.try_send(conn) {
                    warn!("dropping pairing connection: {err}");
                    let (mpsc::error::TrySendError::Full(conn)
                    | mpsc::error::TrySendError::Closed(conn)) = err;
                    conn.close(close::PAIRING_UNAVAILABLE, b"busy");
                }
            }
            None => conn.close(close::PAIRING_UNAVAILABLE, b"not pairing"),
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
mod tests {
    use super::*;
    use crate::{HandlerError, SyncHandler};

    struct Nothing;

    impl SyncHandler for Nothing {
        async fn heads(&self, _: PeerId) -> Result<Vec<u8>, HandlerError> {
            Ok(vec![])
        }
        async fn missing_for(&self, _: PeerId, _: Vec<u8>) -> Result<Vec<Vec<u8>>, HandlerError> {
            Ok(vec![])
        }
        async fn receive(&self, _: PeerId, _: Vec<Vec<u8>>) -> Result<(), HandlerError> {
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
            // b has no outstanding ticket, so it closes the connection.
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

    #[tokio::test]
    async fn sync_preserves_remote_membership_refusal() {
        let a = node(|_: &PeerId| false).await;
        let b = node(|_: &PeerId| true).await;
        let conn = b.connect(a.addr()).await.unwrap();
        let error = conn.sync().await.unwrap_err();
        assert!(matches!(error, Error::MembershipRejected(_)), "{error:?}");
    }
}
