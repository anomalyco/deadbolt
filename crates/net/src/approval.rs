//! Experimental, single-read user approval. No values, grants, or log entries travel here.
//! Only a node with an explicitly installed inbox advertises this ALPN.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use data_encoding::HEXLOWER;
use iroh::{PublicKey, SecretKey, Signature, endpoint::Connection};
use n0_future::time::Instant;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::{Error, Node, PeerAddr, PeerId, Result, error::close, frame};

pub(crate) const ALPN: &[u8] = b"deadbolt/experimental/read-approval/1";
const TTL: u64 = 90;
/// Allowed displacement between peer clocks, including answer transit time.
const CLOCK_SKEW: u64 = 30;
const MAX_FRAME: usize = 8192;
const REQUEST: u8 = 1;
const RESPONSE: u8 = 2;

fn invalid() -> Error {
    Error::Protocol("invalid or no longer outstanding read approval".into())
}
#[expect(
    clippy::disallowed_methods,
    reason = "Unix time at the approval protocol boundary"
)]
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Signed facts for precisely one Read (plaintext release to this caller). Names and
/// process paths are display labels; the stable vault and item IDs are authoritative.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadScope {
    pub vault: String,
    pub item: String,
    pub field: String,
    pub title: String,
    pub origin_name: String,
    /// Audit-token verified process executable, pid/version and code hash. Never the
    /// caller's self-description or claimed identity; ancestry is marked as a hint.
    pub caller: String,
}

fn clean(s: &str, max: usize) -> bool {
    fn unsafe_display(c: char) -> bool {
        c.is_control()
            || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    }
    !s.is_empty() && s.len() <= max && !s.chars().any(unsafe_display)
}
fn hex_id(s: &str, size: usize) -> bool {
    s.len() == size * 2
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl ReadScope {
    fn valid(&self) -> bool {
        hex_id(&self.vault, 32)
            && hex_id(&self.item, 16)
            && clean(&self.field, 256)
            && clean(&self.title, 512)
            && clean(&self.origin_name, 256)
            && clean(&self.caller, 1024)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    origin: PeerId,
    approver: PeerId,
    nonce: [u8; 32],
    expires_at: u64,
    scope: ReadScope,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Answer {
    hash: [u8; 32],
    approver: PeerId,
    allow: bool,
    time: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed<T> {
    body: T,
    signature: Signature,
}
// Canonical compact JSON over fixed-order structs, with only strings, fixed-size
// arrays, integers and bools; no maps, floats or optional fields. Sign the hash
// of these bytes, not the peer's possibly noncanonical JSON spelling.
fn digest<T: Serialize>(domain: &[u8], body: &T) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(body).map_err(|_| invalid())?;
    Ok(Sha256::new()
        .chain_update(ALPN)
        .chain_update(domain)
        .chain_update(bytes)
        .finalize()
        .into())
}
// Tolerate a phone clock behind the origin when checking the signed issue time
// (expiry - TTL). Do not keep a prompt past expiry on the phone's own clock:
// an ahead phone may dismiss early. The origin *never* adds skew to its window.
fn live_on_phone(expiry: u64, at: u64) -> bool {
    expiry > at && expiry - at <= TTL + CLOCK_SKEW
}
fn live_on_origin(expiry: u64, at: u64) -> bool {
    expiry > at && expiry - at <= TTL
}
impl Signed<Request> {
    fn verify(&self, peer: &PublicKey, local: &PeerId, at: u64) -> Result<[u8; 32]> {
        let r = &self.body;
        let hash = digest(b"/request\0", r)?;
        if peer.as_bytes() != &r.origin
            || local != &r.approver
            || local == &r.origin
            || !live_on_phone(r.expires_at, at)
            || !r.scope.valid()
            || peer.verify(&hash, &self.signature).is_err()
        {
            return Err(invalid());
        }
        Ok(hash)
    }
}
impl Signed<Answer> {
    fn verify(&self, hash: [u8; 32], peer: &PublicKey, r: &Request, at: u64) -> Result<()> {
        let a = &self.body;
        if a.hash != hash
            || a.approver != r.approver
            || peer.as_bytes() != &r.approver
            || a.approver == r.origin
            || !live_on_origin(r.expires_at, at)
            || a.time >= r.expires_at
            || a.time.abs_diff(at) > CLOCK_SKEW
            || peer
                .verify(&digest(b"/answer\0", a)?, &self.signature)
                .is_err()
        {
            return Err(invalid());
        }
        if !a.allow {
            return Err(Error::Rejected("read denied on approver".into()));
        }
        Ok(())
    }
}

/// Metadata for the mobile UI, only after checking TLS identity, signature,
/// expiry, destination and the vault-specific membership/readiness predicate.
#[derive(Clone, Debug)]
pub struct PendingRead {
    pub id: String,
    pub origin: PeerId,
    pub expires_at: u64,
    pub scope: ReadScope,
}
struct Slot {
    snapshot: PendingRead,
    hash: [u8; 32],
    approver: PeerId,
    tx: oneshot::Sender<Signed<Answer>>,
}
type Allowed = dyn Fn(&str, &PeerId) -> bool + Send + Sync;
struct InboxState {
    slot: Option<Slot>,
    seen: HashMap<[u8; 32], u64>,
}
/// One pending read at a time. Clone into `NodeConfig.approval_inbox`. Create a
/// fresh inbox on each unlock; the mobile adapter must verify fresh biometric
/// key release for this specific displayed `id` before calling `respond`.
#[derive(Clone)]
pub struct ApprovalInbox {
    state: Arc<Mutex<InboxState>>,
    allowed: Arc<Allowed>,
}
impl ApprovalInbox {
    /// `allowed(vault_hex, origin)` must check current membership of BOTH local
    /// and origin keys in that exact vault, plus unlocked and startup-ready.
    /// This predicate runs while validating an inbox slot. It must not call
    /// back into the inbox. Never hold the adapter's loaded-state lock when
    /// calling pending/respond (including after a biometric unwrap).
    pub fn new(allowed: impl Fn(&str, &PeerId) -> bool + Send + Sync + 'static) -> Self {
        Self {
            state: Arc::new(Mutex::new(InboxState {
                slot: None,
                seen: HashMap::new(),
            })),
            allowed: Arc::new(allowed),
        }
    }
    fn state(&self) -> std::sync::MutexGuard<'_, InboxState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn live(&self, slot: &Slot) -> bool {
        !slot.tx.is_closed()
            && live_on_phone(slot.snapshot.expires_at, now())
            && (self.allowed)(&slot.snapshot.scope.vault, &slot.snapshot.origin)
    }
    pub fn pending(&self) -> Option<PendingRead> {
        let mut state = self.state();
        if state.slot.as_ref().is_some_and(|s| !self.live(s)) {
            state.slot.take();
        }
        state.slot.as_ref().map(|s| s.snapshot.clone())
    }
    /// Sign the response with this device's Ed25519 key, only after user
    /// verification. A stale display id cannot approve a newer request.
    pub fn respond(&self, id: &str, allow: bool, device_key: &[u8; 32]) -> Result<()> {
        let key = SecretKey::from_bytes(device_key);
        let mut state = self.state();
        let slot = state.slot.as_ref().ok_or_else(invalid)?;
        if slot.snapshot.id != id || !self.live(slot) || key.public().as_bytes() != &slot.approver {
            return Err(invalid());
        }
        let slot = state.slot.take().ok_or_else(invalid)?;
        let body = Answer {
            hash: slot.hash,
            approver: slot.approver,
            allow,
            time: now(),
        };
        let signature = key.sign(&digest(b"/answer\0", &body)?);
        slot.tx
            .send(Signed { body, signature })
            .map_err(|_| invalid())
    }
    fn insert(&self, hash: [u8; 32], r: Request) -> Result<oneshot::Receiver<Signed<Answer>>> {
        if !(self.allowed)(&r.scope.vault, &r.origin) {
            return Err(invalid());
        }
        let (tx, rx) = oneshot::channel();
        let mut st = self.state();
        let at = now();
        st.seen.retain(|_, expiry| *expiry > at);
        if st.slot.as_ref().is_some_and(|s| self.live(s))
            || st.seen.len() >= 128
            || st.seen.contains_key(&hash)
            || !live_on_phone(r.expires_at, at)
        {
            return Err(invalid());
        }
        st.seen.insert(hash, r.expires_at);
        st.slot = Some(Slot {
            snapshot: PendingRead {
                id: HEXLOWER.encode(&hash),
                origin: r.origin,
                expires_at: r.expires_at,
                scope: r.scope,
            },
            hash,
            approver: r.approver,
            tx,
        });
        Ok(rx)
    }
}

pub(crate) async fn serve(conn: Connection, local: PeerId, inbox: ApprovalInbox) {
    let run = async {
        let (mut send, mut recv) = conn.accept_bi().await.map_err(|_| invalid())?;
        let data = frame::expect(&mut recv, REQUEST, MAX_FRAME).await?;
        let r: Signed<Request> = serde_json::from_slice(&data).map_err(|_| invalid())?;
        let hash = r.verify(&conn.remote_id(), &local, now())?;
        let response = inbox.insert(hash, r.body)?;
        let answer = tokio::select! {
            result = response => result.map_err(|_| invalid())?,
            _ = conn.closed() => return Err(invalid()),
        };
        let bytes = serde_json::to_vec(&answer).map_err(|_| invalid())?;
        frame::write(&mut send, RESPONSE, &bytes).await?;
        send.finish().map_err(|_| invalid())?;
        send.stopped().await.map_err(|_| invalid())?;
        Ok::<_, Error>(())
    };
    if !matches!(
        n0_future::time::timeout(Duration::from_secs(TTL), run).await,
        Ok(Ok(()))
    ) {
        conn.close(close::ABORTED, b"approval unavailable");
    }
}

/// A non-cloneable, one-shot result; no bearer token or persisted grant. The
/// origin must consume it under its live session lock with the *resolved* scope
/// and currently designated member before returning the value to this socket.
pub struct ApprovedRead {
    scope: ReadScope,
    approver: PeerId,
    expires_at: u64,
    deadline: Instant,
}
impl ApprovedRead {
    pub fn consume(self, scope: &ReadScope, current_approver: &PeerId) -> Result<()> {
        if &self.scope == scope
            && &self.approver == current_approver
            && live_on_origin(self.expires_at, now())
            && Instant::now() < self.deadline
        {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}
impl Node {
    /// Exactly one request, on one QUIC stream, to one explicitly designated
    /// member. `still_designated` rechecks per-vault membership and capability
    /// after dialing, before releasing any metadata. No retry on failure.
    pub async fn request_read_approval(
        &self,
        peer: PeerAddr,
        scope: ReadScope,
        still_designated: impl Fn() -> bool,
    ) -> Result<ApprovedRead> {
        if peer.id == self.id() || !scope.valid() || !still_designated() {
            return Err(invalid());
        }
        self.inner.gate.check_dial(&peer.id)?;
        // Carry the same local budget through consumption, even if the wall
        // clock moves back or the session lock is busy after the exchange.
        let deadline = Instant::now() + Duration::from_secs(TTL);
        let run = async {
            let conn = self
                .inner
                .endpoint
                .connect(peer.to_endpoint_addr()?, ALPN)
                .await
                .map_err(|_| invalid())?;
            let (mut send, mut recv) = conn.open_bi().await.map_err(|_| invalid())?;
            if conn.remote_id().as_bytes() != &peer.id || !still_designated() {
                return Err(invalid());
            }
            let mut nonce = [0; 32];
            getrandom::fill(&mut nonce).map_err(|_| invalid())?;
            let expires_at = now() + TTL;
            let body = Request {
                origin: self.id(),
                approver: peer.id,
                nonce,
                expires_at,
                scope,
            };
            let hash = digest(b"/request\0", &body)?;
            let signature = self.inner.endpoint.secret_key().sign(&hash);
            let signed = Signed { body, signature };
            let bytes = serde_json::to_vec(&signed).map_err(|_| invalid())?;
            frame::write(&mut send, REQUEST, &bytes).await?;
            send.finish().map_err(|_| invalid())?;
            let data = frame::expect(&mut recv, RESPONSE, MAX_FRAME).await?;
            let signed_answer: Signed<Answer> =
                serde_json::from_slice(&data).map_err(|_| invalid())?;
            signed_answer.verify(hash, &conn.remote_id(), &signed.body, now())?;
            if !still_designated() {
                return Err(invalid());
            }
            Ok(ApprovedRead {
                scope: signed.body.scope,
                approver: peer.id,
                expires_at,
                deadline,
            })
        };
        n0_future::time::timeout(deadline.saturating_duration_since(Instant::now()), run)
            .await
            .map_err(|_| Error::Timeout)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeConfig, node::tests::Nothing};
    use std::sync::atomic::{AtomicBool, Ordering};

    fn scope() -> ReadScope {
        ReadScope {
            vault: "01".repeat(32),
            item: "02".repeat(16),
            field: "password".into(),
            title: "Test account".into(),
            origin_name: "test mac".into(),
            caller: "synthetic process fixture".into(),
        }
    }
    #[test]
    fn signed_request_and_response_reject_mutation_replay_self_expiry_and_wrong_signer() {
        let origin = SecretKey::generate();
        let approver = SecretKey::generate();
        let other = SecretKey::generate();
        let at = now();
        let make = || Request {
            origin: *origin.public().as_bytes(),
            approver: *approver.public().as_bytes(),
            nonce: [7; 32],
            expires_at: at + TTL,
            scope: scope(),
        };
        let mut request = make();
        let hash = digest(b"/request\0", &request).unwrap();
        let signed = |body| Signed {
            body,
            signature: origin.sign(&hash),
        };
        let check =
            |r: Signed<Request>| r.verify(&origin.public(), approver.public().as_bytes(), at);
        assert_eq!(check(signed(make())).unwrap(), hash);
        request.scope.field = "otp".into();
        assert!(check(signed(request)).is_err());
        assert!(
            signed(make())
                .verify(&other.public(), approver.public().as_bytes(), at)
                .is_err()
        );
        assert!(
            signed(make())
                .verify(&origin.public(), origin.public().as_bytes(), at)
                .is_err()
        );
        assert!(
            signed(make())
                .verify(&origin.public(), approver.public().as_bytes(), at + TTL)
                .is_err()
        );
        let answer = Answer {
            hash,
            approver: *approver.public().as_bytes(),
            allow: true,
            time: at,
        };
        let signature = approver.sign(&digest(b"/answer\0", &answer).unwrap());
        let mut answer = Signed {
            body: answer,
            signature,
        };
        assert!(answer.verify(hash, &approver.public(), &make(), at).is_ok());
        assert!(answer.verify(hash, &other.public(), &make(), at).is_err());
        assert!(
            answer
                .verify(hash, &approver.public(), &make(), at + TTL)
                .is_err()
        );
        let mut second = make();
        second.nonce = [8; 32];
        assert!(
            answer
                .verify(
                    digest(b"/request\0", &second).unwrap(),
                    &approver.public(),
                    &second,
                    at
                )
                .is_err()
        );
        answer.body.allow = false;
        assert!(matches!(
            answer.verify(hash, &approver.public(), &make(), at),
            Err(Error::Protocol(_))
        ));
        let inbox = ApprovalInbox::new(|_, _| true);
        let _rx = inbox.insert(hash, make()).unwrap();
        let id = HEXLOWER.encode(&hash);
        assert!(inbox.respond(&id, true, &other.to_bytes()).is_err());
        inbox.respond(&id, false, &approver.to_bytes()).unwrap();
        assert!(inbox.respond(&id, true, &approver.to_bytes()).is_err());
        assert!(inbox.insert(hash, make()).is_err());
    }

    #[test]
    fn signed_peer_clock_skew_does_not_extend_origin_expiry() {
        let origin = SecretKey::generate();
        let phone = SecretKey::generate();
        let issued = 1000;
        let r = Request {
            origin: *origin.public().as_bytes(),
            approver: *phone.public().as_bytes(),
            nonce: [7; 32],
            expires_at: issued + TTL,
            scope: scope(),
        };
        let hash = digest(b"/request\0", &r).unwrap();
        let r = Signed {
            body: r,
            signature: origin.sign(&hash),
        };
        let request_at = |at| r.verify(&origin.public(), phone.public().as_bytes(), at);
        let response_at = |signed, received| {
            let body = Answer {
                hash,
                approver: *phone.public().as_bytes(),
                allow: true,
                time: signed,
            };
            let signature = phone.sign(&digest(b"/answer\0", &body).unwrap());
            Signed { body, signature }.verify(hash, &phone.public(), &r.body, received)
        };
        for phone_now in [
            issued - 5,
            issued + 5,
            issued - CLOCK_SKEW,
            issued + CLOCK_SKEW,
        ] {
            assert!(request_at(phone_now).is_ok());
            assert!(response_at(phone_now, issued).is_ok());
        }
        assert!(request_at(issued - CLOCK_SKEW - 1).is_err());
        for phone_now in [issued - CLOCK_SKEW - 1, issued + CLOCK_SKEW + 1] {
            assert!(response_at(phone_now, issued).is_err());
        }
        let expiry = r.body.expires_at;
        assert!(response_at(expiry - 5, expiry - 1).is_ok());
        assert!(response_at(expiry - 5, expiry).is_err());
        assert!(request_at(expiry).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_to_consume_never_outlives_the_monotonic_origin_deadline() {
        let answer = ApprovedRead {
            scope: scope(),
            approver: [1; 32],
            expires_at: now() + TTL,
            deadline: Instant::now() + Duration::from_secs(TTL),
        };
        tokio::time::advance(Duration::from_secs(TTL)).await;
        assert!(live_on_origin(answer.expires_at, now()));
        assert!(answer.consume(&scope(), &[1; 32]).is_err());
    }

    #[tokio::test]
    async fn same_node_transport_requires_live_membership_and_one_interactive_answer() {
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        let member = Arc::new(AtomicBool::new(true));
        let origin_key = *a.public().as_bytes();
        let approver_key = *b.public().as_bytes();
        let m = member.clone();
        let inbox = ApprovalInbox::new(move |vault, peer| {
            vault == scope().vault && *peer == origin_key && m.load(Ordering::Acquire)
        });
        let origin = Node::spawn(
            NodeConfig::local_only(a.to_bytes()),
            Arc::new(move |p: &PeerId| *p == approver_key),
            Nothing,
        )
        .await
        .unwrap();
        let mut config = NodeConfig::local_only(b.to_bytes());
        config.approval_inbox = Some(inbox.clone());
        let m = member.clone();
        let phone = Node::spawn(
            config,
            Arc::new(move |p: &PeerId| *p == origin_key && m.load(Ordering::Acquire)),
            Nothing,
        )
        .await
        .unwrap();
        for attempt in 0..4 {
            let pending = origin.request_read_approval(phone.addr(), scope(), || true);
            let act = async {
                let p = loop {
                    if let Some(p) = inbox.pending() {
                        break p;
                    }
                    tokio::task::yield_now().await;
                };
                assert_eq!(p.origin, origin_key);
                assert_eq!(p.scope, scope());
                if attempt == 3 {
                    member.store(false, Ordering::Release);
                    assert!(phone.enforce_membership() >= 1);
                    assert!(inbox.respond(&p.id, true, &b.to_bytes()).is_err());
                } else {
                    inbox.respond(&p.id, attempt != 2, &b.to_bytes()).unwrap();
                    assert!(inbox.respond(&p.id, true, &b.to_bytes()).is_err());
                }
            };
            let (reply, ()) = tokio::time::timeout(Duration::from_secs(10), async {
                tokio::join!(pending, act)
            })
            .await
            .unwrap();
            match attempt {
                0 => reply.unwrap().consume(&scope(), &approver_key).unwrap(),
                1 => {
                    let mut other = scope();
                    other.field = "otp".into();
                    assert!(reply.unwrap().consume(&other, &approver_key).is_err());
                }
                _ => assert!(reply.is_err()),
            }
        }
        assert!(
            origin
                .request_read_approval(phone.addr(), scope(), || true)
                .await
                .is_err()
        );
        assert!(inbox.pending().is_none());
        phone.shutdown().await;
        origin.shutdown().await;
    }
}
