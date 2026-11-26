#![cfg(test)]
#![cfg(feature = "live")]

//! A sender and a native receiver over local iroh endpoints, end to end.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use deadbolt_send::{
    Bundle, Entry, Error, Group, Network, Node, Policy, PolicyHeader, Progress, SendTicket, Server,
    ShareRequest, State, random_secret, receive, receiver_endpoint, seal,
};

struct Sender {
    server: Server,
    clock: Arc<AtomicU64>,
}

async fn sender() -> Sender {
    let clock = Arc::new(AtomicU64::new(1_000));
    let now = clock.clone();
    let server = Server::spawn(Network::Local, Arc::new(move || now.load(Ordering::SeqCst)))
        .await
        .unwrap();
    Sender { server, clock }
}

fn bundle() -> Bundle {
    Bundle {
        title: Some("for you".into()),
        note: Some("delete after reading".into()),
        entries: vec![
            Node::Entry(Entry::text("API_TOKEN", "tok_123", true)),
            Node::Group(Group {
                name: Some("files".into()),
                entries: vec![Node::Entry(Entry {
                    name: "big.bin".into(),
                    data: (0..200_000u32).map(|i| (i % 253) as u8).collect(),
                    mime: Some("application/octet-stream".into()),
                    sensitive: false,
                })],
            }),
        ],
    }
}

impl Sender {
    /// Shares `bundle` and returns its id and link.
    async fn share(&self, bundle: &Bundle, opens: u32) -> (String, SendTicket) {
        self.share_sealed(bundle, opens, |key, header, plaintext| {
            seal(key, header, plaintext).unwrap()
        })
        .await
    }

    /// Shares `bundle` as `sealer` seals it, and returns its id and link.
    async fn share_sealed(
        &self,
        bundle: &Bundle,
        opens: u32,
        sealer: impl FnOnce(&[u8; 32], &PolicyHeader, &[u8]) -> Vec<u8>,
    ) -> (String, SendTicket) {
        let secret = random_secret().unwrap();
        let key = random_secret().unwrap();
        let policy = Policy {
            opens,
            expires_at: self.clock.load(Ordering::SeqCst) + 3600,
        };
        let header = PolicyHeader {
            expires_unix: policy.expires_at,
            multi_open: opens > 1,
        };
        let sealed = sealer(&key, &header, &bundle.encode());
        let info = self
            .server
            .add(ShareRequest {
                secret: secret.clone(),
                sealed,
                policy,
                label: "test".into(),
            })
            .unwrap();
        assert_eq!(info.state, State::Open);
        let ticket = SendTicket::new(self.server.addr().await, secret, key);
        // Through its text form, as a receiver gets it.
        (info.id, ticket.link().parse().unwrap())
    }
}

async fn fetch(ticket: &SendTicket) -> Result<Bundle, Error> {
    let endpoint = receiver_endpoint(Network::Local).await.unwrap();
    let result = receive(&endpoint, ticket, |_| {}).await;
    endpoint.close().await;
    result
}

#[tokio::test]
async fn a_link_delivers_once() {
    let s = sender().await;
    let (id, ticket) = s.share(&bundle(), 1).await;
    let waiter = tokio::spawn({
        let server = s.server.clone();
        let id = id.clone();
        async move { server.wait(&id).await }
    });

    let endpoint = receiver_endpoint(Network::Local).await.unwrap();
    let mut steps = Vec::new();
    let got = receive(&endpoint, &ticket, |p| steps.push(p))
        .await
        .unwrap();
    assert_eq!(got, bundle());
    assert_eq!(steps.first(), Some(&Progress::Connecting));
    assert_eq!(steps.last(), Some(&Progress::Decrypting));
    assert!(steps.iter().any(|p| matches!(
        p,
        Progress::Downloading { received, total } if received == total && *total > 200_000
    )));

    let done = waiter.await.unwrap().unwrap();
    assert_eq!(done.state, State::PickedUp);
    assert_eq!(done.share.opened, [1_000]);
    assert!(matches!(fetch(&ticket).await, Err(Error::Used)));
    assert_eq!(s.server.list()[0].state, State::PickedUp);
}

#[tokio::test]
async fn several_opens() {
    let s = sender().await;
    let (id, ticket) = s.share(&bundle(), 2).await;
    fetch(&ticket).await.unwrap();
    assert_eq!(s.server.get(&id).unwrap().state, State::Open);
    fetch(&ticket).await.unwrap();
    assert_eq!(s.server.get(&id).unwrap().state, State::PickedUp);
    assert!(matches!(fetch(&ticket).await, Err(Error::Used)));
}

#[tokio::test]
async fn expired_revoked_and_unknown_links_are_refused() {
    let s = sender().await;
    let (expiring, expiring_ticket) = s.share(&bundle(), 1).await;
    let (revoked, revoked_ticket) = s.share(&bundle(), 1).await;

    let revoked_info = s.server.revoke(&revoked[..4]).unwrap();
    assert_eq!(revoked_info.state, State::Revoked);
    assert!(matches!(fetch(&revoked_ticket).await, Err(Error::Revoked)));

    s.clock.fetch_add(3600, Ordering::SeqCst);
    assert!(matches!(fetch(&expiring_ticket).await, Err(Error::Expired)));
    assert_eq!(
        s.server.wait(&expiring).await.unwrap().state,
        State::Expired
    );

    // Right sender, wrong secret.
    let mut wrong = expiring_ticket.clone();
    wrong.secret = random_secret().unwrap();
    assert!(matches!(fetch(&wrong).await, Err(Error::Unknown)));
    // Right secret, wrong content key.
    let (_, mut tampered) = s.share(&bundle(), 1).await;
    tampered.key = random_secret().unwrap();
    assert!(matches!(fetch(&tampered).await, Err(Error::Corrupt(_))));
}

#[tokio::test]
async fn a_stopped_sender_is_offline() {
    let s = sender().await;
    let (_, ticket) = s.share(&bundle(), 1).await;
    s.server.shutdown().await;
    drop(s);
    assert!(matches!(fetch(&ticket).await, Err(Error::Offline(_))));
}

// DELETABLE(v1-send): remove once existing v1 users have upgraded to v2.
mod v1 {
    use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
    use deadbolt_send::{CHUNK_LEN, HEADER_LEN};

    use super::*;

    const PREFIX_LEN: usize = 15;

    /// The sealer of senders from before the policy header, byte for byte:
    /// `prefix(15) || chunk*`, no header, empty associated data on every
    /// chunk, and the 2026-10 key context.
    pub fn seal_legacy(key: &[u8; 32], _: &PolicyHeader, plaintext: &[u8]) -> Vec<u8> {
        let derived = blake3::derive_key("deadbolt send 2026-10 bundle", key);
        let cipher = XChaCha20Poly1305::new((&derived).into());
        let mut prefix = [0u8; PREFIX_LEN];
        // Like any legacy bundle, never starting with a valid header.
        while prefix[..2] == [1, 0] || prefix[..2] == [1, 1] || prefix == [0; PREFIX_LEN] {
            getrandom::fill(&mut prefix).unwrap();
        }
        let chunks = plaintext.len().div_ceil(CHUNK_LEN).max(1);
        let mut out = prefix.to_vec();
        for index in 0..chunks {
            let start = index * CHUNK_LEN;
            let end = (start + CHUNK_LEN).min(plaintext.len());
            let at = out.len();
            out.extend_from_slice(&plaintext[start..end]);
            let mut nonce = [0u8; 24];
            nonce[..PREFIX_LEN].copy_from_slice(&prefix);
            nonce[PREFIX_LEN] = u8::from(index + 1 == chunks);
            nonce[PREFIX_LEN + 1..].copy_from_slice(&(index as u64).to_be_bytes());
            let tag = cipher
                .encrypt_inout_detached(&nonce.into(), &[], out[at..].as_mut().into())
                .unwrap();
            out.extend_from_slice(&tag);
        }
        out
    }

    #[tokio::test]
    async fn an_older_senders_bundle_still_opens() {
        let s = sender().await;
        // Over a chunk boundary, as the 200 KB file in `bundle()` is.
        let (_, ticket) = s.share_sealed(&bundle(), 1, seal_legacy).await;
        assert_eq!(fetch(&ticket).await.unwrap(), bundle());
        // Its content key alone opens it.
        let (_, mut wrong) = s.share_sealed(&bundle(), 1, seal_legacy).await;
        wrong.key = random_secret().unwrap();
        assert!(matches!(fetch(&wrong).await, Err(Error::Corrupt(_))));
    }

    #[tokio::test]
    async fn a_current_bundle_never_opens_as_legacy() {
        let s = sender().await;
        // A different expiry or flag in a well-formed header fails chunk 0.
        let changed = |key: &[u8; 32], header: &PolicyHeader, plaintext: &[u8]| {
            let mut sealed = seal(key, header, plaintext).unwrap();
            let later = PolicyHeader {
                expires_unix: header.expires_unix + 86_400,
                multi_open: !header.multi_open,
            };
            sealed[..HEADER_LEN].copy_from_slice(&later.encode());
            sealed
        };
        let (_, ticket) = s.share_sealed(&bundle(), 1, changed).await;
        assert!(matches!(fetch(&ticket).await, Err(Error::Corrupt(_))));
        // An unparseable header goes to the legacy opener, which can't open
        // a current bundle either: no downgrade opens it.
        for version in [0u8, 2, 0xff] {
            let broken = move |key: &[u8; 32], header: &PolicyHeader, plaintext: &[u8]| {
                let mut sealed = seal(key, header, plaintext).unwrap();
                sealed[0] = version;
                sealed
            };
            let (_, ticket) = s.share_sealed(&bundle(), 1, broken).await;
            assert!(
                matches!(fetch(&ticket).await, Err(Error::Corrupt(_))),
                "version {version}"
            );
        }
        // Stripping the header leaves legacy-looking bytes under the
        // current key context: still refused.
        let stripped = |key: &[u8; 32], header: &PolicyHeader, plaintext: &[u8]| {
            seal(key, header, plaintext).unwrap()[HEADER_LEN..].to_vec()
        };
        let (_, ticket) = s.share_sealed(&bundle(), 1, stripped).await;
        assert!(matches!(fetch(&ticket).await, Err(Error::Corrupt(_))));
    }
}
