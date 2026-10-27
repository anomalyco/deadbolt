#![cfg(test)]

//! A sender and a native receiver over local iroh endpoints, end to end.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use deadbolt_send::{
    Bundle, Entry, Error, Group, Network, Node, Policy, Progress, SendTicket, Server, ShareRequest,
    State, random_secret, receive, receiver_endpoint, seal,
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
        let secret = random_secret().unwrap();
        let key = random_secret().unwrap();
        let sealed = seal(&key, &bundle.encode()).unwrap();
        let info = self
            .server
            .add(ShareRequest {
                secret: secret.clone(),
                sealed,
                policy: Policy {
                    opens,
                    expires_at: self.clock.load(Ordering::SeqCst) + 3600,
                },
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
