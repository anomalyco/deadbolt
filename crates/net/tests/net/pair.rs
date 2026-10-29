use std::{sync::Mutex, time::Duration};

use crate::common::*;
use deadbolt_net::{
    Blob, Error, HandlerError, Inviter, Joiner, PairingCode, PairingContext, PairingOptions,
};

#[derive(Default)]
struct NewDevice {
    offer: Mutex<Option<Vec<u8>>>,
    welcome: Mutex<Option<Vec<Vec<u8>>>>,
}

impl Joiner for NewDevice {
    async fn join(&self, ctx: &PairingContext, offer: Vec<u8>) -> Result<Vec<u8>, HandlerError> {
        *self.offer.lock().unwrap() = Some(offer.clone());
        // Like real join consent: bound to the joining and the inviting device.
        let mut join = b"consent:".to_vec();
        join.extend_from_slice(&offer);
        join.extend_from_slice(&ctx.local);
        join.extend_from_slice(&ctx.remote);
        Ok(join)
    }

    async fn receive(&self, _ctx: &PairingContext, welcome: Vec<Blob>) -> Result<(), HandlerError> {
        *self.welcome.lock().unwrap() = Some(welcome.iter().map(|b| b.to_vec()).collect());
        Ok(())
    }
}

#[derive(Default)]
struct ExistingDevice {
    reject_join: bool,
    join: Mutex<Option<Vec<u8>>>,
}

impl Inviter for ExistingDevice {
    async fn offer(&self, _ctx: &PairingContext) -> Result<Vec<u8>, HandlerError> {
        Ok(b"vault-1".to_vec())
    }

    async fn welcome(
        &self,
        ctx: &PairingContext,
        join: Vec<u8>,
    ) -> Result<Vec<Blob>, HandlerError> {
        let mut expected = b"consent:vault-1".to_vec();
        expected.extend_from_slice(&ctx.remote);
        expected.extend_from_slice(&ctx.local);
        if self.reject_join || join != expected {
            return Err("bad join".into());
        }
        *self.join.lock().unwrap() = Some(join);
        Ok(vec![
            Blob::new(b"add".to_vec()),
            Blob::new(b"membership-log".to_vec()),
            Blob::new(b"data".to_vec()),
        ])
    }
}

fn code() -> PairingCode {
    PairingCode::generate().unwrap()
}

/// Looks only briefly for a device, for tests where none is waiting.
fn quick() -> PairingOptions {
    PairingOptions {
        find_timeout: Duration::from_secs(1),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_then_sync() {
    let new = TestNode::new(Store::with(&[])).await;
    let existing = TestNode::new(Store::with(&["m:add-existing", "d:item"])).await;

    let code = code();
    let listener = within(new.node.start_pairing(&code, PairingOptions::default()))
        .await
        .unwrap();
    // The code travels as text, typed by a person.
    let typed: PairingCode = code
        .to_string()
        .to_uppercase()
        .replace('-', " ")
        .parse()
        .unwrap();

    let joiner = NewDevice::default();
    let inviter = ExistingDevice::default();
    let (joined, invited) = within(async {
        tokio::join!(
            listener.complete(&joiner),
            existing
                .node
                .pair(&typed, PairingOptions::default(), &inviter)
        )
    })
    .await;
    assert_eq!(joined.unwrap().peer, existing.id());
    assert_eq!(invited.unwrap().peer, new.id());

    assert_eq!(
        joiner.offer.lock().unwrap().as_deref(),
        Some(&b"vault-1"[..])
    );
    assert!(inviter.join.lock().unwrap().is_some());
    assert_eq!(
        joiner.welcome.lock().unwrap().clone().unwrap(),
        vec![
            b"add".to_vec(),
            b"membership-log".to_vec(),
            b"data".to_vec()
        ]
    );

    // After applying the welcome, both consider each other members and can sync.
    new.members.add(existing.id());
    existing.members.add(new.id());
    let outcome = within(new.node.sync(existing.node.addr())).await.unwrap();
    assert_eq!(outcome.received, 2);
    assert_eq!(new.store.sorted(), ["d:item", "m:add-existing"]);
}

/// A mistyped code names another rendezvous key, so it finds no device and spends
/// nothing: the right code still works afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_code_finds_no_device_and_spends_nothing() {
    let new = TestNode::new(Store::with(&[])).await;
    let existing = TestNode::new(Store::with(&[])).await;
    let code = code();
    let listener = within(new.node.start_pairing(&code, PairingOptions::default()))
        .await
        .unwrap();
    let joiner = NewDevice::default();
    let inviter = ExistingDevice::default();
    let (joined, (wrong, right)) = within(async {
        tokio::join!(listener.complete(&joiner), async {
            let wrong = existing.node.pair(&self::code(), quick(), &inviter).await;
            let right = existing
                .node
                .pair(&code, PairingOptions::default(), &inviter)
                .await;
            (wrong, right)
        })
    })
    .await;
    assert!(matches!(wrong, Err(Error::PairingNotFound)), "{wrong:?}");
    assert_eq!(right.unwrap().peer, new.id());
    assert_eq!(joined.unwrap().peer, existing.id());
}

/// Once used, the code fails loudly for anyone else, so the legitimate device learns
/// that someone else may have used it.
#[tokio::test(flavor = "multi_thread")]
async fn a_used_code_fails_loudly() {
    let new = TestNode::new(Store::with(&[])).await;
    let existing = TestNode::new(Store::with(&[])).await;
    let other = TestNode::new(Store::with(&[])).await;

    let code = code();
    let listener = within(new.node.start_pairing(&code, PairingOptions::default()))
        .await
        .unwrap();
    let joiner = NewDevice::default();
    let inviter = ExistingDevice::default();
    let (joined, invited) = within(async {
        tokio::join!(
            listener.complete(&joiner),
            existing
                .node
                .pair(&code, PairingOptions::default(), &inviter)
        )
    })
    .await;
    joined.unwrap();
    invited.unwrap();

    let again = within(other.node.pair(&code, quick(), &inviter)).await;
    assert!(matches!(again, Err(Error::PairingCodeUsed)), "{again:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_code_expires() {
    let new = TestNode::new(Store::with(&[])).await;
    let existing = TestNode::new(Store::with(&[])).await;

    let code = code();
    let listener = within(new.node.start_pairing(
        &code,
        PairingOptions {
            ttl: Duration::from_millis(300),
            ..Default::default()
        },
    ))
    .await
    .unwrap();
    let result = within(listener.complete(&NewDevice::default())).await;
    assert!(matches!(result, Err(Error::PairingExpired)), "{result:?}");

    let late = within(
        existing
            .node
            .pair(&code, quick(), &ExistingDevice::default()),
    )
    .await;
    assert!(matches!(late, Err(Error::PairingNotFound)), "{late:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_code_is_refused_even_while_its_listener_is_alive() {
    let new = TestNode::new(Store::with(&[])).await;
    let existing = TestNode::new(Store::with(&[])).await;
    let code = code();
    let _listener = within(new.node.start_pairing(
        &code,
        PairingOptions {
            ttl: Duration::from_millis(200),
            ..Default::default()
        },
    ))
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let late = within(
        existing
            .node
            .pair(&code, quick(), &ExistingDevice::default()),
    )
    .await;
    assert!(matches!(late, Err(Error::PairingNotFound)), "{late:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_pairing_once_the_listener_is_dropped() {
    let new = TestNode::new(Store::with(&[])).await;
    let existing = TestNode::new(Store::with(&[])).await;
    let code = code();
    drop(
        within(new.node.start_pairing(&code, PairingOptions::default()))
            .await
            .unwrap(),
    );
    let result = within(
        existing
            .node
            .pair(&code, quick(), &ExistingDevice::default()),
    )
    .await;
    assert!(matches!(result, Err(Error::PairingNotFound)), "{result:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_cannot_pair_with_its_own_code() {
    let new = TestNode::new(Store::with(&[])).await;
    let code = code();
    let _listener = within(new.node.start_pairing(&code, PairingOptions::default()))
        .await
        .unwrap();
    let result = within(new.node.pair(
        &code,
        PairingOptions::default(),
        &ExistingDevice::default(),
    ))
    .await;
    assert!(matches!(result, Err(Error::OwnCode)), "{result:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_join_reports_error_to_new_device() {
    let new = TestNode::new(Store::with(&[])).await;
    let existing = TestNode::new(Store::with(&[])).await;
    let code = code();
    let listener = within(new.node.start_pairing(&code, PairingOptions::default()))
        .await
        .unwrap();
    let joiner = NewDevice::default();
    let inviter = ExistingDevice {
        reject_join: true,
        ..Default::default()
    };
    let (joined, invited) = within(async {
        tokio::join!(
            listener.complete(&joiner),
            existing
                .node
                .pair(&code, PairingOptions::default(), &inviter)
        )
    })
    .await;
    assert!(matches!(invited, Err(Error::Handler(_))), "{invited:?}");
    assert!(
        matches!(&joined, Err(Error::Remote(m)) if m.contains("bad join")),
        "{joined:?}"
    );
    assert!(joiner.welcome.lock().unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_does_not_bypass_sync_gate() {
    // A device dialing the pair ALPN is not thereby a member for sync.
    let new = TestNode::new(Store::with(&["private"])).await;
    let existing = TestNode::new(Store::with(&[])).await;
    existing.members.add(new.id());
    let _listener = within(new.node.start_pairing(&code(), PairingOptions::default()))
        .await
        .unwrap();
    let result = within(async {
        let conn = existing.node.connect(new.node.addr()).await?;
        conn.sync().await
    })
    .await;
    assert!(
        matches!(result, Err(Error::MembershipRejected(_))),
        "{result:?}"
    );
    assert_eq!(new.store.calls(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn removed_peer_can_still_pair_into_another_vault() {
    let (a, b) = pair_of_members(&["a1"], &["b1"]).await;
    let conn = within(b.node.connect(a.node.addr())).await.unwrap();
    within(conn.sync()).await.unwrap();

    // A removes B from their only shared vault, closing the active sync connection.
    a.members.remove(&b.id());
    assert_eq!(a.node.enforce_membership(), 1);
    within(conn.closed()).await;
    assert!(matches!(
        within(a.node.connect(b.node.addr())).await,
        Err(Error::NotAMember(_))
    ));

    // Later, A pairs B into a different vault without restarting A's node.
    let code = code();
    let listener = within(b.node.start_pairing(&code, PairingOptions::default()))
        .await
        .unwrap();
    let joiner = NewDevice::default();
    let inviter = ExistingDevice::default();
    let (joined, invited) = within(async {
        tokio::join!(
            listener.complete(&joiner),
            a.node.pair(&code, PairingOptions::default(), &inviter)
        )
    })
    .await;
    assert_eq!(joined.unwrap().peer, a.id());
    assert_eq!(invited.unwrap().peer, b.id());
}

/// The real rendezvous: n0's pkarr relay and relays. Needs the internet, so it only
/// runs when asked: `cargo test -p deadbolt-net --test net pairs_through_n0 -- --ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the internet"]
async fn pairs_through_n0() {
    let new = TestNode::with_config(Store::with(&[]), deadbolt_net::NodeConfig::new(key())).await;
    let existing =
        TestNode::with_config(Store::with(&[]), deadbolt_net::NodeConfig::new(key())).await;
    let code = code();
    let listener = new
        .node
        .start_pairing(&code, PairingOptions::default())
        .await
        .unwrap();
    let joiner = NewDevice::default();
    let inviter = ExistingDevice::default();
    let (joined, invited) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(
            listener.complete(&joiner),
            existing
                .node
                .pair(&code, PairingOptions::default(), &inviter)
        )
    })
    .await
    .unwrap();
    assert_eq!(joined.unwrap().peer, existing.id());
    assert_eq!(invited.unwrap().peer, new.id());
    let again = existing.node.pair(&code, quick(), &inviter).await;
    assert!(matches!(again, Err(Error::PairingCodeUsed)), "{again:?}");
}
