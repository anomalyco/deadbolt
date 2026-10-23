#![cfg(test)]

mod common;

use std::{sync::Mutex, time::Duration};

use common::*;
use deadbolt_net::{
    ConfirmationCode, Error, HandlerError, Inviter, Joiner, PairingContext, PairingOptions,
    PairingTicket, QrStyle,
};

#[derive(Default)]
struct NewDevice {
    confirm: Option<bool>,
    code: Mutex<Option<ConfirmationCode>>,
    offer: Mutex<Option<Vec<u8>>>,
    welcome: Mutex<Option<Vec<Vec<u8>>>>,
}

impl Joiner for NewDevice {
    async fn confirm(&self, ctx: &PairingContext) -> bool {
        *self.code.lock().unwrap() = Some(ctx.code);
        self.confirm.unwrap_or(true)
    }

    async fn join(&self, ctx: &PairingContext, offer: Vec<u8>) -> Result<Vec<u8>, HandlerError> {
        *self.offer.lock().unwrap() = Some(offer.clone());
        // Like real join consent: bound to the joining and the inviting device.
        let mut join = b"consent:".to_vec();
        join.extend_from_slice(&offer);
        join.extend_from_slice(&ctx.local);
        join.extend_from_slice(&ctx.remote);
        Ok(join)
    }

    async fn receive(
        &self,
        _ctx: &PairingContext,
        welcome: Vec<Vec<u8>>,
    ) -> Result<(), HandlerError> {
        *self.welcome.lock().unwrap() = Some(welcome);
        Ok(())
    }
}

#[derive(Default)]
struct ExistingDevice {
    confirm: Option<bool>,
    reject_join: bool,
    code: Mutex<Option<ConfirmationCode>>,
    join: Mutex<Option<Vec<u8>>>,
}

impl Inviter for ExistingDevice {
    async fn confirm(&self, ctx: &PairingContext) -> bool {
        *self.code.lock().unwrap() = Some(ctx.code);
        self.confirm.unwrap_or(true)
    }

    async fn offer(&self, _ctx: &PairingContext) -> Result<Vec<u8>, HandlerError> {
        Ok(b"vault-1".to_vec())
    }

    async fn welcome(
        &self,
        ctx: &PairingContext,
        join: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, HandlerError> {
        let mut expected = b"consent:vault-1".to_vec();
        expected.extend_from_slice(&ctx.remote);
        expected.extend_from_slice(&ctx.local);
        if self.reject_join || join != expected {
            return Err("bad join".into());
        }
        *self.join.lock().unwrap() = Some(join);
        Ok(vec![
            b"add".to_vec(),
            b"membership-log".to_vec(),
            b"data".to_vec(),
        ])
    }
}

fn tampered(ticket: &PairingTicket) -> PairingTicket {
    let mut bytes = ticket.to_bytes();
    bytes[40] ^= 1; // inside the secret
    PairingTicket::from_bytes(&bytes).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_then_sync() {
    let new = TestNode::new(Store::with(&[])).await;
    let existing = TestNode::new(Store::with(&["m:add-existing", "d:item"])).await;

    let listener = within(new.node.start_pairing(PairingOptions::default()))
        .await
        .unwrap();
    // The ticket travels as a string (QR or copy/paste).
    let text = listener.ticket().to_string();
    assert!(listener.ticket().to_qr(QrStyle::DarkOnLight).is_ok());
    let ticket: PairingTicket = text.parse().unwrap();
    assert_eq!(ticket.peer_id(), new.id());

    let joiner = NewDevice::default();
    let inviter = ExistingDevice::default();
    let (joined, invited) = within(async {
        tokio::join!(
            listener.complete(&joiner),
            existing.node.pair(&ticket, &inviter)
        )
    })
    .await;
    let joined = joined.unwrap();
    let invited = invited.unwrap();

    assert_eq!(joined.peer, existing.id());
    assert_eq!(invited.peer, new.id());
    // Both screens show the same code.
    assert_eq!(joined.code, invited.code);
    assert_eq!(*joiner.code.lock().unwrap(), Some(joined.code));
    assert_eq!(*inviter.code.lock().unwrap(), Some(joined.code));
    assert_eq!(joined.code.to_string().len(), 6);

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

#[tokio::test(flavor = "multi_thread")]
async fn wrong_secret_fails_without_consuming_ticket() {
    let new = TestNode::new(Store::with(&[])).await;
    let existing = TestNode::new(Store::with(&[])).await;
    let attacker = TestNode::new(Store::with(&[])).await;

    let listener = within(new.node.start_pairing(PairingOptions::default()))
        .await
        .unwrap();
    let ticket = listener.ticket().clone();
    let joiner = NewDevice::default();
    let inviter = ExistingDevice::default();

    let (joined, bad, good) = within(async {
        let complete = listener.complete(&joiner);
        let attempts = async {
            let bad = attacker.node.pair(&tampered(&ticket), &inviter).await;
            let good = existing.node.pair(&ticket, &inviter).await;
            (bad, good)
        };
        let (joined, (bad, good)) = tokio::join!(complete, attempts);
        (joined, bad, good)
    })
    .await;
    assert!(matches!(bad, Err(Error::PairingProofFailed)), "{bad:?}");
    assert_eq!(good.unwrap().peer, new.id());
    assert_eq!(joined.unwrap().peer, existing.id());
    // The attacker never got to confirm or see the offer flow.
    assert!(joiner.offer.lock().unwrap().as_deref() == Some(&b"vault-1"[..]));
}

#[tokio::test(flavor = "multi_thread")]
async fn ticket_is_single_use() {
    let new = TestNode::new(Store::with(&[])).await;
    let existing = TestNode::new(Store::with(&[])).await;
    let other = TestNode::new(Store::with(&[])).await;

    let listener = within(new.node.start_pairing(PairingOptions::default()))
        .await
        .unwrap();
    let ticket = listener.ticket().clone();
    let joiner = NewDevice::default();
    let inviter = ExistingDevice::default();
    let (joined, invited) = within(async {
        tokio::join!(
            listener.complete(&joiner),
            existing.node.pair(&ticket, &inviter)
        )
    })
    .await;
    joined.unwrap();
    invited.unwrap();

    let again = within(other.node.pair(&ticket, &inviter)).await;
    assert!(matches!(again, Err(Error::Rejected(_))), "{again:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn ticket_expires() {
    let new = TestNode::new(Store::with(&[])).await;
    let existing = TestNode::new(Store::with(&[])).await;

    let listener = within(new.node.start_pairing(PairingOptions {
        ttl: Duration::from_millis(200),
        ..Default::default()
    }))
    .await
    .unwrap();
    let ticket = listener.ticket().clone();
    let joiner = NewDevice::default();
    let result = within(listener.complete(&joiner)).await;
    assert!(matches!(result, Err(Error::PairingExpired)), "{result:?}");

    let late = within(existing.node.pair(&ticket, &ExistingDevice::default())).await;
    assert!(matches!(late, Err(Error::Rejected(_))), "{late:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_ticket_is_refused_even_while_listener_is_alive() {
    let new = TestNode::new(Store::with(&[])).await;
    let existing = TestNode::new(Store::with(&[])).await;
    let listener = within(new.node.start_pairing(PairingOptions {
        ttl: Duration::from_millis(100),
        ..Default::default()
    }))
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let late = within(
        existing
            .node
            .pair(listener.ticket(), &ExistingDevice::default()),
    )
    .await;
    assert!(matches!(late, Err(Error::Rejected(_))), "{late:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_pairing_without_listener() {
    let new = TestNode::new(Store::with(&[])).await;
    let existing = TestNode::new(Store::with(&[])).await;
    let ticket = within(new.node.start_pairing(PairingOptions::default()))
        .await
        .unwrap()
        .ticket()
        .clone(); // listener dropped: ticket invalid
    let result = within(existing.node.pair(&ticket, &ExistingDevice::default())).await;
    assert!(matches!(result, Err(Error::Rejected(_))), "{result:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn declined_code_aborts_both_sides() {
    for (new_ok, existing_ok) in [(false, true), (true, false)] {
        let new = TestNode::new(Store::with(&[])).await;
        let existing = TestNode::new(Store::with(&[])).await;
        let listener = within(new.node.start_pairing(PairingOptions::default()))
            .await
            .unwrap();
        let ticket = listener.ticket().clone();
        let joiner = NewDevice {
            confirm: Some(new_ok),
            ..Default::default()
        };
        let inviter = ExistingDevice {
            confirm: Some(existing_ok),
            ..Default::default()
        };
        let (joined, invited) = within(async {
            tokio::join!(
                listener.complete(&joiner),
                existing.node.pair(&ticket, &inviter)
            )
        })
        .await;
        assert!(matches!(joined, Err(Error::PairingDeclined)), "{joined:?}");
        assert!(
            matches!(invited, Err(Error::PairingDeclined)),
            "{invited:?}"
        );
        assert!(joiner.welcome.lock().unwrap().is_none());
        assert!(inviter.join.lock().unwrap().is_none());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_join_reports_error_to_new_device() {
    let new = TestNode::new(Store::with(&[])).await;
    let existing = TestNode::new(Store::with(&[])).await;
    let listener = within(new.node.start_pairing(PairingOptions::default()))
        .await
        .unwrap();
    let ticket = listener.ticket().clone();
    let joiner = NewDevice::default();
    let inviter = ExistingDevice {
        reject_join: true,
        ..Default::default()
    };
    let (joined, invited) = within(async {
        tokio::join!(
            listener.complete(&joiner),
            existing.node.pair(&ticket, &inviter)
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
    let _listener = within(new.node.start_pairing(PairingOptions::default()))
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
    let listener = within(b.node.start_pairing(PairingOptions::default()))
        .await
        .unwrap();
    let ticket = listener.ticket().clone();
    let joiner = NewDevice::default();
    let inviter = ExistingDevice::default();
    let (joined, invited) =
        within(async { tokio::join!(listener.complete(&joiner), a.node.pair(&ticket, &inviter)) })
            .await;
    assert_eq!(joined.unwrap().peer, a.id());
    assert_eq!(invited.unwrap().peer, b.id());
}
