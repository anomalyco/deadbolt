mod common;

use std::sync::Arc;

use common::*;
use deadbolt_net::{Error, SyncOutcome};
use tokio::sync::Notify;

#[tokio::test(flavor = "multi_thread")]
async fn local_addr_has_direct_address() {
    let a = TestNode::new(Store::with(&[])).await;
    let addr = a.node.addr();
    assert_eq!(addr.id, a.id());
    assert!(addr.relay_url.is_none());
    assert!(
        addr.direct_addrs.iter().any(|s| s.ip().is_loopback()),
        "{addr:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_exchanges_missing_entries_both_ways() {
    let (a, b) = pair_of_members(&["m1", "a1", "a2"], &["m1", "b1"]).await;

    let outcome = within(a.node.sync(b.node.addr())).await.unwrap();
    assert_eq!(
        outcome,
        SyncOutcome {
            sent: 2,
            received: 1
        }
    );
    assert_eq!(a.store.sorted(), ["a1", "a2", "b1", "m1"]);
    assert_eq!(b.store.sorted(), ["a1", "a2", "b1", "m1"]);
    // Order chosen by the sender is preserved.
    assert_eq!(
        b.store.received.lock().unwrap().last().unwrap(),
        &vec![b"a1".to_vec(), b"a2".to_vec()]
    );

    // Nothing left to exchange; also works on a reused connection.
    let conn = within(b.node.connect(a.node.addr())).await.unwrap();
    for _ in 0..2 {
        let outcome = within(conn.sync()).await.unwrap();
        assert_eq!(
            outcome,
            SyncOutcome {
                sent: 0,
                received: 0
            }
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn large_entries_sync() {
    let big = "x".repeat(3 * 1024 * 1024);
    let entries: Vec<String> = (0..4).map(|i| format!("{i}{big}")).collect();
    let refs: Vec<&str> = entries.iter().map(String::as_str).collect();
    let (a, b) = pair_of_members(&refs, &refs[..1]).await;
    let outcome = within(b.node.sync(a.node.addr())).await.unwrap();
    assert_eq!(outcome.received, 3);
    assert_eq!(b.store.entries.lock().unwrap().len(), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn accept_rejects_non_member() {
    let a = TestNode::new(Store::with(&["secret"])).await;
    let b = TestNode::new(Store::with(&["b1"])).await;
    // B thinks A is a member, but A does not accept B.
    b.members.add(a.id());

    let result = within(async {
        let conn = b.node.connect(a.node.addr()).await?;
        conn.sync().await
    })
    .await;
    assert!(
        matches!(result, Err(Error::MembershipRejected(_))),
        "{result:?}"
    );

    // A never ran any application logic for B, and B received nothing.
    assert_eq!(a.store.calls(), 0);
    assert!(b.store.received.lock().unwrap().is_empty());
    assert!(a.node.connected_peers().is_empty());
    assert_eq!(a.store.sorted(), ["secret"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn dial_refuses_non_member() {
    let a = TestNode::new(Store::with(&["a1"])).await;
    let b = TestNode::new(Store::with(&["b1"])).await;
    // B would accept A, but A does not consider B a member.
    b.members.add(a.id());

    let result = within(a.node.connect(b.node.addr())).await;
    assert!(
        matches!(result, Err(Error::NotAMember(id)) if id == b.id()),
        "{result:?}"
    );
    let result = within(a.node.sync(b.node.addr())).await;
    assert!(matches!(result, Err(Error::NotAMember(_))), "{result:?}");

    assert_eq!(a.store.calls(), 0);
    assert_eq!(b.store.calls(), 0);
    assert!(b.node.connected_peers().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_closes_live_inbound_connection() {
    let (a, b) = pair_of_members(&["a1"], &["b1"]).await;

    let conn = within(b.node.connect(a.node.addr())).await.unwrap();
    within(conn.sync()).await.unwrap();
    assert_eq!(a.node.connected_peers(), vec![b.id()]);

    // A applies Remove(B).
    a.members.remove(&b.id());
    assert_eq!(a.node.revoke(&b.id()), 1);

    let reason = within(conn.closed()).await;
    assert!(matches!(reason, Error::MembershipRejected(_)), "{reason:?}");
    assert!(conn.is_closed());
    assert!(within(conn.sync()).await.is_err());
    assert!(a.node.connected_peers().is_empty());

    // B (unaware of the removal) cannot get back in.
    let calls = a.store.calls();
    let result = within(async {
        let conn = b.node.connect(a.node.addr()).await?;
        conn.sync().await
    })
    .await;
    assert!(
        matches!(result, Err(Error::MembershipRejected(_))),
        "{result:?}"
    );
    assert_eq!(a.store.calls(), calls);
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_closes_live_outbound_connection_and_blocks_redial() {
    let (a, b) = pair_of_members(&["a1"], &["b1"]).await;

    let conn = within(a.node.connect(b.node.addr())).await.unwrap();
    within(conn.sync()).await.unwrap();

    // Revocation is sticky even if membership has not caught up yet.
    assert_eq!(a.node.revoke(&b.id()), 1);
    within(conn.closed()).await;
    assert!(within(conn.sync()).await.is_err());

    let result = within(a.node.connect(b.node.addr())).await;
    assert!(
        matches!(result, Err(Error::Revoked(id)) if id == b.id()),
        "{result:?}"
    );
    within(async {
        while !b.node.connected_peers().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_interrupts_in_flight_session() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let store = Store {
        block: Some((entered.clone(), release.clone())),
        ..Default::default()
    };
    let a = TestNode::new(Arc::new(store)).await;
    let b = TestNode::new(Store::with(&["b1", "b2"])).await;
    a.members.add(b.id());
    b.members.add(a.id());

    let conn = within(b.node.connect(a.node.addr())).await.unwrap();
    let session = tokio::spawn(async move { conn.sync().await });

    // A is in the middle of the session (computing what B is missing).
    within(entered.notified()).await;
    a.members.remove(&b.id());
    assert_eq!(a.node.revoke(&b.id()), 1);

    let result = within(session).await.unwrap();
    assert!(result.is_err(), "{result:?}");
    release.notify_one();
    // A never accepted B's entries.
    assert!(a.store.received.lock().unwrap().is_empty());
    assert!(a.store.entries.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn enforce_membership_closes_removed_peers_only() {
    let a = TestNode::new(Store::with(&["a1"])).await;
    let b = TestNode::new(Store::with(&["b1"])).await;
    let c = TestNode::new(Store::with(&["c1"])).await;
    for (x, y) in [(&a, &b), (&a, &c), (&b, &a), (&c, &a)] {
        x.members.add(y.id());
    }

    let from_b = within(b.node.connect(a.node.addr())).await.unwrap();
    let from_c = within(c.node.connect(a.node.addr())).await.unwrap();
    within(from_b.sync()).await.unwrap();
    within(from_c.sync()).await.unwrap();
    let mut peers = a.node.connected_peers();
    peers.sort();
    let mut expected = vec![b.id(), c.id()];
    expected.sort();
    assert_eq!(peers, expected);

    a.members.remove(&c.id());
    assert_eq!(a.node.enforce_membership(), 1);
    within(from_c.closed()).await;
    assert!(!from_b.is_closed());
    within(from_b.sync()).await.unwrap();
    assert_eq!(a.node.connected_peers(), vec![b.id()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn three_nodes_converge() {
    let a = TestNode::new(Store::with(&["a"])).await;
    let b = TestNode::new(Store::with(&["b"])).await;
    let c = TestNode::new(Store::with(&["c"])).await;
    for x in [&a, &b, &c] {
        for y in [&a, &b, &c] {
            if x.id() != y.id() {
                x.members.add(y.id());
            }
        }
    }
    within(a.node.sync(b.node.addr())).await.unwrap();
    within(c.node.sync(b.node.addr())).await.unwrap();
    within(a.node.sync(c.node.addr())).await.unwrap();
    for x in [&a, &b, &c] {
        assert_eq!(x.store.sorted(), ["a", "b", "c"]);
    }
}
