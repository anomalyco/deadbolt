//! The four-verb contract on `MemObjStore`, and each `FaultyObjStore` fault.

use crate::{ByteRange, Call, FaultyObjStore, MemObjStore, ObjStore, PutOutcome, RemoteError};

/// The contract every backend keeps; the HTTP tests run it too.
pub async fn contract<S: ObjStore>(store: &S) {
    assert_eq!(
        store.put("v/a/1", b"one", true).await.unwrap(),
        PutOutcome::Created
    );
    assert_eq!(
        store.put("v/a/1", b"other", true).await.unwrap(),
        PutOutcome::AlreadyExists
    );
    assert_eq!(
        store.get("v/a/1", None).await.unwrap().as_deref(),
        Some(&b"one"[..])
    );
    assert_eq!(
        store.put("v/a/1", b"uno", false).await.unwrap(),
        PutOutcome::Created
    );
    assert_eq!(
        store.get("v/a/1", None).await.unwrap().as_deref(),
        Some(&b"uno"[..])
    );

    store.put("v/a/2", b"0123456789", true).await.unwrap();
    let get = |range| async move { store.get("v/a/2", Some(range)).await.unwrap().unwrap() };
    assert_eq!(get(ByteRange::new(2, 4)).await, b"234");
    assert_eq!(get(ByteRange::from(7)).await, b"789");
    assert_eq!(get(ByteRange::new(8, 100)).await, b"89");
    assert_eq!(store.get("v/missing", None).await.unwrap(), None);

    store.put("v/b/1", b"", true).await.unwrap();
    store.put("v/a/3", b"3", true).await.unwrap();
    store.put("w/a/1", b"other vault", true).await.unwrap();
    assert_eq!(
        store.list("v/", None).await.unwrap(),
        ["v/a/1", "v/a/2", "v/a/3", "v/b/1"]
    );
    assert_eq!(
        store.list("v/a/", Some("v/a/1")).await.unwrap(),
        ["v/a/2", "v/a/3"]
    );
    assert_eq!(store.list("v/", Some("v/a/3")).await.unwrap(), ["v/b/1"]);
    assert_eq!(
        store.list("v/a", None).await.unwrap(),
        ["v/a/1", "v/a/2", "v/a/3"]
    );
    assert!(store.list("v/c/", None).await.unwrap().is_empty());
    assert_eq!(
        store.get("v/b/1", None).await.unwrap().as_deref(),
        Some(&b""[..])
    );

    store.delete("v/a/2").await.unwrap();
    store.delete("v/a/2").await.unwrap();
    assert_eq!(store.list("v/a/", None).await.unwrap(), ["v/a/1", "v/a/3"]);

    for bad in ["", "/v/a", "v/../a", "V/a", "v/a\n"] {
        assert!(
            matches!(
                store.put(bad, b"x", true).await,
                Err(RemoteError::InvalidName(_))
            ),
            "{bad:?}"
        );
        assert!(
            matches!(store.get(bad, None).await, Err(RemoteError::InvalidName(_))),
            "{bad:?}"
        );
        assert!(
            matches!(store.delete(bad).await, Err(RemoteError::InvalidName(_))),
            "{bad:?}"
        );
    }
    assert!(matches!(
        store.list("../", None).await,
        Err(RemoteError::InvalidName(_))
    ));
}

#[tokio::test]
async fn mem_store_keeps_the_contract() {
    contract(&MemObjStore::new()).await;
}

#[tokio::test]
async fn faulty_store_is_honest_until_told_otherwise() {
    contract(&FaultyObjStore::new()).await;
}

#[tokio::test]
async fn withhold_hides_from_list_and_get() {
    let store = FaultyObjStore::new();
    store.put("v/1", b"1", true).await.unwrap();
    store.put("v/2", b"2", true).await.unwrap();
    store.withhold(|n| n == "v/2");
    assert_eq!(store.list("v/", None).await.unwrap(), ["v/1"]);
    assert_eq!(store.get("v/2", None).await.unwrap(), None);
    store.heal();
    assert_eq!(store.list("v/", None).await.unwrap(), ["v/1", "v/2"]);
}

#[tokio::test]
async fn truncate_cuts_reads() {
    let store = FaultyObjStore::new();
    store.put("v/1", b"0123456789", true).await.unwrap();
    store.truncate(|n| n.starts_with("v/"), 4);
    assert_eq!(store.get("v/1", None).await.unwrap().unwrap(), b"0123");
}

#[tokio::test]
async fn stale_list_lags_behind_puts() {
    let store = FaultyObjStore::new();
    store.put("v/1", b"1", true).await.unwrap();
    store.freeze_list();
    store.put("v/2", b"2", true).await.unwrap();
    assert_eq!(store.list("v/", None).await.unwrap(), ["v/1"]);
    assert!(store.get("v/2", None).await.unwrap().is_some());
    assert_eq!(
        store.put("v/2", b"2", true).await.unwrap(),
        PutOutcome::AlreadyExists
    );
}

#[tokio::test]
async fn lost_put_response_lands_then_retries_as_already_exists() {
    let store = FaultyObjStore::new();
    store.lose_put_responses(1);
    assert_eq!(
        store.put("v/1", b"1", true).await,
        Err(RemoteError::Injected("lost PUT response"))
    );
    assert_eq!(
        store.put("v/1", b"1", true).await.unwrap(),
        PutOutcome::AlreadyExists
    );
    assert_eq!(store.inner().peek("v/1").unwrap(), b"1");
}

#[tokio::test]
async fn transient_failures_touch_nothing() {
    let store = FaultyObjStore::new();
    store.fail_next(2);
    assert!(store.put("v/1", b"1", true).await.is_err());
    assert!(store.list("v/", None).await.is_err());
    assert!(store.inner().is_empty());
    assert_eq!(
        store.put("v/1", b"1", true).await.unwrap(),
        PutOutcome::Created
    );
}

#[tokio::test]
async fn wipe_and_rollback_remove_history() {
    let store = FaultyObjStore::new();
    store.put("v/1", b"1", true).await.unwrap();
    let old = store.snapshot();
    store.put("v/2", b"2", true).await.unwrap();
    store.put("v/3", b"3", true).await.unwrap();
    store.rollback(&old);
    assert_eq!(store.list("v/", None).await.unwrap(), ["v/1"]);
    store.wipe(|_| true);
    assert!(store.list("v/", None).await.unwrap().is_empty());
}

#[tokio::test]
async fn calls_are_logged_in_order() {
    let store = FaultyObjStore::new();
    store.put("v/1", b"1", true).await.unwrap();
    store.get("v/1", None).await.unwrap();
    store.list("v/", Some("v/0")).await.unwrap();
    store.delete("v/1").await.unwrap();
    assert_eq!(
        store.calls(),
        [
            Call::Put {
                name: "v/1".into(),
                create_only: true
            },
            Call::Get { name: "v/1".into() },
            Call::List {
                prefix: "v/".into(),
                after: Some("v/0".into())
            },
            Call::Delete { name: "v/1".into() },
        ]
    );
}

#[test]
fn byte_ranges_render_and_slice() {
    assert_eq!(ByteRange::new(0, 9).header(), "bytes=0-9");
    assert_eq!(ByteRange::from(5).header(), "bytes=5-");
    assert_eq!(ByteRange::new(5, 2).slice(b"0123456789"), b"");
    assert_eq!(ByteRange::from(20).slice(b"0123"), b"");
    assert_eq!(ByteRange::new(0, u64::MAX).slice(b"0123"), b"0123");
}
