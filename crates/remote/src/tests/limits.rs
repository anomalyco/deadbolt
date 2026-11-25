//! Bounded HTTP bodies: oversized replies are refused, a `206` must carry
//! the range asked for, and a `200` to a ranged GET is sliced as it streams.

use super::mock_http::{MockResponse, serve};
use crate::{ByteRange, DavAuth, ObjStore, RemoteError, WebDavConfig, WebDavObjStore};

async fn dav(
    handler: impl Fn(&super::mock_http::MockRequest) -> MockResponse + Send + Sync + 'static,
) -> WebDavObjStore {
    let (addr, _) = serve(handler).await;
    let config = WebDavConfig::new(&format!("http://{addr}/dav/"), DavAuth::None).unwrap();
    WebDavObjStore::new(config).unwrap()
}

fn object() -> Vec<u8> {
    (0..2_000_000u32).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn an_oversized_reply_body_is_refused() {
    let store = dav(|_| MockResponse::body(201, vec![b'x'; 100 * 1024])).await;
    assert!(matches!(
        store.put("a/b", b"x", true).await,
        Err(RemoteError::Protocol(e)) if e.contains("reply body over")
    ));
    // A 206 longer than the range asked for.
    let store =
        dav(|_| MockResponse::body(206, vec![b'x'; 64]).header("content-range", "bytes 2-4/64"))
            .await;
    assert!(matches!(
        store.get("a/b", Some(ByteRange::new(2, 4))).await,
        Err(RemoteError::Protocol(_))
    ));
}

#[tokio::test]
async fn a_206_must_carry_the_range_asked_for() {
    for header in [
        None,
        Some("bytes 3-5/10"),
        Some("bytes 2-9/10"),
        Some("bytes */10"),
    ] {
        let store = dav(move |_| {
            let reply = MockResponse::body(206, b"234".to_vec());
            match header {
                Some(h) => reply.header("content-range", h),
                None => reply,
            }
        })
        .await;
        assert!(
            matches!(
                store.get("a/b", Some(ByteRange::new(2, 4))).await,
                Err(RemoteError::Protocol(_))
            ),
            "{header:?}"
        );
    }
    let store =
        dav(|_| MockResponse::body(206, b"234".to_vec()).header("content-range", "bytes 2-4/10"))
            .await;
    assert_eq!(
        store
            .get("a/b", Some(ByteRange::new(2, 4)))
            .await
            .unwrap()
            .unwrap(),
        b"234"
    );
    // An unasked-for 206.
    assert!(store.get("a/b", None).await.is_err());
}

#[tokio::test]
async fn a_200_to_a_ranged_get_is_sliced_while_streaming() {
    let whole = object();
    let served = whole.clone();
    let store = dav(move |_| MockResponse::body(200, served.clone())).await;
    for range in [
        ByteRange::new(0, 9),
        ByteRange::new(1_500_000, 1_500_099),
        ByteRange::new(1_999_990, 3_000_000),
        ByteRange::from(1_999_000),
        ByteRange::from(5_000_000),
    ] {
        assert_eq!(
            store.get("a/b", Some(range)).await.unwrap().unwrap(),
            range.slice(&whole),
            "{range:?}"
        );
    }
    assert_eq!(store.get("a/b", None).await.unwrap().unwrap(), whole);
}
