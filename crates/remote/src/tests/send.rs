//! Store-backed Send: names, the round trip through a store, expiry, and
//! (with `http`) a presigned URL fetched with no credentials.

use deadbolt_send::{CHUNK_LEN, HEADER_LEN, PolicyHeader};

use super::fixture::vault;
use crate::{
    MAX_SEND_TTL_SECS, MemObjStore, RemotePath, SendStoreError, download_send, open_stored,
    revoke_send, send_name, send_path, upload_send,
};

const NOW: u64 = 1_764_000_000;

/// Three STREAM chunks and a bit.
fn payload() -> Vec<u8> {
    (0..2 * CHUNK_LEN as u32 + 4321)
        .map(|i| (i % 251) as u8)
        .collect()
}

/// `sealed` with its header's expiry pushed out, the rest untouched.
fn extend_expiry(sealed: &[u8]) -> Vec<u8> {
    let header = PolicyHeader::decode(&sealed[..HEADER_LEN]).unwrap();
    let later = PolicyHeader {
        expires_unix: header.expires_unix + 86_400,
        ..header
    };
    let mut out = sealed.to_vec();
    out[..HEADER_LEN].copy_from_slice(&later.encode());
    out
}

#[test]
fn names_are_derived_from_the_key_and_canonical() {
    let key = [7u8; 32];
    assert_eq!(send_name(&key), send_name(&key));
    assert_ne!(send_name(&key), send_name(&[8; 32]));
    assert_ne!(send_name(&key)[..], key[..16]);
    let path = send_path(vault(), &key);
    let name = path.to_name();
    let (head, leaf) = name.rsplit_once('/').unwrap();
    assert!(head.ends_with("/s"), "{name}");
    assert_eq!(leaf.len(), 32);
    assert_eq!(RemotePath::parse(&name).unwrap(), path);
    assert!(!path.is_content_addressed());
}

#[tokio::test]
async fn a_send_round_trips_through_a_store() {
    let store = MemObjStore::new();
    let payload = payload();
    let send = upload_send(&store, vault(), &payload, NOW, NOW + 3600)
        .await
        .unwrap();
    assert_eq!(send.path, send_path(vault(), &send.key));
    assert_eq!(
        send.header,
        PolicyHeader {
            expires_unix: NOW + 3600,
            multi_open: true
        }
    );
    assert!(format!("{send:?}").contains("key: \"<redacted>\""));
    // Multi-open: any number of receivers, until expiry.
    for t in [NOW, NOW + 1, NOW + 3599] {
        let (header, opened) = download_send(&store, vault(), &send.key, t).await.unwrap();
        assert_eq!(header, send.header);
        assert_eq!(*opened, payload);
    }
    assert!(matches!(
        download_send(&store, vault(), &send.key, NOW + 3600).await,
        Err(SendStoreError::Expired)
    ));
    // A wrong key names a different object.
    assert!(matches!(
        download_send(&store, vault(), &[9; 32], NOW).await,
        Err(SendStoreError::Missing(_))
    ));
    revoke_send(&store, &send).await.unwrap();
    assert!(matches!(
        download_send(&store, vault(), &send.key, NOW).await,
        Err(SendStoreError::Missing(_))
    ));
}

#[tokio::test]
async fn a_store_cannot_change_the_policy_or_the_bytes() {
    let store = MemObjStore::new();
    let send = upload_send(&store, vault(), &payload(), NOW, NOW + 60)
        .await
        .unwrap();
    let name = send.path.to_name();
    let sealed = store.peek(&name).unwrap();
    // A store that pushes the expiry out (to serve past it) breaks chunk 0.
    store.plant(&name, &extend_expiry(&sealed));
    assert!(matches!(
        download_send(&store, vault(), &send.key, NOW + 120).await,
        Err(SendStoreError::Seal(deadbolt_send::Error::Corrupt(_)))
    ));
    let mut single = sealed.clone();
    single[1] = 0;
    store.plant(&name, &single);
    assert!(matches!(
        download_send(&store, vault(), &send.key, NOW).await,
        Err(SendStoreError::Seal(_))
    ));
    let mut flipped = sealed.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    store.plant(&name, &flipped);
    assert!(
        download_send(&store, vault(), &send.key, NOW)
            .await
            .is_err()
    );
    store.plant(&name, &sealed);
    assert!(download_send(&store, vault(), &send.key, NOW).await.is_ok());
    assert!(matches!(
        open_stored(&[9; 32], &sealed, NOW),
        Err(SendStoreError::Seal(_))
    ));
}

#[tokio::test]
async fn expiry_must_be_in_the_future_and_within_a_week() {
    let store = MemObjStore::new();
    for expires in [NOW - 1, NOW, NOW + MAX_SEND_TTL_SECS + 1] {
        assert!(matches!(
            upload_send(&store, vault(), b"x", NOW, expires).await,
            Err(SendStoreError::BadExpiry)
        ));
    }
    upload_send(&store, vault(), b"x", NOW, NOW + MAX_SEND_TTL_SECS)
        .await
        .unwrap();
    assert_eq!(store.len(), 1);
}

#[cfg(feature = "http")]
mod presigned {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::super::mock_http::{MockRequest, MockResponse, serve};
    use super::super::s3_http::{NOW, Objects, credentials, handle};
    use super::*;
    use crate::sigv4::{self, AmzDate, Scope};
    use crate::{Addressing, S3Config, S3ObjStore, presign_send_url};

    /// Mock S3 that also serves presigned `GET`s: the signature must match
    /// the URL as sent, and the URL must not have expired by the server clock.
    fn serve_presigned(objects: &Objects, clock: &AtomicU64, req: &MockRequest) -> MockResponse {
        let Some(signature) = req.param("X-Amz-Signature") else {
            return handle(objects, req);
        };
        let (Some(expires), Some(host)) = (
            req.param("X-Amz-Expires")
                .and_then(|e| e.parse::<u32>().ok()),
            req.header("host"),
        ) else {
            return MockResponse::status(400);
        };
        let date = AmzDate::from_unix(NOW);
        if req.method != "GET" || req.param("X-Amz-Date").as_deref() != Some(date.stamp()) {
            return MockResponse::status(403);
        }
        let expected = sigv4::presign_get_query(
            &credentials(),
            &date,
            &Scope {
                region: "auto",
                service: "s3",
            },
            host,
            &req.path,
            expires,
        );
        if !expected.ends_with(&format!("&X-Amz-Signature={signature}")) {
            return MockResponse::status(403);
        }
        if clock.load(Ordering::SeqCst) > NOW + u64::from(expires) {
            return MockResponse::status(403);
        }
        let key = req.path.trim_start_matches("/bucket/");
        match objects.lock().unwrap().get(key) {
            Some(bytes) => MockResponse::body(200, bytes.clone()),
            None => MockResponse::status(404),
        }
    }

    async fn fetch(url: &str) -> (u16, Vec<u8>) {
        let reply = reqwest::get(url).await.unwrap();
        let status = reply.status().as_u16();
        (status, reply.bytes().await.unwrap().to_vec())
    }

    #[tokio::test]
    async fn a_presigned_url_opens_with_no_credentials_until_it_expires() {
        let objects: Objects = Arc::default();
        let clock = Arc::new(AtomicU64::new(NOW));
        let (state, server_clock) = (objects.clone(), clock.clone());
        let (addr, _) = serve(move |req| serve_presigned(&state, &server_clock, req)).await;
        let config = S3Config::new(
            &format!("http://{addr}"),
            "bucket",
            "auto",
            "",
            Addressing::Path,
            credentials(),
        )
        .unwrap();
        let store = S3ObjStore::new(config.clone()).unwrap().with_clock(|| NOW);
        let payload = payload();
        let send = upload_send(&store, vault(), &payload, NOW, NOW + 3600)
            .await
            .unwrap();

        // The URL lives 10 minutes, and never past the Send's expiry.
        let url = presign_send_url(&config, &send, NOW, 600).unwrap();
        assert!(url.contains("X-Amz-Expires=600&"), "{url}");
        let capped = presign_send_url(&config, &send, NOW, 604_800).unwrap();
        assert!(capped.contains("X-Amz-Expires=3600&"), "{capped}");
        assert!(matches!(
            presign_send_url(&config, &send, NOW + 3600, 600),
            Err(SendStoreError::Expired)
        ));
        assert!(!url.contains("test-secret-key"));

        // A plain GET, no credentials: the receiver's side.
        let (status, sealed) = fetch(&url).await;
        assert_eq!(status, 200);
        let (header, opened) = open_stored(&send.key, &sealed, NOW + 5).unwrap();
        assert!(header.multi_open);
        assert_eq!(*opened, payload);
        // Multi-open: a second fetch works too.
        assert_eq!(fetch(&url).await.0, 200);
        assert!(matches!(
            open_stored(&[9; 32], &sealed, NOW),
            Err(SendStoreError::Seal(_))
        ));

        // A store that rewrites the policy header is caught.
        let name = send.path.to_name();
        let tampered = extend_expiry(&objects.lock().unwrap()[&name]);
        objects.lock().unwrap().insert(name.clone(), tampered);
        let (status, bytes) = fetch(&url).await;
        assert_eq!(status, 200);
        assert!(matches!(
            open_stored(&send.key, &bytes, NOW),
            Err(SendStoreError::Seal(_))
        ));

        // A forged signature, and the URL past its TTL, are refused.
        let forged = format!("{}0", url.trim_end_matches(|c: char| c.is_ascii_hexdigit()));
        assert_eq!(fetch(&forged).await.0, 403);
        clock.store(NOW + 601, Ordering::SeqCst);
        assert_eq!(fetch(&url).await.0, 403);
        assert_eq!(fetch(&capped).await.0, 200);
    }
}
