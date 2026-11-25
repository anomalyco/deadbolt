//! The real `S3ObjStore` over loopback HTTP against a mock S3 that checks
//! every SigV4 signature, honours `If-None-Match: *` and `Range`, and pages
//! `ListObjectsV2` two keys at a time.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use super::mock_http::{MockRequest, MockResponse, requests, serve};
use super::store::contract;
use crate::sigv4::{self, AmzDate, Credentials, Request, Scope, sha256_hex};
use crate::{Addressing, ObjStore, Outbox, PutOutcome, RemoteError, S3Config, S3ObjStore};

const NOW: u64 = 1_764_000_000;
const PAGE: usize = 2;

fn credentials() -> Credentials {
    Credentials::new("AKIDTEST", "test-secret-key")
}

/// Recomputes the request's signature from what actually arrived.
fn signature_ok(req: &MockRequest) -> bool {
    let Some(auth) = req.header("authorization") else {
        return false;
    };
    let Some(signed) = auth
        .split("SignedHeaders=")
        .nth(1)
        .and_then(|s| s.split(',').next())
    else {
        return false;
    };
    let headers: Vec<(String, String)> = signed
        .split(';')
        .map(|name| {
            (
                name.to_owned(),
                req.header(name).unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let payload = req.header("x-amz-content-sha256").unwrap_or_default();
    if payload != sha256_hex(&req.body) {
        return false;
    }
    let date = AmzDate::from_unix(NOW);
    if req.header("x-amz-date") != Some(date.stamp()) {
        return false;
    }
    let expect = sigv4::sign(
        &credentials(),
        &date,
        &Scope {
            region: "auto",
            service: "s3",
        },
        &Request {
            method: &req.method,
            path: &req.path,
            query: &req.params(),
            headers: &headers,
            payload_hash: payload,
        },
    );
    expect.authorization == auth
}

type Objects = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

fn handle(objects: &Objects, req: &MockRequest) -> MockResponse {
    if !signature_ok(req) {
        return MockResponse::status(403);
    }
    let mut objects = objects.lock().unwrap_or_else(PoisonError::into_inner);
    if req.path == "/redirect-bucket/v/moved" || req.path.starts_with("/redirect-bucket") {
        return MockResponse::status(307).header("location", "/evil/stolen");
    }
    let Some(rest) = req.path.strip_prefix("/bucket") else {
        return MockResponse::status(404);
    };
    if rest.is_empty() || rest == "/" {
        if req.method != "GET" || req.param("list-type").as_deref() != Some("2") {
            return MockResponse::status(400);
        }
        let prefix = req.param("prefix").unwrap_or_default();
        let floor = [req.param("start-after"), req.param("continuation-token")]
            .into_iter()
            .flatten()
            .max();
        let keys: Vec<&String> = objects
            .keys()
            .filter(|k| k.starts_with(&prefix) && floor.as_ref().is_none_or(|f| *k > f))
            .collect();
        let page = &keys[..keys.len().min(PAGE)];
        let truncated = keys.len() > PAGE;
        let mut xml = String::from(
            r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>bucket</Name>"#,
        );
        for key in page {
            xml.push_str(&format!(
                "<Contents><Key>{key}</Key><Size>1</Size></Contents>"
            ));
        }
        xml.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
        if truncated {
            xml.push_str(&format!(
                "<NextContinuationToken>{}</NextContinuationToken>",
                page[PAGE - 1]
            ));
        }
        xml.push_str("</ListBucketResult>");
        return MockResponse::body(200, xml);
    }
    let key = rest.trim_start_matches('/').to_owned();
    match req.method.as_str() {
        "PUT" => {
            if req.header("if-none-match") == Some("*") && objects.contains_key(&key) {
                return MockResponse::status(412);
            }
            objects.insert(key, req.body.clone());
            MockResponse::status(200)
        }
        "GET" => match objects.get(&key) {
            None => MockResponse::status(404),
            Some(bytes) => match req.header("range") {
                None => MockResponse::body(200, bytes.clone()),
                Some(range) => {
                    let (a, b) = range.trim_start_matches("bytes=").split_once('-').unwrap();
                    let start: usize = a.parse().unwrap();
                    if start >= bytes.len() {
                        return MockResponse::status(416);
                    }
                    let end = b
                        .parse::<usize>()
                        .map_or(bytes.len(), |e| (e + 1).min(bytes.len()));
                    MockResponse::body(206, bytes[start..end].to_vec()).header(
                        "content-range",
                        &format!("bytes {start}-{}/{}", end - 1, bytes.len()),
                    )
                }
            },
        },
        "DELETE" => match objects.remove(&key) {
            Some(_) => MockResponse::status(204),
            None => MockResponse::status(404),
        },
        _ => MockResponse::status(405),
    }
}

async fn mock_s3(root: &str) -> (S3ObjStore, Objects, super::mock_http::Log) {
    let objects: Objects = Arc::default();
    let state = objects.clone();
    let (addr, log) = serve(move |req| handle(&state, req)).await;
    let config = S3Config::new(
        &format!("http://{addr}"),
        "bucket",
        "auto",
        root,
        Addressing::Path,
        credentials(),
    )
    .unwrap();
    let store = S3ObjStore::new(config).unwrap().with_clock(|| NOW);
    (store, objects, log)
}

#[tokio::test]
async fn s3_store_keeps_the_contract_with_valid_signatures() {
    let (store, _, log) = mock_s3("").await;
    contract(&store).await;
    let all = requests(&log);
    assert!(
        all.iter().all(signature_ok),
        "every request carries a valid signature"
    );
    assert!(all.iter().any(|r| r.header("if-none-match") == Some("*")));
    assert!(all.iter().any(|r| r.header("range") == Some("bytes=2-4")));
}

#[tokio::test]
async fn create_only_put_maps_412_to_already_exists() {
    let (store, objects, _) = mock_s3("").await;
    assert_eq!(
        store.put("v/a", b"1", true).await.unwrap(),
        PutOutcome::Created
    );
    assert_eq!(
        store.put("v/a", b"2", true).await.unwrap(),
        PutOutcome::AlreadyExists
    );
    assert_eq!(objects.lock().unwrap()["v/a"], b"1");
}

#[tokio::test]
async fn list_follows_continuation_tokens_under_a_root() {
    let (store, objects, log) = mock_s3("deadbolt/sub").await;
    for i in 0..7 {
        store.put(&format!("v/d/{i}"), b"x", true).await.unwrap();
    }
    for placeholder in ["elsewhere/v/d/9", "deadbolt/sub/", "deadbolt/sub/v/d/"] {
        objects
            .lock()
            .unwrap()
            .insert(placeholder.into(), b"x".to_vec());
    }
    assert!(objects.lock().unwrap().contains_key("deadbolt/sub/v/d/0"));
    let before = requests(&log).len();
    let names = store.list("v/d/", None).await.unwrap();
    assert_eq!(
        names,
        (0..7).map(|i| format!("v/d/{i}")).collect::<Vec<_>>()
    );
    assert_eq!(requests(&log).len() - before, 4, "four pages of two");
    let tokens: Vec<_> = requests(&log)[before..]
        .iter()
        .map(|r| r.param("continuation-token"))
        .collect();
    assert_eq!(tokens[0], None);
    assert!(tokens[1..].iter().all(Option::is_some));
    assert_eq!(
        store.list("v/d/", Some("v/d/4")).await.unwrap(),
        ["v/d/5", "v/d/6"]
    );
    // start-after rides only on the first page; the token carries it after.
    let before = requests(&log).len();
    assert_eq!(store.list("v/d/", Some("v/d/0")).await.unwrap().len(), 6);
    let pages = &requests(&log)[before..];
    assert_eq!(pages.len(), 3);
    assert_eq!(
        pages[0].param("start-after").as_deref(),
        Some("deadbolt/sub/v/d/0")
    );
    assert!(pages[1..].iter().all(|r| r.param("start-after").is_none()));
    assert!(
        pages
            .iter()
            .all(|r| r.param("encoding-type").as_deref() == Some("url"))
    );
    assert!(store.list("v/x/", None).await.unwrap().is_empty());
}

#[tokio::test]
async fn bad_credentials_surface_as_status_errors() {
    let (addr, _) = serve(|_| MockResponse::status(403)).await;
    let config = S3Config::new(
        &format!("http://{addr}"),
        "bucket",
        "auto",
        "",
        Addressing::Path,
        credentials(),
    )
    .unwrap();
    let store = S3ObjStore::new(config).unwrap();
    assert!(matches!(
        store.get("v/a", None).await,
        Err(RemoteError::Status {
            verb: "GET",
            status: 403,
            ..
        })
    ));
    let (addr, _) = serve(|_| MockResponse::body(200, "<html>captive portal</html>")).await;
    let config = S3Config::new(
        &format!("http://{addr}"),
        "bucket",
        "auto",
        "",
        Addressing::Path,
        credentials(),
    )
    .unwrap();
    let store = S3ObjStore::new(config).unwrap();
    assert!(matches!(
        store.list("v/", None).await,
        Err(RemoteError::Protocol(_))
    ));
}

#[tokio::test]
async fn redirects_are_refused_not_followed() {
    let objects: Objects = Arc::default();
    let state = objects.clone();
    let (addr, log) = serve(move |req| handle(&state, req)).await;
    let config = S3Config::new(
        &format!("http://{addr}"),
        "redirect-bucket",
        "auto",
        "",
        Addressing::Path,
        credentials(),
    )
    .unwrap();
    let store = S3ObjStore::new(config).unwrap().with_clock(|| NOW);
    assert!(matches!(
        store.get("v/moved", None).await,
        Err(RemoteError::Redirect { status: 307, .. })
    ));
    assert!(matches!(
        store.put("v/moved", b"x", true).await,
        Err(RemoteError::Redirect { .. })
    ));
    assert!(requests(&log).iter().all(|r| !r.path.starts_with("/evil")));
}

#[tokio::test]
async fn https_endpoints_never_downgrade_and_debug_redacts() {
    let config = S3Config::new(
        "https://example.r2.cloudflarestorage.com",
        "bucket",
        "auto",
        "",
        Addressing::Path,
        credentials(),
    )
    .unwrap();
    let store = S3ObjStore::new(config).unwrap();
    assert!(!format!("{store:?}").contains("test-secret-key"));
}

#[tokio::test]
async fn the_planner_pushes_and_pulls_through_s3() {
    use super::fixture::{data_chain, device, genesis};
    let (store, _, _) = mock_s3("deadbolt").await;
    let (vault, _, members) = genesis(1);
    let mut frames = members;
    frames.extend(data_chain(&device(1), vault, 5, 1, &[3]));
    let plan = crate::plan_push(
        &vault,
        Outbox {
            frames,
            ..Outbox::default()
        },
    )
    .unwrap();
    let report = crate::push(&store, &plan).await.unwrap();
    assert_eq!(report.created, 7);
    let again = crate::push(&store, &plan).await.unwrap();
    assert_eq!(again.already_present, 7);
    let pull = crate::plan_pull(&store, &vault, &crate::SyncAnchor::default(), None)
        .await
        .unwrap();
    assert_eq!(pull.fetch.len(), 7);
    let mut anchor = crate::SyncAnchor::default();
    for path in &pull.fetch {
        let bytes = store.get(&path.to_name(), None).await.unwrap().unwrap();
        anchor
            .observe(&crate::check_fetched(&anchor, path, &bytes).unwrap())
            .unwrap();
    }
    assert_eq!(anchor.seen.len(), 2);
}

fn page(keys: &[&str], token: Option<&str>) -> MockResponse {
    let mut xml = String::from("<ListBucketResult><EncodingType>url</EncodingType>");
    for key in keys {
        xml.push_str(&format!("<Contents><Key>{key}</Key></Contents>"));
    }
    match token {
        Some(token) => xml.push_str(&format!(
            "<IsTruncated>true</IsTruncated><NextContinuationToken>{token}</NextContinuationToken>"
        )),
        None => xml.push_str("<IsTruncated>false</IsTruncated>"),
    }
    xml.push_str("</ListBucketResult>");
    MockResponse::body(200, xml)
}

async fn scripted(
    handler: impl Fn(&MockRequest) -> MockResponse + Send + Sync + 'static,
) -> (S3ObjStore, super::mock_http::Log) {
    let (addr, log) = serve(handler).await;
    let config = S3Config::new(
        &format!("http://{addr}"),
        "bucket",
        "auto",
        "",
        Addressing::Path,
        credentials(),
    )
    .unwrap();
    (S3ObjStore::new(config).unwrap().with_clock(|| NOW), log)
}

#[tokio::test]
async fn listing_decodes_keys_and_sends_tokens_back_verbatim() {
    let (store, log) = scripted(|req| match req.param("continuation-token").as_deref() {
        None => page(&["v%2Fd%2F1"], Some(" tok/en= ")),
        Some(" tok/en= ") => page(&["v/d/2"], None),
        Some(_) => MockResponse::status(400),
    })
    .await;
    assert_eq!(store.list("v/d/", None).await.unwrap(), ["v/d/1", "v/d/2"]);
    assert_eq!(requests(&log).len(), 2);
}

#[tokio::test]
async fn a_continuation_token_cycle_is_refused() {
    // A -> B -> A: the old check only caught a token repeating at once.
    let (store, log) = scripted(|req| match req.param("continuation-token").as_deref() {
        None | Some("B") => page(&["v/1"], Some("A")),
        Some(_) => page(&["v/2"], Some("B")),
    })
    .await;
    assert!(matches!(
        store.list("v/", None).await,
        Err(RemoteError::Protocol(e)) if e.contains("loop")
    ));
    assert_eq!(requests(&log).len(), 3);
}
