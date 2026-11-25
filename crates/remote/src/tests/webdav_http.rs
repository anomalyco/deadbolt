//! The real `WebDavObjStore` over loopback HTTP against a mock server that
//! answers `409` for a missing parent, needs `MKCOL`, honours
//! `If-None-Match: *` and `Range`, and replies to `PROPFIND` like Nextcloud.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

use super::mock_http::{Log, MockRequest, MockResponse, requests, serve};
use super::store::contract;
use crate::{DavAuth, ObjStore, PutOutcome, RemoteError, WebDavConfig, WebDavObjStore};

const BASE: &str = "/remote.php/dav/files/alex%40example.com/deadbolt/";
/// base64("alex:secret")
const BASIC: &str = "Basic YWxleDpzZWNyZXQ=";

#[derive(Default)]
struct Dav {
    dirs: BTreeSet<String>,
    files: BTreeMap<String, Vec<u8>>,
}

fn parent(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    trimmed.rfind('/').map_or("", |i| &trimmed[..=i])
}

fn propfind(dav: &Dav, dir: &str) -> MockResponse {
    let mut xml = String::from(
        r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:oc="http://owncloud.org/ns">"#,
    );
    let mut entry = |rel: &str, collection: bool| {
        let rtype = if collection {
            "<d:resourcetype><d:collection/></d:resourcetype>"
        } else {
            "<d:resourcetype/>"
        };
        xml.push_str(&format!(
            "<d:response><d:href>{BASE}{rel}</d:href><d:propstat><d:prop>{rtype}</d:prop>\
             <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        ));
    };
    entry(dir, true);
    for d in dav
        .dirs
        .iter()
        .filter(|d| !d.is_empty() && parent(d) == dir)
    {
        entry(d, true);
    }
    for f in dav.files.keys().filter(|f| parent(f) == dir) {
        entry(f, false);
    }
    xml.push_str("</d:multistatus>");
    MockResponse::body(207, xml)
}

fn handle(state: &Mutex<Dav>, req: &MockRequest) -> MockResponse {
    if req.header("authorization") != Some(BASIC) {
        return MockResponse::status(401);
    }
    if req.path.contains("moved") {
        return MockResponse::status(301).header("location", "https://evil.example/steal");
    }
    let Some(rel) = req.path.strip_prefix(BASE) else {
        return MockResponse::status(404);
    };
    let rel = rel.to_owned();
    let mut dav = state.lock().unwrap_or_else(PoisonError::into_inner);
    match req.method.as_str() {
        "PUT" => {
            if !dav.dirs.contains(parent(&rel)) {
                return MockResponse::status(409);
            }
            if req.header("if-none-match") == Some("*") && dav.files.contains_key(&rel) {
                return MockResponse::status(412);
            }
            let existed = dav.files.insert(rel, req.body.clone()).is_some();
            MockResponse::status(if existed { 204 } else { 201 })
        }
        "MKCOL" => {
            if dav.dirs.contains(&rel) {
                return MockResponse::status(405);
            }
            if !dav.dirs.contains(parent(&rel)) {
                return MockResponse::status(409);
            }
            dav.dirs.insert(rel);
            MockResponse::status(201)
        }
        "PROPFIND" => {
            assert_eq!(req.header("depth"), Some("1"));
            if dav.dirs.contains(&rel) {
                propfind(&dav, &rel)
            } else {
                MockResponse::status(404)
            }
        }
        "GET" => match dav.files.get(&rel) {
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
                    MockResponse::body(206, bytes[start..end].to_vec())
                }
            },
        },
        "DELETE" => match dav.files.remove(&rel) {
            Some(_) => MockResponse::status(204),
            None => MockResponse::status(404),
        },
        _ => MockResponse::status(405),
    }
}

async fn mock_dav() -> (WebDavObjStore, Arc<Mutex<Dav>>, Log) {
    let state = Arc::new(Mutex::new(Dav {
        dirs: BTreeSet::from([String::new()]),
        ..Dav::default()
    }));
    let shared = state.clone();
    let (addr, log) = serve(move |req| handle(&shared, req)).await;
    let config = WebDavConfig::new(
        &format!("http://{addr}{BASE}"),
        DavAuth::Basic {
            user: "alex".into(),
            password: "secret".to_owned().into(),
        },
    )
    .unwrap();
    (WebDavObjStore::new(config).unwrap(), state, log)
}

#[tokio::test]
async fn webdav_store_keeps_the_contract() {
    let (store, _, log) = mock_dav().await;
    contract(&store).await;
    assert!(
        requests(&log)
            .iter()
            .all(|r| r.header("authorization") == Some(BASIC))
    );
}

#[tokio::test]
async fn nested_put_creates_parents_once_then_honours_create_only() {
    let (store, state, log) = mock_dav().await;
    let name = "vault/m/author/0000000000000000";
    assert_eq!(
        store.put(name, b"frame", true).await.unwrap(),
        PutOutcome::Created
    );
    let methods: Vec<(String, String)> = requests(&log)
        .iter()
        .map(|r| (r.method.clone(), r.path.trim_start_matches(BASE).to_owned()))
        .collect();
    assert_eq!(
        methods,
        [
            ("PUT", name),
            ("MKCOL", "vault/"),
            ("MKCOL", "vault/m/"),
            ("MKCOL", "vault/m/author/"),
            ("PUT", name),
        ]
        .map(|(m, p)| (m.to_owned(), p.to_owned()))
    );
    assert_eq!(
        store.put(name, b"other", true).await.unwrap(),
        PutOutcome::AlreadyExists
    );
    assert_eq!(state.lock().unwrap().files[name], b"frame");
    let before = requests(&log).len();
    store
        .put("vault/m/author/0000000000000001", b"next", true)
        .await
        .unwrap();
    assert_eq!(
        requests(&log).len() - before,
        1,
        "parents exist now: one PUT"
    );
    // Another client made a sibling directory: MKCOL answers 405 and the PUT goes on.
    state.lock().unwrap().dirs.insert("vault/d/".into());
    store
        .put("vault/d/author/0000000000000000", b"d", true)
        .await
        .unwrap();
}

#[tokio::test]
async fn list_walks_collections_with_prefix_and_after() {
    let (store, _, log) = mock_dav().await;
    for name in [
        "v/m/a/1", "v/m/b/1", "v/m/b/2", "v/d/a/1", "v/d/a/2", "v/d/c/1", "w/m/a/1",
    ] {
        store.put(name, b"x", true).await.unwrap();
    }
    assert_eq!(
        store.list("v/m/", None).await.unwrap(),
        ["v/m/a/1", "v/m/b/1", "v/m/b/2"]
    );
    assert_eq!(
        store.list("v/", None).await.unwrap(),
        [
            "v/d/a/1", "v/d/a/2", "v/d/c/1", "v/m/a/1", "v/m/b/1", "v/m/b/2"
        ]
    );
    assert_eq!(
        store.list("v/d/", Some("v/d/a/2")).await.unwrap(),
        ["v/d/c/1"]
    );
    let before = requests(&log).len();
    assert_eq!(
        store.list("v/d/", Some("v/d/b")).await.unwrap(),
        ["v/d/c/1"]
    );
    let visited: Vec<String> = requests(&log)[before..]
        .iter()
        .map(|r| r.path.trim_start_matches(BASE).to_owned())
        .collect();
    assert_eq!(
        visited,
        ["v/d/", "v/d/c/"],
        "collections wholly before 'after' are skipped"
    );
    assert_eq!(
        store.list("v/d/a/", None).await.unwrap(),
        ["v/d/a/1", "v/d/a/2"]
    );
    assert!(store.list("nothing/", None).await.unwrap().is_empty());
}

#[tokio::test]
async fn webdav_redirects_and_auth_failures_are_errors() {
    let (store, _, log) = mock_dav().await;
    assert!(matches!(
        store.get("v/moved", None).await,
        Err(RemoteError::Redirect { status: 301, .. })
    ));
    assert!(matches!(
        store.list("moved/", None).await,
        Err(RemoteError::Redirect { .. })
    ));
    assert!(requests(&log).iter().all(|r| !r.path.contains("steal")));

    let (addr, _) = serve(|_| MockResponse::status(401)).await;
    let config = WebDavConfig::new(
        &format!("http://{addr}/dav/"),
        DavAuth::Bearer("tok".to_owned().into()),
    )
    .unwrap();
    let store = WebDavObjStore::new(config).unwrap();
    assert!(matches!(
        store.put("a/b", b"x", true).await,
        Err(RemoteError::Status { status: 401, .. })
    ));
    assert!(!format!("{store:?}").contains("tok\""));
}
