//! The broker end to end inside this process: a mock upstream, the broker,
//! and requests from this process, which is inside the tree when the root
//! is this process and outside it when the root is a `sleep`.

use std::convert::Infallible;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use deadbolt_remote::sigv4::{self, AmzDate, Credentials, Scope};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

use super::bind;
use super::config::{BrokerAuth, BrokerConfig, BrokerRoute};
use super::hygiene;
use crate::daemon::taint::{OsProcesses, ProcessFacts};

mod hardening;

const TOKEN: &str = "sk-real-token-0123456789abcdef";
const PLACEHOLDER: &str = "db_ph_0123456789abcdef0123456789abcdef";
const ACCESS_KEY: &str = "AKIAREALKEY000000001";
const SECRET_KEY: &str = "real/secret+key0123456789abcdefghijklmnop";
const SESSION_TOKEN: &str = "real-session-token-0123456789";
const AWS_PLACEHOLDER: &str = "db_ph_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A request the upstream got.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

struct Upstream {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Upstream {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

/// An upstream that records each request. `.../redirect` answers 302 to
/// `redirect`, `.../echo` reflects the Authorization it got, and
/// `/bucket/...` checks a real SigV4 signature.
async fn upstream(redirect: Option<String>) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (log, redirect) = (log.clone(), redirect.clone());
            tokio::spawn(async move {
                let service =
                    service_fn(move |request| respond(log.clone(), redirect.clone(), request));
                http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .ok();
            });
        }
    });
    Upstream { port, seen }
}

async fn respond(
    log: Arc<Mutex<Vec<Seen>>>,
    redirect: Option<String>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = request.into_parts();
    let seen = Seen {
        method: parts.method.to_string(),
        target: parts.uri.to_string(),
        headers: parts
            .headers
            .iter()
            .map(|(n, v)| {
                (
                    n.to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body: body.collect().await.unwrap().to_bytes().to_vec(),
    };
    log.lock().unwrap().push(seen.clone());
    let path = parts.uri.path();
    let mut response = Response::new(Full::new(Bytes::from_static(b"ok")));
    if path.ends_with("/redirect") {
        *response.status_mut() = StatusCode::FOUND;
        let to = redirect.unwrap_or_default();
        response
            .headers_mut()
            .insert("location", to.parse().unwrap());
    } else if path.ends_with("/echo") {
        let sent = seen.header("authorization").unwrap_or_default().to_string();
        response
            .headers_mut()
            .insert("x-echo", sent.parse().unwrap());
        *response.body_mut() = Full::new(Bytes::from(format!("you sent: {sent}")));
    } else if path.ends_with("/echo64") {
        // Reflected the way a debug page or JWT-ish blob would: in base64,
        // inside a longer value.
        let sent = seen.header("authorization").unwrap_or_default();
        let blob = format!("{{\"auth\":\"{sent}\"}}");
        response.headers_mut().insert(
            "x-echo",
            data_encoding::BASE64URL_NOPAD
                .encode(blob.as_bytes())
                .parse()
                .unwrap(),
        );
        *response.body_mut() = Full::new(Bytes::from(format!(
            "auth={}",
            data_encoding::BASE64.encode(sent.as_bytes())
        )));
    } else if path.ends_with("/leak") {
        // The secret key, URL-encoded with lower-case hex.
        let lower: String = SECRET_KEY
            .bytes()
            .map(|b| match b {
                b'/' => "%2f".to_string(),
                b'+' => "%2b".to_string(),
                b => (b as char).to_string(),
            })
            .collect();
        *response.body_mut() = Full::new(Bytes::from(format!("key={lower}")));
    } else if path.ends_with("/gzip") {
        response
            .headers_mut()
            .insert("content-encoding", "gzip".parse().unwrap());
    } else if path.starts_with("/bucket") {
        if verify_sigv4(&seen) {
            *response.body_mut() = Full::new(Bytes::from_static(b"signed"));
        } else {
            *response.status_mut() = StatusCode::FORBIDDEN;
        }
    }
    Ok(response)
}

/// Whether `seen` is signed with the real key, as S3 would check it.
fn verify_sigv4(seen: &Seen) -> bool {
    let Some(authorization) = seen.header("authorization") else {
        return false;
    };
    let field = |name: &str| {
        authorization
            .split([' ', ','])
            .find_map(|part| part.strip_prefix(name))
            .unwrap_or_default()
            .to_string()
    };
    let credential = field("Credential=");
    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 || parts[0] != ACCESS_KEY {
        return false;
    }
    let stamp = seen.header("x-amz-date").unwrap_or_default();
    let now = crate::config::now();
    let Some(date) = (now - 300..now + 5)
        .map(AmzDate::from_unix)
        .find(|date| date.stamp() == stamp)
    else {
        return false;
    };
    let payload_hash = sigv4::sha256_hex(&seen.body);
    if seen.header("x-amz-content-sha256") != Some(payload_hash.as_str())
        || seen.header("x-amz-security-token") != Some(SESSION_TOKEN)
    {
        return false;
    }
    let headers: Vec<(String, String)> = field("SignedHeaders=")
        .split(';')
        .map(|name| {
            (
                name.to_string(),
                seen.header(name).unwrap_or_default().to_string(),
            )
        })
        .collect();
    let (path, query) = seen.target.split_once('?').unwrap_or((&seen.target, ""));
    let query: Vec<(String, String)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let text = |t: &str| String::from_utf8(hygiene::decode(t)).unwrap();
            (text(k), text(v))
        })
        .collect();
    let credentials = Credentials::new(ACCESS_KEY, SECRET_KEY).with_session_token(SESSION_TOKEN);
    let signature = sigv4::sign(
        &credentials,
        &date,
        &Scope {
            region: parts[2],
            service: parts[3],
        },
        &sigv4::Request {
            method: &seen.method,
            path,
            query: &query,
            headers: &headers,
            payload_hash: &payload_hash,
        },
    );
    signature.signature == field("Signature=")
}

fn me() -> Option<u32> {
    Some(std::process::id())
}

/// A broker for `routes` whose run is `root`, serving in the background.
async fn broker(routes: Vec<BrokerRoute>, root: Option<u32>) -> u16 {
    let root_start = root.and_then(|pid| OsProcesses.facts(pid)).map(|f| f.start);
    let config = BrokerConfig {
        root_pid: root,
        root_start,
        routes,
    };
    let (broker, listener) = bind(config).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(broker.serve(listener));
    port
}

fn bearer(alias: &str, upstream: u16, header: &str) -> BrokerRoute {
    BrokerRoute {
        alias: alias.to_string(),
        upstream: format!("http://127.0.0.1:{upstream}/base"),
        auth: BrokerAuth::Bearer {
            placeholder: PLACEHOLDER.to_string(),
            token: Zeroizing::new(TOKEN.to_string()),
            header_name: header.to_string(),
        },
        methods: vec!["GET".into(), "POST".into()],
        path_prefixes: vec!["/v1".into()],
        path_globs: vec![],
        max_body_bytes: 1024,
    }
}

fn s3(upstream: u16) -> BrokerRoute {
    BrokerRoute {
        alias: "s3".to_string(),
        upstream: format!("http://127.0.0.1:{upstream}"),
        auth: BrokerAuth::AwsSigV4 {
            placeholder_access_key: AWS_PLACEHOLDER.to_string(),
            access_key: Zeroizing::new(ACCESS_KEY.to_string()),
            secret_key: Zeroizing::new(SECRET_KEY.to_string()),
            session_token: Some(Zeroizing::new(SESSION_TOKEN.to_string())),
            region: "us-east-1".to_string(),
            service: "s3".to_string(),
        },
        methods: vec![],
        path_prefixes: vec!["/bucket".into()],
        path_globs: vec![],
        max_body_bytes: 1024,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Sends `head` (with `Connection: close`) as is; the status.
async fn raw(port: u16, head: &str) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0)
}

#[tokio::test]
async fn a_placeholder_becomes_the_token_upstream() {
    let up = upstream(None).await;
    let port = broker(
        vec![
            bearer("api", up.port, "authorization"),
            bearer("anthropic", up.port, "x-api-key"),
        ],
        me(),
    )
    .await;
    let base = format!("http://127.0.0.1:{port}");
    let response = client()
        .post(format!("{base}/api/v1/chat?stream=true"))
        .bearer_auth(PLACEHOLDER)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "ok");
    let response = client()
        .get(format!("{base}/anthropic/v1/messages"))
        .header("x-api-key", PLACEHOLDER)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let seen = up.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].target, "/base/v1/chat?stream=true");
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].body, b"{}");
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert_eq!(seen[1].header("x-api-key"), Some(TOKEN));
    assert_eq!(seen[1].header("authorization"), None);
    for request in &seen {
        assert!(
            request
                .headers
                .iter()
                .all(|(_, v)| !v.contains(PLACEHOLDER))
        );
    }
}

#[tokio::test]
async fn a_missing_or_wrong_placeholder_is_refused() {
    let up = upstream(None).await;
    let port = broker(vec![bearer("api", up.port, "authorization")], me()).await;
    let url = format!("http://127.0.0.1:{port}/api/v1/chat");
    for auth in [
        None,
        Some("Bearer db_ph_wrong"),
        Some(TOKEN),
        Some(&*format!("Bearer {TOKEN}")),
    ] {
        let mut request = client().get(&url);
        if let Some(auth) = auth {
            request = request.header("authorization", auth);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 403);
        assert!(!response.text().await.unwrap().contains(TOKEN));
    }
    assert!(up.seen().is_empty());
}

#[tokio::test]
async fn out_of_scope_paths_and_methods_are_refused() {
    let up = upstream(None).await;
    let port = broker(vec![bearer("api", up.port, "authorization")], me()).await;
    let base = format!("http://127.0.0.1:{port}");
    for (method, path) in [
        ("GET", "/api/admin"),
        ("GET", "/api/v1x"),
        ("DELETE", "/api/v1/chat"),
        ("PUT", "/api/v1/chat"),
        ("GET", "/other/v1/chat"),
        ("GET", "/"),
    ] {
        let response = client()
            .request(method.parse().unwrap(), format!("{base}{path}"))
            .bearer_auth(PLACEHOLDER)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "{method} {path}");
    }
    assert!(up.seen().is_empty());
}

#[tokio::test]
async fn non_canonical_requests_are_refused() {
    let up = upstream(None).await;
    let port = broker(vec![bearer("api", up.port, "authorization")], me()).await;
    let auth = format!("Authorization: Bearer {PLACEHOLDER}\r\n");
    for target in [
        "/api/v1/../admin",
        "/api/v1/%2e%2e/admin",
        "/api/v1/%2E%2E/admin",
        "//api/v1/chat",
        "/api//v1/chat",
        "/api/v1/./chat",
        "/api/v1%2fadmin",
        "/api/v1/chat%00",
        "/api/v1/chat;jsessionid=1",
        "/api/v1/chat?x=%0d%0aHost:evil",
        "http://evil.local/api/v1/chat",
    ] {
        let head = format!("GET {target} HTTP/1.1\r\nHost: x\r\n{auth}Connection: close\r\n\r\n");
        let status = raw(port, &head).await;
        assert!(status == 400 || status == 403, "{target}: {status}");
    }
    // Repeated credentials and framing.
    let framed = |extra: &str| {
        format!("POST /api/v1/chat HTTP/1.1\r\nHost: x\r\n{auth}{extra}Connection: close\r\n\r\nhi")
    };
    for head in [
        framed(&auth),
        framed("Host: y\r\n"),
        framed("Content-Length: 2\r\nContent-Length: 3\r\n"),
        framed("Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n"),
    ] {
        assert_eq!(raw(port, &head).await, 400, "{head}");
    }
    assert!(up.seen().is_empty());
}

/// A body framed both ways is read as chunked (RFC 9112 §6.3, which hyper
/// enforces by dropping the `Content-Length`) and goes upstream with framing
/// of the broker's own, so the two ends can't read it differently.
#[tokio::test]
async fn a_body_framed_two_ways_goes_upstream_framed_once() {
    let up = upstream(None).await;
    let port = broker(vec![bearer("api", up.port, "authorization")], me()).await;
    let head = format!(
        "POST /api/v1/chat HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {PLACEHOLDER}\r\nContent-Length: 40\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nhi\r\n0\r\n\r\n"
    );
    assert_eq!(raw(port, &head).await, 200);
    let seen = up.seen();
    assert_eq!(seen[0].body, b"hi");
    assert_eq!(seen[0].header("content-length"), Some("2"));
    assert_eq!(seen[0].header("transfer-encoding"), None);
}

#[tokio::test]
async fn bodies_over_the_limit_are_refused() {
    let up = upstream(None).await;
    let port = broker(vec![bearer("api", up.port, "authorization")], me()).await;
    let url = format!("http://127.0.0.1:{port}/api/v1/chat");
    let response = client()
        .post(&url)
        .bearer_auth(PLACEHOLDER)
        .body(vec![b'x'; 2048])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
    assert!(up.seen().is_empty());
}

#[tokio::test]
async fn redirects_are_not_followed_and_never_get_the_token() {
    let evil = upstream(None).await;
    let up = upstream(Some(format!("http://127.0.0.1:{}/steal", evil.port))).await;
    let port = broker(vec![bearer("api", up.port, "authorization")], me()).await;
    // Even a caller that follows redirects gets nowhere.
    let following = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = following
        .get(format!("http://127.0.0.1:{port}/api/v1/redirect"))
        .bearer_auth(PLACEHOLDER)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert!(response.headers().get("location").is_none());
    assert_eq!(up.seen().len(), 1);
    assert!(evil.seen().is_empty());
}

#[tokio::test]
async fn a_reflected_token_comes_back_starred() {
    let up = upstream(None).await;
    let port = broker(vec![bearer("api", up.port, "authorization")], me()).await;
    let response = client()
        .get(format!("http://127.0.0.1:{port}/api/v1/echo"))
        .bearer_auth(PLACEHOLDER)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let stars = "*".repeat(TOKEN.len());
    assert_eq!(
        response.headers()["x-echo"],
        format!("Bearer {stars}").as_str()
    );
    assert_eq!(
        response.text().await.unwrap(),
        format!("you sent: Bearer {stars}")
    );
}

#[tokio::test]
async fn a_process_outside_the_run_is_refused() {
    let up = upstream(None).await;
    // The run is some other process; this one is not in its tree.
    let mut outsider = Command::new("sleep").arg("30").spawn().unwrap();
    let port = broker(
        vec![bearer("api", up.port, "authorization")],
        Some(outsider.id()),
    )
    .await;
    let response = client()
        .get(format!("http://127.0.0.1:{port}/api/v1/chat"))
        .bearer_auth(PLACEHOLDER)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("isn't part of the deadbolt run")
    );
    assert!(up.seen().is_empty());
    outsider.kill().unwrap();
    outsider.wait().unwrap();
}

/// A request signed with `key`, as an AWS client would sign it; an
/// `aws-chunked` body is sent unsigned, with a trailer.
fn signed(
    method: &str,
    port: u16,
    path: &str,
    query: &[(String, String)],
    key: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> reqwest::RequestBuilder {
    let chunked = extra.iter().any(|(_, v)| *v == "aws-chunked");
    let hash = sigv4::sha256_hex(body);
    let payload_hash = if chunked {
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
    } else {
        &hash
    };
    let date = AmzDate::from_unix(crate::config::now());
    let host = format!("127.0.0.1:{port}");
    let credentials = Credentials::new(key, "placeholder-secret");
    let mut headers = sigv4::base_headers(&credentials, &host, &date, payload_hash);
    headers.extend(extra.iter().map(|(n, v)| (n.to_string(), v.to_string())));
    let scope = Scope {
        region: "us-east-1",
        service: "s3",
    };
    let signature = sigv4::sign(
        &credentials,
        &date,
        &scope,
        &sigv4::Request {
            method,
            path,
            query,
            headers: &headers,
            payload_hash,
        },
    );
    let mut url = format!("http://{host}{path}");
    if !query.is_empty() {
        url = format!("{url}?{}", sigv4::canonical_query(query));
    }
    let mut request = client()
        .request(method.parse().unwrap(), url)
        .header("authorization", signature.authorization)
        .body(body.to_vec());
    for (name, value) in headers.iter().filter(|(n, _)| n != "host") {
        request = request.header(name, value);
    }
    request
}

#[tokio::test]
async fn sigv4_requests_are_signed_again_with_the_real_key() {
    let up = upstream(None).await;
    let port = broker(vec![s3(up.port)], me()).await;
    let body = b"hello world";
    let put = signed(
        "PUT",
        port,
        "/s3/bucket/key%20one.txt",
        &[],
        AWS_PLACEHOLDER,
        &[("content-type", "text/plain")],
        body,
    );
    let response = put.send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "signed");

    let query = [
        ("list-type".to_string(), "2".to_string()),
        ("prefix".to_string(), "a/b c".to_string()),
    ];
    let list = signed("GET", port, "/s3/bucket", &query, AWS_PLACEHOLDER, &[], b"");
    assert_eq!(list.send().await.unwrap().text().await.unwrap(), "signed");

    // aws-chunked with a checksum trailer, as newer AWS SDKs send it.
    let chunked = b"b\r\nhello world\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\n\r\n";
    let put = signed(
        "PUT",
        port,
        "/s3/bucket/chunked",
        &[],
        AWS_PLACEHOLDER,
        &[
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "11"),
            ("x-amz-trailer", "x-amz-checksum-crc32"),
        ],
        chunked,
    );
    assert_eq!(put.send().await.unwrap().text().await.unwrap(), "signed");

    let seen = up.seen();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].target, "/bucket/key%20one.txt");
    assert!(
        seen[0]
            .header("authorization")
            .unwrap()
            .contains(ACCESS_KEY)
    );
    assert_eq!(seen[2].body, b"hello world");
    assert_eq!(seen[2].header("x-amz-checksum-crc32"), Some("DUoRhQ=="));
    assert_eq!(seen[2].header("content-encoding"), None);
    for request in &seen {
        assert!(
            request
                .headers
                .iter()
                .all(|(_, v)| !v.contains(AWS_PLACEHOLDER))
        );
    }

    // Another key, or none, never reaches the upstream.
    let other = signed(
        "GET",
        port,
        "/s3/bucket",
        &[],
        "AKIAOTHERKEY00000000",
        &[],
        b"",
    );
    assert_eq!(other.send().await.unwrap().status(), 403);
    let unsigned = client()
        .get(format!("http://127.0.0.1:{port}/s3/bucket"))
        .send()
        .await
        .unwrap();
    assert_eq!(unsigned.status(), 403);
    let presigned =
        format!("http://127.0.0.1:{port}/s3/bucket/x?X-Amz-Credential={AWS_PLACEHOLDER}");
    assert_eq!(client().get(presigned).send().await.unwrap().status(), 403);
    assert_eq!(up.seen().len(), 3);
}

/// Every request on a new connection, so each pays the process-tree check.
#[tokio::test]
async fn latency_with_a_fresh_connection_each_time() {
    let up = upstream(None).await;
    let port = broker(vec![bearer("api", up.port, "authorization")], me()).await;
    let fresh = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{port}/api/v1/chat");
    let direct = format!("http://127.0.0.1:{}/base/v1/chat", up.port);
    let (mut via, mut plain) = (Vec::with_capacity(50), Vec::with_capacity(50));
    for _ in 0..50 {
        let start = Instant::now();
        let response = fresh
            .get(&url)
            .bearer_auth(PLACEHOLDER)
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "ok");
        via.push(start.elapsed());
        let start = Instant::now();
        fresh
            .get(&direct)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        plain.push(start.elapsed());
    }
    via.sort();
    plain.sort();
    eprintln!(
        "broker p50 {:?} p95 {:?}; direct p50 {:?} p95 {:?}",
        via[24], via[47], plain[24], plain[47]
    );
    let limit = if cfg!(debug_assertions) { 20 } else { 2 };
    assert!(via[47] < Duration::from_millis(limit), "p95 {:?}", via[47]);
}

#[test]
fn configs_the_broker_cannot_serve_safely_are_refused() {
    let ok = || bearer("api", 1, "authorization");
    let check = |route: BrokerRoute| {
        BrokerConfig {
            root_pid: None,
            root_start: None,
            routes: vec![route],
        }
        .validate()
    };
    assert!(check(ok()).is_ok());
    let mut plain = ok();
    plain.upstream = "http://api.example.com".into();
    assert!(check(plain).is_err());
    let mut header = ok();
    header.auth = BrokerAuth::Bearer {
        placeholder: PLACEHOLDER.into(),
        token: Zeroizing::new(TOKEN.into()),
        header_name: "Proxy-Authorization".into(),
    };
    assert!(check(header).is_err());
    let mut same = ok();
    same.auth = BrokerAuth::Bearer {
        placeholder: PLACEHOLDER.into(),
        token: Zeroizing::new(PLACEHOLDER.into()),
        header_name: "authorization".into(),
    };
    assert!(check(same).is_err());
    let twice = BrokerConfig {
        root_pid: None,
        root_start: None,
        routes: vec![ok(), ok()],
    };
    assert!(twice.validate().is_err());
    // A config prints no secret.
    let printed = format!("{:?}", s3(1));
    assert!(!printed.contains(SECRET_KEY) && !printed.contains(ACCESS_KEY));
}
