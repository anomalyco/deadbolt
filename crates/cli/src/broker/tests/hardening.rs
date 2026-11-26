//! Regressions for the broker's security audit: each test is one way a
//! request (or an answer) once got past a check.

use std::cell::RefCell;
use std::collections::HashMap;

use super::super::Lineage;
use super::*;
use deadbolt_client::peer::ancestry::{Facts, Hidden, Start};

/// A path-scoped S3 route can't be made to read another bucket's object
/// through CopyObject's (or RenameObject's) source header.
#[tokio::test]
async fn a_copy_or_rename_source_is_refused_on_a_scoped_route() {
    let up = upstream(None).await;
    let port = broker(vec![s3(up.port)], me()).await;
    for source in ["x-amz-copy-source", "x-amz-rename-source"] {
        let put = signed(
            "PUT",
            port,
            "/s3/bucket/sandbox/loot",
            &[],
            AWS_PLACEHOLDER,
            &[(source, "/other-prod-bucket/secret.key")],
            b"",
        );
        let response = put.send().await.unwrap();
        assert_eq!(response.status(), 403, "{source}");
    }
    assert!(up.seen().is_empty());
}

/// The upstream is asked for an uncompressed answer whatever the caller
/// accepts, and a compressed one is refused: the redactor reads plaintext.
#[tokio::test]
async fn answers_come_uncompressed_or_not_at_all() {
    let up = upstream(None).await;
    let port = broker(vec![bearer("api", up.port, "authorization")], me()).await;
    let base = format!("http://127.0.0.1:{port}/api/v1");
    let response = client()
        .get(format!("{base}/chat"))
        .bearer_auth(PLACEHOLDER)
        .header("accept-encoding", "gzip, br")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(up.seen()[0].header("accept-encoding"), Some("identity"));
    let response = client()
        .get(format!("{base}/gzip"))
        .bearer_auth(PLACEHOLDER)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
}

/// A token reflected in base64 inside a longer value (`Bearer ` shifts it
/// by a byte), or URL-encoded with lower-case hex, still comes back starred.
#[tokio::test]
async fn a_token_reflected_in_base64_or_lower_case_escapes_is_starred() {
    let up = upstream(None).await;
    let port = broker(
        vec![bearer("api", up.port, "authorization"), s3(up.port)],
        me(),
    )
    .await;
    let response = client()
        .get(format!("http://127.0.0.1:{port}/api/v1/echo64"))
        .bearer_auth(PLACEHOLDER)
        .send()
        .await
        .unwrap();
    let header = response.headers()["x-echo"].to_str().unwrap().to_string();
    let body = response.text().await.unwrap();
    let bearer = format!("Bearer {TOKEN}");
    for (text, encoded) in [
        (&body, data_encoding::BASE64.encode(bearer.as_bytes())),
        (
            &header,
            data_encoding::BASE64URL_NOPAD.encode(format!("{{\"auth\":\"{bearer}\"}}").as_bytes()),
        ),
    ] {
        assert!(text.contains("****************"), "{text}");
        // Nothing of the token's own encoding is left to decode.
        let middle = &encoded[encoded.len() / 2 - 8..encoded.len() / 2 + 8];
        assert!(!text.contains(middle), "{text}");
    }

    let leak = signed(
        "GET",
        port,
        "/s3/bucket/leak",
        &[],
        AWS_PLACEHOLDER,
        &[],
        b"",
    );
    let body = leak.send().await.unwrap().text().await.unwrap();
    assert!(!body.contains("secret%2bkey"), "{body}");
    assert!(body.starts_with("key=*"), "{body}");
}

/// `%3b` decodes to a matrix parameter an upstream might honour.
#[tokio::test]
async fn an_escaped_semicolon_in_the_path_is_refused() {
    let up = upstream(None).await;
    let port = broker(vec![bearer("api", up.port, "authorization")], me()).await;
    for target in ["/api/v1/secret%3b.json", "/api/v1/secret%3B.json"] {
        let head = format!(
            "GET {target} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {PLACEHOLDER}\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(raw(port, &head).await, 403, "{target}");
    }
    assert!(up.seen().is_empty());
}

/// `X-Amz-*` query parameters are a presigned URL's, however escaped.
#[tokio::test]
async fn escaped_presigned_parameters_are_refused() {
    let up = upstream(None).await;
    let port = broker(vec![s3(up.port)], me()).await;
    // Signed (as the broker checks it) with the run's placeholder key, so
    // only the query can be what's refused.
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={AWS_PLACEHOLDER}/20261125/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=00"
    );
    for query in ["%58-Amz-Security-Token=x", "x-amz-%65xpires=60"] {
        let url = format!("http://127.0.0.1:{port}/s3/bucket/x?{query}");
        let response = client()
            .get(url)
            .header("authorization", &authorization)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "{query}");
    }
    assert!(up.seen().is_empty());
}

/// An `aws-chunked` body with bytes after its end, or a decoded length that
/// isn't a number, is refused rather than guessed at.
#[tokio::test]
async fn malformed_aws_chunked_framing_is_refused() {
    let up = upstream(None).await;
    let port = broker(vec![s3(up.port)], me()).await;
    let chunked = |body: &'static [u8], length: &'static str| {
        signed(
            "PUT",
            port,
            "/s3/bucket/chunked",
            &[],
            AWS_PLACEHOLDER,
            &[
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", length),
            ],
            body,
        )
    };
    for (body, length) in [
        (&b"b\r\nhello world\r\n0\r\n\r\nsmuggled"[..], "11"),
        (b"b\r\nhello world\r\n0\r\n", "11"),
        (b"b\r\nhello world\r\n0\r\n\r\n", "eleven"),
        (b"b\r\nhello world\r\n0\r\n\r\n", "-1"),
    ] {
        let response = chunked(body, length).send().await.unwrap();
        assert_eq!(response.status(), 400, "{body:?} {length}");
    }
    assert!(up.seen().is_empty());
}

/// A refused client gets one answer and the connection closes: it can't
/// keep a socket open, or pipeline request after request on it.
#[tokio::test]
async fn a_refused_connection_is_not_kept_alive() {
    let up = upstream(None).await;
    let mut outsider = Command::new("sleep").arg("30").spawn().unwrap();
    let port = broker(
        vec![bearer("api", up.port, "authorization")],
        Some(outsider.id()),
    )
    .await;
    let one = format!(
        "GET /api/v1/chat HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n"
    );
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(format!("{one}{one}").as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("the broker closes a refused connection")
        .unwrap();
    let text = String::from_utf8_lossy(&response);
    assert_eq!(text.matches("HTTP/1.1 403").count(), 1, "{text}");
    assert!(up.seen().is_empty());
    outsider.kill().unwrap();
    outsider.wait().unwrap();
}

/// Processes by pid, changeable while a check runs.
struct Procs(RefCell<HashMap<u32, Facts>>);

impl Procs {
    fn new(rows: &[(u32, u32, u64)]) -> Self {
        Self(RefCell::new(
            rows.iter()
                .map(|&(pid, ppid, start)| {
                    (
                        pid,
                        Facts {
                            ppid,
                            start: (start, 0),
                        },
                    )
                })
                .collect(),
        ))
    }
}

impl ProcessFacts for Procs {
    fn facts(&self, pid: u32) -> Option<Facts> {
        self.0.borrow().get(&pid).copied()
    }
}

/// The owner the tree walk names is checked by `(pid, start)`: it must
/// descend from the run by start time and still hold the socket after, so
/// a pid that exits and is reused mid-check is never let in.
#[test]
fn a_connections_owner_must_still_be_the_runs_after_the_check() {
    let lineage = Lineage {
        root_pid: 20,
        root_start: Some((20, 0)),
    };
    let rows = [(1, 0, 1), (20, 1, 20), (30, 20, 30), (40, 30, 40)];
    // The tree walk found `owner`; `holds` is the socket asked again.
    let allowed = |procs: &Procs, owner: u32, holds: &dyn Fn(u32) -> bool| {
        lineage.allows_with(procs, |_, confirm| {
            (confirm(owner) && holds(owner)).then_some(owner)
        })
    };
    let procs = Procs::new(&rows);
    assert!(allowed(&procs, 40, &|pid| pid == 40));
    assert!(allowed(&procs, 20, &|pid| pid == 20));
    // Not holding the socket on the second look.
    assert!(!allowed(&procs, 40, &|_| false));
    // Outside the run's tree, or under a parent younger than its child.
    let outside = Procs::new(&[(1, 0, 1), (20, 1, 20), (40, 1, 40)]);
    assert!(!allowed(&outside, 40, &|_| true));
    let younger = Procs::new(&[(1, 0, 1), (20, 1, 20), (30, 20, 50), (40, 30, 40)]);
    assert!(!allowed(&younger, 40, &|_| true));
    // The owner exits and its pid is reused while the check runs.
    let procs = Procs::new(&rows);
    let reused = |pid: u32| {
        procs.0.borrow_mut().insert(
            40,
            Facts {
                ppid: 1,
                start: (99, 0),
            },
        );
        pid == 40
    };
    assert!(!allowed(&procs, 40, &reused));
    // The run is gone.
    let gone = Procs::new(&[(1, 0, 1), (20, 1, 21), (40, 20, 40)]);
    assert!(!allowed(&gone, 40, &|_| true));
}

/// A cycle in the parent table stops immediately instead of spinning through
/// the hop limit, and refuses the connection.
#[test]
fn broker_lineage_guards_against_parent_cycles() {
    struct CountingProcs {
        procs: Procs,
        lookups: std::cell::Cell<usize>,
    }

    impl ProcessFacts for CountingProcs {
        fn facts(&self, pid: u32) -> Option<Facts> {
            self.lookups.set(self.lookups.get() + 1);
            self.procs.facts(pid)
        }
    }

    let lineage = Lineage {
        root_pid: 20,
        root_start: Some((20, 0)),
    };
    let cyclic = CountingProcs {
        procs: Procs::new(&[(20, 1, 20), (30, 40, 10), (40, 30, 10)]),
        lookups: std::cell::Cell::new(0),
    };
    assert!(!lineage.descends(&cyclic, 40, (10, 0)));
    assert!(
        cyclic.lookups.get() <= 4,
        "cycle should stop immediately, took {} lookups",
        cyclic.lookups.get()
    );
}

/// Under Linux `hidepid`, a hidden intermediate process whose visible parent
/// is the run's tree still lets its descendant through, while a system
/// boundary, an unproven missing parent, or a younger visible grandparent is
/// refused.
#[test]
fn broker_lineage_walks_through_hidepid_visible_parent() {
    struct HidingProcs {
        procs: Procs,
        hidden: Option<Hidden>,
    }

    impl ProcessFacts for HidingProcs {
        fn facts(&self, pid: u32) -> Option<Facts> {
            self.procs.facts(pid)
        }

        fn hidden(&self, parent: u32, child: u32, child_start: Start) -> Option<Hidden> {
            (parent == 30 && child == 40 && child_start == (40, 0)).then_some(self.hidden?)
        }
    }

    let lineage = Lineage {
        root_pid: 20,
        root_start: Some((20, 0)),
    };
    let rows = || Procs::new(&[(1, 0, 1), (20, 1, 20), (40, 30, 40)]);

    let through = HidingProcs {
        procs: rows(),
        hidden: Some(Hidden::VisibleParent(20)),
    };
    assert!(lineage.allows_with(&through, |_, confirm| confirm(40).then_some(40)));

    let system = HidingProcs {
        procs: rows(),
        hidden: Some(Hidden::SystemBoundary),
    };
    assert!(!lineage.allows_with(&system, |_, confirm| confirm(40).then_some(40)));

    let unproven = HidingProcs {
        procs: rows(),
        hidden: None,
    };
    assert!(!lineage.allows_with(&unproven, |_, confirm| confirm(40).then_some(40)));

    // Grandparent started after the visible child: pid reuse, refused.
    let younger_grandparent = HidingProcs {
        procs: Procs::new(&[(1, 0, 1), (20, 1, 99), (40, 30, 40)]),
        hidden: Some(Hidden::VisibleParent(20)),
    };
    let reused_lineage = Lineage {
        root_pid: 20,
        root_start: Some((99, 0)),
    };
    assert!(
        !reused_lineage.allows_with(&younger_grandparent, |_, confirm| {
            confirm(40).then_some(40)
        })
    );
}
