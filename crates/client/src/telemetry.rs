//! OpenTelemetry traces for a local collector: OTLP/HTTP JSON to a loopback
//! address, posted by one background thread. Off unless [`start`] is given
//! an address: no thread, no socket, and spans that do nothing.
//!
//! Spans carry only fixed metadata: names, counts, durations, flags and
//! `&'static str` labels such as a command's name or an error code. A
//! string attribute must be `'static`, so a passphrase, an item's title, a
//! field's value or a URL read at run time can't become one.
//!
//! Callers only push finished spans onto a bounded channel, dropping them
//! when it's full; the exporter batches them and drops a batch nothing
//! listens for. [`capture`] collects one thread's spans instead, for tests.

use std::cell::RefCell;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value as Json, json};

/// Where `OTEL_EXPORTER_OTLP_ENDPOINT=1` sends: Motel's OTLP/HTTP receiver.
pub const LOOPBACK_DEFAULT: &str = "127.0.0.1:27686";
const PATH: &str = "/v1/traces";
/// Finished spans waiting for the exporter; more are dropped.
const QUEUE: usize = 4096;
/// The most spans in one request.
const BATCH: usize = 512;
/// How long the exporter waits for more spans before posting, so one
/// trace's spans tend to share a request.
const LINGER: Duration = Duration::from_millis(200);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
const IO_TIMEOUT: Duration = Duration::from_secs(1);
/// How long [`flush`] waits for the exporter.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// An attribute's value: a number, a flag, or a fixed label.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Float(f64),
    /// Only a `'static` string, so nothing read at run time.
    Label(&'static str),
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Self::Int(i64::from(value))
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Self::Int(i64::try_from(value).unwrap_or(i64::MAX))
    }
}

impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Self::Int(i64::try_from(value).unwrap_or(i64::MAX))
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl From<&'static str> for Value {
    fn from(value: &'static str) -> Self {
        Self::Label(value)
    }
}

impl Value {
    /// OTLP's `AnyValue`.
    fn otlp(self) -> Json {
        match self {
            Self::Bool(b) => json!({ "boolValue": b }),
            Self::Int(n) => json!({ "intValue": n.to_string() }),
            Self::Float(x) => json!({ "doubleValue": x }),
            Self::Label(s) => json!({ "stringValue": s }),
        }
    }
}

/// A span's place in its trace, for starting a child on another thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ctx {
    trace: u128,
    span: u64,
}

/// One timed operation. Inert when telemetry is off: nothing is allocated
/// and ending it does nothing. A span that is dropped without [`Span::end`]
/// isn't recorded.
#[must_use = "a span is only recorded when it ends"]
pub struct Span(Option<Box<Live>>);

struct Live {
    ctx: Ctx,
    parent: Option<u64>,
    name: &'static str,
    start: Instant,
    attrs: Vec<(&'static str, Value)>,
    failed: bool,
}

impl Span {
    /// A span that starts a trace.
    pub fn root(name: &'static str) -> Self {
        Self::new(None, name, || (u128::from(id()) << 64) | u128::from(id()))
    }

    /// A span under `parent`, in its trace.
    pub fn child_of(parent: Ctx, name: &'static str) -> Self {
        Self::new(Some(parent.span), name, || parent.trace)
    }

    /// A span under this one; inert when this one is.
    pub fn child(&self, name: &'static str) -> Self {
        match &self.0 {
            Some(live) => Self::child_of(live.ctx, name),
            None => Self(None),
        }
    }

    fn new(parent: Option<u64>, name: &'static str, trace: impl FnOnce() -> u128) -> Self {
        if !on() {
            return Self(None);
        }
        Self(Some(Box::new(Live {
            ctx: Ctx {
                trace: trace(),
                span: id(),
            },
            parent,
            name,
            start: Instant::now(),
            attrs: Vec::new(),
            failed: false,
        })))
    }

    /// Whether this span will be recorded when it ends.
    pub fn is_recording(&self) -> bool {
        self.0.is_some()
    }

    pub fn ctx(&self) -> Option<Ctx> {
        self.0.as_ref().map(|live| live.ctx)
    }

    /// Moves the start back, for an interval that began earlier.
    pub fn at(mut self, start: Instant) -> Self {
        if let Some(live) = &mut self.0 {
            live.start = start;
        }
        self
    }

    pub fn attr(mut self, key: &'static str, value: impl Into<Value>) -> Self {
        self.set(key, value);
        self
    }

    /// Sets an attribute, replacing one of the same key.
    pub fn set(&mut self, key: &'static str, value: impl Into<Value>) {
        let Some(live) = &mut self.0 else { return };
        let value = value.into();
        match live.attrs.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = value,
            None => live.attrs.push((key, value)),
        }
    }

    /// Marks the operation as succeeded: `outcome = "ok"`.
    pub fn ok(&mut self) {
        self.set("outcome", "ok");
    }

    /// Marks the operation as failed: `outcome = "error"`, `error = true`,
    /// `error.code` when there is one, and an error status with no message
    /// (an error's message can quote what the user typed).
    pub fn fail(&mut self, code: Option<&'static str>) {
        self.set("outcome", "error");
        self.set("error", true);
        if let Some(code) = code {
            self.set("error.code", code);
        }
        if let Some(live) = &mut self.0 {
            live.failed = true;
        }
    }

    pub fn end(self) {
        self.end_at(Instant::now());
    }

    pub fn end_at(self, end: Instant) {
        let Some(live) = self.0 else { return };
        let attrs: Vec<Json> = live
            .attrs
            .iter()
            .map(|(key, value)| json!({ "key": key, "value": value.otlp() }))
            .collect();
        let mut span = json!({
            "traceId": format!("{:032x}", live.ctx.trace),
            "spanId": format!("{:016x}", live.ctx.span),
            "name": live.name,
            "kind": 1,
            "startTimeUnixNano": unix_nanos(live.start).to_string(),
            "endTimeUnixNano": unix_nanos(end.max(live.start)).to_string(),
            "attributes": attrs,
            "status": { "code": if live.failed { 2 } else { 0 } },
        });
        if let Some(parent) = live.parent {
            span["parentSpanId"] = format!("{parent:016x}").into();
        }
        let captured = CAPTURE.with(|c| match c.borrow_mut().as_mut() {
            Some(spans) => {
                spans.push(span.clone());
                true
            }
            None => false,
        });
        if !captured && let Some(exporter) = exporter() {
            exporter.send(span);
        }
    }
}

/// A random, nonzero id.
fn id() -> u64 {
    static N: AtomicU64 = AtomicU64::new(0);
    static SEED: OnceLock<RandomState> = OnceLock::new();
    let mut h = SEED.get_or_init(RandomState::new).build_hasher();
    h.write_u64(N.fetch_add(1, Ordering::Relaxed));
    h.finish().max(1)
}

/// `t` as Unix nanoseconds, against one wall-clock reading taken the first
/// time a span ends, so spans stay ordered whatever the wall clock does.
fn unix_nanos(t: Instant) -> u128 {
    static ANCHOR: OnceLock<(Instant, u128)> = OnceLock::new();
    #[expect(
        clippy::disallowed_methods,
        reason = "OTLP timestamps are wall-clock: one reading anchors every span's Instant"
    )]
    let anchor = || {
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        (Instant::now(), unix)
    };
    let (at, unix) = *ANCHOR.get_or_init(anchor);
    if t >= at {
        unix + (t - at).as_nanos()
    } else {
        unix.saturating_sub((at - t).as_nanos())
    }
}

thread_local! {
    /// Spans this thread ends, kept instead of sent (`capture`).
    static CAPTURE: RefCell<Option<Vec<Json>>> = const { RefCell::new(None) };
}

/// Runs `f` with this thread's spans collected instead of sent, and returns
/// them as OTLP JSON spans. Spans start recording inside it even when
/// telemetry is off.
pub fn capture<R>(f: impl FnOnce() -> R) -> (R, Vec<Json>) {
    let outer = CAPTURE.with(|c| c.borrow_mut().replace(Vec::new()));
    let result = f();
    let spans = CAPTURE.with(|c| std::mem::replace(&mut *c.borrow_mut(), outer));
    (result, spans.unwrap_or_default())
}

/// Whether spans go anywhere: an exporter is running, or a [`capture`].
pub fn on() -> bool {
    exporter().is_some() || CAPTURE.with(|c| c.borrow().is_some())
}

/// Where an `OTEL_EXPORTER_OTLP_ENDPOINT` setting sends: `1` is
/// [`LOOPBACK_DEFAULT`], otherwise `host:port` or
/// `http://host:port[/v1/traces]` on loopback (`localhost` included).
/// Anything else is off: empty, `0`, `https`, or another host, since
/// traces go out unencrypted.
pub fn endpoint(setting: &str) -> Option<SocketAddr> {
    let setting = setting.trim();
    if setting == "1" {
        return LOOPBACK_DEFAULT.parse().ok();
    }
    let rest = match setting.split_once("://") {
        Some(("http", rest)) => rest,
        Some(_) => return None,
        None => setting,
    };
    let authority = rest.split('/').next()?;
    let authority = match authority.strip_prefix("localhost:") {
        Some(port) => format!("127.0.0.1:{port}"),
        None => authority.to_owned(),
    };
    authority
        .parse::<SocketAddr>()
        .ok()
        .filter(|addr| addr.ip().is_loopback() && addr.port() != 0)
}

static EXPORTER: OnceLock<Option<Exporter>> = OnceLock::new();

fn exporter() -> Option<&'static Exporter> {
    EXPORTER.get().and_then(Option::as_ref)
}

/// Names this process's service and where its spans go. `None` leaves
/// telemetry off for good, with no thread started. The first call wins.
pub fn start(service: &'static str, version: &str, to: Option<SocketAddr>) {
    EXPORTER.get_or_init(|| to.and_then(|to| Exporter::spawn(service, version, to)));
}

/// Waits briefly for spans ended so far to be posted, as a process exits.
/// Returns at once when telemetry is off.
pub fn flush() {
    if let Some(exporter) = exporter() {
        exporter.flush();
    }
}

enum Message {
    Span(Json),
    Flush(mpsc::Sender<()>),
}

/// The background thread that posts spans, and the way to it.
struct Exporter {
    queue: SyncSender<Message>,
}

impl Exporter {
    fn spawn(service: &'static str, version: &str, to: SocketAddr) -> Option<Self> {
        let (send, receive) = mpsc::sync_channel(QUEUE);
        let resource = json!([
            { "key": "service.name", "value": { "stringValue": service } },
            { "key": "service.version", "value": { "stringValue": version } },
            { "key": "process.pid", "value": { "intValue": std::process::id().to_string() } },
        ]);
        std::thread::Builder::new()
            .name("otel-export".into())
            .spawn(move || export(&receive, service, &resource, to))
            .ok()?;
        Some(Self { queue: send })
    }

    /// Queues a span, or drops it when the queue is full.
    fn send(&self, span: Json) {
        drop(self.queue.try_send(Message::Span(span)));
    }

    /// Whether the exporter posted (or dropped) everything queued before
    /// this, within [`FLUSH_TIMEOUT`].
    fn flush(&self) -> bool {
        let (done, wait) = mpsc::channel();
        match self.queue.try_send(Message::Flush(done)) {
            Ok(()) => wait.recv_timeout(FLUSH_TIMEOUT).is_ok(),
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
        }
    }
}

/// The exporter thread: gathers spans for up to [`LINGER`] (or until a
/// flush, or [`BATCH`] of them), posts them, and answers flushes.
fn export(queue: &Receiver<Message>, service: &str, resource: &Json, to: SocketAddr) {
    while let Ok(first) = queue.recv() {
        let deadline = Instant::now() + LINGER;
        let mut spans = Vec::new();
        let mut flushes = Vec::new();
        let mut next = Some(first);
        while let Some(message) = next.take() {
            match message {
                Message::Span(span) => spans.push(span),
                Message::Flush(done) => flushes.push(done),
            }
            if !flushes.is_empty() || spans.len() >= BATCH {
                break;
            }
            match queue.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(message) => next = Some(message),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {}
            }
        }
        if !spans.is_empty() {
            post(to, &payload(service, resource, spans));
        }
        for done in flushes {
            done.send(()).unwrap_or_default();
        }
    }
}

/// One OTLP/HTTP JSON `ExportTraceServiceRequest`.
fn payload(service: &str, resource: &Json, spans: Vec<Json>) -> String {
    json!({
        "resourceSpans": [{
            "resource": { "attributes": resource },
            "scopeSpans": [{ "scope": { "name": service }, "spans": spans }],
        }],
    })
    .to_string()
}

/// One HTTP/1.1 POST; a refused or slow connection drops the batch.
fn post(to: SocketAddr, body: &str) {
    let Ok(mut stream) = TcpStream::connect_timeout(&to, CONNECT_TIMEOUT) else {
        return;
    };
    drop(stream.set_write_timeout(Some(IO_TIMEOUT)));
    drop(stream.set_read_timeout(Some(IO_TIMEOUT)));
    let head = format!(
        "POST {PATH} HTTP/1.1\r\nHost: {to}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()))
        .is_ok()
    {
        // Wait for the collector's status line, so a flush means received.
        drop(stream.read(&mut [0; 256]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn attr(span: &Json, key: &str) -> Option<Json> {
        span["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["key"] == key)
            .map(|a| a["value"].clone())
    }

    #[test]
    fn endpoints_are_loopback_http_only() {
        let addr = |s: &str| s.parse::<SocketAddr>().ok();
        assert_eq!(endpoint("1"), addr(LOOPBACK_DEFAULT));
        assert_eq!(endpoint("http://127.0.0.1:4318"), addr("127.0.0.1:4318"));
        assert_eq!(
            endpoint("http://localhost:4318/v1/traces"),
            addr("127.0.0.1:4318")
        );
        assert_eq!(endpoint(" http://localhost:4318/ "), addr("127.0.0.1:4318"));
        assert_eq!(endpoint("127.0.0.1:9"), addr("127.0.0.1:9"));
        assert_eq!(endpoint("localhost:27686"), addr("127.0.0.1:27686"));
        assert_eq!(endpoint("http://[::1]:4318"), addr("[::1]:4318"));
        for off in [
            "",
            "0",
            "localhost",
            "127.0.0.1",
            "127.0.0.1:0",
            "http://10.0.0.2:4318",
            "https://127.0.0.1:4318",
            "https://otel.example.com",
            "grpc://127.0.0.1:4317",
            "otel.example.com:4318",
        ] {
            assert_eq!(endpoint(off), None, "{off:?}");
        }
    }

    /// No exporter started and no capture running: spans are inert.
    #[test]
    fn off_by_default() {
        start("deadbolt-test", "0", None);
        assert!(EXPORTER.get().is_some_and(Option::is_none));
        assert!(!on());
        let span = Span::root("idle").attr("count", 3u32);
        assert!(!span.is_recording());
        assert!(span.ctx().is_none());
        assert!(!span.child("inner").is_recording());
        span.end();
        flush();
    }

    #[test]
    fn spans_are_otlp_json() {
        let (_, spans) = capture(|| {
            let mut span = Span::root("daemon.command")
                .attr("command", "item-get")
                .attr("rows", 3u32)
                .attr("held", true)
                .attr("ms", 1.5);
            span.ok();
            span.end();
        });
        assert_eq!(spans.len(), 1);
        let span = &spans[0];
        assert_eq!(span["name"], "daemon.command");
        assert_eq!(span["kind"], 1);
        assert_eq!(span["traceId"].as_str().unwrap().len(), 32);
        assert_eq!(span["spanId"].as_str().unwrap().len(), 16);
        assert!(span.get("parentSpanId").is_none());
        let start: u128 = span["startTimeUnixNano"].as_str().unwrap().parse().unwrap();
        let end: u128 = span["endTimeUnixNano"].as_str().unwrap().parse().unwrap();
        assert!(start > 1_600_000_000_000_000_000 && end >= start);
        assert_eq!(
            attr(span, "command"),
            Some(json!({ "stringValue": "item-get" }))
        );
        assert_eq!(attr(span, "rows"), Some(json!({ "intValue": "3" })));
        assert_eq!(attr(span, "held"), Some(json!({ "boolValue": true })));
        assert_eq!(attr(span, "ms"), Some(json!({ "doubleValue": 1.5 })));
        assert_eq!(attr(span, "outcome"), Some(json!({ "stringValue": "ok" })));
        assert_eq!(span["status"], json!({ "code": 0 }));
    }

    #[test]
    fn children_share_the_trace_and_name_their_parent() {
        let (_, spans) = capture(|| {
            let root = Span::root("outer");
            let child = root.child("inner");
            let ctx = child.ctx().unwrap();
            // Across a thread, by context.
            let grandchild = Span::child_of(ctx, "deeper");
            grandchild.end();
            child.end();
            root.end();
        });
        let [deeper, inner, outer] = &spans[..] else {
            panic!("{spans:?}");
        };
        assert_eq!(outer["name"], "outer");
        assert_eq!(inner["parentSpanId"], outer["spanId"]);
        assert_eq!(deeper["parentSpanId"], inner["spanId"]);
        assert_eq!(inner["traceId"], outer["traceId"]);
        assert_eq!(deeper["traceId"], outer["traceId"]);
        assert_ne!(inner["spanId"], outer["spanId"]);
        // Another root starts another trace.
        let (_, other) = capture(|| Span::root("again").end());
        assert_ne!(other[0]["traceId"], outer["traceId"]);
    }

    #[test]
    fn failures_carry_a_code_and_no_message() {
        let (_, spans) = capture(|| {
            let mut coded = Span::root("coded");
            coded.ok();
            coded.fail(Some("locked"));
            coded.end();
            let mut bare = Span::root("bare");
            bare.fail(None);
            bare.end();
        });
        let (coded, bare) = (&spans[0], &spans[1]);
        assert_eq!(
            attr(coded, "outcome"),
            Some(json!({ "stringValue": "error" }))
        );
        assert_eq!(attr(coded, "error"), Some(json!({ "boolValue": true })));
        assert_eq!(
            attr(coded, "error.code"),
            Some(json!({ "stringValue": "locked" }))
        );
        assert_eq!(coded["status"], json!({ "code": 2 }));
        assert_eq!(
            coded["attributes"].as_array().unwrap().len(),
            3,
            "outcome set once"
        );
        assert_eq!(attr(bare, "error"), Some(json!({ "boolValue": true })));
        assert_eq!(attr(bare, "error.code"), None);
        assert_eq!(bare["status"], json!({ "code": 2 }));
    }

    #[test]
    fn capture_nests_and_spans_end_where_they_started() {
        let (inner, outer) = capture(|| {
            Span::root("outer").end();
            capture(|| Span::root("inner").end()).1
        });
        assert_eq!(outer.len(), 1);
        assert_eq!(inner.len(), 1);
        assert_eq!(outer[0]["name"], "outer");
        assert_eq!(inner[0]["name"], "inner");
        assert!(!CAPTURE.with(|c| c.borrow().is_some()));
    }

    /// Reads one HTTP request and answers it.
    fn receive(listener: &TcpListener) -> (String, Json) {
        let (mut conn, _) = listener.accept().unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut raw = Vec::new();
        let mut buf = [0; 4096];
        let (head, body) = loop {
            let n = conn.read(&mut buf).unwrap();
            assert!(n > 0, "closed before the body");
            raw.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&raw);
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                if body.len() >= len {
                    break (head.to_owned(), body.to_owned());
                }
            }
        };
        conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        (head, serde_json::from_str(&body).unwrap())
    }

    #[test]
    fn the_exporter_posts_one_batch_per_flush() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let exporter =
            Exporter::spawn("deadbolt-test", "9.9.9", listener.local_addr().unwrap()).unwrap();
        let (_, spans) = capture(|| {
            let root = Span::root("daemon.command").attr("command", "status");
            root.child("inner").end();
            root.end();
        });
        for span in spans {
            exporter.send(span);
        }
        let server = std::thread::spawn(move || receive(&listener));
        assert!(exporter.flush());
        let (head, body) = server.join().unwrap();
        assert!(head.starts_with("POST /v1/traces HTTP/1.1\r\n"), "{head}");
        assert!(head.contains("Content-Type: application/json"), "{head}");
        let rs = &body["resourceSpans"][0];
        let resource = |key: &str| {
            rs["resource"]["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["key"] == key)
                .unwrap()["value"]
                .clone()
        };
        assert_eq!(
            resource("service.name"),
            json!({ "stringValue": "deadbolt-test" })
        );
        assert_eq!(
            resource("service.version"),
            json!({ "stringValue": "9.9.9" })
        );
        assert_eq!(
            resource("process.pid"),
            json!({ "intValue": std::process::id().to_string() })
        );
        let scope = &rs["scopeSpans"][0];
        assert_eq!(scope["scope"]["name"], "deadbolt-test");
        let spans = scope["spans"].as_array().unwrap();
        assert_eq!(spans.len(), 2, "both spans in one request");
        assert_eq!(spans[0]["parentSpanId"], spans[1]["spanId"]);
    }

    #[test]
    fn nothing_listening_drops_the_batch() {
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let exporter = Exporter::spawn("deadbolt-test", "0", addr).unwrap();
        let (_, spans) = capture(|| Span::root("lost").end());
        let started = Instant::now();
        exporter.send(spans.into_iter().next().unwrap());
        assert!(exporter.flush());
        assert!(started.elapsed() < FLUSH_TIMEOUT);
        // And a flush with nothing queued answers too.
        assert!(exporter.flush());
    }
}
