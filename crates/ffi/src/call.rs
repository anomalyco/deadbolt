//! One AutoFill request over the App Group socket: connect, check the
//! daemon's code, send the line, read the reply line, all by a deadline, and
//! cancellable from another thread at any point.
//!
//! The socket is non-blocking and every wait is a `poll` bounded by the
//! deadline. Cancelling shuts the socket down, which wakes the wait at once
//! and tells the daemon the caller hung up, so it dismisses an open Touch ID
//! sheet.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use deadbolt_client::{append, peer};
use deadbolt_proto::daemon::{MAX_AUTOFILL_LINE, Message, PROTOCOL_VERSION, Request};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use zeroize::Zeroizing;

use crate::autofill::{self, AutofillCommand, AutofillReply, DaemonCallError};

/// The longest socket path `sockaddr_un` takes on macOS (104 bytes with
/// its NUL).
const SUN_PATH_MAX: usize = 103;
/// The shortest deadline a call gets, however small its timeout.
const MIN_TIMEOUT: Duration = Duration::from_millis(50);
/// The longest deadline a call gets, however large its timeout: longer than
/// any Touch ID sheet stays up.
const MAX_TIMEOUT: Duration = Duration::from_secs(300);

/// Swift's timeout in seconds, as a deadline from now that can't overflow:
/// NaN, zero and negative get the shortest, anything over five minutes
/// (infinity included) the longest.
fn timeout_of(secs: f64) -> Duration {
    if secs.is_nan() || secs <= 0.0 {
        return MIN_TIMEOUT;
    }
    Duration::try_from_secs_f64(secs)
        .unwrap_or(MAX_TIMEOUT)
        .clamp(MIN_TIMEOUT, MAX_TIMEOUT)
}

/// Cancels a call in flight from any thread, such as when the AutoFill
/// sheet goes away. A handle cancelled before its call starts fails it
/// straight away; once cancelled it stays so.
#[derive(Debug, Default, uniffi::Object)]
pub struct CallHandle {
    state: Mutex<HandleState>,
}

#[derive(Debug, Default)]
struct HandleState {
    cancelled: bool,
    /// A duplicate of the call's socket while it runs, to shut down.
    socket: Option<UnixStream>,
}

#[uniffi::export]
impl CallHandle {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    /// Fails the call with `cancelled`, at once if it's waiting on the
    /// daemon.
    pub fn cancel(&self) {
        let socket = {
            let mut state = self.state();
            state.cancelled = true;
            state.socket.take()
        };
        if let Some(socket) = socket {
            drop(socket.shutdown(Shutdown::Both));
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.state().cancelled
    }
}

impl CallHandle {
    fn state(&self) -> MutexGuard<'_, HandleState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A call's handle, holding its socket until the call ends.
struct Attached<'a>(Option<&'a CallHandle>);

impl<'a> Attached<'a> {
    fn new(handle: Option<&'a CallHandle>, stream: &UnixStream) -> Result<Self, DaemonCallError> {
        let Some(handle) = handle else {
            return Ok(Self(None));
        };
        let socket = stream
            .try_clone()
            .map_err(|_| unavailable("could not create Unix socket"))?;
        let mut state = handle.state();
        if state.cancelled {
            drop(state);
            drop(socket.shutdown(Shutdown::Both));
            return Err(DaemonCallError::Cancelled);
        }
        state.socket = Some(socket);
        Ok(Self(Some(handle)))
    }

    fn cancelled(&self) -> bool {
        self.0.is_some_and(CallHandle::is_cancelled)
    }

    /// `error`, or `cancelled` when that's why it happened.
    fn or_cancelled(&self, error: DaemonCallError) -> DaemonCallError {
        if self.cancelled() {
            DaemonCallError::Cancelled
        } else {
            error
        }
    }
}

impl Drop for Attached<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.0 {
            handle.state().socket = None;
        }
    }
}

/// What a call came to. Swift turns `failed` into a thrown error.
#[derive(Debug, uniffi::Enum)]
pub enum CallOutcome {
    Replied(AutofillReply),
    Failed(DaemonCallError),
}

/// Sends `command` to the daemon at `socket_path` and waits up to
/// `timeout_secs` for its reply. Blocks: call it off the main thread.
///
/// With `daemon`, the path of the daemon binary this extension ships
/// with, the socket's peer must be that binary's code
/// ([`peer::check`]) before anything is sent. Without it, nothing that
/// carries the passphrase is.
#[uniffi::export]
pub fn autofill_call(
    socket_path: String,
    command: AutofillCommand,
    timeout_secs: f64,
    handle: Option<Arc<CallHandle>>,
    daemon: Option<String>,
) -> CallOutcome {
    match send(
        Path::new(&socket_path),
        command,
        timeout_of(timeout_secs),
        handle.as_deref(),
        daemon.as_deref().map(Path::new),
    ) {
        Ok(reply) => CallOutcome::Replied(reply),
        Err(error) => CallOutcome::Failed(error),
    }
}

fn send(
    path: &Path,
    command: AutofillCommand,
    timeout: Duration,
    handle: Option<&CallHandle>,
    daemon: Option<&Path>,
) -> Result<AutofillReply, DaemonCallError> {
    if handle.is_some_and(CallHandle::is_cancelled) {
        return Err(DaemonCallError::Cancelled);
    }
    let len = path.as_os_str().len();
    if len == 0 || len > SUN_PATH_MAX {
        return Err(unavailable("AutoFill socket path exceeds sun_path limit"));
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(DaemonCallError::TimedOut)?;
    let stream =
        UnixStream::connect(path).map_err(|_| unavailable("Deadbolt's daemon is not running"))?;
    // A write to a daemon that hung up fails with EPIPE rather than killing
    // the extension with SIGPIPE, which Swift doesn't ignore.
    #[cfg(target_vendor = "apple")]
    rustix::net::sockopt::set_socket_nosigpipe(&stream, true)
        .map_err(|_| unavailable("could not create Unix socket"))?;
    stream
        .set_nonblocking(true)
        .map_err(|_| unavailable("could not create Unix socket"))?;
    let call = Attached::new(handle, &stream)?;

    let command = command.into_proto();
    match daemon {
        Some(daemon) => {
            peer::check(&stream, daemon)
                .map_err(|reason| call.or_cancelled(DaemonCallError::PeerRejected { reason }))?;
        }
        None if command.carries_client_secret() => {
            return Err(DaemonCallError::PeerRejected {
                reason: "refusing to send a secret without verifying Deadbolt's daemon signature"
                    .into(),
            });
        }
        None => {}
    }
    let request = Request {
        v: PROTOCOL_VERSION,
        command,
    };
    let line = deadbolt_client::encode_json(
        b"", &request, b"
",
    )
    .map_err(|_| DaemonCallError::InvalidResponse {
        reason: "could not encode the request".into(),
    })?;
    drop(request);
    write_all(&stream, &line, deadline, &call)?;
    let reply = read_line(&stream, MAX_AUTOFILL_LINE, deadline, &call)?;
    decode(&reply)
}

fn unavailable(reason: &str) -> DaemonCallError {
    DaemonCallError::DaemonUnavailable {
        reason: reason.into(),
    }
}

/// Waits until `stream` is ready for `flags` (or hung up), by `deadline`.
fn wait(
    stream: &UnixStream,
    flags: PollFlags,
    deadline: Instant,
    call: &Attached<'_>,
) -> Result<(), DaemonCallError> {
    loop {
        if call.cancelled() {
            return Err(DaemonCallError::Cancelled);
        }
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or(DaemonCallError::TimedOut)?;
        let timeout = Timespec {
            tv_sec: i64::try_from(left.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: left.subsec_nanos().into(),
        };
        let mut fds = [PollFd::new(stream, flags)];
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) => return Err(call.or_cancelled(DaemonCallError::TimedOut)),
            Ok(_) => return Ok(()),
            Err(Errno::INTR) => {}
            Err(_) => {
                return Err(call.or_cancelled(unavailable("waiting on AutoFill socket failed")));
            }
        }
    }
}

fn write_all(
    mut stream: &UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
    call: &Attached<'_>,
) -> Result<(), DaemonCallError> {
    const WHAT: &str = "writing to Deadbolt's daemon failed";
    while !bytes.is_empty() {
        if call.cancelled() {
            return Err(DaemonCallError::Cancelled);
        }
        match stream.write(bytes) {
            Ok(0) => return Err(call.or_cancelled(unavailable(WHAT))),
            Ok(n) => bytes = bytes.get(n..).unwrap_or_default(),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait(stream, PollFlags::OUT, deadline, call)?;
            }
            Err(_) => return Err(call.or_cancelled(unavailable(WHAT))),
        }
    }
    Ok(())
}

/// The reply line, without its `\n`, into a buffer wiped on drop. A daemon
/// that hangs up after a partial line has said all it will.
fn read_line(
    mut stream: &UnixStream,
    max: usize,
    deadline: Instant,
    call: &Attached<'_>,
) -> Result<Zeroizing<Vec<u8>>, DaemonCallError> {
    const WHAT: &str = "reading from Deadbolt's daemon failed";
    let too_long = || DaemonCallError::InvalidResponse {
        reason: "daemon reply exceeded max line size".into(),
    };
    let mut line = Zeroizing::new(Vec::with_capacity(1024));
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        if call.cancelled() {
            return Err(DaemonCallError::Cancelled);
        }
        let n = match stream.read(&mut chunk[..]) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait(stream, PollFlags::IN, deadline, call)?;
                continue;
            }
            Err(_) => return Err(call.or_cancelled(unavailable(WHAT))),
        };
        if n == 0 {
            if call.cancelled() {
                return Err(DaemonCallError::Cancelled);
            }
            if line.is_empty() {
                return Err(unavailable("Deadbolt's daemon closed the connection"));
            }
            return Ok(line);
        }
        let read = chunk.get(..n).unwrap_or_default();
        let end = read.iter().position(|b| *b == b'\n');
        let part = read.get(..end.unwrap_or(n)).unwrap_or_default();
        if line.len() + part.len() > max {
            return Err(too_long());
        }
        append(&mut line, part, max);
        if end.is_some() {
            return Ok(line);
        }
    }
}

/// The daemon's message, as the extension sees it. A parse error names
/// where the reply broke, never what it said: it may hold a secret.
fn decode(line: &[u8]) -> Result<AutofillReply, DaemonCallError> {
    let invalid = |reason: String| DaemonCallError::InvalidResponse { reason };
    match serde_json::from_slice::<Message>(line) {
        Ok(Message::Ok { reply }) => autofill::reply(reply)
            .ok_or_else(|| invalid("unexpected reply from Deadbolt's daemon".into())),
        Ok(Message::Error { code, message }) => Err(DaemonCallError::DaemonError {
            code: code.into(),
            message,
        }),
        Ok(Message::Event { .. } | Message::Change { .. }) => {
            Err(invalid("unexpected message from Deadbolt's daemon".into()))
        }
        Err(e) => Err(invalid(format!(
            "malformed reply from Deadbolt's daemon (line {}, column {})",
            e.line(),
            e.column()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;
    use std::thread;

    use super::*;
    use crate::autofill::{AutofillStatusReply, DaemonErrorCode};

    /// A daemon that reads one request and answers with `reply` (unless
    /// `None`, when it holds the line open until the client hangs up).
    fn daemon(
        reply: Option<&'static str>,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        thread::JoinHandle<String>,
    ) {
        let dir = tempfile::Builder::new()
            .prefix("dbffi")
            .tempdir_in("/tmp")
            .unwrap();
        let path = dir.path().join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(&stream).read_line(&mut request).unwrap();
            match reply {
                Some(reply) => (&stream).write_all(reply.as_bytes()).unwrap(),
                None => {
                    let mut rest = Vec::new();
                    drop((&stream).read_to_end(&mut rest));
                }
            }
            request
        });
        (dir, path, server)
    }

    fn status() -> AutofillCommand {
        AutofillCommand::AutofillStatus
    }

    #[test]
    fn a_reply_comes_back_typed() {
        let (_dir, path, server) = daemon(Some(
            "{\"type\":\"ok\",\"reply\":{\"reply\":\"autofill-status\",\"initialized\":true,\"unlocked\":false,\"touch_id_ready\":true,\"touch_id_reset\":false,\"can_verify\":false}}\n",
        ));
        let reply = send(&path, status(), Duration::from_secs(5), None, None).unwrap();
        assert_eq!(
            reply,
            AutofillReply::AutofillStatus(AutofillStatusReply {
                initialized: true,
                unlocked: false,
                touch_id_ready: true,
                touch_id_reset: false,
                can_verify: false,
                identities_hash: None,
            })
        );
        let request = server.join().unwrap();
        assert_eq!(
            request,
            format!("{{\"v\":{PROTOCOL_VERSION},\"cmd\":\"autofill-status\"}}\n")
        );
    }

    #[test]
    fn a_refusal_is_the_daemons_error() {
        let (_dir, path, _server) = daemon(Some(
            "{\"type\":\"error\",\"code\":\"domain-mismatch\",\"message\":\"not for this site\"}\n",
        ));
        let error = send(&path, status(), Duration::from_secs(5), None, None).unwrap_err();
        assert_eq!(
            error,
            DaemonCallError::DaemonError {
                code: DaemonErrorCode::DomainMismatch,
                message: "not for this site".into(),
            }
        );
    }

    #[test]
    fn a_malformed_reply_never_echoes_its_contents() {
        let (_dir, path, _server) = daemon(Some("{\"password\":\"hunter22\"\n"));
        let error = send(&path, status(), Duration::from_secs(5), None, None).unwrap_err();
        let DaemonCallError::InvalidResponse { reason } = error else {
            panic!("{error:?}");
        };
        assert!(!reason.contains("hunter22"), "{reason}");
    }

    #[test]
    fn an_overlong_reply_is_refused() {
        let long: &'static str =
            Box::leak(format!("{}\n", "x".repeat(MAX_AUTOFILL_LINE + 1)).into_boxed_str());
        let (_dir, path, _server) = daemon(Some(long));
        let error = send(&path, status(), Duration::from_secs(5), None, None).unwrap_err();
        assert!(
            matches!(error, DaemonCallError::InvalidResponse { .. }),
            "{error:?}"
        );
    }

    /// A reply longer than one read, the daemon hanging up right after it.
    #[test]
    fn a_long_reply_arrives_whole() {
        let password = |i| {
            format!(
                "{{\"domain\":\"site{i}.example\",\"username\":\"alex\",\"record_id\":\"r{i}\",\"rank\":{i}}}"
            )
        };
        let passwords: Vec<String> = (0..400).map(password).collect();
        let reply: &'static str = Box::leak(
            format!(
                "{{\"type\":\"ok\",\"reply\":{{\"reply\":\"autofill-identities\",\"identities_hash\":\"h\",\"passwords\":[{}],\"passkeys\":[],\"one_time_codes\":[]}}}}\n",
                passwords.join(",")
            )
            .into_boxed_str(),
        );
        assert!(reply.len() > 4 * 4096 && reply.len() < MAX_AUTOFILL_LINE);
        let (_dir, path, _server) = daemon(Some(reply));
        let command = AutofillCommand::AutofillIdentities;
        let reply = send(&path, command, Duration::from_secs(5), None, None).unwrap();
        let AutofillReply::AutofillIdentities(identities) = reply else {
            panic!("{reply:?}");
        };
        assert_eq!(identities.passwords.len(), 400);
        assert_eq!(identities.passwords[399].record_id, "r399");
    }

    #[test]
    fn no_daemon_is_unavailable() {
        let dir = tempfile::Builder::new()
            .prefix("dbffi")
            .tempdir_in("/tmp")
            .unwrap();
        let error = send(
            &dir.path().join("s"),
            status(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(error, DaemonCallError::DaemonUnavailable { .. }),
            "{error:?}"
        );
        let long = Path::new("/tmp").join("x".repeat(SUN_PATH_MAX));
        let error = send(&long, status(), Duration::from_secs(1), None, None).unwrap_err();
        assert!(
            matches!(error, DaemonCallError::DaemonUnavailable { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn a_silent_daemon_times_out() {
        let (_dir, path, _server) = daemon(None);
        let started = Instant::now();
        let error = send(&path, status(), Duration::from_millis(200), None, None).unwrap_err();
        assert_eq!(error, DaemonCallError::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// A cancel from another thread wakes the blocked read at once.
    #[test]
    fn cancelling_wakes_the_call_at_once() {
        let (_dir, path, server) = daemon(None);
        let handle = CallHandle::new();
        let canceller = {
            let handle = handle.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(100));
                handle.cancel();
            })
        };
        let started = Instant::now();
        let error = send(
            &path,
            status(),
            Duration::from_secs(10),
            Some(&handle),
            None,
        )
        .unwrap_err();
        assert_eq!(error, DaemonCallError::Cancelled);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        canceller.join().unwrap();
        // The daemon saw the hang-up.
        server.join().unwrap();
        assert!(handle.state().socket.is_none());

        // Cancelled before it starts, a call never connects.
        let error = send(&path, status(), Duration::from_secs(1), Some(&handle), None).unwrap_err();
        assert_eq!(error, DaemonCallError::Cancelled);
    }

    /// The passphrase goes only to a daemon whose code was checked, and
    /// never to code other than the binary named.
    #[test]
    fn the_passphrase_needs_a_checked_daemon() {
        let unlock = || AutofillCommand::Unlock {
            passphrase: "hunter22".into(),
        };
        let (_dir, path, _server) = daemon(None);
        let error = send(&path, unlock(), Duration::from_secs(1), None, None).unwrap_err();
        assert!(
            matches!(error, DaemonCallError::PeerRejected { .. }),
            "{error:?}"
        );

        // The listener here is this test binary, never `/usr/bin/true`.
        #[cfg(target_os = "macos")]
        {
            let (_dir, path, _server) = daemon(None);
            let error = send(
                &path,
                unlock(),
                Duration::from_secs(1),
                None,
                Some(Path::new("/usr/bin/true")),
            )
            .unwrap_err();
            assert!(
                matches!(error, DaemonCallError::PeerRejected { .. }),
                "{error:?}"
            );
        }
    }

    /// Whatever number Swift passes, the deadline neither panics nor waits
    /// past five minutes.
    #[test]
    fn any_timeout_is_a_bounded_deadline() {
        assert_eq!(timeout_of(1e12), MAX_TIMEOUT);
        assert_eq!(timeout_of(f64::INFINITY), MAX_TIMEOUT);
        assert_eq!(timeout_of(f64::MAX), MAX_TIMEOUT);
        assert_eq!(timeout_of(f64::NAN), MIN_TIMEOUT);
        assert_eq!(timeout_of(-1.0), MIN_TIMEOUT);
        assert_eq!(timeout_of(0.0), MIN_TIMEOUT);
        assert_eq!(timeout_of(2.5), Duration::from_millis(2500));

        let (_dir, path, _server) = daemon(Some(
            "{\"type\":\"ok\",\"reply\":{\"reply\":\"autofill-status\",\"initialized\":true,\"unlocked\":false,\"touch_id_ready\":true,\"touch_id_reset\":false,\"can_verify\":false}}\n",
        ));
        let socket = path.display().to_string();
        let outcome = autofill_call(socket, status(), 1e12, None, None);
        assert!(matches!(outcome, CallOutcome::Replied(_)), "{outcome:?}");
        let (_dir, path, _server) = daemon(None);
        let started = Instant::now();
        let outcome = autofill_call(path.display().to_string(), status(), f64::NAN, None, None);
        assert!(
            matches!(outcome, CallOutcome::Failed(DaemonCallError::TimedOut)),
            "{outcome:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        // A deadline past the clock's end is a timeout, not a panic.
        let error = send(&path, status(), Duration::MAX, None, None).unwrap_err();
        assert_eq!(error, DaemonCallError::TimedOut);
    }

    #[test]
    fn call_reports_failure_as_an_outcome() {
        let outcome = autofill_call("".into(), status(), 0.0, None, None);
        assert!(matches!(
            outcome,
            CallOutcome::Failed(DaemonCallError::DaemonUnavailable { .. })
        ));
        let outcome = autofill_call(
            "/tmp/x".into(),
            status(),
            f64::NAN,
            Some(CallHandle::new()),
            None,
        );
        assert!(matches!(outcome, CallOutcome::Failed(_)));
    }
}
