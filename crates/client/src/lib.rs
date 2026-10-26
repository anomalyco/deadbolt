//! Talking to the agent: its control protocol, where its files live,
//! starting it on demand, replacing an agent of an older protocol, and sending
//! requests. The CLI and the desktop app are both clients of this crate.

pub mod export;
pub mod paths;
pub mod protocol;

use std::fmt;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command as Process, Stdio};
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use zeroize::Zeroizing;

pub use paths::Paths;
use protocol::{
    Answer, Change, Command, ErrorCode, Event, Message, PROTOCOL_VERSION, Reply, Request, Status,
};

const STATUS_TIMEOUT: Duration = Duration::from_secs(3);

/// An error reported by the agent.
#[derive(Debug)]
pub struct AgentError {
    pub code: ErrorCode,
    pub message: String,
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AgentError {}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Agent(#[from] AgentError),
    #[error("connecting to the agent")]
    Connect(#[source] std::io::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Encode(serde_json::Error),
    #[error("invalid reply from the agent")]
    InvalidReply(#[source] serde_json::Error),
    #[error("the agent closed the connection")]
    Closed,
    /// The caller's event handler failed.
    #[error(transparent)]
    Event(Box<dyn std::error::Error + Send + Sync>),
    #[error("unexpected event {0:?}")]
    UnexpectedEvent(Event),
    #[error("unexpected change {0:?}")]
    UnexpectedChange(Change),
    #[error("creating {}", .0.display())]
    CreateDir(PathBuf, #[source] std::io::Error),
    #[error("opening {}", .0.display())]
    OpenLog(PathBuf, #[source] std::io::Error),
    #[error("starting the agent from {}", .0.display())]
    Spawn(PathBuf, #[source] std::io::Error),
    #[error("the agent did not start; see {}", .0.display())]
    NotStarted(PathBuf),
    #[error("the agent did not stop")]
    NotStopped,
    #[error(
        "a newer Deadbolt agent is running ({}, version {}, pid {}): it speaks protocol {}, and this copy speaks {}. Update this copy of Deadbolt, or stop that agent with `deadbolt agent stop` and try again",
        .0.program.as_deref().unwrap_or("unknown program"),
        .0.version,
        .0.pid,
        .0.protocol,
        PROTOCOL_VERSION
    )]
    NewerAgent(Box<AgentId>),
    #[error(
        "a Deadbolt agent of another build is running ({}, version {}, pid {}): it says protocol {} but its status doesn't match this copy's. Stop it with `deadbolt agent stop` and try again",
        .0.program.as_deref().unwrap_or("unknown program"),
        .0.version,
        .0.pid,
        .0.protocol
    )]
    MismatchedAgent(Box<AgentId>),
}

/// The fields every protocol's status reply carries, so a client can tell
/// which agent is running even when the rest of its reply has another shape.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AgentId {
    pub pid: u32,
    pub version: String,
    pub protocol: u32,
    #[serde(default)]
    pub program: Option<String>,
}

impl Error {
    /// The agent's error code, when the agent refused the request.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Agent(error) => Some(error.code),
            _ => None,
        }
    }
}

/// How to start an agent when none is running.
#[derive(Debug, Clone)]
pub struct Launch {
    /// A `deadbolt` binary; the agent runs as `<program> agent`.
    pub program: PathBuf,
}

/// Sends one request. `on_event` handles interactive events and returns the
/// answer to send back, if the event asks for one.
pub async fn call<E>(
    paths: &Paths,
    command: Command,
    mut on_event: impl FnMut(Event) -> Result<Option<bool>, E>,
) -> Result<Reply, Error>
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    converse(paths, command, |event| std::future::ready(on_event(event))).await
}

/// [`call`] with an event handler that may take its time, such as one waiting
/// for a person to compare a confirmation code. If the agent finishes while
/// an answer is pending (the other device declined, the ticket expired), its
/// final message ends the call at once and the pending answer is dropped.
pub async fn converse<E, F>(
    paths: &Paths,
    command: Command,
    mut on_event: impl FnMut(Event) -> F,
) -> Result<Reply, Error>
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
    F: Future<Output = Result<Option<bool>, E>>,
{
    let stream = UnixStream::connect(&paths.socket)
        .await
        .map_err(Error::Connect)?;
    let (read, mut write) = stream.into_split();
    let mut lines = LineReader::new(BufReader::new(read));
    let body = encode_line(&Request {
        v: PROTOCOL_VERSION,
        command,
    })?;
    write.write_all(&body).await?;
    let mut queued = std::collections::VecDeque::new();
    loop {
        let message = match queued.pop_front() {
            Some(message) => message,
            None => read_message(&mut lines).await?,
        };
        match message {
            Message::Event { event } => {
                let answer = on_event(event);
                tokio::pin!(answer);
                // Events that arrive while one is being answered wait their turn.
                let answer = loop {
                    tokio::select! {
                        biased;
                        answer = &mut answer => break answer,
                        message = read_message(&mut lines) => match message? {
                            Message::Ok { reply } => return Ok(reply),
                            Message::Error { code, message } => {
                                return Err(AgentError { code, message }.into());
                            }
                            event => queued.push_back(event),
                        },
                    }
                };
                if let Some(answer) = answer.map_err(|e| Error::Event(e.into()))? {
                    write.write_all(&encode_line(&Answer { answer })?).await?;
                }
            }
            Message::Change { change } => return Err(Error::UnexpectedChange(change)),
            Message::Ok { reply } => return Ok(reply),
            Message::Error { code, message } => return Err(AgentError { code, message }.into()),
        }
    }
}

async fn read_message(lines: &mut LineReader<BufReader<OwnedReadHalf>>) -> Result<Message, Error> {
    let Some(line) = lines.next_line().await? else {
        return Err(Error::Closed);
    };
    serde_json::from_slice::<Message>(&line).map_err(Error::InvalidReply)
}

/// Reads the agent's lines, which carry values, into buffers that are wiped
/// on drop and grow without leaving copies behind (`export::append`).
struct LineReader<R> {
    reader: R,
    /// The line so far, kept across a cancelled read.
    line: Zeroizing<Vec<u8>>,
}

impl<R: AsyncBufRead + Unpin> LineReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            line: Zeroizing::new(Vec::new()),
        }
    }

    /// The next line without its `\n` (or `\r\n`), or `None` at the end.
    /// Cancel-safe.
    async fn next_line(&mut self) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
        loop {
            let available = self.reader.fill_buf().await?;
            if available.is_empty() {
                if self.line.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(std::mem::take(&mut self.line)));
            }
            let (end, used) = match available.iter().position(|b| *b == b'\n') {
                Some(at) => (Some(at), at + 1),
                None => (None, available.len()),
            };
            export::append(
                &mut self.line,
                &available[..end.unwrap_or(used)],
                usize::MAX,
            );
            self.reader.consume(used);
            if end.is_some() {
                if self.line.last() == Some(&b'\r') {
                    self.line.pop();
                }
                return Ok(Some(std::mem::take(&mut self.line)));
            }
        }
    }
}

/// `value` as one JSON line. Requests can carry a passphrase.
fn encode_line(value: &impl serde::Serialize) -> Result<Zeroizing<Vec<u8>>, Error> {
    encode_json(b"", value, b"\n").map_err(Error::Encode)
}

/// `value` as JSON between `before` and `after`, for messages that can
/// carry secrets: the buffer is sized up front, so no reallocation leaves a
/// copy behind, and wiped on drop.
pub fn encode_json(
    before: &[u8],
    value: &impl serde::Serialize,
    after: &[u8],
) -> serde_json::Result<Zeroizing<Vec<u8>>> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut len = Count(0);
    serde_json::to_writer(&mut len, value)?;
    let mut body = Zeroizing::new(Vec::with_capacity(before.len() + len.0 + after.len()));
    body.extend_from_slice(before);
    serde_json::to_writer(&mut *body, value)?;
    body.extend_from_slice(after);
    Ok(body)
}

/// Sends a request that expects no events.
pub async fn simple(paths: &Paths, command: Command) -> Result<Reply, Error> {
    call(paths, command, |event| Err(Error::UnexpectedEvent(event))).await
}

/// A live `watch` stream. Dropping it hangs up.
pub struct Watch {
    lines: LineReader<BufReader<OwnedReadHalf>>,
    /// Held open: the agent ends the stream when the client stops writing.
    _write: OwnedWriteHalf,
}

impl Watch {
    /// The next change, or `None` once the agent ended the stream (after
    /// [`Change::Stopping`]). Cancel-safe.
    pub async fn next(&mut self) -> Result<Option<Change>, Error> {
        let Some(line) = self.lines.next_line().await? else {
            return Err(Error::Closed);
        };
        match serde_json::from_slice::<Message>(&line).map_err(Error::InvalidReply)? {
            Message::Change { change } => Ok(Some(change)),
            Message::Ok { .. } => Ok(None),
            Message::Error { code, message } => Err(AgentError { code, message }.into()),
            Message::Event { event } => Err(Error::UnexpectedEvent(event)),
        }
    }
}

/// Subscribes to the running agent's changes. The first is
/// [`Change::Watching`]; fetch state after it so nothing is missed.
pub async fn watch(paths: &Paths) -> Result<Watch, Error> {
    let stream = UnixStream::connect(&paths.socket)
        .await
        .map_err(Error::Connect)?;
    let (read, mut write) = stream.into_split();
    let body = encode_line(&Request {
        v: PROTOCOL_VERSION,
        command: Command::Watch,
    })?;
    write.write_all(&body).await?;
    Ok(Watch {
        lines: LineReader::new(BufReader::new(read)),
        _write: write,
    })
}

/// The running agent's status, or `None` when none is running or it speaks
/// a protocol whose status this copy can't read.
pub async fn status(paths: &Paths) -> Option<Status> {
    probe(paths).await.and_then(|(_, status)| status)
}

/// Which agent is running, whatever its protocol, or `None` when none is.
pub async fn running(paths: &Paths) -> Option<AgentId> {
    probe(paths).await.map(|(agent, _)| agent)
}

/// Asks the running agent for its status once. Every agent answers `status`
/// whatever the request's protocol, but a status of another protocol may not
/// decode as ours, so its identity is read on its own.
async fn probe(paths: &Paths) -> Option<(AgentId, Option<Status>)> {
    #[derive(serde::Deserialize)]
    struct Head {
        reply: AgentId,
    }
    let line = tokio::time::timeout(STATUS_TIMEOUT, status_line(paths))
        .await
        .ok()?
        .ok()?;
    let agent = serde_json::from_str::<Head>(&line).ok()?.reply;
    let status = match serde_json::from_str::<Message>(&line) {
        Ok(Message::Ok {
            reply: Reply::Status(status),
        }) => Some(*status),
        _ => None,
    };
    Some((agent, status))
}

async fn status_line(paths: &Paths) -> Result<String, Error> {
    let stream = UnixStream::connect(&paths.socket)
        .await
        .map_err(Error::Connect)?;
    let (read, mut write) = stream.into_split();
    let body = encode_line(&Request {
        v: PROTOCOL_VERSION,
        command: Command::Status,
    })?;
    write.write_all(&body).await?;
    BufReader::new(read)
        .lines()
        .next_line()
        .await?
        .ok_or(Error::Closed)
}

/// Starts the agent unless one that speaks [`PROTOCOL_VERSION`] is running.
///
/// The app and the CLI share this rule, so two builds never take turns
/// replacing each other's agent:
///
/// - same protocol: reuse it, whatever its build
/// - older protocol: stop it, then start `launch.program`
/// - newer protocol: [`Error::NewerAgent`], leaving it running
///
/// A rebuilt agent of the same protocol is only picked up once the running
/// one stops (`deadbolt agent stop`).
pub async fn ensure_running(paths: &Paths, launch: &Launch) -> Result<Status, Error> {
    if let Some((agent, status)) = probe(paths).await {
        match agent.protocol.cmp(&PROTOCOL_VERSION) {
            std::cmp::Ordering::Equal => {
                return status.ok_or_else(|| Error::MismatchedAgent(Box::new(agent)));
            }
            std::cmp::Ordering::Greater => return Err(Error::NewerAgent(Box::new(agent))),
            std::cmp::Ordering::Less => {
                stop(paths).await?;
            }
        }
    }
    if let Some(dir) = paths.log.parent() {
        fs::create_dir_all(dir).map_err(|e| Error::CreateDir(dir.into(), e))?;
    }
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.log)
        .map_err(|e| Error::OpenLog(paths.log.clone(), e))?;
    Process::new(&launch.program)
        .arg("agent")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .process_group(0)
        .spawn()
        .map_err(|e| Error::Spawn(launch.program.clone(), e))?;
    for _ in 0..250 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if let Some(status) = status(paths).await {
            return Ok(status);
        }
    }
    Err(Error::NotStarted(paths.log.clone()))
}

/// True when no process holds the agent lock file.
fn lock_free(paths: &Paths) -> bool {
    match fs::File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&paths.lock)
    {
        Ok(file) => file.try_lock().is_ok(),
        Err(_) => false,
    }
}

/// Stops the agent. Returns whether one was running.
///
/// Waits until the lock file is really free before returning, so a new agent
/// started right after `stop` (e.g. `deadbolt agent stop && deadbolt unlock`)
/// doesn't fail with "the agent is already running" while the old process is
/// still releasing the lock.
pub async fn stop(paths: &Paths) -> Result<bool, Error> {
    if running(paths).await.is_none() {
        return Ok(false);
    }
    simple(paths, Command::Stop).await?;
    for _ in 0..150 {
        if running(paths).await.is_none() && lock_free(paths) {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(Error::NotStopped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::DeviceInfo;
    use std::sync::{Arc, Mutex};
    use tokio::net::UnixListener;

    /// Encoding never reallocates, which would leave a copy of a secret in
    /// freed memory.
    #[test]
    fn encoded_messages_fit_their_buffers_exactly() {
        let secret = "s".repeat(1000);
        for (before, after) in [(&b""[..], &b"\n"[..]), (&[7, 0, 0, 0][..], &b""[..])] {
            let body =
                encode_json(before, &serde_json::json!({"password": secret}), after).unwrap();
            assert_eq!(body.capacity(), body.len());
            assert!(body.starts_with(before) && body.ends_with(after));
            assert_eq!(body.len(), before.len() + 1015 + after.len());
        }
    }

    /// Reply lines land in wiped buffers, whole however the reads split them.
    #[test]
    fn reply_lines_are_read_into_wiped_buffers() {
        run(async {
            let bytes = b"{\"a\":1}\r\n{\"value\":\"hunter22\"}\npartial".as_slice();
            let mut lines = LineReader::new(BufReader::with_capacity(3, bytes));
            let mut read = Vec::new();
            loop {
                let line: Option<Zeroizing<Vec<u8>>> = lines.next_line().await.unwrap();
                let Some(line) = line else { break };
                read.push(String::from_utf8(line.to_vec()).unwrap());
            }
            assert_eq!(read, ["{\"a\":1}", "{\"value\":\"hunter22\"}", "partial"]);
        });
    }

    fn paths(dir: &std::path::Path) -> Paths {
        Paths {
            data: dir.join("data"),
            config: dir.join("config.toml"),
            socket: dir.join("agent.sock"),
            lock: dir.join("agent.lock"),
            log: dir.join("agent.log"),
        }
    }

    fn joining() -> Message {
        Message::Event {
            event: Event::Joining {
                code: "482913".into(),
                vault: "personal".into(),
                inviter: DeviceInfo {
                    id: "d1".into(),
                    name: Some("studio".into()),
                    this: false,
                    connected: true,
                    last_seen: None,
                },
            },
        }
    }

    /// A one-request agent: reads the request, sends `joining`, then runs `rest`.
    async fn agent<F, Fut>(listener: UnixListener, rest: F)
    where
        F: FnOnce(
            tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
            tokio::net::unix::OwnedWriteHalf,
        ) -> Fut,
        Fut: Future<Output = ()>,
    {
        let (stream, _) = listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        lines.next_line().await.unwrap().unwrap();
        write
            .write_all(&encode_line(&joining()).unwrap())
            .await
            .unwrap();
        rest(lines, write).await;
    }

    fn run(test: impl Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(test);
    }

    /// A running agent of `protocol` that answers `status` and `stop`, and
    /// records what it was asked. It goes away on `stop`, like a real one.
    /// Of another protocol, its status has another shape, as a real one's does.
    fn fake_agent(paths: &Paths, protocol: u32) -> Arc<Mutex<Vec<&'static str>>> {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let listener = UnixListener::bind(&paths.socket).unwrap();
        let socket = paths.socket.clone();
        let log = asked.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (read, mut write) = stream.into_split();
                let mut lines = BufReader::new(read).lines();
                let request: Request =
                    serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
                let reply = match request.command {
                    Command::Status => Reply::Status(Box::new(Status {
                        pid: 41,
                        version: "another-build".into(),
                        protocol,
                        program: Some("/opt/homebrew/bin/deadbolt".into()),
                        home: String::new(),
                        initialized: true,
                        unlocked: false,
                        locks_in_secs: None,
                        device: None,
                        vaults: vec![],
                        peers_online: 0,
                        peers: 0,
                        touch_id_available: false,
                        touch_id_enabled: false,
                        touch_id_ready: false,
                        touch_id_reset: false,
                    })),
                    Command::Stop => Reply::Done,
                    other => panic!("an agent of another build was sent {other:?}"),
                };
                let stopping = matches!(reply, Reply::Done);
                log.lock()
                    .unwrap()
                    .push(if stopping { "stop" } else { "status" });
                let reply = if stopping || protocol == PROTOCOL_VERSION {
                    encode_line(&Message::Ok { reply }).unwrap().to_vec()
                } else {
                    let mut line = serde_json::to_vec(&serde_json::json!({
                        "type": "ok",
                        "reply": {
                            "reply": "status",
                            "pid": 41,
                            "version": "another-build",
                            "protocol": protocol,
                            "program": "/opt/homebrew/bin/deadbolt",
                            "a-field-of-another-protocol": true,
                        },
                    }))
                    .unwrap();
                    line.push(b'\n');
                    line
                };
                write.write_all(&reply).await.unwrap();
                if stopping {
                    fs::remove_file(&socket).unwrap();
                    return;
                }
            }
        });
        asked
    }

    fn launch(dir: &std::path::Path) -> Launch {
        Launch {
            program: dir.join("our-deadbolt"),
        }
    }

    #[test]
    fn an_agent_of_the_same_protocol_is_reused_whatever_its_build() {
        run(async {
            let dir = tempfile::tempdir().unwrap();
            let paths = paths(dir.path());
            let asked = fake_agent(&paths, PROTOCOL_VERSION);
            let status = ensure_running(&paths, &launch(dir.path())).await.unwrap();
            assert_eq!((status.pid, status.version.as_str()), (41, "another-build"));
            // A second client of yet another build reuses it too: nobody replaces anybody.
            ensure_running(&paths, &launch(dir.path())).await.unwrap();
            assert_eq!(*asked.lock().unwrap(), ["status", "status"]);
        });
    }

    #[test]
    fn an_older_agent_is_stopped_before_ours_starts() {
        run(async {
            let dir = tempfile::tempdir().unwrap();
            let paths = paths(dir.path());
            let asked = fake_agent(&paths, PROTOCOL_VERSION - 1);
            let result = ensure_running(&paths, &launch(dir.path())).await;
            assert_eq!(*asked.lock().unwrap(), ["status", "status", "stop"]);
            // Then it starts our binary, which this test doesn't have.
            assert!(matches!(result, Err(Error::Spawn(..))), "{result:?}");
        });
    }

    #[test]
    fn a_newer_agent_is_left_running_and_named() {
        run(async {
            let dir = tempfile::tempdir().unwrap();
            let paths = paths(dir.path());
            let asked = fake_agent(&paths, PROTOCOL_VERSION + 1);
            let error = ensure_running(&paths, &launch(dir.path()))
                .await
                .unwrap_err();
            assert!(matches!(error, Error::NewerAgent(_)), "{error:?}");
            let message = error.to_string();
            for part in [
                "/opt/homebrew/bin/deadbolt",
                "another-build",
                "pid 41",
                "deadbolt agent stop",
            ] {
                assert!(message.contains(part), "{message}");
            }
            assert_eq!(*asked.lock().unwrap(), ["status"]);
        });
    }

    #[test]
    fn an_answer_goes_back_and_the_reply_ends_the_call() {
        run(async {
            let dir = tempfile::tempdir().unwrap();
            let paths = paths(dir.path());
            let listener = UnixListener::bind(&paths.socket).unwrap();
            let server = agent(listener, |mut lines, mut write| async move {
                let answer = lines.next_line().await.unwrap().unwrap();
                assert_eq!(answer, r#"{"answer":true}"#);
                let done = Message::Ok { reply: Reply::Done };
                write.write_all(&encode_line(&done).unwrap()).await.unwrap();
            });
            let client = converse(&paths, Command::Join { confirm: true }, |_| async {
                Ok::<_, std::convert::Infallible>(Some(true))
            });
            let (reply, ()) = tokio::join!(client, server);
            assert!(matches!(reply, Ok(Reply::Done)));
        });
    }

    #[test]
    fn the_agent_finishing_drops_a_pending_answer() {
        run(async {
            let dir = tempfile::tempdir().unwrap();
            let paths = paths(dir.path());
            let listener = UnixListener::bind(&paths.socket).unwrap();
            // The other device declines while this one is still looking at the code.
            let server = agent(listener, |_lines, mut write| async move {
                let declined = Message::Error {
                    code: ErrorCode::Failed,
                    message: "pairing confirmation code was not confirmed".into(),
                };
                write
                    .write_all(&encode_line(&declined).unwrap())
                    .await
                    .unwrap();
            });
            let client = converse(&paths, Command::Join { confirm: true }, |_| {
                std::future::pending::<Result<Option<bool>, std::convert::Infallible>>()
            });
            let (reply, ()) = tokio::join!(client, server);
            let error = reply.unwrap_err();
            assert_eq!(error.code(), Some(ErrorCode::Failed));
            assert!(error.to_string().contains("not confirmed"));
        });
    }
}
