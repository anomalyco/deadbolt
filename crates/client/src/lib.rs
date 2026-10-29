//! Talking to the agent: its control protocol, where its files live,
//! starting it on demand, replacing an agent of an older protocol, and sending
//! requests. The CLI and the desktop app are both clients of this crate.

pub mod export;
pub mod paths;
pub mod peer;
pub mod protocol;

use std::fmt;
use std::fs;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command as Process, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use zeroize::Zeroizing;

pub use paths::Paths;
use protocol::{
    Answer, Change, Claim, Command, ErrorCode, Event, MAX_LINE, Message, PROTOCOL_VERSION, Reply,
    Request, Status,
};

const STATUS_TIMEOUT: Duration = Duration::from_secs(3);

/// Checks who holds the other end of a connection (a duplicate of its
/// socket), before the client talks to it. `Err` says why not.
pub type AgentCheck = Box<dyn Fn(OwnedFd) -> Result<(), String> + Send + Sync>;

static AGENT_CHECK: OnceLock<AgentCheck> = OnceLock::new();
static CLAIM: OnceLock<Claim> = OnceLock::new();
/// The agent process that last passed the [`AgentCheck`], as the kernel
/// names it (on macOS its audit token, pid version included), so each
/// connection to it doesn't run the check again.
static CHECKED: Mutex<Option<peer::Peer>> = Mutex::new(None);

/// Sets how this client checks the agent, on every connection. Without
/// one, requests that carry a passphrase (`setup`, `unlock`) fail, and the
/// rest only check that the agent runs as this user. The first call wins.
pub fn set_agent_check(check: AgentCheck) {
    drop(AGENT_CHECK.set(check));
}

/// Sets what this client says about who drives it, sent with every request.
/// The agent shows it as claimed and never trusts it. The first call wins.
pub fn set_claim(claim: Claim) {
    if !claim.is_empty() {
        drop(CLAIM.set(claim));
    }
}

fn request(command: Command) -> Request {
    Request {
        v: PROTOCOL_VERSION,
        claimed: CLAIM.get().cloned(),
        command,
    }
}

/// Checks `stream`'s peer before anything goes to it: that it runs as this
/// user, then the [`AgentCheck`], unless that very process passed it
/// already. Without a check, `required` (a passphrase would follow) fails.
async fn check_agent(stream: &UnixStream, required: bool) -> Result<(), String> {
    let agent =
        peer::Peer::of(stream).map_err(|e| format!("reading the agent's credentials: {e}"))?;
    if agent.uid != rustix::process::getuid().as_raw() {
        return Err(format!(
            "the agent (pid {}) runs as another user",
            agent.pid
        ));
    }
    if *CHECKED.lock().unwrap_or_else(|e| e.into_inner()) == Some(agent) {
        return Ok(());
    }
    let Some(check) = AGENT_CHECK.get() else {
        return if required {
            Err("this client has no way to check the agent".into())
        } else {
            Ok(())
        };
    };
    let socket = stream
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| e.to_string())?;
    tokio::task::spawn_blocking(move || check(socket))
        .await
        .map_err(|e| e.to_string())??;
    *CHECKED.lock().unwrap_or_else(|e| e.into_inner()) = Some(agent);
    Ok(())
}

/// [`check_agent`] for `command`, as the error to report. `stop` goes to
/// whatever holds the socket: it sends nothing and asks nothing back, and it
/// is how an agent that fails the check is stopped.
async fn check_for(stream: &UnixStream, command: &Command) -> Result<(), Error> {
    if matches!(command, Command::Stop) {
        return Ok(());
    }
    let passphrase = command.carries_passphrase();
    check_agent(stream, passphrase).await.map_err(|why| {
        if passphrase {
            Error::UncheckedAgent(why)
        } else {
            Error::UnverifiedAgent(why)
        }
    })
}

/// An error reported by the agent.
#[derive(Debug)]
pub struct AgentError {
    pub code: ErrorCode,
    pub message: String,
    /// With `not-granted`: what the user would have to allow.
    pub grant: Option<protocol::NotGranted>,
    /// With `choose-passkey`: the passkeys to choose from.
    pub passkeys: Option<Vec<protocol::AgentPasskey>>,
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
    /// The agent failed the [`AgentCheck`], so the passphrase wasn't sent.
    #[error("not sending the passphrase: {0}")]
    UncheckedAgent(String),
    /// The agent failed the [`AgentCheck`], so nothing was sent to it.
    #[error("not talking to the agent: {0}")]
    UnverifiedAgent(String),
    /// A line from the agent was longer than the protocol allows.
    #[error("the agent sent a line longer than {MAX_LINE} bytes")]
    LineTooLong,
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
    mut on_event: impl FnMut(Event) -> Result<Option<Answer>, E>,
) -> Result<Reply, Error>
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    converse(paths, command, |event| std::future::ready(on_event(event))).await
}

/// [`call`] with an event handler that may take its time, such as one waiting
/// for a person to choose a passphrase. If the agent finishes while an answer
/// is pending, its final message ends the call at once and the pending answer
/// is dropped.
pub async fn converse<E, F>(
    paths: &Paths,
    command: Command,
    mut on_event: impl FnMut(Event) -> F,
) -> Result<Reply, Error>
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
    F: Future<Output = Result<Option<Answer>, E>>,
{
    let stream = UnixStream::connect(&paths.socket)
        .await
        .map_err(Error::Connect)?;
    check_for(&stream, &command).await?;
    let (read, mut write) = stream.into_split();
    let mut lines = LineReader::new(BufReader::new(read));
    let body = encode_line(&request(command))?;
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
                            Message::Error { code, message, grant, passkeys } => {
                                return Err(AgentError { code, message, grant, passkeys }.into());
                            }
                            event => queued.push_back(event),
                        },
                    }
                };
                if let Some(answer) = answer.map_err(|e| Error::Event(e.into()))? {
                    write.write_all(&encode_line(&answer)?).await?;
                }
            }
            Message::Change { change } => return Err(Error::UnexpectedChange(change)),
            Message::Ok { reply } => return Ok(reply),
            Message::Error {
                code,
                message,
                grant,
                passkeys,
            } => {
                return Err(AgentError {
                    code,
                    message,
                    grant,
                    passkeys,
                }
                .into());
            }
        }
    }
}

async fn read_message(lines: &mut LineReader<BufReader<OwnedReadHalf>>) -> Result<Message, Error> {
    let Some(line) = lines.line().await? else {
        return Err(Error::Closed);
    };
    serde_json::from_slice::<Message>(&line).map_err(Error::InvalidReply)
}

/// A line past [`LineReader`]'s limit.
#[derive(Debug, thiserror::Error)]
#[error("line too long")]
struct TooLong;

/// Reads the agent's lines, which carry values, into buffers that are wiped
/// on drop and grow without leaving copies behind (`export::append`), up to
/// [`MAX_LINE`] bytes each.
struct LineReader<R> {
    reader: R,
    /// The line so far, kept across a cancelled read.
    line: Zeroizing<Vec<u8>>,
    max: usize,
}

impl<R: AsyncBufRead + Unpin> LineReader<R> {
    fn new(reader: R) -> Self {
        Self::with_max(reader, MAX_LINE)
    }

    fn with_max(reader: R, max: usize) -> Self {
        Self {
            reader,
            line: Zeroizing::new(Vec::new()),
            max,
        }
    }

    /// The next line without its `\n` (or `\r\n`), or `None` at the end.
    /// A line longer than the limit is an [`io::ErrorKind::InvalidData`]
    /// error. Cancel-safe.
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
            let bytes = &available[..end.unwrap_or(used)];
            // Room for a `\r` before the `\n`, dropped below.
            if self.line.len() + bytes.len() > self.max + 1 {
                self.line = Zeroizing::new(Vec::new());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    TooLong,
                ));
            }
            export::append(&mut self.line, bytes, self.max + 1);
            self.reader.consume(used);
            if end.is_some() {
                if self.line.last() == Some(&b'\r') {
                    self.line.pop();
                }
                if self.line.len() > self.max {
                    self.line = Zeroizing::new(Vec::new());
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        TooLong,
                    ));
                }
                return Ok(Some(std::mem::take(&mut self.line)));
            }
        }
    }

    /// [`LineReader::next_line`], with a line too long as
    /// [`Error::LineTooLong`].
    async fn line(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        self.next_line().await.map_err(|error| {
            if error.get_ref().is_some_and(|e| e.is::<TooLong>()) {
                Error::LineTooLong
            } else {
                Error::Io(error)
            }
        })
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
        let Some(line) = self.lines.line().await? else {
            return Err(Error::Closed);
        };
        match serde_json::from_slice::<Message>(&line).map_err(Error::InvalidReply)? {
            Message::Change { change } => Ok(Some(change)),
            Message::Ok { .. } => Ok(None),
            Message::Error {
                code,
                message,
                grant,
                passkeys,
            } => Err(AgentError {
                code,
                message,
                grant,
                passkeys,
            }
            .into()),
            Message::Event { event } => Err(Error::UnexpectedEvent(event)),
        }
    }
}

/// Subscribes to the running agent's changes. The first is
/// [`Change::Watching`]; fetch state after it so nothing is missed. `app`
/// marks the desktop app's main window, which alone gets
/// [`Change::Activate`].
pub async fn watch(paths: &Paths, app: bool) -> Result<Watch, Error> {
    let stream = UnixStream::connect(&paths.socket)
        .await
        .map_err(Error::Connect)?;
    let command = Command::Watch { app };
    check_for(&stream, &command).await?;
    let (read, mut write) = stream.into_split();
    let body = encode_line(&request(command))?;
    write.write_all(&body).await?;
    Ok(Watch {
        lines: LineReader::new(BufReader::new(read)),
        _write: write,
    })
}

/// The running agent's status, or `None` when none is running, it fails
/// this client's [`AgentCheck`], or it speaks a protocol whose status this
/// copy can't read.
pub async fn status(paths: &Paths) -> Option<Status> {
    let probe = probe(paths).await?;
    probe.checked.ok().and(probe.status)
}

/// Which agent is running, whatever its protocol, or `None` when none is.
/// What it says isn't checked: this only names it.
pub async fn running(paths: &Paths) -> Option<AgentId> {
    probe(paths).await.map(|probe| probe.agent)
}

/// What one `status` asked of the running agent found.
struct Probe {
    agent: AgentId,
    status: Option<Status>,
    /// Whether it passed this client's [`AgentCheck`], and if not, why.
    checked: Result<(), String>,
}

/// Asks the running agent for its status once. Every agent answers `status`
/// whatever the request's protocol, but a status of another protocol may not
/// decode as ours, so its identity is read on its own.
async fn probe(paths: &Paths) -> Option<Probe> {
    #[derive(serde::Deserialize)]
    struct Head {
        reply: AgentId,
    }
    let (line, checked) = tokio::time::timeout(STATUS_TIMEOUT, status_line(paths))
        .await
        .ok()?
        .ok()?;
    let agent = serde_json::from_slice::<Head>(&line).ok()?.reply;
    let status = match serde_json::from_slice::<Message>(&line) {
        Ok(Message::Ok {
            reply: Reply::Status(status),
        }) => Some(*status),
        _ => None,
    };
    Some(Probe {
        agent,
        status,
        checked,
    })
}

async fn status_line(paths: &Paths) -> Result<(Zeroizing<Vec<u8>>, Result<(), String>), Error> {
    let stream = UnixStream::connect(&paths.socket)
        .await
        .map_err(Error::Connect)?;
    // A status carries nothing secret either way, and naming an agent that
    // fails the check is how a client says which one to stop.
    let checked = check_agent(&stream, false).await;
    let (read, mut write) = stream.into_split();
    let body = encode_line(&request(Command::Status))?;
    write.write_all(&body).await?;
    let line = LineReader::new(BufReader::new(read))
        .line()
        .await?
        .ok_or(Error::Closed)?;
    Ok((line, checked))
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
    if let Some(Probe {
        agent,
        status,
        checked,
    }) = probe(paths).await
    {
        match agent.protocol.cmp(&PROTOCOL_VERSION) {
            std::cmp::Ordering::Equal => {
                checked.map_err(Error::UnverifiedAgent)?;
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

    /// A request for the fake agents below. Not `join`, which carries a
    /// passphrase and so needs an agent check these tests don't install.
    fn join() -> Command {
        Command::Pair {
            code: "violin-garden-tiger-lamp".into(),
            vault: None,
        }
    }

    fn joining() -> Message {
        Message::Event {
            event: Event::Joined {
                vault: "personal".into(),
                inviter: DeviceInfo {
                    id: "d1".into(),
                    name: Some("studio".into()),
                    this: false,
                    connected: true,
                    last_seen: None,
                },
                passphrase: true,
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

    fn status_of(protocol: u32) -> Status {
        Status {
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
            caller: protocol::CallerInfo::unverified("test"),
        }
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
                    Command::Status => Reply::Status(Box::new(status_of(protocol))),
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
                assert_eq!(answer, r#"{"answer":true,"passphrase":"hunter2"}"#);
                let done = Message::Ok { reply: Reply::Done };
                write.write_all(&encode_line(&done).unwrap()).await.unwrap();
            });
            let client = converse(&paths, join(), |_| async {
                Ok::<_, std::convert::Infallible>(Some(Answer::passphrase(protocol::Secret::new(
                    "hunter2",
                ))))
            });
            let (reply, ()) = tokio::join!(client, server);
            assert!(matches!(reply, Ok(Reply::Done)));
        });
    }

    /// The process an impostor test runs in, re-run from this test binary:
    /// it holds the socket at `DEADBOLT_TEST_IMPOSTOR`, answers every line
    /// with a status of this protocol, and appends what it was sent to
    /// `<socket>.sent`.
    #[test]
    #[ignore = "run by every_connection_waits_for_the_agent_check"]
    fn impostor() {
        let Some(socket) = std::env::var_os("DEADBOLT_TEST_IMPOSTOR") else {
            return;
        };
        let socket = PathBuf::from(socket);
        let sent = socket.with_extension("sent");
        run(async move {
            let listener = UnixListener::bind(&socket).unwrap();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let sent = sent.clone();
                tokio::spawn(async move {
                    let (read, mut write) = stream.into_split();
                    let mut lines = BufReader::new(read).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let mut log = fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&sent)
                            .unwrap();
                        std::io::Write::write_all(&mut log, format!("{line}\n").as_bytes())
                            .unwrap();
                        let reply = Message::Ok {
                            reply: Reply::Status(Box::new(status_of(PROTOCOL_VERSION))),
                        };
                        if write
                            .write_all(&encode_line(&reply).unwrap())
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });
    }

    /// Every connection waits for the client's check, which sees the very
    /// connection the request would travel on, and runs once per agent
    /// process. Something else holding the socket gets nothing: not a
    /// passphrase, not a request, not a watcher, and its status isn't taken.
    #[test]
    fn every_connection_waits_for_the_agent_check() {
        // The sockets each check was for. The other tests' connections are
        // checked too, concurrently, so only this test's socket is counted.
        static CHECKS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
        run(async {
            let dir = tempfile::tempdir().unwrap();
            let paths = paths(dir.path());
            let listener = UnixListener::bind(&paths.socket).unwrap();
            let unlock = || Command::Unlock {
                passphrase: Zeroizing::new("hunter22".into()),
                timeout_secs: None,
            };
            // No check set yet: nothing is sent.
            let refused = tokio::join!(simple(&paths, unlock()), async {
                let (stream, _) = listener.accept().await.unwrap();
                let mut line = String::new();
                BufReader::new(stream).read_line(&mut line).await.unwrap();
                line
            });
            assert!(
                matches!(refused.0, Err(Error::UncheckedAgent(_))),
                "{:?}",
                refused.0
            );
            assert_eq!(refused.1, "");
            drop(listener);
            fs::remove_file(&paths.socket).unwrap();

            // The other tests' agents run in this process, and pass.
            set_agent_check(Box::new(|socket| {
                let socket = std::os::unix::net::UnixStream::from(socket);
                if let Some(path) = socket
                    .peer_addr()
                    .ok()
                    .and_then(|a| a.as_pathname().map(Into::into))
                {
                    CHECKS.lock().unwrap().push(path);
                }
                let agent = peer::Peer::of(&socket).map_err(|e| e.to_string())?;
                if agent.pid == std::process::id() {
                    Ok(())
                } else {
                    Err(format!("pid {} is an impostor", agent.pid))
                }
            }));

            let impostor = Paths {
                socket: dir.path().join("impostor.sock"),
                ..paths.clone()
            };
            struct Killed(std::process::Child);
            impl Drop for Killed {
                fn drop(&mut self) {
                    drop(self.0.kill());
                    drop(self.0.wait());
                }
            }
            let child = Killed(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "tests::impostor",
                        "--ignored",
                        "--test-threads=1",
                    ])
                    .env("DEADBOLT_TEST_IMPOSTOR", &impostor.socket)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            // Its socket file appears at `bind`, before it listens: wait
            // until it takes a connection. Sending nothing, this one isn't
            // in what it was sent.
            for _ in 0..500 {
                if UnixStream::connect(&impostor.socket).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let impostor_said = |error: Error| {
                let message = error.to_string();
                assert!(message.contains("is an impostor"), "{message}");
                error
            };
            let error = impostor_said(simple(&impostor, unlock()).await.unwrap_err());
            assert!(matches!(error, Error::UncheckedAgent(_)), "{error:?}");
            let error = impostor_said(simple(&impostor, Command::VaultList).await.unwrap_err());
            assert!(matches!(error, Error::UnverifiedAgent(_)), "{error:?}");
            let Err(error) = watch(&impostor, true).await else {
                panic!("an impostor's watch was taken");
            };
            assert!(matches!(impostor_said(error), Error::UnverifiedAgent(_)));
            assert!(status(&impostor).await.is_none());
            assert_eq!(running(&impostor).await.map(|a| a.pid), Some(41));
            let error = ensure_running(&impostor, &launch(dir.path()))
                .await
                .unwrap_err();
            assert!(matches!(impostor_said(error), Error::UnverifiedAgent(_)));
            let sent = fs::read_to_string(impostor.socket.with_extension("sent")).unwrap();
            assert!(!sent.is_empty());
            for line in sent.lines() {
                let request: Request = serde_json::from_str(line).unwrap();
                assert!(matches!(request.command, Command::Status), "{line}");
            }
            drop(child);

            // An agent that passes is checked once, however often it's asked.
            fake_agent(&paths, PROTOCOL_VERSION);
            for _ in 0..5 {
                assert!(status(&paths).await.is_some());
            }
            let checks = CHECKS.lock().unwrap();
            assert!(checks.iter().filter(|p| **p == paths.socket).count() <= 1);
        });
    }

    /// A reply line longer than the protocol allows ends the read.
    #[test]
    fn reply_lines_are_capped() {
        run(async {
            let bytes = b"0123456789\nabc\r\n0123456789a\n".as_slice();
            let mut lines = LineReader::with_max(BufReader::with_capacity(4, bytes), 10);
            assert_eq!(&**lines.next_line().await.unwrap().unwrap(), b"0123456789");
            assert_eq!(&**lines.next_line().await.unwrap().unwrap(), b"abc");
            assert!(matches!(lines.line().await, Err(Error::LineTooLong)));
        });
    }

    #[test]
    fn the_agent_finishing_drops_a_pending_answer() {
        run(async {
            let dir = tempfile::tempdir().unwrap();
            let paths = paths(dir.path());
            let listener = UnixListener::bind(&paths.socket).unwrap();
            // The agent gives up while this one is still asking for the passphrase.
            let server = agent(listener, |_lines, mut write| async move {
                let declined = Message::Error {
                    code: ErrorCode::Failed,
                    message: "the agent stopped".into(),
                    grant: None,
                    passkeys: None,
                };
                write
                    .write_all(&encode_line(&declined).unwrap())
                    .await
                    .unwrap();
            });
            let client = converse(&paths, join(), |_| {
                std::future::pending::<Result<Option<Answer>, std::convert::Infallible>>()
            });
            let (reply, ()) = tokio::join!(client, server);
            let error = reply.unwrap_err();
            assert_eq!(error.code(), Some(ErrorCode::Failed));
            assert!(error.to_string().contains("stopped"));
        });
    }
}
