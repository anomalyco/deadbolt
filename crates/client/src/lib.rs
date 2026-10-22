//! Talking to the agent: its control protocol, where its files live,
//! starting it on demand, replacing an agent of another version, and sending
//! requests. The CLI and the desktop app are both clients of this crate.

pub mod paths;
pub mod protocol;

use std::fmt;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command as Process, Stdio};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub use paths::Paths;
use protocol::{
    Answer, Command, ErrorCode, Event, Message, PROTOCOL_VERSION, Reply, Request, Status,
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
    #[error("creating {}", .0.display())]
    CreateDir(PathBuf, #[source] std::io::Error),
    #[error("opening {}", .0.display())]
    OpenLog(PathBuf, #[source] std::io::Error),
    #[error("starting the agent")]
    Spawn(#[source] std::io::Error),
    #[error("the agent did not start; see {}", .0.display())]
    NotStarted(PathBuf),
    #[error("the agent did not stop")]
    NotStopped,
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
    /// The build the client expects. A running agent of another build is
    /// replaced. `None` accepts any agent that speaks [`PROTOCOL_VERSION`].
    pub version: Option<String>,
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
    let stream = UnixStream::connect(&paths.socket)
        .await
        .map_err(Error::Connect)?;
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let mut body = serde_json::to_vec(&Request {
        v: PROTOCOL_VERSION,
        command,
    })
    .map_err(Error::Encode)?;
    body.push(b'\n');
    write.write_all(&body).await?;
    loop {
        let Some(line) = lines.next_line().await? else {
            return Err(Error::Closed);
        };
        match serde_json::from_str::<Message>(&line).map_err(Error::InvalidReply)? {
            Message::Event { event } => {
                if let Some(answer) = on_event(event).map_err(|e| Error::Event(e.into()))? {
                    let mut body = serde_json::to_vec(&Answer { answer }).map_err(Error::Encode)?;
                    body.push(b'\n');
                    write.write_all(&body).await?;
                }
            }
            Message::Ok { reply } => return Ok(reply),
            Message::Error { code, message } => return Err(AgentError { code, message }.into()),
        }
    }
}

/// Sends a request that expects no events.
pub async fn simple(paths: &Paths, command: Command) -> Result<Reply, Error> {
    call(paths, command, |event| Err(Error::UnexpectedEvent(event))).await
}

/// The running agent's status, or `None` when none is running.
pub async fn status(paths: &Paths) -> Option<Status> {
    match tokio::time::timeout(STATUS_TIMEOUT, simple(paths, Command::Status)).await {
        Ok(Ok(Reply::Status(status))) => Some(*status),
        _ => None,
    }
}

/// Starts the agent unless a suitable one is running (see [`Launch::version`]),
/// replacing one of another version.
pub async fn ensure_running(paths: &Paths, launch: &Launch) -> Result<Status, Error> {
    if let Some(status) = status(paths).await {
        let same_build = launch.version.as_ref().is_none_or(|v| *v == status.version);
        if same_build && status.protocol == PROTOCOL_VERSION {
            return Ok(status);
        }
        stop(paths).await?;
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
        .map_err(Error::Spawn)?;
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
    if status(paths).await.is_none() {
        return Ok(false);
    }
    simple(paths, Command::Stop).await?;
    for _ in 0..150 {
        if status(paths).await.is_none() && lock_free(paths) {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(Error::NotStopped)
}
