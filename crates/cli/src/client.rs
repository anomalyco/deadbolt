//! Talking to the agent: starting it on demand, replacing an agent of another
//! version, and sending requests.

use std::fmt;
use std::fs;
use std::os::unix::process::CommandExt;
use std::process::{Command as Process, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::paths::Paths;
use crate::protocol::{
    Answer, Command, ErrorCode, Event, Message, PROTOCOL_VERSION, Reply, Request, Status,
};

const STATUS_TIMEOUT: Duration = Duration::from_secs(3);

/// This binary's version. `DEADBOLT_TEST_VERSION` overrides it so tests can
/// run an agent that looks outdated.
pub fn version() -> String {
    std::env::var("DEADBOLT_TEST_VERSION")
        .unwrap_or_else(|_| concat!(env!("CARGO_PKG_VERSION"), "+", env!("DEADBOLT_BUILD")).into())
}

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

pub fn code(error: &anyhow::Error) -> Option<ErrorCode> {
    error.downcast_ref::<AgentError>().map(|e| e.code)
}

/// Sends one request. `on_event` handles interactive events and returns the
/// answer to send back, if the event asks for one.
pub async fn call(
    paths: &Paths,
    command: Command,
    mut on_event: impl FnMut(Event) -> Result<Option<bool>>,
) -> Result<Reply> {
    let stream = UnixStream::connect(&paths.socket)
        .await
        .context("connecting to the agent")?;
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let mut body = serde_json::to_vec(&Request {
        v: PROTOCOL_VERSION,
        command,
    })?;
    body.push(b'\n');
    write.write_all(&body).await?;
    loop {
        let Some(line) = lines.next_line().await? else {
            bail!("the agent closed the connection");
        };
        match serde_json::from_str::<Message>(&line).context("invalid reply from the agent")? {
            Message::Event { event } => {
                if let Some(answer) = on_event(event)? {
                    let mut body = serde_json::to_vec(&Answer { answer })?;
                    body.push(b'\n');
                    write.write_all(&body).await?;
                }
            }
            Message::Ok { reply } => return Ok(reply),
            Message::Error { code, message } => return Err(AgentError { code, message }.into()),
        }
    }
}

pub async fn simple(paths: &Paths, command: Command) -> Result<Reply> {
    call(paths, command, |event| bail!("unexpected event {event:?}")).await
}

/// The running agent's status, or `None` when none is running.
pub async fn status(paths: &Paths) -> Option<Status> {
    match tokio::time::timeout(STATUS_TIMEOUT, simple(paths, Command::Status)).await {
        Ok(Ok(Reply::Status(status))) => Some(*status),
        _ => None,
    }
}

/// Starts the agent unless one of this version is running, replacing one of
/// another version.
pub async fn ensure_running(paths: &Paths) -> Result<Status> {
    if let Some(status) = status(paths).await {
        if status.version == version() && status.protocol == PROTOCOL_VERSION {
            return Ok(status);
        }
        stop(paths).await?;
    }
    if let Some(dir) = paths.log.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.log)
        .with_context(|| format!("opening {}", paths.log.display()))?;
    Process::new(std::env::current_exe()?)
        .arg("agent")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .process_group(0)
        .spawn()
        .context("starting the agent")?;
    for _ in 0..250 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if let Some(status) = status(paths).await {
            return Ok(status);
        }
    }
    bail!("the agent did not start; see {}", paths.log.display())
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
pub async fn stop(paths: &Paths) -> Result<bool> {
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
    bail!("the agent did not stop")
}
