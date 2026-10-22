//! The CLI's side of `deadbolt-client`: this binary is the agent it starts,
//! and its build is the version it expects.

use anyhow::Result;
use deadbolt_client::{Error, Launch};

pub use deadbolt_client::{AgentError, simple, status, stop};

use crate::paths::Paths;
use crate::protocol::{Command, ErrorCode, Event, Reply, Status};

/// This binary's version. `DEADBOLT_TEST_VERSION` overrides it so tests can
/// run an agent that looks outdated.
pub fn version() -> String {
    std::env::var("DEADBOLT_TEST_VERSION")
        .unwrap_or_else(|_| concat!(env!("CARGO_PKG_VERSION"), "+", env!("DEADBOLT_BUILD")).into())
}

pub fn code(error: &anyhow::Error) -> Option<ErrorCode> {
    error
        .downcast_ref::<AgentError>()
        .map(|e| e.code)
        .or_else(|| error.downcast_ref::<Error>().and_then(Error::code))
}

/// Sends one request. `on_event` handles interactive events and returns the
/// answer to send back, if the event asks for one.
pub async fn call(
    paths: &Paths,
    command: Command,
    on_event: impl FnMut(Event) -> Result<Option<bool>>,
) -> Result<Reply> {
    Ok(deadbolt_client::call(paths, command, on_event).await?)
}

/// Starts the agent unless one of this version is running, replacing one of
/// another version.
pub async fn ensure_running(paths: &Paths) -> Result<Status> {
    let launch = Launch {
        program: std::env::current_exe()?,
        version: Some(version()),
    };
    Ok(deadbolt_client::ensure_running(paths, &launch).await?)
}
