//! The CLI's side of `deadbolt-client`: this binary is the daemon it starts.

use anyhow::Result;
use deadbolt_client::{Error, Launch};

pub use deadbolt_client::{DaemonError, running, simple, status, stop};

use crate::paths::Paths;
use crate::protocol::{Answer, Command, ErrorCode, Event, PROTOCOL_VERSION, Reply, Status};

/// This binary's version. `DEADBOLT_TEST_VERSION` overrides it in a debug
/// build so tests can run a daemon of another build.
pub fn version() -> String {
    crate::config::test_env("DEADBOLT_TEST_VERSION")
        .unwrap_or_else(|| concat!(env!("CARGO_PKG_VERSION"), "+", env!("DEADBOLT_BUILD")).into())
}

/// The protocol this binary's daemon speaks. `DEADBOLT_TEST_PROTOCOL`
/// overrides it in a debug build so tests can run a daemon that looks older
/// or newer.
pub fn protocol() -> u32 {
    crate::config::test_env("DEADBOLT_TEST_PROTOCOL")
        .and_then(|v| v.parse().ok())
        .unwrap_or(PROTOCOL_VERSION)
}

pub fn code(error: &anyhow::Error) -> Option<ErrorCode> {
    error
        .downcast_ref::<DaemonError>()
        .map(|e| e.code)
        .or_else(|| error.downcast_ref::<Error>().and_then(Error::code))
}

/// Sends one request. `on_event` handles interactive events and returns the
/// answer to send back, if the event asks for one.
pub async fn call(
    paths: &Paths,
    command: Command,
    on_event: impl FnMut(Event) -> Result<Option<Answer>>,
) -> Result<Reply> {
    Ok(deadbolt_client::call(paths, command, on_event).await?)
}

/// Starts this binary's daemon unless a compatible one is running (see
/// [`deadbolt_client::ensure_running`]).
pub async fn ensure_running(paths: &Paths) -> Result<Status> {
    let launch = Launch {
        program: std::env::current_exe()?,
    };
    Ok(deadbolt_client::ensure_running(paths, &launch).await?)
}
