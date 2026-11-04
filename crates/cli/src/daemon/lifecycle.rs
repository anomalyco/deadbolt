//! Running the daemon: the pid lock, the control socket, and the accept loop
//! that serves connections until a signal or a `Stop` request.

use std::fs::{self, File, TryLockError};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{info, warn};

use super::{
    AbortOnDrop, DRAIN_TIMEOUT, Daemon, biometric, legacy, macos_autofill, ssh_cleanup, system,
    updates,
};
use crate::client::version;
use crate::paths::Paths;
use crate::protocol::MAX_LINE;

/// Runs the daemon until it's stopped. `old_name`: an older build's update
/// started it as `deadbolt agent` and waits for it at the old socket
/// ([`legacy`]).
pub async fn serve(paths: Paths, old_name: bool) -> Result<()> {
    let runtime = paths.socket.parent().context("socket has no parent")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(runtime)
        .with_context(|| format!("creating {}", runtime.display()))?;
    // Only this user can reach the socket, from the moment it's bound.
    deadbolt_client::paths::secure_dir(runtime)
        .with_context(|| format!("checking {}", runtime.display()))?;
    let lock = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&paths.lock)
        .with_context(|| format!("opening {}", paths.lock.display()))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => bail!("the daemon is already running"),
        Err(TryLockError::Error(error)) => return Err(error).context("locking the daemon"),
    }
    legacy::stop(&paths).await;
    remove_socket(&paths.socket)?;
    let listener = UnixListener::bind(&paths.socket)
        .with_context(|| format!("binding {}", paths.socket.display()))?;
    fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600))?;
    let old_link = if old_name { legacy::link(&paths) } else { None };

    let env = crate::config::Environment::load();
    let local_net = env.local_net;
    let socket = paths.socket.clone();
    drop(
        tokio::time::timeout(
            Duration::from_millis(500),
            tokio::task::spawn_blocking(biometric::refresh_status),
        )
        .await,
    );
    ssh_cleanup::run(&paths);
    let daemon = Daemon::new(paths, local_net, env.kdf);
    let mut autofill = macos_autofill::bind_default().await;
    info!(
        pid = std::process::id(),
        version = %version(),
        local_net,
        autofill_socket = autofill.as_ref().map(|(_, p)| p.display().to_string()),
        "daemon started"
    );
    let (system, events) = mpsc::channel(8);
    let _sources = system::spawn(system);
    let _follow = AbortOnDrop(tokio::spawn(daemon.clone().follow_system(events)));
    let _updates = AbortOnDrop(tokio::spawn(updates::run(daemon.clone())));

    let mut connections = JoinSet::new();
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accepting control connection")?;
                let daemon = daemon.clone();
                connections.spawn(async move { daemon.handle(stream, MAX_LINE).await });
            }
            accepted = async {
                match autofill.as_ref() {
                    Some((autofill_listener, _)) => autofill_listener.accept().await,
                    None => std::future::pending().await,
                }
            } => {
                let (stream, _) = accepted.context("accepting macOS AutoFill connection")?;
                let daemon = daemon.clone();
                connections.spawn(async move {
                    daemon
                        .handle_on(
                            stream,
                            crate::protocol::MAX_AUTOFILL_LINE,
                            macos_autofill::SocketKind::AutoFill,
                        )
                        .await
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => report_connection(result),
            _ = daemon.shutdown.notified() => break,
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            _ = tick.tick() => daemon.check_idle().await,
        }
    }
    info!("daemon stopping");
    drop(listener);
    let autofill_socket = autofill.take().map(|(autofill_listener, path)| {
        drop(autofill_listener);
        path
    });
    daemon.cancel_biometric_prompt();
    daemon.interrupt_op();
    daemon.watchers.stopping();
    daemon.stop_sends().await;
    drain_connections(&mut connections).await;
    daemon.lock().await;
    if let Some(old_link) = old_link {
        drop(remove_socket(&old_link));
    }
    remove_socket(&socket)?;
    if let Some(autofill_socket) = autofill_socket {
        drop(remove_socket(&autofill_socket));
    }
    drop(lock);
    Ok(())
}

pub(crate) fn remove_socket(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("removing control socket"),
    }
}

fn report_connection(result: Result<Result<()>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!("control connection failed: {error:#}"),
        Err(error) => warn!("control connection task failed: {error}"),
    }
}

pub(super) async fn drain_connections(connections: &mut JoinSet<Result<()>>) {
    let drain = async {
        while let Some(result) = connections.join_next().await {
            report_connection(result);
        }
    };
    if tokio::time::timeout(DRAIN_TIMEOUT, drain).await.is_err() {
        warn!("control connections did not finish during shutdown; cancelling them");
        connections.shutdown().await;
    }
}
