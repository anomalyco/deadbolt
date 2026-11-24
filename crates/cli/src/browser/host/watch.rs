//! Daemon status handshake and change-stream watcher for the native messaging host.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::protocol::{Body, Envelope, PROTOCOL, encode};
use crate::client;
use crate::paths::Paths;
use crate::protocol::Change;

/// How often to look for a daemon to watch while none runs.
pub(super) const RECONNECT: Duration = Duration::from_secs(2);

/// Starts the daemon if none runs, never unlocking it.
/// Also whether a daemon answered.
pub(super) async fn hello(paths: &Paths) -> (Body, bool) {
    let (status, detail) = match client::ensure_running(paths).await {
        Ok(status) if !status.initialized => (
            "not-set-up",
            Some("Set up Deadbolt to fill passwords: run `deadbolt init`".to_string()),
        ),
        Ok(status) if !status.unlocked => (
            "locked",
            Some("Unlock Deadbolt to fill passwords".to_string()),
        ),
        Ok(_) => ("ready", None),
        Err(error) => ("unavailable", Some(format!("{error:#}"))),
    };
    let body = Body::Hello {
        protocol: PROTOCOL,
        version: client::version(),
        status,
        detail,
        capabilities: [
            "list",
            "fill",
            "check",
            "save",
            "generate",
            "passkeys",
            "learn",
            "learn-files",
            "forms",
            "save-form",
        ],
    };
    (body, status != "unavailable")
}

/// What the extension hears of a change in the daemon, if anything.
pub(super) fn changed(change: &Change) -> Option<&'static str> {
    match change {
        Change::Locked => Some("locked"),
        Change::Unlocked => Some("unlocked"),
        Change::Items { .. } | Change::Vaults | Change::Resync => Some("items"),
        Change::Stopping => Some("stopped"),
        Change::Watching
        | Change::Devices { .. }
        | Change::Activity
        | Change::Health
        | Change::Update
        | Change::Activate { .. } => None,
    }
}

/// Pushes the daemon's changes. While no daemon runs it looks for one every
/// `reconnect`. A stream counts only once the daemon said it's watching: one
/// that refuses or hangs up first (a daemon of another protocol) is no
/// change. Says `started` on finding a daemon if `announce` is set.
pub(super) async fn watch(
    paths: Paths,
    frames: mpsc::Sender<Zeroizing<Vec<u8>>>,
    announce: Arc<AtomicBool>,
    reconnect: Duration,
) {
    let push = |change: &'static str| {
        let frames = frames.clone();
        async move {
            let envelope = Envelope {
                id: None,
                body: Body::Changed { change },
            };
            match encode(&envelope) {
                Ok(frame) => frames.send(frame).await.is_ok(),
                Err(_) => false,
            }
        }
    };
    loop {
        if let Ok(mut stream) = deadbolt_client::watch(&paths, false).await {
            let mut watching = false;
            let mut stopped = false;
            loop {
                match stream.next().await {
                    Ok(Some(Change::Watching)) => {
                        watching = true;
                        if announce.swap(false, Ordering::SeqCst) && !push("started").await {
                            return;
                        }
                    }
                    Ok(Some(change)) => {
                        stopped |= change == Change::Stopping;
                        if let Some(change) = changed(&change)
                            && !push(change).await
                        {
                            return;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            if watching {
                announce.store(true, Ordering::SeqCst);
                if !stopped && !push("stopped").await {
                    return;
                }
            }
        }
        tokio::time::sleep(reconnect).await;
    }
}
