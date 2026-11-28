//! Daemon status handshake and change-stream watcher for the native messaging host.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use zeroize::Zeroizing;

use deadbolt_proto::browser::{CAPABILITIES, Change, HostStatus, PROTOCOL};

use super::protocol::{Body, Envelope, encode};
use crate::client;
use crate::paths::Paths;
use crate::protocol::Change as DaemonChange;

/// How often to look for a daemon to watch while none runs.
pub(super) const RECONNECT: Duration = Duration::from_secs(2);

/// Starts the daemon if none runs, never unlocking it.
/// Also whether a daemon answered.
pub(super) async fn hello(paths: &Paths) -> (Body, bool) {
    let mut touch_id_ready = false;
    let (status, detail) = match client::ensure_running(paths).await {
        Ok(status) if !status.initialized => (
            HostStatus::NotSetUp,
            Some("Set up Deadbolt to fill passwords: run `deadbolt init`".to_string()),
        ),
        Ok(status) if !status.unlocked => {
            touch_id_ready = status.touch_id_ready;
            (
                HostStatus::Locked,
                Some("Unlock Deadbolt to fill passwords".to_string()),
            )
        }
        Ok(_) => (HostStatus::Ready, None),
        Err(error) => (HostStatus::Unavailable, Some(format!("{error:#}"))),
    };
    let body = Body::Hello {
        protocol: PROTOCOL,
        version: client::version(),
        status,
        detail,
        capabilities: CAPABILITIES.map(String::from).to_vec(),
        touch_id_ready,
    };
    (body, status != HostStatus::Unavailable)
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
    let push = |change: Change| {
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
                    Ok(Some(DaemonChange::Watching)) => {
                        watching = true;
                        if announce.swap(false, Ordering::SeqCst) && !push(Change::Started).await {
                            return;
                        }
                    }
                    Ok(Some(change)) => {
                        stopped |= change == DaemonChange::Stopping;
                        if let Some(change) = Change::of(&change)
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
                if !stopped && !push(Change::Stopped).await {
                    return;
                }
            }
        }
        tokio::time::sleep(reconnect).await;
    }
}
