//! `watch` through the daemon: what a watcher sees, that a stuck watcher
//! can't hold the daemon up, locking on system events, and `app-activate`
//! reaching the app's watcher.

use std::sync::Arc;
use std::time::Duration;

use deadbolt_core::{DeviceSecret, Field, FieldType, VaultId};
use deadbolt_net::SyncHandler;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedReadHalf;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use super::session::Changes;
use super::system::SystemEvent;
use super::tests::test_paths;
use super::{Daemon, MAX_LINE, items, sync, watchers};
use crate::protocol::{Change, Command, FieldInput, Message, PROTOCOL_VERSION, Reply, Request};

const KDF: deadbolt_store::KdfParams = deadbolt_store::KdfParams {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};
/// Long enough for any real change to arrive; quiet after that means none came.
const QUIET: Duration = Duration::from_millis(300);
const STEP: Duration = Duration::from_secs(10);

fn daemon(dir: &std::path::Path) -> Arc<Daemon> {
    Daemon::new(test_paths(dir), true, KDF)
}

fn passphrase() -> Zeroizing<String> {
    Zeroizing::new("test".into())
}

fn request(command: Command) -> Vec<u8> {
    let mut line = serde_json::to_vec(&Request {
        v: PROTOCOL_VERSION,
        claimed: None,
        command,
    })
    .unwrap();
    line.push(b'\n');
    line
}

type Watcher = (
    Lines<BufReader<OwnedReadHalf>>,
    tokio::net::unix::OwnedWriteHalf,
);

/// Subscribes over a socket pair, returning the watcher's lines.
async fn subscribe(daemon: &Arc<Daemon>, connections: &mut JoinSet<anyhow::Result<()>>) -> Watcher {
    watch_as(daemon, connections, false).await
}

/// Subscribes as the app's main window (`app`) or another watcher.
async fn watch_as(
    daemon: &Arc<Daemon>,
    connections: &mut JoinSet<anyhow::Result<()>>,
    app: bool,
) -> Watcher {
    let (server, client) = UnixStream::pair().unwrap();
    connections.spawn(daemon.clone().handle(server, MAX_LINE));
    let (read, mut write) = client.into_split();
    write
        .write_all(&request(Command::Watch { app }))
        .await
        .unwrap();
    let mut lines = BufReader::new(read).lines();
    assert_eq!(next(&mut lines).await, Some(Change::Watching));
    (lines, write)
}

/// The next change, or `None` for the final reply.
async fn next(lines: &mut Lines<BufReader<OwnedReadHalf>>) -> Option<Change> {
    let line = tokio::time::timeout(STEP, lines.next_line())
        .await
        .expect("a change in time")
        .unwrap()
        .expect("the stream is open");
    match serde_json::from_str::<Message>(&line).unwrap() {
        Message::Change { change } => Some(change),
        Message::Ok { reply: Reply::Done } => None,
        other => panic!("unexpected {other:?}"),
    }
}

async fn changes(lines: &mut Lines<BufReader<OwnedReadHalf>>, n: usize) -> Vec<Change> {
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(next(lines).await.expect("a change"));
    }
    out
}

async fn quiet(lines: &mut Lines<BufReader<OwnedReadHalf>>) {
    if let Ok(line) = tokio::time::timeout(QUIET, lines.next_line()).await {
        panic!("expected no change, got {line:?}");
    }
}

fn items_in(vault: VaultId) -> Change {
    Change::Items {
        vault: vault.to_string(),
    }
}

fn devices_in(vault: VaultId) -> Change {
    Change::Devices {
        vault: vault.to_string(),
    }
}

#[tokio::test]
async fn a_watcher_sees_lock_state_local_writes_and_one_change_per_sync_batch() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = daemon(dir.path());
    let mut connections = JoinSet::new();
    let (mut lines, _write) = subscribe(&daemon, &mut connections).await;

    daemon.setup(passphrase(), "device".into()).await.unwrap();
    assert_eq!(next(&mut lines).await, Some(Change::Unlocked));
    daemon.lock().await;
    assert_eq!(next(&mut lines).await, Some(Change::Locked));
    daemon.unlock(passphrase(), None).await.unwrap();
    assert_eq!(next(&mut lines).await, Some(Change::Unlocked));
    quiet(&mut lines).await;

    let vault = daemon.with(|s| s.create_vault("personal")).unwrap();
    assert_eq!(
        changes(&mut lines, 3).await,
        [Change::Vaults, devices_in(vault), items_in(vault)]
    );
    let fields = vec![FieldInput {
        name: "password".into(),
        kind: None,
        value: "local".into(),
    }];
    daemon
        .with(|s| items::create(s, None, "login", Some("mine".into()), fields))
        .unwrap();
    assert_eq!(next(&mut lines).await, Some(items_in(vault)));
    quiet(&mut lines).await;

    // Another member writes three items; they arrive in one sync batch.
    let other = DeviceSecret::from_bytes(&[52; 32]);
    daemon
        .with(|s| {
            s.update(vault, |v, key| {
                Ok(v.add(
                    key,
                    other.device_id(),
                    other.join_consent(&vault, &key.device_id()),
                )?)
            })
        })
        .unwrap();
    assert_eq!(
        changes(&mut lines, 2).await,
        [Change::Vaults, devices_in(vault)]
    );
    let mut theirs = daemon.with(|s| Ok(s.vault(&vault).clone())).unwrap();
    let batch: Vec<deadbolt_net::Blob> = (0..3)
        .map(|n| {
            let field = Field::new(FieldType::Secret, format!("theirs-{n}"));
            let (_, entry) = theirs
                .create_item(&other, "login", None, [("password".into(), field)])
                .unwrap();
            entry.encode()
        })
        .collect();
    daemon.ready.send_replace(true);
    sync::Handler(daemon.clone())
        .receive(*other.device_id().as_bytes(), batch, &mut false, true)
        .await
        .unwrap();
    assert_eq!(
        daemon.with(|s| Ok(s.vault(&vault).items().len())).unwrap(),
        4
    );
    assert_eq!(next(&mut lines).await, Some(items_in(vault)));
    quiet(&mut lines).await;

    // Stopping ends the stream with a final reply.
    daemon.watchers.stopping();
    assert_eq!(next(&mut lines).await, Some(Change::Stopping));
    assert_eq!(next(&mut lines).await, None);
    assert_eq!(lines.next_line().await.unwrap(), None);
    connections.join_next().await.unwrap().unwrap().unwrap();
    assert_eq!(daemon.watchers.len(), 0);
    daemon.lock().await;
}

#[tokio::test]
async fn hanging_up_ends_a_watch_quietly() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = daemon(dir.path());
    let mut connections = JoinSet::new();
    let (lines, write) = subscribe(&daemon, &mut connections).await;
    assert_eq!(daemon.watchers.len(), 1);
    drop((lines, write));
    tokio::time::timeout(STEP, connections.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(daemon.watchers.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_watcher_that_stops_reading_cannot_stall_the_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = daemon(dir.path());
    let (server, mut client) = UnixStream::pair().unwrap();
    client
        .write_all(&request(Command::Watch { app: false }))
        .await
        .unwrap();
    // Fill the daemon's side of the socket: the client never reads.
    server.writable().await.unwrap();
    loop {
        match server.try_write(&[0; 8192]) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("{error}"),
        }
    }
    let mut connections = JoinSet::new();
    connections.spawn(daemon.clone().handle(server, MAX_LINE));
    while daemon.watchers.len() == 0 {
        tokio::task::yield_now().await;
    }

    let start = tokio::time::Instant::now();
    for n in 0..10_000u32 {
        let mut id = [0; 32];
        id[..4].copy_from_slice(&n.to_le_bytes());
        daemon.watchers.changed(&Changes {
            items: [VaultId::from_bytes(id)].into(),
            ..Changes::default()
        });
        daemon.watchers.locked();
        daemon.watchers.unlocked();
    }
    daemon.lock().await;
    assert_eq!(start.elapsed(), Duration::ZERO, "publishing never waits");

    let result = tokio::time::timeout(watchers::SEND_TIMEOUT * 2, connections.join_next())
        .await
        .expect("the stuck watcher is dropped")
        .unwrap()
        .unwrap();
    assert!(result.is_err());
    assert!(start.elapsed() >= watchers::SEND_TIMEOUT);
    assert_eq!(daemon.watchers.len(), 0);
    drop(client);
}

#[tokio::test]
async fn system_events_lock_unless_lock_on_sleep_is_off() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = daemon(dir.path());
    let unlocked = || daemon.session.lock().unwrap().is_some();
    let deliver = |events: &[SystemEvent]| {
        let (tx, rx) = mpsc::channel(events.len());
        for event in events {
            tx.try_send(*event).unwrap();
        }
        drop(tx);
        daemon.clone().follow_system(rx)
    };
    let mut connections = JoinSet::new();
    let (mut lines, _write) = subscribe(&daemon, &mut connections).await;

    daemon.setup(passphrase(), "device".into()).await.unwrap();
    assert_eq!(next(&mut lines).await, Some(Change::Unlocked));
    deliver(&[SystemEvent::Sleep]).await;
    assert!(!unlocked());
    assert_eq!(next(&mut lines).await, Some(Change::Locked));

    for event in [SystemEvent::ScreenLocked, SystemEvent::Slept] {
        daemon.unlock(passphrase(), None).await.unwrap();
        deliver(&[event]).await;
        assert!(!unlocked(), "{event:?} locks");
    }

    std::fs::write(&daemon.paths.config, "lock_on_sleep = false\n").unwrap();
    daemon.unlock(passphrase(), None).await.unwrap();
    deliver(&[
        SystemEvent::Sleep,
        SystemEvent::ScreenLocked,
        SystemEvent::Slept,
    ])
    .await;
    assert!(unlocked(), "turned off, nothing locks");

    // A config that doesn't parse locks: failing safe beats failing open.
    std::fs::write(&daemon.paths.config, "lock_on_sleep = \"sometimes\"\n").unwrap();
    deliver(&[SystemEvent::Sleep]).await;
    assert!(!unlocked());
}

/// One request over a socket pair, and its reply.
async fn ask(daemon: &Arc<Daemon>, command: Command) -> Reply {
    let (server, client) = UnixStream::pair().unwrap();
    let handled = tokio::spawn(daemon.clone().handle(server, MAX_LINE));
    let (read, mut write) = client.into_split();
    write.write_all(&request(command)).await.unwrap();
    let line = tokio::time::timeout(
        watchers::STARTING * 2,
        BufReader::new(read).lines().next_line(),
    )
    .await
    .expect("a reply in time")
    .unwrap()
    .expect("a reply");
    handled.await.unwrap().unwrap();
    match serde_json::from_str::<Message>(&line).unwrap() {
        Message::Ok { reply } => reply,
        other => panic!("unexpected {other:?}"),
    }
}

fn activate(token: &str) -> Command {
    Command::AppActivate {
        token: Some(token.into()),
    }
}

#[tokio::test]
async fn app_activate_reaches_only_the_newest_app_watcher() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = daemon(dir.path());
    let mut connections = JoinSet::new();
    let (mut other, _other) = subscribe(&daemon, &mut connections).await;
    let (mut older, _older) = watch_as(&daemon, &mut connections, true).await;
    let (mut newer, newer_write) = watch_as(&daemon, &mut connections, true).await;

    assert!(matches!(
        ask(&daemon, activate("one")).await,
        Reply::Activated
    ));
    assert_eq!(
        next(&mut newer).await,
        Some(Change::Activate {
            token: Some("one".into())
        })
    );
    quiet(&mut older).await;
    quiet(&mut other).await;

    // The newest window gone, the one before it comes forward.
    drop((newer, newer_write));
    while daemon.watchers.len() == 3 {
        tokio::task::yield_now().await;
    }
    let none = Command::AppActivate { token: None };
    assert!(matches!(ask(&daemon, none).await, Reply::Activated));
    assert_eq!(
        next(&mut older).await,
        Some(Change::Activate { token: None })
    );
    quiet(&mut other).await;
}

#[tokio::test]
async fn without_an_app_a_second_launch_waits_for_the_first_ones() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = daemon(dir.path());
    let mut connections = JoinSet::new();
    // A watcher that isn't the app doesn't count.
    let (mut other, _other) = subscribe(&daemon, &mut connections).await;

    // The first launch starts the app; the second, meanwhile, waits for it.
    assert!(matches!(
        ask(&daemon, activate("first")).await,
        Reply::NoApp
    ));
    let second = tokio::spawn({
        let daemon = daemon.clone();
        async move { ask(&daemon, activate("second")).await }
    });
    tokio::time::sleep(QUIET).await;
    assert!(!second.is_finished(), "the second launch waits");
    let (mut app, _app) = watch_as(&daemon, &mut connections, true).await;
    assert!(matches!(second.await.unwrap(), Reply::Activated));
    assert_eq!(
        next(&mut app).await,
        Some(Change::Activate {
            token: Some("second".into())
        })
    );
    quiet(&mut other).await;
}
