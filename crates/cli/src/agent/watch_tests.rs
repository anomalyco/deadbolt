//! `watch` through the agent: what a watcher sees, that a stuck watcher
//! can't hold the agent up, and locking on system events.

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
use super::{Agent, MAX_LINE, items, sync, watchers};
use crate::protocol::{Change, Command, FieldInput, Message, PROTOCOL_VERSION, Reply, Request};

const KDF: deadbolt_store::KdfParams = deadbolt_store::KdfParams {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};
/// Long enough for any real change to arrive; quiet after that means none came.
const QUIET: Duration = Duration::from_millis(300);
const STEP: Duration = Duration::from_secs(10);

fn agent(dir: &std::path::Path) -> Arc<Agent> {
    Agent::new(test_paths(dir), true, KDF)
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

/// Subscribes over a socket pair, returning the watcher's lines.
async fn subscribe(
    agent: &Arc<Agent>,
    connections: &mut JoinSet<anyhow::Result<()>>,
) -> (
    Lines<BufReader<OwnedReadHalf>>,
    tokio::net::unix::OwnedWriteHalf,
) {
    let (server, client) = UnixStream::pair().unwrap();
    connections.spawn(agent.clone().handle(server, MAX_LINE));
    let (read, mut write) = client.into_split();
    write.write_all(&request(Command::Watch)).await.unwrap();
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
    let agent = agent(dir.path());
    let mut connections = JoinSet::new();
    let (mut lines, _write) = subscribe(&agent, &mut connections).await;

    agent.setup(passphrase(), "device".into()).await.unwrap();
    assert_eq!(next(&mut lines).await, Some(Change::Unlocked));
    agent.lock().await;
    assert_eq!(next(&mut lines).await, Some(Change::Locked));
    agent.unlock(passphrase(), None).await.unwrap();
    assert_eq!(next(&mut lines).await, Some(Change::Unlocked));
    quiet(&mut lines).await;

    let vault = agent.with(|s| s.create_vault("personal")).unwrap();
    assert_eq!(
        changes(&mut lines, 3).await,
        [Change::Vaults, devices_in(vault), items_in(vault)]
    );
    let fields = vec![FieldInput {
        name: "password".into(),
        kind: None,
        value: "local".into(),
    }];
    agent
        .with(|s| items::create(s, None, "login", Some("mine".into()), fields))
        .unwrap();
    assert_eq!(next(&mut lines).await, Some(items_in(vault)));
    quiet(&mut lines).await;

    // Another member writes three items; they arrive in one sync batch.
    let other = DeviceSecret::from_bytes(&[52; 32]);
    agent
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
    let mut theirs = agent.with(|s| Ok(s.vault(&vault).clone())).unwrap();
    let batch: Vec<Vec<u8>> = (0..3)
        .map(|n| {
            let field = Field::new(FieldType::Secret, format!("theirs-{n}"));
            let (_, entry) = theirs
                .create_item(&other, "login", None, [("password".into(), field)])
                .unwrap();
            entry.encode()
        })
        .collect();
    agent.ready.send_replace(true);
    sync::Handler(agent.clone())
        .receive(*other.device_id().as_bytes(), batch)
        .await
        .unwrap();
    assert_eq!(
        agent.with(|s| Ok(s.vault(&vault).items().len())).unwrap(),
        4
    );
    assert_eq!(next(&mut lines).await, Some(items_in(vault)));
    quiet(&mut lines).await;

    // Stopping ends the stream with a final reply.
    agent.watchers.stopping();
    assert_eq!(next(&mut lines).await, Some(Change::Stopping));
    assert_eq!(next(&mut lines).await, None);
    assert_eq!(lines.next_line().await.unwrap(), None);
    connections.join_next().await.unwrap().unwrap().unwrap();
    assert_eq!(agent.watchers.len(), 0);
    agent.lock().await;
}

#[tokio::test]
async fn hanging_up_ends_a_watch_quietly() {
    let dir = tempfile::tempdir().unwrap();
    let agent = agent(dir.path());
    let mut connections = JoinSet::new();
    let (lines, write) = subscribe(&agent, &mut connections).await;
    assert_eq!(agent.watchers.len(), 1);
    drop((lines, write));
    tokio::time::timeout(STEP, connections.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(agent.watchers.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_watcher_that_stops_reading_cannot_stall_the_agent() {
    let dir = tempfile::tempdir().unwrap();
    let agent = agent(dir.path());
    let (server, mut client) = UnixStream::pair().unwrap();
    client.write_all(&request(Command::Watch)).await.unwrap();
    // Fill the agent's side of the socket: the client never reads.
    server.writable().await.unwrap();
    loop {
        match server.try_write(&[0; 8192]) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("{error}"),
        }
    }
    let mut connections = JoinSet::new();
    connections.spawn(agent.clone().handle(server, MAX_LINE));
    while agent.watchers.len() == 0 {
        tokio::task::yield_now().await;
    }

    let start = tokio::time::Instant::now();
    for n in 0..10_000u32 {
        let mut id = [0; 32];
        id[..4].copy_from_slice(&n.to_le_bytes());
        agent.watchers.changed(&Changes {
            items: [VaultId::from_bytes(id)].into(),
            ..Changes::default()
        });
        agent.watchers.locked();
        agent.watchers.unlocked();
    }
    agent.lock().await;
    assert_eq!(start.elapsed(), Duration::ZERO, "publishing never waits");

    let result = tokio::time::timeout(watchers::SEND_TIMEOUT * 2, connections.join_next())
        .await
        .expect("the stuck watcher is dropped")
        .unwrap()
        .unwrap();
    assert!(result.is_err());
    assert!(start.elapsed() >= watchers::SEND_TIMEOUT);
    assert_eq!(agent.watchers.len(), 0);
    drop(client);
}

#[tokio::test]
async fn system_events_lock_unless_lock_on_sleep_is_off() {
    let dir = tempfile::tempdir().unwrap();
    let agent = agent(dir.path());
    let unlocked = || agent.session.lock().unwrap().is_some();
    let deliver = |events: &[SystemEvent]| {
        let (tx, rx) = mpsc::channel(events.len());
        for event in events {
            tx.try_send(*event).unwrap();
        }
        drop(tx);
        agent.clone().follow_system(rx)
    };
    let mut connections = JoinSet::new();
    let (mut lines, _write) = subscribe(&agent, &mut connections).await;

    agent.setup(passphrase(), "device".into()).await.unwrap();
    assert_eq!(next(&mut lines).await, Some(Change::Unlocked));
    deliver(&[SystemEvent::Sleep]).await;
    assert!(!unlocked());
    assert_eq!(next(&mut lines).await, Some(Change::Locked));

    for event in [SystemEvent::ScreenLocked, SystemEvent::Slept] {
        agent.unlock(passphrase(), None).await.unwrap();
        deliver(&[event]).await;
        assert!(!unlocked(), "{event:?} locks");
    }

    std::fs::write(&agent.paths.config, "lock_on_sleep = false\n").unwrap();
    agent.unlock(passphrase(), None).await.unwrap();
    deliver(&[
        SystemEvent::Sleep,
        SystemEvent::ScreenLocked,
        SystemEvent::Slept,
    ])
    .await;
    assert!(unlocked(), "turned off, nothing locks");

    // A config that doesn't parse locks: failing safe beats failing open.
    std::fs::write(&agent.paths.config, "lock_on_sleep = \"sometimes\"\n").unwrap();
    deliver(&[SystemEvent::Sleep]).await;
    assert!(!unlocked());
}
