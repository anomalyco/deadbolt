//! The background agent: the only process that opens the store. Holds it
//! unlocked, runs the iroh node while unlocked, and serves the control socket.

mod activity;
mod autofill;
pub mod biometric;
mod caller;
mod forms;
mod generate;
mod grants;
mod guesses;
mod health;
mod items;
mod macos_autofill;
mod mirror;
mod pairing;
mod passkeys;
mod remote_read;
mod secrets;
mod send;
mod session;
#[cfg(test)]
mod sim;
pub(crate) mod ssh;
mod sync;
mod system;
#[cfg(test)]
mod watch_tests;
mod watchers;

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, TryLockError};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use deadbolt_client::export;
use deadbolt_core::DeviceId;
use deadbolt_net::{Membership, Node, NodeConfig, PeerId};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::client::{AgentError, protocol, version};
use crate::config::Config;
use crate::paths::Paths;
use crate::protocol::{
    Answer, CallerInfo, Change, Command, ErrorCode, Event, MAX_LINE, Message, Reply, Request,
    Status,
};
use session::{Loaded, Session, clean_name};
use system::SystemEvent;
use watchers::Watchers;

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const BIOMETRIC_CANCEL_COOLDOWN: Duration = Duration::from_secs(2);
const INTERRUPTED: &str = "locked during the sync from 1Password; nothing was written";

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone)]
struct BiometricFlight {
    cancel: Arc<biometric::CancelHandle>,
    rx: watch::Receiver<Option<Result<(), String>>>,
}

#[cfg(test)]
type BiometricUnsealHook = Arc<
    dyn Fn(&biometric::CancelHandle) -> Result<Zeroizing<[u8; 32]>, biometric::UnlockError>
        + Send
        + Sync,
>;

pub struct Agent {
    paths: Paths,
    local_net: bool,
    kdf: deadbolt_store::KdfParams,
    session: Mutex<Option<Session>>,
    /// The membership gate: members of any vault this device holds.
    members: Arc<RwLock<HashSet<PeerId>>>,
    /// Cleared on unlock until membership was synced with reachable peers.
    ready: watch::Sender<bool>,
    sync_now: Notify,
    /// Serializes setup, unlock and lock.
    transition: tokio::sync::Mutex<()>,
    /// Held by the one join or pair running.
    pairing: tokio::sync::Mutex<()>,
    /// Held by the one sync from 1Password running.
    syncing_op: tokio::sync::Mutex<()>,
    /// Bumped by a lock and at shutdown: a sync from 1Password running
    /// kills `op` and writes nothing.
    interrupts: watch::Sender<u64>,
    #[cfg(test)]
    op_program: Mutex<Option<std::path::PathBuf>>,
    /// In-memory metadata of `"biometric.token"`, loaded once at startup and
    /// updated on enrollment/clear/wipe so `status()` never opens `store.redb`.
    biometric_slot: Mutex<Option<biometric::TokenMeta>>,
    /// True once Touch ID has been enrolled for this store (`initial_slot.is_some()`
    /// or enrolled during this agent's lifetime) and not explicitly turned off,
    /// so `touch_id_reset` distinguishes a wiped/expired slot from a store
    /// where `touch_id = true` was set in `config.toml` before ever enrolling.
    biometric_was_enrolled: AtomicBool,
    /// Coalesces concurrent `UnlockBiometric` requests and lets `Unlock`,
    /// `Lock`, `TouchIdSet`, or `Stop` cancel an in-flight Touch ID prompt.
    biometric_flight: Mutex<Option<BiometricFlight>>,
    /// Short cooldown after a user-cancelled Touch ID prompt so rapid window
    /// focus or summon events do not immediately re-prompt.
    biometric_cooldown_until: Mutex<Option<Instant>>,
    /// The one Touch ID prompt verifying a passkey ceremony, cancelled with
    /// the unlock prompt.
    passkey_prompt: Mutex<Option<Arc<biometric::CancelHandle>>>,
    #[cfg(test)]
    touch_id_available_override: Mutex<Option<bool>>,
    #[cfg(test)]
    biometric_hook: Mutex<Option<BiometricUnsealHook>>,
    idle: Mutex<Idle>,
    /// Requests in progress; the idle timeout waits for them (e.g. pairing).
    busy: AtomicUsize,
    shutdown: Notify,
    watchers: Watchers,
    /// Who connections come from.
    callers: caller::Callers,
    /// Activity not stored yet: entries recorded while locked, and each
    /// caller's count against its limit.
    activity: Mutex<activity::Ledger>,
    /// Each paired agent client's rate limit, by client id.
    agent_rates: Mutex<HashMap<String, crate::browser::host::Bucket>>,
    /// AI callers' `resolve` rate limits, by anchor, and one for them all.
    resolve_rates: Mutex<HashMap<String, crate::browser::host::Bucket>>,
    /// macOS AutoFill extension rate limits for fills and passkey ceremonies.
    autofill_fill_rate: Mutex<Option<crate::browser::host::Bucket>>,
    autofill_passkey_rate: Mutex<Option<crate::browser::host::Bucket>>,
    /// Every passphrase check: one at a time, wrong ones backed off.
    guesses: guesses::Guesses,
    /// Deadbolt Send's endpoint, started by the first send.
    send_server: tokio::sync::Mutex<Option<deadbolt_send::Server>>,
    /// Set as the agent stops, ending sends and anyone waiting on one.
    stopping: watch::Sender<bool>,
    /// SSH agent (`ssh.sock`) listener, Touch ID queue and TTY grants.
    ssh: ssh::SshState,
}

impl Agent {
    fn new(paths: Paths, local_net: bool, kdf: deadbolt_store::KdfParams) -> Arc<Agent> {
        let initial_slot = biometric::read_token_meta(&paths.data);
        biometric::spawn_background_refresh();
        Arc::new(Agent {
            paths,
            local_net,
            kdf,
            session: Mutex::default(),
            members: Arc::default(),
            ready: watch::channel(false).0,
            sync_now: Notify::new(),
            transition: tokio::sync::Mutex::new(()),
            pairing: tokio::sync::Mutex::new(()),
            syncing_op: tokio::sync::Mutex::new(()),
            interrupts: watch::channel(0).0,
            #[cfg(test)]
            op_program: Mutex::default(),
            biometric_was_enrolled: AtomicBool::new(initial_slot.is_some()),
            biometric_slot: Mutex::new(initial_slot),
            biometric_flight: Mutex::default(),
            biometric_cooldown_until: Mutex::default(),
            passkey_prompt: Mutex::default(),
            #[cfg(test)]
            touch_id_available_override: Mutex::default(),
            #[cfg(test)]
            biometric_hook: Mutex::default(),
            idle: Mutex::default(),
            busy: AtomicUsize::new(0),
            shutdown: Notify::new(),
            watchers: Watchers::default(),
            callers: caller::Callers::new(),
            activity: Mutex::default(),
            agent_rates: Mutex::default(),
            resolve_rates: Mutex::default(),
            autofill_fill_rate: Mutex::default(),
            autofill_passkey_rate: Mutex::default(),
            guesses: guesses::Guesses::default(),
            send_server: tokio::sync::Mutex::default(),
            stopping: watch::channel(false).0,
            ssh: ssh::SshState::default(),
        })
    }

    /// Holds off the idle lock until dropped: for a request waiting on the
    /// user (a Touch ID prompt, a passphrase check).
    fn busy(&self) -> Busy<'_> {
        self.busy.fetch_add(1, Ordering::SeqCst);
        Busy(&self.busy)
    }

    fn interrupt_op(&self) {
        self.interrupts.send_modify(|n| *n += 1);
    }

    fn op(&self) -> mirror::Op {
        #[cfg(test)]
        if let Some(program) = self
            .op_program
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return mirror::Op::at(program);
        }
        mirror::Op::find()
    }

    fn cancel_biometric_prompt(&self) {
        if let Some(flight) = self
            .biometric_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            flight.cancel.cancel();
        }
        if let Some(prompt) = self
            .passkey_prompt
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            prompt.cancel();
        }
        self.ssh.policy.cancel_prompt();
    }
}

/// See [`Agent::busy`].
struct Busy<'a>(&'a AtomicUsize);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.cancel_biometric_prompt();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::FieldInput;
    use crate::protocol::PROTOCOL_VERSION;
    use deadbolt_core::DeviceSecret;
    use tokio::io::AsyncReadExt;

    fn locked_agent(dir: &std::path::Path) -> Arc<Agent> {
        Agent::new(test_paths(dir), true, deadbolt_store::KdfParams::DEFAULT)
    }

    pub(super) fn test_paths(dir: &std::path::Path) -> Paths {
        Paths {
            data: dir.into(),
            config: dir.join("config"),
            socket: dir.join("socket"),
            lock: dir.join("lock"),
            log: dir.join("log"),
            ssh_link: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stop_reply_precedes_shutdown_even_with_backpressure() {
        let dir = tempfile::tempdir().unwrap();
        let agent = locked_agent(dir.path());
        let (server, mut client) = UnixStream::pair().unwrap();
        server.writable().await.unwrap();
        let mut buffered = 0;
        loop {
            match server.try_write(&[0; 8192]) {
                Ok(n) => buffered += n,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("{error}"),
            }
        }
        let mut request = serde_json::to_vec(&Request {
            v: PROTOCOL_VERSION,
            claimed: None,
            command: Command::Stop,
        })
        .unwrap();
        request.push(b'\n');
        client.write_all(&request).await.unwrap();
        let mut connections = JoinSet::new();
        connections.spawn(agent.clone().handle(server, MAX_LINE));
        assert!(
            tokio::time::timeout(Duration::from_secs(1), agent.shutdown.notified())
                .await
                .is_err()
        );
        client.read_exact(&mut vec![0; buffered]).await.unwrap();
        tokio::time::timeout(IO_TIMEOUT, agent.shutdown.notified())
            .await
            .unwrap();
        drain_connections(&mut connections).await;
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        assert!(matches!(
            serde_json::from_str::<Message>(&reply).unwrap(),
            Message::Ok { reply: Reply::Done }
        ));
    }

    #[tokio::test]
    async fn a_locked_agent_generates_passwords() {
        let dir = tempfile::tempdir().unwrap();
        let agent = locked_agent(dir.path());
        let ask = |length, symbols| {
            let agent = agent.clone();
            async move {
                let (server, mut client) = UnixStream::pair().unwrap();
                let mut request = serde_json::to_vec(&Request {
                    v: PROTOCOL_VERSION,
                    claimed: None,
                    command: Command::Generate {
                        length,
                        symbols,
                        url: None,
                    },
                })
                .unwrap();
                request.push(b'\n');
                client.write_all(&request).await.unwrap();
                agent.handle(server, MAX_LINE).await.unwrap();
                let mut reply = String::new();
                client.read_to_string(&mut reply).await.unwrap();
                serde_json::from_str::<Message>(&reply).unwrap()
            }
        };
        match ask(12, false).await {
            Message::Ok {
                reply: Reply::Password { password },
            } => {
                assert_eq!(password.len(), 12);
                assert!(password.bytes().all(|b| b.is_ascii_alphanumeric()));
            }
            other => panic!("expected a password, got {other:?}"),
        }
        match ask(4, true).await {
            Message::Error { code, message, .. } => {
                assert_eq!(code, ErrorCode::Failed);
                assert_eq!(message, "a generated password must be 8 to 256 characters");
            }
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_drain_cancels_idle_connections() {
        let dir = tempfile::tempdir().unwrap();
        let (server, _client) = UnixStream::pair().unwrap();
        let mut connections = JoinSet::new();
        connections.spawn(locked_agent(dir.path()).handle(server, MAX_LINE));
        let start = Instant::now();
        drain_connections(&mut connections).await;
        assert!(connections.is_empty());
        assert!(start.elapsed() < IO_TIMEOUT);
    }

    #[tokio::test]
    async fn oversized_requests_finish_writing_and_receive_a_clean_error() {
        for newline in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let agent = locked_agent(dir.path());
            let (server, mut client) = UnixStream::pair().unwrap();
            let exchange = async {
                tokio::join!(agent.handle(server, 64), async {
                    // More than the socket buffer: replying early breaks this write.
                    for _ in 0..128 {
                        client.write_all(&[b'x'; 8192]).await.unwrap();
                    }
                    if newline {
                        client.write_all(b"\n").await.unwrap();
                    } else {
                        client.shutdown().await.unwrap();
                    }
                    let mut reply = String::new();
                    client.read_to_string(&mut reply).await.unwrap();
                    match serde_json::from_str::<Message>(&reply).unwrap() {
                        Message::Error { code, message, .. } => {
                            assert!(matches!(code, ErrorCode::Failed));
                            assert_eq!(message, "request too large");
                        }
                        _ => panic!("expected an oversized-request error"),
                    }
                })
            };
            let (handled, ()) = tokio::time::timeout(IO_TIMEOUT, exchange).await.unwrap();
            handled.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stop_notifies_shutdown_when_the_client_cannot_receive_its_reply() {
        let dir = tempfile::tempdir().unwrap();
        let agent = locked_agent(dir.path());
        let (server, mut client) = UnixStream::pair().unwrap();
        let mut request = serde_json::to_vec(&Request {
            v: PROTOCOL_VERSION,
            claimed: None,
            command: Command::Stop,
        })
        .unwrap();
        request.push(b'\n');
        client.write_all(&request).await.unwrap();
        drop(client);
        assert!(agent.clone().handle(server, MAX_LINE).await.is_err());
        tokio::time::timeout(Duration::from_secs(1), agent.shutdown.notified())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn ambiguous_append_closes_the_gate_and_cannot_be_reopened_by_readiness() {
        let dir = tempfile::tempdir().unwrap();
        let agent = locked_agent(dir.path());
        let (mut loaded, fault) = session::tests::fault_store(dir.path(), [7; 32]);
        let id = loaded.create_vault("personal").unwrap();
        let peer = DeviceSecret::from_bytes(&[8; 32]);
        let consent = peer.join_consent(&id, &loaded.id);
        loaded
            .update(id, |v, key| Ok(v.add(key, peer.device_id(), consent)?))
            .unwrap();
        let members = agent.members.clone();
        let node = Node::spawn(
            NodeConfig::local_only(*loaded.secret.to_bytes()),
            Arc::new(move |id: &PeerId| members.read().unwrap().contains(id)),
            sync::Handler(agent.clone()),
        )
        .await
        .unwrap();
        let mut session = Session::new(loaded, node.clone());
        let background = tokio::spawn(std::future::pending::<()>());
        let aborted = background.abort_handle();
        session.sync_task = Some(AbortOnDrop(background));
        agent.refresh(&mut session);
        *agent.session.lock().unwrap() = Some(session);
        agent.ready.send_replace(true);
        let peer_node = Node::spawn(
            NodeConfig::local_only(*peer.to_bytes()),
            Arc::new(|_: &PeerId| true),
            sync::Handler(agent.clone()),
        )
        .await
        .unwrap();
        // Dial out so the tracked connection is installed on the exact node
        // whose membership is revoked below, without waiting for the accept task.
        let conn = node.connect(peer_node.addr()).await.unwrap();
        assert!(node.connected_peers().contains(peer.device_id().as_bytes()));
        fault.store(2, Ordering::SeqCst);
        let error = agent
            .with(|s| s.update(id, |v, key| Ok(v.remove(key, peer.device_id())?)))
            .unwrap_err();
        assert!(error.to_string().contains("commit outcome is uncertain"));
        assert!(agent.members.read().unwrap().is_empty());
        assert!(node.connected_peers().is_empty());
        assert!(!*agent.ready.borrow());
        assert!(!agent.status().unlocked);
        assert!(agent.status().vaults.is_empty());
        assert!(agent.with(|s| Ok(s.vault_infos())).is_err());
        assert!(agent.with_data(|_| Ok(())).is_err());
        assert!(
            agent
                .with(|_| {
                    agent.ready.send_replace(true);
                    Ok(())
                })
                .is_err()
        );
        assert!(!*agent.ready.borrow());
        assert!(agent.wait_ready().await.is_err());
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            agent.unlock(zeroize::Zeroizing::new("wrong".into()), Some(0)),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(wrong_passphrase(&error));
        assert!(!agent.status().unlocked);
        assert!(agent.session.lock().unwrap().is_none());
        assert!(agent.members.read().unwrap().is_empty());
        // A failed authentication discarded the old handle, not quarantine's
        // protection. A later normal Unlock must authenticate and replay.
        agent
            .unlock(zeroize::Zeroizing::new("test".into()), Some(0))
            .await
            .unwrap();
        agent
            .with(|s| {
                assert!(!s.vault(&id).is_member(&peer.device_id()));
                assert_eq!(s.vault(&id).entries().len(), 3);
                Ok(())
            })
            .unwrap();
        tokio::task::yield_now().await;
        assert!(aborted.is_finished());
        conn.close();
        agent.lock().await;
        peer_node.shutdown().await;
        let reopened = Loaded::open(dir.path(), b"test").unwrap();
        assert!(!reopened.vault(&id).is_member(&peer.device_id()));
    }

    #[tokio::test]
    async fn quarantine_unlock_authenticates_and_replays_without_a_separate_lock() {
        for biometric in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let agent = locked_agent(dir.path());
            let (mut loaded, fault) = session::tests::fault_store(dir.path(), [7; 32]);
            let id = loaded.create_vault("personal").unwrap();
            let key = deadbolt_store::generate_biometric_key().unwrap();
            loaded
                .store
                .set_biometric(&key, &make_valid_biometric_token(session::now()))
                .unwrap();
            let node = Node::spawn(
                NodeConfig::local_only(*loaded.secret.to_bytes()),
                Arc::new(|_: &PeerId| false),
                sync::Handler(agent.clone()),
            )
            .await
            .unwrap();
            *agent.session.lock().unwrap() = Some(Session::new(loaded, node));
            fault.store(2, Ordering::SeqCst);
            assert!(
                agent
                    .with(|s| s.update(id, |v, key| Ok(v.rename(key, "committed")?)))
                    .is_err()
            );
            assert!(!agent.status().unlocked);
            if biometric {
                crate::config::set_touch_id(&agent.paths.config, true).unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let called = calls.clone();
                let key = *key;
                *agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |cancel| {
                    assert!(!cancel.is_cancelled());
                    called.fetch_add(1, Ordering::SeqCst);
                    Ok(Zeroizing::new(key))
                }));
                assert!(
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        agent.unlock_biometric_with_reason(Some(0), "test recovery")
                    )
                    .await
                    .unwrap()
                    .unwrap()
                );
                assert_eq!(calls.load(Ordering::SeqCst), 1);
            } else {
                // Concurrent explicit unlocks serialize teardown/open. Neither
                // may reopen the poisoned handle or duplicate the logged edit.
                let (a, b) = tokio::time::timeout(Duration::from_secs(5), async {
                    tokio::join!(
                        agent.unlock(Zeroizing::new("test".into()), Some(0)),
                        agent.unlock(Zeroizing::new("test".into()), Some(0))
                    )
                })
                .await
                .unwrap();
                a.unwrap();
                b.unwrap();
            }
            agent
                .with(|s| {
                    assert_eq!(s.vault(&id).name(), "committed");
                    assert_eq!(s.vault(&id).entries().len(), 2);
                    Ok(())
                })
                .unwrap();
            agent.lock().await;
            assert!(agent.session.lock().unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn quarantine_explicit_lock_still_closes_the_failed_handle() {
        let dir = tempfile::tempdir().unwrap();
        let agent = locked_agent(dir.path());
        let (mut loaded, fault) = session::tests::fault_store(dir.path(), [7; 32]);
        let id = loaded.create_vault("personal").unwrap();
        let node = Node::spawn(
            NodeConfig::local_only(*loaded.secret.to_bytes()),
            Arc::new(|_: &PeerId| false),
            sync::Handler(agent.clone()),
        )
        .await
        .unwrap();
        *agent.session.lock().unwrap() = Some(Session::new(loaded, node));
        fault.store(2, Ordering::SeqCst);
        assert!(
            agent
                .with(|s| s.update(id, |v, key| Ok(v.rename(key, "committed")?)))
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(5), agent.lock())
            .await
            .unwrap();
        assert!(agent.session.lock().unwrap().is_none());
        let loaded = Loaded::open(dir.path(), b"test").unwrap();
        assert_eq!(loaded.vault(&id).name(), "committed");
    }

    #[tokio::test]
    async fn locking_wakes_membership_waiters_with_the_locked_error() {
        let dir = tempfile::tempdir().unwrap();
        let agent = locked_agent(dir.path());
        let loaded = Loaded::setup(
            dir.path(),
            b"test",
            "device",
            deadbolt_store::KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        let node = Node::spawn(
            NodeConfig::local_only(*loaded.secret.to_bytes()),
            Arc::new(|_: &PeerId| false),
            sync::Handler(agent.clone()),
        )
        .await
        .unwrap();
        *agent.session.lock().unwrap() = Some(Session::new(loaded, node));
        tokio::time::pause();
        let (error, ()) = tokio::join!(
            async {
                tokio::time::timeout(Duration::from_secs(2), agent.wait_ready())
                    .await
                    .unwrap()
                    .unwrap_err()
            },
            async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                agent.lock().await;
            }
        );
        let error = error.downcast::<AgentError>().unwrap();
        assert!(matches!(error.code, ErrorCode::Locked));
        assert_eq!(error.message, "locked: run `deadbolt unlock`");
    }

    #[test]
    fn invalid_requests_are_described_without_their_values() {
        let line = r#"{"v":4,"cmd":"import","export":"hunter2","apply":"hunter2"}"#;
        let error = serde_json::from_str::<Request>(line).unwrap_err();
        assert!(error.to_string().contains("hunter2"), "serde quotes values");
        let message = invalid_request(&error).to_string();
        assert!(!message.contains("hunter2"), "{message}");
        assert!(
            message.starts_with("invalid request: not a request"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn line_limit_preserves_answers_and_rejects_unterminated_oversize() {
        let mut read = BufReader::new(&b"request\nyes\n"[..]);
        assert_eq!(
            request_line(&mut read, 7)
                .await
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("request")
        );
        assert_eq!(
            request_line(&mut read, 7)
                .await
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("yes")
        );
        let mut read = BufReader::new(&b"1234567890123456"[..]);
        assert!(request_line(&mut read, 7).await.is_err());
        let mut rest = String::new();
        read.read_to_string(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        let mut read = BufReader::new(&b"1234567890123456\nyes\n"[..]);
        assert!(request_line(&mut read, 7).await.is_err());
        assert_eq!(
            request_line(&mut read, 7)
                .await
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("yes")
        );
    }

    #[tokio::test]
    async fn local_item_commands_work_immediately_after_unlock_with_offline_peers() {
        let dir = tempfile::tempdir().unwrap();
        let key = [51; 32];
        let store = deadbolt_store::init_with_params(
            dir.path(),
            b"test",
            key,
            deadbolt_store::KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        drop(store);
        let mut loaded = Loaded::open(dir.path(), b"test").unwrap();
        let id = loaded.create_vault("personal").unwrap();
        let offline = DeviceSecret::from_bytes(&[52; 32]);
        loaded
            .update(id, |v, key| {
                Ok(v.add(
                    key,
                    offline.device_id(),
                    offline.join_consent(&id, &key.device_id()),
                )?)
            })
            .unwrap();
        drop(loaded);
        let loaded = Loaded::open(dir.path(), b"test").unwrap();
        let agent = locked_agent(dir.path());
        let node = Node::spawn(
            NodeConfig::local_only(key),
            Arc::new(|_: &PeerId| false),
            sync::Handler(agent.clone()),
        )
        .await
        .unwrap();
        *agent.session.lock().unwrap() = Some(Session::new(loaded, node));
        // No startup task can open readiness: any local wait/gate is a regression.
        let (socket, _client) = UnixStream::pair().unwrap();
        let (_, write) = socket.into_split();
        let conv = Conversation {
            write: tokio::sync::Mutex::new(write),
            answers: tokio::sync::Mutex::new(mpsc::channel(1).1),
            closed: watch::channel(false).1,
        };
        let fields = || {
            vec![
                FieldInput {
                    name: "password".into(),
                    kind: None,
                    value: "offline-value".into(),
                },
                FieldInput {
                    name: "notes".into(),
                    kind: None,
                    value: "offline note".into(),
                },
            ]
        };
        let commands = vec![
            Command::ItemNew {
                vault: None,
                kind: "login".into(),
                name: Some("offline-login".into()),
                fields: fields(),
                favorite: false,
                tags: Vec::new(),
            },
            Command::ItemGet {
                vault: None,
                query: vec!["offline-login".into()],
                otp: false,
                ssh_private: false,
                files: Vec::new(),
                deleted: false,
            },
            Command::ItemList {
                vault: None,
                query: vec![],
                kind: None,
                deleted: false,
                tags: Vec::new(),
                favorites: false,
            },
            Command::ItemSet {
                vault: None,
                query: vec!["offline-login".into()],
                fields: fields(),
                name: None,
                unset: Vec::new(),
                favorite: None,
                add_tags: Vec::new(),
                remove_tags: Vec::new(),
            },
            Command::ItemUnset {
                vault: None,
                query: vec!["offline-login".into()],
                field: "notes".into(),
            },
            Command::Import {
                vault: None,
                export: "name,password\nimported,offline-import\n"
                    .to_string()
                    .into(),
                files: Vec::new(),
                apply: true,
            },
            Command::ItemRemove {
                vault: None,
                query: vec!["offline-login".into()],
            },
            Command::ItemRestore {
                vault: None,
                query: vec!["offline-login".into()],
            },
        ];
        for command in commands {
            tokio::time::timeout(Duration::from_secs(2), agent.clone().run(command, &conv))
                .await
                .unwrap()
                .unwrap();
            assert!(!*agent.ready.borrow());
        }
        assert!(
            agent.with_data(|_| Ok(())).is_err(),
            "invitations must still wait"
        );
        tokio::time::pause();
        let (waited, ()) = tokio::join!(agent.wait_ready(), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            agent.ready.send_replace(true);
        });
        waited.unwrap();
        agent.with_data(|_| Ok(())).unwrap();
        agent.ready.send_replace(false);
        let start = tokio::time::Instant::now();
        assert_eq!(
            agent.wait_ready().await.unwrap_err().to_string(),
            "waiting for membership sync"
        );
        assert!(start.elapsed() >= sync::STARTUP_TIMEOUT);
        // Tokio's timer wheel rounds deadlines to millisecond ticks.
        assert!(start.elapsed() <= sync::STARTUP_TIMEOUT + Duration::from_millis(1));
        agent.lock().await;
    }

    /// An agent holding one empty vault, its `op` a script that records
    /// its pid in `pid` and hangs.
    async fn syncing_agent(dir: &std::path::Path) -> (Arc<Agent>, std::path::PathBuf) {
        let fast = deadbolt_store::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        };
        let mut loaded = Loaded::setup(dir, b"test", "device", fast).unwrap();
        loaded.create_vault("personal").unwrap();
        let key = *loaded.store.device_secret();
        let agent = locked_agent(dir);
        let node = Node::spawn(
            NodeConfig::local_only(key),
            Arc::new(|_: &PeerId| false),
            sync::Handler(agent.clone()),
        )
        .await
        .unwrap();
        *agent.session.lock().unwrap() = Some(Session::new(loaded, node));
        let pid = dir.join("pid");
        let op = dir.join("op");
        fs::write(
            &op,
            format!("#!/bin/sh\necho $$ > '{}'\nexec sleep 30\n", pid.display()),
        )
        .unwrap();
        fs::set_permissions(&op, fs::Permissions::from_mode(0o755)).unwrap();
        *agent.op_program.lock().unwrap() = Some(op);
        (agent, pid)
    }

    pub(super) fn conversation() -> (Conversation, UnixStream, watch::Sender<bool>) {
        let (socket, client) = UnixStream::pair().unwrap();
        let (_, write) = socket.into_split();
        let (closed, closed_rx) = watch::channel(false);
        let conv = Conversation {
            write: tokio::sync::Mutex::new(write),
            answers: tokio::sync::Mutex::new(mpsc::channel(1).1),
            closed: closed_rx,
        };
        (conv, client, closed)
    }

    /// Seed only this test process's unlocked agent. There is no corresponding
    /// RPC, store row or environment switch. The caller must own the synthetic
    /// session and know its passphrase; membership and proof checks still run.
    #[cfg(target_os = "macos")]
    pub(super) async fn designate_fixture_approver(
        agent: &Agent,
        vault: deadbolt_core::VaultId,
        device: DeviceId,
        fixture_passphrase: Zeroizing<String>,
    ) -> Result<()> {
        let (conv, _socket, _open) = conversation();
        agent
            .experimental_approver_set(
                Some(&vault.to_string()),
                Some(&device.to_string()),
                Some(fixture_passphrase),
                &conv,
            )
            .await?;
        Ok(())
    }

    /// Manual two-stage proof: pair the fixture with the real phone, then read
    /// after biometric enrollment. This is a Mac test host, not a stock CLI
    /// operator: it opens only the synthetic fixture, invokes its production
    /// inviter internally, and designates via the test-only proof helper. The
    /// read goes through the unmodified Unix socket/audit-token boundary.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore = "requires an isolated synthetic fixture and a real foreground mobile device"]
    async fn paired_mobile_fixture_approval() -> Result<()> {
        use crate::protocol::{Check, Claim, Purpose};
        use anyhow::{anyhow, ensure};

        // The operator supplies the synthetic fixture. Never fall back to the
        // default store or accept arbitrary passphrases or item selectors.
        const PASS: &str = "synthetic-mobile-fixture-passphrase";
        const TITLE: &str = "Synthetic account 00000";
        const EXPECTED: &str = "synthetic-password-00000";
        let dir = std::path::PathBuf::from(
            std::env::var_os("DEADBOLT_MOBILE_FIXTURE_DIR")
                .context("set DEADBOLT_MOBILE_FIXTURE_DIR to the synthetic CLI fixture")?,
        );
        let expected_count = match dir.file_name().and_then(|name| name.to_str()) {
            Some("deadbolt-mobile-fixture-1000") => 1_000,
            Some("deadbolt-mobile-fixture-10000") => 10_000,
            _ => bail!("expected a named 1000- or 10000-item synthetic fixture"),
        };
        enum Stage {
            Pair(deadbolt_net::PairingCode),
            Read(DeviceId),
        }
        let stage = match (
            crate::config::test_env("DEADBOLT_MOBILE_PAIR_CODE").map(Zeroizing::new),
            crate::config::test_env("DEADBOLT_MOBILE_APPROVER_ID"),
        ) {
            (Some(code), None) => Stage::Pair(
                code.parse()
                    .map_err(|_| anyhow!("invalid five-word code"))?,
            ),
            (None, Some(id)) => Stage::Read(DeviceId::from_bytes(
                session::unhex(&id).map_err(|_| anyhow!("invalid phone device id"))?,
            )),
            _ => bail!(
                "supply exactly one of DEADBOLT_MOBILE_PAIR_CODE or DEADBOLT_MOBILE_APPROVER_ID"
            ),
        };
        let loaded = Loaded::open(&dir, PASS.as_bytes()).map_err(|_| anyhow!("cannot open fixture: confirm stock fixture agent stopped and fixture passphrase matches"))?;
        ensure!(
            loaded.meta.device_name == "Synthetic fixture CLI"
                && loaded.vaults.len() == 1
                && loaded.unavailable.is_empty(),
            "wrong fixture identity"
        );
        let vault = loaded.resolve(None)?;
        let v = loaded.vault(&vault);
        ensure!(
            v.name() == "mobile-fixture" && v.is_member(&loaded.id),
            "not a current fixture vault"
        );
        match &stage {
            Stage::Pair(_) => ensure!(
                v.members().count() == 1,
                "pair mode requires the fresh, single-member fixture"
            ),
            Stage::Read(phone) => ensure!(
                v.members().count() == 2 && *phone != loaded.id && v.is_member(phone),
                "expected fixture CLI and named phone as the two paired members"
            ),
        }
        ensure!(
            v.iter_items().count() == expected_count,
            "wrong fixture item count"
        );
        let item = v
            .iter_items()
            .find(|i| {
                i.name.as_deref() == Some(TITLE)
                    && i.kind == "login"
                    && i.fields
                        .get("password")
                        .is_some_and(|f| f.value == EXPECTED)
            })
            .context("expected synthetic login missing")?
            .id;
        let refs = vec![format!("deadbolt://{vault}/{item}/password")];
        let runtime = tempfile::tempdir()?;
        let mut paths = test_paths(runtime.path());
        paths.data = dir;
        let env = crate::config::Environment::load();
        ensure!(
            !env.local_net,
            "unset DEADBOLT_NET=local for the real mobile peer"
        );
        let agent = Agent::new(paths, env.local_net, env.kdf);

        async fn request(agent: &Arc<Agent>, command: Command) -> Result<Message> {
            let (server, mut client) = UnixStream::pair()?;
            let (_, message) = tokio::try_join!(agent.clone().handle(server, MAX_LINE), async {
                let request = Request {
                    v: PROTOCOL_VERSION,
                    command,
                    claimed: Some(Claim {
                        caller: None,
                        opencode_session: Some("synthetic-mobile-approval-harness".into()),
                    }),
                };
                client
                    .write_all(&deadbolt_client::encode_json(b"", &request, b"\n")?)
                    .await?;
                let reply = request_line(&mut BufReader::new(&mut client), 64 * 1024)
                    .await?
                    .context("no reply")?;
                serde_json::from_str(&reply).map_err(|_| anyhow!("invalid reply"))
            })?;
            Ok(message)
        }
        let run = async {
            agent.start(loaded, None).await?;
            agent.wait_ready().await?;
            let phone = match stage {
                Stage::Read(phone) => phone,
                Stage::Pair(code) => {
                    let (conv, _socket, _open) = conversation();
                    println!("APPROVAL_HARNESS_READY phase=pair vault={vault}");
                    let paired =
                        pairing::pair(&agent, &conv, code.to_string(), Some(vault.to_string()))
                            .await?;
                    let Reply::Device { device, .. } = paired else {
                        bail!("pair did not return an admitted device")
                    };
                    let phone = DeviceId::from_bytes(session::unhex(&device.id)?);
                    agent.with_data(|s| {
                        let held = s.vault(&vault);
                        ensure!(
                            phone != s.id && held.is_member(&phone) && held.members().count() == 2,
                            "pair did not admit the remote member"
                        );
                        Ok(())
                    })?;
                    return Ok(format!(
                        "APPROVAL_HARNESS_PAIRED vault={vault} phone={phone}"
                    ));
                }
            };
            let Message::Ok {
                reply: Reply::Status(status),
            } = request(&agent, Command::Status).await?
            else {
                bail!("status failed")
            };
            ensure!(
                status.caller.check == Check::Signature
                    && status.caller.pid == std::process::id()
                    && status.caller.signature.is_some_and(|sig| sig.valid)
                    && !agent.can_verify(),
                "expected verified test host and no Mac biometric slot"
            );
            let plain = Command::Resolve {
                refs: refs.clone(),
                purpose: Purpose::Read,
            };
            let refused = request(&agent, plain).await?;
            ensure!(
                matches!(
                    refused,
                    Message::Error {
                        code: ErrorCode::Forbidden,
                        ..
                    }
                ),
                "ordinary AI resolve was not refused"
            );
            designate_fixture_approver(&agent, vault, phone, Zeroizing::new(PASS.into())).await?;
            let read = || Command::ExperimentalMobileRead { refs: refs.clone() };
            println!(
                "APPROVAL_HARNESS_READY phase=allow caller=verified-mac-test-host vault={vault} phone={phone} item={item} field=password"
            );
            let first = request(&agent, read()).await?;
            let Message::Ok {
                reply: Reply::Secrets { secrets },
            } = first
            else {
                bail!("first phone read was not approved")
            };
            ensure!(
                matches!(secrets.as_slice(), [s] if s.item == item.to_string() && s.vault == "mobile-fixture" && s.title == TITLE && s.field == "password" && s.value.expose() == EXPECTED),
                "answer did not release exactly the requested fixture field"
            );
            drop(secrets);
            println!(
                "APPROVAL_HARNESS_READY phase=deny first_release_count=1 phone={phone} item={item} field=password"
            );
            // The SAME read must ask again. Only a signed denial passes, not a
            // timeout, offline phone, local failure or an already-consumed allow.
            let second = request(&agent, read()).await?;
            ensure!(
                matches!(second, Message::Error {code: ErrorCode::Forbidden, message, ..} if message.ends_with("read denied on approver")),
                "second read did not receive a signed denial"
            );
            Ok::<_, anyhow::Error>(
                "APPROVAL_HARNESS_PASS ordinary=refused first=one_field second=signed_denial"
                    .into(),
            )
        };
        let result = tokio::time::timeout(Duration::from_secs(240), run).await;
        tokio::time::timeout(Duration::from_secs(10), agent.lock())
            .await
            .context("fixture shutdown timed out")?;
        println!("{}", result.context("phone proof exceeded 240 seconds")??);
        Ok(())
    }

    /// Add one origin-matched login to the already paired 10k Safari fixture.
    /// Prepare offline first; serve only the replayed item on the ordinary network.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore = "requires an explicitly named, paired synthetic Safari fixture"]
    async fn paired_mobile_fixture_otp() -> Result<()> {
        use anyhow::ensure;
        use deadbolt_core::{Field, FieldType};
        use std::collections::BTreeMap;

        const TITLE: &str = "Synthetic OTP Safari";
        let dir = std::path::PathBuf::from(
            std::env::var_os("DEADBOLT_MOBILE_FIXTURE_DIR").context("set the fixture directory")?,
        );
        ensure!(
            dir.is_absolute()
                && dir.file_name().and_then(|s| s.to_str())
                    == Some("deadbolt-mobile-fixture-10000"),
            "expected an absolute, named 10k fixture directory"
        );
        let phone = DeviceId::from_bytes(session::unhex(
            &crate::config::env("DEADBOLT_MOBILE_APPROVER_ID")
                .context("set the paired phone ID")?,
        )?);
        let serve = match crate::config::env("DEADBOLT_MOBILE_OTP_STAGE").as_deref() {
            Ok("prepare") => false,
            Ok("serve") => true,
            _ => bail!("set DEADBOLT_MOBILE_OTP_STAGE to prepare or serve"),
        };
        let open = || Loaded::open(&dir, b"synthetic-mobile-fixture-passphrase");
        let fields = |username: String, password: String, url: String| {
            BTreeMap::from([
                ("username".into(), Field::new(FieldType::Text, username)),
                ("password".into(), Field::new(FieldType::Secret, password)),
                ("url".into(), Field::new(FieldType::Url, url)),
                ("otp".into(), Field::new(FieldType::Otp, "JBSWY3DPEHPK3PXP")),
            ])
        };
        let otp = fields(
            "synthetic-otp@example.test".into(),
            "synthetic-password-otp".into(),
            "https://deadbolt-otp.i.vogel.dev".into(),
        );
        let inspect = |loaded: &Loaded| -> Result<_> {
            ensure!(
                loaded.meta.device_name == "Synthetic fixture CLI"
                    && loaded.vaults.len() == 1
                    && loaded.unavailable.is_empty(),
                "wrong fixture identity"
            );
            let vault = loaded.resolve(None)?;
            let v = loaded.vault(&vault);
            ensure!(
                v.name() == "mobile-fixture"
                    && phone != loaded.id
                    && v.members().count() == 2
                    && v.is_member(&loaded.id)
                    && v.is_member(&phone),
                "expected the fixture CLI and named phone as the only members"
            );
            let mut numbered: HashSet<_> = (0..10_000).map(|n| format!("{n:05}")).collect();
            let mut existing = None;
            for item in v.iter_items() {
                // The phone may also have synced its separate passkey fixture.
                if item.kind == "passkey" {
                    continue;
                }
                ensure!(item.kind == "login", "unexpected fixture item kind");
                if item.name.as_deref() == Some(TITLE) {
                    ensure!(
                        item.fields == otp && existing.replace(item.id).is_none(),
                        "wrong or duplicate Safari login"
                    );
                    continue;
                }
                let n = item
                    .name
                    .as_deref()
                    .and_then(|n| n.strip_prefix("Synthetic account "))
                    .context("unexpected login in synthetic fixture")?;
                ensure!(
                    numbered.remove(n)
                        && item.fields
                            == fields(
                                format!("synthetic-{n}@example.test"),
                                format!("synthetic-password-{n}"),
                                format!("https://site-{n}.example.test")
                            ),
                    "wrong or duplicate numbered fixture login"
                );
            }
            ensure!(numbered.is_empty(), "missing numbered fixture login");
            Ok((vault, existing))
        };
        let mut loaded = open()?;
        let (vault, existing) = inspect(&loaded)?;
        if !serve {
            let item = match existing {
                Some(item) => item,
                None => loaded.update(vault, |write, key| {
                    Ok(write
                        .create_item(key, "login", Some(TITLE.into()), otp.clone())?
                        .0)
                })?,
            };
            drop(loaded);
            ensure!(
                inspect(&open()?)? == (vault, Some(item)),
                "signed login failed durable replay"
            );
            println!(
                "OTP_FIXTURE_PREPARED item={item} logins=10001 appended={}",
                existing.is_none()
            );
            return Ok(());
        }
        let item = existing.context("prepare the fixture offline before serving")?;
        let runtime = tempfile::tempdir()?;
        let mut paths = test_paths(runtime.path());
        paths.data = dir;
        let env = crate::config::Environment::load();
        ensure!(
            !env.local_net,
            "unset DEADBOLT_NET=local for the real mobile peer"
        );
        let agent = Agent::new(paths, env.local_net, env.kdf);
        let run = async {
            agent.start(loaded, None).await?;
            agent.wait_ready().await?;
            println!("OTP_FIXTURE_SERVING item={item} logins=10001 seconds=300");
            tokio::time::sleep(Duration::from_secs(300)).await;
            Ok(())
        };
        let result = tokio::time::timeout(Duration::from_secs(360), run).await;
        tokio::time::timeout(Duration::from_secs(10), agent.lock())
            .await
            .context("fixture shutdown timed out")?;
        result.context("fixture serving timed out")?
    }

    fn sync_op() -> Command {
        Command::SyncOnePassword {
            vault: None,
            account: None,
            op_vaults: Vec::new(),
            dry_run: false,
        }
    }

    async fn started(pid: &std::path::Path) -> String {
        for _ in 0..200 {
            if let Ok(pid) = fs::read_to_string(pid)
                && !pid.trim().is_empty()
            {
                return pid.trim().to_string();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("op never ran");
    }

    #[tokio::test]
    async fn the_idle_lock_stops_a_stuck_sync_from_1password() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, pid) = syncing_agent(dir.path()).await;
        let (conv, _client, _closed) = conversation();
        let syncing = {
            let agent = agent.clone();
            tokio::spawn(async move { agent.dispatch(&caller::nobody(), sync_op(), &conv).await })
        };
        let pid = started(&pid).await;

        // One at a time.
        let (conv, _client, _closed) = conversation();
        let error = agent
            .clone()
            .dispatch(&caller::nobody(), sync_op(), &conv)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "already syncing from 1Password: try again when it finishes"
        );

        // It does not hold the vault open.
        {
            let mut idle = agent.idle.lock().unwrap();
            idle.timeout = Some(Duration::from_secs(1));
            idle.deadline = Some(Instant::now());
        }
        agent.check_idle().await;
        assert!(!agent.status().unlocked);
        let error = syncing.await.unwrap().unwrap_err();
        let error = error.downcast::<AgentError>().unwrap();
        assert_eq!(error.code, ErrorCode::Locked);
        assert_eq!(error.message, INTERRUPTED);
        assert!(mirror::tests::gone(&pid).await, "op {pid} still running");
    }

    #[tokio::test]
    async fn a_client_that_goes_away_stops_its_sync_from_1password() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, pid) = syncing_agent(dir.path()).await;
        let (conv, _client, closed) = conversation();
        let syncing = {
            let agent = agent.clone();
            tokio::spawn(async move { agent.dispatch(&caller::nobody(), sync_op(), &conv).await })
        };
        let pid = started(&pid).await;
        closed.send_replace(true);
        let error = syncing.await.unwrap().unwrap_err();
        assert_eq!(error.to_string(), "the sync from 1Password was cancelled");
        assert!(mirror::tests::gone(&pid).await, "op {pid} still running");
        assert!(agent.status().unlocked);
        agent.lock().await;
    }

    fn make_valid_biometric_token(now_secs: u64) -> Vec<u8> {
        let mut token = Vec::new();
        token.extend_from_slice(b"DBSE");
        token.push(1); // version
        token.push(1); // FLAG_BIOMETRY_CURRENT_SET
        token.extend_from_slice(&now_secs.to_le_bytes());
        token.extend_from_slice(b"payload");
        token
    }

    #[tokio::test]
    async fn touch_id_set_off_clears_slot_and_updates_status() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = Loaded::setup(
            dir.path(),
            b"test",
            "device",
            deadbolt_store::KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        let now = session::now();
        let token = make_valid_biometric_token(now);
        let bio_key = deadbolt_store::generate_biometric_key().unwrap();
        loaded.store.set_biometric(&bio_key, &token).unwrap();
        drop(loaded);

        let agent = locked_agent(dir.path());
        *agent.touch_id_available_override.lock().unwrap() = Some(true);
        crate::config::set_touch_id(&agent.paths.config, true).unwrap();

        // While another handle holds `store.redb` open, `agent.status()` still
        // reports `touch_id_ready = true` from in-memory metadata without
        // opening the store or hitting `Error::InUse`.
        let held = deadbolt_store::unlock(dir.path(), b"test").unwrap();
        let before = agent.status();
        assert!(before.touch_id_available);
        assert!(before.touch_id_enabled);
        assert!(before.touch_id_ready);
        assert!(!before.touch_id_reset);
        drop(held);

        agent.set_touch_id(false).await.unwrap();
        assert!(!Config::load(&agent.paths.config).unwrap().touch_id());
        assert!(
            deadbolt_store::biometric_token(dir.path())
                .unwrap()
                .is_none()
        );
        let st = agent.status();
        assert!(st.touch_id_available);
        assert!(!st.touch_id_enabled);
        assert!(!st.touch_id_ready);
        assert!(!st.touch_id_reset);
    }

    #[tokio::test]
    async fn touch_id_coalesces_overlapping_requests_and_cancels_on_passphrase_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let fast = deadbolt_store::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        };
        let loaded = Loaded::setup(dir.path(), b"test", "device", fast).unwrap();
        let now = session::now();
        let token = make_valid_biometric_token(now);
        let bio_key = deadbolt_store::generate_biometric_key().unwrap();
        loaded.store.set_biometric(&bio_key, &token).unwrap();
        drop(loaded);

        let agent = Agent::new(test_paths(dir.path()), true, fast);
        *agent.touch_id_available_override.lock().unwrap() = Some(true);
        crate::config::set_touch_id(&agent.paths.config, true).unwrap();

        // 1. Two overlapping `unlock_biometric` calls coalesce onto one unseal invocation.
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_hook = calls.clone();
        let key_copy = *bio_key;
        *agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |_cancel| {
            calls_for_hook.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(80));
            Ok(Zeroizing::new(key_copy))
        }));

        let a1 = agent.clone();
        let a2 = agent.clone();
        let (r1, r2) = tokio::join!(a1.unlock_biometric(None), a2.unlock_biometric(None));
        r1.unwrap();
        r2.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(agent.status().unlocked);
        agent.lock().await;

        // 2. A cancelled prompt sets a short cooldown so an immediate retry is
        // rejected without invoking the helper again.
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls_hook = cancel_calls.clone();
        *agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |_cancel| {
            cancel_calls_hook.fetch_add(1, Ordering::SeqCst);
            Err(biometric::UnlockError::Cancelled)
        }));
        assert!(agent.unlock_biometric(None).await.is_err());
        assert!(agent.unlock_biometric(None).await.is_err());
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);

        // 3. Programmatic cancellation (e.g. `lock()`) does not arm the user-cancel
        // cooldown, so the next `unlock_biometric` call runs immediately.
        *agent.biometric_cooldown_until.lock().unwrap() = None;
        *agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |cancel| {
            while !cancel.is_cancelled() {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(biometric::UnlockError::Cancelled)
        }));
        let bio_agent = agent.clone();
        let bio_task = tokio::spawn(async move { bio_agent.unlock_biometric(None).await });
        tokio::time::sleep(Duration::from_millis(40)).await;
        agent.lock().await;
        assert!(bio_task.await.unwrap().is_err());
        assert!(
            agent.biometric_cooldown_until.lock().unwrap().is_none(),
            "programmatic cancel must not set user-cancel cooldown"
        );

        // 4. An `Invalidated` error from a cancelled flight (or when the stored token
        // no longer matches the unsealed token) must not wipe the current slot.
        *agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |cancel| {
            cancel.cancel();
            Err(biometric::UnlockError::Invalidated("stale flight".into()))
        }));
        assert!(agent.unlock_biometric(None).await.is_err());
        assert!(
            deadbolt_store::biometric_token(dir.path())
                .unwrap()
                .is_some(),
            "cancelled flight must not clear biometric slot"
        );
        assert!(agent.status().touch_id_ready);
        assert!(!agent.status().touch_id_reset);

        // 5. A passphrase unlock cancels an in-flight biometric prompt and clears cooldown.
        *agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |cancel| {
            while !cancel.is_cancelled() {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(biometric::UnlockError::Cancelled)
        }));
        let bio_agent = agent.clone();
        let bio_task = tokio::spawn(async move { bio_agent.unlock_biometric(None).await });
        tokio::time::sleep(Duration::from_millis(40)).await;
        agent
            .unlock(Zeroizing::new("test".into()), None)
            .await
            .unwrap();
        assert!(bio_task.await.unwrap().is_err());
        assert!(agent.status().unlocked);
        agent.lock().await;

        // 6. A genuine `Invalidated` error clears the matching slot and marks
        // `touch_id_reset = true`, whereas a fresh store with `touch_id = true`
        // that has never enrolled has `touch_id_reset = false`.
        *agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |_cancel| {
            Err(biometric::UnlockError::Invalidated(
                "biometry changed".into(),
            ))
        }));
        assert!(agent.unlock_biometric(None).await.is_err());
        let reset_st = agent.status();
        assert!(reset_st.touch_id_enabled);
        assert!(!reset_st.touch_id_ready);
        assert!(reset_st.touch_id_reset);

        let never_dir = tempfile::tempdir().unwrap();
        drop(Loaded::setup(never_dir.path(), b"test", "device", fast).unwrap());
        let never_agent = Agent::new(test_paths(never_dir.path()), true, fast);
        *never_agent.touch_id_available_override.lock().unwrap() = Some(true);
        crate::config::set_touch_id(&never_agent.paths.config, true).unwrap();
        let never_st = never_agent.status();
        assert!(never_st.touch_id_enabled);
        assert!(!never_st.touch_id_ready);
        assert!(
            !never_st.touch_id_reset,
            "never-enrolled store must not report touch_id_reset"
        );
    }

    /// Unlocking (locked or not) and the proof for pairing share one backoff:
    /// past five wrong passphrases even the right one waits, `rate-limited`.
    #[tokio::test]
    async fn every_passphrase_check_shares_one_backoff() {
        let dir = tempfile::tempdir().unwrap();
        let fast = deadbolt_store::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        };
        let agent = Agent::new(test_paths(dir.path()), true, fast);
        let pass = |text: &str| Zeroizing::new(text.to_string());
        agent.setup(pass("test"), "laptop".into()).await.unwrap();
        agent.lock().await;
        for _ in 1..guesses::FREE_FAILURES {
            let error = agent.unlock(pass("wrong"), None).await.unwrap_err();
            assert!(wrong_passphrase(&error), "{error:#}");
        }
        // A right one resets the count.
        agent.unlock(pass("test"), Some(60)).await.unwrap();
        // Wrong ones while unlocked (asking for a longer timeout) count
        // too, and so do locked ones.
        for _ in 0..3 {
            let error = agent.unlock(pass("wrong"), Some(0)).await.unwrap_err();
            assert!(wrong_passphrase(&error), "{error:#}");
        }
        agent.lock().await;
        for _ in 0..2 {
            assert!(agent.unlock(pass("wrong"), None).await.is_err());
        }
        let error = agent.unlock(pass("test"), None).await.unwrap_err();
        assert_eq!(crate::client::code(&error), Some(ErrorCode::RateLimited));
        assert_eq!(
            error.to_string(),
            "Too many wrong passphrases. Try again in 30 s."
        );
        assert!(!agent.status().unlocked);
    }

    /// Unlocking while unlocked may shorten the idle timeout as it is; a
    /// longer one, or never, takes the right passphrase or a Touch ID prompt.
    /// And a passphrase that doesn't open the store never cancels a prompt.
    #[tokio::test]
    async fn an_unverified_unlock_only_shortens_the_idle_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let fast = deadbolt_store::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        };
        let loaded = Loaded::setup(dir.path(), b"test", "device", fast).unwrap();
        let token = make_valid_biometric_token(session::now());
        let bio_key = deadbolt_store::generate_biometric_key().unwrap();
        loaded.store.set_biometric(&bio_key, &token).unwrap();
        drop(loaded);
        let agent = Agent::new(test_paths(dir.path()), true, fast);
        *agent.touch_id_available_override.lock().unwrap() = Some(true);
        crate::config::set_touch_id(&agent.paths.config, true).unwrap();

        let prompts = Arc::new(AtomicUsize::new(0));
        let finger = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let key = *bio_key;
        let (counted, touched) = (prompts.clone(), finger.clone());
        *agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |_cancel| {
            counted.fetch_add(1, Ordering::SeqCst);
            if touched.load(Ordering::SeqCst) {
                Ok(Zeroizing::new(key))
            } else {
                Err(biometric::UnlockError::Cancelled)
            }
        }));
        let timeout = || agent.idle.lock().unwrap().timeout.map(|t| t.as_secs());
        let pass = |text: &str| Zeroizing::new(text.to_string());

        agent.unlock_biometric(Some(3600)).await.unwrap();
        assert_eq!((prompts.load(Ordering::SeqCst), timeout()), (1, Some(3600)));

        agent.unlock(pass("wrong"), Some(600)).await.unwrap();
        assert_eq!(timeout(), Some(600));
        for longer in [Some(7200), Some(0)] {
            let error = agent.unlock(pass("wrong"), longer).await.unwrap_err();
            assert!(error.to_string().contains("wrong passphrase"), "{error}");
            assert_eq!(timeout(), Some(600));
        }
        agent.unlock(pass("test"), Some(7200)).await.unwrap();
        assert_eq!(timeout(), Some(7200));
        agent.unlock(pass("test"), Some(0)).await.unwrap();
        assert_eq!(timeout(), None);

        agent.unlock_biometric(Some(60)).await.unwrap();
        assert_eq!((prompts.load(Ordering::SeqCst), timeout()), (1, Some(60)));
        finger.store(false, Ordering::SeqCst);
        assert!(agent.unlock_biometric(Some(0)).await.is_err());
        assert_eq!((prompts.load(Ordering::SeqCst), timeout()), (2, Some(60)));
        *agent.biometric_cooldown_until.lock().unwrap() = None;
        finger.store(true, Ordering::SeqCst);
        agent.unlock_biometric(Some(0)).await.unwrap();
        assert_eq!((prompts.load(Ordering::SeqCst), timeout()), (3, None));
        assert!(agent.status().unlocked);

        agent.lock().await;
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let released = release.clone();
        *agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |cancel| {
            loop {
                if cancel.is_cancelled() {
                    return Err(biometric::UnlockError::Cancelled);
                }
                if released.load(Ordering::SeqCst) {
                    return Ok(Zeroizing::new(key));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }));
        let bio_agent = agent.clone();
        let bio_task = tokio::spawn(async move { bio_agent.unlock_biometric(None).await });
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(agent.unlock(pass("wrong"), None).await.is_err());
        release.store(true, Ordering::SeqCst);
        bio_task.await.unwrap().unwrap();
        assert!(agent.status().unlocked);
        agent.lock().await;
    }
}

#[derive(Default)]
struct Idle {
    timeout: Option<Duration>,
    deadline: Option<Instant>,
}

/// Whether `error` says the passphrase was wrong.
fn wrong_passphrase(error: &anyhow::Error) -> bool {
    error.chain().any(|e| {
        matches!(
            e.downcast_ref::<deadbolt_store::Error>(),
            Some(deadbolt_store::Error::WrongPassphrase)
        )
    })
}

fn fail(code: ErrorCode, message: impl Into<String>) -> anyhow::Error {
    AgentError {
        code,
        message: message.into(),
        grant: None,
        passkeys: None,
    }
    .into()
}

pub async fn serve(paths: Paths) -> Result<()> {
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
        Err(TryLockError::WouldBlock) => bail!("the agent is already running"),
        Err(TryLockError::Error(error)) => return Err(error).context("locking the agent"),
    }
    remove_socket(&paths.socket)?;
    let listener = UnixListener::bind(&paths.socket)
        .with_context(|| format!("binding {}", paths.socket.display()))?;
    fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600))?;

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
    let agent = Agent::new(paths, local_net, env.kdf);
    let mut autofill = macos_autofill::bind_default().await;
    agent.start_ssh_if_enabled();
    info!(
        pid = std::process::id(),
        version = %version(),
        local_net,
        autofill_socket = autofill.as_ref().map(|(_, p)| p.display().to_string()),
        "agent started"
    );
    let (system, events) = mpsc::channel(8);
    let _sources = system::spawn(system);
    let _follow = AbortOnDrop(tokio::spawn(agent.clone().follow_system(events)));

    let mut connections = JoinSet::new();
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accepting control connection")?;
                let agent = agent.clone();
                connections.spawn(async move { agent.handle(stream, MAX_LINE).await });
            }
            accepted = async {
                match autofill.as_ref() {
                    Some((autofill_listener, _)) => autofill_listener.accept().await,
                    None => std::future::pending().await,
                }
            } => {
                let (stream, _) = accepted.context("accepting macOS AutoFill connection")?;
                let agent = agent.clone();
                connections.spawn(async move {
                    agent
                        .handle_on(
                            stream,
                            crate::protocol::MAX_AUTOFILL_LINE,
                            macos_autofill::SocketKind::AutoFill,
                        )
                        .await
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => report_connection(result),
            _ = agent.shutdown.notified() => break,
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            _ = tick.tick() => agent.check_idle().await,
        }
    }
    info!("agent stopping");
    drop(listener);
    let autofill_socket = autofill.take().map(|(autofill_listener, path)| {
        drop(autofill_listener);
        path
    });
    agent.ssh.shutdown();
    agent.cancel_biometric_prompt();
    agent.interrupt_op();
    agent.watchers.stopping();
    agent.stop_sends().await;
    drain_connections(&mut connections).await;
    agent.lock().await;
    remove_socket(&socket)?;
    if let Some(autofill_socket) = autofill_socket {
        drop(remove_socket(&autofill_socket));
    }
    drop(lock);
    Ok(())
}

fn remove_socket(path: &std::path::Path) -> Result<()> {
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

async fn drain_connections(connections: &mut JoinSet<Result<()>>) {
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

/// Limit each line before buffering it, preserving buffered answers for the next read.
async fn request_line(
    read: &mut (impl AsyncBufRead + Unpin),
    max: usize,
) -> Result<Option<Zeroizing<String>>> {
    // Requests carry passphrases and whole exports: the line grows in a
    // buffer that is wiped, also when it is outgrown. Past `max` (plus a
    // `\r`) it stops growing and the rest of the line is skipped.
    let mut line = Zeroizing::new(Vec::new());
    let mut read_any = false;
    let mut too_large = false;
    loop {
        let bytes = read.fill_buf().await?;
        if bytes.is_empty() {
            break;
        }
        read_any = true;
        let newline = bytes.iter().position(|b| *b == b'\n');
        let end = newline.unwrap_or(bytes.len());
        if !too_large && line.len() + end > max + 1 {
            too_large = true;
            line = Zeroizing::new(Vec::new());
        }
        if !too_large {
            export::append(&mut line, &bytes[..end], max + 1);
        }
        read.consume(newline.map_or(end, |i| i + 1));
        if newline.is_some() {
            break;
        }
    }
    if !read_any {
        return Ok(None);
    }
    if line.ends_with(b"\r") {
        line.pop();
    }
    if too_large || line.len() > max {
        return Err(fail(ErrorCode::Failed, "request too large"));
    }
    match String::from_utf8(std::mem::take(&mut *line)) {
        Ok(line) => Ok(Some(Zeroizing::new(line))),
        Err(error) => {
            drop(Zeroizing::new(error.into_bytes()));
            Err(fail(ErrorCode::Failed, "invalid request: not UTF-8"))
        }
    }
}

/// Why a request isn't valid, by position only: serde's messages can
/// quote the values in it.
fn invalid_request(error: &serde_json::Error) -> anyhow::Error {
    let what = match error.classify() {
        serde_json::error::Category::Io => "unreadable",
        serde_json::error::Category::Syntax => "not valid JSON",
        serde_json::error::Category::Data => "not a request this agent knows",
        serde_json::error::Category::Eof => "cut short",
    };
    fail(
        ErrorCode::Failed,
        format!(
            "invalid request: {what} (line {} column {})",
            error.line(),
            error.column()
        ),
    )
}

/// One control connection: sends events and reads answers.
pub struct Conversation {
    write: tokio::sync::Mutex<OwnedWriteHalf>,
    answers: tokio::sync::Mutex<mpsc::Receiver<Answer>>,
    closed: watch::Receiver<bool>,
}

impl Conversation {
    async fn send(&self, message: &Message) -> Result<()> {
        // Replies carry secrets.
        let body = deadbolt_client::encode_json(b"", message, b"\n")?;
        tokio::time::timeout(IO_TIMEOUT, async {
            self.write.lock().await.write_all(&body).await
        })
        .await??;
        Ok(())
    }

    pub async fn event(&self, event: Event) -> Result<()> {
        self.send(&Message::Event { event }).await
    }

    /// Sends an event and waits for the client's answer; `None` if it hangs up.
    pub async fn ask(&self, event: Event) -> Option<Answer> {
        self.event(event).await.ok()?;
        self.answers.lock().await.recv().await
    }

    /// Resolves once the client hangs up.
    pub async fn closed(&self) {
        let mut closed = self.closed.clone();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "a dropped sender also means the connection closed"
        )]
        let _ = closed.wait_for(|closed| *closed).await;
    }
}

impl Agent {
    async fn handle(self: Arc<Self>, stream: UnixStream, max_line: usize) -> Result<()> {
        self.handle_on(stream, max_line, macos_autofill::SocketKind::Control)
            .await
    }

    async fn handle_on(
        self: Arc<Self>,
        stream: UnixStream,
        max_line: usize,
        socket: macos_autofill::SocketKind,
    ) -> Result<()> {
        // The socket's directory keeps other users out; this holds even if
        // it didn't. (macOS keeps a peer's uid, but not its audit token, once
        // it hangs up.)
        match deadbolt_client::peer::uid(&stream) {
            Ok(uid) if uid == rustix::process::getuid().as_raw() => {}
            Ok(uid) => bail!("refused a connection from uid {uid}: not this user"),
            Err(error) => bail!("refused a connection: reading its credentials: {error}"),
        }
        let peer = deadbolt_client::peer::Peer::of(&stream);
        let (read, write) = stream.into_split();
        let mut read = BufReader::new(read);
        let request =
            match tokio::time::timeout(IO_TIMEOUT, request_line(&mut read, max_line)).await? {
                Ok(Some(line)) => {
                    serde_json::from_str::<Request>(&line).map_err(|e| invalid_request(&e))
                }
                Ok(None) => return Ok(()),
                Err(error) => Err(error),
            };
        let (answers_tx, answers) = mpsc::channel(4);
        let (closed_tx, closed) = watch::channel(false);
        let _reader = AbortOnDrop(tokio::spawn(async move {
            while let Ok(Some(line)) = request_line(&mut read, max_line).await {
                let Ok(answer) = serde_json::from_str::<Answer>(&line) else {
                    break;
                };
                if answers_tx.send(answer).await.is_err() {
                    break;
                }
            }
            closed_tx.send_replace(true);
        }));
        let conversation = Conversation {
            write: tokio::sync::Mutex::new(write),
            answers: tokio::sync::Mutex::new(answers),
            closed,
        };
        let mut stop = false;
        let result = match request {
            Ok(Request {
                v,
                command: Command::Watch { app },
                ..
            }) if v == protocol() && socket == macos_autofill::SocketKind::Control => {
                return self.watch(&conversation, app).await;
            }
            Ok(request) => {
                let asked_stop = matches!(request.command, Command::Stop);
                let always = matches!(request.command, Command::Status | Command::Stop);
                if request.v != protocol() && !always {
                    Err(fail(
                        ErrorCode::Version,
                        format!(
                            "the agent speaks protocol {}, not {}; run `deadbolt agent stop`",
                            protocol(),
                            request.v
                        ),
                    ))
                } else {
                    let (result, entry) = self
                        .clone()
                        .answer(socket, peer, request, &conversation)
                        .await;
                    // Recorded before the reply goes: a client that never
                    // reads it, or the agent stopping, can't lose the entry.
                    if let Some(entry) = entry {
                        self.record(entry);
                    }
                    stop = asked_stop && result.is_ok();
                    result
                }
            }
            Err(error) => Err(error),
        };
        let message = match result {
            Ok(reply) => Message::Ok { reply },
            Err(error) => match error.downcast::<AgentError>() {
                Ok(error) => Message::Error {
                    code: error.code,
                    message: error.message,
                    grant: error.grant,
                    passkeys: error.passkeys,
                },
                Err(error) => Message::Error {
                    code: ErrorCode::Failed,
                    message: format!("{error:#}"),
                    grant: None,
                    passkeys: None,
                },
            },
        };
        let sent = async {
            conversation.send(&message).await?;
            conversation.write.lock().await.shutdown().await?;
            Ok(())
        }
        .await;
        if stop {
            self.shutdown.notify_one();
        }
        sent
    }

    async fn dispatch(
        self: Arc<Self>,
        caller: &CallerInfo,
        command: Command,
        conv: &Conversation,
    ) -> Result<Reply> {
        if matches!(command, Command::Status | Command::Stop) {
            return self.run(command, conv).await;
        }
        self.ai_gate(caller, &command, conv).await?;
        // A one-time code isn't use: a client showing one asks every period,
        // which would otherwise hold the vault open for as long as it shows.
        // Nor is a browser looking at a page: it asks for every page loaded.
        // Nor are sends, which never touch the vault, nor SSH keygen/inspect.
        // Nor is bringing the app forward.
        let send = matches!(
            command,
            Command::SendCreate { .. }
                | Command::SendList
                | Command::SendShow { .. }
                | Command::SendRevoke { .. }
                | Command::SendWait { .. }
                | Command::SshGenerate { .. }
                | Command::SshInspect { .. }
        );
        let used = !send
            && !matches!(
                command,
                Command::ItemCode { .. }
                    | Command::SiteLogins { .. }
                    | Command::SiteCheck { .. }
                    | Command::FormItems { .. }
                    | Command::PasskeyList { .. }
                    | Command::SiteGenerateCheck { .. }
                    | Command::SiteGenerateDrop { .. }
                    | Command::AppActivate { .. }
                    // An AI signing in unattended mustn't hold the vault open.
                    | Command::AgentLogins { .. }
                    | Command::AgentFill { .. }
                    | Command::AgentPasskeyGet { .. }
                    // macOS AutoFill lookups run in the background without use.
                    | Command::AutofillStatus
                    | Command::AutofillIdentities
                    | Command::AutofillList { .. }
                    | Command::SshSign { .. }
            );
        // Nor does a sync from 1Password hold the vault open: `op` may hang,
        // and a lock stops it before it writes anything. Nor does waiting
        // for a send to be picked up, or for an app to start.
        let busy = !matches!(
            command,
            Command::SyncOnePassword { .. }
                | Command::SendWait { .. }
                | Command::AppActivate { .. }
        );
        if busy {
            self.busy.fetch_add(1, Ordering::SeqCst);
        }
        if used {
            self.touch();
        }
        let result = self.clone().run(command, conv).await;
        if used {
            self.touch();
        }
        if busy {
            self.busy.fetch_sub(1, Ordering::SeqCst);
        }
        result
    }

    async fn run(self: Arc<Self>, command: Command, conv: &Conversation) -> Result<Reply> {
        match command {
            Command::Status => Ok(Reply::Status(Box::new(self.status()))),
            Command::Stop => {
                self.cancel_biometric_prompt();
                Ok(Reply::Done)
            }
            Command::Setup {
                passphrase,
                device_name,
            } => {
                self.setup(passphrase, device_name).await?;
                Ok(Reply::Done)
            }
            Command::Unlock {
                passphrase,
                timeout_secs,
            } => {
                self.unlock(passphrase, timeout_secs).await?;
                Ok(Reply::Done)
            }
            Command::UnlockBiometric { timeout_secs } => {
                let outcome = tokio::select! {
                    res = self.unlock_biometric(timeout_secs) => res,
                    () = conv.closed() => return Err(fail(ErrorCode::Cancelled, "the request was cancelled")),
                };
                match outcome {
                    Ok(()) => Ok(Reply::Done),
                    Err(error) if macos_autofill::is_biometric_cancelled(&error) => {
                        Err(fail(ErrorCode::Cancelled, error.to_string()))
                    }
                    Err(error) => Err(error),
                }
            }
            Command::TouchIdSet { enabled } => {
                self.set_touch_id(enabled).await?;
                Ok(Reply::Done)
            }
            Command::Lock => {
                self.lock().await;
                Ok(Reply::Done)
            }
            Command::Watch { .. } => bail!("watch streams on a connection of its own"),
            Command::AppActivate { token } => Ok(if self.watchers.activate(token).await {
                Reply::Activated
            } else {
                Reply::NoApp
            }),
            Command::ActivityReport { .. } => bail!("reports are answered as they arrive"),
            Command::ActivityList {
                since,
                limit,
                before,
            } => self.activity_list(since, limit, before),
            Command::VaultCreate { name } => {
                let vault = self.with(|s| {
                    let id = s.create_vault(&name)?;
                    Ok(s.vault_info(&id))
                })?;
                Ok(Reply::Vault { vault })
            }
            Command::VaultList => Ok(Reply::Vaults {
                vaults: self.with(|s| Ok(s.vault_infos()))?,
            }),
            Command::VaultRename { vault, name } => {
                let vault = self.with(|s| {
                    let id = s.resolve(Some(&vault))?;
                    if s.name_taken(&name, Some(id)) {
                        bail!("a vault named {name} already exists");
                    }
                    s.update(id, |v, secret| {
                        v.rename(secret, name.clone()).context("renaming")
                    })?;
                    Ok(s.vault_info(&id))
                })?;
                self.sync_now.notify_one();
                Ok(Reply::Vault { vault })
            }
            Command::VaultDefault { vault } => {
                let vault = self.with(|s| {
                    let id = s.resolve(Some(&vault))?;
                    s.meta.default_vault = Some(id);
                    s.save_meta()?;
                    Ok(s.vault_info(&id))
                })?;
                Ok(Reply::Vault { vault })
            }
            Command::Devices { vault } => {
                let devices = self.with(|s| {
                    let id = s.resolve(vault.as_deref())?;
                    let connected: HashSet<PeerId> = s.node.connected_peers().into_iter().collect();
                    let mut devices: Vec<_> = s
                        .vault(&id)
                        .members()
                        .map(|member| s.device_info(&member, &connected))
                        .collect();
                    devices
                        .sort_by(|a, b| (!a.this, &a.name, &a.id).cmp(&(!b.this, &b.name, &b.id)));
                    Ok(devices)
                })?;
                Ok(Reply::Devices { devices })
            }
            Command::DeviceRemove { vault, device } => {
                let (vault, device) = self.with(|s| {
                    let id = s.resolve(vault.as_deref())?;
                    let target = s.resolve_device(&id, &device)?;
                    if target == s.id {
                        bail!("cannot remove this device; remove it from another device");
                    }
                    let info = s.device_info(&target, &HashSet::new());
                    s.update(id, |v, secret| {
                        v.remove(secret, target).context("removing device")
                    })?;
                    self.refresh(s);
                    Ok((s.vault_info(&id), info))
                })?;
                self.sync_now.notify_one();
                Ok(Reply::Device { vault, device })
            }
            Command::Sync { vault } => {
                let only =
                    self.with(|s| vault.as_deref().map(|v| s.resolve(Some(v))).transpose())?;
                self.wait_ready().await?;
                Ok(Reply::Sync {
                    peers: sync::sync_all(&self, only).await?,
                })
            }
            Command::Join {
                device_name,
                passphrase,
            } => pairing::join(&self, conv, device_name, passphrase).await,
            Command::Pair { code, vault } => pairing::pair(&self, conv, code, vault).await,
            Command::ItemGet {
                vault,
                query,
                otp,
                ssh_private,
                files,
                deleted,
            } => Ok(Reply::Item {
                item: self.with(|s| {
                    items::get(
                        s,
                        vault.as_deref(),
                        &query,
                        otp,
                        ssh_private,
                        &files,
                        deleted,
                    )
                })?,
            }),
            Command::ItemCode { vault, query } => Ok(Reply::Code {
                code: self.with(|s| {
                    items::code(s, vault.as_deref(), &query, crate::config::wall_clock())
                })?,
            }),
            Command::ItemList {
                vault,
                query,
                kind,
                deleted,
                tags,
                favorites,
            } => Ok(Reply::Items {
                items: self.with(|s| {
                    items::list_filtered(
                        s,
                        vault.as_deref(),
                        &query,
                        kind.as_deref(),
                        deleted,
                        &tags,
                        favorites,
                    )
                })?,
            }),
            Command::TagList { vault } => Ok(Reply::Tags {
                tags: self.with(|s| items::tags(s, vault.as_deref()))?,
            }),
            Command::ItemNew {
                vault,
                kind,
                name,
                fields,
                favorite,
                tags,
            } => self.item_write(|s| {
                items::create_with(s, vault.as_deref(), &kind, name, fields, favorite, tags)
            }),
            Command::ItemSet {
                vault,
                query,
                fields,
                name,
                unset,
                favorite,
                add_tags,
                remove_tags,
            } => self.item_write(|s| {
                items::set_with(
                    s,
                    vault.as_deref(),
                    &query,
                    fields,
                    name,
                    &unset,
                    favorite,
                    &add_tags,
                    &remove_tags,
                )
            }),
            Command::ItemUnset {
                vault,
                query,
                field,
            } => self.item_write(|s| items::unset(s, vault.as_deref(), &query, &field)),
            Command::ItemRemove { vault, query } => {
                // Resolve once before consent: a renamed item, default-vault
                // change or sync during Touch ID must not retarget the delete.
                let (vault, id, passkey) = self.with(|s| {
                    let vault = s.resolve(vault.as_deref())?;
                    let item = items::find_live(s.vault(&vault), &query)?;
                    Ok((vault, item.id, item.kind == "passkey"))
                })?;
                if passkey {
                    self.verify_user(
                        conv,
                        crate::protocol::Verify::Preferred,
                        "delete a saved passkey",
                    )
                    .await?;
                }
                self.item_write(|s| items::remove_id(s, vault, id))
            }
            Command::ItemRestore { vault, query } => {
                self.item_write(|s| items::restore(s, vault.as_deref(), &query))
            }
            Command::Import {
                vault,
                export,
                files,
                apply,
            } => {
                // Mapping needs no session: it runs before taking the lock.
                let parsed = crate::import::parse_with(&export, &files)?;
                drop((export, files));
                let report = self.with(|s| items::import(s, vault.as_deref(), parsed, apply))?;
                if apply {
                    self.sync_now.notify_one();
                }
                Ok(Reply::Import { report })
            }
            Command::SyncOnePassword {
                vault,
                account,
                op_vaults,
                dry_run,
            } => {
                let Ok(_syncing) = self.syncing_op.try_lock() else {
                    bail!("already syncing from 1Password: try again when it finishes");
                };
                let mut interrupts = self.interrupts.subscribe();
                // Locked fails here, before 1Password is asked anything. `op`
                // runs outside the lock: it may wait on 1Password's prompt.
                let known = self.with(|s| mirror::known(s, vault.as_deref()))?;
                let fetch = mirror::fetch(self.op(), account.as_deref(), &op_vaults, &known);
                // Dropping the fetch kills `op`.
                let fetched = tokio::select! {
                    fetched = fetch => fetched?,
                    _ = interrupts.changed() => return Err(fail(ErrorCode::Locked, INTERRUPTED)),
                    () = conv.closed() => bail!("the sync from 1Password was cancelled"),
                };
                let report = self.with(|s| {
                    // A lock bumps `interrupts` before it lets go of the vault.
                    if interrupts.has_changed().unwrap_or(true) {
                        return Err(fail(ErrorCode::Locked, INTERRUPTED));
                    }
                    mirror::apply(s, &known, fetched, !dry_run)
                })?;
                if report.applied && report.changed() {
                    self.sync_now.notify_one();
                }
                Ok(Reply::Mirror { report })
            }
            Command::SendCreate {
                secret,
                sealed,
                opens,
                ttl_secs,
                label,
            } => {
                self.send_create(secret, sealed, opens, ttl_secs, label)
                    .await
            }
            Command::SendList => Ok(self.send_list().await),
            Command::SendShow { id } => self.send_show(&id).await,
            Command::SendRevoke { id } => self.send_revoke(&id).await,
            Command::SendWait { id } => self.send_wait(&id, conv).await,
            Command::Generate {
                length,
                symbols,
                url,
            } => Ok(Reply::Password {
                password: deadbolt_core::site_password::generate_for_url(
                    url.as_deref(),
                    length,
                    symbols,
                )?,
            }),
            Command::SiteLogins { origin } => {
                let (site, logins) = self.with(|s| autofill::list(s, &origin))?;
                Ok(Reply::SiteLogins { site, logins })
            }
            Command::SiteFill {
                origin,
                login,
                want,
            } => Ok(Reply::SiteFill {
                values: self.with(|s| {
                    autofill::fill(s, &origin, &login, &want, crate::config::wall_clock())
                })?,
            }),
            Command::SiteGenerateCheck { origin, field } => {
                generate::check(&origin, &generate::field_rules(&field))?;
                Ok(Reply::Done)
            }
            Command::SiteGenerate { origin, field } => {
                let password = crate::protocol::Secret::new(
                    generate::generate(&origin, &generate::field_rules(&field))?.as_str(),
                );
                let id = self.with(|s| {
                    s.generated
                        .offer(&origin, password.clone(), std::time::Instant::now())
                })?;
                Ok(Reply::SiteGenerated { password, id })
            }
            Command::SiteGenerateKeep { origin, id } => {
                self.with(|s| s.generated.keep(&origin, &id, std::time::Instant::now()))?;
                Ok(Reply::Done)
            }
            Command::SiteGenerateDrop { origin, id } => {
                self.with(|s| {
                    s.generated.drop_candidate(&origin, &id);
                    Ok(())
                })?;
                Ok(Reply::Done)
            }
            Command::SiteCheck {
                origin,
                username,
                password,
            } => {
                let (status, matches) = self.with(|s| {
                    let password =
                        s.generated
                            .resolve(&origin, &password, std::time::Instant::now())?;
                    autofill::check(s, &origin, username.as_deref(), &password)
                })?;
                Ok(Reply::SiteCheck { status, matches })
            }
            Command::SiteSave {
                origin,
                login,
                title,
                url,
                username,
                password,
            } => {
                let (login, created) = self.with(|s| {
                    let secret =
                        s.generated
                            .resolve(&origin, &password, std::time::Instant::now())?;
                    let saved = autofill::save(
                        s,
                        autofill::Save {
                            origin: &origin,
                            login: login.as_ref(),
                            title: &title,
                            url: &url,
                            username: &username,
                            password: &secret,
                        },
                    )?;
                    s.generated.saved(&password);
                    Ok(saved)
                })?;
                self.sync_now.notify_one();
                Ok(Reply::SiteSaved { login, created })
            }
            Command::FormItems { origin, kinds } => self.form_items(&origin, &kinds),
            Command::FormFill {
                origin,
                item,
                fields,
            } => self.form_fill(&origin, &item, &fields, conv).await,
            command @ (Command::PasskeyList { .. }
            | Command::PasskeyCreate { .. }
            | Command::PasskeyGet { .. }) => self.passkey(command, conv).await,
            Command::AgentClientAdd { .. }
            | Command::AgentGrantSet { .. }
            | Command::SecretGrantSet { .. }
            | Command::ExperimentalApproverSet { .. }
            | Command::ExperimentalMobileRead { .. }
            | Command::Resolve { .. }
            | Command::Health { .. }
            | Command::HealthIgnore { .. }
            | Command::BreachChecksSet { .. } => {
                bail!("pairing, grants, references and health are answered with the caller")
            }
            Command::AgentClientList => Ok(Reply::AgentClients {
                clients: self.with(|s| grants::list_clients(s))?,
            }),
            Command::AgentClientRemove { id } => {
                let (id, _) = self.with(|s| grants::remove_client(s, &id))?;
                self.forget_agent_client(&id);
                Ok(Reply::Done)
            }
            Command::AgentGrantList => Ok(Reply::AgentGrants {
                grants: self.with(|s| grants::list_grants(s, session::now()))?,
            }),
            Command::AgentGrantRemove { id } => {
                // Either kind of grant: a sign-in grant, else a secret grant.
                self.with(|s| match grants::remove_grant(s, &id) {
                    Err(error) if crate::client::code(&error) == Some(ErrorCode::NotFound) => {
                        secrets::remove_grant(s, &id)
                    }
                    removed => removed.map(drop),
                })?;
                Ok(Reply::Done)
            }
            Command::SecretGrantList => Ok(Reply::SecretGrants {
                grants: self.with(|s| secrets::list_grants(s, session::now()))?,
            }),
            Command::SshAgentSet { enabled } => {
                self.set_ssh_agent(enabled)?;
                Ok(Reply::Done)
            }
            Command::SshGenerate { kind, comment } => self.ssh_generate(kind, comment.as_deref()),
            Command::SshInspect {
                private_key,
                passphrase,
                comment,
            } => self.ssh_inspect(&private_key, passphrase.as_ref(), comment.as_deref()),
            Command::SshSign { .. } => bail!("ssh-sign is answered with the caller"),
            command @ (Command::AgentLogins { .. }
            | Command::AgentFill { .. }
            | Command::AgentPasskeyGet { .. }) => self.agent_client(command),
            command @ (Command::AutofillStatus
            | Command::AutofillIdentities
            | Command::AutofillList { .. }
            | Command::AutofillFill { .. }
            | Command::AutofillPasskeyGet { .. }
            | Command::AutofillPasskeyCreate { .. }) => self.macos_autofill(command, conv).await,
        }
    }

    /// Runs a local item write, then syncs it out right away.
    fn item_write(
        &self,
        f: impl FnOnce(&mut Session) -> Result<crate::protocol::ItemInfo>,
    ) -> Result<Reply> {
        let item = self.with(f)?;
        self.sync_now.notify_one();
        Ok(Reply::Item { item })
    }

    /// Waits within the startup budget; the background loop owns the fallback.
    async fn wait_ready(&self) -> Result<()> {
        let mut ready = self.ready.subscribe();
        let deadline = Instant::now() + sync::STARTUP_TIMEOUT;
        loop {
            // Mark this version observed before checking the session so a lock
            // between the check and changed() cannot be missed.
            let is_ready = *ready.borrow_and_update();
            self.with(|_| Ok(()))?;
            if is_ready {
                return Ok(());
            }
            match tokio::time::timeout_at(deadline, ready.changed()).await {
                Ok(changed) => changed?,
                Err(_) => {
                    self.with(|_| Ok(()))?;
                    bail!("waiting for membership sync");
                }
            }
        }
    }

    /// Checks readiness before serving vault data to a pairing peer.
    pub fn with_data<T>(&self, f: impl FnOnce(&mut Session) -> Result<T>) -> Result<T> {
        self.with(|s| {
            if !*self.ready.borrow() {
                bail!("waiting for membership sync");
            }
            f(s)
        })
    }

    /// Runs `f` on the unlocked session.
    pub fn with<T>(&self, f: impl FnOnce(&mut Session) -> Result<T>) -> Result<T> {
        let mut guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let Some(session) = guard.as_mut() else {
            return Err(if deadbolt_store::is_initialized(&self.paths.data) {
                fail(ErrorCode::Locked, "locked: run `deadbolt unlock`")
            } else {
                fail(
                    ErrorCode::NotInitialized,
                    "this device is not set up; run `deadbolt init` or `deadbolt join`",
                )
            });
        };
        session.ensure_usable()?;
        let result = f(session);
        if session.append_uncertain {
            // The old membership may have been revoked on disk. Quarantine
            // synchronously, before another request or startup retry can run.
            self.refresh(session);
            self.ready.send_replace(false);
            session.sync_task.take();
            session.health_task.take();
            self.ssh.clear_on_lock();
            self.cancel_biometric_prompt();
            self.interrupt_op();
            self.watchers.locked();
            // Keep the failed handle until explicit lock/unlock: recovery must
            // close the node/store and authenticate/replay, never reuse it.
            session.ensure_usable()?;
        }
        // Publish even if `f` failed: it may have committed earlier changes.
        if !session.changes.is_empty() {
            self.watchers.changed(&std::mem::take(&mut session.changes));
        }
        result
    }

    /// Streams changes to one watcher until it hangs up or the agent stops.
    /// A watcher that stops reading is dropped after [`watchers::SEND_TIMEOUT`];
    /// publishing never waits for it.
    async fn watch(&self, conv: &Conversation, app: bool) -> Result<()> {
        let subscription = self.watchers.subscribe(app);
        let send = |change| async move {
            tokio::time::timeout(
                watchers::SEND_TIMEOUT,
                conv.send(&Message::Change { change }),
            )
            .await
            .context("the watcher stopped reading")?
        };
        send(Change::Watching).await?;
        loop {
            let changes = tokio::select! {
                changes = subscription.next() => changes,
                () = conv.closed() => return Ok(()),
            };
            for change in changes {
                let stopping = change == Change::Stopping;
                send(change).await?;
                if stopping {
                    conv.send(&Message::Ok { reply: Reply::Done }).await?;
                    conv.write.lock().await.shutdown().await?;
                    return Ok(());
                }
            }
        }
    }

    /// Locks on each sleep or screen-lock event unless `lock_on_sleep` is off.
    async fn follow_system(self: Arc<Self>, mut events: mpsc::Receiver<SystemEvent>) {
        while let Some(event) = events.recv().await {
            let enabled = match Config::load(&self.paths.config) {
                Ok(config) => config.lock_on_sleep(),
                Err(error) => {
                    warn!("{error:#}; locking anyway");
                    true
                }
            };
            let unlocked = self
                .session
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some();
            if enabled && unlocked {
                info!(?event, "locking");
                self.lock().await;
            }
        }
    }

    /// Updates the membership gate and closes open sync connections to devices
    /// that are no longer members of any vault.
    pub fn refresh(&self, session: &mut Session) {
        session.revoke_stale_approvers();
        *self.members.write().unwrap_or_else(|e| e.into_inner()) = session.peer_set();
        let closed = session.node.enforce_membership();
        if closed > 0 {
            info!(closed, "closed sync connections to removed devices");
        }
        if session.unavailable.is_empty()
            && !session.vaults.is_empty()
            && !session.vaults.values().any(|v| v.is_member(&session.id))
        {
            drop(session.store.clear_biometric());
            self.biometric_was_enrolled.store(false, Ordering::SeqCst);
            *self
                .biometric_slot
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = None;
        }
    }

    fn is_touch_id_available(&self) -> bool {
        #[cfg(test)]
        if let Some(override_val) = *self
            .touch_id_available_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
        {
            return override_val;
        }
        biometric::cached_status().is_available()
    }

    async fn refresh_touch_id_available(&self) -> bool {
        #[cfg(test)]
        if let Some(override_val) = *self
            .touch_id_available_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
        {
            return override_val;
        }
        tokio::task::spawn_blocking(|| biometric::refresh_status().is_available())
            .await
            .unwrap_or(false)
    }

    fn status(&self) -> Status {
        let initialized = deadbolt_store::is_initialized(&self.paths.data);
        let touch_id_available = self.is_touch_id_available();
        let cfg = Config::load(&self.paths.config).unwrap_or_default();
        let touch_id_cfg = cfg.touch_id();
        let ssh_agent = cfg.ssh_agent() && self.ssh.is_listening();
        let ssh_socket = ssh_agent.then(|| self.paths.ssh_client_socket().display().to_string());
        let touch_id_enabled = touch_id_available && touch_id_cfg;
        let now = session::now();
        let slot = *self
            .biometric_slot
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let was_enrolled = slot.is_some() || self.biometric_was_enrolled.load(Ordering::SeqCst);
        let slot_ready = touch_id_enabled && initialized && slot.is_some_and(|m| m.is_ready(now));
        let touch_id_ready = slot_ready;
        let touch_id_reset = touch_id_enabled && initialized && was_enrolled && !slot_ready;

        let guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let session = guard.as_ref().filter(|s| !s.append_uncertain);
        let connected: HashSet<PeerId> = session
            .map(|s| s.node.connected_peers().into_iter().collect())
            .unwrap_or_default();
        let peers = session.map(|s| s.peer_set()).unwrap_or_default();
        let idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let unlocked = session.is_some();
        Status {
            pid: std::process::id(),
            version: version(),
            protocol: protocol(),
            program: std::env::current_exe()
                .ok()
                .map(|p| p.display().to_string()),
            home: self.paths.data.display().to_string(),
            initialized,
            unlocked,
            locks_in_secs: idle
                .deadline
                .filter(|_| unlocked)
                .map(|d| d.saturating_duration_since(Instant::now()).as_secs()),
            device: session.map(|s| s.device_info(&s.id, &connected)),
            vaults: session.map(|s| s.vault_infos()).unwrap_or_default(),
            peers_online: session
                .map(|s| peers.iter().filter(|p| s.online(p, &connected)).count())
                .unwrap_or_default(),
            peers: peers.len(),
            touch_id_available,
            touch_id_enabled,
            touch_id_ready,
            touch_id_reset,
            ssh_agent,
            ssh_socket,
            // Filled in for the connection that asked (`handle`).
            caller: caller::nobody(),
        }
    }

    fn touch(&self) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        idle.deadline = idle.timeout.map(|t| Instant::now() + t);
    }

    async fn check_idle(&self) {
        let expired = {
            let idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
            idle.deadline.is_some_and(|d| Instant::now() >= d)
                && self.busy.load(Ordering::SeqCst) == 0
        };
        if expired {
            info!("idle timeout; locking");
            self.lock().await;
        }
    }

    /// The idle timeout `timeout_secs` asks for: `Some(0)` is never, `None`
    /// the configured one.
    fn requested_timeout(&self, timeout_secs: Option<u64>) -> Result<Option<Duration>> {
        Ok(match timeout_secs {
            Some(0) => None,
            Some(secs) => Some(Duration::from_secs(secs)),
            None => Config::load(&self.paths.config)?.unlock_timeout()?,
        })
    }

    fn set_timeout(&self, timeout_secs: Option<u64>) -> Result<()> {
        let timeout = self.requested_timeout(timeout_secs)?;
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        idle.timeout = timeout;
        idle.deadline = timeout.map(|t| Instant::now() + t);
        Ok(())
    }

    /// Sets the idle timeout `timeout_secs` asks for if it's no longer than
    /// the current one, returning whether it did. An unlock request while
    /// unlocked may always shorten it; only a verified passphrase or finger
    /// may lengthen it or make it never.
    fn tighten_timeout(&self, timeout_secs: Option<u64>) -> Result<bool> {
        let timeout = self.requested_timeout(timeout_secs)?;
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let tighter = match (timeout, idle.timeout) {
            (_, None) => true,
            (Some(new), Some(current)) => new <= current,
            (None, Some(_)) => false,
        };
        if tighter {
            idle.timeout = timeout;
            idle.deadline = timeout.map(|t| Instant::now() + t);
        }
        Ok(tighter)
    }

    async fn setup(
        self: &Arc<Self>,
        passphrase: zeroize::Zeroizing<String>,
        device_name: String,
    ) -> Result<()> {
        self.cancel_biometric_prompt();
        let _transition = self.transition.lock().await;
        self.settle_activity(true);
        *self
            .biometric_cooldown_until
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        if deadbolt_store::is_initialized(&self.paths.data) {
            bail!("this device is already set up");
        }
        let device_name = clean_name(&device_name);
        if device_name.is_empty() {
            bail!("the device name cannot be empty");
        }
        if passphrase.is_empty() {
            bail!("the passphrase cannot be empty");
        }
        let dir = self.paths.data.clone();
        let params = self.kdf;
        let loaded = tokio::task::spawn_blocking(move || {
            Loaded::setup(&dir, passphrase.as_bytes(), &device_name, params)
        })
        .await??;
        self.biometric_was_enrolled.store(false, Ordering::SeqCst);
        *self
            .biometric_slot
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        self.start(loaded, None).await
    }

    /// First run through a join: creates the store with the device key that
    /// joined and stores the vault it received, then unlocks.
    async fn setup_joined(
        self: &Arc<Self>,
        joined: pairing::Fresh,
        passphrase: crate::protocol::Secret,
    ) -> Result<crate::protocol::VaultInfo> {
        self.cancel_biometric_prompt();
        let _transition = self.transition.lock().await;
        self.settle_activity(true);
        *self
            .biometric_cooldown_until
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        if deadbolt_store::is_initialized(&self.paths.data) {
            bail!("this device was set up meanwhile; nothing from the join was saved");
        }
        if passphrase.expose().is_empty() {
            bail!("the passphrase cannot be empty");
        }
        let dir = self.paths.data.clone();
        let params = self.kdf;
        let (loaded, vault) =
            tokio::task::spawn_blocking(move || joined.persist(&dir, &passphrase, params))
                .await??;
        self.biometric_was_enrolled.store(false, Ordering::SeqCst);
        *self
            .biometric_slot
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        self.start(loaded, None).await?;
        Ok(vault)
    }

    /// Unlocks with `passphrase`. While unlocked, it changes the idle
    /// timeout: to a shorter one at once, to a longer one (or never) only if
    /// the passphrase is right. A Touch ID prompt in flight is cancelled only
    /// once the passphrase has opened the store.
    async fn unlock(
        self: &Arc<Self>,
        passphrase: zeroize::Zeroizing<String>,
        timeout_secs: Option<u64>,
    ) -> Result<()> {
        let _transition = self.transition.lock().await;
        self.close_quarantined(&_transition).await;
        self.settle_activity(true);
        *self
            .biometric_cooldown_until
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        let open = self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|s| {
                s.ensure_usable()?;
                Ok::<_, anyhow::Error>(s.store.passphrase_check()?)
            });
        if let Some(check) = open {
            let check = check?;
            if self.with(|_| self.tighten_timeout(timeout_secs))? {
                return Ok(());
            }
            let turn = self.guesses.turn()?;
            let right =
                tokio::task::spawn_blocking(move || check.matches(passphrase.as_bytes())).await?;
            turn.settle(right);
            if !right {
                return Err(deadbolt_store::Error::WrongPassphrase.into());
            }
            return self.with(|_| self.set_timeout(timeout_secs));
        }
        if !deadbolt_store::is_initialized(&self.paths.data) {
            return Err(fail(
                ErrorCode::NotInitialized,
                "this device is not set up; run `deadbolt init` or `deadbolt join`",
            ));
        }
        let dir = self.paths.data.clone();
        let want_touch_id = Config::load(&self.paths.config)
            .map(|c| c.touch_id())
            .unwrap_or(false);
        let enroll_touch_id = want_touch_id && self.refresh_touch_id_available().await;
        let now = session::now();
        let turn = self.guesses.turn()?;
        let opened = tokio::task::spawn_blocking(move || {
            let loaded = Loaded::open(&dir, passphrase.as_bytes())?;
            if enroll_touch_id && let Err(error) = biometric::enroll(&loaded.store, now) {
                warn!("Touch ID enrollment on unlock failed: {error:#}");
            }
            let meta =
                biometric::token_meta(loaded.store.biometric_token().ok().flatten().as_deref());
            Ok::<_, anyhow::Error>((loaded, meta))
        })
        .await?;
        match &opened {
            Ok(_) => turn.settle(true),
            Err(error) if wrong_passphrase(error) => turn.settle(false),
            // Neither right nor wrong (a damaged store, a store in use).
            Err(_) => drop(turn),
        }
        let (loaded, slot_meta) = opened?;
        self.cancel_biometric_prompt();
        if slot_meta.is_some() {
            self.biometric_was_enrolled.store(true, Ordering::SeqCst);
        }
        *self
            .biometric_slot
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = slot_meta;
        self.start(loaded, timeout_secs).await
    }

    /// Unlocks with Touch ID. While unlocked, it changes the idle timeout:
    /// to a shorter one at once, to a longer one (or never) only after a
    /// Touch ID prompt succeeds.
    async fn unlock_biometric(self: &Arc<Self>, timeout_secs: Option<u64>) -> Result<()> {
        self.unlock_biometric_with_reason(timeout_secs, "unlock your Deadbolt vaults")
            .await
            .map(drop)
    }

    /// Like [`Agent::unlock_biometric`], with a custom `reason` on the Touch ID
    /// sheet. Returns `Ok(true)` only when this call's own Touch ID prompt
    /// unsealed the biometric key (as opposed to returning early while already
    /// unlocked or coalescing onto another caller's prompt).
    pub(super) async fn unlock_biometric_with_reason(
        self: &Arc<Self>,
        timeout_secs: Option<u64>,
        reason: &str,
    ) -> Result<bool> {
        let unlocked = {
            let transition = self.transition.lock().await;
            self.close_quarantined(&transition).await;
            self.session
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
        };
        if unlocked && self.with(|_| self.tighten_timeout(timeout_secs))? {
            return Ok(false);
        }
        if !unlocked && !deadbolt_store::is_initialized(&self.paths.data) {
            return Err(fail(
                ErrorCode::NotInitialized,
                "this device is not set up; run `deadbolt init` or `deadbolt join`",
            ));
        }
        if !Config::load(&self.paths.config)?.touch_id() {
            bail!(
                "Touch ID unlock is not enabled; turn it on in Settings or run `deadbolt touchid on`"
            );
        }
        if let Some(until) = *self
            .biometric_cooldown_until
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            && Instant::now() < until
        {
            bail!("{}", biometric::UnlockError::Cancelled);
        }

        let flight_or_wait = {
            let mut guard = self
                .biometric_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = guard.as_ref() {
                Err(existing.rx.clone())
            } else {
                let cancel = biometric::CancelHandle::new();
                let (tx, rx) = watch::channel(None);
                *guard = Some(BiometricFlight {
                    cancel: cancel.clone(),
                    rx,
                });
                Ok((cancel, tx))
            }
        };

        let (cancel, done_tx) = match flight_or_wait {
            Err(mut rx) => {
                let outcome = rx
                    .wait_for(Option::is_some)
                    .await
                    .ok()
                    .and_then(|v| v.clone())
                    .unwrap_or_else(|| Err(biometric::UnlockError::Cancelled.to_string()));
                // The finger was for the prompt's own request: this one may
                // only shorten the timeout that request set, and never claims
                // `unsealed_here = true` for passkey UV.
                return match outcome {
                    Ok(()) => self
                        .with(|_| self.tighten_timeout(timeout_secs))
                        .map(|_| false),
                    Err(msg) => bail!("{msg}"),
                };
            }
            Ok(pair) => pair,
        };

        struct FlightCleanup<'a> {
            agent: &'a Agent,
            cancel: Arc<biometric::CancelHandle>,
            done_tx: Option<watch::Sender<Option<Result<(), String>>>>,
        }
        impl FlightCleanup<'_> {
            fn clear_flight(&self) {
                let mut guard = self
                    .agent
                    .biometric_flight
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if guard
                    .as_ref()
                    .is_some_and(|f| Arc::ptr_eq(&f.cancel, &self.cancel))
                {
                    *guard = None;
                }
            }
        }
        impl Drop for FlightCleanup<'_> {
            fn drop(&mut self) {
                self.cancel.cancel();
                self.clear_flight();
                if let Some(tx) = self.done_tx.take() {
                    tx.send_replace(Some(Err(biometric::UnlockError::Cancelled.to_string())));
                }
            }
        }

        let mut cleanup = FlightCleanup {
            agent: self,
            cancel: cancel.clone(),
            done_tx: Some(done_tx),
        };

        let res = self
            .run_biometric_leader(timeout_secs, reason, cancel.clone())
            .await;
        cleanup.clear_flight();
        if let Some(tx) = cleanup.done_tx.take() {
            let broadcast = match &res {
                Ok(_) => Ok(()),
                Err(err) => Err(format!("{err:#}")),
            };
            tx.send_replace(Some(broadcast));
        }
        res
    }

    async fn run_biometric_leader(
        self: &Arc<Self>,
        timeout_secs: Option<u64>,
        reason: &str,
        cancel: Arc<biometric::CancelHandle>,
    ) -> Result<bool> {
        let now = session::now();
        let token = {
            let _transition = self.transition.lock().await;
            self.close_quarantined(&_transition).await;
            let open = self
                .session
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|s| {
                    s.ensure_usable()?;
                    Ok::<_, anyhow::Error>(s.store.biometric_token()?)
                });
            if let Some(token) = open {
                let token = token?;
                // Unlocked: the prompt only verifies a longer timeout.
                if self.with(|_| self.tighten_timeout(timeout_secs))? {
                    return Ok(false);
                }
                let Some(token) = token else {
                    bail!("{}", biometric::UnlockError::NotEnrolled);
                };
                if let Err(err) = biometric::validate_token(&token, true, now) {
                    bail!("{err}");
                }
                token
            } else {
                let dir = self.paths.data.clone();
                let raw =
                    tokio::task::spawn_blocking(move || deadbolt_store::biometric_token(&dir))
                        .await?;
                let token = match raw {
                    Ok(Some(token)) => token,
                    Ok(None) => {
                        *self
                            .biometric_slot
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()) = None;
                        bail!("{}", biometric::UnlockError::NotEnrolled);
                    }
                    Err(ref err) if biometric::is_biometric_slot_error(err) => {
                        let msg = err.to_string();
                        let dir = self.paths.data.clone();
                        drop(
                            tokio::task::spawn_blocking(move || {
                                deadbolt_store::clear_biometric(&dir)
                            })
                            .await,
                        );
                        self.biometric_was_enrolled.store(true, Ordering::SeqCst);
                        *self
                            .biometric_slot
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()) = None;
                        bail!("{}", biometric::UnlockError::Invalidated(msg));
                    }
                    Err(err) => return Err(err.into()),
                };
                if let Err(err) = biometric::validate_token(&token, true, now) {
                    let dir = self.paths.data.clone();
                    let expected = token.clone();
                    drop(
                        tokio::task::spawn_blocking(move || {
                            biometric::clear_biometric_if_matches(&dir, &expected)
                        })
                        .await,
                    );
                    self.biometric_was_enrolled.store(true, Ordering::SeqCst);
                    *self
                        .biometric_slot
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = None;
                    bail!("{err}");
                }
                token
            }
        };

        // Run the interactive Touch ID unseal WITHOUT holding `self.transition`
        // or keeping `store.redb` open, so a concurrent passphrase Unlock or
        // Lock can cancel the prompt immediately and never hits `Error::InUse`.
        let prompt_reason = reason.to_string();
        let unsealed = {
            #[cfg(test)]
            let hook = self
                .biometric_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            #[cfg(test)]
            if let Some(hook) = hook {
                let cancel_for_hook = cancel.clone();
                tokio::task::spawn_blocking(move || hook(&cancel_for_hook)).await?
            } else {
                let cancel_for_unseal = cancel.clone();
                let token_for_unseal = token.clone();
                tokio::task::spawn_blocking(move || {
                    biometric::unseal_token(
                        &token_for_unseal,
                        now,
                        &prompt_reason,
                        &cancel_for_unseal,
                        biometric::PROMPT_TIMEOUT,
                    )
                })
                .await?
            }
            #[cfg(not(test))]
            {
                let cancel_for_unseal = cancel.clone();
                let token_for_unseal = token.clone();
                tokio::task::spawn_blocking(move || {
                    biometric::unseal_token(
                        &token_for_unseal,
                        now,
                        &prompt_reason,
                        &cancel_for_unseal,
                        biometric::PROMPT_TIMEOUT,
                    )
                })
                .await?
            }
        };

        let key = match unsealed {
            Ok(key) => key,
            Err(biometric::UnlockError::Cancelled) => {
                if !cancel.is_cancelled() {
                    *self
                        .biometric_cooldown_until
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) =
                        Some(Instant::now() + BIOMETRIC_CANCEL_COOLDOWN);
                }
                bail!("{}", biometric::UnlockError::Cancelled);
            }
            Err(
                err @ (biometric::UnlockError::Invalidated(_) | biometric::UnlockError::Expired(_)),
            ) => {
                if !cancel.is_cancelled() {
                    let _transition = self.transition.lock().await;
                    if !cancel.is_cancelled()
                        && self
                            .session
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .is_none()
                    {
                        let dir = self.paths.data.clone();
                        let expected = token.clone();
                        let cleared = tokio::task::spawn_blocking(move || {
                            biometric::clear_biometric_if_matches(&dir, &expected)
                        })
                        .await
                        .unwrap_or(false);
                        if cleared {
                            self.biometric_was_enrolled.store(true, Ordering::SeqCst);
                            *self
                                .biometric_slot
                                .lock()
                                .unwrap_or_else(|e| e.into_inner()) = None;
                        }
                    }
                }
                bail!("{err}");
            }
            Err(err) => bail!("{err}"),
        };

        let _transition = self.transition.lock().await;
        self.close_quarantined(&_transition).await;
        if self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            self.with(|_| self.set_timeout(timeout_secs))?;
            return Ok(true);
        }
        if cancel.is_cancelled() {
            bail!("{}", biometric::UnlockError::Cancelled);
        }

        let dir = self.paths.data.clone();
        let expected_token = token;
        let opened = tokio::task::spawn_blocking(move || {
            match deadbolt_store::unlock_biometric(&dir, &key) {
                Ok(store) => {
                    let meta =
                        biometric::token_meta(store.biometric_token().ok().flatten().as_deref());
                    let loaded = Loaded::from_unlocked(store)
                        .map_err(|e| (biometric::UnlockError::from(e), false))?;
                    Ok((loaded, meta))
                }
                Err(ref err) if biometric::is_biometric_slot_error(err) => {
                    let cleared = biometric::clear_biometric_if_matches(&dir, &expected_token);
                    Err((
                        biometric::UnlockError::Invalidated(
                            "biometric key rejected by store header".into(),
                        ),
                        cleared,
                    ))
                }
                Err(err) => Err((biometric::UnlockError::Store(err), false)),
            }
        })
        .await?;

        let (loaded, meta) = match opened {
            Ok(pair) => pair,
            Err((err, cleared)) => {
                if cleared {
                    self.biometric_was_enrolled.store(true, Ordering::SeqCst);
                    *self
                        .biometric_slot
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = None;
                }
                bail!("{err}");
            }
        };

        if meta.is_some() {
            self.biometric_was_enrolled.store(true, Ordering::SeqCst);
        }
        *self
            .biometric_slot
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = meta;
        self.start(loaded, timeout_secs).await?;
        Ok(true)
    }

    async fn set_touch_id(&self, enabled: bool) -> Result<()> {
        self.cancel_biometric_prompt();
        let _transition = self.transition.lock().await;
        self.settle_activity(true);
        *self
            .biometric_cooldown_until
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        if enabled {
            if !self.refresh_touch_id_available().await {
                bail!("Touch ID is not available on this Mac");
            }
            if self
                .session
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_none()
            {
                return Err(if deadbolt_store::is_initialized(&self.paths.data) {
                    fail(ErrorCode::Locked, "locked: run `deadbolt unlock`")
                } else {
                    fail(
                        ErrorCode::NotInitialized,
                        "this device is not set up; run `deadbolt init` or `deadbolt join`",
                    )
                });
            }
            let now = session::now();
            let sealed = tokio::task::spawn_blocking(move || biometric::seal_new(now)).await??;
            self.with(|s| {
                s.store
                    .set_biometric(&sealed.key, &sealed.token)
                    .context("saving Touch ID key slot")?;
                crate::config::set_touch_id(&self.paths.config, true)
                    .context("updating config.toml")
            })?;
            self.biometric_was_enrolled.store(true, Ordering::SeqCst);
            *self
                .biometric_slot
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(sealed.meta);
            Ok(())
        } else {
            crate::config::set_touch_id(&self.paths.config, false)
                .context("updating config.toml")?;
            self.biometric_was_enrolled.store(false, Ordering::SeqCst);
            *self
                .biometric_slot
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = None;
            let clear_open = {
                let guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
                guard.as_ref().map(|s| s.store.clear_biometric())
            };
            match clear_open {
                Some(res) => {
                    res.context("clearing Touch ID key slot")?;
                }
                None if deadbolt_store::is_initialized(&self.paths.data) => {
                    let dir = self.paths.data.clone();
                    tokio::task::spawn_blocking(move || deadbolt_store::clear_biometric(&dir))
                        .await?
                        .context("clearing Touch ID key slot")?;
                }
                None => {}
            }
            Ok(())
        }
    }

    async fn start(self: &Arc<Self>, loaded: Loaded, timeout_secs: Option<u64>) -> Result<()> {
        loaded.ensure_usable()?;
        let secret = *loaded.secret.to_bytes();
        let config = if self.local_net {
            NodeConfig::local_only(secret)
        } else {
            NodeConfig::new(secret)
        };
        let members = self.members.clone();
        let gate: Arc<dyn Membership> = Arc::new(move |id: &[u8; 32]| {
            members
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .contains(id)
        });
        self.ready.send_replace(false);
        let node = Node::spawn(config, gate, sync::Handler(self.clone())).await?;
        let mut session = Session::new(loaded, node);
        self.refresh(&mut session);
        self.ready.send_replace(session.peer_set().is_empty());
        let id: DeviceId = session.id;
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = Some(session);
        self.watchers.unlocked();
        self.settle_activity(false);
        self.set_timeout(timeout_secs)?;
        self.with(|s| {
            s.sync_task = Some(AbortOnDrop(tokio::spawn(sync::run(self.clone()))));
            s.health_task = Some(AbortOnDrop(tokio::spawn(health::run_background(
                self.clone(),
            ))));
            Ok(())
        })?;
        info!(device = %id, "unlocked");
        Ok(())
    }

    async fn lock(&self) {
        self.ssh.clear_on_lock();
        self.cancel_biometric_prompt();
        self.interrupt_op();
        let transition = self.transition.lock().await;
        self.close_session(&transition).await;
    }

    /// Only an explicit unlock retires quarantine; all normal reads/retries
    /// continue to fail closed. The transition serializes close with open and
    /// lock, and avoids calling lock() while already holding its mutex.
    async fn close_quarantined(&self, transition: &tokio::sync::MutexGuard<'_, ()>) {
        let quarantined = self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|s| s.append_uncertain);
        if quarantined {
            // Quarantine already cancelled prompts and background work. Do not
            // cancel a new biometric flight that is authenticating recovery.
            self.close_session(transition).await;
        }
    }

    async fn close_session(&self, _transition: &tokio::sync::MutexGuard<'_, ()>) {
        self.settle_activity(true);
        *self
            .biometric_cooldown_until
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        let session = self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        self.members
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.ready.send_replace(false);
        *self.idle.lock().unwrap_or_else(|e| e.into_inner()) = Idle::default();
        if let Some(mut session) = session {
            self.watchers.locked();
            session.health_task.take();
            session.sync_task.take();
            session.node.shutdown().await;
            drop(session);
            info!("locked");
        }
    }
}
