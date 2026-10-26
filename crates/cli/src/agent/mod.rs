//! The background agent: the only process that opens the store. Holds it
//! unlocked, runs the iroh node while unlocked, and serves the control socket.

mod items;
mod pairing;
mod session;
#[cfg(test)]
mod sim;
mod sync;
mod system;
#[cfg(test)]
mod watch_tests;
mod watchers;

use std::collections::HashSet;
use std::fs::{self, File, TryLockError};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};
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
    Answer, Change, Command, ErrorCode, Event, MAX_LINE, Message, Reply, Request, Status,
};
use session::{Loaded, Session, clean_name};
use system::SystemEvent;
use watchers::Watchers;

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

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
    idle: Mutex<Idle>,
    /// Requests in progress; the idle timeout waits for them (e.g. pairing).
    busy: AtomicUsize,
    shutdown: Notify,
    watchers: Watchers,
}

impl Agent {
    fn new(paths: Paths, local_net: bool, kdf: deadbolt_store::KdfParams) -> Arc<Agent> {
        Arc::new(Agent {
            paths,
            local_net,
            kdf,
            session: Mutex::default(),
            members: Arc::default(),
            ready: watch::channel(false).0,
            sync_now: Notify::new(),
            transition: tokio::sync::Mutex::new(()),
            idle: Mutex::default(),
            busy: AtomicUsize::new(0),
            shutdown: Notify::new(),
            watchers: Watchers::default(),
        })
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
                        Message::Error { code, message } => {
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
            },
            Command::ItemGet {
                vault: None,
                query: vec!["offline-login".into()],
            },
            Command::ItemList {
                vault: None,
                query: vec![],
                kind: None,
            },
            Command::ItemSet {
                vault: None,
                query: vec!["offline-login".into()],
                fields: fields(),
                name: None,
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
                apply: true,
            },
            Command::ItemRemove {
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
}

#[derive(Default)]
struct Idle {
    timeout: Option<Duration>,
    deadline: Option<Instant>,
}

fn fail(code: ErrorCode, message: impl Into<String>) -> anyhow::Error {
    AgentError {
        code,
        message: message.into(),
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
    fs::set_permissions(runtime, fs::Permissions::from_mode(0o700))?;
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
    let agent = Agent::new(paths, local_net, env.kdf);
    info!(pid = std::process::id(), version = %version(), local_net, "agent started");
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
            Some(result) = connections.join_next(), if !connections.is_empty() => report_connection(result),
            _ = agent.shutdown.notified() => break,
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            _ = tick.tick() => agent.check_idle().await,
        }
    }
    info!("agent stopping");
    drop(listener);
    agent.watchers.stopping();
    drain_connections(&mut connections).await;
    agent.lock().await;
    remove_socket(&socket)?;
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
    answers: tokio::sync::Mutex<mpsc::Receiver<bool>>,
    closed: watch::Receiver<bool>,
}

impl Conversation {
    async fn send(&self, message: &Message) -> Result<()> {
        let mut body = serde_json::to_vec(message)?;
        body.push(b'\n');
        tokio::time::timeout(IO_TIMEOUT, async {
            self.write.lock().await.write_all(&body).await
        })
        .await??;
        Ok(())
    }

    pub async fn event(&self, event: Event) -> Result<()> {
        self.send(&Message::Event { event }).await
    }

    /// Sends an event and waits for the client's answer; `false` if it hangs up.
    pub async fn ask(&self, event: Event) -> bool {
        if self.event(event).await.is_err() {
            return false;
        }
        self.answers.lock().await.recv().await.unwrap_or(false)
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
                if answers_tx.send(answer.answer).await.is_err() {
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
            Ok(request) if matches!(request.command, Command::Watch) && request.v == protocol() => {
                return self.watch(&conversation).await;
            }
            Ok(request) => {
                stop = matches!(request.command, Command::Stop);
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
                    self.clone().dispatch(request.command, &conversation).await
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
                },
                Err(error) => Message::Error {
                    code: ErrorCode::Failed,
                    message: format!("{error:#}"),
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

    async fn dispatch(self: Arc<Self>, command: Command, conv: &Conversation) -> Result<Reply> {
        if matches!(command, Command::Status | Command::Stop) {
            return self.run(command, conv).await;
        }
        self.busy.fetch_add(1, Ordering::SeqCst);
        self.touch();
        let result = self.clone().run(command, conv).await;
        self.touch();
        self.busy.fetch_sub(1, Ordering::SeqCst);
        result
    }

    async fn run(self: Arc<Self>, command: Command, conv: &Conversation) -> Result<Reply> {
        match command {
            Command::Status => Ok(Reply::Status(Box::new(self.status()))),
            Command::Stop => Ok(Reply::Done),
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
            Command::Lock => {
                self.lock().await;
                Ok(Reply::Done)
            }
            Command::Watch => bail!("watch streams on a connection of its own"),
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
            Command::Join { confirm } => pairing::join(&self, conv, confirm).await,
            Command::Pair {
                ticket,
                vault,
                confirm,
            } => pairing::pair(&self, conv, ticket, vault, confirm).await,
            Command::ItemGet { vault, query } => Ok(Reply::Item {
                item: self.with(|s| items::get(s, vault.as_deref(), &query))?,
            }),
            Command::ItemCode { vault, query } => Ok(Reply::Code {
                code: self.with(|s| {
                    items::code(s, vault.as_deref(), &query, crate::config::wall_clock())
                })?,
            }),
            Command::ItemList { vault, query, kind } => Ok(Reply::Items {
                items: self.with(|s| items::list(s, vault.as_deref(), &query, kind.as_deref()))?,
            }),
            Command::ItemNew {
                vault,
                kind,
                name,
                fields,
            } => self.item_write(|s| items::create(s, vault.as_deref(), &kind, name, fields)),
            Command::ItemSet {
                vault,
                query,
                fields,
                name,
            } => self.item_write(|s| items::set(s, vault.as_deref(), &query, fields, name)),
            Command::ItemUnset {
                vault,
                query,
                field,
            } => self.item_write(|s| items::unset(s, vault.as_deref(), &query, &field)),
            Command::ItemRemove { vault, query } => {
                self.item_write(|s| items::remove(s, vault.as_deref(), &query))
            }
            Command::Import {
                vault,
                export,
                apply,
            } => {
                // Mapping needs no session: it runs before taking the lock.
                let parsed = crate::import::parse(&export)?;
                drop(export);
                let report = self.with(|s| items::import(s, vault.as_deref(), parsed, apply))?;
                if apply {
                    self.sync_now.notify_one();
                }
                Ok(Reply::Import { report })
            }
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
        let result = f(session);
        // Publish even if `f` failed: it may have committed earlier changes.
        if !session.changes.is_empty() {
            self.watchers.changed(&std::mem::take(&mut session.changes));
        }
        result
    }

    /// Streams changes to one watcher until it hangs up or the agent stops.
    /// A watcher that stops reading is dropped after [`watchers::SEND_TIMEOUT`];
    /// publishing never waits for it.
    async fn watch(&self, conv: &Conversation) -> Result<()> {
        let subscription = self.watchers.subscribe();
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
    pub fn refresh(&self, session: &Session) {
        *self.members.write().unwrap_or_else(|e| e.into_inner()) = session.peer_set();
        let closed = session.node.enforce_membership();
        if closed > 0 {
            info!(closed, "closed sync connections to removed devices");
        }
    }

    fn status(&self) -> Status {
        let guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let session = guard.as_ref();
        let connected: HashSet<PeerId> = session
            .map(|s| s.node.connected_peers().into_iter().collect())
            .unwrap_or_default();
        let peers = session.map(|s| s.peer_set()).unwrap_or_default();
        let idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        Status {
            pid: std::process::id(),
            version: version(),
            protocol: protocol(),
            program: std::env::current_exe()
                .ok()
                .map(|p| p.display().to_string()),
            home: self.paths.data.display().to_string(),
            initialized: deadbolt_store::is_initialized(&self.paths.data),
            unlocked: session.is_some(),
            locks_in_secs: idle
                .deadline
                .filter(|_| session.is_some())
                .map(|d| d.saturating_duration_since(Instant::now()).as_secs()),
            device: session.map(|s| s.device_info(&s.id, &connected)),
            vaults: session.map(|s| s.vault_infos()).unwrap_or_default(),
            peers_online: session
                .map(|s| peers.iter().filter(|p| s.online(p, &connected)).count())
                .unwrap_or_default(),
            peers: peers.len(),
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

    fn set_timeout(&self, timeout_secs: Option<u64>) -> Result<()> {
        let timeout = match timeout_secs {
            Some(0) => None,
            Some(secs) => Some(Duration::from_secs(secs)),
            None => Config::load(&self.paths.config)?.unlock_timeout()?,
        };
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        idle.timeout = timeout;
        idle.deadline = timeout.map(|t| Instant::now() + t);
        Ok(())
    }

    async fn setup(
        self: &Arc<Self>,
        passphrase: zeroize::Zeroizing<String>,
        device_name: String,
    ) -> Result<()> {
        let _transition = self.transition.lock().await;
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
        self.start(loaded, None).await
    }

    async fn unlock(
        self: &Arc<Self>,
        passphrase: zeroize::Zeroizing<String>,
        timeout_secs: Option<u64>,
    ) -> Result<()> {
        let _transition = self.transition.lock().await;
        if self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return self.set_timeout(timeout_secs);
        }
        if !deadbolt_store::is_initialized(&self.paths.data) {
            return Err(fail(
                ErrorCode::NotInitialized,
                "this device is not set up; run `deadbolt init` or `deadbolt join`",
            ));
        }
        let dir = self.paths.data.clone();
        let loaded = tokio::task::spawn_blocking(move || Loaded::open(&dir, passphrase.as_bytes()))
            .await??;
        self.start(loaded, timeout_secs).await
    }

    async fn start(self: &Arc<Self>, loaded: Loaded, timeout_secs: Option<u64>) -> Result<()> {
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
        let session = Session::new(loaded, node);
        self.refresh(&session);
        self.ready.send_replace(session.peer_set().is_empty());
        let id: DeviceId = session.id;
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = Some(session);
        self.watchers.unlocked();
        self.set_timeout(timeout_secs)?;
        self.with(|s| {
            s.sync_task = Some(AbortOnDrop(tokio::spawn(sync::run(self.clone()))));
            Ok(())
        })?;
        info!(device = %id, "unlocked");
        Ok(())
    }

    async fn lock(&self) {
        let _transition = self.transition.lock().await;
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
            session.sync_task.take();
            session.node.shutdown().await;
            drop(session);
            info!("locked");
        }
    }
}
