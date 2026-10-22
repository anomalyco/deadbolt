//! The background agent: the only process that opens the store. Holds it
//! unlocked, runs the iroh node while unlocked, and serves the control socket.

mod items;
mod pairing;
mod session;
#[cfg(test)]
mod sim;
mod sync;

use std::collections::HashSet;
use std::fs::{self, File, TryLockError};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use deadbolt_core::DeviceId;
use deadbolt_net::{Membership, Node, NodeConfig, PeerId};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::client::{AgentError, version};
use crate::config::Config;
use crate::paths::Paths;
use crate::protocol::{
    Answer, Command, ErrorCode, Event, Message, PROTOCOL_VERSION, Reply, Request, Status,
};
use session::{Loaded, Session, clean_name};

/// Large enough for `item-import` of a big vault.
const MAX_LINE: usize = 64 * 1024 * 1024;

pub struct Agent {
    paths: Paths,
    local_net: bool,
    session: Mutex<Option<Session>>,
    /// The membership gate: members of any vault this device holds.
    members: Arc<RwLock<HashSet<PeerId>>>,
    /// Cleared on unlock until membership was synced with reachable peers.
    ready: AtomicBool,
    sync_now: Notify,
    sync_task: Mutex<Option<JoinHandle<()>>>,
    /// Serializes setup, unlock and lock.
    transition: tokio::sync::Mutex<()>,
    idle: Mutex<Idle>,
    /// Requests in progress; the idle timeout waits for them (e.g. pairing).
    busy: AtomicUsize,
    shutdown: Notify,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::FieldInput;
    use deadbolt_core::DeviceSecret;

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
                Ok(v.add(key, offline.device_id(), offline.join_consent(&id))?)
            })
            .unwrap();
        drop(loaded);
        let loaded = Loaded::open(dir.path(), b"test").unwrap();
        let agent = Arc::new(Agent {
            paths: Paths {
                data: dir.path().into(),
                config: dir.path().join("config"),
                socket: dir.path().join("socket"),
                lock: dir.path().join("lock"),
                log: dir.path().join("log"),
            },
            local_net: true,
            session: Mutex::default(),
            members: Arc::default(),
            ready: AtomicBool::new(false),
            sync_now: Notify::new(),
            sync_task: Mutex::default(),
            transition: tokio::sync::Mutex::new(()),
            idle: Mutex::default(),
            busy: AtomicUsize::new(0),
            shutdown: Notify::new(),
        });
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
            Command::ItemImport {
                vault: None,
                items: vec![crate::protocol::NewItem {
                    kind: "login".into(),
                    name: Some("imported".into()),
                    fields: fields(),
                }],
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
            assert!(!agent.ready.load(Ordering::SeqCst));
        }
        assert!(
            agent.with_data(|_| Ok(())).is_err(),
            "invitations must still wait"
        );
        tokio::time::pause();
        let (waited, ()) = tokio::join!(agent.wait_ready(), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            agent.ready.store(true, Ordering::SeqCst);
        });
        waited.unwrap();
        agent.with_data(|_| Ok(())).unwrap();
        agent.ready.store(false, Ordering::SeqCst);
        let start = tokio::time::Instant::now();
        assert!(agent.wait_ready().await.is_err());
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
    let runtime = paths.socket.parent().expect("socket has a parent");
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
    let _ = fs::remove_file(&paths.socket);
    let listener = UnixListener::bind(&paths.socket)
        .with_context(|| format!("binding {}", paths.socket.display()))?;
    fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600))?;

    let local_net = std::env::var("DEADBOLT_NET").as_deref() == Ok("local");
    let socket = paths.socket.clone();
    let agent = Arc::new(Agent {
        paths,
        local_net,
        session: Mutex::default(),
        members: Arc::default(),
        ready: AtomicBool::new(false),
        sync_now: Notify::new(),
        sync_task: Mutex::default(),
        transition: tokio::sync::Mutex::new(()),
        idle: Mutex::default(),
        busy: AtomicUsize::new(0),
        shutdown: Notify::new(),
    });
    info!(pid = std::process::id(), version = %version(), local_net, "agent started");

    let accept = tokio::spawn(accept_loop(agent.clone(), listener));
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = agent.shutdown.notified() => break,
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            _ = tick.tick() => agent.check_idle().await,
        }
    }
    info!("agent stopping");
    accept.abort();
    agent.lock().await;
    let _ = fs::remove_file(&socket);
    drop(lock);
    Ok(())
}

async fn accept_loop(agent: Arc<Agent>, listener: UnixListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let agent = agent.clone();
        tokio::spawn(async move {
            if let Err(error) = agent.handle(stream).await {
                warn!("control connection failed: {error:#}");
            }
        });
    }
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
        self.write.lock().await.write_all(&body).await?;
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
        let _ = closed.wait_for(|closed| *closed).await;
    }
}

impl Agent {
    async fn handle(self: Arc<Self>, stream: UnixStream) -> Result<()> {
        let (read, write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        let Some(line) = lines.next_line().await? else {
            return Ok(());
        };
        let (answers_tx, answers) = mpsc::channel(4);
        let (closed_tx, closed) = watch::channel(false);
        let reader = tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(answer) = serde_json::from_str::<Answer>(&line) else {
                    break;
                };
                if answers_tx.send(answer.answer).await.is_err() {
                    break;
                }
            }
            let _ = closed_tx.send(true);
        });
        let conversation = Conversation {
            write: tokio::sync::Mutex::new(write),
            answers: tokio::sync::Mutex::new(answers),
            closed,
        };
        let result = if line.len() > MAX_LINE {
            Err(fail(ErrorCode::Failed, "request too large"))
        } else {
            match serde_json::from_str::<Request>(&line) {
                Ok(request) => {
                    let always = matches!(request.command, Command::Status | Command::Stop);
                    if request.v != PROTOCOL_VERSION && !always {
                        Err(fail(
                            ErrorCode::Version,
                            format!(
                                "the agent speaks protocol {PROTOCOL_VERSION}, not {}; run `deadbolt agent stop`",
                                request.v
                            ),
                        ))
                    } else {
                        self.clone().dispatch(request.command, &conversation).await
                    }
                }
                Err(error) => Err(fail(ErrorCode::Failed, format!("invalid request: {error}"))),
            }
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
        conversation.send(&message).await?;
        conversation.write.lock().await.shutdown().await?;
        reader.abort();
        Ok(())
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
            Command::Stop => {
                self.shutdown.notify_one();
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
            Command::Lock => {
                self.lock().await;
                Ok(Reply::Done)
            }
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
                let (node, removed, vault, device) = self.with(|s| {
                    let id = s.resolve(vault.as_deref())?;
                    let target = s.resolve_device(&id, &device)?;
                    if target == s.id {
                        bail!("cannot remove this device; remove it from another device");
                    }
                    let info = s.device_info(&target, &HashSet::new());
                    s.update(id, |v, secret| {
                        v.remove(secret, target).context("removing device")
                    })?;
                    Ok((s.node.clone(), self.refresh(s), s.vault_info(&id), info))
                })?;
                self.enforce(&node, &removed);
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
            Command::ItemImport { vault, items } => {
                self.with(|s| items::import(s, vault.as_deref(), items))?;
                self.sync_now.notify_one();
                Ok(Reply::Done)
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
        let deadline = tokio::time::Instant::now() + sync::STARTUP_TIMEOUT;
        while !self.ready.load(Ordering::SeqCst) {
            self.with(|_| Ok(()))?;
            if tokio::time::Instant::now() >= deadline {
                bail!("waiting for membership sync");
            }
            tokio::time::sleep_until(
                deadline.min(tokio::time::Instant::now() + Duration::from_millis(50)),
            )
            .await;
        }
        Ok(())
    }

    /// Checks readiness before serving vault data to a pairing peer.
    pub fn with_data<T>(&self, f: impl FnOnce(&mut Session) -> Result<T>) -> Result<T> {
        self.with(|s| {
            if !self.ready.load(Ordering::SeqCst) {
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
        f(session)
    }

    /// Updates the membership gate; returns devices that are no longer
    /// members of any vault.
    pub fn refresh(&self, session: &Session) -> Vec<PeerId> {
        let next = session.peer_set();
        let mut members = self.members.write().unwrap_or_else(|e| e.into_inner());
        let removed = members.difference(&next).copied().collect();
        *members = next;
        removed
    }

    /// Closes connections to devices that are no longer members.
    pub fn enforce(&self, node: &Node, removed: &[PeerId]) {
        for peer in removed {
            let closed = node.revoke(peer);
            info!(peer = %session::short(peer), closed, "revoked device");
        }
        node.enforce_membership();
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
            protocol: PROTOCOL_VERSION,
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

    async fn setup(self: &Arc<Self>, passphrase: String, device_name: String) -> Result<()> {
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
        let passphrase = zeroize::Zeroizing::new(passphrase);
        let dir = self.paths.data.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            Loaded::setup(&dir, passphrase.as_bytes(), &device_name)
        })
        .await??;
        self.start(loaded, None).await
    }

    async fn unlock(self: &Arc<Self>, passphrase: String, timeout_secs: Option<u64>) -> Result<()> {
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
        let passphrase = zeroize::Zeroizing::new(passphrase);
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
        self.ready.store(false, Ordering::SeqCst);
        let node = Node::spawn(config, gate, sync::Handler(self.clone())).await?;
        let session = Session::new(loaded, node);
        self.refresh(&session);
        self.ready
            .store(session.peer_set().is_empty(), Ordering::SeqCst);
        let id: DeviceId = session.id;
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = Some(session);
        self.set_timeout(timeout_secs)?;
        let task = tokio::spawn(sync::run(self.clone()));
        if let Some(old) = self
            .sync_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(task)
        {
            old.abort();
        }
        info!(device = %id, "unlocked");
        Ok(())
    }

    async fn lock(&self) {
        let _transition = self.transition.lock().await;
        if let Some(task) = self
            .sync_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            task.abort();
        }
        let session = self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        self.members
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.ready.store(false, Ordering::SeqCst);
        *self.idle.lock().unwrap_or_else(|e| e.into_inner()) = Idle::default();
        if let Some(session) = session {
            session.node.shutdown().await;
            drop(session);
            info!("locked");
        }
    }
}
