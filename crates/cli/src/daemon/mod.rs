//! The background daemon: the only process that opens the store. Holds it
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
mod legacy;
mod macos_autofill;
mod mirror;
mod pairing;
mod passkeys;
mod secrets;
mod send;
mod session;
#[cfg(test)]
mod sim;
mod ssh_cleanup;
pub(crate) mod ssh_keys;
mod sync;
mod system;
#[cfg(test)]
mod tests;
mod updates;
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

use crate::client::{DaemonError, protocol, version};
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

pub struct Daemon {
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
    /// or enrolled during this daemon's lifetime) and not explicitly turned off,
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
    /// Set as the daemon stops, ending sends and anyone waiting on one.
    stopping: watch::Sender<bool>,
    /// What the background update check last found (`updates`).
    update: Mutex<Option<crate::protocol::UpdateInfo>>,
}

impl Daemon {
    fn new(paths: Paths, local_net: bool, kdf: deadbolt_store::KdfParams) -> Arc<Daemon> {
        let initial_slot = biometric::read_token_meta(&paths.data);
        biometric::spawn_background_refresh();
        Arc::new(Daemon {
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
            update: Mutex::default(),
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
    }
}

/// See [`Daemon::busy`].
struct Busy<'a>(&'a AtomicUsize);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.cancel_biometric_prompt();
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
    DaemonError {
        code,
        message: message.into(),
        grant: None,
        passkeys: None,
    }
    .into()
}

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
        serde_json::error::Category::Data => "not a request this daemon knows",
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

impl Daemon {
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
                            "the daemon speaks protocol {}, not {}; run `deadbolt debug daemon stop`",
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
                    // reads it, or the daemon stopping, can't lose the entry.
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
            Err(error) => match error.downcast::<DaemonError>() {
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
        // Nor are sends, which never touch the vault, nor SSH key generation.
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
            Command::SiteLink {
                origin,
                title,
                url,
                provider,
                account,
            } => {
                let (login, created) = self.with(|s| {
                    autofill::link(
                        s,
                        autofill::Link {
                            origin: &origin,
                            title: &title,
                            url: &url,
                            provider: &provider,
                            account: &account,
                        },
                    )
                })?;
                if created {
                    self.sync_now.notify_one();
                }
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
            Command::SshGenerate { kind, comment } => self.ssh_generate(kind, comment.as_deref()),
            Command::SshInspect {
                private_key,
                passphrase,
                comment,
            } => self.ssh_inspect(&private_key, passphrase.as_ref(), comment.as_deref()),
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

    /// Streams changes to one watcher until it hangs up or the daemon stops.
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
    pub fn refresh(&self, session: &Session) {
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
        let touch_id_cfg = Config::load(&self.paths.config)
            .map(|c| c.touch_id())
            .unwrap_or(false);
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
            // Filled in for the connection that asked (`handle`).
            caller: caller::nobody(),
            update: self
                .update
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
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

    /// Like [`Daemon::unlock_biometric`], with a custom `reason` on the Touch ID
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
            daemon: &'a Daemon,
            cancel: Arc<biometric::CancelHandle>,
            done_tx: Option<watch::Sender<Option<Result<(), String>>>>,
        }
        impl FlightCleanup<'_> {
            fn clear_flight(&self) {
                let mut guard = self
                    .daemon
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
            daemon: self,
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
        let session = Session::new(loaded, node);
        self.refresh(&session);
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
