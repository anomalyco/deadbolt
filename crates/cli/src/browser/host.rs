//! The native messaging host: the browser extension's connection to the
//! agent. The message set is specified in `docs/autofill.md`.
//!
//! The browser starts it per `connectNative` and talks over stdin/stdout in
//! frames of a native-endian `u32` length and that many bytes of UTF-8 JSON.
//! Requests are answered in order, but for passkey ceremonies, which answer
//! when done ([`super::passkeys`]), and their cancels, which answer at once
//! however busy the agent is; `changed` messages from the agent's watch
//! stream are pushed in between. It exits when stdin closes.
//!
//! The host only checks requests' shape and turns them into agent commands:
//! the agent finds a page's site from its origin and decides what it gets.
//! The host never prompts for a passphrase or Touch ID.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::passkeys::{self, Ceremonies};
use super::{EXTENSION_ID, extension_origin};
use crate::client;
use crate::paths::Paths;
use crate::protocol::{
    Change, Command, ErrorCode, Fill, LoginRef, Reply, Secret, SignIn, SiteStatus, SiteValues,
};
use crate::site::Site;

/// The version of this message set, in `hello`.
pub const PROTOCOL: u32 = 1;
/// The largest request read; anything bigger is skipped and refused.
pub const MAX_REQUEST: usize = 64 * 1024;
/// The browser's limit on a message from the host.
pub const MAX_REPLY: usize = 1024 * 1024;
/// How often to look for an agent to watch while none runs.
const RECONNECT: Duration = Duration::from_secs(2);

/// The longest item name the vault takes.
const MAX_TITLE: usize = 128;
const MAX_USERNAME: usize = 500;
const MAX_PASSWORD: usize = 4096;
const MAX_URL: usize = 2048;

/// Checks are a password oracle and fills hand out secrets, so a runaway
/// or hostile caller gets them slowly: a burst, then one per interval.
const CHECKS: (u32, Duration) = (20, Duration::from_secs(1));
const FILLS: (u32, Duration) = (60, Duration::from_millis(250));

/// A token bucket: `capacity` at once, refilled one per `every`.
pub(super) struct Bucket {
    capacity: u32,
    every: Duration,
    tokens: u32,
    since: Instant,
}

impl Bucket {
    pub(super) fn new((capacity, every): (u32, Duration), now: Instant) -> Self {
        Self {
            capacity,
            every,
            tokens: capacity,
            since: now,
        }
    }

    pub(super) fn take(&mut self, now: Instant) -> bool {
        let earned = now.saturating_duration_since(self.since).as_nanos() / self.every.as_nanos();
        if earned > 0 {
            let earned = u32::try_from(earned).unwrap_or(u32::MAX);
            self.tokens = self.tokens.saturating_add(earned).min(self.capacity);
            self.since = if self.tokens == self.capacity {
                now
            } else {
                self.since + self.every * earned
            };
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

#[derive(Deserialize)]
struct Head {
    #[serde(default)]
    id: Value,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum Request {
    Hello,
    List {
        origin: String,
    },
    Fill {
        origin: String,
        #[serde(rename = "ref")]
        login: String,
        want: Vec<Fill>,
    },
    Check {
        origin: String,
        username: String,
        password: Secret,
    },
    Save {
        origin: String,
        entry: Entry,
        #[serde(rename = "ref")]
        login: Option<String>,
    },
    PasskeyList(passkeys::List),
    PasskeyCreate(passkeys::Create),
    PasskeyGet(passkeys::Get),
    PasskeyCancel(passkeys::Cancel),
}

#[derive(Deserialize)]
struct Entry {
    title: String,
    url: String,
    username: String,
    password: Secret,
}

#[derive(Serialize)]
pub(super) struct Envelope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) id: Option<Value>,
    #[serde(flatten)]
    pub(super) body: Body,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub(super) enum Body {
    #[serde(rename_all = "camelCase")]
    Hello {
        protocol: u32,
        version: String,
        status: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        capabilities: [&'static str; 5],
    },
    List {
        site: String,
        accounts: Vec<Account>,
    },
    Fill {
        #[serde(flatten)]
        values: SiteValues,
    },
    Check {
        status: SiteStatus,
        matches: Vec<String>,
    },
    Save {
        #[serde(rename = "ref")]
        login: String,
        created: bool,
    },
    Error {
        code: Code,
        message: String,
    },
    Changed {
        change: &'static str,
    },
    Passkeys(passkeys::Listed),
    PasskeyCreated(passkeys::Created),
    PasskeyAssertion(passkeys::Assertion),
    PasskeyCancelled {
        found: bool,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Account {
    #[serde(rename = "ref")]
    login: String,
    vault: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    has_password: bool,
    has_totp: bool,
    urls: Vec<String>,
    /// `{provider, account?}` for a "Sign in with Google" login.
    #[serde(skip_serializing_if = "Option::is_none")]
    sign_in: Option<SignIn>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Code {
    Locked,
    NotFound,
    DomainMismatch,
    BadRequest,
    RateLimited,
    /// A passkey the registration excluded is already saved.
    Exists,
    /// A passkey ceremony stopped by `passkey-cancel`.
    Cancelled,
    Failed,
}

pub(super) struct Refusal {
    code: Code,
    message: String,
}

impl Refusal {
    pub(super) fn body(self) -> Body {
        Body::Error {
            code: self.code,
            message: self.message,
        }
    }

    pub(super) fn bad(message: impl Into<String>) -> Self {
        Self {
            code: Code::BadRequest,
            message: message.into(),
        }
    }

    pub(super) fn slow_down() -> Self {
        Self {
            code: Code::RateLimited,
            message: "too many requests; try again in a moment".into(),
        }
    }
}

impl From<anyhow::Error> for Refusal {
    fn from(error: anyhow::Error) -> Self {
        let code = match client::code(&error) {
            Some(ErrorCode::Locked | ErrorCode::NotInitialized) => Code::Locked,
            Some(ErrorCode::NotFound) => Code::NotFound,
            Some(ErrorCode::DomainMismatch) => Code::DomainMismatch,
            Some(ErrorCode::Exists) => Code::Exists,
            Some(ErrorCode::Version | ErrorCode::Failed) => Code::Failed,
            None if matches!(
                error.downcast_ref::<deadbolt_client::Error>(),
                Some(deadbolt_client::Error::Connect(_))
            ) =>
            {
                return Self {
                    code: Code::Locked,
                    message: "Deadbolt isn't running: unlock it".into(),
                };
            }
            None => Code::Failed,
        };
        let mut message = format!("{error:#}");
        if let Some((end, _)) = message.char_indices().nth(200) {
            message.truncate(end);
        }
        Self { code, message }
    }
}

/// Serves the extension at `origin` until stdin closes.
pub async fn run(paths: Paths, origin: &str) -> Result<()> {
    if origin != extension_origin() {
        bail!(
            "refusing {origin:?}: only the Deadbolt extension ({EXTENSION_ID}) may use this host"
        );
    }
    let input = stdin()?;
    let (frames, outbox) = mpsc::channel(16);
    let mut writer = tokio::spawn(write_frames(tokio::io::stdout(), outbox));
    let mut host = Host::new(paths);
    let watcher = tokio::spawn(watch(
        host.serial.paths.clone(),
        frames.clone(),
        host.serial.announce.clone(),
        RECONNECT,
    ));
    // The browser hanging up closes stdout as well as stdin: stop on either.
    let served = tokio::select! {
        served = host.serve(input, &frames) => served,
        written = &mut writer => {
            watcher.abort();
            return written?;
        }
    };
    watcher.abort();
    drop(frames);
    let written = writer.await?;
    served.and(written)
}

/// Stdin, readable without a blocking thread when it's a pipe (as a
/// browser runs the host), so the host can stop while a read waits.
fn stdin() -> Result<Box<dyn AsyncRead + Unpin + Send>> {
    use std::os::fd::AsFd;
    let fd = std::io::stdin().as_fd().try_clone_to_owned()?;
    Ok(match tokio::net::unix::pipe::Receiver::from_owned_fd(fd) {
        Ok(pipe) => Box::new(pipe),
        Err(_) => Box::new(tokio::io::stdin()),
    })
}

fn refuse(id: Value, refusal: Refusal) -> Envelope {
    Envelope {
        id: Some(id),
        body: refusal.body(),
    }
}

/// Why a request isn't valid, by position only: serde's messages can
/// quote the values in it.
fn invalid(error: &serde_json::Error) -> String {
    let what = match error.classify() {
        serde_json::error::Category::Data => "not a request this host knows",
        _ => "not valid JSON",
    };
    format!("invalid request: {what} (column {})", error.column())
}

fn site(origin: &str) -> Result<(), Refusal> {
    Site::from_origin(origin)
        .map(drop)
        .map_err(|reason| Refusal::bad(format!("origin {origin:?}: {reason}")))
}

pub(super) fn parse_ref(text: &str) -> Result<LoginRef, Refusal> {
    let hex = |s: &str, len: usize| {
        s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    match text.split_once(':') {
        Some((vault, item)) if hex(vault, 64) && hex(item, 32) => Ok(LoginRef {
            vault: vault.into(),
            item: item.into(),
        }),
        _ => Err(Refusal::bad("invalid ref")),
    }
}

pub(super) fn format_ref(login: &LoginRef) -> String {
    format!("{}:{}", login.vault, login.item)
}

fn check_login(username: &str, password: &Secret) -> Result<(), Refusal> {
    if username.chars().count() > MAX_USERNAME {
        return Err(Refusal::bad(format!(
            "a username is at most {MAX_USERNAME} characters"
        )));
    }
    let len = password.expose().chars().count();
    if len == 0 || len > MAX_PASSWORD {
        return Err(Refusal::bad(format!(
            "a password is 1 to {MAX_PASSWORD} characters"
        )));
    }
    Ok(())
}

pub(super) async fn call(paths: &Paths, command: Command) -> Result<Reply, Refusal> {
    Ok(client::simple(paths, command)
        .await
        .map_err(anyhow::Error::from)?)
}

pub(super) fn unexpected() -> Refusal {
    Refusal {
        code: Code::Failed,
        message: "unexpected reply from the agent".into(),
    }
}

/// One connection's state. Requests that ask the agent are answered one
/// at a time, in order ([`Serial`]); passkey ceremonies and cancels are
/// dealt with as they arrive, so a cancel never waits behind them.
struct Host {
    serial: Serial,
    ceremonies: Ceremonies,
}

/// The state of requests answered in order.
struct Serial {
    paths: Paths,
    /// Whether the watcher says `started` when it next finds an agent: set
    /// when a watched agent goes away or hello couldn't reach one, cleared
    /// when hello did.
    announce: Arc<AtomicBool>,
    checks: Bucket,
    fills: Bucket,
    passkey_lists: Bucket,
}

/// Where a request goes once read.
enum Triage {
    /// Answered at once.
    Now(Envelope),
    /// A passkey ceremony, which answers on `frames` when it's done.
    Later,
    /// Answered in order, after the requests before it.
    Queue(Value, Request),
}

/// Requests read but not yet answered in order; past this they're refused.
const QUEUED: usize = 64;

impl Host {
    fn new(paths: Paths) -> Self {
        let now = Instant::now();
        Self {
            serial: Serial {
                paths,
                announce: Arc::new(AtomicBool::new(false)),
                checks: Bucket::new(CHECKS, now),
                fills: Bucket::new(FILLS, now),
                passkey_lists: Bucket::new(passkeys::LISTS, now),
            },
            ceremonies: Ceremonies::new(now),
        }
    }

    async fn serve(
        &mut self,
        mut input: impl AsyncRead + Unpin,
        frames: &mpsc::Sender<Zeroizing<Vec<u8>>>,
    ) -> Result<()> {
        let (queue, mut queued) = mpsc::channel::<(Value, Request)>(QUEUED);
        let Self { serial, ceremonies } = self;
        let paths = serial.paths.clone();
        let answering = async {
            while let Some((id, request)) = queued.recv().await {
                let envelope = serial.answer(id, request).await;
                if frames.send(encode(&envelope)?).await.is_err() {
                    break;
                }
            }
            anyhow::Ok(())
        };
        let reading = async move {
            loop {
                let mut prefix = [0u8; 4];
                match input.read_exact(&mut prefix).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                    Err(e) => return Err(e.into()),
                }
                let len = u32::from_ne_bytes(prefix) as usize;
                let envelope = if len > MAX_REQUEST {
                    let skipped =
                        tokio::io::copy(&mut (&mut input).take(len as u64), &mut tokio::io::sink())
                            .await?;
                    if skipped < len as u64 {
                        return Ok(());
                    }
                    refuse(
                        Value::Null,
                        Refusal::bad(format!(
                            "a request is at most {MAX_REQUEST} bytes; this was {len}"
                        )),
                    )
                } else {
                    let mut body = Zeroizing::new(vec![0u8; len]);
                    match input.read_exact(&mut body).await {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                        Err(e) => return Err(e.into()),
                    }
                    match triage(&paths, ceremonies, &body, frames).await {
                        Triage::Now(envelope) => envelope,
                        Triage::Later => continue,
                        Triage::Queue(id, request) => match queue.try_send((id, request)) {
                            Ok(()) => continue,
                            Err(mpsc::error::TrySendError::Full((id, _))) => {
                                refuse(id, Refusal::slow_down())
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                        },
                    }
                };
                if frames.send(encode(&envelope)?).await.is_err() {
                    return Ok(());
                }
            }
        };
        let (read, answered) = tokio::join!(reading, answering);
        read.and(answered)
    }

    /// The answer to one request, or `None` for a passkey ceremony that
    /// answers on `frames` when it's done.
    #[cfg(test)]
    async fn answer(
        &mut self,
        body: &[u8],
        frames: &mpsc::Sender<Zeroizing<Vec<u8>>>,
    ) -> Option<Envelope> {
        match triage(&self.serial.paths, &mut self.ceremonies, body, frames).await {
            Triage::Now(envelope) => Some(envelope),
            Triage::Later => None,
            Triage::Queue(id, request) => Some(self.serial.answer(id, request).await),
        }
    }
}

/// Reads one request: answers it at once if it's malformed or a passkey
/// cancel, starts it if it's a passkey ceremony, else queues it.
async fn triage(
    paths: &Paths,
    ceremonies: &mut Ceremonies,
    body: &[u8],
    frames: &mpsc::Sender<Zeroizing<Vec<u8>>>,
) -> Triage {
    let id = match serde_json::from_slice::<Head>(body) {
        Ok(Head {
            id: id @ (Value::String(_) | Value::Number(_)),
        }) if id.as_str().is_none_or(|s| s.len() <= 200) => id,
        Ok(_) => {
            return Triage::Now(refuse(Value::Null, Refusal::bad("a request needs an id")));
        }
        Err(_) => {
            return Triage::Now(refuse(
                Value::Null,
                Refusal::bad("a request is a JSON object"),
            ));
        }
    };
    let request = match serde_json::from_slice::<Request>(body) {
        Ok(request) => request,
        Err(e) => return Triage::Now(refuse(id, Refusal::bad(invalid(&e)))),
    };
    let ceremony = match request {
        Request::PasskeyCreate(create) => passkeys::create_command(create),
        Request::PasskeyGet(get) => passkeys::get_command(get),
        Request::PasskeyCancel(cancel) => {
            let body = ceremonies.cancel(cancel, frames).await;
            return Triage::Now(Envelope { id: Some(id), body });
        }
        request => return Triage::Queue(id, request),
    };
    match ceremonies.start(paths, id.clone(), ceremony, frames) {
        Ok(()) => Triage::Later,
        Err(refusal) => Triage::Now(refuse(id, refusal)),
    }
}

impl Serial {
    async fn answer(&mut self, id: Value, request: Request) -> Envelope {
        match self.handle(request).await {
            Ok(body) => Envelope { id: Some(id), body },
            Err(refusal) => refuse(id, refusal),
        }
    }

    async fn handle(&mut self, request: Request) -> Result<Body, Refusal> {
        match request {
            Request::Hello => {
                // Cleared first: the agent this hello may start must not be
                // announced if the watcher reconnects before hello returns.
                self.announce.store(false, Ordering::SeqCst);
                let (body, reached) = hello(&self.paths).await;
                self.announce.store(!reached, Ordering::SeqCst);
                Ok(body)
            }
            Request::List { origin } => {
                site(&origin)?;
                let Reply::SiteLogins { site, logins } =
                    call(&self.paths, Command::SiteLogins { origin }).await?
                else {
                    return Err(unexpected());
                };
                let accounts = logins
                    .into_iter()
                    .map(|l| Account {
                        login: format_ref(&l.login),
                        vault: l.vault,
                        title: l.title,
                        username: l.username,
                        has_password: l.has_password,
                        has_totp: l.has_otp,
                        urls: l.urls,
                        sign_in: l.sign_in,
                    })
                    .collect();
                Ok(Body::List { site, accounts })
            }
            Request::Fill {
                origin,
                login,
                mut want,
            } => {
                site(&origin)?;
                let login = parse_ref(&login)?;
                if !self.fills.take(Instant::now()) {
                    return Err(Refusal::slow_down());
                }
                want.sort_unstable_by_key(|f| *f as u8);
                want.dedup();
                if want.is_empty() || want.len() > 3 {
                    return Err(Refusal::bad("want names username, password and/or totp"));
                }
                let Reply::SiteFill { values } = call(
                    &self.paths,
                    Command::SiteFill {
                        origin,
                        login,
                        want,
                    },
                )
                .await?
                else {
                    return Err(unexpected());
                };
                Ok(Body::Fill { values })
            }
            Request::Check {
                origin,
                username,
                password,
            } => {
                site(&origin)?;
                check_login(&username, &password)?;
                if !self.checks.take(Instant::now()) {
                    return Err(Refusal::slow_down());
                }
                let Reply::SiteCheck { status, matches } = call(
                    &self.paths,
                    Command::SiteCheck {
                        origin,
                        username,
                        password,
                    },
                )
                .await?
                else {
                    return Err(unexpected());
                };
                Ok(Body::Check {
                    status,
                    matches: matches.iter().map(format_ref).collect(),
                })
            }
            Request::Save {
                origin,
                entry,
                login,
            } => {
                site(&origin)?;
                let login = login.as_deref().map(parse_ref).transpose()?;
                check_login(&entry.username, &entry.password)?;
                let title = entry.title.trim();
                if title.is_empty() || title.chars().count() > MAX_TITLE {
                    return Err(Refusal::bad(format!(
                        "a title is 1 to {MAX_TITLE} characters"
                    )));
                }
                if entry.url.len() > MAX_URL {
                    return Err(Refusal::bad(format!(
                        "entry.url is at most {MAX_URL} bytes"
                    )));
                }
                let url = crate::site::page_url(&entry.url)
                    .map_err(|reason| Refusal::bad(format!("entry.url: {reason}")))?;
                let Reply::SiteSaved { login, created } = call(
                    &self.paths,
                    Command::SiteSave {
                        origin,
                        login,
                        title: title.into(),
                        url: url.into(),
                        username: entry.username,
                        password: entry.password,
                    },
                )
                .await?
                else {
                    return Err(unexpected());
                };
                Ok(Body::Save {
                    login: format_ref(&login),
                    created,
                })
            }
            Request::PasskeyList(list) => {
                if !self.passkey_lists.take(Instant::now()) {
                    return Err(Refusal::slow_down());
                }
                passkeys::list(&self.paths, list).await
            }
            Request::PasskeyCreate(_) | Request::PasskeyGet(_) | Request::PasskeyCancel(_) => {
                Err(unexpected())
            }
        }
    }
}

/// Starts the agent if none runs, never unlocking it.
/// Also whether an agent answered.
async fn hello(paths: &Paths) -> (Body, bool) {
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
        capabilities: ["list", "fill", "check", "save", "passkeys"],
    };
    (body, status != "unavailable")
}

/// What the extension hears of a change in the agent, if anything.
fn changed(change: &Change) -> Option<&'static str> {
    match change {
        Change::Locked => Some("locked"),
        Change::Unlocked => Some("unlocked"),
        Change::Items { .. } | Change::Vaults | Change::Resync => Some("items"),
        Change::Stopping => Some("stopped"),
        Change::Watching | Change::Devices { .. } => None,
    }
}

/// Pushes the agent's changes. While no agent runs it looks for one every
/// `reconnect`. A stream counts only once the agent said it's watching: one
/// that refuses or hangs up first (an agent of another protocol) is no
/// change. Says `started` on finding an agent if `announce` is set.
async fn watch(
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
        if let Ok(mut stream) = deadbolt_client::watch(&paths).await {
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

/// One frame: the length prefix and the JSON. A reply over the browser's
/// limit becomes an error.
pub(super) fn encode(envelope: &Envelope) -> Result<Zeroizing<Vec<u8>>> {
    let mut frame = deadbolt_client::encode_json(&[0; 4], envelope, b"")?;
    if frame.len() - 4 > MAX_REPLY {
        let error = refuse(
            envelope.id.clone().unwrap_or_default(),
            Refusal {
                code: Code::Failed,
                message: "the reply is too large".into(),
            },
        );
        return encode(&error);
    }
    let len = u32::try_from(frame.len() - 4)?;
    frame[..4].copy_from_slice(&len.to_ne_bytes());
    Ok(frame)
}

async fn write_frames(
    mut output: impl AsyncWrite + Unpin,
    mut frames: mpsc::Receiver<Zeroizing<Vec<u8>>>,
) -> Result<()> {
    while let Some(frame) = frames.recv().await {
        let written = match output.write_all(&frame).await {
            Ok(()) => output.flush().await,
            Err(e) => Err(e),
        };
        match written {
            Ok(()) => {}
            // The browser hung up.
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Message;

    fn json(envelope: &Envelope) -> Value {
        let frame = encode(envelope).unwrap();
        let len = u32::from_ne_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(len, frame.len() - 4);
        serde_json::from_slice(&frame[4..]).unwrap()
    }

    #[test]
    fn replies_have_the_documented_shapes() {
        let fill = Envelope {
            id: Some("3".into()),
            body: Body::Fill {
                values: SiteValues {
                    username: Some("octocat".into()),
                    password: Some(Secret::new("hunter2")),
                    totp: None,
                },
            },
        };
        assert_eq!(
            json(&fill),
            serde_json::json!({"id": "3", "type": "fill", "username": "octocat", "password": "hunter2"})
        );
        let list = Envelope {
            id: Some(2.into()),
            body: Body::List {
                site: "github.com".into(),
                accounts: vec![
                    Account {
                        login: "a:b".into(),
                        vault: "personal".into(),
                        title: "GitHub".into(),
                        username: None,
                        has_password: true,
                        has_totp: false,
                        urls: vec!["https://github.com".into()],
                        sign_in: None,
                    },
                    Account {
                        login: "a:c".into(),
                        vault: "personal".into(),
                        title: "GitHub".into(),
                        username: None,
                        has_password: false,
                        has_totp: false,
                        urls: vec!["https://github.com".into()],
                        sign_in: Some(SignIn {
                            provider: "google".into(),
                            account: Some("dax@example.com".into()),
                        }),
                    },
                ],
            },
        };
        assert_eq!(
            json(&list),
            serde_json::json!({"id": 2, "type": "list", "site": "github.com", "accounts": [
                {"ref": "a:b", "vault": "personal", "title": "GitHub", "hasPassword": true,
                 "hasTotp": false, "urls": ["https://github.com"]},
                {"ref": "a:c", "vault": "personal", "title": "GitHub", "hasPassword": false,
                 "hasTotp": false, "urls": ["https://github.com"],
                 "signIn": {"provider": "google", "account": "dax@example.com"}}
            ]})
        );
        let changed = Envelope {
            id: None,
            body: Body::Changed { change: "locked" },
        };
        assert_eq!(
            json(&changed),
            serde_json::json!({"type": "changed", "change": "locked"})
        );
        let error = refuse(Value::Null, Refusal::bad("nope"));
        assert_eq!(
            json(&error),
            serde_json::json!({"id": null, "type": "error", "code": "bad_request", "message": "nope"})
        );
        let check = Envelope {
            id: Some("4".into()),
            body: Body::Check {
                status: SiteStatus::Update,
                matches: vec!["a:b".into()],
            },
        };
        assert_eq!(
            json(&check),
            serde_json::json!({"id": "4", "type": "check", "status": "update", "matches": ["a:b"]})
        );
    }

    #[test]
    fn a_reply_over_the_browser_limit_becomes_an_error() {
        let big = Envelope {
            id: Some("1".into()),
            body: Body::List {
                site: "github.com".into(),
                accounts: (0..20_000)
                    .map(|i| Account {
                        login: format!("{i:0>129}"),
                        vault: "personal".into(),
                        title: "GitHub".into(),
                        username: None,
                        has_password: true,
                        has_totp: false,
                        urls: vec![],
                        sign_in: None,
                    })
                    .collect(),
            },
        };
        let reply = json(&big);
        assert_eq!(reply["type"], "error");
        assert_eq!(reply["code"], "failed");
        assert_eq!(reply["id"], "1");
    }

    #[test]
    fn frames_fit_their_buffers_exactly() {
        let fill = Envelope {
            id: Some("3".into()),
            body: Body::Fill {
                values: SiteValues {
                    username: None,
                    password: Some(Secret::new("p".repeat(1000))),
                    totp: None,
                },
            },
        };
        let frame = encode(&fill).unwrap();
        assert_eq!(frame.capacity(), frame.len());
    }

    #[test]
    fn buckets_allow_a_burst_then_one_per_interval() {
        let start = Instant::now();
        let second = Duration::from_secs(1);
        let mut bucket = Bucket::new((3, second), start);
        assert!((0..3).all(|_| bucket.take(start)));
        assert!(!bucket.take(start));
        assert!(!bucket.take(start + second / 2));
        assert!(bucket.take(start + second));
        assert!(!bucket.take(start + second * 3 / 2));
        // A long pause refills to the burst, no more.
        let later = start + second * 100;
        assert!((0..3).all(|_| bucket.take(later)));
        assert!(!bucket.take(later));
        // Partial intervals carry over.
        assert!(!bucket.take(later + second * 7 / 10));
        assert!(bucket.take(later + second * 14 / 10));
        assert!(!bucket.take(later + second * 19 / 10));
        assert!(bucket.take(later + second * 2));
    }

    /// A fake agent at `paths`: each connection gets the next of `script`'s
    /// lines and is closed, round and round if `cycle`, else holding the
    /// last connection open.
    fn fake_agent(paths: &Paths, script: Vec<Vec<Message>>, cycle: bool) {
        let listener = tokio::net::UnixListener::bind(&paths.socket).unwrap();
        tokio::spawn(async move {
            let count = script.len();
            let mut held = Vec::new();
            for n in 0.. {
                if !cycle && n == count {
                    break;
                }
                let (mut conn, _) = listener.accept().await.unwrap();
                for message in &script[n % count] {
                    let line = deadbolt_client::encode_json(b"", message, b"\n").unwrap();
                    conn.write_all(&line).await.ok();
                }
                if !cycle && n + 1 == count {
                    held.push(conn);
                }
            }
            std::future::pending::<()>().await;
            drop(held);
        });
    }

    fn test_paths(dir: &std::path::Path) -> Paths {
        Paths {
            data: dir.join("data"),
            config: dir.join("config"),
            socket: dir.join("s"),
            lock: dir.join("lock"),
            log: dir.join("log"),
        }
    }

    async fn pushes(paths: Paths, announce: bool, run: Duration) -> (Vec<Value>, bool) {
        let (frames, mut outbox) = mpsc::channel(1024);
        let announce = Arc::new(AtomicBool::new(announce));
        let watcher = tokio::spawn(watch(
            paths,
            frames,
            announce.clone(),
            Duration::from_millis(10),
        ));
        tokio::time::sleep(run).await;
        watcher.abort();
        let mut pushed = Vec::new();
        while let Ok(frame) = outbox.try_recv() {
            let body: Value = serde_json::from_slice(&frame[4..]).unwrap();
            pushed.push(body["change"].clone());
        }
        (pushed, announce.load(Ordering::SeqCst))
    }

    /// An agent that won't be watched (another protocol) or hangs up
    /// before watching isn't one that stopped.
    #[tokio::test]
    async fn a_refused_watch_is_no_change() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(dir.path());
        let refused = Message::Error {
            code: ErrorCode::Version,
            message: "the agent speaks protocol 6".into(),
        };
        fake_agent(&paths, vec![vec![refused], vec![]], true);
        let (pushed, announce) = pushes(paths, false, Duration::from_millis(300)).await;
        assert_eq!(pushed, Vec::<Value>::new());
        assert!(!announce);
    }

    #[tokio::test]
    async fn an_agent_that_goes_away_is_announced_when_back() {
        let watching = || Message::Change {
            change: Change::Watching,
        };
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(dir.path());
        fake_agent(
            &paths,
            vec![
                vec![
                    watching(),
                    Message::Change {
                        change: Change::Locked,
                    },
                ],
                vec![watching()],
            ],
            false,
        );
        let (pushed, announce) = pushes(paths, false, Duration::from_millis(300)).await;
        assert_eq!(pushed, ["locked", "stopped", "started"]);
        assert!(!announce);

        // Armed by a hello that found no agent.
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(dir.path());
        fake_agent(&paths, vec![vec![watching()]], false);
        let (pushed, _) = pushes(paths, true, Duration::from_millis(300)).await;
        assert_eq!(pushed, ["started"]);
    }

    #[test]
    fn refs_are_a_vault_id_and_an_item_id() {
        let vault = "ab".repeat(32);
        let item = "cd".repeat(16);
        let login = parse_ref(&format!("{vault}:{item}")).ok().unwrap();
        assert_eq!(format_ref(&login), format!("{vault}:{item}"));
        for bad in [
            "",
            ":",
            &vault,
            &format!("{vault}:"),
            &format!("{vault}:{}", &item[2..]),
            &format!("{vault}:{vault}"),
            &format!("{item}:{vault}"),
            &format!("{}:{item}", vault.to_uppercase()),
            &format!("{vault}:{item}:{item}"),
        ] {
            assert!(parse_ref(bad).is_err(), "{bad:?}");
        }
    }

    /// A passkey ceremony waits on Touch ID beside other requests, and a
    /// cancel stops it and answers it.
    #[tokio::test]
    async fn passkey_ceremonies_answer_when_done_and_can_be_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(dir.path());
        // An agent that takes the request and never answers.
        fake_agent(&paths, vec![vec![]], false);
        let mut host = Host::new(paths);
        let (frames, mut outbox) = mpsc::channel(16);
        let get = serde_json::json!({
            "id": "p1", "type": "passkey-get", "origin": "https://example.com",
            "ref": format!("{}:{}", "ab".repeat(32), "cd".repeat(16)),
            "challenge": "AAAAAAAAAAAAAAAAAAAAAA", "userVerification": "preferred",
        });
        let body = serde_json::to_vec(&get).unwrap();
        assert!(
            host.answer(&body, &frames).await.is_none(),
            "answered later"
        );
        let again = host.answer(&body, &frames).await.unwrap();
        assert_eq!(json(&again)["code"], "bad_request", "one per id");

        let cancel = br#"{"id": 9, "type": "passkey-cancel", "request": "p1"}"#;
        let cancelled = host.answer(cancel, &frames).await.unwrap();
        assert_eq!(
            json(&cancelled),
            serde_json::json!({"id": 9, "type": "passkey-cancelled", "found": true})
        );
        let frame = outbox.recv().await.unwrap();
        let answer: Value = serde_json::from_slice(&frame[4..]).unwrap();
        assert_eq!(
            answer,
            serde_json::json!({"id": "p1", "type": "error", "code": "cancelled",
                               "message": "the passkey request was cancelled"})
        );
        let none = host.answer(cancel, &frames).await.unwrap();
        assert_eq!(json(&none)["found"], false);
        assert!(outbox.try_recv().is_err());
    }

    fn framed(request: Value) -> Vec<u8> {
        let body = serde_json::to_vec(&request).unwrap();
        let mut frame = u32::try_from(body.len()).unwrap().to_ne_bytes().to_vec();
        frame.extend(body);
        frame
    }

    /// A page flooding passkey calls keeps the agent busy listing; another
    /// tab's cancel is still answered at once.
    #[tokio::test]
    async fn a_cancel_is_not_stuck_behind_listing() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(dir.path());
        // An agent that takes every request and never answers.
        let listener = tokio::net::UnixListener::bind(&paths.socket).unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((conn, _)) = listener.accept().await {
                held.push(conn);
            }
        });
        let mut host = Host::new(paths);
        let (frames, mut outbox) = mpsc::channel(16);
        let (mut browser, input) = tokio::io::duplex(64 * 1024);
        let serving = tokio::spawn(async move { host.serve(input, &frames).await });

        let get = serde_json::json!({
            "id": "p1", "type": "passkey-get", "origin": "https://example.com",
            "ref": format!("{}:{}", "ab".repeat(32), "cd".repeat(16)),
            "challenge": "AAAAAAAAAAAAAAAAAAAAAA", "userVerification": "preferred",
        });
        browser.write_all(&framed(get)).await.unwrap();
        for n in 0..5 {
            let list = serde_json::json!({"id": n, "type": "passkey-list", "origin": "https://flood.example"});
            browser.write_all(&framed(list)).await.unwrap();
        }
        let cancel = serde_json::json!({"id": "c1", "type": "passkey-cancel", "request": "p1"});
        browser.write_all(&framed(cancel)).await.unwrap();

        let mut answers = Vec::new();
        for _ in 0..2 {
            let frame = tokio::time::timeout(Duration::from_secs(5), outbox.recv())
                .await
                .expect("the cancel is answered while listing waits")
                .unwrap();
            answers.push(serde_json::from_slice::<Value>(&frame[4..]).unwrap());
        }
        answers.sort_by_key(|a| a["id"].to_string());
        assert_eq!(answers[0]["type"], "passkey-cancelled");
        assert_eq!(answers[0]["found"], true);
        assert_eq!(answers[1]["code"], "cancelled");
        assert!(outbox.try_recv().is_err(), "the lists still wait");
        serving.abort();
    }

    /// Listing comes before anyone is asked, so it's limited like checks.
    #[tokio::test]
    async fn passkey_lists_are_rate_limited() {
        let dir = tempfile::tempdir().unwrap();
        // No agent: each list that gets through says so.
        let mut host = Host::new(test_paths(dir.path()));
        let (frames, _outbox) = mpsc::channel(16);
        let list = br#"{"id": 1, "type": "passkey-list", "origin": "https://example.com"}"#;
        for _ in 0..passkeys::LISTS.0 {
            let answer = host.answer(list, &frames).await.unwrap();
            assert_eq!(json(&answer)["code"], "locked");
        }
        let answer = host.answer(list, &frames).await.unwrap();
        assert_eq!(json(&answer)["code"], "rate_limited");
    }
}
