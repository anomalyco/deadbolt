//! The native messaging host: the browser extension's connection to the
//! daemon. The message set is specified in `docs/autofill.md`.
//!
//! The browser starts it per `connectNative` and talks over stdin/stdout in
//! frames of a native-endian `u32` length and that many bytes of UTF-8 JSON.
//! Requests are answered in order, but for passkey ceremonies, which answer
//! when done ([`super::passkeys`]), and their cancels, which answer at once
//! however busy the daemon is; `changed` messages from the daemon's watch
//! stream are pushed in between. It exits when stdin closes.
//!
//! The host only checks requests' shape and turns them into daemon commands:
//! the daemon finds a page's site from its origin and decides what it gets.
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
    CARD_FORM_FIELDS, Change, Command, ErrorCode, FieldInput, Fill, FormCard, FormIdentity,
    FormKind, IDENTITY_FORM_FIELDS, LoginRef, PagePassword, Reply, Secret, SignIn, SiteField,
    SiteStatus, SiteValues,
};
use crate::site::Site;

/// The version of this message set, in `hello`.
pub const PROTOCOL: u32 = 3;
/// The largest request read; anything bigger is skipped and refused.
pub const MAX_REQUEST: usize = 64 * 1024;
/// The browser's limit on a message from the host.
pub const MAX_REPLY: usize = 1024 * 1024;
/// How often to look for a daemon to watch while none runs.
const RECONNECT: Duration = Duration::from_secs(2);

/// The longest item name the vault takes.
const MAX_TITLE: usize = 128;
const MAX_USERNAME: usize = 500;
const MAX_PASSWORD: usize = 4096;
const MAX_URL: usize = 2048;
/// The longest `passwordrules` or `pattern` character set a page sends.
const MAX_RULES: usize = 1024;

/// Checks are a password oracle and fills hand out secrets, so a runaway
/// or hostile caller gets them slowly: a burst, then one per interval.
const CHECKS: (u32, Duration) = (20, Duration::from_secs(1));
const FILLS: (u32, Duration) = (60, Duration::from_millis(250));
/// Learning logs a line per sign-in step and frame: a burst, then a steady trickle.
const LEARNS: (u32, Duration) = (100, Duration::from_millis(100));
/// The most one learning session's log grows to; past it lines are refused.
const MAX_LEARN_LOG: u64 = 4 * 1024 * 1024;
/// How many session logs are kept, and for how long; a new session prunes the rest, oldest first.
const MAX_LEARN_LOGS: usize = 10;
const LEARN_LOG_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// The most of a log one `learn-read` answers: escaped, well under `MAX_REPLY`.
const LEARN_READ: u64 = 256 * 1024;

/// A token bucket: `capacity` at once, refilled one per `every`.
pub(crate) struct Bucket {
    capacity: u32,
    every: Duration,
    tokens: u32,
    since: Instant,
}

impl Bucket {
    pub(crate) fn new((capacity, every): (u32, Duration), now: Instant) -> Self {
        Self {
            capacity,
            every,
            tokens: capacity,
            since: now,
        }
    }

    pub(crate) fn take(&mut self, now: Instant) -> bool {
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
    Generate {
        origin: String,
        #[serde(flatten)]
        field: Field,
    },
    GenerateCheck {
        origin: String,
        #[serde(flatten)]
        field: Field,
    },
    GenerateKeep {
        origin: String,
        generated: String,
    },
    GenerateDrop {
        origin: String,
        generated: String,
    },
    Check {
        origin: String,
        username: Option<String>,
        password: Option<Secret>,
        generated: Option<String>,
    },
    Save {
        origin: String,
        entry: Entry,
        #[serde(rename = "ref")]
        login: Option<String>,
    },
    /// The identities and cards a form on the page can be filled from.
    Forms {
        origin: String,
        kinds: Vec<FormKind>,
    },
    /// Some fields of one identity or card.
    FillForm {
        origin: String,
        #[serde(rename = "ref")]
        item: String,
        fields: Vec<String>,
    },
    /// Saves an identity or card the user typed into a form and chose to
    /// keep: a new one, or changed fields of the one `ref` names. Never a
    /// card's security code.
    SaveForm {
        origin: String,
        kind: FormKind,
        #[serde(rename = "ref")]
        item: Option<String>,
        fields: std::collections::BTreeMap<String, Secret>,
    },
    PasskeyList(passkeys::List),
    PasskeyCreate(passkeys::Create),
    PasskeyGet(passkeys::Get),
    PasskeyCancel(passkeys::Cancel),
    /// One line for the log of a recording (Record). The extension
    /// sends form shapes only, never values; the host just appends it.
    Learn {
        session: String,
        line: serde_json::Map<String, Value>,
    },
    /// Part of a session's log, from byte `offset`, for the popup's Download.
    LearnRead {
        session: String,
        #[serde(default)]
        offset: u64,
    },
    /// Deletes a session's log, for the popup's Delete.
    LearnDelete {
        session: String,
    },
}

/// A new-password field's rules, as the extension words them.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Field {
    rules: Option<String>,
    min_length: Option<usize>,
    max_length: Option<usize>,
    allowed: Option<String>,
}

impl Field {
    fn check(self) -> Result<SiteField, Refusal> {
        if self.rules.as_ref().is_some_and(|r| r.len() > MAX_RULES)
            || self.allowed.as_ref().is_some_and(|a| a.len() > MAX_RULES)
        {
            return Err(Refusal::bad(format!(
                "rules and allowed are at most {MAX_RULES} bytes"
            )));
        }
        Ok(SiteField {
            rules: self.rules,
            min_length: self.min_length,
            max_length: self.max_length,
            allowed: self.allowed,
        })
    }
}

/// A generated password's id, as `generate` gave it.
fn generated_id(id: &str) -> Result<String, Refusal> {
    if id.is_empty() || id.len() > 64 {
        return Err(Refusal::bad("generated is 1 to 64 bytes"));
    }
    Ok(id.to_string())
}

#[derive(Deserialize)]
struct Entry {
    title: String,
    url: String,
    #[serde(default)]
    username: String,
    password: Option<Secret>,
    generated: Option<String>,
    /// In place of a password: a login that signs in with a provider login.
    #[serde(rename = "signIn")]
    sign_in: Option<EntrySignIn>,
}

/// A save's provider link: the provider's id and the login (a ref) it signs in with.
#[derive(Deserialize)]
struct EntrySignIn {
    provider: String,
    account: String,
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
        capabilities: [&'static str; 10],
    },
    List {
        site: String,
        accounts: Vec<Account>,
    },
    Fill {
        #[serde(flatten)]
        values: SiteValues,
    },
    Generate {
        password: Secret,
        generated: String,
    },
    GenerateCheck,
    GenerateKeep,
    GenerateDrop,
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
    #[serde(rename_all = "camelCase")]
    Forms {
        identities: Vec<IdentityEntry>,
        cards: Vec<CardEntry>,
        /// Whether filling a card's number or code now raises Touch ID.
        can_verify: bool,
    },
    FillForm {
        values: std::collections::BTreeMap<String, Secret>,
        verified: bool,
    },
    SaveForm {
        #[serde(rename = "ref")]
        item: String,
        created: bool,
    },
    Passkeys(passkeys::Listed),
    PasskeyCreated(passkeys::Created),
    PasskeyAssertion(passkeys::Assertion),
    PasskeyCancelled {
        found: bool,
    },
    Learned,
    LearnText {
        text: String,
        next: Option<u64>,
    },
    LearnDeleted {
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

/// An identity in the `forms` reply, without values.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IdentityEntry {
    #[serde(rename = "ref")]
    item: String,
    vault: String,
    title: String,
    summary: String,
    fields: Vec<String>,
}

impl From<FormIdentity> for IdentityEntry {
    fn from(i: FormIdentity) -> Self {
        Self {
            item: format_ref(&i.item),
            vault: i.vault,
            title: i.title,
            summary: i.summary,
            fields: i.fields,
        }
    }
}

/// A card in the `forms` reply: never its number or code.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CardEntry {
    #[serde(rename = "ref")]
    item: String,
    vault: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    brand: Option<String>,
    last4: String,
    /// `YYYY-MM`.
    #[serde(skip_serializing_if = "Option::is_none")]
    expiry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cardholder: Option<String>,
    /// The ref of the identity that is its billing address.
    #[serde(skip_serializing_if = "Option::is_none")]
    billing: Option<String>,
    fields: Vec<String>,
}

impl From<FormCard> for CardEntry {
    fn from(c: FormCard) -> Self {
        Self {
            item: format_ref(&c.item),
            vault: c.vault,
            title: c.title,
            brand: c.brand,
            last4: c.last4,
            expiry: c.expiry,
            cardholder: c.cardholder,
            billing: c.billing.as_ref().map(format_ref),
            fields: c.fields,
        }
    }
}

/// The kinds a `forms` request asks for: one or both, once each.
fn form_kinds(mut kinds: Vec<FormKind>) -> Result<Vec<FormKind>, Refusal> {
    kinds.sort_unstable();
    kinds.dedup();
    if kinds.is_empty() {
        return Err(Refusal::bad("kinds names identity and/or card"));
    }
    Ok(kinds)
}

/// The fields a `fill-form` request asks for: known form fields, once each.
fn form_fields(mut fields: Vec<String>) -> Result<Vec<String>, Refusal> {
    fields.sort_unstable();
    fields.dedup();
    let known = |f: &String| {
        IDENTITY_FORM_FIELDS.contains(&f.as_str()) || CARD_FORM_FIELDS.contains(&f.as_str())
    };
    if fields.is_empty() || !fields.iter().all(known) {
        return Err(Refusal::bad(
            "fields names an identity's or a card's form fields",
        ));
    }
    Ok(fields)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Code {
    Forbidden,
    Locked,
    NotFound,
    DomainMismatch,
    BadRequest,
    RateLimited,
    /// A passkey the registration excluded is already saved.
    Exists,
    /// A passkey ceremony stopped by `passkey-cancel`.
    Cancelled,
    /// A site's rules allow only weak generated passwords.
    Weak,
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
            Some(ErrorCode::Forbidden) => Code::Forbidden,
            Some(ErrorCode::Exists) => Code::Exists,
            Some(ErrorCode::Weak) => Code::Weak,
            Some(ErrorCode::RateLimited) => Code::RateLimited,
            // Agent sign-ins and macOS AutoFill only; the browser host never asks for them.
            Some(
                ErrorCode::Version
                | ErrorCode::NotGranted
                | ErrorCode::ChoosePasskey
                | ErrorCode::InteractionRequired
                | ErrorCode::Cancelled
                | ErrorCode::Failed,
            ) => Code::Failed,
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

/// The username, and the password as typed or the generated one by its id:
/// one or the other.
fn check_login(
    username: &str,
    password: Option<Secret>,
    generated: Option<String>,
) -> Result<PagePassword, Refusal> {
    if username.chars().count() > MAX_USERNAME {
        return Err(Refusal::bad(format!(
            "a username is at most {MAX_USERNAME} characters"
        )));
    }
    match (password, generated) {
        (Some(password), None) => {
            let len = password.expose().chars().count();
            if len == 0 || len > MAX_PASSWORD {
                return Err(Refusal::bad(format!(
                    "a password is 1 to {MAX_PASSWORD} characters"
                )));
            }
            Ok(PagePassword::Typed(password))
        }
        (None, Some(id)) if !id.is_empty() && id.len() <= 64 => Ok(PagePassword::Generated(id)),
        _ => Err(Refusal::bad("a password or a generated one's id, not both")),
    }
}

pub(super) async fn call(paths: &Paths, command: Command) -> Result<Reply, Refusal> {
    Ok(client::simple(paths, command)
        .await
        .map_err(anyhow::Error::from)?)
}

fn done(reply: Reply) -> Result<(), Refusal> {
    match reply {
        Reply::Done => Ok(()),
        _ => Err(unexpected()),
    }
}

pub(super) fn unexpected() -> Refusal {
    Refusal {
        code: Code::Failed,
        message: "unexpected reply from the daemon".into(),
    }
}

/// One connection's state. Requests that ask the daemon are answered one
/// at a time, in order ([`Serial`]); passkey ceremonies and cancels are
/// dealt with as they arrive, so a cancel never waits behind them.
struct Host {
    serial: Serial,
    ceremonies: Ceremonies,
}

/// The state of requests answered in order.
struct Serial {
    paths: Paths,
    /// Whether the watcher says `started` when it next finds a daemon: set
    /// when a watched daemon goes away or hello couldn't reach one, cleared
    /// when hello did.
    announce: Arc<AtomicBool>,
    checks: Bucket,
    fills: Bucket,
    passkey_lists: Bucket,
    learns: Bucket,
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
                learns: Bucket::new(LEARNS, now),
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
                // Cleared first: the daemon this hello may start must not be
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
            Request::Generate { origin, field } => {
                site(&origin)?;
                let field = field.check()?;
                if !self.fills.take(Instant::now()) {
                    return Err(Refusal::slow_down());
                }
                let Reply::SiteGenerated { password, id } =
                    call(&self.paths, Command::SiteGenerate { origin, field }).await?
                else {
                    return Err(unexpected());
                };
                Ok(Body::Generate {
                    password,
                    generated: id,
                })
            }
            Request::GenerateCheck { origin, field } => {
                site(&origin)?;
                let field = field.check()?;
                if !self.checks.take(Instant::now()) {
                    return Err(Refusal::slow_down());
                }
                done(call(&self.paths, Command::SiteGenerateCheck { origin, field }).await?)?;
                Ok(Body::GenerateCheck)
            }
            Request::GenerateKeep { origin, generated } => {
                site(&origin)?;
                let id = generated_id(&generated)?;
                done(call(&self.paths, Command::SiteGenerateKeep { origin, id }).await?)?;
                Ok(Body::GenerateKeep)
            }
            Request::GenerateDrop { origin, generated } => {
                site(&origin)?;
                let id = generated_id(&generated)?;
                done(call(&self.paths, Command::SiteGenerateDrop { origin, id }).await?)?;
                Ok(Body::GenerateDrop)
            }
            Request::Check {
                origin,
                username,
                password,
                generated,
            } => {
                site(&origin)?;
                let password =
                    check_login(username.as_deref().unwrap_or_default(), password, generated)?;
                let username = username.filter(|u| !u.trim().is_empty());
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
                let title = entry.title.trim();
                if let Some(link) = entry.sign_in {
                    if login.is_some()
                        || entry.password.is_some()
                        || entry.generated.is_some()
                        || !entry.username.is_empty()
                    {
                        return Err(Refusal::bad(
                            "a sign-in link is a new login with no username or password",
                        ));
                    }
                    if title.is_empty()
                        || title.chars().count() > MAX_TITLE
                        || entry.url.len() > MAX_URL
                    {
                        return Err(Refusal::bad(format!(
                            "a title is 1 to {MAX_TITLE} characters, entry.url at most {MAX_URL} bytes"
                        )));
                    }
                    let url = crate::site::page_url(&entry.url)
                        .map_err(|reason| Refusal::bad(format!("entry.url: {reason}")))?;
                    let Reply::SiteSaved { login, created } = call(
                        &self.paths,
                        Command::SiteLink {
                            origin,
                            title: title.into(),
                            url: url.into(),
                            provider: link.provider,
                            account: parse_ref(&link.account)?,
                        },
                    )
                    .await?
                    else {
                        return Err(unexpected());
                    };
                    return Ok(Body::Save {
                        login: format_ref(&login),
                        created,
                    });
                }
                let password = check_login(&entry.username, entry.password, entry.generated)?;
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
                        password,
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
            Request::Forms { origin, kinds } => {
                site(&origin)?;
                let kinds = form_kinds(kinds)?;
                let Reply::FormItems {
                    identities,
                    cards,
                    can_verify,
                } = call(&self.paths, Command::FormItems { origin, kinds }).await?
                else {
                    return Err(unexpected());
                };
                Ok(Body::Forms {
                    identities: identities.into_iter().map(Into::into).collect(),
                    cards: cards.into_iter().map(Into::into).collect(),
                    can_verify,
                })
            }
            // A card's number or code may wait on Touch ID: requests behind
            // it wait too, as the user is at the prompt.
            Request::FillForm {
                origin,
                item,
                fields,
            } => {
                site(&origin)?;
                let item = parse_ref(&item)?;
                let fields = form_fields(fields)?;
                if !self.fills.take(Instant::now()) {
                    return Err(Refusal::slow_down());
                }
                let Reply::FormFill {
                    values, verified, ..
                } = call(
                    &self.paths,
                    Command::FormFill {
                        origin,
                        item,
                        fields,
                    },
                )
                .await?
                else {
                    return Err(unexpected());
                };
                Ok(Body::FillForm { values, verified })
            }
            // What the user typed into a form and chose to keep: an item the
            // daemon creates or changes as it does for the CLI, with only an
            // identity's or a card's form fields, never a security code.
            Request::SaveForm {
                origin,
                kind,
                item,
                fields,
            } => {
                site(&origin)?;
                let target = item.as_deref().map(parse_ref).transpose()?;
                if !self.fills.take(Instant::now()) {
                    return Err(Refusal::slow_down());
                }
                let fields = deadbolt_core::forms::saved_fields(
                    kind.as_str(),
                    fields
                        .iter()
                        .map(|(name, value)| (name.clone(), value.expose().to_owned())),
                    target.is_some(),
                )
                .map_err(|error| Refusal::bad(error.to_string()))?;
                let inputs: Vec<FieldInput> = fields
                    .into_iter()
                    .map(|(name, field)| FieldInput {
                        name,
                        kind: None,
                        value: field.value.clone(),
                    })
                    .collect();
                if let Some(target) = target {
                    // Only an identity or card of that kind, as `forms` lists it.
                    if !form_refs(&self.paths, &origin, kind)
                        .await?
                        .contains(&target)
                    {
                        return Err(Refusal {
                            code: Code::NotFound,
                            message: format!("no such {}", kind.as_str()),
                        });
                    }
                    // By its vault and its whole id, which names that item
                    // only (never a text match: see the daemon's item lookup).
                    let Reply::Item { item } = call(
                        &self.paths,
                        Command::ItemSet {
                            vault: Some(target.vault.clone()),
                            query: vec![target.item.clone()],
                            fields: inputs,
                            name: None,
                            unset: Vec::new(),
                            favorite: None,
                            add_tags: Vec::new(),
                            remove_tags: Vec::new(),
                        },
                    )
                    .await?
                    else {
                        return Err(unexpected());
                    };
                    if item.id != target.item {
                        return Err(unexpected());
                    }
                    return Ok(Body::SaveForm {
                        item: format_ref(&target),
                        created: false,
                    });
                }
                let Reply::Item { item } = call(
                    &self.paths,
                    Command::ItemNew {
                        vault: None,
                        kind: kind.as_str().into(),
                        name: None,
                        fields: inputs,
                        favorite: false,
                        tags: Vec::new(),
                    },
                )
                .await?
                else {
                    return Err(unexpected());
                };
                // Its vault, as `forms` names the new item.
                let created = form_refs(&self.paths, &origin, kind)
                    .await?
                    .into_iter()
                    .find(|r| r.item == item.id)
                    .ok_or_else(unexpected)?;
                Ok(Body::SaveForm {
                    item: format_ref(&created),
                    created: true,
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
            Request::Learn { session, line } => {
                if !self.learns.take(Instant::now()) {
                    return Err(Refusal::slow_down());
                }
                learn(&self.paths, &session, &line)?;
                Ok(Body::Learned)
            }
            Request::LearnRead { session, offset } => {
                if !self.learns.take(Instant::now()) {
                    return Err(Refusal::slow_down());
                }
                learn_read(&self.paths, &session, offset)
            }
            Request::LearnDelete { session } => {
                if !learn_session(&session) {
                    return Err(Refusal::bad("session is a lowercase UUID"));
                }
                let path = self.paths.learn_dir().join(format!("{session}.jsonl"));
                Ok(Body::LearnDeleted {
                    found: std::fs::remove_file(path).is_ok(),
                })
            }
        }
    }
}

/// The identities or cards (`kind`) the daemon lists for forms on `origin`.
async fn form_refs(paths: &Paths, origin: &str, kind: FormKind) -> Result<Vec<LoginRef>, Refusal> {
    let Reply::FormItems {
        identities, cards, ..
    } = call(
        paths,
        Command::FormItems {
            origin: origin.into(),
            kinds: vec![kind],
        },
    )
    .await?
    else {
        return Err(unexpected());
    };
    Ok(identities
        .into_iter()
        .map(|i| i.item)
        .chain(cards.into_iter().map(|c| c.item))
        .collect())
}

/// A session id is a UUID, as the extension's `crypto.randomUUID()` makes
/// it: it names the log file, so nothing else gets near the path.
fn learn_session(session: &str) -> bool {
    session.len() == 36
        && session.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit() && !b.is_ascii_uppercase(),
        })
}

/// Appends `line` to the session's log, `<learn dir>/<session>.jsonl`, both
/// readable by this user only. Works locked: it touches no vault. A new
/// session's log first prunes the old ones (see `prune_learn_logs`).
fn learn(
    paths: &Paths,
    session: &str,
    line: &serde_json::Map<String, Value>,
) -> Result<(), Refusal> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    if !learn_session(session) {
        return Err(Refusal::bad("session is a lowercase UUID"));
    }
    let failed = |what: &str, error: std::io::Error| Refusal {
        code: Code::Failed,
        message: format!("couldn't {what} the learning log: {error}"),
    };
    let dir = paths.learn_dir();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| failed("create", e))?;
    // Also when it was there already, with looser permissions.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| failed("create", e))?;
    let path = dir.join(format!("{session}.jsonl"));
    let mut bytes = serde_json::to_vec(line).map_err(|_| Refusal::bad("line is not JSON"))?;
    bytes.push(b'\n');
    let existing = std::fs::metadata(&path).ok();
    if existing.is_none() {
        let now = std::time::UNIX_EPOCH + Duration::from_secs(crate::config::now());
        prune_learn_logs(&dir, now);
    }
    let size = existing.map(|m| m.len()).unwrap_or(0);
    if size + bytes.len() as u64 > MAX_LEARN_LOG {
        return Err(Refusal::bad(format!(
            "a learning log is at most {MAX_LEARN_LOG} bytes"
        )));
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut file| file.write_all(&bytes))
        .map_err(|e| failed("write", e))
}

/// Up to `LEARN_READ` bytes of a session's log from `offset`, whole lines
/// only (a line is far smaller), and where the next part starts, if any.
fn learn_read(paths: &Paths, session: &str, offset: u64) -> Result<Body, Refusal> {
    use std::io::{Read, Seek};

    if !learn_session(session) {
        return Err(Refusal::bad("session is a lowercase UUID"));
    }
    let path = paths.learn_dir().join(format!("{session}.jsonl"));
    let Ok(mut file) = std::fs::File::open(path) else {
        return Err(Refusal {
            code: Code::NotFound,
            message: "no such learning log".into(),
        });
    };
    let mut bytes = Vec::new();
    file.seek(std::io::SeekFrom::Start(offset))
        .and_then(|_| file.take(LEARN_READ + 1).read_to_end(&mut bytes))
        .map_err(|_| Refusal::bad("couldn't read the learning log"))?;
    let mut next = None;
    if bytes.len() as u64 > LEARN_READ {
        let end = bytes[..LEARN_READ as usize]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(LEARN_READ as usize, |i| i + 1);
        bytes.truncate(end);
        next = Some(offset + end as u64);
    }
    let text = String::from_utf8(bytes).map_err(|_| Refusal::bad("the learning log isn't text"))?;
    Ok(Body::LearnText { text, next })
}

/// Before a new session's log: removes the logs older than `LEARN_LOG_AGE`,
/// then the oldest until the new one makes `MAX_LEARN_LOGS`. Best effort: a
/// log that can't be read or removed is left.
fn prune_learn_logs(dir: &std::path::Path, now: std::time::SystemTime) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut logs: Vec<(std::time::SystemTime, std::path::PathBuf)> = entries
        .filter_map(|e| {
            let e = e.ok()?;
            let path = e.path();
            let meta = e.metadata().ok()?;
            let modified = meta.modified().ok()?;
            (meta.is_file() && path.extension().is_some_and(|x| x == "jsonl"))
                .then_some((modified, path))
        })
        .collect();
    logs.sort();
    let excess = (logs.len() + 1).saturating_sub(MAX_LEARN_LOGS);
    for (i, (modified, path)) in logs.iter().enumerate() {
        let old = now.duration_since(*modified).unwrap_or_default() > LEARN_LOG_AGE;
        if i < excess || old {
            std::fs::remove_file(path).ok();
        }
    }
}

/// Starts the daemon if none runs, never unlocking it.
/// Also whether a daemon answered.
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
fn changed(change: &Change) -> Option<&'static str> {
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
#[path = "host/tests.rs"]
mod tests;
