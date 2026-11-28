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
//! The host never prompts for a passphrase. It asks for Touch ID, or brings
//! Deadbolt's window forward, only on `unlock-prompt` ([`unlock`]), which
//! the user's click in the extension's locked menu sends.

mod learn;
mod protocol;
mod unlock;
mod watch;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::passkeys::{self, Ceremonies};
use super::{EXTENSION_ID, extension_origin};
use crate::client;
use crate::paths::Paths;
use crate::protocol::{Command, FieldInput, FormKind, LoginRef, PagePassword, Reply, Secret};
use learn::{learn, learn_read, learn_session};
pub(crate) use protocol::Bucket;
use protocol::MAX_REQUEST;
pub(super) use protocol::{Body, Code, Envelope, Refusal, encode, format_ref, parse_ref};
use protocol::{
    Head, MAX_PASSWORD, MAX_TITLE, MAX_URL, MAX_USERNAME, Request, field_rules, form_fields,
    form_kinds, generated_id, invalid, refuse, site, write_frames,
};
use watch::{RECONNECT, hello, watch};

/// Checks are a password oracle and fills hand out secrets, so a runaway
/// or hostile caller gets them slowly: a burst, then one per interval.
const CHECKS: (u32, Duration) = (20, Duration::from_secs(1));
const FILLS: (u32, Duration) = (60, Duration::from_millis(250));
/// Learning logs a line per sign-in step and frame: a burst, then a steady trickle.
const LEARNS: (u32, Duration) = (100, Duration::from_millis(100));
/// Each unlock prompt raises Touch ID or a window: a few, then one every two seconds.
const UNLOCKS: (u32, Duration) = (3, Duration::from_secs(2));

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
    unlocks: Bucket,
    /// How `unlock-prompt` brings Deadbolt's window forward.
    open_app: unlock::OpenApp,
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
                unlocks: Bucket::new(UNLOCKS, now),
                open_app: unlock::open_app,
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
                Ok(Body::List {
                    site,
                    accounts: logins.into_iter().map(Into::into).collect(),
                })
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
                let field = field_rules(field)?;
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
                let field = field_rules(field)?;
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
                learn_read(&self.paths, &session, offset.unwrap_or(0))
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
            // Touch ID waits on the user: requests behind it wait too.
            Request::UnlockPrompt => {
                if !self.unlocks.take(Instant::now()) {
                    return Err(Refusal::slow_down());
                }
                unlock::prompt(&self.paths, self.open_app).await
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

#[cfg(test)]
mod tests;
