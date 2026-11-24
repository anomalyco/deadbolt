//! Native messaging host wire types, framing, rate limiting, and validation.

use std::time::{Duration, Instant};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::super::passkeys;
use crate::client;
use crate::protocol::{
    CARD_FORM_FIELDS, ErrorCode, Fill, FormCard, FormIdentity, FormKind, IDENTITY_FORM_FIELDS,
    LoginRef, Secret, SignIn, SiteField, SiteStatus, SiteValues,
};
use crate::site::Site;

/// The version of this message set, in `hello`.
pub const PROTOCOL: u32 = 3;
/// The largest request read; anything bigger is skipped and refused.
pub const MAX_REQUEST: usize = 64 * 1024;
/// The browser's limit on a message from the host.
pub const MAX_REPLY: usize = 1024 * 1024;

/// The longest item name the vault takes.
pub(super) const MAX_TITLE: usize = 128;
pub(super) const MAX_USERNAME: usize = 500;
pub(super) const MAX_PASSWORD: usize = 4096;
pub(super) const MAX_URL: usize = 2048;
/// The longest `passwordrules` or `pattern` character set a page sends.
pub(super) const MAX_RULES: usize = 1024;

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
pub(super) struct Head {
    #[serde(default)]
    pub(super) id: Value,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub(super) enum Request {
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
pub(super) struct Field {
    pub(super) rules: Option<String>,
    pub(super) min_length: Option<usize>,
    pub(super) max_length: Option<usize>,
    pub(super) allowed: Option<String>,
}

impl Field {
    pub(super) fn check(self) -> Result<SiteField, Refusal> {
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
pub(super) fn generated_id(id: &str) -> Result<String, Refusal> {
    if id.is_empty() || id.len() > 64 {
        return Err(Refusal::bad("generated is 1 to 64 bytes"));
    }
    Ok(id.to_string())
}

#[derive(Deserialize)]
pub(super) struct Entry {
    pub(super) title: String,
    pub(super) url: String,
    #[serde(default)]
    pub(super) username: String,
    pub(super) password: Option<Secret>,
    pub(super) generated: Option<String>,
    /// In place of a password: a login that signs in with a provider login.
    #[serde(rename = "signIn")]
    pub(super) sign_in: Option<EntrySignIn>,
}

/// A save's provider link: the provider's id and the login (a ref) it signs in with.
#[derive(Deserialize)]
pub(super) struct EntrySignIn {
    pub(super) provider: String,
    pub(super) account: String,
}

#[derive(Serialize)]
pub(in super::super) struct Envelope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in super::super) id: Option<Value>,
    #[serde(flatten)]
    pub(in super::super) body: Body,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub(in super::super) enum Body {
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
pub(in super::super) struct Account {
    #[serde(rename = "ref")]
    pub(super) login: String,
    pub(super) vault: String,
    pub(super) title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) username: Option<String>,
    pub(super) has_password: bool,
    pub(super) has_totp: bool,
    pub(super) urls: Vec<String>,
    /// `{provider, account?}` for a "Sign in with Google" login.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) sign_in: Option<SignIn>,
}

/// An identity in the `forms` reply, without values.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in super::super) struct IdentityEntry {
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
pub(in super::super) struct CardEntry {
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
pub(super) fn form_kinds(mut kinds: Vec<FormKind>) -> Result<Vec<FormKind>, Refusal> {
    kinds.sort_unstable();
    kinds.dedup();
    if kinds.is_empty() {
        return Err(Refusal::bad("kinds names identity and/or card"));
    }
    Ok(kinds)
}

/// The fields a `fill-form` request asks for: known form fields, once each.
pub(super) fn form_fields(mut fields: Vec<String>) -> Result<Vec<String>, Refusal> {
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
pub(in super::super) enum Code {
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

pub(in super::super) struct Refusal {
    pub(super) code: Code,
    pub(super) message: String,
}

impl Refusal {
    pub(in super::super) fn body(self) -> Body {
        Body::Error {
            code: self.code,
            message: self.message,
        }
    }

    pub(in super::super) fn bad(message: impl Into<String>) -> Self {
        Self {
            code: Code::BadRequest,
            message: message.into(),
        }
    }

    pub(in super::super) fn slow_down() -> Self {
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
            // macOS AutoFill only; the browser host never asks for them.
            Some(
                ErrorCode::Version
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

pub(super) fn refuse(id: Value, refusal: Refusal) -> Envelope {
    Envelope {
        id: Some(id),
        body: refusal.body(),
    }
}

/// Why a request isn't valid, by position only: serde's messages can
/// quote the values in it.
pub(super) fn invalid(error: &serde_json::Error) -> String {
    let what = match error.classify() {
        serde_json::error::Category::Data => "not a request this host knows",
        _ => "not valid JSON",
    };
    format!("invalid request: {what} (column {})", error.column())
}

pub(super) fn site(origin: &str) -> Result<(), Refusal> {
    Site::from_origin(origin)
        .map(drop)
        .map_err(|reason| Refusal::bad(format!("origin {origin:?}: {reason}")))
}

pub(in super::super) fn parse_ref(text: &str) -> Result<LoginRef, Refusal> {
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

pub(in super::super) fn format_ref(login: &LoginRef) -> String {
    format!("{}:{}", login.vault, login.item)
}

/// One frame: the length prefix and the JSON. A reply over the browser's
/// limit becomes an error.
pub(in super::super) fn encode(envelope: &Envelope) -> Result<Zeroizing<Vec<u8>>> {
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

pub(super) async fn write_frames(
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
