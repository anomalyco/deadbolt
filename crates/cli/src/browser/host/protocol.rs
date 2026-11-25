//! Native messaging host framing, rate limiting, and validation. The
//! messages themselves are [`deadbolt_proto::browser`]'s.

use std::time::{Duration, Instant};

use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::client;
use crate::protocol::{
    CARD_FORM_FIELDS, ErrorCode, FormKind, IDENTITY_FORM_FIELDS, LoginRef, SiteField,
};
use crate::site::Site;

pub(in super::super) use deadbolt_proto::browser::{
    Body, Envelope, ErrorCode as Code, FieldRules, MAX_REPLY, MAX_REQUEST, Request, format_ref,
};

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

/// A new-password field's rules, checked.
pub(super) fn field_rules(field: FieldRules) -> Result<SiteField, Refusal> {
    if field.rules.as_ref().is_some_and(|r| r.len() > MAX_RULES)
        || field.allowed.as_ref().is_some_and(|a| a.len() > MAX_RULES)
    {
        return Err(Refusal::bad(format!(
            "rules and allowed are at most {MAX_RULES} bytes"
        )));
    }
    Ok(field.into())
}

/// A generated password's id, as `generate` gave it.
pub(super) fn generated_id(id: &str) -> Result<String, Refusal> {
    if id.is_empty() || id.len() > 64 {
        return Err(Refusal::bad("generated is 1 to 64 bytes"));
    }
    Ok(id.to_string())
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
