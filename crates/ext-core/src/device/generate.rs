//! Browser message adapters for the native agent's shared generation policy.

use std::time::Duration;

use deadbolt_core::{
    site::Site,
    site_password::{self, FieldRules, Pending},
};
use n0_future::time::Instant;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Error, Result, state, text};

thread_local! {
    static EPOCH: Instant = Instant::now();
}

/// The candidate queue uses elapsed time, not the adjustable wall clock.
pub(super) fn now() -> Duration {
    EPOCH.with(Instant::elapsed)
}

fn optional_text<'a>(body: &'a Value, key: &str) -> Result<Option<&'a str>> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        _ => Err(Error::Protocol("Expected a string")),
    }
}

fn length(body: &Value, key: &str) -> Result<Option<usize>> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .map(Some)
            .ok_or(Error::Protocol(
                "Password lengths must be nonnegative integers",
            )),
    }
}

fn field(body: &Value) -> Result<FieldRules<'_>> {
    Ok(FieldRules {
        rules: optional_text(body, "rules")?,
        min_length: length(body, "minLength")?,
        max_length: length(body, "maxLength")?,
        allowed: optional_text(body, "allowed")?,
    })
}

fn origin(body: &Value) -> Result<&str> {
    let origin = text(body, "origin")?;
    Site::from_origin(origin).map_err(Error::Protocol)?;
    // The native candidate queue binds to the exact supplied origin, not a
    // registrable domain. Never broaden that binding when keeping/resolving.
    Ok(origin)
}

pub(super) fn generated_id(body: &Value) -> Result<&str> {
    let id = text(body, "generated")?;
    if id.is_empty() || id.len() > 64 {
        return Err(Error::Protocol("generated is 1 to 64 bytes"));
    }
    Ok(id)
}

/// A passive check works even while the vault is locked and creates nothing.
pub(super) fn check(body: &Value) -> Result<Value> {
    site_password::check(origin(body)?, &field(body)?)?;
    Ok(json!({"type": "generate-check"}))
}

pub(super) fn generate(body: &Value) -> Result<Value> {
    let origin = origin(body)?;
    let field = field(body)?;
    state().with(|s| {
        let password = site_password::generate(origin, &field)?;
        let id = s.generated.offer(origin, password.clone(), now())?;
        Ok(json!({"type": "generate", "password": password.as_str(), "generated": id}))
    })
}

pub(super) fn keep(body: &Value) -> Result<Value> {
    let origin = origin(body)?;
    let id = generated_id(body)?;
    state().with(|s| {
        s.generated.keep(origin, id, now())?;
        Ok(json!({"type": "generate-keep"}))
    })
}

pub(super) fn drop_candidate(body: &Value) -> Result<Value> {
    let origin = origin(body)?;
    let id = generated_id(body)?;
    state().with(|s| {
        s.generated.drop_candidate(origin, id);
        Ok(json!({"type": "generate-drop"}))
    })
}

/// Resolve a check's body or save's entry only while the loaded state is held.
/// As in the host protocol, exactly one password source is required.
pub(super) fn resolve(
    pending: &mut Pending,
    origin: &str,
    body: &Value,
) -> Result<Zeroizing<String>> {
    let now = now();
    pending.expire(now);
    match (
        optional_text(body, "password")?,
        optional_text(body, "generated")?,
    ) {
        (Some(password), None) => {
            let len = password.chars().count();
            if len == 0 || len > 4096 {
                return Err(Error::Protocol("a password is 1 to 4096 characters"));
            }
            Ok(Zeroizing::new(password.to_owned()))
        }
        (None, Some(_)) => Ok(pending.resolve(origin, generated_id(body)?, now)?),
        _ => Err(Error::Protocol(
            "a password or a generated one's id, not both",
        )),
    }
}

/// Call only after the save's durable commit has succeeded.
pub(super) fn saved(pending: &mut Pending, body: &Value) {
    if let Some(id) = body.get("generated").and_then(Value::as_str) {
        pending.saved(id);
    }
}
