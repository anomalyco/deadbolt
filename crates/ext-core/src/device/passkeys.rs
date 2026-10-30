//! Standalone storage/consent adapter for the same ceremonies as the agent.

use std::cell::{Cell, RefCell};
use std::time::Duration;

use deadbolt_core::{
    DataOp, Item, ItemId,
    autofill::{same_password, value},
    passkeys, webauthn,
};
use n0_future::time::Instant;
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;

use super::{
    Error, PRESET, Result, check_passphrase, item_ref, reference, request_sync, state, text,
};
use crate::policy;

thread_local! {
    /// A one-shot authorization bound to the exact ceremony. Checking a slow
    /// passphrase must not save a passkey after its page cancels or navigates.
    static AUTHORIZED: RefCell<Option<(String, Value, Instant)>> = const { RefCell::new(None) };
}

pub(super) fn authorize(body: &mut Value) -> Result<Value> {
    AUTHORIZED.with(|slot| slot.borrow_mut().take());
    let mut ceremony = body
        .get_mut("ceremony")
        .map(Value::take)
        .ok_or(Error::Protocol("Missing ceremony"))?;
    if !matches!(text(&ceremony, "type")?, "passkey-create" | "passkey-get") {
        return Err(Error::Protocol("Invalid ceremony"));
    }
    ceremony["passphrase"] = body
        .get_mut("passphrase")
        .map(Value::take)
        .ok_or(Error::PassphraseNeeded)?;
    consent(&mut ceremony)?;
    let mut token = [0; 32];
    getrandom::fill(&mut token).map_err(|_| Error::State)?;
    let token = webauthn::b64(&token);
    AUTHORIZED.with(|slot| *slot.borrow_mut() = Some((token.clone(), ceremony, Instant::now())));
    Ok(json!({"type": "passkey-authorized", "token": token}))
}

pub(super) fn finish(body: &Value) -> Result<Value> {
    let token = text(body, "token")?;
    let (expected, mut ceremony, at) = AUTHORIZED
        .with(|slot| slot.borrow_mut().take())
        .ok_or(Error::Protocol("Passkey authorization expired"))?;
    // Reuse the core's constant-time hash comparison for secret strings.
    if !same_password(Some(&expected), token) || at.elapsed() > Duration::from_secs(120) {
        return Err(Error::Protocol("Passkey authorization expired"));
    }
    // The token may not outlive a policy change; Strict still has a checked
    // passphrase because authorize always checks the supplied one.
    match text(&ceremony, "type")? {
        "passkey-create" => create_inner(&mut ceremony, true),
        "passkey-get" => get_inner(&mut ceremony, true),
        _ => Err(Error::State),
    }
}

#[wasm_bindgen(inline_js = r#"
// Same nearest-day convention as the native passkey creation date.
export function passkey_date() { return new Date(Date.now() + 43199000).toISOString().slice(0, 10); }
"#)]
extern "C" {
    fn passkey_date() -> String;
}

fn rp(body: &Value) -> Result<String> {
    let origin = text(body, "origin")?;
    let rp = body.get("rpId").and_then(Value::as_str);
    if origin.len() > 2048 || rp.is_some_and(|rp| rp.len() > 253) {
        return Err(Error::Protocol("Invalid passkey origin or relying party"));
    }
    Ok(passkeys::rp_id(origin, rp)?)
}

fn metadata(item: &Item, s: &super::Loaded) -> Value {
    let mut row = json!({
        "ref": reference(&s.vault, item.id), "vault": s.vault.name(),
        "rpId": value(item, "rp-id").unwrap_or_default(),
        "credentialId": value(item, "credential-id").unwrap_or_default(),
    });
    for name in ["username", "created"] {
        if let Some(value) = value(item, name) {
            row[name] = json!(value);
        }
    }
    row
}

fn rows(s: &super::Loaded, rp: Option<&str>) -> Vec<Value> {
    let mut items: Vec<_> = s
        .vault
        .items()
        .into_iter()
        .filter(|item| {
            !item.deleted
                && item.kind == "passkey"
                && rp.is_none_or(|rp| passkeys::matches(item, rp))
        })
        .collect();
    items.sort_by(|a, b| (value(a, "username"), a.id).cmp(&(value(b, "username"), b.id)));
    items.iter().map(|item| metadata(item, s)).collect()
}

pub(super) fn list(body: &Value) -> Result<Value> {
    let rp = rp(body)?;
    state().with(|s| Ok(json!({"type": "passkeys", "rpId": rp, "canVerify": false, "asksPassphrase": PRESET.with(Cell::get).reauth(), "passkeys": rows(s, Some(&rp))})))
}

pub(super) fn all() -> Result<Value> {
    state().with(|s| Ok(json!({"type": "device-passkeys", "passkeys": rows(s, None)})))
}

fn find(s: &super::Loaded, body: &Value) -> Result<Item> {
    let id = item_ref(&s.vault, text(body, "ref")?).map_err(|_| Error::NotFound)?;
    s.vault
        .item(&id)
        .filter(|item| !item.deleted && item.kind == "passkey")
        .ok_or(Error::NotFound)
}

/// A trusted management-page action, never reachable from the page bridge.
pub(super) fn delete(body: &mut Value) -> Result<Value> {
    check_passphrase(body, PRESET.with(Cell::get).reauth())?;
    let reply = state().with(|s| {
        let item = find(s, body)?;
        let mut staged = s.vault.clone();
        staged.write(&s.secret, vec![DataOp::delete(item.id)])?;
        s.commit(staged)?;
        Ok(json!({"type": "device-delete", "ok": true}))
    })?;
    request_sync();
    Ok(reply)
}

fn consent(body: &mut Value) -> Result<()> {
    let verify = body
        .get("userVerification")
        .and_then(Value::as_str)
        .unwrap_or("preferred");
    if verify == "required" {
        return Err(Error::Protocol(
            "This site requires user verification; use the browser's authenticator",
        ));
    }
    if !matches!(verify, "preferred" | "discouraged") {
        return Err(Error::Protocol("Invalid user verification preference"));
    }
    check_passphrase(
        body,
        policy::passkey_reauth(PRESET.with(Cell::get), verify == "discouraged"),
    )?;
    Ok(())
}

pub(super) fn create(body: &mut Value) -> Result<Value> {
    create_inner(body, false)
}

fn create_inner(body: &mut Value, authorized: bool) -> Result<Value> {
    let rp = rp(body)?;
    let user = body
        .get("user")
        .ok_or(Error::Protocol("Missing passkey account"))?;
    let exclude: Vec<String> = body
        .get("exclude")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| Error::Protocol("Invalid passkey account or exclusions"))?
        .unwrap_or_default();
    if exclude.len() > 64
        || exclude
            .iter()
            .any(|id| id.len() > 1364 || webauthn::unb64(id).is_err())
        || text(user, "name")?.len() > passkeys::MAX_USER_NAME * 4
        || user
            .get("displayName")
            .and_then(Value::as_str)
            .is_some_and(|name| name.len() > passkeys::MAX_USER_NAME * 4)
    {
        return Err(Error::Protocol("Invalid passkey account or exclusions"));
    }
    let mut new = passkeys::check_create(
        text(body, "origin")?,
        Some(&rp),
        text(body, "challenge")?,
        text(user, "id")?,
        text(user, "name")?,
        &exclude,
    )?;
    new.display_name = passkeys::user_text(
        user.get("displayName")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    state().with(|s| Ok(passkeys::check_excluded(&s.vault.items(), &rp, &exclude)?))?;
    if !authorized {
        consent(body)?;
    }
    let reply = state().with(|s| {
        let items = s.vault.items();
        passkeys::check_excluded(&items, &rp, &exclude)?;
        let made = passkeys::register(&new, false, &passkey_date())?;
        let mut staged = s.vault.clone();
        let entry = staged.write(&s.secret, vec![made.create])?;
        let id = ItemId::of_create(&entry.hash(), 0);
        s.commit(staged)?;
        Ok(json!({"type": "passkey-created", "ref": reference(&s.vault, id), "credentialId": made.credential_id,
            "clientDataJSON": made.client_data_json, "attestationObject": made.attestation_object,
            "authenticatorData": made.authenticator_data, "publicKey": made.public_key, "verified": false}))
    })?;
    request_sync();
    Ok(reply)
}

pub(super) fn get(body: &mut Value) -> Result<Value> {
    get_inner(body, false)
}

fn get_inner(body: &mut Value, authorized: bool) -> Result<Value> {
    let rp = rp(body)?;
    webauthn::challenge(text(body, "challenge")?).map_err(passkeys::Error::from)?;
    state().with(|s| Ok(passkeys::validate(&find(s, body)?, &rp)?))?;
    if !authorized {
        consent(body)?;
    }
    state().with(|s| {
        let signed = passkeys::sign(&find(s, body)?, text(body, "origin")?, &rp, text(body, "challenge")?, false)?;
        Ok(json!({"type": "passkey-assertion", "credentialId": signed.credential_id, "clientDataJSON": signed.client_data_json,
            "authenticatorData": signed.authenticator_data, "signature": signed.signature, "userHandle": signed.user_handle, "verified": false}))
    })
}
