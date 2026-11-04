//! What this device records in Activity ([`crate::activity`]), as the native
//! daemon records the browser host's requests and the app's reports: a page's
//! fills (a card's, not an identity's), saves, made passwords and passkey
//! ceremonies, and what the vault page showed or copied. A page's look-ups
//! (`list`, `check`, `forms`, `passkey-list`, `generate-check` and
//! `generate-drop`) come with every page and aren't entries; nor are the vault
//! page's own reads and changes, or reading Activity. Entries are written
//! before the reply goes, and only while unlocked: locked, there's no store.

use deadbolt_core::Item;
use deadbolt_core::autofill::{otp, value};
use deadbolt_core::listing::label;
use serde_json::{Value, json};

use super::{Error, Result, item_ref, passkeys, reference, state, text, unix_time};
use crate::activity::{self, Caller, Entry, Outcome};

/// An entry being written: what the request named, before it ran.
pub(super) struct Draft {
    caller: Caller,
    command: &'static str,
    site: Option<String>,
    item: Option<String>,
    fields: Vec<String>,
    /// A form fill: an entry only for a card, not for an identity's address
    /// and contact details, as native.
    cards_only: bool,
}

/// A field's name as native records it: a one-time code is `otp`.
fn field_name(name: &str) -> String {
    if name == "totp" { "otp" } else { name }.to_owned()
}

/// The draft of an entry for `body`, or `None` when it isn't recorded.
pub(super) fn draft(body: &Value) -> Option<Draft> {
    let named = |key: &str| body.get(key).and_then(Value::as_str).map(str::to_owned);
    let names = |key: &str| -> Vec<String> {
        body.get(key)
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .map(field_name)
                    .collect()
            })
            .unwrap_or_default()
    };
    let fields = |list: &[&str]| list.iter().map(|f| (*f).to_owned()).collect();
    let (command, fields) = match body.get("type")?.as_str()? {
        "fill" => ("site-fill", names("want")),
        "fill-form" => ("form-fill", names("fields")),
        // An update changes only the password.
        "save" if body.get("ref").is_some() => ("site-save", fields(&["password"])),
        "save" => ("site-save", fields(&["username", "password"])),
        "generate" => ("site-generate", fields(&["password"])),
        "generate-keep" => ("site-generate-keep", fields(&["password"])),
        "passkey-create" => ("passkey-create", fields(&["passkey"])),
        "passkey-get" => ("passkey-get", fields(&["passkey"])),
        // Strict's passphrase came first: the entry is the ceremony's.
        "passkey-finish" => return draft(&passkeys::authorized()?),
        "device-report" => {
            let command = match body.get("action")?.as_str()? {
                "reveal" => "reveal",
                "copy" => "copy",
                _ => return None,
            };
            return Some(Draft {
                caller: Caller::Vault,
                command,
                site: None,
                item: named("ref"),
                fields: named("field").into_iter().collect(),
                cards_only: false,
            });
        }
        _ => return None,
    };
    Some(Draft {
        caller: Caller::Autofill,
        command,
        site: named("origin"),
        item: named("ref"),
        fields,
        cards_only: command == "form-fill",
    })
}

/// How an entry names an item: its label, as the vault page lists it, or a
/// passkey's account.
fn title(item: &Item) -> String {
    match value(item, "username") {
        Some(username) if item.kind == "passkey" => username.to_owned(),
        _ => label(item),
    }
}

impl Draft {
    /// Records the entry for the request answered with `result`. A request
    /// that only asked for the passphrase isn't one, nor a vault page report
    /// the vault refused.
    pub(super) fn record(self, result: &Result<Value>) {
        let outcome = match result {
            Ok(_) => Outcome::Allowed,
            Err(Error::PassphraseNeeded) => return,
            Err(_) if self.caller == Caller::Vault => return,
            Err(
                Error::WrongPassphrase
                | Error::Store(deadbolt_store::Error::WrongPassphrase)
                | Error::DomainMismatch,
            ) => Outcome::Refused,
            Err(_) => Outcome::Failed,
        };
        // A new login or passkey: the reply names it.
        let target = self.item.or_else(|| {
            let reply = result.as_ref().ok()?;
            reply.get("ref").and_then(Value::as_str).map(str::to_owned)
        });
        // Locked, there's no store to record into; a write the store refuses
        // doesn't fail the request it records, as native only warns.
        drop(state().with(|s| {
            let item = target
                .and_then(|r| item_ref(&s.vault, &r).ok())
                .and_then(|id| s.vault.item(&id));
            if self.cards_only && item.as_ref().is_none_or(|i| i.kind != "card") {
                return Ok(());
            }
            let items = item
                .map(|item| {
                    vec![activity::Item {
                        id: Some(reference(&s.vault, item.id)),
                        title: title(&item),
                    }]
                })
                .unwrap_or_default();
            let now = unix_time() as u64;
            let entry = Entry {
                id: 0,
                time: now,
                caller: self.caller,
                command: self.command.into(),
                items,
                fields: self.fields,
                site: self.site,
                outcome,
                more: 0,
            };
            activity::record(&s.store, entry, now, activity::BUDGET)?;
            Ok(())
        }));
    }
}

/// The vault page showed or copied `field` of the item `ref`, which only it
/// sees (`action` is `reveal` or `copy`), as the native app reports its own:
/// the entry is [`draft`]'s, recorded when the item has that field.
pub(super) fn report(body: &Value) -> Result<Value> {
    if !matches!(text(body, "action")?, "reveal" | "copy") {
        return Err(Error::Protocol("An activity report is a reveal or a copy"));
    }
    let field = text(body, "field")?;
    state().with(|s| {
        let id = item_ref(&s.vault, text(body, "ref")?)?;
        s.vault
            .item(&id)
            .filter(|item| {
                // A login's one-time code is `otp`, whatever its field is called.
                !item.deleted
                    && (item.fields.contains_key(field) || (field == "otp" && otp(item).is_some()))
            })
            .ok_or(Error::NotFound)?;
        Ok(json!({"type": "device-report", "ok": true}))
    })
}

/// Activity, newest first: `limit` entries (50 unless asked) with ids before
/// `before`, the page back from the last one shown.
pub(super) fn list(body: &Value) -> Result<Value> {
    let before = body.get("before").and_then(Value::as_u64);
    let limit = body
        .get("limit")
        .and_then(Value::as_u64)
        .map_or(activity::PAGE, |n| {
            usize::try_from(n).unwrap_or(activity::MAX_PAGE)
        });
    state().with(|s| {
        let entries = activity::list(&s.store, before, limit)?;
        Ok(json!({"type": "device-activity", "now": unix_time() as u64, "entries": entries}))
    })
}
