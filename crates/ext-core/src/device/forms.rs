//! Browser protocol adapter for the shared identity/card form rules.

use std::{cell::Cell, collections::BTreeMap};

use deadbolt_core::{Item, forms, site::Site};
use serde_json::{Value, json};

use super::{Error, PRESET, Result, item_ref, reauthenticate, state, text};
use crate::policy;

fn strings(body: &Value, key: &str) -> Result<Vec<String>> {
    let values = body
        .get(key)
        .and_then(Value::as_array)
        .ok_or(Error::Protocol("Missing requested form fields or kinds"))?;
    let mut values = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(Error::Protocol("Invalid form field or kind"))
        })
        .collect::<Result<Vec<_>>>()?;
    values.sort_unstable();
    values.dedup();
    if values.is_empty() {
        return Err(Error::Protocol("No form fields or kinds asked for"));
    }
    Ok(values)
}

fn reference(item: forms::Reference) -> String {
    format!("{}:{}", item.vault, item.item)
}

pub(super) fn list(body: &Value) -> Result<Value> {
    Site::from_origin(text(body, "origin")?).map_err(Error::Protocol)?;
    let kinds = strings(body, "kinds")?;
    if kinds
        .iter()
        .any(|kind| !matches!(kind.as_str(), "identity" | "card"))
    {
        return Err(Error::Protocol("kinds names identity and/or card"));
    }
    state().with(|s| {
        let kinds: Vec<_> = kinds.iter().map(String::as_str).collect();
        let (identities, cards) = forms::list(&[&s.vault], &kinds);
        let identities: Vec<_> = identities
            .into_iter()
            .map(|i| {
                json!({
                    "ref": reference(i.item), "vault": i.vault, "title": i.title,
                    "summary": i.summary, "fields": i.fields,
                })
            })
            .collect();
        let cards: Vec<_> = cards
            .into_iter()
            .map(|c| {
                let mut card = json!({
                    "ref": reference(c.item), "vault": c.vault, "title": c.title,
                    "last4": c.last4, "fields": c.fields,
                });
                for (key, value) in [
                    ("brand", c.brand),
                    ("expiry", c.expiry),
                    ("cardholder", c.cardholder),
                    ("billing", c.billing.map(reference)),
                ] {
                    if let Some(value) = value {
                        card[key] = json!(value);
                    }
                }
                card
            })
            .collect();
        // This says whether Touch ID is available, not whether Strict may ask
        // for the local passphrase. The browser cannot perform Touch ID.
        Ok(json!({"type": "forms", "canVerify": false, "identities": identities, "cards": cards}))
    })
}

fn find(body: &Value, fields: &[String]) -> Result<Item> {
    state().with(|s| {
        let target = text(body, "ref")?;
        // Malformed references are bad requests, well-formed references to a
        // vault this browser does not hold are simply not found.
        let (vault, item) = target
            .split_once(':')
            .ok_or(Error::Protocol("Invalid form reference"))?;
        super::unhex::<32>(vault)?;
        super::unhex::<16>(item)?;
        let id = item_ref(&s.vault, target).map_err(|_| Error::NotFound)?;
        let item = s.vault.item(&id).ok_or(Error::NotFound)?;
        forms::validate(&item, fields).map_err(|error| match error {
            forms::Error::NotFound => Error::NotFound,
            forms::Error::NoFields => Error::Protocol("No form fields asked for"),
            forms::Error::WrongField { .. } => {
                Error::Protocol("That item cannot fill the requested fields")
            }
        })?;
        Ok(item)
    })
}

pub(super) fn fill(body: &mut Value) -> Result<Value> {
    Site::from_origin(text(body, "origin")?).map_err(Error::Protocol)?;
    let fields = strings(body, "fields")?;
    if fields.iter().any(|field| {
        !forms::IDENTITY_FORM_FIELDS.contains(&field.as_str())
            && !forms::CARD_FORM_FIELDS.contains(&field.as_str())
    }) {
        return Err(Error::Protocol(
            "fields names an identity's or a card's form fields",
        ));
    }
    let item = find(body, &fields)?;
    let required = policy::card_reauth(PRESET.with(Cell::get), forms::needs_verify(&item, &fields));
    drop(item);
    // Comfortable/Relaxed have native Touch-ID-off behavior: the explicit
    // pick fills without verification, even if an extra passphrase was sent.
    let verified = required && reauthenticate(body, required)?;
    let item = find(body, &fields)?;
    let values: BTreeMap<_, _> = forms::values(&item, &fields).collect();
    Ok(json!({"type": "fill-form", "verified": verified, "values": values}))
}
