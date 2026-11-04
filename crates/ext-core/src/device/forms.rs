//! Browser protocol adapter for the shared identity/card form rules.

use std::{cell::Cell, collections::BTreeMap};

use deadbolt_core::{DataOp, Item, forms, site::Site};
use serde_json::{Value, json};

use super::{
    Error, PRESET, Result, item_ref, reauthenticate, reference as item_reference, request_sync,
    state, text,
};
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

/// `save-form`: keeps an identity or a card the user typed into a form and
/// chose to save, new or changed, with only its form fields and never a
/// card's security code (`forms::saved_fields`, the daemon's rule too).
/// Under Strict a card asks for the passphrase first, as showing its number
/// does.
pub(super) fn save(body: &mut Value) -> Result<Value> {
    Site::from_origin(text(body, "origin")?).map_err(Error::Protocol)?;
    let kind = text(body, "kind")?.to_owned();
    let values = body
        .get("fields")
        .and_then(Value::as_object)
        .ok_or(Error::Protocol("Missing form fields"))?
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|v| (name.clone(), v.to_owned()))
                .ok_or(Error::Protocol("A form field's value is text"))
        })
        .collect::<Result<Vec<_>>>()?;
    let update = body.get("ref").is_some();
    let fields = forms::saved_fields(&kind, values, update).map_err(|error| {
        Error::Protocol(match error {
            forms::SaveError::Kind => "kind is identity or card",
            forms::SaveError::WrongField { .. } => "That item can't be saved with those fields",
            forms::SaveError::Number => "A new card needs its number",
            forms::SaveError::NoFields => "Nothing to save",
        })
    })?;
    // A changed item has to be there, and of that kind, before anyone is asked.
    let target = if update {
        let target = text(body, "ref")?;
        let (vault, item) = target
            .split_once(':')
            .ok_or(Error::Protocol("Invalid form reference"))?;
        super::unhex::<32>(vault)?;
        super::unhex::<16>(item)?;
        let id = state().with(|s| {
            let id = item_ref(&s.vault, target).map_err(|_| Error::NotFound)?;
            s.vault
                .item(&id)
                .filter(|i| !i.deleted && i.kind == kind)
                .ok_or(Error::NotFound)?;
            Ok(id)
        })?;
        Some(id)
    } else {
        None
    };
    let required = policy::card_reauth(PRESET.with(Cell::get), kind == "card");
    if required {
        reauthenticate(body, true)?;
    }
    let reply = state().with(|s| {
        let (id, created) = match target {
            Some(id) => {
                s.vault
                    .item(&id)
                    .filter(|i| !i.deleted && i.kind == kind)
                    .ok_or(Error::NotFound)?;
                s.write(
                    fields
                        .into_iter()
                        .map(|(name, field)| DataOp::set(id, name, field))
                        .collect(),
                )?;
                (id, false)
            }
            None => (
                s.mutate(|v, key| Ok(v.create_item(key, &kind, None, fields)?.0))?,
                true,
            ),
        };
        Ok(json!({"type": "save-form", "ref": item_reference(&s.vault, id), "created": created}))
    })?;
    request_sync();
    Ok(reply)
}
