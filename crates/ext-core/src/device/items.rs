//! Every item type for the vault page: the list, an item's details, its
//! secret values, adding, editing and deleting. Labels, details, search
//! words and input typing come from `deadbolt_core::listing`, as the
//! native agent names and writes them. Logins keep their own commands
//! (`device-save`, the page's `save`) for the site rules they need; this
//! adds the other types, and a login's one-time password.

use std::cell::Cell;

use deadbolt_core::item::{FieldType, file_parts, file_size};
use deadbolt_core::listing::{self, detail, input_field, label, searchable};
use deadbolt_core::passkeys::private;
use deadbolt_core::tag::{MAX_TAGS, fold_tag, normalize_tag};
use deadbolt_core::totp::Totp;
use deadbolt_core::{DataOp, Item, Vault, schema, schemas};
use serde_json::{Value, json};

use super::{
    Error, Loaded, PRESET, Result, account, check_passphrase, item_ref, origin, reauthenticate,
    reference, request_sync, state, text, unix_time,
};

/// Whether the vault page can change items of this type. A passkey is made
/// by a site through the browser; it can only be deleted here.
fn editable(kind: &str) -> bool {
    kind != "passkey" && schema(kind).is_some()
}

fn find(s: &Loaded, body: &Value) -> Result<Item> {
    let id = item_ref(&s.vault, text(body, "ref")?)?;
    s.vault
        .item(&id)
        .filter(|i| !i.deleted)
        .ok_or(Error::NotFound)
}

/// One row of the vault page's list: the type, the label and detail the
/// agent gives it, the words a search finds it by (never a secret), and a
/// login's account as the page menus have it.
fn summary(item: &Item, vault: &Vault) -> Value {
    let mut row = if item.kind == "login" {
        account(item, vault)
    } else {
        let urls: Vec<&str> = item
            .fields
            .values()
            .filter(|f| f.kind == FieldType::Url)
            .map(|f| f.value.as_str())
            .collect();
        json!({"ref": reference(vault, item.id), "vault": vault.name(), "urls": urls})
    };
    row["kind"] = json!(item.kind);
    row["title"] = json!(label(item));
    if let Some(detail) = detail(item) {
        row["detail"] = json!(detail);
    }
    row["search"] = json!(searchable(item));
    row["favorite"] = json!(item.favorite);
    row["tags"] = json!(item.tags.iter().collect::<Vec<_>>());
    if let Some(primary) = listing::primary_field(&item.kind)
        .filter(|f| item.fields.contains_key(*f) && !private(item, f))
    {
        row["primary"] = json!(primary);
    }
    row
}

pub(super) fn parse_tags(raw: Option<&Value>) -> Result<Option<Vec<String>>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let list = raw.as_array().ok_or(Error::Protocol("tags is a list"))?;
    let mut seen = std::collections::BTreeMap::new();
    for entry in list {
        let s = entry.as_str().ok_or(Error::Protocol("tags are text"))?;
        let clean = normalize_tag(s).ok_or(Error::Protocol(
            "A tag is 1 to 128 characters, with non-empty / parts",
        ))?;
        seen.insert(fold_tag(&clean), clean);
    }
    if seen.len() > MAX_TAGS {
        return Err(Error::Protocol("An item can have at most 64 tags"));
    }
    Ok(Some(seen.into_values().collect()))
}

pub(super) fn tag_ops(item: &Item, favorite: Option<bool>, tags: Option<&[String]>) -> Vec<DataOp> {
    let mut ops = Vec::new();
    if let Some(fav) = favorite
        && item.favorite != fav
    {
        ops.push(DataOp::favorite(item.id, fav));
    }
    if let Some(tags) = tags {
        for tag in tags {
            if !item.tags.contains(tag) {
                ops.push(DataOp::tag_add(item.id, tag.clone()));
            }
        }
        for existing in &item.tags {
            let ef = fold_tag(existing);
            if !tags.iter().any(|t| fold_tag(t) == ef) {
                ops.push(DataOp::tag_remove(item.id, existing.clone()));
            }
        }
    }
    ops
}

/// `device-items`: every item but deleted ones.
pub(super) fn all() -> Result<Value> {
    state().with(|s| {
        let items: Vec<_> = s
            .vault
            .items()
            .iter()
            .filter(|i| !i.deleted)
            .map(|i| summary(i, &s.vault))
            .collect();
        Ok(json!({"type": "device-items", "items": items}))
    })
}

/// `device-item`: one item for its detail view. Plain values come with it;
/// secrets (and a one-time password's secret) only say they're there, and
/// come one at a time from `device-secret`. A file says its name and size.
/// A login also has what the page's menus show, and its current code.
pub(super) fn detail_of(body: &Value) -> Result<Value> {
    state().with(|s| {
        let item = find(s, body)?;
        let mut reply = summary(&item, &s.vault);
        reply["type"] = json!("device-item");
        reply["name"] = json!(item.name);
        reply["editable"] = json!(editable(&item.kind));
        if item.kind == "login" {
            reply["url"] = json!(item.fields.get("url").map(|f| f.value.as_str()).unwrap_or_default());
        }
        let known: Vec<&str> = schema(&item.kind)
            .map(|s| s.fields.iter().map(|f| f.name).collect())
            .unwrap_or_default();
        let order = known
            .iter()
            .copied()
            .filter(|name| item.fields.contains_key(*name))
            .chain(item.fields.keys().map(String::as_str).filter(|n| !known.contains(n)))
            .filter(|name| !private(&item, name));
        let fields: Vec<Value> = order
            .map(|name| {
                let field = &item.fields[name];
                let mut out = json!({"name": name, "type": field.kind.as_str()});
                match field.kind {
                    FieldType::Secret | FieldType::Otp => out["secret"] = json!(true),
                    FieldType::File => {
                        let (file, contents) = file_parts(&field.value);
                        out["value"] = json!(file);
                        if let Some(size) = contents.and_then(file_size) {
                            out["size"] = json!(size);
                        }
                    }
                    _ => out["value"] = json!(field.value),
                }
                out
            })
            .collect();
        reply["fields"] = json!(fields);
        if let Some(totp) = deadbolt_core::autofill::otp(&item).and_then(|f| Totp::parse(&f.value).ok()) {
            let now = unix_time() as u64;
            reply["totp"] = json!({"code": totp.code(now), "period": totp.period(), "until": totp.valid_until(now)});
        }
        Ok(reply)
    })
}

/// `device-secret`: one secret value (a login's password unless `field`
/// names another), for reveal and copy; a file's whole value for a
/// download. Strict asks for the passphrase before any secret, as before a
/// password.
pub(super) fn secret(body: &mut Value) -> Result<Value> {
    let name = body
        .get("field")
        .and_then(Value::as_str)
        .unwrap_or("password")
        .to_owned();
    let kind = state().with(|s| {
        let item = find(s, body)?;
        if private(&item, &name) {
            return Err(Error::NotFound);
        }
        item.fields
            .get(&name)
            .map(|f| f.kind.clone())
            .ok_or(Error::NotFound)
    })?;
    reauthenticate(body, kind.is_secret() && PRESET.with(Cell::get).reauth())?;
    state().with(|s| {
        let item = find(s, body)?;
        let field = item
            .fields
            .get(&name)
            .filter(|f| f.kind == kind)
            .ok_or(Error::NotFound)?;
        Ok(json!({"type": "device-secret", "value": field.value}))
    })
}

/// The `fields` of a save, typed and normalized: `[{name, value, type?}]`.
/// A login's web addresses follow the site rules a login's website does.
fn inputs(
    kind: &str,
    existing: Option<&Item>,
    body: &Value,
) -> Result<Vec<(String, deadbolt_core::Field)>> {
    let Some(list) = body.get("fields") else {
        return Ok(Vec::new());
    };
    let list = list.as_array().ok_or(Error::Protocol("fields is a list"))?;
    let mut seen = std::collections::BTreeSet::new();
    list.iter()
        .map(|f| {
            let name = text(f, "name")?;
            if !seen.insert(name.to_owned()) || (existing.is_some_and(|i| private(i, name))) {
                return Err(Error::Protocol("A field is given twice, or can't be set"));
            }
            let value = text(f, "value")?.to_owned();
            let field = input_field(
                kind,
                existing,
                name,
                f.get("type").and_then(Value::as_str),
                value,
            )?;
            if kind == "login" && field.kind == FieldType::Url {
                origin(&field.value)?;
            }
            Ok((name.to_owned(), field))
        })
        .collect()
}

/// `device-item-save`: adds an item of `kind`, or edits the item `ref`
/// names. `fields` are set, `remove` names fields to take off, and `name`
/// (when given; empty clears it) is its name. Fields left out stay as they
/// are, so an edit never needs a secret it doesn't change.
pub(super) fn save(body: &Value) -> Result<Value> {
    let name = match body.get("name") {
        None | Some(Value::Null) => None,
        Some(Value::String(n)) => Some(n.trim().to_owned()),
        Some(_) => return Err(Error::Protocol("name is text")),
    };
    let remove: Vec<String> = match body.get("remove") {
        None => Vec::new(),
        Some(v) => v
            .as_array()
            .ok_or(Error::Protocol("remove is a list"))?
            .iter()
            .map(|n| {
                n.as_str()
                    .map(str::to_owned)
                    .ok_or(Error::Protocol("remove names fields"))
            })
            .collect::<Result<_>>()?,
    };
    let favorite = match body.get("favorite") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err(Error::Protocol("favorite is true or false")),
    };
    let tags = parse_tags(body.get("tags"))?;
    let reply = state().with(|s| {
        let mut staged = s.vault.clone();
        let (id, created) = if body.get("ref").is_some() {
            let item = find(s, body)?;
            let meta_only = name.is_none()
                && remove.is_empty()
                && body
                    .get("fields")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty);
            if !editable(&item.kind) && !meta_only {
                return Err(Error::Protocol(
                    "This kind of item can't be changed here; delete it instead",
                ));
            }
            let set = inputs(&item.kind, Some(&item), body)?;
            let setting: Vec<String> = set.iter().map(|(n, _)| n.clone()).collect();
            let mut ops: Vec<DataOp> = set
                .into_iter()
                .map(|(n, f)| DataOp::set(item.id, n, f))
                .collect();
            for field in &remove {
                if item.fields.contains_key(field) && !setting.contains(field) {
                    ops.push(DataOp::remove(item.id, field));
                }
            }
            if let Some(name) = name {
                ops.push(DataOp::name(item.id, Some(name).filter(|n| !n.is_empty())));
            }
            ops.extend(tag_ops(&item, favorite, tags.as_deref()));
            if !ops.is_empty() {
                staged.write(&s.secret, ops)?;
            }
            (item.id, false)
        } else {
            let kind = text(body, "kind")?;
            if !editable(kind) {
                return Err(Error::Protocol("Deadbolt can't add that kind of item"));
            }
            let fields = inputs(kind, None, body)?;
            let (id, _) = staged.create_item_with(
                &s.secret,
                kind,
                name.filter(|n| !n.is_empty()),
                fields,
                favorite.unwrap_or(false),
                tags.unwrap_or_default(),
            )?;
            (id, true)
        };
        s.commit(staged)?;
        Ok(json!({"type": "device-item-save", "ref": reference(&s.vault, id), "created": created}))
    })?;
    request_sync();
    Ok(reply)
}

/// `device-item-delete`: deletes the item, on every device once synced.
pub(super) fn delete(body: &mut Value) -> Result<Value> {
    // The general item page can delete passkeys too. Keep the same Strict
    // consent rule as passkey Settings, based on the stored kind, never input.
    let passkey = state().with(|s| Ok(find(s, body)?.kind == "passkey"))?;
    check_passphrase(body, passkey && PRESET.with(Cell::get).reauth())?;
    state().with(|s| {
        let item = find(s, body)?;
        let mut staged = s.vault.clone();
        staged.write(&s.secret, vec![DataOp::delete(item.id)])?;
        s.commit(staged)
    })?;
    request_sync();
    Ok(json!({"type": "device-item-delete", "ok": true}))
}

/// `device-kinds`: the item types the vault page can add, in the order
/// clients list them, with what one is called and its fields (the core's
/// schemas).
pub(super) fn kinds() -> Value {
    let kinds: Vec<Value> = listing::KINDS
        .iter()
        .filter(|(kind, ..)| editable(kind))
        .filter_map(|(kind, one, _)| {
            let schema = schemas().iter().find(|s| s.kind == *kind)?;
            let fields: Vec<Value> = schema
                .fields
                .iter()
                .map(|f| json!({"name": f.name, "type": f.kind.as_str(), "required": f.required, "multiline": f.multiline}))
                .collect();
            Some(json!({"kind": kind, "noun": one, "fields": fields}))
        })
        .collect();
    json!({"type": "device-kinds", "kinds": kinds})
}
