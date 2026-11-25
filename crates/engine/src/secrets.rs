//! Secrets for commands (`docs/secrets.md`): `resolve` finds the fields
//! secret references name, for `deadbolt run`, `inject` and `read`. Like
//! `deadbolt get`, any caller gets what it names while the vault is
//! unlocked; Activity records which items and fields, never values.

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use deadbolt_core::totp::Totp;
use deadbolt_core::{FieldType, Item, VaultId};
use deadbolt_proto::daemon::{ErrorCode, Reference, ResolvedSecret, Secret};
use zeroize::Zeroizing;

use crate::items::{Listing, label, line};
use crate::{Engine, fail};

/// The one item in `vault` that `query` names: its title (any case), its
/// whole id or an id prefix of at least 4 characters. None or several is
/// an error, listing the candidates by short id.
fn item(s: &Engine, vault: VaultId, query: &str) -> Result<Item> {
    let listing = Listing::new(s.vault(&vault));
    let lower = query.trim().to_lowercase();
    let hex = lower.len() >= 4 && lower.bytes().all(|b| b.is_ascii_hexdigit());
    let found: Vec<&Item> = listing
        .items
        .iter()
        .filter(|item| {
            label(item).to_lowercase() == lower || (hex && item.id.to_string().starts_with(&lower))
        })
        .collect();
    let vault_name = s.vault(&vault).name();
    match found.as_slice() {
        [item] => Ok((*item).clone()),
        [] => Err(fail(
            ErrorCode::NotFound,
            format!("no item titled {query:?} (or with that id) in vault {vault_name}"),
        )),
        many => {
            let mut lines: Vec<String> = many
                .iter()
                .map(|item| line(&listing.info(item, false, false)))
                .collect();
            lines.sort();
            Err(fail(
                ErrorCode::Failed,
                format!(
                    "{query:?} names {} items in vault {vault_name}; use its short id instead:\n{}",
                    many.len(),
                    lines.join("\n")
                ),
            ))
        }
    }
}

/// The value `reference` names at `now`: a one-time password field gives
/// its current code, never its secret.
pub fn find(s: &Engine, reference: &Reference, now: Duration) -> Result<ResolvedSecret> {
    let vault = s.resolve(reference.vault.as_deref())?;
    let item = item(s, vault, &reference.item)?;
    let title = label(&item);
    let field = item
        .fields
        .get(&reference.field)
        .filter(|_| !crate::passkeys::private(&item, &reference.field));
    let Some(field) = field else {
        let names: Vec<&str> = item
            .fields
            .keys()
            .map(String::as_str)
            .filter(|name| !crate::passkeys::private(&item, name))
            .collect();
        return Err(fail(
            ErrorCode::NotFound,
            format!(
                "{title} has no field {:?}; its fields are {}",
                reference.field,
                names.join(", ")
            ),
        ));
    };
    let value = match field.kind {
        FieldType::Otp => {
            let totp = Totp::parse(&field.value)
                .map_err(|e| anyhow!("the one-time password of {title} is invalid: {e}"))?;
            Zeroizing::new(totp.code(now.as_secs()))
        }
        _ => Zeroizing::new(field.value.clone()),
    };
    if value.is_empty() {
        bail!("{title} › {} is empty", reference.field);
    }
    Ok(ResolvedSecret {
        vault: s.vault(&vault).name().into(),
        item: item.id.to_string(),
        title,
        field: reference.field.clone(),
        value: Secret::new(value.as_str()),
        file: field.kind == FieldType::File,
    })
}

/// "personal › GitHub › token".
pub fn named(found: &ResolvedSecret) -> String {
    format!("{} › {} › {}", found.vault, found.title, found.field)
}

/// The reference that names `found`, by vault and title.
pub fn reference_of(found: &ResolvedSecret) -> String {
    format!("deadbolt://{}/{}/{}", found.vault, found.title, found.field)
}
