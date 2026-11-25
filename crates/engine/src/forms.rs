//! Forms: the identities and cards a web form's address, contact and
//! payment fields are filled from (docs/autofill.md, "Forms"). Unlike a
//! login, neither belongs to a site: any page autofill takes may list them,
//! by the same origin rules (https, http only on a local host, never a
//! sandboxed or opaque frame). Listing gives no values; a fill gives only
//! the fields asked for, and a card's number or security code verifies the
//! user first (the host's job).

use std::collections::BTreeMap;

use anyhow::Result;
use deadbolt_core::{Item, ItemId, VaultId, forms};
use deadbolt_proto::daemon::{ErrorCode, FormCard, FormIdentity, FormKind, LoginRef, Secret};

use crate::autofill::{login_ref, site};
use crate::{Engine, fail, unhex};

/// The identities and cards a form on the page at `origin` can be filled
/// from, by title. The shared core owns listing metadata and field rules.
pub fn list(
    s: &Engine,
    origin: &str,
    kinds: &[FormKind],
) -> Result<(Vec<FormIdentity>, Vec<FormCard>)> {
    site(origin)?;
    let vaults: Vec<_> = s.vaults.values().collect();
    let kinds: Vec<_> = kinds.iter().map(|kind| kind.as_str()).collect();
    let (identities, cards) = forms::list(&vaults, &kinds);
    Ok((
        identities
            .into_iter()
            .map(|i| FormIdentity {
                item: login_ref(&i.item.vault, &i.item.item),
                vault: i.vault,
                title: i.title,
                summary: i.summary,
                fields: i.fields,
            })
            .collect(),
        cards
            .into_iter()
            .map(|c| FormCard {
                item: login_ref(&c.item.vault, &c.item.item),
                vault: c.vault,
                title: c.title,
                brand: c.brand,
                last4: c.last4,
                expiry: c.expiry,
                cardholder: c.cardholder,
                billing: c.billing.map(|r| login_ref(&r.vault, &r.item)),
                fields: c.fields,
            })
            .collect(),
    ))
}

/// The identity or card `target` names, for the page at `origin`, and the
/// fields asked checked against its kind's form fields.
pub fn find(s: &Engine, origin: &str, target: &LoginRef, fields: &[String]) -> Result<Item> {
    site(origin)?;
    let not_found = || fail(ErrorCode::NotFound, "no such identity or card");
    let vault = VaultId::from_bytes(unhex(&target.vault).map_err(|_| not_found())?);
    let id = ItemId::from_bytes(unhex(&target.item).map_err(|_| not_found())?);
    let item = s
        .vaults
        .get(&vault)
        .and_then(|v| v.item(&id))
        .filter(|item| !item.deleted && matches!(item.kind.as_str(), "identity" | "card"))
        .ok_or_else(not_found)?;
    forms::validate(&item, fields)?;
    Ok(item)
}

/// The values of `fields` that `item` has.
pub fn values(item: &Item, fields: &[String]) -> BTreeMap<String, Secret> {
    forms::values(item, fields)
        .map(|(f, v)| (f.to_string(), Secret::new(v)))
        .collect()
}
