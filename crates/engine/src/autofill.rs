//! Browser autofill: which logins belong to a web page, and the values a
//! page may have. The daemon decides, not the browser host: every request
//! names the page's origin, and a login is only listed, filled or updated
//! for a page on the site of one of its URLs (see [`deadbolt_core::site`]).
//! A login saved on a site that shares the page's credentials is listed and
//! filled there too, but a page only ever saves, links or updates logins of
//! its own site ([`Site::owns_url`]).
//!
//! A site's logins are listed closest first (see [`autofill::rank`]), then the
//! most recently filled on this device, then by title.

use std::time::Duration;

use anyhow::{Result, anyhow};
use deadbolt_core::autofill::{self, Status, item_name};
pub use deadbolt_core::autofill::{otp, urls, value};
use deadbolt_core::listing::{SIGN_IN_HOSTS, saved_at_provider, sign_in_name, sign_in_provider};
use deadbolt_core::site::{Site, page_url};
use deadbolt_core::site_recipe::{RECIPE_FIELD, SiteRecipe, canonical_origin};
use deadbolt_core::totp::Totp;
use deadbolt_core::{DataOp, Field, FieldType, Item, ItemId, VaultId};
use deadbolt_proto::daemon::{
    ErrorCode, FieldInput, Fill, LoginRef, Secret, SignIn, SiteLogin, SiteStatus, SiteValues,
};

use crate::items::{create, label};
use crate::{Engine, fail, hex, unhex};

pub fn site(origin: &str) -> Result<Site> {
    Site::from_origin(origin).map_err(|reason| anyhow!("{origin}: {reason}"))
}

pub fn login_ref(vault: &VaultId, item: &ItemId) -> LoginRef {
    LoginRef {
        vault: hex(vault.as_bytes()),
        item: hex(item.as_bytes()),
    }
}

/// Every login on `site`, in every vault.
pub fn logins<'a>(s: &'a Engine, site: &'a Site) -> impl Iterator<Item = (VaultId, Item)> + 'a {
    s.vaults
        .iter()
        .flat_map(move |(id, vault)| vault.site_logins(site).map(move |item| (*id, item)))
}

/// The login `login` names, refused unless it's on `site`.
pub fn find(s: &Engine, login: &LoginRef, site: &Site) -> Result<(VaultId, Item)> {
    let not_found = || fail(ErrorCode::NotFound, "no such login");
    let vault = VaultId::from_bytes(unhex(&login.vault).map_err(|_| not_found())?);
    let id = ItemId::from_bytes(unhex(&login.item).map_err(|_| not_found())?);
    let item = s
        .vaults
        .get(&vault)
        .and_then(|v| v.item(&id))
        .filter(|item| !item.deleted && item.kind == "login")
        .ok_or_else(not_found)?;
    if !site.matches(urls(&item)) {
        return Err(fail(
            ErrorCode::DomainMismatch,
            format!("{} isn't saved for {}", label(&item), site.domain),
        ));
    }
    Ok((vault, item))
}

/// Whether one of `item`'s URLs is on `site` itself, not only on a site
/// sharing its credentials.
fn owned(site: &Site, item: &Item) -> bool {
    urls(item).any(|url| site.owns_url(url))
}

/// Refuses `item` unless it is saved for `site` itself.
fn own(site: &Site, item: &Item) -> Result<()> {
    if owned(site, item) {
        return Ok(());
    }
    Err(fail(
        ErrorCode::DomainMismatch,
        format!("{} isn't saved for {}", label(item), site.domain),
    ))
}

fn filled_key(login: &LoginRef) -> String {
    format!("{}:{}", login.vault, login.item)
}

/// How a login signs in with another account: its `sign-in-with`, and the
/// username (else the title) of its `sign-in-account`, if that login is in
/// one of the vaults here. Nothing else of that login.
pub fn sign_in(s: &Engine, item: &Item) -> Option<SignIn> {
    let provider = value(item, "sign-in-with")?.to_string();
    let account = value(item, "sign-in-account")
        .and_then(|id| unhex(id).ok())
        .map(ItemId::from_bytes)
        .filter(|id| *id != item.id)
        .and_then(|id| {
            s.vaults
                .values()
                .find_map(|v| v.item(&id).filter(|i| !i.deleted))
        })
        .map(|account| {
            value(&account, "username")
                .map(str::to_string)
                .unwrap_or_else(|| label(&account))
        });
    Some(SignIn { provider, account })
}

/// The form `item` was taught for the page at `origin` (see [`save_recipe`]),
/// if it's a login of the page's own site and its recipe is a valid one for
/// that exact origin. Anything else (another origin of the site, a site
/// sharing its credentials, a recipe a newer or broken client wrote) has none.
fn recipe(site: &Site, origin: Option<&str>, item: &Item) -> Option<String> {
    let origin = origin?;
    if !owned(site, item) {
        return None;
    }
    let raw = value(item, RECIPE_FIELD)?;
    let recipe = SiteRecipe::parse_and_validate(raw, site).ok()?;
    (recipe.origin == origin).then(|| raw.to_string())
}

pub fn list(s: &Engine, origin: &str) -> Result<(String, Vec<SiteLogin>)> {
    let site = site(origin)?;
    let page = canonical_origin(origin);
    let filled = s.filled();
    let mut found: Vec<_> = logins(s, &site)
        .map(|(vault, item)| {
            let login = SiteLogin {
                login: login_ref(&vault, &item.id),
                vault: s.vault(&vault).name().to_string(),
                title: label(&item),
                username: value(&item, "username").map(str::to_string),
                has_password: value(&item, "password").is_some(),
                has_otp: otp(&item).is_some_and(|f| !f.value.is_empty()),
                urls: urls(&item)
                    .filter(|url| site.matches_url(url))
                    .map(str::to_string)
                    .collect(),
                sign_in: sign_in(s, &item),
                recipe: recipe(&site, page.as_deref(), &item),
            };
            let used = filled.get(&filled_key(&login.login)).copied().unwrap_or(0);
            (autofill::rank(origin, &item, used), login)
        })
        .collect();
    found.sort_by(|(ra, a), (rb, b)| {
        ra.cmp(rb)
            .then_with(|| (&a.login.vault, &a.login.item).cmp(&(&b.login.vault, &b.login.item)))
    });
    Ok((site.domain, found.into_iter().map(|(_, l)| l).collect()))
}

/// The values `want` names that the login has, at `now` for a code.
pub fn fill(
    s: &Engine,
    origin: &str,
    login: &LoginRef,
    want: &[Fill],
    now: Duration,
) -> Result<SiteValues> {
    let site = site(origin)?;
    let (_, item) = find(s, login, &site)?;
    let mut values = SiteValues::default();
    for fill in want {
        match fill {
            Fill::Username => values.username = value(&item, "username").map(str::to_string),
            Fill::Password => values.password = value(&item, "password").map(Secret::new),
            Fill::Totp => {
                let Some(field) = otp(&item).filter(|f| !f.value.is_empty()) else {
                    continue;
                };
                let totp = Totp::parse(&field.value).map_err(|e| {
                    anyhow!("the one-time password of {} is invalid: {e}", label(&item))
                })?;
                values.totp = Some(Secret::new(totp.code(now.as_secs())));
            }
        }
    }
    // Only ranks a site's logins: never fail a fill that was allowed.
    if let Err(error) = s.set_filled(filled_key(login), now.as_secs()) {
        tracing::warn!(%error, "remembering the fill failed");
    }
    Ok(values)
}

/// Without a username, a login with any username and the same password is
/// `same`, and nothing is `update`. Only the site's own logins are
/// matches, closest first: a login of a site sharing its credentials is
/// never one to update, though one with the same username and password
/// makes the page `same`, with no matches.
pub fn check(
    s: &Engine,
    origin: &str,
    username: Option<&str>,
    password: &Secret,
) -> Result<(SiteStatus, Vec<LoginRef>)> {
    let site = site(origin)?;
    let filled = s.filled();
    let mut status = Status::New;
    let mut matches = Vec::new();
    let mut shared_same = false;
    for (vault, saved) in &s.vaults {
        let (own, shared): (Vec<Item>, Vec<Item>) = saved
            .site_logins(&site)
            .partition(|item| owned(&site, item));
        let (checked, ids) = autofill::check(own.iter().cloned(), username, password.expose());
        if checked > status {
            status = checked;
            matches.clear();
        }
        if checked == status {
            for item in own.iter().filter(|item| ids.contains(&item.id)) {
                let login = login_ref(vault, &item.id);
                let used = filled.get(&filled_key(&login)).copied().unwrap_or(0);
                matches.push((autofill::rank(origin, item, used), login));
            }
        }
        shared_same |= autofill::check(shared, username, password.expose()).0 == Status::Same;
    }
    if status == Status::New && shared_same {
        status = Status::Same;
    }
    matches.sort_by(|(ra, a), (rb, b)| {
        ra.cmp(rb)
            .then_with(|| (&a.vault, &a.item).cmp(&(&b.vault, &b.item)))
    });
    let matches = matches.into_iter().map(|(_, login)| login).collect();
    let status = match status {
        Status::New => SiteStatus::New,
        Status::Update => SiteStatus::Update,
        Status::Same => SiteStatus::Same,
    };
    Ok((status, matches))
}

/// What to save from a page.
pub struct Save<'a> {
    pub origin: &'a str,
    pub login: Option<&'a LoginRef>,
    pub title: &'a str,
    pub url: &'a str,
    pub username: &'a str,
    pub password: &'a Secret,
}

/// Saves a new login in the default vault, or `save.login`'s new
/// password. Returns the login and whether it is new.
pub fn save(s: &mut Engine, save: Save) -> Result<(LoginRef, bool)> {
    let site = site(save.origin)?;
    if save.password.expose().is_empty() {
        return Err(anyhow!("the password is empty"));
    }
    let url = page_url(save.url).map_err(|reason| anyhow!("{reason}"))?;
    if !site.owns_url(url) {
        return Err(fail(
            ErrorCode::DomainMismatch,
            format!("{url} isn't on {}", site.domain),
        ));
    }
    if let Some(login) = save.login {
        let (vault, item) = find(s, login, &site)?;
        own(&site, &item)?;
        let today = s.today();
        s.update(vault, |v, secret| {
            Ok(v.write(
                secret,
                autofill::password_update_at(item.id, save.password.expose(), &today),
            )?)
        })?;
        return Ok((login_ref(&vault, &item.id), false));
    }
    let vault = s.resolve(None)?;
    let input = |name: &str, value: &str| FieldInput {
        name: name.into(),
        kind: None,
        value: value.into(),
    };
    let mut inputs = vec![input("url", url)];
    if !save.username.trim().is_empty() {
        inputs.push(input("username", save.username.trim()));
    }
    inputs.push(input("password", save.password.expose()));
    let title = item_name(save.title);
    let name = Some(title).filter(|t| !t.is_empty() && *t != site.domain);
    let info = create(s, None, "login", name, inputs)?;
    Ok((
        LoginRef {
            vault: hex(vault.as_bytes()),
            item: info.id,
        },
        true,
    ))
}

/// Keeps `recipe` (JSON, see [`SiteRecipe`]) on `login` as the form the user
/// taught it on the page at `origin`, or with `None` clears the one it has.
/// Only on a login of the page's own site, never one it only shares
/// credentials with, and only a valid recipe for that exact origin: it is
/// stored as compact JSON, so nothing but its own keys ever goes in.
/// Returns whether the login changed.
pub fn save_recipe(
    s: &mut Engine,
    origin: &str,
    login: &LoginRef,
    recipe: Option<&str>,
) -> Result<bool> {
    let site = site(origin)?;
    let (vault, item) = find(s, login, &site)?;
    own(&site, &item)?;
    let op = match recipe {
        Some(raw) => {
            let recipe = SiteRecipe::parse_and_validate(raw, &site).map_err(|e| anyhow!("{e}"))?;
            if canonical_origin(origin).as_deref() != Some(recipe.origin.as_str()) {
                return Err(fail(
                    ErrorCode::DomainMismatch,
                    format!("the learned form is for {}, not {origin}", recipe.origin),
                ));
            }
            let json = recipe.to_json();
            if value(&item, RECIPE_FIELD) == Some(json.as_str()) {
                return Ok(false);
            }
            DataOp::set(item.id, RECIPE_FIELD, Field::new(FieldType::Text, json))
        }
        None if item.fields.contains_key(RECIPE_FIELD) => DataOp::remove(item.id, RECIPE_FIELD),
        None => return Ok(false),
    };
    s.update(vault, |v, secret| Ok(v.write(secret, vec![op])?))?;
    Ok(true)
}

/// What a provider link saves (see link).
pub struct Link<'a> {
    pub origin: &'a str,
    pub title: &'a str,
    pub url: &'a str,
    pub provider: &'a str,
    pub account: &'a LoginRef,
    /// Also accept the test sign-in hosts (`DEADBOLT_TEST_PROVIDER_HOSTS`).
    pub test_hosts: bool,
}

/// Saves a new login, in the vault of `link.account`, for the site of
/// `link.origin` that signs in with `link.provider` through `link.account`,
/// the provider login a sign-in just went through (docs/autofill.md, "Your
/// provider accounts"). It holds no password of its own. Refused for an
/// unknown provider or an account not saved at its sign-in host. Returns
/// the login and whether it is new: an existing link is returned as is.
pub fn link(s: &mut Engine, link: Link) -> Result<(LoginRef, bool)> {
    let site = site(link.origin)?;
    let url = page_url(link.url).map_err(|reason| anyhow!("{reason}"))?;
    if !site.owns_url(url) {
        return Err(fail(
            ErrorCode::DomainMismatch,
            format!("{url} isn't on {}", site.domain),
        ));
    }
    // Only a provider Deadbolt knows the sign-in hosts of, by its id.
    let provider = sign_in_provider(link.provider)
        .filter(|p| SIGN_IN_HOSTS.iter().any(|(id, _)| id == p))
        .ok_or_else(|| anyhow!("{} isn't a provider Deadbolt links", link.provider.trim()))?;
    let not_found = || fail(ErrorCode::NotFound, "no such login");
    let vault = VaultId::from_bytes(unhex(&link.account.vault).map_err(|_| not_found())?);
    let id = ItemId::from_bytes(unhex(&link.account.item).map_err(|_| not_found())?);
    let account = s
        .vaults
        .get(&vault)
        .and_then(|v| v.item(&id))
        .filter(|item| !item.deleted && item.kind == "login")
        .ok_or_else(not_found)?;
    // The account must be the provider's own login, saved at its sign-in host.
    if !urls(&account).any(|u| saved_at_provider(&provider, u, link.test_hosts)) {
        return Err(fail(
            ErrorCode::DomainMismatch,
            format!(
                "{} isn't saved at {}",
                label(&account),
                sign_in_name(&provider)
            ),
        ));
    }
    // One already links the site itself to it: that's the link. One on a
    // site sharing its credentials isn't.
    let account_id = hex(id.as_bytes());
    if let Some((held, item)) = logins(s, &site).find(|(_, item)| {
        owned(&site, item)
            && value(item, "sign-in-with") == Some(provider.as_str())
            && value(item, "sign-in-account") == Some(account_id.as_str())
    }) {
        return Ok((login_ref(&held, &item.id), false));
    }
    let input = |name: &str, value: &str| FieldInput {
        name: name.into(),
        kind: None,
        value: value.into(),
    };
    let inputs = vec![
        input("url", url),
        input("sign-in-with", &provider),
        input("sign-in-account", &account_id),
    ];
    let title = item_name(link.title);
    let name = Some(title).filter(|t| !t.is_empty() && *t != site.domain);
    // In the provider login's own vault, beside it, not the default one.
    let info = create(s, Some(&link.account.vault), "login", name, inputs)?;
    Ok((
        LoginRef {
            vault: link.account.vault.clone(),
            item: info.id,
        },
        true,
    ))
}

#[cfg(test)]
mod tests;
