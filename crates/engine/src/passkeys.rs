//! Passkeys: the daemon is the authenticator. A passkey is an item of kind
//! `passkey` found by its relying party id; its private key is read here to
//! sign and is never listed, returned or exported to a client. Every request
//! names the page's origin, which the browser (not the page) reported, and
//! the daemon builds the client data from it (see docs/autofill.md).

use anyhow::{Context, Result};
use deadbolt_core::{Item, ItemId, VaultId, passkeys as shared};
use deadbolt_proto::daemon::{ErrorCode, LoginRef, SitePasskey};

use crate::clock::nearest_date;
use crate::{Engine, fail, hex, unhex};
pub use shared::{NewPasskey, private, user_text};

pub fn shared_error(error: shared::Error) -> anyhow::Error {
    match error {
        shared::Error::DomainMismatch(_) => fail(ErrorCode::DomainMismatch, error.to_string()),
        shared::Error::Exists => fail(ErrorCode::Exists, error.to_string()),
        shared::Error::NotFound => fail(ErrorCode::NotFound, error.to_string()),
        _ => error.into(),
    }
}

/// The relying party id a page at `origin` asks for, checked.
pub fn rp_id(origin: &str, rp_id: Option<&str>) -> Result<String> {
    if origin == "null" {
        return Err(fail(
            ErrorCode::DomainMismatch,
            "a sandboxed or opaque frame gets no passkeys",
        ));
    }
    deadbolt_core::site::rp_id(origin, rp_id).map_err(|reason| {
        fail(
            ErrorCode::DomainMismatch,
            format!("{origin}: {reason} ({})", rp_id.unwrap_or("no rp id")),
        )
    })
}

fn value<'a>(item: &'a Item, field: &str) -> Option<&'a str> {
    item.fields
        .get(field)
        .map(|f| f.value.as_str())
        .filter(|v| !v.is_empty())
}

fn passkey_ref(vault: &VaultId, item: &ItemId) -> LoginRef {
    LoginRef {
        vault: hex(vault.as_bytes()),
        item: hex(item.as_bytes()),
    }
}

/// Every passkey for the relying party `rp`, in every vault.
pub fn passkeys<'a>(s: &'a Engine, rp: &'a str) -> impl Iterator<Item = (VaultId, Item)> + 'a {
    s.vaults.iter().flat_map(move |(id, vault)| {
        vault
            .items()
            .into_iter()
            .filter(|item| shared::matches(item, rp))
            .map(move |item| (*id, item))
    })
}

pub fn list(s: &Engine, origin: &str, rp: Option<&str>) -> Result<(String, Vec<SitePasskey>)> {
    let rp = rp_id(origin, rp)?;
    let mut found: Vec<(bool, SitePasskey)> = passkeys(s, &rp)
        .map(|(vault, item)| {
            (
                item.favorite,
                SitePasskey {
                    passkey: passkey_ref(&vault, &item.id),
                    vault: s.vault(&vault).name().to_string(),
                    credential_id: value(&item, "credential-id").unwrap_or_default().into(),
                    username: value(&item, "username").map(str::to_string),
                    created: value(&item, "created").map(str::to_string),
                },
            )
        })
        .collect();
    found.sort_by(|(fa, a), (fb, b)| {
        (!*fa, &a.username, &a.vault, &a.passkey.item).cmp(&(
            !*fb,
            &b.username,
            &b.vault,
            &b.passkey.item,
        ))
    });
    Ok((rp, found.into_iter().map(|(_, p)| p).collect()))
}

/// Refuses a registration when the site already has one of `exclude` here.
fn check_excluded(s: &Engine, rp: &str, exclude: &[String]) -> Result<()> {
    let items: Vec<_> = passkeys(s, rp).map(|(_, item)| item).collect();
    shared::check_excluded(&items, rp, exclude).map_err(shared_error)
}

/// Checks a registration before the user is asked or anything is stored:
/// the relying party, the challenge and user handle, and that the site
/// doesn't already have one of `exclude` here.
pub fn check_create(
    s: &Engine,
    origin: &str,
    rp: Option<&str>,
    challenge: &str,
    user_id: &str,
    user_name: &str,
    exclude: &[String],
) -> Result<NewPasskey> {
    let rp = rp_id(origin, rp)?;
    let new = shared::check_create(origin, Some(&rp), challenge, user_id, user_name, exclude)
        .map_err(shared_error)?;
    check_excluded(s, &new.rp_id, exclude)?;
    Ok(new)
}

pub struct Created {
    pub passkey: LoginRef,
    pub credential_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
    pub authenticator_data: String,
    pub public_key: String,
}

/// Makes the passkey `new` describes as a new item in the default vault,
/// preserving any existing credential until the user explicitly deletes it.
/// The vault can have changed while the user was asked, so exclusions are
/// checked again here. `now` is Unix seconds, for its creation date.
pub fn create_passkey(
    s: &mut Engine,
    new: &NewPasskey,
    verified: bool,
    now: i64,
) -> Result<Created> {
    check_excluded(s, &new.rp_id, &new.exclude)?;
    let created = nearest_date(now);
    let made = shared::register(new, verified, &created).map_err(shared_error)?;

    let vault = s.resolve(None)?;
    let (ids, _) = s.update(vault, |v, author| Ok(v.create_items(author, vec![made.create])?))?;
    let id = ids.first().copied().context("the passkey was not created")?;
    let passkey = passkey_ref(&vault, &id);
    Ok(Created {
        passkey,
        credential_id: made.credential_id,
        client_data_json: made.client_data_json,
        attestation_object: made.attestation_object,
        authenticator_data: made.authenticator_data,
        public_key: made.public_key,
    })
}

/// The passkey `passkey` names, refused unless it's for the relying party
/// `rp`.
pub fn find(s: &Engine, passkey: &LoginRef, rp: &str) -> Result<(VaultId, Item)> {
    let not_found = || fail(ErrorCode::NotFound, "no such passkey");
    let vault = VaultId::from_bytes(unhex(&passkey.vault).map_err(|_| not_found())?);
    let id = ItemId::from_bytes(unhex(&passkey.item).map_err(|_| not_found())?);
    let item = s
        .vaults
        .get(&vault)
        .and_then(|v| v.item(&id))
        .filter(|item| !item.deleted && item.kind == "passkey")
        .ok_or_else(not_found)?;
    shared::validate(&item, rp).map_err(|error| match error {
        shared::Error::DomainMismatch(_) => fail(
            ErrorCode::DomainMismatch,
            format!("this passkey isn't for {rp}"),
        ),
        other => shared_error(other),
    })?;
    Ok((vault, item))
}

pub use shared::Assertion;

/// Signs `challenge` for the page at `origin` with the passkey `passkey`
/// for the relying party `rp` (checked by [`rp_id`]).
pub fn sign(
    s: &Engine,
    origin: &str,
    rp: &str,
    passkey: &LoginRef,
    challenge: &str,
    verified: bool,
) -> Result<Assertion> {
    let (_, item) = find(s, passkey, rp)?;
    shared::sign(&item, origin, rp, challenge, verified).map_err(shared_error)
}
