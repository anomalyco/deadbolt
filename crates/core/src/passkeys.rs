//! Shared passkey ceremony rules and mutation planning. Adapters establish
//! user presence/verification and persist the planned write before replying.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::{
    DataOp, Field, FieldType, Item,
    autofill::value,
    site,
    webauthn::{self, Ceremony},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("this relying party id isn't this site's")]
    DomainMismatch,
    #[error("this site already has a passkey here")]
    Exists,
    #[error("no such passkey")]
    NotFound,
    #[error("this passkey is incomplete")]
    Incomplete,
    #[error(transparent)]
    Webauthn(#[from] webauthn::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub fn rp_id(origin: &str, rp: Option<&str>) -> Result<String> {
    site::rp_id(origin, rp).map_err(|_| Error::DomainMismatch)
}

pub fn matches(item: &Item, rp: &str) -> bool {
    !item.deleted && item.kind == "passkey" && value(item, "rp-id") == Some(rp)
}

pub fn private(item: &Item, name: &str) -> bool {
    item.kind == "passkey" && name == "private-key"
}

pub struct NewPasskey {
    pub origin: String,
    pub rp_id: String,
    pub challenge: String,
    pub user_id: String,
    pub user_name: String,
    pub display_name: String,
    pub exclude: Vec<String>,
}

pub fn check_excluded<'a>(
    items: impl IntoIterator<Item = &'a Item>,
    rp: &str,
    exclude: &[String],
) -> Result<()> {
    if items.into_iter().any(|item| {
        matches(item, rp)
            && value(item, "credential-id").is_some_and(|id| exclude.iter().any(|e| e == id))
    }) {
        return Err(Error::Exists);
    }
    Ok(())
}

/// Validate before asking the user. Exclusions are checked again by the
/// adapter against current items immediately before committing registration.
pub fn check_create(
    origin: &str,
    rp: Option<&str>,
    challenge: &str,
    user_id: &str,
    user_name: &str,
    exclude: &[String],
) -> Result<NewPasskey> {
    let rp_id = rp_id(origin, rp)?;
    webauthn::challenge(challenge)?;
    webauthn::user_handle(user_id)?;
    Ok(NewPasskey {
        origin: origin.into(),
        rp_id,
        challenge: challenge.into(),
        user_id: user_id.into(),
        user_name: user_text(user_name),
        display_name: String::new(),
        exclude: exclude.to_vec(),
    })
}

/// Page-provided account labels: no controls, 256 characters, trimmed.
pub fn user_text(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect::<String>()
        .trim()
        .into()
}

pub struct Registration {
    pub fields: BTreeMap<String, Field>,
    pub credential_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
    pub authenticator_data: String,
    pub public_key: String,
}

/// Prepare a registration without publishing it. No response may leave the
/// adapter until its fields have been committed durably.
pub fn register(new: &NewPasskey, verified: bool, created: &str) -> Result<Registration> {
    rp_id(&new.origin, Some(&new.rp_id))?;
    let key = webauthn::generate()?;
    let made = webauthn::attest(&new.rp_id, &key.credential_id, &key.private_key, verified)?;
    let client = webauthn::client_data(Ceremony::Create, &new.challenge, &new.origin)?;
    let credential_id = webauthn::b64(&key.credential_id);
    let private_key = Zeroizing::new(webauthn::b64(&key.private_key));
    let mut fields = BTreeMap::from([
        ("rp-id".into(), Field::new(FieldType::Text, &new.rp_id)),
        (
            "credential-id".into(),
            Field::new(FieldType::Text, &credential_id),
        ),
        (
            "user-handle".into(),
            Field::new(FieldType::Text, &new.user_id),
        ),
        (
            "private-key".into(),
            Field::new(FieldType::Secret, private_key.as_str()),
        ),
        ("created".into(), Field::new(FieldType::Date, created)),
    ]);
    for (name, text) in [
        ("username", &new.user_name),
        ("display-name", &new.display_name),
    ] {
        if !text.is_empty() {
            fields.insert(name.into(), Field::new(FieldType::Text, text));
        }
    }
    Ok(Registration {
        fields,
        credential_id,
        client_data_json: webauthn::b64(&client),
        attestation_object: webauthn::b64(&made.attestation_object),
        authenticator_data: webauthn::b64(&made.authenticator_data),
        public_key: webauthn::b64(&made.public_key),
    })
}

/// Replacing an account preserves its identity, notes and other custom fields,
/// but removes account labels that the new registration no longer supplies.
pub fn replace(item: &Item, fields: &BTreeMap<String, Field>) -> Vec<DataOp> {
    let mut ops: Vec<_> = fields
        .iter()
        .map(|(name, field)| DataOp::set(item.id, name, field.clone()))
        .collect();
    for name in ["username", "display-name"] {
        if !fields.contains_key(name) && item.fields.contains_key(name) {
            ops.push(DataOp::remove(item.id, name));
        }
    }
    ops
}

pub struct Assertion {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: String,
}

pub fn validate(item: &Item, rp: &str) -> Result<()> {
    if item.deleted || item.kind != "passkey" {
        return Err(Error::NotFound);
    }
    if !matches(item, rp) {
        return Err(Error::DomainMismatch);
    }
    Ok(())
}

pub fn sign(
    item: &Item,
    origin: &str,
    rp: &str,
    challenge: &str,
    verified: bool,
) -> Result<Assertion> {
    rp_id(origin, Some(rp))?;
    validate(item, rp)?;
    let private_key = Zeroizing::new(
        webauthn::unb64(value(item, "private-key").ok_or(Error::Incomplete)?)
            .map_err(|_| Error::Incomplete)?,
    );
    let client = webauthn::client_data(Ceremony::Get, challenge, origin)?;
    let (data, signature) = webauthn::assert(rp, &private_key, &client, verified)?;
    Ok(Assertion {
        credential_id: value(item, "credential-id")
            .ok_or(Error::Incomplete)?
            .into(),
        client_data_json: webauthn::b64(&client),
        authenticator_data: webauthn::b64(&data),
        signature: webauthn::b64(&signature),
        user_handle: value(item, "user-handle").ok_or(Error::Incomplete)?.into(),
    })
}
