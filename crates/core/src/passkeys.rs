//! Shared passkey ceremony rules and mutation planning. Adapters establish
//! user presence/verification and persist the planned write before replying.

use std::{borrow::Borrow, collections::BTreeMap};

use zeroize::Zeroizing;

use crate::{
    DataOp, Field, FieldType, Item,
    autofill::value,
    site,
    webauthn::{self, Ceremony},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    DomainMismatch(&'static str),
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

/// The longest stored account label, in Unicode characters.
pub const MAX_USER_NAME: usize = 256;

pub fn rp_id(origin: &str, rp: Option<&str>) -> Result<String> {
    site::rp_id(origin, rp).map_err(Error::DomainMismatch)
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

pub fn check_excluded<I: Borrow<Item>>(
    items: impl IntoIterator<Item = I>,
    rp: &str,
    exclude: &[String],
) -> Result<()> {
    if items.into_iter().any(|item| {
        let item = item.borrow();
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

/// Page-provided account labels: no controls or bidi overrides, bounded and trimmed.
pub fn user_text(text: &str) -> String {
    text.chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(c, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(MAX_USER_NAME)
        .collect::<String>()
        .trim()
        .into()
}

pub struct Registration {
    pub create: DataOp,
    pub credential_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
    pub authenticator_data: String,
    pub public_key: String,
}

/// Registration input when the platform supplies a pre-computed 32-byte
/// `clientDataHash` (`ASPasskeyCredentialRequest` on macOS).
pub struct NewPasskeyHash {
    pub rp_id: String,
    pub client_data_hash: [u8; 32],
    pub user_id: String,
    pub user_name: String,
    pub display_name: String,
    pub exclude: Vec<String>,
}

pub struct HashRegistration {
    pub create: DataOp,
    pub credential_id: String,
    pub client_data_hash: String,
    pub attestation_object: String,
    pub authenticator_data: String,
    pub public_key: String,
}

fn passkey_create_op(
    rp_id: &str,
    credential_id: &str,
    user_id: &str,
    user_name: &str,
    display_name: &str,
    private_key: &str,
    created: &str,
) -> DataOp {
    let mut fields = BTreeMap::from([
        ("rp-id".into(), Field::new(FieldType::Text, rp_id)),
        (
            "credential-id".into(),
            Field::new(FieldType::Text, credential_id),
        ),
        ("user-handle".into(), Field::new(FieldType::Text, user_id)),
        (
            "private-key".into(),
            Field::new(FieldType::Secret, private_key),
        ),
        ("created".into(), Field::new(FieldType::Date, created)),
    ]);
    for (name, text) in [("username", user_name), ("display-name", display_name)] {
        if !text.is_empty() {
            fields.insert(name.into(), Field::new(FieldType::Text, text));
        }
    }
    DataOp::create("passkey", None, fields)
}

/// Prepare a registration without publishing it. No response may leave the
/// adapter until its create operation has been committed durably. Always make a
/// new item: the RP may reject or never receive this registration, so an existing
/// credential for the same user handle must remain usable. Only the RP's exclude
/// list establishes duplicates, not the user handle.
pub fn register(new: &NewPasskey, verified: bool, created: &str) -> Result<Registration> {
    rp_id(&new.origin, Some(&new.rp_id))?;
    let key = webauthn::generate()?;
    let made = webauthn::attest(&new.rp_id, &key.credential_id, &key.private_key, verified)?;
    let client = webauthn::client_data(Ceremony::Create, &new.challenge, &new.origin)?;
    let credential_id = webauthn::b64(&key.credential_id);
    let private_key = Zeroizing::new(webauthn::b64(&key.private_key));
    let create = passkey_create_op(
        &new.rp_id,
        &credential_id,
        &new.user_id,
        &new.user_name,
        &new.display_name,
        private_key.as_str(),
        created,
    );
    Ok(Registration {
        create,
        credential_id,
        client_data_json: webauthn::b64(&client),
        attestation_object: webauthn::b64(&made.attestation_object),
        authenticator_data: webauthn::b64(&made.authenticator_data),
        public_key: webauthn::b64(&made.public_key),
    })
}

/// Validate a pre-hashed registration (`ASPasskeyCredentialRequest`) before
/// asking the user.
pub fn check_create_hash(
    rp_id: &str,
    client_data_hash: &str,
    user_id: &str,
    user_name: &str,
    exclude: &[String],
) -> Result<NewPasskeyHash> {
    let rp_id = site::valid_rp_id(rp_id).map_err(Error::DomainMismatch)?;
    let client_data_hash = webauthn::client_data_hash(client_data_hash)?;
    webauthn::user_handle(user_id)?;
    for excluded in exclude {
        webauthn::unb64(excluded)?;
    }
    Ok(NewPasskeyHash {
        rp_id,
        client_data_hash,
        user_id: user_id.into(),
        user_name: user_text(user_name),
        display_name: String::new(),
        exclude: exclude.to_vec(),
    })
}

/// Prepare a pre-hashed registration (`ASPasskeyRegistrationCredential`).
pub fn register_hash(
    new: &NewPasskeyHash,
    verified: bool,
    created: &str,
) -> Result<HashRegistration> {
    let rp_id = site::valid_rp_id(&new.rp_id).map_err(Error::DomainMismatch)?;
    let key = webauthn::generate()?;
    let made = webauthn::attest(&rp_id, &key.credential_id, &key.private_key, verified)?;
    let credential_id = webauthn::b64(&key.credential_id);
    let private_key = Zeroizing::new(webauthn::b64(&key.private_key));
    let create = passkey_create_op(
        &rp_id,
        &credential_id,
        &new.user_id,
        &new.user_name,
        &new.display_name,
        private_key.as_str(),
        created,
    );
    Ok(HashRegistration {
        create,
        credential_id,
        client_data_hash: webauthn::b64(&new.client_data_hash),
        attestation_object: webauthn::b64(&made.attestation_object),
        authenticator_data: webauthn::b64(&made.authenticator_data),
        public_key: webauthn::b64(&made.public_key),
    })
}

pub struct Assertion {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: String,
}

pub struct HashAssertion {
    pub credential_id: String,
    pub client_data_hash: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: String,
}

pub fn validate(item: &Item, rp: &str) -> Result<()> {
    if item.deleted || item.kind != "passkey" {
        return Err(Error::NotFound);
    }
    if !matches(item, rp) {
        return Err(Error::DomainMismatch(
            "this passkey isn't for this relying party",
        ));
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

/// Sign a pre-computed 32-byte `clientDataHash` (`ASPasskeyCredentialRequest`).
pub fn sign_hash(
    item: &Item,
    rp: &str,
    client_data_hash: &str,
    verified: bool,
) -> Result<HashAssertion> {
    let rp = site::valid_rp_id(rp).map_err(Error::DomainMismatch)?;
    validate(item, &rp)?;
    let hash = webauthn::client_data_hash(client_data_hash)?;
    let private_key = Zeroizing::new(
        webauthn::unb64(value(item, "private-key").ok_or(Error::Incomplete)?)
            .map_err(|_| Error::Incomplete)?,
    );
    let (data, signature) = webauthn::assert_hash(&rp, &private_key, &hash, verified)?;
    Ok(HashAssertion {
        credential_id: value(item, "credential-id")
            .ok_or(Error::Incomplete)?
            .into(),
        client_data_hash: webauthn::b64(&hash),
        authenticator_data: webauthn::b64(&data),
        signature: webauthn::b64(&signature),
        user_handle: value(item, "user-handle").ok_or(Error::Incomplete)?.into(),
    })
}
