//! What the viewer shows and fills, projected from a pack's Head and
//! Secret records (`deadbolt_core::v2::pack`: each item's canonical CRDT
//! registers, the secret ones in the Secret).
//!
//! ```text
//! ViewerHit    {item_id, title, username, urls, passkey…, has_password, has_totp}   from Head
//! ViewerSecret {item_id, password, totp, passkey {credential_id, user_handle, private_key}} from Secret
//! keys = "item\0" || item id 16       one per item
//!        "site\0" || registrable domain of each saved URL
//!        "rp\0"   || passkey rp id
//! ```
//!
//! Both records carry the item id, and a reader checks it: a record the
//! index points at for the wrong item is refused, not shown.

use std::fmt;

use deadbolt_core::site;
use deadbolt_core::totp::Totp;
use deadbolt_core::v2::pack::{ItemHead, ItemSecret};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, ViewerError};

/// What a picker shows for one item: its Head record. No secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ViewerHit {
    /// 32 lowercase hex digits.
    pub item_id: String,
    pub title: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub passkey_rp_id: Option<String>,
    /// Base64url, as WebAuthn gives it.
    #[serde(default)]
    pub passkey_credential_id: Option<String>,
    #[serde(default)]
    pub has_password: bool,
    #[serde(default)]
    pub has_totp: bool,
}

/// A passkey's private material. Wiped on drop; `Debug` shows the ids only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewerPasskey {
    /// Base64url.
    pub credential_id: String,
    /// Base64url.
    pub user_handle: String,
    /// Base64url PKCS#8 of the P-256 key.
    pub private_key: Zeroizing<String>,
}

impl fmt::Debug for ViewerPasskey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewerPasskey")
            .field("credential_id", &self.credential_id)
            .finish_non_exhaustive()
    }
}

/// One item's Secret record: what a fill needs. Wiped on drop; `Debug`
/// shows which fields are set, never their values.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi", derive(uniffi::Object))]
pub struct ViewerSecret {
    pub item_id: String,
    #[serde(default)]
    pub password: Option<Zeroizing<String>>,
    /// A TOTP secret, as `otpauth://` or bare base32.
    #[serde(default)]
    pub totp: Option<Zeroizing<String>>,
    #[serde(default)]
    pub passkey: Option<ViewerPasskey>,
}

#[cfg_attr(feature = "ffi", uniffi::export)]
impl ViewerSecret {
    /// The TOTP code at `now_unix`, if the item has a TOTP secret.
    pub fn totp_code(&self, now_unix: u64) -> Result<Option<String>> {
        let Some(secret) = &self.totp else {
            return Ok(None);
        };
        let totp = Totp::parse(secret).map_err(|err| ViewerError::corrupt(err.to_string()))?;
        Ok(Some(totp.code(now_unix)))
    }
}

impl fmt::Debug for ViewerSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewerSecret")
            .field("item_id", &self.item_id)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("totp", &self.totp.as_ref().map(|_| "<redacted>"))
            .field("passkey", &self.passkey)
            .finish()
    }
}

/// 16 bytes from 32 hex digits, either case.
pub(crate) fn parse_item_id(hex: &str) -> Result<[u8; 16]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 32 {
        return Err(ViewerError::invalid("an item id is 32 hex digits"));
    }
    let digit = |b: u8| {
        char::from(b)
            .to_digit(16)
            .ok_or_else(|| ViewerError::invalid("an item id is 32 hex digits"))
    };
    let mut out = [0; 16];
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        out[i] = u8::try_from(digit(pair[0])? << 4 | digit(pair[1])?)
            .map_err(|_| ViewerError::invalid("an item id is 32 hex digits"))?;
    }
    Ok(out)
}

/// The index key an item is filed under by id.
pub fn item_key(id: &[u8; 16]) -> Vec<u8> {
    [b"item\0".as_slice(), id].concat()
}

/// The index key for a site (a registrable domain).
pub fn site_key(domain: &str) -> Vec<u8> {
    [b"site\0".as_slice(), domain.as_bytes()].concat()
}

/// The index key for a passkey's relying party id.
pub fn rp_key(rp_id: &str) -> Vec<u8> {
    [b"rp\0".as_slice(), rp_id.as_bytes()].concat()
}

/// The sites a Head is filed under: the registrable domain of each saved URL.
pub(crate) fn sites_of(hit: &ViewerHit) -> Vec<String> {
    let mut out: Vec<String> = site::login_domains(hit.urls.iter().map(String::as_str))
        .iter()
        .map(|host| site::registrable_domain(host))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The winning values of a Head's public fields of type `url`, in name order.
fn urls_of(head: &ItemHead) -> Vec<String> {
    head.fields
        .keys()
        .filter_map(|name| head.value(name))
        .filter(|v| v.kind == "url")
        .map(|v| v.value.clone())
        .collect()
}

pub(crate) fn hex_id(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

impl ViewerHit {
    /// What a picker shows for the item a Head record holds; `None` for a
    /// deleted item or one never created.
    pub fn from_head(head: &ItemHead) -> Option<Self> {
        let kind = head.kind()?;
        if head.deleted() {
            return None;
        }
        let text = |name: &str| head.value(name).map(|v| v.value.clone());
        let passkey = kind == "passkey";
        Some(Self {
            item_id: hex_id(head.id.as_bytes()),
            title: text("@name").unwrap_or_default(),
            username: text("username"),
            urls: urls_of(head),
            passkey_rp_id: passkey.then(|| text("rp-id")).flatten(),
            passkey_credential_id: passkey.then(|| text("credential-id")).flatten(),
            has_password: head
                .secret_fields
                .get("password")
                .is_some_and(|kind| !kind.is_empty()),
            has_totp: head.secret_fields.values().any(|kind| kind == "otp"),
        })
    }
}

impl ViewerSecret {
    /// What a fill needs from a Secret record.
    pub fn from_record(secret: &ItemSecret) -> Self {
        let value = |name: &str| secret.value(name).map(|v| Zeroizing::new(v.value.clone()));
        let totp = secret
            .fields
            .keys()
            .filter_map(|name| secret.value(name))
            .find(|v| v.kind == "otp")
            .map(|v| Zeroizing::new(v.value.clone()));
        let passkey = match (value("private-key"), secret.fill.get("credential-id")) {
            (Some(private_key), Some(credential_id)) => Some(ViewerPasskey {
                credential_id: credential_id.clone(),
                user_handle: secret.fill.get("user-handle").cloned().unwrap_or_default(),
                private_key,
            }),
            _ => None,
        };
        Self {
            item_id: hex_id(secret.id.as_bytes()),
            password: value("password"),
            totp,
            passkey,
        }
    }
}

/// Every key the index files an item's Head under.
pub(crate) fn keys_of(id: &[u8; 16], hit: Option<&ViewerHit>) -> crate::Result<Vec<Vec<u8>>> {
    let mut keys = vec![item_key(id)];
    let Some(hit) = hit else {
        return Ok(keys);
    };
    keys.extend(sites_of(hit).iter().map(|domain| site_key(domain)));
    if let Some(rp_id) = &hit.passkey_rp_id
        && let Ok(rp_id) = site::valid_rp_id(rp_id)
    {
        keys.push(rp_key(&rp_id));
    }
    Ok(keys)
}
