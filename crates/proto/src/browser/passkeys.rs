//! The passkey messages: listing a relying party's passkeys, a registration
//! (`passkey-create`), a sign-in (`passkey-get`), and stopping one.
//! Binary fields are base64url, as the page gets them.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

use super::format_ref;
use crate::daemon::{SitePasskey, Verify};

/// The passkeys saved for the page's relying party.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyList {
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub rp_id: Option<String>,
}

/// The account a registration is for, as the page names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyUser {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[ts(as = "Option<String>", optional)]
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCreate {
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub rp_id: Option<String>,
    pub challenge: String,
    pub user: PasskeyUser,
    /// Credential ids already registered, which must not be registered again.
    #[serde(default)]
    pub exclude: Vec<String>,
    pub user_verification: Verify,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyGet {
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub rp_id: Option<String>,
    #[serde(rename = "ref")]
    pub passkey: String,
    pub challenge: String,
    pub user_verification: Verify,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct PasskeyCancel {
    /// The id of the `passkey-create` or `passkey-get` to stop.
    #[ts(type = "number")]
    pub request: Value,
}

/// The `passkeys` reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct Passkeys {
    pub rp_id: String,
    pub can_verify: bool,
    pub passkeys: Vec<Passkey>,
}

/// A passkey saved for the relying party; never its private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct Passkey {
    #[serde(rename = "ref")]
    pub passkey: String,
    pub vault: String,
    pub credential_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub username: Option<String>,
    /// `YYYY-MM-DD`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub created: Option<String>,
}

impl From<SitePasskey> for Passkey {
    fn from(p: SitePasskey) -> Self {
        Self {
            passkey: format_ref(&p.passkey),
            vault: p.vault,
            credential_id: p.credential_id,
            username: p.username,
            created: p.created,
        }
    }
}

/// The `passkey-created` reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCreated {
    #[serde(rename = "ref")]
    pub passkey: String,
    pub credential_id: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub attestation_object: String,
    pub authenticator_data: String,
    pub public_key: String,
    pub verified: bool,
}

/// The `passkey-assertion` reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAssertion {
    pub credential_id: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: String,
    pub verified: bool,
}
