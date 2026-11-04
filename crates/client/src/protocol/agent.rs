//! AI callers (`docs/agent-control.md`): the clients paired to fill for them,
//! the grants that let them, and the secrets they resolve.

use serde::{Deserialize, Serialize};

use super::{Fill, LoginRef, Secret, SignIn};

/// What resolved secrets are for: a command's environment (`deadbolt
/// run`), a file (`deadbolt inject`) or printing (`deadbolt read`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    Run,
    Inject,
    Read,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Inject => "inject",
            Self::Read => "read",
        }
    }
}

/// One resolved reference: which item and field it found, and the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSecret {
    /// The vault's name.
    pub vault: String,
    /// The item's id.
    pub item: String,
    pub title: String,
    pub field: String,
    pub value: Secret,
    /// A file field: `value` is its name and contents in base64, which only
    /// `inject` writes out (decoded), for a template that is that one
    /// reference.
    #[serde(default)]
    pub file: bool,
}

/// A standing grant letting AI callers resolve one item's fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretGrantInfo {
    pub id: String,
    /// The vault's name, when the grant was made.
    pub vault: String,
    /// The item's id.
    pub item: String,
    /// The item's title, when the grant was made.
    pub title: String,
    /// Every field when empty.
    pub fields: Vec<String>,
    pub purposes: Vec<Purpose>,
    /// Unix seconds.
    pub created: u64,
    pub expires_at: Option<u64>,
    pub expired: bool,
}

/// A paired agent client's credentials, on every request it makes: its id
/// and the token `agent-client-add` gave it (64 hex digits). The daemon keeps
/// only the token's SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAuth {
    pub id: String,
    pub token: Secret,
}

/// A paired agent client, never its token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentClientInfo {
    pub id: String,
    pub name: String,
    /// Unix seconds.
    pub created: u64,
    /// When it last filled or signed in, Unix seconds.
    pub last_used: Option<u64>,
}

/// What a standing grant lets one client do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentGrantInfo {
    pub id: String,
    pub client_id: String,
    /// The client's name, if it is still paired.
    pub client_name: Option<String>,
    /// A registrable domain (`github.com`) or an exact origin
    /// (`https://app.example.com`); `None` for every site.
    pub site: Option<String>,
    /// One login only, else every login on the site.
    pub login: Option<LoginRef>,
    /// That login's username, else its title, when the grant was made.
    pub login_label: Option<String>,
    pub fields: Vec<Fill>,
    pub passkeys: bool,
    /// Unix seconds.
    pub created: u64,
    pub expires_at: Option<u64>,
    /// Whether it has expired.
    pub expired: bool,
}

/// A login an agent client may be shown, without values, and what its
/// grants cover of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLogin {
    #[serde(rename = "ref")]
    pub login: LoginRef,
    pub title: String,
    pub username: Option<String>,
    pub has_password: bool,
    pub has_totp: bool,
    /// A passkey for the page's relying party, for this login's username.
    pub has_passkey: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in: Option<SignIn>,
    /// The fields live grants let this client fill; empty if none.
    pub fields: Vec<Fill>,
    /// Whether a live grant lets this client sign in with its passkey.
    pub passkeys: bool,
}

/// A passkey an agent client may sign in with, or choose between. Never
/// its key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPasskey {
    #[serde(rename = "ref")]
    pub passkey: LoginRef,
    /// The WebAuthn user name the site gave it.
    pub username: Option<String>,
    /// The WebAuthn display name, when one was saved.
    pub display_name: Option<String>,
    pub rp_id: String,
    /// Base64url.
    pub credential_id: String,
}

/// What a `not-granted` error names, so the client can say what to allow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotGranted {
    /// The page's registrable domain.
    pub site: String,
    /// The login's username, else its title; `None` for the whole site.
    pub login: Option<String>,
}
