//! Sites: the logins saved for one, what a page or a macOS AutoFill service
//! asks of it, and the values a fill returns. Never a secret the caller
//! didn't ask for.

use serde::{Deserialize, Serialize};

use super::Secret;

/// How macOS `AuthenticationServices` names the service asking for a fill
/// (`ASCredentialServiceIdentifier`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutofillService {
    pub identifier: String,
    pub kind: AutofillServiceKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutofillServiceKind {
    Domain,
    Url,
    /// `ASCredentialServiceIdentifierTypeApp` (macOS 26.2+): an app bundle id
    /// with no web domain of its own.
    App,
}

/// One `ASPasswordCredentialIdentity` entry for `ASCredentialIdentityStore`.
/// Never carries a password or vault/item title.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordIdentity {
    pub domain: String,
    pub username: String,
    pub record_id: String,
    pub rank: i64,
}

/// One `ASPasskeyCredentialIdentity` entry for `ASCredentialIdentityStore`.
/// Never carries the private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyIdentity {
    pub rp_id: String,
    pub username: String,
    /// Base64url.
    pub credential_id: String,
    /// Base64url.
    pub user_handle: String,
    pub record_id: String,
    pub rank: i64,
}

/// One `ASOneTimeCodeCredentialIdentity` entry (macOS 15+) for
/// `ASCredentialIdentityStore`. Never carries the OTP seed or code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimeCodeIdentity {
    pub domain: String,
    pub label: String,
    pub record_id: String,
    pub rank: i64,
}
/// What a site asks of user verification in a passkey ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verify {
    Required,
    Preferred,
    Discouraged,
}

/// A passkey saved for a relying party, without its key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SitePasskey {
    pub passkey: LoginRef,
    /// The name of its vault.
    pub vault: String,
    /// Base64url.
    pub credential_id: String,
    pub username: Option<String>,
    /// `YYYY-MM-DD`.
    pub created: Option<String>,
}

/// What a page asks of a new password: its `passwordrules`, the field's
/// `minlength` and `maxlength` (with its `pattern`'s length) and the
/// characters its `pattern` takes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteField {
    pub rules: Option<String>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub allowed: Option<String>,
}

/// A password submitted on a web page: as the page had it, or the pending
/// one `site-generate` made for the page's origin, by its id, which the daemon
/// fills in itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PagePassword {
    Typed(Secret),
    Generated(String),
}

/// One login, unambiguously: its vault's id and its item id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRef {
    pub vault: String,
    pub item: String,
}

/// A value autofill can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fill {
    Username,
    Password,
    /// The current one-time code.
    Totp,
}

/// A login saved for a site, without values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteLogin {
    pub login: LoginRef,
    /// The name of its vault.
    pub vault: String,
    pub title: String,
    pub username: Option<String>,
    pub has_password: bool,
    pub has_otp: bool,
    /// The login's URLs that match the site; others are left out.
    pub urls: Vec<String>,
    /// How the site is signed in to with another account, if it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in: Option<SignIn>,
}

/// A "Sign in with Google" login: the provider and, if the login it signs
/// in with is in one of the user's vaults, that login's username, else its
/// title. Never any other value of that login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignIn {
    /// The provider's id (`google`, see
    /// [`crate::protocol::SIGN_IN_PROVIDERS`]) or, for one
    /// this version doesn't know, its name as given.
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}
/// What a fill asked for and the login has.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteValues {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<Secret>,
}

/// How a login typed into a page compares with the saved ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SiteStatus {
    /// No saved login for the site has that username.
    New,
    /// Saved, with another password.
    Update,
    /// Saved with that password.
    Same,
}
