//! The line itself: what the daemon streams back, and the `Secret` carried
//! on it.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    ActivityEntry, AgentClientInfo, AgentGrantInfo, AgentLogin, AgentPasskey, Code, DeviceInfo,
    FormCard, FormIdentity, HealthReport, ImportReport, ItemInfo, LoginRef, MirrorReport,
    NotGranted, OneTimeCodeIdentity, PasskeyIdentity, PasswordIdentity, PeerSync, ResolvedSecret,
    SecretGrantInfo, SendInfo, SenderInfo, SiteLogin, SitePasskey, SiteStatus, SiteValues, Status,
    TagCount, VaultInfo,
};

/// A secret on the wire: wiped on drop; Debug leaves it out.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Message {
    Event {
        event: Event,
    },
    /// Streamed by `watch`.
    Change {
        #[serde(flatten)]
        change: Change,
    },
    Ok {
        reply: Reply,
    },
    Error {
        code: ErrorCode,
        message: String,
        /// With `not-granted`: what the user would have to allow.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant: Option<NotGranted>,
        /// With `choose-passkey`: the passkeys to choose from, no secrets.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passkeys: Option<Vec<AgentPasskey>>,
    },
}

/// What changed in the daemon. Vaults are named by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "kebab-case")]
pub enum Change {
    /// The first change: the stream is live. Fetch what you show now.
    Watching,
    Locked,
    Unlocked,
    /// The vault list changed: a vault was created, joined or renamed, its
    /// members changed, or the default moved.
    Vaults,
    /// Items in `vault` changed, written here or received by sync.
    Items {
        vault: String,
    },
    /// Devices were added to or removed from `vault`.
    Devices {
        vault: String,
    },
    /// New Activity entries were recorded.
    Activity,
    /// Password health findings or breach-check state changed.
    Health,
    /// Whether a newer Deadbolt is available changed: fetch the status.
    Update,
    /// Changes were dropped because the watcher fell behind. Fetch everything.
    Resync,
    /// The daemon is stopping, which locks the store. The stream ends.
    Stopping,
    /// Only to an app watcher: another launch asked for the window. Show
    /// and focus it, with `token` for the compositor when there is one.
    Activate {
        token: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    /// The request needs the store unlocked.
    Locked,
    /// No device is set up yet.
    NotInitialized,
    /// The item a request names doesn't exist.
    NotFound,
    /// The login a request names isn't saved for the site it names.
    DomainMismatch,
    /// A passkey the registration excludes is already saved for the site.
    Exists,
    /// The request's protocol version is not supported.
    Version,
    /// A site's rules allow only weak generated passwords.
    Weak,
    /// The agent client isn't paired (unknown or removed id, wrong token),
    /// or the caller may not do this (an AI pairing a client or granting).
    Forbidden,
    /// No live grant covers this client, site, login and field.
    NotGranted,
    /// Too many requests from this client; try again shortly.
    RateLimited,
    /// Several passkeys could sign: the error lists them, and the client
    /// asks again naming one.
    ChoosePasskey,
    /// Silent AutoFill (`interactive: false`) needs user interaction (Touch ID
    /// for passkey `UV`, or confirmation on an unassociated app).
    InteractionRequired,
    /// The user or closing sheet cancelled an interactive prompt.
    Cancelled,
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Event {
    /// The code to type on a device that holds the vault.
    Code { code: String },
    /// Paired into `vault` by `inviter`. With `passphrase`, the device isn't
    /// set up and the answer must carry its new passphrase.
    Joined {
        vault: String,
        inviter: DeviceInfo,
        passphrase: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Answer {
    pub answer: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<Secret>,
}

impl Answer {
    pub fn yes() -> Self {
        Self {
            answer: true,
            passphrase: None,
        }
    }

    pub fn no() -> Self {
        Self {
            answer: false,
            passphrase: None,
        }
    }

    pub fn passphrase(passphrase: Secret) -> Self {
        Self {
            answer: true,
            passphrase: Some(passphrase),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "kebab-case")]
pub enum Reply {
    Status(Box<Status>),
    Done,
    /// `app-activate` reached a running app.
    Activated,
    /// `app-activate` found no app: the caller starts one.
    NoApp,
    Vault {
        vault: VaultInfo,
    },
    Vaults {
        vaults: Vec<VaultInfo>,
    },
    /// A device added to (`pair`) or removed from (`device-remove`) a vault.
    Device {
        vault: VaultInfo,
        device: DeviceInfo,
    },
    Devices {
        devices: Vec<DeviceInfo>,
    },
    Sync {
        peers: Vec<PeerSync>,
    },
    Item {
        item: ItemInfo,
    },
    Items {
        items: Vec<ItemInfo>,
    },
    Tags {
        tags: Vec<TagCount>,
    },
    Import {
        report: ImportReport,
    },
    Code {
        code: Code,
    },
    Password {
        password: Zeroizing<String>,
    },
    SiteLogins {
        /// The page's site: its registrable domain.
        site: String,
        logins: Vec<SiteLogin>,
    },
    SiteFill {
        values: SiteValues,
    },
    SiteGenerated {
        password: Secret,
        /// Names it in `site-check` and `site-save`.
        id: String,
    },
    SiteCheck {
        status: SiteStatus,
        /// The logins with that username: those with another password for
        /// `update`, those with the same one for `same`.
        matches: Vec<LoginRef>,
    },
    SiteSaved {
        login: LoginRef,
        created: bool,
    },
    FormItems {
        identities: Vec<FormIdentity>,
        cards: Vec<FormCard>,
        /// Whether a card fill now would verify the user (Touch ID is on).
        can_verify: bool,
    },
    FormFill {
        /// `identity` or `card`.
        kind: String,
        /// The item's label.
        title: String,
        /// The fields asked for that it has, by name.
        values: BTreeMap<String, Secret>,
        /// Whether Touch ID verified the user for this fill.
        verified: bool,
    },
    Passkeys {
        rp_id: String,
        passkeys: Vec<SitePasskey>,
        /// Whether a ceremony now would verify the user (Touch ID is on).
        can_verify: bool,
    },
    /// A new passkey's registration. Binary values are base64url.
    PasskeyCreated {
        passkey: LoginRef,
        credential_id: String,
        client_data_json: String,
        attestation_object: String,
        authenticator_data: String,
        /// SubjectPublicKeyInfo DER.
        public_key: String,
        verified: bool,
    },
    /// A passkey sign-in. Binary values are base64url.
    PasskeyAssertion {
        credential_id: String,
        client_data_json: String,
        authenticator_data: String,
        signature: String,
        user_handle: String,
        verified: bool,
    },
    Mirror {
        report: MirrorReport,
    },
    SendCreated {
        send: SendInfo,
        /// How receivers reach the daemon's send endpoint.
        sender: SenderInfo,
    },
    Sends {
        sends: Vec<SendInfo>,
    },
    Send {
        send: SendInfo,
    },
    Activity {
        entries: Vec<ActivityEntry>,
    },
    /// A new agent client and its token, shown only now.
    AgentClientAdded {
        client: AgentClientInfo,
        token: Secret,
    },
    AgentClients {
        clients: Vec<AgentClientInfo>,
    },
    AgentGrant {
        grant: AgentGrantInfo,
    },
    AgentGrants {
        grants: Vec<AgentGrantInfo>,
    },
    /// What `resolve` found, in reference order.
    Secrets {
        secrets: Vec<ResolvedSecret>,
    },
    SecretGrants {
        grants: Vec<SecretGrantInfo>,
    },
    Health {
        report: HealthReport,
    },
    AgentLogins {
        /// The page's site: its registrable domain.
        site: String,
        /// Whether any live grant of the client covers the site.
        granted: bool,
        logins: Vec<AgentLogin>,
        /// The passkeys for the page its grants let it sign in with.
        passkeys: Vec<AgentPasskey>,
    },
    AutofillStatus {
        initialized: bool,
        unlocked: bool,
        touch_id_ready: bool,
        touch_id_reset: bool,
        can_verify: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identities_hash: Option<String>,
    },
    AutofillIdentities {
        identities_hash: String,
        passwords: Vec<PasswordIdentity>,
        passkeys: Vec<PasskeyIdentity>,
        one_time_codes: Vec<OneTimeCodeIdentity>,
    },
    AutofillList {
        logins: Vec<SiteLogin>,
        passkeys: Vec<SitePasskey>,
        unassociated: bool,
        can_verify: bool,
        identities_hash: String,
    },
    AutofillFill {
        values: SiteValues,
        identities_hash: String,
    },
    AutofillPasskeyCreated {
        passkey: LoginRef,
        credential_id: String,
        client_data_hash: String,
        attestation_object: String,
        authenticator_data: String,
        public_key: String,
        verified: bool,
        identities_hash: String,
    },
    AutofillPasskeyAssertion {
        credential_id: String,
        client_data_hash: String,
        authenticator_data: String,
        signature: String,
        user_handle: String,
        verified: bool,
        identities_hash: String,
    },
    SshGenerated {
        private_key: Secret,
        public_key: String,
        fingerprint: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<String>,
    },
}
