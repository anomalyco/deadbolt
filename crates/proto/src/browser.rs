//! The native messaging protocol between the browser extension and
//! `deadbolt browser-host` (docs/autofill.md). The browser frames each
//! message (a native-endian u32 length, then UTF-8 JSON); these types are the
//! JSON.
//!
//! ```text
//! extension -> host  {"id":1,"type":"list","origin":"https://github.com"}   a Request
//! host -> extension  {"id":1,"type":"list","site":"github.com",...}         its Body
//! host -> extension  {"type":"changed","change":"items"}                    pushed, no id
//! ```
//!
//! Every request carries an `id` the host echoes on its answer. A request
//! the host can't read is answered with an `error` whose `id` is the one it
//! could read, or `null`.
//!
//! These types are also the extension's: `gen-ts` writes them to
//! `extension/src/gen/proto.ts`. Optional fields are left out when empty, as
//! the TypeScript's `?` says.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

use crate::daemon::{
    self, Fill, FormKind, LoginRef, Secret, SignIn, SiteField, SiteStatus, SiteValues,
};

mod passkeys;
#[cfg(test)]
mod tests;

pub use passkeys::{
    Passkey, PasskeyAssertion, PasskeyCancel, PasskeyCreate, PasskeyCreated, PasskeyGet,
    PasskeyList, PasskeyUser, Passkeys,
};

/// The version of this message set, in `hello`.
pub use crate::BROWSER_PROTOCOL_VERSION as PROTOCOL;

/// The native messaging host's name, in its manifest and the extension's
/// `connectNative`.
pub const NATIVE_HOST: &str = "anomaly.deadbolt.browser";

/// The largest request the host reads; anything bigger is skipped and refused.
pub const MAX_REQUEST: usize = 64 * 1024;

/// The browser's limit on a message from the host.
pub const MAX_REPLY: usize = 1024 * 1024;

/// What this host does, in `hello`. The extension offers a feature only when
/// the host names it.
pub const CAPABILITIES: [&str; 11] = [
    "list",
    "fill",
    "check",
    "save",
    "generate",
    "passkeys",
    "learn",
    "learn-files",
    "forms",
    "save-form",
    "unlock-prompt",
];

/// A message from the extension, after its `id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[ts(rename = "RequestBody")]
pub enum Request {
    Hello,
    /// The logins saved for the page's site, without values.
    List {
        origin: String,
    },
    /// Values of one login.
    Fill {
        origin: String,
        #[serde(rename = "ref")]
        login: String,
        want: Vec<Fill>,
    },
    /// A new password for a new-password field, held by the daemon as
    /// `generated` until it's kept or dropped.
    Generate {
        origin: String,
        #[serde(flatten)]
        field: FieldRules,
    },
    /// Whether `generate` would make a strong password for the field.
    GenerateCheck {
        origin: String,
        #[serde(flatten)]
        field: FieldRules,
    },
    GenerateKeep {
        origin: String,
        generated: String,
    },
    GenerateDrop {
        origin: String,
        generated: String,
    },
    /// How a login typed into the page compares with the saved ones.
    Check {
        origin: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        password: Option<Secret>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        generated: Option<String>,
    },
    /// Saves a new login, or updates the one `ref` names.
    Save {
        origin: String,
        entry: Entry,
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        login: Option<String>,
    },
    /// The identities and cards a form on the page can be filled from.
    Forms {
        origin: String,
        kinds: Vec<FormKind>,
    },
    /// Some fields of one identity or card.
    FillForm {
        origin: String,
        #[serde(rename = "ref")]
        item: String,
        #[ts(type = "Array<FormField>")]
        fields: Vec<String>,
    },
    /// Saves an identity or card the user typed into a form and chose to
    /// keep: a new one, or changed fields of the one `ref` names. Never a
    /// card's security code; an update never changes a card's number.
    SaveForm {
        origin: String,
        kind: FormKind,
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        item: Option<String>,
        #[ts(type = "Partial<Record<FormField, string>>")]
        fields: BTreeMap<String, Secret>,
    },
    PasskeyList(PasskeyList),
    PasskeyCreate(PasskeyCreate),
    PasskeyGet(PasskeyGet),
    PasskeyCancel(PasskeyCancel),
    /// One line for the log of a recording (Record). The extension sends
    /// form shapes only, never values; the host just appends it.
    Learn {
        session: String,
        #[ts(type = "Record<string, unknown>")]
        line: serde_json::Map<String, Value>,
    },
    /// Part of a session's log, from byte `offset` (0 when left out), whole
    /// lines, for the popup's Download.
    LearnRead {
        session: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        offset: Option<u64>,
    },
    /// Deletes a session's log, for the popup's Delete.
    LearnDelete {
        session: String,
    },
    /// The user clicked "Unlock Deadbolt" in the locked menu: Touch ID when
    /// it's ready, else Deadbolt's own window, where the passphrase is
    /// typed. The browser never asks for the passphrase.
    UnlockPrompt,
}

/// What a page says about a new-password field: its `passwordrules`, length
/// limits and the characters its `pattern` takes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct FieldRules {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub rules: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub min_length: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub max_length: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub allowed: Option<String>,
}

impl From<FieldRules> for SiteField {
    fn from(f: FieldRules) -> Self {
        Self {
            rules: f.rules,
            min_length: f.min_length,
            max_length: f.max_length,
            allowed: f.allowed,
        }
    }
}

/// A login to save: a password, typed or `generated`, or a provider link
/// (`signIn`) in its place.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub title: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[ts(as = "Option<String>", optional)]
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub password: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub generated: Option<String>,
    /// In place of a password: a login that signs in with a provider login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub sign_in: Option<EntrySignIn>,
}

/// A save's provider link: the provider's id and the login (a ref) it signs
/// in with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct EntrySignIn {
    pub provider: String,
    pub account: String,
}

/// One message from the host: its `id` (none on a pushed change) and body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(flatten)]
    pub body: Body,
}

/// What the host sends: the answer to a request, or (`changed`) a change
/// it pushes on its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Body {
    #[serde(rename_all = "camelCase")]
    Hello {
        protocol: u32,
        version: String,
        status: HostStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        detail: Option<String>,
        /// What this host does ([`CAPABILITIES`]).
        capabilities: Vec<String>,
        /// Locked, and Touch ID can unlock it now (`unlock-prompt` asks for it).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        #[ts(as = "Option<bool>", optional)]
        touch_id_ready: bool,
    },
    List {
        /// The site the origin belongs to, as the logins are saved for.
        site: String,
        accounts: Vec<Account>,
    },
    /// Only the values asked for that the login has.
    Fill {
        #[serde(flatten)]
        values: SiteValues,
    },
    Generate {
        password: Secret,
        /// Names it in `check` and `save`.
        generated: String,
    },
    GenerateCheck,
    GenerateKeep,
    GenerateDrop,
    Check {
        status: SiteStatus,
        /// The refs of the saved logins with that username.
        matches: Vec<String>,
    },
    Save {
        #[serde(rename = "ref")]
        login: String,
        created: bool,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
    /// Pushed when the daemon locks, unlocks, stops, starts or its items change.
    #[serde(rename_all = "camelCase")]
    Changed {
        change: Change,
        /// On `locked`: Touch ID can unlock it now, as hello's says.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        #[ts(as = "Option<bool>", optional)]
        touch_id_ready: bool,
    },
    #[serde(rename_all = "camelCase")]
    Forms {
        identities: Vec<FormIdentity>,
        cards: Vec<FormCard>,
        /// Whether filling a card's number or code now raises Touch ID.
        can_verify: bool,
    },
    FillForm {
        /// Only the fields asked for that the item has.
        #[ts(type = "Partial<Record<FormField, string>>")]
        values: BTreeMap<String, Secret>,
        /// Whether Touch ID verified the user for this fill.
        verified: bool,
    },
    SaveForm {
        #[serde(rename = "ref")]
        item: String,
        created: bool,
    },
    Passkeys(Passkeys),
    PasskeyCreated(PasskeyCreated),
    PasskeyAssertion(PasskeyAssertion),
    PasskeyCancelled {
        found: bool,
    },
    Learned,
    LearnText {
        text: String,
        /// Where the rest of the log starts, or null at its end.
        next: Option<u64>,
    },
    LearnDeleted {
        found: bool,
    },
    /// The answer to `unlock-prompt`: `app` when Deadbolt's window came
    /// forward for the passphrase (`unlocked` follows once it's typed
    /// there), false when Touch ID unlocked it or it already was.
    UnlockPrompt {
        app: bool,
    },
}

/// Whether the host can serve requests now, in `hello`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "kebab-case")]
pub enum HostStatus {
    Ready,
    Locked,
    NotSetUp,
    /// No daemon answered.
    Unavailable,
}

/// What the host pushes about the daemon, in `changed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "kebab-case")]
pub enum Change {
    Locked,
    Unlocked,
    /// Items or vaults changed: refetch what's shown.
    Items,
    /// The daemon stopped.
    Stopped,
    /// A daemon started after one stopped or none ran.
    Started,
}

impl Change {
    /// What the extension hears of a change in the daemon, if anything.
    pub fn of(change: &daemon::Change) -> Option<Self> {
        use daemon::Change as D;
        match change {
            D::Locked => Some(Self::Locked),
            D::Unlocked => Some(Self::Unlocked),
            D::Items { .. } | D::Vaults | D::Resync => Some(Self::Items),
            D::Stopping => Some(Self::Stopped),
            D::Watching
            | D::Devices { .. }
            | D::Activity
            | D::Health
            | D::Update
            | D::Activate { .. } => None,
        }
    }
}

/// Why a request was refused, in `error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Forbidden,
    /// The daemon is locked, not set up, or not running.
    Locked,
    NotFound,
    DomainMismatch,
    BadRequest,
    RateLimited,
    /// A passkey the registration excluded is already saved.
    Exists,
    /// A passkey ceremony stopped by `passkey-cancel`.
    Cancelled,
    /// A site's rules allow only weak generated passwords.
    Weak,
    Failed,
}

/// A login saved for the site, without values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    #[serde(rename = "ref")]
    pub login: String,
    pub vault: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub username: Option<String>,
    pub has_password: bool,
    pub has_totp: bool,
    pub urls: Vec<String>,
    /// A "Sign in with Google" login: the provider (a known id such as
    /// `google`, or a name), and the linked account's username or title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub sign_in: Option<SignIn>,
}

impl From<daemon::SiteLogin> for Account {
    fn from(l: daemon::SiteLogin) -> Self {
        Self {
            login: format_ref(&l.login),
            vault: l.vault,
            title: l.title,
            username: l.username,
            has_password: l.has_password,
            has_totp: l.has_otp,
            urls: l.urls,
            sign_in: l.sign_in,
        }
    }
}

/// An identity a form can be filled from: no values, only which fields it has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct FormIdentity {
    #[serde(rename = "ref")]
    pub item: String,
    pub vault: String,
    pub title: String,
    /// "Alex Mercer · 123 Main St, Brooklyn"; may be empty.
    pub summary: String,
    #[ts(type = "Array<IdentityField>")]
    pub fields: Vec<String>,
}

impl From<daemon::FormIdentity> for FormIdentity {
    fn from(i: daemon::FormIdentity) -> Self {
        Self {
            item: format_ref(&i.item),
            vault: i.vault,
            title: i.title,
            summary: i.summary,
            fields: i.fields,
        }
    }
}

/// A card a form can be filled from: never its number or code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct FormCard {
    #[serde(rename = "ref")]
    pub item: String,
    pub vault: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub brand: Option<String>,
    pub last4: String,
    /// `YYYY-MM`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub expiry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub cardholder: Option<String>,
    /// The ref of the identity whose address is its billing address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub billing: Option<String>,
    #[ts(type = "Array<CardField>")]
    pub fields: Vec<String>,
}

impl From<daemon::FormCard> for FormCard {
    fn from(c: daemon::FormCard) -> Self {
        Self {
            item: format_ref(&c.item),
            vault: c.vault,
            title: c.title,
            brand: c.brand,
            last4: c.last4,
            expiry: c.expiry,
            cardholder: c.cardholder,
            billing: c.billing.as_ref().map(format_ref),
            fields: c.fields,
        }
    }
}

/// A login's ref as the extension holds it: `<vault id>:<item id>`.
pub fn format_ref(login: &LoginRef) -> String {
    format!("{}:{}", login.vault, login.item)
}
