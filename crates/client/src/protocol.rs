//! The control protocol between the CLI and the daemon.
//!
//! Line-delimited JSON over the daemon's Unix socket, one request per
//! connection:
//!
//! ```text
//! client -> daemon  Request   {"v":1,"cmd":"...",...}
//! daemon -> client  Message*  {"type":"event",...}         join only
//! client -> daemon  Answer    {"answer":true,"passphrase":"…"}   after an event that asks
//! daemon -> client  Message   {"type":"ok",...} | {"type":"error",...}   final
//! ```
//!
//! Only `joined` with `passphrase` set asks for an answer: the passphrase for a
//! device that isn't set up yet. A client hanging up cancels a pending
//! `join`/`pair`, and discards a joined vault still waiting for its passphrase.
//!
//! `watch` keeps the connection open and streams what changed:
//!
//! ```text
//! client -> daemon  Request   {"v":13,"cmd":"watch","app":false}
//! daemon -> client  Message*  {"type":"change","change":"watching"}   first
//!                             {"type":"change","change":"items","vault":"…"}
//! daemon -> client  Message   {"type":"ok","reply":{"reply":"done"}}   after "stopping"
//! ```
//!
//! Changes name what changed, never values: clients refetch. They are
//! coalesced, so a burst (a sync batch, an import) arrives as one change per
//! vault. A watcher that can't keep up gets `resync`, or is dropped if it
//! stops reading. The stream ends when the client hangs up or the daemon stops.
//!
//! The desktop app's main window watches with `app` set. `app-activate` (a
//! second launch) reaches the most recent such watcher as an `activate`
//! change, so the running app comes forward instead of a second one starting.
//!
//! `status` and `stop` are answered whatever `v` says, so a client can always
//! find and replace a daemon of an older protocol. They are the only messages
//! exchanged between different builds, so `Request` and `Status` must stay
//! readable by older and newer ones. `claimed` is left out when empty, so a
//! status request reads the same to every daemon.

mod agent;
mod caller;
mod command;
mod health;
mod items;
mod reference;
mod reports;
mod send;
mod site;
mod status;
mod wire;

#[cfg(test)]
mod tests;

pub use agent::{
    AgentClientInfo, AgentGrantInfo, AgentLogin, AgentPasskey, ClientAuth, NotGranted, Purpose,
    ResolvedSecret, SecretGrantInfo,
};
pub use caller::{
    ActivityEntry, ActivityItem, Ancestor, AppAction, CallerClass, CallerInfo, Check, Claim,
    Outcome, Signature, Tier, UNVERIFIED_LINUX,
};
pub use command::{Command, Request};
pub use health::{
    Finding, FindingKind, HealthCounts, HealthPeer, HealthReport, ItemHealth, PassphraseStrength,
    RiskLevel, WeakReason, audited_password_field, passphrase_strength,
};
pub use items::{
    CARD_FORM_FIELDS, CARD_VERIFIED_FIELDS, ExportFile, FieldInfo, FieldInput, FormCard,
    FormIdentity, FormKind, IDENTITY_FORM_FIELDS, ItemInfo, KINDS, SIGN_IN_PROVIDERS, SshKeyKind,
    TagCount, code_field, noun, primary_field, sign_in_name, sign_in_provider,
};
pub use reference::{Reference, SCHEME};
pub use reports::{
    Code, ImportReport, ImportSource, MirrorAction, MirrorItem, MirrorReport, SignInCounts, Tally,
};
pub use send::{SendInfo, SendState, SenderInfo};
pub use site::{
    AutofillService, AutofillServiceKind, Fill, LoginRef, OneTimeCodeIdentity, PagePassword,
    PasskeyIdentity, PasswordIdentity, SignIn, SiteField, SiteLogin, SitePasskey, SiteStatus,
    SiteValues, Verify,
};
pub use status::{DeviceInfo, PeerSync, Status, UpdateInfo, VaultInfo};
pub use wire::{Answer, Change, ErrorCode, Event, Message, Reply, Secret};

// `tests.rs` reads these through `super::*`.
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const PROTOCOL_VERSION: u32 = 28;

/// The longest line the daemon reads, large enough for `import` of a big export.
pub const MAX_LINE: usize = 64 * 1024 * 1024;

/// The longest line the daemon reads on the macOS AutoFill App Group socket.
pub const MAX_AUTOFILL_LINE: usize = 64 * 1024;
