//! The control protocol between the CLI and the agent.
//!
//! Line-delimited JSON over the agent's Unix socket, one request per
//! connection:
//!
//! ```text
//! client -> agent   Request   {"v":1,"cmd":"...",...}
//! agent  -> client  Message*  {"type":"event",...}         join only
//! client -> agent   Answer    {"answer":true,"passphrase":"…"}   after an event that asks
//! agent  -> client  Message   {"type":"ok",...} | {"type":"error",...}   final
//! ```
//!
//! Only `joined` with `passphrase` set asks for an answer: the passphrase for a
//! device that isn't set up yet. A client hanging up cancels a pending
//! `join`/`pair`, and discards a joined vault still waiting for its passphrase.
//!
//! `watch` keeps the connection open and streams what changed:
//!
//! ```text
//! client -> agent   Request   {"v":13,"cmd":"watch","app":false}
//! agent  -> client  Message*  {"type":"change","change":"watching"}   first
//!                             {"type":"change","change":"items","vault":"…"}
//! agent  -> client  Message   {"type":"ok","reply":{"reply":"done"}}   after "stopping"
//! ```
//!
//! Changes name what changed, never values: clients refetch. They are
//! coalesced, so a burst (a sync batch, an import) arrives as one change per
//! vault. A watcher that can't keep up gets `resync`, or is dropped if it
//! stops reading. The stream ends when the client hangs up or the agent stops.
//!
//! The desktop app's main window watches with `app` set. `app-activate` (a
//! second launch) reaches the most recent such watcher as an `activate`
//! change, so the running app comes forward instead of a second one starting.
//!
//! `status` and `stop` are answered whatever `v` says, so a client can always
//! find and replace an agent of an older protocol. They are the only messages
//! exchanged between different builds, so `Request` and `Status` must stay
//! readable by older and newer ones. `claimed` is left out when empty, so a
//! status request reads the same to every agent.

mod caller;
mod health;
mod reference;
mod reports;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub use caller::{
    ActivityEntry, ActivityItem, Ancestor, AppAction, CallerClass, CallerInfo, Check, Claim,
    Outcome, Signature, Tier, UNVERIFIED_LINUX,
};
pub use health::{
    Finding, FindingKind, HealthCounts, HealthPeer, HealthReport, ItemHealth, PassphraseStrength,
    RiskLevel, WeakReason, audited_password_field, passphrase_strength,
};
pub use reference::{Reference, SCHEME};
pub use reports::{
    Code, ImportReport, ImportSource, MirrorAction, MirrorItem, MirrorReport, SignInCounts, Tally,
};

pub const PROTOCOL_VERSION: u32 = 24;

/// The longest line the agent reads, large enough for `import` of a big export.
pub const MAX_LINE: usize = 64 * 1024 * 1024;

/// The longest line the agent reads on the macOS AutoFill App Group socket.
pub const MAX_AUTOFILL_LINE: usize = 64 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub v: u32,
    /// Who the client says it is acting for. Shown as claimed, never trusted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed: Option<Claim>,
    #[serde(flatten)]
    pub command: Command,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
pub enum Command {
    Status,
    Stop,
    /// First run: create the device key and store, leaving it unlocked.
    Setup {
        passphrase: Zeroizing<String>,
        device_name: String,
    },
    Unlock {
        passphrase: Zeroizing<String>,
        /// Idle timeout in seconds; `None` uses the config file, `Some(0)` never locks.
        timeout_secs: Option<u64>,
    },
    /// Unlocks the store with Touch ID using the enrolled biometric key set.
    UnlockBiometric {
        /// Idle timeout in seconds; `None` uses the config file, `Some(0)` never locks.
        timeout_secs: Option<u64>,
    },
    /// Turns Touch ID unlock on (requires the store unlocked) or off.
    TouchIdSet {
        enabled: bool,
    },
    Lock,
    /// Streams [`Change`]s until the client hangs up or the agent stops.
    /// `app` marks the desktop app's main window, which `app-activate`
    /// brings forward.
    Watch {
        app: bool,
    },
    /// Brings the running desktop app forward: an `activate` change with
    /// `token` (the launcher's `XDG_ACTIVATION_TOKEN` or `DESKTOP_STARTUP_ID`)
    /// to the most recent app watcher, replying `activated`. With none, it
    /// replies `no-app` and holds a short reservation for the app the caller
    /// is about to start: an `app-activate` during it waits for that app to
    /// watch, then activates it. Needs no unlock.
    AppActivate {
        token: Option<String>,
    },
    VaultCreate {
        name: String,
    },
    VaultList,
    VaultRename {
        vault: String,
        name: String,
    },
    VaultDefault {
        vault: String,
    },
    Devices {
        vault: Option<String>,
    },
    DeviceRemove {
        vault: Option<String>,
        device: String,
    },
    Sync {
        vault: Option<String>,
    },
    /// Emits `code`, then `joined` once paired, then replies `vault`. On a
    /// device that isn't set up, the device key and the vault stay in memory
    /// until the passphrase arrives: `passphrase` here, else the answer to
    /// `joined`. A `false` answer or hanging up discards them. `device_name`
    /// (default: the agent's hostname) applies only then.
    Join {
        device_name: Option<String>,
        passphrase: Option<Secret>,
    },
    /// Admits the device showing `code` into `vault`; replies `device`.
    Pair {
        code: String,
        vault: Option<String>,
    },
    /// Creates an item; replies `item`.
    ItemNew {
        vault: Option<String>,
        kind: String,
        name: Option<String>,
        fields: Vec<FieldInput>,
        #[serde(default)]
        favorite: bool,
        #[serde(default)]
        tags: Vec<String>,
    },
    /// Finds exactly one item, with its field values; replies `item`. One-time
    /// password secrets (fields of type otp) come back empty unless `otp`
    /// asks for them: a client that shows codes asks `ItemCode` instead.
    /// A file field (type file) comes back as its name alone unless `files`
    /// names it, for its contents too (`deadbolt_core::item::file_parts`):
    /// a client asks for the one file it needs, never all of an item's.
    /// With `deleted` it finds one of the deleted items instead, to show
    /// before restoring it.
    ItemGet {
        vault: Option<String>,
        query: Vec<String>,
        otp: bool,
        #[serde(default)]
        ssh_private: bool,
        #[serde(default)]
        files: Vec<String>,
        #[serde(default)]
        deleted: bool,
    },
    /// Finds exactly one item and computes its current one-time code from
    /// its code field (`code_field`); replies `code`. The secret itself
    /// never leaves. It doesn't count as use for the idle lock: a client
    /// showing a code asks once a period.
    ItemCode {
        vault: Option<String>,
        query: Vec<String>,
    },
    /// Lists matching items without field values; replies `items`. With
    /// `deleted`, the deleted items instead, newest first, each with when it
    /// was deleted.
    ItemList {
        vault: Option<String>,
        query: Vec<String>,
        kind: Option<String>,
        #[serde(default)]
        deleted: bool,
        #[serde(default)]
        tags: Vec<String>,
        #[serde(default)]
        favorites: bool,
    },
    /// Lists every tag in `vault` with how many items match it; replies `tags`.
    TagList {
        vault: Option<String>,
    },
    /// Sets fields, removes the `unset` ones, sets the name (`Some("")`
    /// clears it), stars/unstars (`favorite`), and/or adds/removes tags,
    /// all in one change; replies `item`.
    ItemSet {
        vault: Option<String>,
        query: Vec<String>,
        fields: Vec<FieldInput>,
        name: Option<String>,
        unset: Vec<String>,
        #[serde(default)]
        favorite: Option<bool>,
        #[serde(default)]
        add_tags: Vec<String>,
        #[serde(default)]
        remove_tags: Vec<String>,
    },
    ItemUnset {
        vault: Option<String>,
        query: Vec<String>,
        field: String,
    },
    /// Deletes the item. It stays in the vault, listed by `ItemList` with
    /// `deleted`, until `ItemRestore` brings it back.
    ItemRemove {
        vault: Option<String>,
        query: Vec<String>,
    },
    /// Brings back the one deleted item `query` matches, as it was when it
    /// was deleted; replies `item`.
    ItemRestore {
        vault: Option<String>,
        query: Vec<String>,
    },
    /// Imports another password manager's export (the text of the file, see
    /// [`crate::export`]); the agent detects the format. Items already in the
    /// vault, or earlier in the export, are skipped as duplicates. With
    /// `apply` it creates all new items or none, in as few entries as fit;
    /// without, it writes nothing. Replies `import`.
    /// A `.1pux`'s attachments come in `files` ([`crate::export`]).
    Import {
        vault: Option<String>,
        export: Zeroizing<String>,
        #[serde(default)]
        files: Vec<ExportFile>,
        apply: bool,
    },
    /// A new random password of `length` characters (8 to 256): letters and
    /// digits, and symbols if `symbols`, honoring `url`'s vendored site rules
    /// when given. Needs no unlock; replies `password`.
    Generate {
        length: usize,
        symbols: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
    },
    /// Mirrors 1Password into `vault` with the 1Password CLI (`op`), which
    /// the agent runs: from every vault of `account` (`op`'s default
    /// without one), or only the `op_vaults` named. Fails as `locked`
    /// before asking 1Password anything. With `dry_run` it writes nothing.
    /// Replies `mirror`.
    SyncOnePassword {
        vault: Option<String>,
        account: Option<String>,
        op_vaults: Vec<String>,
        dry_run: bool,
    },
    /// Browser autofill: the logins, in every vault, saved for the site of
    /// the web page at `origin`, without values; replies `site-logins`.
    /// Each carries only its URLs on that site. Doesn't count as use for the
    /// idle lock.
    SiteLogins {
        origin: String,
    },
    /// Browser autofill: the values `want` names of one login, refused
    /// (`domain-mismatch`) unless one of its URLs is on the site of
    /// `origin`. A one-time password comes as its current code, never its
    /// secret. Replies `site-fill`.
    SiteFill {
        origin: String,
        login: LoginRef,
        want: Vec<Fill>,
    },
    /// Browser autofill: whether `site-generate` would make a password for
    /// this field, without making one. Fails `weak` when the site's rules
    /// and the field allow only weak passwords, `failed` when they allow
    /// none. Doesn't count as use for the idle lock. Replies `done`.
    SiteGenerateCheck {
        origin: String,
        #[serde(flatten)]
        field: SiteField,
    },
    /// Browser autofill: a new password for a sign-up or change-password
    /// form on the page at `origin`, within the site's rules (Apple's
    /// password-manager-resources quirks, else the field's `passwordrules`)
    /// and the field's own limits, with at least 60 bits of entropy (else it
    /// fails `weak`). Nothing is saved: it's a candidate for `origin` until
    /// `site-generate-keep` says it went into the page, then pending until a
    /// `site-save` names it, it expires or the agent locks. Replies
    /// `site-generated`.
    SiteGenerate {
        origin: String,
        #[serde(flatten)]
        field: SiteField,
    },
    /// Browser autofill: the candidate `id` went into the page at `origin`;
    /// hold it as pending. Replies `done`.
    SiteGenerateKeep {
        origin: String,
        id: String,
    },
    /// Browser autofill: the candidate `id` didn't go into the page at
    /// `origin` (or no longer matters); forget it. Replies `done`.
    SiteGenerateDrop {
        origin: String,
        id: String,
    },
    /// Browser autofill: whether a login submitted on the page at `origin`
    /// is new, a changed password or already saved, revealing nothing;
    /// replies `site-check`. Without a username, logins with any username
    /// count, by password only. Doesn't count as use for the idle lock.
    SiteCheck {
        origin: String,
        username: Option<String>,
        password: PagePassword,
    },
    /// Browser autofill: saves a login submitted on the page at `origin`
    /// (`url` must be on its site): a new one in the default vault, or with
    /// `login` that login's new password, refused unless one of its URLs is
    /// on the site. A generated password saved is no longer pending.
    /// Replies `site-saved`.
    SiteSave {
        origin: String,
        login: Option<LoginRef>,
        title: String,
        url: String,
        username: String,
        password: PagePassword,
    },
    /// Passkeys: those in every vault for the relying party `rp_id` (the
    /// host of the page at `origin` when `None`), refused unless it is that
    /// host or a parent of it on the same site. Says whether a sign-in or
    /// registration now can verify the user (Touch ID). Replies `passkeys`.
    /// Doesn't count as use for the idle lock.
    PasskeyList {
        origin: String,
        rp_id: Option<String>,
    },
    /// Passkeys: makes a passkey for `rp_id` in the default vault, replacing
    /// one there for the same user, and returns the registration with
    /// client data the agent builds from `origin`. Verifies the user with
    /// Touch ID first unless `verify` is `discouraged`; `required` without
    /// Touch ID fails before anything is stored. Binary values are
    /// base64url. Replies `passkey-created`.
    PasskeyCreate {
        origin: String,
        rp_id: Option<String>,
        challenge: String,
        user_id: String,
        user_name: String,
        /// The WebAuthn `user.displayName`, kept beside the user name.
        #[serde(default)]
        user_display_name: String,
        /// Credential ids the site already has; one of them here fails it.
        exclude: Vec<String>,
        verify: Verify,
    },
    /// Passkeys: signs `challenge` with one passkey, refused
    /// (`domain-mismatch`) unless its relying party is `rp_id`, with client
    /// data the agent builds from `origin`. Verifies the user as
    /// `PasskeyCreate` does. Replies `passkey-assertion`.
    PasskeyGet {
        origin: String,
        rp_id: Option<String>,
        passkey: LoginRef,
        challenge: String,
        verify: Verify,
    },
    /// Forms: the identities and cards (`kinds`), in every vault, a form
    /// on the page at `origin` can be filled from, without values: an
    /// identity's summary, a card's brand, last four digits, expiry and
    /// cardholder, and which form fields each has. Not bound to a site: any
    /// page autofill takes (https; http only on a local host), never a
    /// sandboxed or opaque frame (`null`). Doesn't count as use for the idle
    /// lock. Replies `form-items`.
    FormItems {
        origin: String,
        kinds: Vec<FormKind>,
    },
    /// Forms: the values of `fields` (see [`IDENTITY_FORM_FIELDS`] and
    /// [`CARD_FORM_FIELDS`]) that the identity or card `item` has, for the
    /// page at `origin` (the same origin rules as `form-items`). A card's
    /// number or security code (`cvv`) verifies the user each time: Touch ID
    /// when it is on and enrolled, else the pick in the browser counts.
    /// Replies `form-fill`.
    FormFill {
        origin: String,
        item: LoginRef,
        fields: Vec<String>,
    },
    /// Deadbolt Send: serves `sealed`, a bundle the client sealed with a
    /// content key the agent never sees, to receivers that prove `secret`
    /// (64 hex digits), `opens` times (at least 1) for `ttl_secs`. Shares
    /// live in the agent's memory and end when it stops; they need no
    /// unlock. Replies `send-created`.
    SendCreate {
        secret: Secret,
        /// Base64 (standard, padded).
        sealed: String,
        opens: u32,
        ttl_secs: u64,
        /// What the sender sees in `send-list`.
        label: String,
    },
    /// Every share this agent serves or served; replies `sends`.
    SendList,
    /// One share, by id or unique id prefix; replies `send`.
    SendShow {
        id: String,
    },
    /// Stops a share being opened; replies `send`.
    SendRevoke {
        id: String,
    },
    /// Waits until a share is picked up, expires or is revoked; replies
    /// `send`. Doesn't hold the store unlocked.
    SendWait {
        id: String,
    },
    /// What callers did, newest first: entries at or after `since` (Unix
    /// seconds) with ids before `before`, at most `limit` (default 500, at
    /// most 1000; page back with the last id). Never an entry itself.
    /// Replies `activity`.
    ActivityList {
        since: Option<u64>,
        limit: Option<u32>,
        #[serde(default)]
        before: Option<u64>,
    },
    /// The app showed or copied `field` of the item `item` (its id, titled
    /// `title`), which it reports for Activity. Only from Deadbolt.app.
    /// Replies `done`.
    ActivityReport {
        action: AppAction,
        vault: Option<String>,
        item: String,
        title: String,
        field: String,
    },
    /// Agent sign-ins (`docs/agent-control.md`, "Standing grants"): pairs a
    /// new agent client, such as Browse's relay, and replies
    /// `agent-client-added` with its token, shown once. Needs the user:
    /// Touch ID raised by the agent, or `passphrase`, which the CLI reads
    /// from the terminal or `--passphrase-stdin`, never the environment.
    /// Refused (`forbidden`) to a caller Deadbolt takes for an AI.
    AgentClientAdd {
        name: String,
        passphrase: Option<Zeroizing<String>>,
    },
    /// The paired agent clients; replies `agent-clients`.
    AgentClientList,
    /// Unpairs a client and drops its grants; replies `done`.
    AgentClientRemove {
        id: String,
    },
    /// Lets `client_id` fill `fields` of the logins on `site` (a
    /// registrable domain, or an exact origin with its scheme; `None` for
    /// every site), or only of `login` (a login's id, short id, title or
    /// username on that site), and sign in with that site's passkeys if
    /// `passkeys`, until `expires_at` (Unix seconds; `None` never). A login
    /// still fills only on the site of one of its URLs. Needs the user as
    /// `AgentClientAdd` does, and refuses AIs the same way. Replies
    /// `agent-grant`.
    AgentGrantSet {
        client_id: String,
        site: Option<String>,
        login: Option<String>,
        fields: Vec<Fill>,
        passkeys: bool,
        expires_at: Option<u64>,
        passphrase: Option<Zeroizing<String>>,
    },
    /// Every grant, expired ones too; replies `agent-grants`.
    AgentGrantList,
    /// Removes a grant, a sign-in or a secret grant; replies `done`.
    AgentGrantRemove {
        id: String,
    },
    /// From a paired client: the logins on the site of the page at
    /// `origin`, without values, and what its grants cover of each;
    /// replies `agent-logins`. Empty, with `granted` false, when no live
    /// grant of the client covers the site.
    AgentLogins {
        client: ClientAuth,
        origin: String,
    },
    /// From a paired client: the values `want` names of `login` for the
    /// frame at `origin`, only if live grants cover the client, the site,
    /// the login and every wanted field (else `not-granted` naming the site
    /// and login), and one of the login's URLs is on the site (else
    /// `domain-mismatch`). A one-time password comes as its current code.
    /// Replies `site-fill`.
    AgentFill {
        client: ClientAuth,
        origin: String,
        login: LoginRef,
        want: Vec<Fill>,
    },
    /// From a paired client: signs `challenge` with a passkey for `rp_id`
    /// (the host of `origin` when `None`) that a live grant with
    /// `passkeys` covers: `login` (a passkey ref from `agent-logins`), else
    /// the only covered one among `allow_credentials` (all of the site's
    /// when empty); with several, fails `choose-passkey` listing them.
    /// Client data is built from `origin`. User presence is set (the grant
    /// is the user's standing consent), user verification never, so
    /// `required` fails. Replies `passkey-assertion` with `verified` false.
    AgentPasskeyGet {
        client: ClientAuth,
        origin: String,
        rp_id: Option<String>,
        #[serde(default)]
        login: Option<LoginRef>,
        challenge: String,
        #[serde(default)]
        allow_credentials: Vec<String>,
        user_verification: Verify,
    },
    /// Secrets for commands (`docs/agent-control.md`, "Use, don't read"):
    /// the values `refs` name (`deadbolt://[vault/]item/field`, see
    /// [`Reference`]), for `purpose`. Each item is a title or short id that
    /// must match exactly one item; a one-time password field gives its
    /// current code. A caller Deadbolt takes for an AI needs a live
    /// `secret-grant-set` grant covering every item, field and purpose for
    /// `run` and `inject` (else `not-granted`), and Touch ID each time for
    /// `read` (else `forbidden`). Replies `secrets`, in reference order.
    Resolve {
        refs: Vec<String>,
        purpose: Purpose,
    },
    /// Lets AI callers resolve `fields` (every field when empty) of the
    /// items `items` (titles or short ids in `vault`) for `purposes` (run,
    /// inject; never read) without asking, until `expires_at` (Unix seconds;
    /// `None` never). Setting the same item again replaces its grant. Needs
    /// the user as `AgentClientAdd` does, and refuses AIs the same way.
    /// Replies `secret-grants` with the grants made.
    SecretGrantSet {
        vault: Option<String>,
        items: Vec<String>,
        fields: Vec<String>,
        purposes: Vec<Purpose>,
        expires_at: Option<u64>,
        passphrase: Option<Zeroizing<String>>,
    },
    /// Every secret grant, expired ones too; replies `secret-grants`.
    /// `agent-grant-remove` removes them.
    SecretGrantList,
    /// macOS AutoFill (`docs/macos-autofill.md`): lock and Touch ID status
    /// plus `identities_hash` (when unlocked) so the extension knows whether
    /// `ASCredentialIdentityStore` needs a sync. Doesn't count as use for the
    /// idle lock.
    AutofillStatus,
    /// macOS AutoFill: every login, passkey and one-time-code identity for
    /// `ASCredentialIdentityStore`, without secrets, and `identities_hash`.
    /// Doesn't count as use for the idle lock.
    AutofillIdentities,
    /// macOS AutoFill: the logins (and passkeys when `rp_id` is set) a picker
    /// sheet may show for `services` (most specific first; empty for an
    /// unassociated native app). Doesn't count as use for the idle lock.
    AutofillList {
        services: Vec<AutofillService>,
        #[serde(default)]
        rp_id: Option<String>,
        #[serde(default)]
        allowed_credentials: Vec<String>,
        #[serde(default)]
        for_otp: bool,
    },
    /// macOS AutoFill: the values `want` names of `login` for `service`
    /// (`None` only when the user picked manually for an unassociated app).
    /// With `interactive` false (`provideCredentialWithoutUserInteraction`),
    /// never raises Touch ID and fails `locked` or `interaction-required`
    /// when user interaction is needed.
    AutofillFill {
        service: Option<AutofillService>,
        login: LoginRef,
        want: Vec<Fill>,
        interactive: bool,
    },
    /// macOS AutoFill: signs the 32-byte `client_data_hash` (base64url) with
    /// `passkey` for `rp_id`. With `interactive` true while locked and Touch
    /// ID ready, one Touch ID tap both unlocks the store and sets `UV = 1`.
    AutofillPasskeyGet {
        rp_id: String,
        passkey: LoginRef,
        client_data_hash: String,
        verify: Verify,
        interactive: bool,
    },
    /// macOS AutoFill: registers an ES256 passkey in the default vault for
    /// `rp_id` with the 32-byte `client_data_hash` (base64url).
    AutofillPasskeyCreate {
        rp_id: String,
        client_data_hash: String,
        user_id: String,
        user_name: String,
        #[serde(default)]
        user_display_name: String,
        exclude: Vec<String>,
        verify: Verify,
        interactive: bool,
    },
    /// Password health findings and summary counts for `vault` (`None` uses the
    /// default vault; `Some("*")` includes every unlocked vault), never values
    /// or hashes. With `online`, runs a Have I Been Pwned range check first.
    /// Refused to AI callers. Replies `health`.
    Health {
        vault: Option<String>,
        #[serde(default)]
        online: bool,
    },
    /// Ignores (`ignored = true`) or restores (`false`) `kind` on the item
    /// matching `query` in `vault`, syncing the dismissal across devices.
    /// Refused to AI callers. Replies `health`.
    HealthIgnore {
        vault: Option<String>,
        query: Vec<String>,
        kind: FindingKind,
        ignored: bool,
    },
    /// Enables or disables opt-in Have I Been Pwned breach checks in
    /// `config.toml`. Refused to AI callers. Replies `done`.
    BreachChecksSet {
        enabled: bool,
    },
    /// Turns the SSH agent listener (`ssh.sock`) on or off in `config.toml`
    /// and binds or drops the socket immediately. Replies `done`.
    SshAgentSet {
        enabled: bool,
    },
    /// Generates a new SSH key pair (`ed25519` or `ecdsa-p256`) inside the
    /// agent without writing to a vault yet; needs no unlock. Replies
    /// `ssh-generated`.
    SshGenerate {
        kind: SshKeyKind,
        comment: Option<String>,
    },
    /// Parses and normalizes an imported SSH private key file (decrypting with
    /// `passphrase` when encrypted) into unencrypted OpenSSH PEM and derived
    /// metadata without writing to a vault yet; needs no unlock. Replies
    /// `ssh-generated`.
    SshInspect {
        private_key: Secret,
        passphrase: Option<Secret>,
        comment: Option<String>,
    },
    /// Signs `data` (standard base64 of raw bytes) in the OpenSSH `SSHSIG`
    /// format (`ssh-keygen -Y sign`) using the vault's SSH key matching
    /// `public_key`, approving with Touch ID (and unlocking with the same tap
    /// when `touch_id_ready` is true). Replies `ssh-signature`.
    SshSign {
        public_key: String,
        namespace: String,
        data: String,
    },
}

impl Command {
    /// Whether the request carries the vault passphrase, so the client must
    /// check who it is talking to before sending it.
    pub fn carries_passphrase(&self) -> bool {
        match self {
            // A join asks for one if the device isn't set up.
            Self::Setup { .. } | Self::Unlock { .. } | Self::Join { .. } => true,
            Self::AgentClientAdd { passphrase, .. }
            | Self::AgentGrantSet { passphrase, .. }
            | Self::SecretGrantSet { passphrase, .. } => passphrase.is_some(),
            _ => false,
        }
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SshKeyKind {
    Ed25519,
    EcdsaP256,
}

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
/// and the token `agent-client-add` gave it (64 hex digits). The agent keeps
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
/// one `site-generate` made for the page's origin, by its id, which the agent
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
    /// The provider's id (`google`, see [`SIGN_IN_PROVIDERS`]) or, for one
    /// this version doesn't know, its name as given.
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

/// The kinds of item forms fill from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FormKind {
    Identity,
    Card,
}

impl FormKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Card => "card",
        }
    }
}

pub use deadbolt_core::forms::{CARD_FORM_FIELDS, CARD_VERIFIED_FIELDS, IDENTITY_FORM_FIELDS};
pub use deadbolt_core::listing::{
    KINDS, SIGN_IN_PROVIDERS, noun, primary_field, sign_in_name, sign_in_provider,
};

/// An identity a form can be filled from, without values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormIdentity {
    pub item: LoginRef,
    /// The name of its vault.
    pub vault: String,
    pub title: String,
    /// Who and where: "Kit Langton · 123 Main St, Brooklyn". May be empty.
    pub summary: String,
    /// The form fields it has a value for.
    pub fields: Vec<String>,
}

/// A card a form can be filled from, without its number or code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormCard {
    pub item: LoginRef,
    pub vault: String,
    pub title: String,
    pub brand: Option<String>,
    pub last4: String,
    /// `YYYY-MM`.
    pub expiry: Option<String>,
    pub cardholder: Option<String>,
    /// Its billing address's identity, if that is in one of the vaults here.
    pub billing: Option<LoginRef>,
    pub fields: Vec<String>,
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

/// A file from an export, beside its text: a `.1pux`'s attachment, named
/// as in the archive's `files/` (`<documentId>__<fileName>`), its contents
/// in base64. `too_large` (and no contents) for one over the cap or past
/// what fits in the request, so the agent can say why it's left out. Wiped
/// on drop; Debug leaves out the contents.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ExportFile {
    pub name: String,
    pub data: String,
    #[serde(default)]
    pub too_large: bool,
}

impl std::fmt::Debug for ExportFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportFile")
            .field("name", &self.name)
            .field("data", &"<redacted>")
            .finish()
    }
}

/// A field as typed by the user. Without `kind`, the agent uses the item
/// type's field type, else the field's current type, else `text`. Wiped on
/// drop; Debug leaves out the value.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct FieldInput {
    pub name: String,
    pub kind: Option<String>,
    pub value: String,
}

impl std::fmt::Debug for FieldInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldInput")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("value", &"<redacted>")
            .finish()
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

/// What changed in the agent. Vaults are named by id.
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
    /// Changes were dropped because the watcher fell behind. Fetch everything.
    Resync,
    /// The agent is stopping, which locks the store. The stream ends.
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
        /// How receivers reach the agent's send endpoint.
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
    SshSignature {
        /// PEM-armored `-----BEGIN SSH SIGNATURE-----` block.
        signature: String,
    },
}

/// A Deadbolt Send share, as its sender sees it. Never its secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendInfo {
    pub id: String,
    pub label: String,
    /// Sealed bytes.
    pub size: u64,
    /// Unix seconds.
    pub created: u64,
    pub expires: u64,
    /// How many times it may be opened.
    pub opens: u32,
    /// When each open happened, Unix seconds.
    pub opened: Vec<u64>,
    pub revoked: Option<u64>,
    pub state: SendState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SendState {
    Open,
    PickedUp,
    Expired,
    Revoked,
}

impl fmt::Display for SendState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::PickedUp => "picked up",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        })
    }
}

/// The address of the agent's send endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderInfo {
    /// The endpoint id, 64 hex digits: a key of its own, not the device's.
    pub id: String,
    pub relay_url: Option<String>,
    pub direct_addrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagCount {
    pub tag: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemInfo {
    pub id: String,
    /// Shortest unique id prefix, at least 4 characters.
    pub short: String,
    pub kind: String,
    /// The name, or one derived from the fields.
    pub label: String,
    /// What the item is, if anything says: a login's username (else "Sign
    /// in with Google" for one that signs in with another account), a card's
    /// expiry, an SSH key's comment or fingerprint, an identity's email or
    /// phone. Never a secure note's body.
    pub detail: Option<String>,
    /// Known fields in schema order, then extra fields by name. Empty in lists.
    pub fields: Vec<FieldInfo>,
    /// The app the item is mirrored from ("1Password"), which overwrites
    /// changes made here; `None` for the user's own.
    pub source: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    /// When a deleted item was deleted (seconds since the Unix epoch, on
    /// the deleting device's clock), in `ItemList` with `deleted`. `None`
    /// for live items, and for deletes from before deletes were timed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<u64>,
}

/// The field an item's one-time code comes from, as the agent picks it:
/// `otp`, else the first field of type otp.
pub fn code_field(fields: &[FieldInfo]) -> Option<usize> {
    let otp = |f: &FieldInfo| f.kind == "otp";
    fields
        .iter()
        .position(|f| f.name == "otp" && otp(f))
        .or_else(|| fields.iter().position(otp))
}

/// Wiped on drop; Debug leaves out the value.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct FieldInfo {
    pub name: String,
    pub kind: String,
    pub value: String,
}

impl std::fmt::Debug for FieldInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldInfo")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub pid: u32,
    pub version: String,
    pub protocol: u32,
    /// The agent's executable, so a client that can't use it can say which one runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// The store directory this agent serves.
    pub home: String,
    pub initialized: bool,
    pub unlocked: bool,
    /// Seconds until the idle timeout locks the store.
    pub locks_in_secs: Option<u64>,
    pub device: Option<DeviceInfo>,
    pub vaults: Vec<VaultInfo>,
    pub peers_online: usize,
    pub peers: usize,
    /// Whether this device has Touch ID hardware and an enrolled finger.
    pub touch_id_available: bool,
    /// Whether Touch ID unlock is turned on in config.toml.
    pub touch_id_enabled: bool,
    /// Whether the locked store can be unlocked with Touch ID right now.
    pub touch_id_ready: bool,
    /// Whether Touch ID is enabled on this store, but its enrolled slot was
    /// reset (expired after 14 days, fingerprint set changed, or passphrase changed).
    pub touch_id_reset: bool,
    /// Whether the SSH agent (`ssh.sock`) is turned on in config.toml.
    #[serde(default)]
    pub ssh_agent: bool,
    /// Where SSH clients reach this agent's SSH socket when `ssh_agent` is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_socket: Option<String>,
    /// How the agent sees the client asking (`deadbolt whoami`).
    pub caller: CallerInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultInfo {
    pub id: String,
    pub name: String,
    pub default: bool,
    pub members: usize,
    /// Whether this device is still a member.
    pub member: bool,
    /// Present when the history could not be loaded. Membership is unknown,
    /// `members` is zero, and the encrypted entries remain on disk.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: Option<String>,
    pub this: bool,
    pub connected: bool,
    /// Unix seconds of the last successful sync with this device.
    pub last_seen: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSync {
    pub device: DeviceInfo,
    pub sent: usize,
    pub received: usize,
    pub error: Option<String>,
}
