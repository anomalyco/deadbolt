//! What a client asks the daemon to do: the `Request` the daemon reads
//! whatever its version, and the `Command` it carries.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    AppAction, AutofillService, Claim, ClientAuth, ExportFile, FieldInput, Fill, FindingKind,
    FormKind, LoginRef, PagePassword, Purpose, Secret, SiteField, SshKeyKind, Verify,
};

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
    /// Streams [`crate::protocol::Change`]s until the client hangs up or the
    /// daemon stops.
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
    /// (default: the daemon's hostname) applies only then.
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
    /// [`crate::export`]); the daemon detects the format. Items already in the
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
    /// the daemon runs: from every vault of `account` (`op`'s default
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
    /// `site-save` names it, it expires or the daemon locks. Replies
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
    /// Browser autofill: links the site at `origin` to `account`, a provider
    /// login it just signed in with: a new login at `url` (on its site), in
    /// `account`'s own vault, that signs in with `provider` through
    /// `account`, with no password of its own. Refused unless `provider` is a
    /// known one and `account` is a login saved at its sign-in host; an
    /// existing link is returned instead of a second (`created: false`).
    /// Replies `site-saved`.
    SiteLink {
        origin: String,
        title: String,
        url: String,
        provider: String,
        account: LoginRef,
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
    /// client data the daemon builds from `origin`. Verifies the user with
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
    /// data the daemon builds from `origin`. Verifies the user as
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
    /// Forms: the values of `fields` (see
    /// [`crate::protocol::IDENTITY_FORM_FIELDS`] and
    /// [`crate::protocol::CARD_FORM_FIELDS`]) that the identity or card `item`
    /// has, for the
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
    /// content key the daemon never sees, to receivers that prove `secret`
    /// (64 hex digits), `opens` times (at least 1) for `ttl_secs`. Shares
    /// live in the daemon's memory and end when it stops; they need no
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
    /// Every share this daemon serves or served; replies `sends`.
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
    /// Touch ID raised by the daemon, or `passphrase`, which the CLI reads
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
    /// [`crate::protocol::Reference`]), for `purpose`. Each item is a title or
    /// short id that
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
    /// Generates a new SSH key pair (`ed25519` or `ecdsa-p256`) inside the
    /// daemon without writing to a vault yet; needs no unlock. Replies
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
