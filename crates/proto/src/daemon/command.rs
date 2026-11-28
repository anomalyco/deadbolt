//! What a client asks the daemon to do: the `Request` the daemon reads
//! whatever its version, and the `Command` it carries.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    AppAction, AutofillService, ExportFile, FieldInput, Fill, FindingKind, FormKind, LoginRef,
    PagePassword, Purpose, RemoteInput, Secret, SiteField, SshKeyKind, Verify,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub v: u32,
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
    /// Streams [`crate::daemon::Change`]s until the client hangs up or the
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
    /// Removes a device that was stolen: only its data frames written before
    /// `since_secs` (Unix seconds; `None` keeps them all) keep counting, and
    /// the removal is judged as of before the theft, so whoever it added
    /// gets no new key and whoever it removed does. Replies `device`.
    DeviceRemoveStolen {
        vault: Option<String>,
        device: String,
        #[serde(default)]
        since_secs: Option<u64>,
    },
    /// The person confirmed that `device`, removed and now back, belongs:
    /// the vault stops being parked on it. Replies `vault`.
    VaultConfirmReinstated {
        vault: Option<String>,
        device: String,
    },
    /// Each vault's state beyond `vault-list` (why it is parked, frames no
    /// key opens yet, its remote), or only `vault`'s. Replies `vault-states`.
    VaultStatus {
        vault: Option<String>,
    },
    /// Hands a vault's recovery root on to a new kit, given the current 24
    /// words. Replies `recovery-rotated` with the new words, shown once.
    RecoveryRotate {
        vault: Option<String>,
        words: Secret,
    },
    /// Sets the vault's blind remote. Replies `remote`.
    RemoteSet {
        vault: Option<String>,
        remote: RemoteInput,
    },
    /// Replies `remote`, redacted.
    RemoteShow {
        vault: Option<String>,
    },
    /// Pulls from and pushes to the vault's remote, then collects behind its
    /// checkpoints. Replies `remote-synced`.
    RemoteSync {
        vault: Option<String>,
    },
    /// Forgets the vault's remote and its credentials. Replies `remote`.
    RemoteRemove {
        vault: Option<String>,
    },
    /// Rebuilds vault `vault` (its id) on this unlocked device from its
    /// recovery kit and remote alone, adding this device and removing the
    /// lost ones. Replies `vault`.
    Recover {
        vault: String,
        words: Secret,
        remote: RemoteInput,
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
    /// `deadbolt_client::export`); the daemon detects the format. Items already in the
    /// vault, or earlier in the export, are skipped as duplicates. With
    /// `apply` it creates all new items or none, in as few entries as fit;
    /// without, it writes nothing. Replies `import`.
    /// A `.1pux`'s attachments come in `files` (`deadbolt_client::export`).
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
    /// Browser autofill: keeps `recipe`, a form the user taught it on the
    /// page at `origin` (`deadbolt_core::site_recipe`), on `login`, or with
    /// none clears the one it has. Refused unless one of the login's URLs is
    /// on the page's site itself and the recipe is for that exact origin.
    /// Replies `done`.
    SiteRecipe {
        origin: String,
        login: LoginRef,
        recipe: Option<String>,
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
    /// [`crate::daemon::IDENTITY_FORM_FIELDS`] and
    /// [`crate::daemon::CARD_FORM_FIELDS`]) that the identity or card `item`
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
    /// Secrets for commands: the values `refs` name
    /// (`deadbolt://[vault/]item/field`, see [`crate::daemon::Reference`]),
    /// for `purpose`. Each item is a title or short id that must match
    /// exactly one item; a one-time password field gives its current code.
    /// Replies `secrets`, in reference order.
    Resolve {
        refs: Vec<String>,
        purpose: Purpose,
    },
    /// macOS AutoFill (`docs/autofill.md`): lock and Touch ID status
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
    /// Replies `health`.
    Health {
        vault: Option<String>,
        #[serde(default)]
        online: bool,
    },
    /// Ignores (`ignored = true`) or restores (`false`) `kind` on the item
    /// matching `query` in `vault`, syncing the dismissal across devices.
    /// Replies `health`.
    HealthIgnore {
        vault: Option<String>,
        query: Vec<String>,
        kind: FindingKind,
        ignored: bool,
    },
    /// Enables or disables opt-in Have I Been Pwned breach checks in
    /// `config.toml`. Replies `done`.
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
    /// `deadbolt run`, about to start its command: registers the caller's
    /// own process, so it and everything it starts get nothing from the
    /// daemon. Replies `run-tainted` with the run id that ends it, which
    /// must never reach the command. Needs no unlock.
    RunTaint,
    /// Ends the run `run` (hex) names, once its command has exited.
    RunUntaint {
        run: Secret,
    },
}

/// What the daemon does around a command, decided for every command (see
/// [`Command::policy`]) so a new one doesn't compile until it says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Counts as use for the idle lock.
    pub keepalive: bool,
    /// Holds the daemon busy while it runs.
    pub busy: bool,
    /// Carries a secret of the client's, so the client must check who it is
    /// talking to before sending it.
    pub client_secret: bool,
}

impl Policy {
    /// Use, held while it runs.
    const USE: Self = Self {
        keepalive: true,
        busy: true,
        client_secret: false,
    };
    /// Use, carrying a client secret.
    const SECRET: Self = Self {
        client_secret: true,
        ..Self::USE
    };
    /// Held while it runs, but not use.
    const QUIET: Self = Self {
        keepalive: false,
        ..Self::USE
    };
    /// Neither use nor held.
    const IDLE: Self = Self {
        keepalive: false,
        busy: false,
        client_secret: false,
    };
}

impl Command {
    /// The command's [`Policy`].
    pub fn policy(&self) -> Policy {
        use Policy as P;
        match self {
            // Answered at once, or waiting on someone else: a send being
            // picked up, an app starting.
            Self::Status | Self::Stop | Self::SendWait { .. } | Self::AppActivate { .. } => P::IDLE,
            // The passphrase (a join asks for one if the device isn't set
            // up), the recovery kit, a remote's credentials, an export.
            Self::Setup { .. }
            | Self::Unlock { .. }
            | Self::Join { .. }
            | Self::RecoveryRotate { .. }
            | Self::RemoteSet { .. }
            | Self::Recover { .. }
            | Self::Import { .. } => P::SECRET,
            // An SSH private key, which never touches the vault.
            Self::SshInspect { .. } => Policy {
                client_secret: true,
                ..P::QUIET
            },
            // A one-time code isn't use: a client showing one asks every
            // period, which would otherwise hold the vault open for as long
            // as it shows. Nor is a browser or AutoFill looking at a page:
            // it asks for every page loaded. Nor are sends, which never
            // touch the vault, nor SSH key generation.
            Self::ItemCode { .. }
            | Self::SiteLogins { .. }
            | Self::SiteCheck { .. }
            | Self::FormItems { .. }
            | Self::PasskeyList { .. }
            | Self::SiteGenerateCheck { .. }
            | Self::SiteGenerateDrop { .. }
            | Self::AutofillStatus
            | Self::AutofillIdentities
            | Self::AutofillList { .. }
            | Self::SendCreate { .. }
            | Self::SendList
            | Self::SendShow { .. }
            | Self::SendRevoke { .. }
            | Self::SshGenerate { .. } => P::QUIET,
            Self::UnlockBiometric { .. }
            | Self::TouchIdSet { .. }
            | Self::Lock
            | Self::Watch { .. }
            | Self::VaultCreate { .. }
            | Self::VaultList
            | Self::VaultRename { .. }
            | Self::VaultDefault { .. }
            | Self::Devices { .. }
            | Self::DeviceRemove { .. }
            | Self::DeviceRemoveStolen { .. }
            | Self::VaultConfirmReinstated { .. }
            | Self::VaultStatus { .. }
            | Self::RemoteShow { .. }
            | Self::RemoteSync { .. }
            | Self::RemoteRemove { .. }
            | Self::Sync { .. }
            | Self::Pair { .. }
            | Self::ItemNew { .. }
            | Self::ItemGet { .. }
            | Self::ItemList { .. }
            | Self::TagList { .. }
            | Self::ItemSet { .. }
            | Self::ItemUnset { .. }
            | Self::ItemRemove { .. }
            | Self::ItemRestore { .. }
            | Self::Generate { .. }
            | Self::SiteFill { .. }
            | Self::SiteGenerate { .. }
            | Self::SiteGenerateKeep { .. }
            | Self::SiteSave { .. }
            | Self::SiteLink { .. }
            | Self::SiteRecipe { .. }
            | Self::PasskeyCreate { .. }
            | Self::PasskeyGet { .. }
            | Self::FormFill { .. }
            | Self::ActivityList { .. }
            | Self::ActivityReport { .. }
            | Self::Resolve { .. }
            | Self::AutofillFill { .. }
            | Self::AutofillPasskeyGet { .. }
            | Self::AutofillPasskeyCreate { .. }
            | Self::Health { .. }
            | Self::HealthIgnore { .. }
            | Self::BreachChecksSet { .. }
            | Self::RunTaint
            | Self::RunUntaint { .. } => P::USE,
        }
    }

    /// Whether the request carries a secret of the client's
    /// ([`Policy::client_secret`]).
    pub fn carries_client_secret(&self) -> bool {
        self.policy().client_secret
    }

    /// The command's wire name (its `cmd` tag), for logs and traces:
    /// fixed, so it never carries what the request does.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Stop => "stop",
            Self::Setup { .. } => "setup",
            Self::Unlock { .. } => "unlock",
            Self::UnlockBiometric { .. } => "unlock-biometric",
            Self::TouchIdSet { .. } => "touch-id-set",
            Self::Lock => "lock",
            Self::Watch { .. } => "watch",
            Self::AppActivate { .. } => "app-activate",
            Self::VaultCreate { .. } => "vault-create",
            Self::VaultList => "vault-list",
            Self::VaultRename { .. } => "vault-rename",
            Self::VaultDefault { .. } => "vault-default",
            Self::Devices { .. } => "devices",
            Self::DeviceRemove { .. } => "device-remove",
            Self::DeviceRemoveStolen { .. } => "device-remove-stolen",
            Self::VaultConfirmReinstated { .. } => "vault-confirm-reinstated",
            Self::VaultStatus { .. } => "vault-status",
            Self::RecoveryRotate { .. } => "recovery-rotate",
            Self::RemoteSet { .. } => "remote-set",
            Self::RemoteShow { .. } => "remote-show",
            Self::RemoteSync { .. } => "remote-sync",
            Self::RemoteRemove { .. } => "remote-remove",
            Self::Recover { .. } => "recover",
            Self::Sync { .. } => "sync",
            Self::Join { .. } => "join",
            Self::Pair { .. } => "pair",
            Self::ItemNew { .. } => "item-new",
            Self::ItemGet { .. } => "item-get",
            Self::ItemCode { .. } => "item-code",
            Self::ItemList { .. } => "item-list",
            Self::TagList { .. } => "tag-list",
            Self::ItemSet { .. } => "item-set",
            Self::ItemUnset { .. } => "item-unset",
            Self::ItemRemove { .. } => "item-remove",
            Self::ItemRestore { .. } => "item-restore",
            Self::Import { .. } => "import",
            Self::Generate { .. } => "generate",
            Self::SiteLogins { .. } => "site-logins",
            Self::SiteFill { .. } => "site-fill",
            Self::SiteGenerateCheck { .. } => "site-generate-check",
            Self::SiteGenerate { .. } => "site-generate",
            Self::SiteGenerateKeep { .. } => "site-generate-keep",
            Self::SiteGenerateDrop { .. } => "site-generate-drop",
            Self::SiteCheck { .. } => "site-check",
            Self::SiteSave { .. } => "site-save",
            Self::SiteLink { .. } => "site-link",
            Self::SiteRecipe { .. } => "site-recipe",
            Self::PasskeyList { .. } => "passkey-list",
            Self::PasskeyCreate { .. } => "passkey-create",
            Self::PasskeyGet { .. } => "passkey-get",
            Self::FormItems { .. } => "form-items",
            Self::FormFill { .. } => "form-fill",
            Self::SendCreate { .. } => "send-create",
            Self::SendList => "send-list",
            Self::SendShow { .. } => "send-show",
            Self::SendRevoke { .. } => "send-revoke",
            Self::SendWait { .. } => "send-wait",
            Self::ActivityList { .. } => "activity-list",
            Self::ActivityReport { .. } => "activity-report",
            Self::Resolve { .. } => "resolve",
            Self::AutofillStatus => "autofill-status",
            Self::AutofillIdentities => "autofill-identities",
            Self::AutofillList { .. } => "autofill-list",
            Self::AutofillFill { .. } => "autofill-fill",
            Self::AutofillPasskeyGet { .. } => "autofill-passkey-get",
            Self::AutofillPasskeyCreate { .. } => "autofill-passkey-create",
            Self::Health { .. } => "health",
            Self::HealthIgnore { .. } => "health-ignore",
            Self::BreachChecksSet { .. } => "breach-checks-set",
            Self::SshGenerate { .. } => "ssh-generate",
            Self::SshInspect { .. } => "ssh-inspect",
            Self::RunTaint => "run-taint",
            Self::RunUntaint { .. } => "run-untaint",
        }
    }
}
