//! The AutoFill requests and replies as Swift sees them, converted from and
//! to [`deadbolt_proto::daemon`]'s, which alone define the wire. Each
//! conversion names every field, so a change to the schema stops the build
//! here rather than reaching Swift as a missing value.

use deadbolt_proto::daemon as proto;
use zeroize::Zeroizing;

/// How macOS names the service asking for a fill
/// (`ASCredentialServiceIdentifier`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AutofillService {
    pub identifier: String,
    pub kind: AutofillServiceKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AutofillServiceKind {
    Domain,
    Url,
    /// An app bundle id with no web domain of its own.
    App,
}

/// One login: its vault's id and its item id, both lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Hash, uniffi::Record)]
pub struct LoginRef {
    pub vault: String,
    pub item: String,
}

/// A value a fill can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FillField {
    Username,
    Password,
    Totp,
}

/// An `ASPasswordCredentialIdentity`. Never a password.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasswordIdentity {
    pub domain: String,
    pub username: String,
    /// `<vault>:<item>` ([`login_ref_record_identifier`]).
    pub record_id: String,
    pub rank: i64,
}

/// An `ASPasskeyCredentialIdentity`. Never the private key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
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

/// An `ASOneTimeCodeCredentialIdentity`. Never the seed or a code.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OneTimeCodeIdentity {
    pub domain: String,
    pub label: String,
    pub record_id: String,
    pub rank: i64,
}

/// How a site is signed in to with another account ("Sign in with Google").
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignInInfo {
    pub provider: String,
    #[uniffi(default = None)]
    pub account: Option<String>,
}

/// A login saved for a site, without values.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SiteLogin {
    pub login: LoginRef,
    /// Its vault's name.
    pub vault: String,
    pub title: String,
    pub username: Option<String>,
    pub has_password: bool,
    #[uniffi(default = false)]
    pub has_otp: bool,
    #[uniffi(default = [])]
    pub urls: Vec<String>,
    #[uniffi(default = None)]
    pub sign_in: Option<SignInInfo>,
}

/// A passkey saved for a relying party, without its key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SitePasskey {
    pub passkey: LoginRef,
    pub vault: String,
    pub credential_id: String,
    pub username: Option<String>,
    /// `YYYY-MM-DD`.
    pub created: Option<String>,
}

/// What a fill asked for and the login has.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct SiteValues {
    #[uniffi(default = None)]
    pub username: Option<String>,
    #[uniffi(default = None)]
    pub password: Option<String>,
    #[uniffi(default = None)]
    pub totp: Option<String>,
}

impl std::fmt::Debug for SiteValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SiteValues")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// A request the extension sends.
#[derive(Clone, PartialEq, Eq, uniffi::Enum)]
pub enum AutofillCommand {
    /// Unlocks with the passphrase. Sent only to a daemon whose code
    /// checked out.
    Unlock { passphrase: String },
    /// Unlocks with Touch ID; cancelling the call dismisses the sheet.
    UnlockBiometric,
    /// Lock and Touch ID status, and the identities' hash when unlocked.
    AutofillStatus,
    /// Every identity for `ASCredentialIdentityStore`, without secrets.
    AutofillIdentities,
    /// The logins (and passkeys, with `rp_id`) a picker may show for
    /// `services`, most specific first; empty for an unassociated app.
    AutofillList {
        services: Vec<AutofillService>,
        #[uniffi(default = None)]
        rp_id: Option<String>,
        #[uniffi(default = [])]
        allowed_credentials: Vec<String>,
        #[uniffi(default = false)]
        for_otp: bool,
    },
    /// The values `want` names of `login` for `service` (`None` only
    /// when the user picked it for an unassociated app). Not `interactive`,
    /// it never raises Touch ID.
    AutofillFill {
        service: Option<AutofillService>,
        login: LoginRef,
        want: Vec<FillField>,
        interactive: bool,
    },
}

impl std::fmt::Debug for AutofillCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.clone().into_proto().name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AutofillStatusReply {
    pub initialized: bool,
    pub unlocked: bool,
    pub touch_id_ready: bool,
    #[uniffi(default = false)]
    pub touch_id_reset: bool,
    #[uniffi(default = false)]
    pub can_verify: bool,
    #[uniffi(default = None)]
    pub identities_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AutofillIdentitiesReply {
    pub identities_hash: String,
    pub passwords: Vec<PasswordIdentity>,
    #[uniffi(default = [])]
    pub passkeys: Vec<PasskeyIdentity>,
    #[uniffi(default = [])]
    pub one_time_codes: Vec<OneTimeCodeIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AutofillListReply {
    pub logins: Vec<SiteLogin>,
    #[uniffi(default = [])]
    pub passkeys: Vec<SitePasskey>,
    #[uniffi(default = false)]
    pub unassociated: bool,
    #[uniffi(default = false)]
    pub can_verify: bool,
    pub identities_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AutofillFillReply {
    pub values: SiteValues,
    pub identities_hash: String,
}

/// The daemon's answer to an [`AutofillCommand`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum AutofillReply {
    Done,
    AutofillStatus(AutofillStatusReply),
    AutofillIdentities(AutofillIdentitiesReply),
    AutofillList(AutofillListReply),
    AutofillFill(AutofillFillReply),
}

/// Why the daemon refused a request ([`proto::ErrorCode`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DaemonErrorCode {
    Locked,
    NotInitialized,
    NotFound,
    DomainMismatch,
    Exists,
    Version,
    Weak,
    Forbidden,
    RateLimited,
    InteractionRequired,
    Cancelled,
    Failed,
}

/// Why a call failed. Swift throws it (`UnixSocketDaemonClient`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum DaemonCallError {
    /// No daemon answered: none runs, or the socket isn't there.
    DaemonUnavailable {
        reason: String,
    },
    TimedOut,
    /// The call's [`crate::CallHandle`] was cancelled.
    Cancelled,
    /// The socket's peer isn't Deadbolt's daemon, so nothing was sent.
    PeerRejected {
        reason: String,
    },
    InvalidResponse {
        reason: String,
    },
    /// The daemon refused the request.
    DaemonError {
        code: DaemonErrorCode,
        message: String,
    },
}

impl AutofillCommand {
    pub(crate) fn into_proto(self) -> proto::Command {
        match self {
            Self::Unlock { passphrase } => proto::Command::Unlock {
                passphrase: Zeroizing::new(passphrase),
                timeout_secs: None,
            },
            Self::UnlockBiometric => proto::Command::UnlockBiometric { timeout_secs: None },
            Self::AutofillStatus => proto::Command::AutofillStatus,
            Self::AutofillIdentities => proto::Command::AutofillIdentities,
            Self::AutofillList {
                services,
                rp_id,
                allowed_credentials,
                for_otp,
            } => proto::Command::AutofillList {
                services: services.into_iter().map(Into::into).collect(),
                rp_id,
                allowed_credentials,
                for_otp,
            },
            Self::AutofillFill {
                service,
                login,
                want,
                interactive,
            } => proto::Command::AutofillFill {
                service: service.map(Into::into),
                login: login.into(),
                want: want.into_iter().map(Into::into).collect(),
                interactive,
            },
        }
    }
}

impl From<AutofillService> for proto::AutofillService {
    fn from(AutofillService { identifier, kind }: AutofillService) -> Self {
        Self {
            identifier,
            kind: match kind {
                AutofillServiceKind::Domain => proto::AutofillServiceKind::Domain,
                AutofillServiceKind::Url => proto::AutofillServiceKind::Url,
                AutofillServiceKind::App => proto::AutofillServiceKind::App,
            },
        }
    }
}

impl From<LoginRef> for proto::LoginRef {
    fn from(LoginRef { vault, item }: LoginRef) -> Self {
        Self { vault, item }
    }
}

impl From<proto::LoginRef> for LoginRef {
    fn from(proto::LoginRef { vault, item }: proto::LoginRef) -> Self {
        Self { vault, item }
    }
}

impl From<FillField> for proto::Fill {
    fn from(field: FillField) -> Self {
        match field {
            FillField::Username => Self::Username,
            FillField::Password => Self::Password,
            FillField::Totp => Self::Totp,
        }
    }
}

impl From<proto::ErrorCode> for DaemonErrorCode {
    fn from(code: proto::ErrorCode) -> Self {
        use proto::ErrorCode as C;
        match code {
            C::Locked => Self::Locked,
            C::NotInitialized => Self::NotInitialized,
            C::NotFound => Self::NotFound,
            C::DomainMismatch => Self::DomainMismatch,
            C::Exists => Self::Exists,
            C::Version => Self::Version,
            C::Weak => Self::Weak,
            C::Forbidden => Self::Forbidden,
            C::RateLimited => Self::RateLimited,
            C::InteractionRequired => Self::InteractionRequired,
            C::Cancelled => Self::Cancelled,
            C::Failed => Self::Failed,
        }
    }
}

fn site_login(login: proto::SiteLogin) -> SiteLogin {
    let proto::SiteLogin {
        login,
        vault,
        title,
        username,
        has_password,
        has_otp,
        urls,
        sign_in,
    } = login;
    SiteLogin {
        login: login.into(),
        vault,
        title,
        username,
        has_password,
        has_otp,
        urls,
        sign_in: sign_in
            .map(|proto::SignIn { provider, account }| SignInInfo { provider, account }),
    }
}

fn site_passkey(passkey: proto::SitePasskey) -> SitePasskey {
    let proto::SitePasskey {
        passkey,
        vault,
        credential_id,
        username,
        created,
    } = passkey;
    SitePasskey {
        passkey: passkey.into(),
        vault,
        credential_id,
        username,
        created,
    }
}

fn password_identity(identity: proto::PasswordIdentity) -> PasswordIdentity {
    let proto::PasswordIdentity {
        domain,
        username,
        record_id,
        rank,
    } = identity;
    PasswordIdentity {
        domain,
        username,
        record_id,
        rank,
    }
}

fn passkey_identity(identity: proto::PasskeyIdentity) -> PasskeyIdentity {
    let proto::PasskeyIdentity {
        rp_id,
        username,
        credential_id,
        user_handle,
        record_id,
        rank,
    } = identity;
    PasskeyIdentity {
        rp_id,
        username,
        credential_id,
        user_handle,
        record_id,
        rank,
    }
}

fn one_time_code_identity(identity: proto::OneTimeCodeIdentity) -> OneTimeCodeIdentity {
    let proto::OneTimeCodeIdentity {
        domain,
        label,
        record_id,
        rank,
    } = identity;
    OneTimeCodeIdentity {
        domain,
        label,
        record_id,
        rank,
    }
}

fn site_values(values: proto::SiteValues) -> SiteValues {
    let proto::SiteValues {
        username,
        password,
        totp,
    } = values;
    let expose = |secret: proto::Secret| secret.expose().to_owned();
    SiteValues {
        username,
        password: password.map(expose),
        totp: totp.map(expose),
    }
}

/// The extension's view of `reply`; `None` for a reply no AutoFill
/// request gets.
pub(crate) fn reply(reply: proto::Reply) -> Option<AutofillReply> {
    Some(match reply {
        proto::Reply::Done => AutofillReply::Done,
        proto::Reply::AutofillStatus {
            initialized,
            unlocked,
            touch_id_ready,
            touch_id_reset,
            can_verify,
            identities_hash,
        } => AutofillReply::AutofillStatus(AutofillStatusReply {
            initialized,
            unlocked,
            touch_id_ready,
            touch_id_reset,
            can_verify,
            identities_hash,
        }),
        proto::Reply::AutofillIdentities {
            identities_hash,
            passwords,
            passkeys,
            one_time_codes,
        } => AutofillReply::AutofillIdentities(AutofillIdentitiesReply {
            identities_hash,
            passwords: passwords.into_iter().map(password_identity).collect(),
            passkeys: passkeys.into_iter().map(passkey_identity).collect(),
            one_time_codes: one_time_codes
                .into_iter()
                .map(one_time_code_identity)
                .collect(),
        }),
        proto::Reply::AutofillList {
            logins,
            passkeys,
            unassociated,
            can_verify,
            identities_hash,
        } => AutofillReply::AutofillList(AutofillListReply {
            logins: logins.into_iter().map(site_login).collect(),
            passkeys: passkeys.into_iter().map(site_passkey).collect(),
            unassociated,
            can_verify,
            identities_hash,
        }),
        proto::Reply::AutofillFill {
            values,
            identities_hash,
        } => AutofillReply::AutofillFill(AutofillFillReply {
            values: site_values(values),
            identities_hash,
        }),
        _ => return None,
    })
}

/// `login` as an `ASCredentialIdentityStore` record identifier,
/// `<vault>:<item>`.
#[uniffi::export]
pub fn login_ref_record_identifier(login: LoginRef) -> String {
    format!("{}:{}", login.vault, login.item)
}

/// The login a record identifier names: 64 hex digits of vault id, `:`,
/// 32 of item id, read as lowercase. `None` for anything else.
#[uniffi::export]
pub fn login_ref_from_record_identifier(raw: String) -> Option<LoginRef> {
    let (vault, item) = raw.split_once(':')?;
    let hex = |s: &str, len| s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit());
    (hex(vault, 64) && hex(item, 32)).then(|| LoginRef {
        vault: vault.to_ascii_lowercase(),
        item: item.to_ascii_lowercase(),
    })
}

/// The AutoFill socket's name in the App Group container.
#[uniffi::export]
pub fn autofill_socket_name() -> String {
    proto::AUTOFILL_SOCKET.to_owned()
}

/// This process's Deadbolt App Group (`<team>.anomaly.deadbolt`), when its
/// own Apple-anchored signature is entitled to it; `None` for an ad-hoc
/// build, whose container macOS would prompt for.
#[uniffi::export]
pub fn own_app_group() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        deadbolt_client::peer::macos::own_app_group()
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_identifiers_are_vault_and_item_hex() {
        let vault = "Ab".repeat(32);
        let item = "0F".repeat(16);
        let login = login_ref_from_record_identifier(format!("{vault}:{item}")).unwrap();
        assert_eq!(login.vault, vault.to_ascii_lowercase());
        assert_eq!(login.item, item.to_ascii_lowercase());
        assert_eq!(
            login_ref_record_identifier(login.clone()),
            format!("{}:{}", login.vault, login.item)
        );
        for bad in [
            "short:id".to_owned(),
            "a".repeat(97),
            format!("{}:{}", "z".repeat(64), "0".repeat(32)),
            format!("{}:{}", "a".repeat(63), "0".repeat(33)),
            format!("{}:{}:", "a".repeat(64), "0".repeat(32)),
        ] {
            assert_eq!(login_ref_from_record_identifier(bad.clone()), None, "{bad}");
        }
    }

    /// Commands reach the wire in the daemon's own schema, the passphrase
    /// in a buffer wiped on drop.
    #[test]
    fn commands_are_the_daemons_own() {
        let list = AutofillCommand::AutofillList {
            services: vec![AutofillService {
                identifier: "github.com".into(),
                kind: AutofillServiceKind::Domain,
            }],
            rp_id: None,
            allowed_credentials: Vec::new(),
            for_otp: false,
        };
        let json = serde_json::to_value(list.into_proto()).unwrap();
        assert_eq!(json["cmd"], "autofill-list");
        assert_eq!(json["services"][0]["kind"], "domain");

        let unlock = AutofillCommand::Unlock {
            passphrase: "hunter22".into(),
        };
        assert_eq!(format!("{unlock:?}"), "unlock");
        let unlock = unlock.into_proto();
        assert!(unlock.carries_client_secret());
        assert!(
            !AutofillCommand::UnlockBiometric
                .into_proto()
                .carries_client_secret()
        );
    }

    #[test]
    fn fills_carry_their_values_but_never_print_them() {
        let message: proto::Message = serde_json::from_str(
            r#"{"type":"ok","reply":{"reply":"autofill-fill","values":{"username":"alex","password":"hunter22"},"identities_hash":"h"}}"#,
        )
        .unwrap();
        let proto::Message::Ok { reply: fill } = message else {
            panic!("not ok");
        };
        let Some(AutofillReply::AutofillFill(fill)) = reply(fill) else {
            panic!("not a fill");
        };
        assert_eq!(fill.values.password.as_deref(), Some("hunter22"));
        assert_eq!(fill.values.username.as_deref(), Some("alex"));
        assert!(!format!("{fill:?}").contains("hunter22"));
        assert_eq!(reply(proto::Reply::Activated), None);
    }
}
