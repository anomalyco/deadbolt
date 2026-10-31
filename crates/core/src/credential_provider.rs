//! Platform credential-provider rules shared by the macOS AutoFill backend
//! and the iOS credential provider: which web site an
//! `ASCredentialServiceIdentifier` names, which logins and passkeys the
//! picker offers and in what order, the secret-free identity snapshot for
//! `ASCredentialIdentityStore` and its digest, the values a fill returns,
//! and when a passkey ceremony needs user verification.
//!
//! Pure: callers supply the unlocked vault items, the per-record fill
//! history and the platform's verification capability, and map [`Error`]
//! to their own wire errors. Passkey signing and registration live in
//! [`crate::passkeys`].

use std::borrow::Borrow;
use std::cmp::Reverse;

use data_encoding::HEXLOWER;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::autofill::{self, otp, urls, value};
use crate::listing::label;
use crate::site::{self, Site};
use crate::totp::{Totp, TotpError};
use crate::{Item, ItemId, VaultId, webauthn};

/// The most allowed or excluded credential ids a passkey request may name.
pub const MAX_CREDENTIALS: usize = 64;
/// The most values one fill may ask for.
pub const MAX_FILL_FIELDS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A domain or URL service identifier that names no fillable site.
    #[error("{identifier}: {reason}")]
    InvalidService {
        identifier: String,
        reason: &'static str,
    },
    #[error("an app identifier has no web domain")]
    AppService,
    #[error("no valid service identifier")]
    NoService,
    #[error("a fill wants 1 to {MAX_FILL_FIELDS} fields")]
    FillFields,
    #[error("filling into an unassociated app requires confirmation")]
    UnassociatedApp,
    #[error("the one-time password of {label} is invalid: {error}")]
    InvalidTotp { label: String, error: TotpError },
    #[error("{rp_id}: {reason}")]
    InvalidRpId { rp_id: String, reason: &'static str },
    #[error("at most {MAX_CREDENTIALS} allowed credentials")]
    TooManyAllowed,
    #[error("at most {MAX_CREDENTIALS} excluded credentials")]
    TooManyExcluded,
    #[error("allowed credential id is not base64url")]
    AllowedNotBase64,
    /// The site requires user verification and this device can't verify.
    #[error("this site requires user verification, which is not available")]
    VerificationUnavailable,
    /// User verification is possible but only with an interactive prompt.
    #[error("user verification requires interactive presentation")]
    InteractionRequired,
}

/// The kind of an `ASCredentialServiceIdentifier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    Domain,
    Url,
    /// An app bundle id with no web domain of its own.
    App,
}

/// A web service a fill is for: its site, and the origin logins are ranked
/// against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedService {
    pub site: Site,
    pub origin: String,
}

/// The site a domain or URL service identifier names. An app identifier
/// has none.
pub fn resolve_service(kind: ServiceKind, identifier: &str) -> Result<ResolvedService, Error> {
    let invalid = |reason| Error::InvalidService {
        identifier: identifier.to_string(),
        reason,
    };
    match kind {
        ServiceKind::Domain => {
            let (site, origin) = Site::from_domain(identifier).map_err(invalid)?;
            Ok(ResolvedService { site, origin })
        }
        ServiceKind::Url => Ok(ResolvedService {
            site: Site::from_origin(identifier).map_err(invalid)?,
            origin: identifier.to_string(),
        }),
        ServiceKind::App => Err(Error::AppService),
    }
}

/// What a picker request is scoped to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// No web service was named (none, or only app identifiers): every
    /// login is offered.
    Unassociated,
    /// The named web services that resolved, in request order (earlier
    /// ones rank first).
    Services(Vec<ResolvedService>),
}

/// The scope of a picker request. App identifiers are ignored; when web
/// identifiers were named but none resolves, the first one's error.
pub fn scope<'a>(
    services: impl IntoIterator<Item = (ServiceKind, &'a str)>,
) -> Result<Scope, Error> {
    let mut named = false;
    let mut resolved = Vec::new();
    let mut first_err = None;
    for (kind, identifier) in services {
        if kind == ServiceKind::App {
            continue;
        }
        named = true;
        match resolve_service(kind, identifier) {
            Ok(service) => resolved.push(service),
            Err(err) => {
                first_err.get_or_insert(err);
            }
        }
    }
    if !named {
        return Ok(Scope::Unassociated);
    }
    if resolved.is_empty() {
        return Err(first_err.unwrap_or(Error::NoService));
    }
    Ok(Scope::Services(resolved))
}

/// The fill-history and identity-store key of an item: `vault:item`, both
/// lowercase hex.
pub fn record_id(vault: &VaultId, item: &ItemId) -> String {
    format!(
        "{}:{}",
        HEXLOWER.encode(vault.as_bytes()),
        HEXLOWER.encode(item.as_bytes())
    )
}

/// Whether a login can serve a password (or, with `for_otp`, a one-time
/// code) request.
pub fn usable(item: &Item, for_otp: bool) -> bool {
    if for_otp {
        otp(item).is_some_and(|f| !f.value.is_empty())
    } else {
        value(item, "password").is_some()
    }
}

/// A login the picker offers.
#[derive(Debug)]
pub struct Pick {
    pub vault: VaultId,
    pub item: Item,
    /// The index in [`Scope::Services`] of the service it was matched for;
    /// `None` when unassociated. Show only the login's URLs on that
    /// service's site.
    pub service: Option<usize>,
}

impl Scope {
    /// The resolved service at `index` of a scoped request.
    pub fn service(&self, index: usize) -> Option<&ResolvedService> {
        match self {
            Self::Unassociated => None,
            Self::Services(services) => services.get(index),
        }
    }
}

/// The logins among `items` (every item of every unlocked vault, consumed
/// one at a time; deleted ones are skipped) that the picker offers for
/// `scope`, best first. Only offered logins are kept. `used` gives a
/// record's last fill time (0 if never).
///
/// Unassociated: every usable login, most recently filled first, then
/// starred, title (case-insensitively), username, and record. Scoped: each
/// usable login on any service's site, under the earliest service it
/// matches, ordered by service, [`autofill::rank`] against that service's
/// origin, and record.
pub fn picker_logins(
    scope: &Scope,
    items: impl IntoIterator<Item = (VaultId, Item)>,
    used: impl Fn(&str) -> u64,
    for_otp: bool,
) -> Vec<Pick> {
    let live = items
        .into_iter()
        .filter(|(_, item)| !item.deleted && item.kind == "login" && usable(item, for_otp));
    let refs = |vault: &VaultId, item: &Item| {
        (
            HEXLOWER.encode(vault.as_bytes()),
            HEXLOWER.encode(item.id.as_bytes()),
        )
    };
    match scope {
        Scope::Unassociated => {
            let mut all: Vec<_> = live
                .map(|(vault, item)| {
                    let key = refs(&vault, &item);
                    let used = used(&format!("{}:{}", key.0, key.1));
                    let title = label(&item).to_lowercase();
                    let username = value(&item, "username").map(str::to_string);
                    let order = (Reverse(used), Reverse(item.favorite), title, username, key);
                    (
                        order,
                        Pick {
                            vault,
                            item,
                            service: None,
                        },
                    )
                })
                .collect();
            all.sort_by(|(a, _), (b, _)| a.cmp(b));
            all.into_iter().map(|(_, pick)| pick).collect()
        }
        Scope::Services(services) => {
            let mut ranked: Vec<_> = live
                .filter_map(|(vault, item)| {
                    let (idx, service) = services
                        .iter()
                        .enumerate()
                        .find(|(_, service)| service.site.matches(urls(&item)))?;
                    let key = refs(&vault, &item);
                    let rank = autofill::rank(
                        &service.origin,
                        &item,
                        used(&format!("{}:{}", key.0, key.1)),
                    );
                    Some((
                        (idx, rank, key),
                        Pick {
                            vault,
                            item,
                            service: Some(idx),
                        },
                    ))
                })
                .collect();
            ranked.sort_by(|(a, _), (b, _)| a.cmp(b));
            ranked.into_iter().map(|(_, pick)| pick).collect()
        }
    }
}

/// Validates a passkey picker request: the relying party id (normalized)
/// and the allowed credential ids.
pub fn passkey_request(rp_id: &str, allowed: &[String]) -> Result<String, Error> {
    let rp = valid_rp_id(rp_id)?;
    if allowed.len() > MAX_CREDENTIALS {
        return Err(Error::TooManyAllowed);
    }
    for cred in allowed {
        webauthn::unb64(cred).map_err(|_| Error::AllowedNotBase64)?;
    }
    Ok(rp)
}

/// A standalone relying party id, lowercased, or why it isn't one.
pub fn valid_rp_id(rp_id: &str) -> Result<String, Error> {
    site::valid_rp_id(rp_id).map_err(|reason| Error::InvalidRpId {
        rp_id: rp_id.to_string(),
        reason,
    })
}

/// Whether a passkey is among `allowed` credential ids (any, when empty).
pub fn allows(item: &Item, allowed: &[String]) -> bool {
    allowed.is_empty()
        || value(item, "credential-id").is_some_and(|id| allowed.iter().any(|c| c == id))
}

/// Refuses more than [`MAX_CREDENTIALS`] excluded credentials.
pub fn check_exclude(exclude: &[String]) -> Result<(), Error> {
    if exclude.len() > MAX_CREDENTIALS {
        return Err(Error::TooManyExcluded);
    }
    Ok(())
}

/// A value a fill can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    Username,
    Password,
    /// The current one-time code.
    Totp,
}

/// Checks a fill request and resolves its service. Without a service (an
/// app with no associated domain) the fill must be interactive and returns
/// `None`.
pub fn fill_target(
    want: &[Want],
    service: Option<(ServiceKind, &str)>,
    interactive: bool,
) -> Result<Option<ResolvedService>, Error> {
    if want.is_empty() || want.len() > MAX_FILL_FIELDS {
        return Err(Error::FillFields);
    }
    match service {
        Some((kind, identifier)) => resolve_service(kind, identifier).map(Some),
        None if interactive => Ok(None),
        None => Err(Error::UnassociatedApp),
    }
}

/// The values a fill returns.
#[derive(Default)]
pub struct LoginValues {
    pub username: Option<String>,
    pub password: Option<Zeroizing<String>>,
    pub totp: Option<Zeroizing<String>>,
}

/// The values `want` names that `login` has, with the one-time code at
/// `unix` seconds. A login without a code leaves it out; an invalid code is
/// an error.
pub fn login_values(login: &Item, want: &[Want], unix: u64) -> Result<LoginValues, Error> {
    let mut values = LoginValues::default();
    for fill in want {
        match fill {
            Want::Username => values.username = value(login, "username").map(str::to_string),
            Want::Password => {
                values.password = value(login, "password").map(|p| Zeroizing::new(p.into()));
            }
            Want::Totp => {
                let Some(field) = otp(login).filter(|f| !f.value.is_empty()) else {
                    continue;
                };
                let totp = Totp::parse(&field.value).map_err(|error| Error::InvalidTotp {
                    label: label(login),
                    error,
                })?;
                values.totp = Some(Zeroizing::new(totp.code(unix)));
            }
        }
    }
    Ok(values)
}

/// What a site asks of user verification in a passkey ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserVerification {
    Required,
    Preferred,
    Discouraged,
}

/// Whether a passkey ceremony may proceed without presenting UI
/// (unverified). `can_verify`: this device can verify the user (Touch ID,
/// Face ID).
pub fn silent_verification(verify: UserVerification, can_verify: bool) -> Result<(), Error> {
    match verify {
        UserVerification::Discouraged => Ok(()),
        UserVerification::Preferred if !can_verify => Ok(()),
        UserVerification::Required if !can_verify => Err(Error::VerificationUnavailable),
        UserVerification::Preferred | UserVerification::Required => Err(Error::InteractionRequired),
    }
}

/// How an interactive passkey ceremony settles user verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// The site discourages it: unverified.
    Skip,
    /// The biometric unlock for this ceremony already verified the user.
    Verified,
    /// Ask the platform to verify the user.
    Prompt,
}

/// `unlocked_by_biometrics`: this ceremony's own biometric prompt unlocked
/// the store.
pub fn interactive_verification(
    verify: UserVerification,
    unlocked_by_biometrics: bool,
) -> Verification {
    if verify == UserVerification::Discouraged {
        Verification::Skip
    } else if unlocked_by_biometrics {
        Verification::Verified
    } else {
        Verification::Prompt
    }
}

/// One `ASPasswordCredentialIdentity`. Never carries a password or title.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasswordIdentity {
    pub domain: String,
    pub username: String,
    pub record_id: String,
    pub rank: i64,
}

/// One `ASPasskeyCredentialIdentity`. Never carries the private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

/// One `ASOneTimeCodeCredentialIdentity`. Never carries the seed or a code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OneTimeCodeIdentity {
    pub domain: String,
    pub label: String,
    pub record_id: String,
    pub rank: i64,
}

/// The secret-free `ASCredentialIdentityStore` snapshot, sorted, and its
/// BLAKE3 digest (hex) over the JSON `{passwords, passkeys,
/// one_time_codes}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identities {
    pub hash: String,
    pub passwords: Vec<PasswordIdentity>,
    pub passkeys: Vec<PasskeyIdentity>,
    pub one_time_codes: Vec<OneTimeCodeIdentity>,
}

#[derive(Serialize)]
struct IdentitiesRef<'a> {
    passwords: &'a [PasswordIdentity],
    passkeys: &'a [PasskeyIdentity],
    one_time_codes: &'a [OneTimeCodeIdentity],
}

/// The identity snapshot of `items` (every item of every unlocked vault,
/// owned or borrowed, consumed one at a time; deleted ones are skipped).
/// `used` gives a record's last fill time (0 if never), its rank.
///
/// A login with a username and password gives a password identity per
/// saved domain ([`site::login_domains`]); one with a one-time code gives a
/// code identity per domain, labelled by its username else its title. A
/// passkey with a valid relying party, credential id and user handle gives
/// a passkey identity labelled by its username else display name.
pub fn identities<I: Borrow<Item>>(
    items: impl IntoIterator<Item = (VaultId, I)>,
    used: impl Fn(&str) -> u64,
) -> Identities {
    let mut passwords = Vec::new();
    let mut passkeys = Vec::new();
    let mut one_time_codes = Vec::new();

    for (vault, item) in items {
        let item = item.borrow();
        if item.deleted {
            continue;
        }
        let record_id = record_id(&vault, &item.id);
        let rank = i64::try_from(used(&record_id)).unwrap_or(i64::MAX);
        match item.kind.as_str() {
            "login" => {
                let domains = site::login_domains(urls(item));
                if domains.is_empty() {
                    continue;
                }
                if let (Some(username), Some(_)) =
                    (value(item, "username"), value(item, "password"))
                {
                    let username = username.trim();
                    if !username.is_empty() {
                        for domain in &domains {
                            passwords.push(PasswordIdentity {
                                domain: domain.clone(),
                                username: username.to_string(),
                                record_id: record_id.clone(),
                                rank,
                            });
                        }
                    }
                }
                if otp(item).is_some_and(|f| !f.value.is_empty()) {
                    let otp_label = value(item, "username")
                        .map(str::trim)
                        .filter(|u| !u.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| label(item));
                    for domain in &domains {
                        one_time_codes.push(OneTimeCodeIdentity {
                            domain: domain.clone(),
                            label: otp_label.clone(),
                            record_id: record_id.clone(),
                            rank,
                        });
                    }
                }
            }
            "passkey" => {
                let Some(rp) = value(item, "rp-id").and_then(|rp| site::valid_rp_id(rp).ok())
                else {
                    continue;
                };
                let Some(credential_id) = value(item, "credential-id")
                    .filter(|id| webauthn::unb64(id).is_ok_and(|b| !b.is_empty()))
                else {
                    continue;
                };
                let Some(user_handle) =
                    value(item, "user-handle").filter(|h| webauthn::user_handle(h).is_ok())
                else {
                    continue;
                };
                let username = value(item, "username")
                    .or_else(|| value(item, "display-name"))
                    .unwrap_or_default()
                    .to_string();
                passkeys.push(PasskeyIdentity {
                    rp_id: rp,
                    username,
                    credential_id: credential_id.to_string(),
                    user_handle: user_handle.to_string(),
                    record_id,
                    rank,
                });
            }
            _ => {}
        }
    }

    passwords.sort_by(|a, b| {
        (&a.domain, &a.username, &a.record_id).cmp(&(&b.domain, &b.username, &b.record_id))
    });
    passkeys.sort_by(|a, b| {
        (&a.rp_id, &a.username, &a.credential_id, &a.record_id).cmp(&(
            &b.rp_id,
            &b.username,
            &b.credential_id,
            &b.record_id,
        ))
    });
    one_time_codes.sort_by(|a, b| {
        (&a.domain, &a.label, &a.record_id).cmp(&(&b.domain, &b.label, &b.record_id))
    });

    let encoded = serde_json::to_vec(&IdentitiesRef {
        passwords: &passwords,
        passkeys: &passkeys,
        one_time_codes: &one_time_codes,
    })
    .unwrap_or_default();
    let hash = blake3::hash(&encoded).to_hex().to_string();

    Identities {
        hash,
        passwords,
        passkeys,
        one_time_codes,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{Field, FieldType};

    const PASSWORD: &str = "hunter2-super-secret";
    const OTP_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const PRIVATE_KEY: &str = "private-key-material";

    fn vault() -> VaultId {
        VaultId::from_bytes([1; 32])
    }

    fn item(id: u8, kind: &str, deleted: bool, fields: &[(&str, FieldType, &str)]) -> Item {
        Item {
            id: ItemId::from_bytes([id; 16]),
            kind: kind.into(),
            name: Some(format!("item {id}")),
            fields: fields
                .iter()
                .map(|(name, kind, value)| ((*name).into(), Field::new(kind.clone(), *value)))
                .collect(),
            source: None,
            favorite: false,
            tags: BTreeSet::new(),
            password_entry: None,
            password_changed: None,
            ignored: BTreeMap::new(),
            deleted,
        }
    }

    fn login(id: u8, deleted: bool) -> Item {
        item(
            id,
            "login",
            deleted,
            &[
                ("url", FieldType::Url, "https://example.com/login"),
                ("username", FieldType::Text, "alice"),
                ("password", FieldType::Secret, PASSWORD),
                ("otp", FieldType::Otp, OTP_SECRET),
            ],
        )
    }

    fn passkey(id: u8, credential_id: &str) -> Item {
        item(
            id,
            "passkey",
            false,
            &[
                ("rp-id", FieldType::Text, "example.com"),
                ("credential-id", FieldType::Text, credential_id),
                ("user-handle", FieldType::Text, &webauthn::b64(b"alice")),
                ("username", FieldType::Text, "alice"),
                ("private-key", FieldType::Secret, PRIVATE_KEY),
            ],
        )
    }

    fn picked(scope: &Scope, items: Vec<(VaultId, Item)>) -> Vec<ItemId> {
        picker_logins(scope, items, |_| 0, false)
            .into_iter()
            .map(|pick| pick.item.id)
            .collect()
    }

    #[test]
    fn deleted_logins_are_never_picked() {
        let items = vec![(vault(), login(1, false)), (vault(), login(2, true))];
        let live = vec![ItemId::from_bytes([1; 16])];
        assert_eq!(picked(&Scope::Unassociated, items.clone()), live);
        let services = scope([(ServiceKind::Domain, "example.com")]).unwrap();
        assert!(matches!(services, Scope::Services(_)));
        assert_eq!(picked(&services, items), live);
    }

    #[test]
    fn invalid_web_services_never_broaden_to_unassociated() {
        for services in [
            vec![(ServiceKind::Domain, "com")],
            vec![(ServiceKind::Domain, "not a domain")],
            vec![(ServiceKind::Url, "http://example.com")],
            vec![
                (ServiceKind::App, "com.example.app"),
                (ServiceKind::Url, ""),
            ],
        ] {
            let err = scope(services.clone()).unwrap_err();
            assert!(
                matches!(err, Error::InvalidService { .. }),
                "{services:?}: {err}"
            );
        }
        assert_eq!(
            scope([(ServiceKind::App, "com.example.app")]).unwrap(),
            Scope::Unassociated
        );
        assert_eq!(scope([]).unwrap(), Scope::Unassociated);
        let Scope::Services(resolved) = scope([
            (ServiceKind::Domain, "com"),
            (ServiceKind::Url, "https://www.example.com/x"),
        ])
        .unwrap() else {
            panic!("a valid service scopes the request");
        };
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].site.domain, "example.com");
        assert_eq!(
            resolve_service(ServiceKind::App, "com.example.app"),
            Err(Error::AppService)
        );
        assert_eq!(
            fill_target(&[Want::Password], None, false).unwrap_err(),
            Error::UnassociatedApp
        );
        assert_eq!(fill_target(&[Want::Password], None, true).unwrap(), None);
        assert_eq!(fill_target(&[], None, true).unwrap_err(), Error::FillFields);
        assert_eq!(
            fill_target(&[Want::Username; 4], None, true).unwrap_err(),
            Error::FillFields
        );
    }

    #[test]
    fn rp_ids_and_credential_lists_are_exact_and_bounded() {
        assert_eq!(passkey_request("Example.COM", &[]).unwrap(), "example.com");
        for bad in [
            "",
            "com",
            "github.io",
            "127.0.0.1",
            "[::1]",
            "https://example.com",
        ] {
            assert!(
                matches!(passkey_request(bad, &[]), Err(Error::InvalidRpId { .. })),
                "{bad}"
            );
        }

        let cred = webauthn::b64(&[9; 16]);
        let max = vec![cred.clone(); MAX_CREDENTIALS];
        assert!(passkey_request("example.com", &max).is_ok());
        let over = vec![cred.clone(); MAX_CREDENTIALS + 1];
        assert_eq!(
            passkey_request("example.com", &over),
            Err(Error::TooManyAllowed)
        );
        assert_eq!(
            passkey_request("example.com", &["not base64!".into()]),
            Err(Error::AllowedNotBase64)
        );
        assert!(check_exclude(&max).is_ok());
        assert_eq!(check_exclude(&over), Err(Error::TooManyExcluded));

        let key = passkey(3, &cred);
        assert!(allows(&key, &[]));
        assert!(allows(&key, std::slice::from_ref(&cred)));
        let prefix = cred[..cred.len() - 1].to_string();
        assert!(!allows(&key, &[prefix]));
        assert!(!allows(&key, &[webauthn::b64(&[8; 16])]));
    }

    #[test]
    fn verification_decisions() {
        use UserVerification::*;
        assert_eq!(silent_verification(Discouraged, true), Ok(()));
        assert_eq!(silent_verification(Discouraged, false), Ok(()));
        assert_eq!(silent_verification(Preferred, false), Ok(()));
        assert_eq!(
            silent_verification(Preferred, true),
            Err(Error::InteractionRequired)
        );
        assert_eq!(
            silent_verification(Required, true),
            Err(Error::InteractionRequired)
        );
        assert_eq!(
            silent_verification(Required, false),
            Err(Error::VerificationUnavailable)
        );

        for unlocked in [false, true] {
            assert_eq!(
                interactive_verification(Discouraged, unlocked),
                Verification::Skip
            );
        }
        for verify in [Preferred, Required] {
            assert_eq!(
                interactive_verification(verify, true),
                Verification::Verified
            );
            assert_eq!(
                interactive_verification(verify, false),
                Verification::Prompt
            );
        }
    }

    #[test]
    fn identities_are_secret_free_and_skip_deleted() {
        let cred = webauthn::b64(&[9; 16]);
        let items = vec![
            (vault(), login(1, false)),
            (vault(), login(2, true)),
            (vault(), passkey(3, &cred)),
            (
                vault(),
                item(4, "note", false, &[("notes", FieldType::Secret, "diary")]),
            ),
        ];
        let snap = identities(items, |_| 7);
        let live = record_id(&vault(), &ItemId::from_bytes([1; 16]));
        assert_eq!(snap.passwords.len(), 1);
        assert_eq!(snap.passwords[0].domain, "example.com");
        assert_eq!(snap.passwords[0].username, "alice");
        assert_eq!(snap.passwords[0].record_id, live);
        assert_eq!(snap.passwords[0].rank, 7);
        assert_eq!(snap.one_time_codes.len(), 1);
        assert_eq!(snap.one_time_codes[0].label, "alice");
        assert_eq!(snap.passkeys.len(), 1);
        assert_eq!(snap.passkeys[0].credential_id, cred);

        let json = serde_json::to_string(&IdentitiesRef {
            passwords: &snap.passwords,
            passkeys: &snap.passkeys,
            one_time_codes: &snap.one_time_codes,
        })
        .unwrap();
        for secret in [PASSWORD, OTP_SECRET, PRIVATE_KEY, "diary", "item 1"] {
            assert!(!json.contains(secret), "{secret} in {json}");
        }
        assert_eq!(
            snap.hash,
            blake3::hash(json.as_bytes()).to_hex().to_string()
        );

        let borrowed = [(vault(), login(1, false))];
        let by_ref = identities(borrowed.iter().map(|(v, i)| (*v, i)), |_| 7);
        assert_eq!(by_ref.passwords, snap.passwords);
    }
}
