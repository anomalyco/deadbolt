//! Secret-free identity projection and BLAKE3 digest for macOS
//! `ASCredentialIdentityStore` (`docs/macos-autofill.md`).

use deadbolt_core::site as core_site;
use serde::Serialize;

use super::super::autofill::{otp, urls, value};
use super::super::items::label;
use super::super::session::{Loaded, hex};
use crate::protocol::{OneTimeCodeIdentity, PasskeyIdentity, PasswordIdentity};
use crate::webauthn;

#[derive(Serialize)]
struct IdentitySnapshotRef<'a> {
    passwords: &'a [PasswordIdentity],
    passkeys: &'a [PasskeyIdentity],
    one_time_codes: &'a [OneTimeCodeIdentity],
}

pub struct IdentitySnapshot {
    pub hash: String,
    pub passwords: Vec<PasswordIdentity>,
    pub passkeys: Vec<PasskeyIdentity>,
    pub one_time_codes: Vec<OneTimeCodeIdentity>,
}

/// Builds the secret-free `ASCredentialIdentityStore` snapshot across all
/// unlocked vaults and its deterministic BLAKE3 digest.
pub fn identities(s: &Loaded) -> IdentitySnapshot {
    let filled = s.filled();
    let mut passwords = Vec::new();
    let mut passkeys = Vec::new();
    let mut one_time_codes = Vec::new();

    for (vault_id, vault) in &s.vaults {
        for item in vault.items() {
            if item.deleted {
                continue;
            }
            let record_id = format!("{}:{}", hex(vault_id.as_bytes()), hex(item.id.as_bytes()));
            let rank =
                i64::try_from(filled.get(&record_id).copied().unwrap_or(0)).unwrap_or(i64::MAX);
            match item.kind.as_str() {
                "login" => {
                    let domains = core_site::login_domains(urls(&item));
                    if domains.is_empty() {
                        continue;
                    }
                    if let (Some(username), Some(_)) =
                        (value(&item, "username"), value(&item, "password"))
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
                    if otp(&item).is_some_and(|f| !f.value.is_empty()) {
                        let otp_label = value(&item, "username")
                            .map(str::trim)
                            .filter(|u| !u.is_empty())
                            .map(str::to_string)
                            .unwrap_or_else(|| label(&item));
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
                    let Some(rp) =
                        value(&item, "rp-id").and_then(|rp| core_site::valid_rp_id(rp).ok())
                    else {
                        continue;
                    };
                    let Some(credential_id) = value(&item, "credential-id")
                        .filter(|id| webauthn::unb64(id).is_ok_and(|b| !b.is_empty()))
                    else {
                        continue;
                    };
                    let Some(user_handle) =
                        value(&item, "user-handle").filter(|h| webauthn::user_handle(h).is_ok())
                    else {
                        continue;
                    };
                    let username = value(&item, "username")
                        .or_else(|| value(&item, "display-name"))
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

    let encoded = serde_json::to_vec(&IdentitySnapshotRef {
        passwords: &passwords,
        passkeys: &passkeys,
        one_time_codes: &one_time_codes,
    })
    .unwrap_or_default();
    let hash = blake3::hash(&encoded).to_hex().to_string();

    IdentitySnapshot {
        hash,
        passwords,
        passkeys,
        one_time_codes,
    }
}

pub fn identities_hash(s: &Loaded) -> String {
    identities(s).hash
}
