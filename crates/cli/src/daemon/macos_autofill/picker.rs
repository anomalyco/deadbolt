//! Service resolution and candidate ranking for the macOS AutoFill picker
//! (`AutofillList`, `docs/macos-autofill.md`).

use std::cmp::Reverse;
use std::collections::HashMap;

use anyhow::{Result, anyhow, bail};
use deadbolt_core::{autofill as core_autofill, site as core_site};

use super::super::autofill::{self, login_ref, otp, urls, value};
use super::super::items::label;
use super::super::passkeys;
use super::super::session::Loaded;
use super::super::{ErrorCode, fail};
use super::identities::identities_hash;
use crate::protocol::{AutofillService, AutofillServiceKind, Reply, SiteLogin, SitePasskey};
use crate::site::Site;
use crate::webauthn;

pub(super) const MAX_CREDENTIALS: usize = 64;

pub(super) fn resolve_service(service: &AutofillService) -> Result<(Site, String)> {
    match service.kind {
        AutofillServiceKind::Domain => Site::from_domain(&service.identifier).map_err(|reason| {
            fail(
                ErrorCode::DomainMismatch,
                format!("{}: {reason}", service.identifier),
            )
        }),
        AutofillServiceKind::Url => {
            let site = Site::from_origin(&service.identifier).map_err(|reason| {
                fail(
                    ErrorCode::DomainMismatch,
                    format!("{}: {reason}", service.identifier),
                )
            })?;
            Ok((site, service.identifier.clone()))
        }
        AutofillServiceKind::App => Err(fail(
            ErrorCode::DomainMismatch,
            "an app identifier has no web domain",
        )),
    }
}

fn usable_for_picker(login: &SiteLogin, for_otp: bool) -> bool {
    if for_otp {
        login.has_otp
    } else {
        login.has_password
    }
}

pub(super) fn list_for_picker(
    s: &Loaded,
    services: &[AutofillService],
    rp_id: Option<&str>,
    allowed_credentials: &[String],
    for_otp: bool,
    can_verify: bool,
) -> Result<Reply> {
    let web_services: Vec<&AutofillService> = services
        .iter()
        .filter(|svc| svc.kind != AutofillServiceKind::App)
        .collect();

    let (logins, unassociated) = if web_services.is_empty() {
        let filled = s.filled();
        let mut all = Vec::new();
        for (vault_id, vault) in &s.vaults {
            for item in vault.items() {
                if item.deleted || item.kind != "login" {
                    continue;
                }
                let login = SiteLogin {
                    login: login_ref(vault_id, &item.id),
                    vault: vault.name().to_string(),
                    title: label(&item),
                    username: value(&item, "username").map(str::to_string),
                    has_password: value(&item, "password").is_some(),
                    has_otp: otp(&item).is_some_and(|f| !f.value.is_empty()),
                    urls: urls(&item).map(str::to_string).collect(),
                    sign_in: autofill::sign_in(s, &item),
                };
                if !usable_for_picker(&login, for_otp) {
                    continue;
                }
                let key = format!("{}:{}", login.login.vault, login.login.item);
                let used = filled.get(&key).copied().unwrap_or(0);
                all.push((used, item.favorite, login));
            }
        }
        all.sort_by(|(ua, fa, a), (ub, fb, b)| {
            Reverse(*ua)
                .cmp(&Reverse(*ub))
                .then_with(|| Reverse(*fa).cmp(&Reverse(*fb)))
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
                .then_with(|| a.username.cmp(&b.username))
                .then_with(|| (&a.login.vault, &a.login.item).cmp(&(&b.login.vault, &b.login.item)))
        });
        (all.into_iter().map(|(_, _, l)| l).collect(), true)
    } else {
        let mut resolved = Vec::new();
        let mut first_err = None;
        for (idx, svc) in web_services.into_iter().enumerate() {
            match resolve_service(svc) {
                Ok((site, origin)) => resolved.push((idx, site, origin)),
                Err(err) => {
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            }
        }
        if resolved.is_empty() {
            return Err(first_err.unwrap_or_else(|| {
                fail(ErrorCode::DomainMismatch, "no valid service identifier")
            }));
        }

        let filled = s.filled();
        let mut best: HashMap<(String, String), (usize, core_autofill::Rank, SiteLogin)> =
            HashMap::new();
        for (idx, site, origin) in &resolved {
            for (vault_id, item) in autofill::logins(s, site) {
                let lref = login_ref(&vault_id, &item.id);
                let key_str = format!("{}:{}", lref.vault, lref.item);
                let used = filled.get(&key_str).copied().unwrap_or(0);
                let rank = core_autofill::rank(origin, &item, used);
                let login = SiteLogin {
                    login: lref.clone(),
                    vault: s.vault(&vault_id).name().to_string(),
                    title: label(&item),
                    username: value(&item, "username").map(str::to_string),
                    has_password: value(&item, "password").is_some(),
                    has_otp: otp(&item).is_some_and(|f| !f.value.is_empty()),
                    urls: urls(&item)
                        .filter(|u| site.matches_url(u))
                        .map(str::to_string)
                        .collect(),
                    sign_in: autofill::sign_in(s, &item),
                };
                if !usable_for_picker(&login, for_otp) {
                    continue;
                }
                let map_key = (lref.vault, lref.item);
                match best.get_mut(&map_key) {
                    Some((prev_idx, prev_rank, prev_login)) => {
                        if (*idx, &rank) < (*prev_idx, &*prev_rank) {
                            *prev_idx = *idx;
                            *prev_rank = rank;
                            *prev_login = login;
                        }
                    }
                    None => {
                        best.insert(map_key, (*idx, rank, login));
                    }
                }
            }
        }
        let mut ranked: Vec<_> = best.into_values().collect();
        ranked.sort_by(|(ia, ra, a), (ib, rb, b)| {
            ia.cmp(ib)
                .then_with(|| ra.cmp(rb))
                .then_with(|| (&a.login.vault, &a.login.item).cmp(&(&b.login.vault, &b.login.item)))
        });
        (ranked.into_iter().map(|(_, _, l)| l).collect(), false)
    };

    let passkeys = match rp_id {
        Some(rp) => {
            let rp = core_site::valid_rp_id(rp)
                .map_err(|reason| fail(ErrorCode::DomainMismatch, format!("{rp}: {reason}")))?;
            if allowed_credentials.len() > MAX_CREDENTIALS {
                bail!("at most {MAX_CREDENTIALS} allowed credentials");
            }
            for cred in allowed_credentials {
                webauthn::unb64(cred)
                    .map_err(|_| anyhow!("allowed credential id is not base64url"))?;
            }
            let mut found: Vec<SitePasskey> = passkeys::passkeys(s, &rp)
                .filter(|(_, item)| {
                    allowed_credentials.is_empty()
                        || value(item, "credential-id")
                            .is_some_and(|id| allowed_credentials.iter().any(|c| c == id))
                })
                .map(|(vault, item)| SitePasskey {
                    passkey: login_ref(&vault, &item.id),
                    vault: s.vault(&vault).name().to_string(),
                    credential_id: value(&item, "credential-id").unwrap_or_default().into(),
                    username: value(&item, "username").map(str::to_string),
                    created: value(&item, "created").map(str::to_string),
                })
                .collect();
            found.sort_by(|a, b| {
                (&a.username, &a.vault, &a.passkey.item).cmp(&(
                    &b.username,
                    &b.vault,
                    &b.passkey.item,
                ))
            });
            found
        }
        None => Vec::new(),
    };

    Ok(Reply::AutofillList {
        logins,
        passkeys,
        unassociated,
        can_verify,
        identities_hash: identities_hash(s),
    })
}
