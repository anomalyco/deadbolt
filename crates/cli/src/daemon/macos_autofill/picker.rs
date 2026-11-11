//! Service resolution and candidate ranking for the macOS AutoFill picker
//! (`AutofillList`; rules in [`credential_provider`]).

use anyhow::Result;
use deadbolt_core::credential_provider::{self, ServiceKind};

use super::super::autofill::{self, login_ref, otp, urls, value};
use super::super::items::label;
use super::super::passkeys;
use super::super::session::Loaded;
use super::identities::identities_hash;
use super::map_provider_error;
use crate::protocol::{AutofillService, AutofillServiceKind, Reply, SiteLogin, SitePasskey};

pub(super) fn service_kind(kind: AutofillServiceKind) -> ServiceKind {
    match kind {
        AutofillServiceKind::Domain => ServiceKind::Domain,
        AutofillServiceKind::Url => ServiceKind::Url,
        AutofillServiceKind::App => ServiceKind::App,
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
    let scope = credential_provider::scope(
        services
            .iter()
            .map(|svc| (service_kind(svc.kind), svc.identifier.as_str())),
    )
    .map_err(map_provider_error)?;
    let unassociated = scope == credential_provider::Scope::Unassociated;

    let items = s
        .vaults
        .iter()
        .flat_map(|(id, vault)| vault.iter_items().map(move |item| (*id, item)));
    let filled = s.filled();
    let logins = credential_provider::picker_logins(
        &scope,
        items,
        |record| filled.get(record).copied().unwrap_or(0),
        for_otp,
        |pick| pick,
    )
    .into_iter()
    .map(|pick| {
        let item = &pick.item;
        let service = pick.service.and_then(|idx| scope.service(idx));
        SiteLogin {
            login: login_ref(&pick.vault, &item.id),
            vault: s.vault(&pick.vault).name().to_string(),
            title: label(item),
            username: value(item, "username").map(str::to_string),
            has_password: value(item, "password").is_some(),
            has_otp: otp(item).is_some_and(|f| !f.value.is_empty()),
            urls: urls(item)
                .filter(|u| service.is_none_or(|svc| svc.site.matches_url(u)))
                .map(str::to_string)
                .collect(),
            sign_in: autofill::sign_in(s, item),
        }
    })
    .collect();

    let passkeys = match rp_id {
        Some(rp) => {
            let rp = credential_provider::passkey_request(rp, allowed_credentials)
                .map_err(map_provider_error)?;
            let mut found: Vec<SitePasskey> = passkeys::passkeys(s, &rp)
                .filter(|(_, item)| credential_provider::allows(item, allowed_credentials))
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
