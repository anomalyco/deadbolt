//! Secret-free identity projection and BLAKE3 digest for macOS
//! `ASCredentialIdentityStore` (rules in [`credential_provider::identities`]).

use deadbolt_core::credential_provider;

use super::super::session::Loaded;
use crate::protocol::{OneTimeCodeIdentity, PasskeyIdentity, PasswordIdentity};

pub struct IdentitySnapshot {
    pub hash: String,
    pub passwords: Vec<PasswordIdentity>,
    pub passkeys: Vec<PasskeyIdentity>,
    pub one_time_codes: Vec<OneTimeCodeIdentity>,
}

fn snapshot(s: &Loaded) -> credential_provider::Identities {
    let filled = s.filled();
    let items = s
        .vaults
        .iter()
        .flat_map(|(id, vault)| vault.items().into_iter().map(move |item| (*id, item)));
    credential_provider::identities(items, |record| filled.get(record).copied().unwrap_or(0))
}

/// Builds the secret-free `ASCredentialIdentityStore` snapshot across all
/// unlocked vaults and its deterministic BLAKE3 digest.
pub fn identities(s: &Loaded) -> IdentitySnapshot {
    let snap = snapshot(s);
    IdentitySnapshot {
        hash: snap.hash,
        passwords: snap
            .passwords
            .into_iter()
            .map(|p| PasswordIdentity {
                domain: p.domain,
                username: p.username,
                record_id: p.record_id,
                rank: p.rank,
            })
            .collect(),
        passkeys: snap
            .passkeys
            .into_iter()
            .map(|p| PasskeyIdentity {
                rp_id: p.rp_id,
                username: p.username,
                credential_id: p.credential_id,
                user_handle: p.user_handle,
                record_id: p.record_id,
                rank: p.rank,
            })
            .collect(),
        one_time_codes: snap
            .one_time_codes
            .into_iter()
            .map(|c| OneTimeCodeIdentity {
                domain: c.domain,
                label: c.label,
                record_id: c.record_id,
                rank: c.rank,
            })
            .collect(),
    }
}

pub fn identities_hash(s: &Loaded) -> String {
    snapshot(s).hash
}
