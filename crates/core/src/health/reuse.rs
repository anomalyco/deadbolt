//! Keyed-hash password reuse grouping and same-account deduplication.

use crate::Item;
use crate::autofill::{urls, value};

use super::directory::canonical_account_site;

/// Identifies one logical account so two copies of the same login (for example
/// `github.com` and `gist.github.com` with username `alex`, or `amazon.com` and
/// `amazon.co.uk` in `shared.json`) collapse before counting password reuse.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AccountKey {
    /// A login with a canonical site and non-empty normalized username.
    SiteLogin { site: String, username: String },
    /// Anything without both a site and a username (`database`, `server`,
    /// `crypto`, or a login missing URL or username) is its own account.
    Distinct { vault: String, item: String },
}

/// Whether `kind`'s password participates in cross-account reuse checks.
/// Excludes `wifi` (2.4 GHz and 5 GHz SSIDs on one router share a passphrase)
/// and `ssh` (one personal passphrase often encrypts multiple SSH keys).
pub fn checks_reuse(kind: &str) -> bool {
    matches!(kind, "login" | "database" | "server" | "crypto")
}

/// Computes the ephemeral keyed BLAKE3 digest of `item`'s password and its
/// logical [`AccountKey`], without keeping plaintext copies.
pub fn item_reuse(
    reuse_key: &[u8; 32],
    vault_id: &str,
    item: &Item,
) -> Option<([u8; 32], AccountKey)> {
    if !checks_reuse(&item.kind) {
        return None;
    }
    let password = value(item, "password")?;
    let digest = *blake3::keyed_hash(reuse_key, password.as_bytes()).as_bytes();
    let account = if item.kind == "login" {
        let site = urls(item).find_map(canonical_account_site);
        let username = value(item, "username")
            .map(|u| u.trim().to_lowercase())
            .filter(|u| !u.is_empty());
        match (site, username) {
            (Some(site), Some(username)) => AccountKey::SiteLogin { site, username },
            _ => AccountKey::Distinct {
                vault: vault_id.to_owned(),
                item: item.id.to_string(),
            },
        }
    } else {
        AccountKey::Distinct {
            vault: vault_id.to_owned(),
            item: item.id.to_string(),
        }
    };
    Some((digest, account))
}
