//! Pure password health engine: per-item memoization, cross-vault reuse
//! clustering, site breach date checks, and 2FA / passkey availability.
//!
//! No network or disk IO happens here; the background agent supplies an
//! ephemeral `reuse_key`, a store-derived `hibp_key` for encrypted breach-cache
//! lookups, and any cached HIBP counts.

pub mod directory;
pub mod reuse;
pub mod strength;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha1::{Digest as _, Sha1};
use zeroize::Zeroizing;

use crate::autofill::{otp, urls, value};
use crate::listing::{detail, label};
use crate::site::{registrable_domain, valid_domain};
use crate::{Hash, Item};

pub use directory::{PasskeySite, SiteBreach, TfaSite, change_password_url};
pub use reuse::{AccountKey, checks_reuse, item_reuse};
pub use strength::{
    MIN_PASSPHRASE_CHARS, PassphraseStrength, WeakReason, WeakScore, audited_password_field,
    check_weak, item_weak, passphrase_strength,
};

/// Sentinel hash stored in `Item::ignored` for item-wide findings
/// (`missing-2fa`, `passkey`) that do not depend on a password write.
pub const IGNORE_ALWAYS: Hash = Hash([0; 32]);

/// Categories of findings, ordered from highest severity to informational.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    Breached,
    SiteBreach,
    Reused,
    Weak,
    MissingTwoFactor,
    PasskeyAvailable,
}

impl FindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Breached => "breached",
            Self::SiteBreach => "site-breach",
            Self::Reused => "reused",
            Self::Weak => "weak",
            Self::MissingTwoFactor => "missing-2fa",
            Self::PasskeyAvailable => "passkey",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "breached" => Self::Breached,
            "site-breach" => Self::SiteBreach,
            "reused" => Self::Reused,
            "weak" => Self::Weak,
            "missing-2fa" | "2fa" => Self::MissingTwoFactor,
            "passkey" | "passkeys" => Self::PasskeyAvailable,
            _ => return None,
        })
    }

    /// True for actionable password risks shown in the sidebar count and row
    /// dots; false for 2FA and passkey upgrade opportunities.
    pub fn is_risk(self) -> bool {
        matches!(
            self,
            Self::Breached | Self::SiteBreach | Self::Reused | Self::Weak
        )
    }

    /// True when ignoring this finding binds to `Item::password_entry` so a
    /// password change re-enables the check automatically.
    pub fn binds_to_password(self) -> bool {
        self.is_risk()
    }
}

/// Severity tint for sidebar row dots and item banners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskLevel {
    Caution,
    Danger,
}

/// Non-secret reference to another item (for example in a reuse group).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthPeer {
    pub vault: String,
    pub vault_name: String,
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// One concrete finding on an item. Never carries secret values or hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Finding {
    Breached {
        /// Times observed in HIBP Pwned Passwords.
        count: u64,
    },
    SiteBreach {
        title: String,
        date: String,
        /// False when the item predates `password-changed` tracking.
        date_known: bool,
    },
    Reused {
        /// Total distinct accounts sharing this password, this item included.
        count: usize,
        others: Vec<HealthPeer>,
    },
    Weak {
        score: u8,
        reason: WeakReason,
    },
    MissingTwoFactor {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        doc_url: Option<String>,
    },
    PasskeyAvailable {
        passwordless: bool,
        mfa: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        doc_url: Option<String>,
    },
}

impl Finding {
    pub fn kind(&self) -> FindingKind {
        match self {
            Self::Breached { .. } => FindingKind::Breached,
            Self::SiteBreach { .. } => FindingKind::SiteBreach,
            Self::Reused { .. } => FindingKind::Reused,
            Self::Weak { .. } => FindingKind::Weak,
            Self::MissingTwoFactor { .. } => FindingKind::MissingTwoFactor,
            Self::PasskeyAvailable { .. } => FindingKind::PasskeyAvailable,
        }
    }

    pub fn summary(&self) -> String {
        match self {
            Self::Breached { count: 1 } => "Exposed in 1 data breach".into(),
            Self::Breached { count } => format!("Exposed in {} data breaches", fmt_count(*count)),
            Self::SiteBreach {
                title,
                date,
                date_known: true,
            } => format!("{title} breached {} · password older", short_month(date)),
            Self::SiteBreach {
                title,
                date,
                date_known: false,
            } => format!(
                "{title} breached {} · password date unknown",
                short_month(date)
            ),
            Self::Reused { others, .. } => match others.as_slice() {
                [one] => format!("Same password as {}", one.label),
                [first, rest @ ..] => {
                    format!(
                        "Same password as {} and {} {}",
                        first.label,
                        rest.len(),
                        if rest.len() == 1 { "other" } else { "others" }
                    )
                }
                [] => "Reused password".into(),
            },
            Self::Weak { score, reason } => reason.summary(*score).into(),
            Self::MissingTwoFactor { .. } => "Supports authenticator codes".into(),
            Self::PasskeyAvailable {
                passwordless: true, ..
            } => "Supports passkey sign-in".into(),
            Self::PasskeyAvailable { .. } => "Supports passkey two-factor".into(),
        }
    }
}

fn fmt_count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn short_month(date: &str) -> String {
    let Some((year, rest)) = date.split_once('-') else {
        return date.to_owned();
    };
    let month = rest.split('-').next().unwrap_or("");
    let name = match month {
        "01" => "Jan",
        "02" => "Feb",
        "03" => "Mar",
        "04" => "Apr",
        "05" => "May",
        "06" => "Jun",
        "07" => "Jul",
        "08" => "Aug",
        "09" => "Sep",
        "10" => "Oct",
        "11" => "Nov",
        "12" => "Dec",
        _ => return date.to_owned(),
    };
    format!("{name} {year}")
}

/// Health entry for one item that has active or ignored findings (or a
/// recorded `password_changed` date).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemHealth {
    pub vault: String,
    pub vault_name: String,
    pub id: String,
    pub kind: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_changed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<RiskLevel>,
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignored: Vec<Finding>,
}

/// Summary counts across a vault's active findings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCounts {
    /// Items with at least one active risk finding (`Breached`, `SiteBreach`,
    /// `Reused`, or `Weak`).
    pub risk_items: usize,
    pub breached: usize,
    pub site_breach: usize,
    pub reused: usize,
    pub weak: usize,
    pub missing_two_factor: usize,
    pub passkeys_available: usize,
    pub ignored: usize,
}

/// Non-secret cached memo for one item in `Session`. Holds no plaintext values
/// and no unsalted SHA-1 hashes.
#[derive(Debug, Clone)]
pub struct ItemMemo {
    pub vault_id: String,
    pub vault_name: String,
    pub id: String,
    pub fingerprint: [u8; 32],
    pub kind: String,
    pub label: String,
    pub detail: Option<String>,
    pub primary_url: Option<String>,
    pub change_url: Option<String>,
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub password_entry: Option<Hash>,
    pub password_changed: Option<String>,
    pub fallback_date: Option<String>,
    pub has_otp: bool,
    pub sign_in_with: bool,
    pub passkey_site: Option<String>,
    pub ignored: BTreeMap<String, Hash>,
    pub weak: Option<WeakScore>,
    pub reuse: Option<([u8; 32], AccountKey)>,
    /// Store-keyed BLAKE3 digest of `SHA-1(password)`, for looking up cached
    /// HIBP breach counts without keeping unsalted SHA-1 in memory.
    pub hibp_key: Option<[u8; 32]>,
}

/// Keyed fingerprint of everything `ItemMemo` depends on, so unchanged items
/// skip `zxcvbn` on edits and syncs.
pub fn item_fingerprint(key: &[u8; 32], vault_name: &str, item: &Item) -> [u8; 32] {
    fn feed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    let mut hasher = blake3::Hasher::new_keyed(key);
    feed(&mut hasher, vault_name.as_bytes());
    feed(&mut hasher, item.kind.as_bytes());
    feed(&mut hasher, item.name.as_deref().unwrap_or("").as_bytes());
    feed(&mut hasher, &[u8::from(item.deleted)]);
    if let Some(entry) = &item.password_entry {
        feed(&mut hasher, entry.as_bytes());
    } else {
        feed(&mut hasher, &[]);
    }
    feed(
        &mut hasher,
        item.password_changed.as_deref().unwrap_or("").as_bytes(),
    );
    if let Some(src) = &item.source {
        feed(&mut hasher, src.id.as_bytes());
        feed(&mut hasher, src.version.as_bytes());
    } else {
        feed(&mut hasher, &[]);
    }
    hasher.update(&(item.ignored.len() as u64).to_le_bytes());
    for (k, v) in &item.ignored {
        feed(&mut hasher, k.as_bytes());
        feed(&mut hasher, v.as_bytes());
    }
    hasher.update(&(item.fields.len() as u64).to_le_bytes());
    for (name, field) in &item.fields {
        feed(&mut hasher, name.as_bytes());
        feed(&mut hasher, field.kind.as_str().as_bytes());
        if field.kind == crate::FieldType::File {
            feed(
                &mut hasher,
                crate::item::file_parts(&field.value).0.as_bytes(),
            );
        } else {
            feed(&mut hasher, field.value.as_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

/// Computes `(5-char uppercase SHA-1 prefix, 35-char uppercase suffix, hibp_key)`
/// in zeroizing buffers for an online HIBP range query.
pub fn hibp_parts(
    hibp_cache_key: &[u8; 32],
    password: &str,
) -> ([u8; 5], Zeroizing<[u8; 35]>, [u8; 32]) {
    let digest = Zeroizing::new(<[u8; 20]>::from(Sha1::digest(password.as_bytes())));
    let hibp_key = *blake3::keyed_hash(hibp_cache_key, digest.as_slice()).as_bytes();
    let hex = Zeroizing::new(data_encoding::HEXUPPER.encode(digest.as_slice()));
    let bytes = hex.as_bytes();
    let mut prefix = [0u8; 5];
    prefix.copy_from_slice(&bytes[..5]);
    let mut suffix = Zeroizing::new([0u8; 35]);
    suffix.copy_from_slice(&bytes[5..40]);
    (prefix, suffix, hibp_key)
}

pub fn hibp_key_of(hibp_cache_key: &[u8; 32], password: &str) -> [u8; 32] {
    let digest = Zeroizing::new(<[u8; 20]>::from(Sha1::digest(password.as_bytes())));
    *blake3::keyed_hash(hibp_cache_key, digest.as_slice()).as_bytes()
}

/// Builds one [`ItemMemo`] from an item. Safe to run off the session lock.
pub fn build_memo(
    reuse_key: &[u8; 32],
    hibp_cache_key: &[u8; 32],
    vault_id: &str,
    vault_name: &str,
    item: &Item,
    fallback_date: Option<String>,
) -> ItemMemo {
    let fingerprint = item_fingerprint(reuse_key, vault_name, item);
    let item_urls: Vec<String> = urls(item).map(str::to_owned).collect();
    let primary_url = item_urls.first().cloned();
    let change_url = item_urls
        .iter()
        .find_map(|u| change_password_url(u))
        .map(str::to_owned);
    let pw_field = audited_password_field(&item.kind);
    let hibp_key = pw_field
        .and_then(|f| value(item, f))
        .map(|pw| hibp_key_of(hibp_cache_key, pw));
    let passkey_site = if item.kind == "passkey" {
        value(item, "rp-id")
            .map(registrable_domain)
            .filter(|d| valid_domain(d))
    } else {
        None
    };
    ItemMemo {
        vault_id: vault_id.to_owned(),
        vault_name: vault_name.to_owned(),
        id: item.id.to_string(),
        fingerprint,
        kind: item.kind.clone(),
        label: label(item),
        detail: detail(item),
        primary_url,
        change_url,
        urls: item_urls,
        username: value(item, "username").map(|u| u.trim().to_lowercase()),
        password_entry: item.password_entry,
        password_changed: item.password_changed.clone(),
        fallback_date,
        has_otp: otp(item).is_some(),
        sign_in_with: item.fields.contains_key("sign-in-with"),
        passkey_site,
        ignored: item.ignored.clone(),
        weak: item_weak(item),
        reuse: item_reuse(reuse_key, vault_id, item),
        hibp_key,
    }
}

fn is_ignored(memo: &ItemMemo, kind: FindingKind) -> bool {
    let Some(at) = memo.ignored.get(kind.as_str()) else {
        return false;
    };
    if *at == IGNORE_ALWAYS {
        return true;
    }
    kind.binds_to_password() && memo.password_entry.as_ref() == Some(at)
}

/// Evaluates health findings for `target_vault` (`None` includes all vaults),
/// still checking password reuse and saved passkeys across every unlocked vault
/// in `memos`.
pub fn evaluate(
    memos: &[ItemMemo],
    target_vault: Option<&str>,
    hibp_counts: &BTreeMap<[u8; 32], u64>,
    refreshed_breaches: Option<&BTreeMap<String, SiteBreach>>,
) -> (HealthCounts, Vec<ItemHealth>) {
    // 1. Saved passkeys across all unlocked vaults: (site, optional username).
    let mut passkey_sites: BTreeSet<String> = BTreeSet::new();
    let mut passkey_accounts: BTreeSet<(String, String)> = BTreeSet::new();
    let mut passkey_unscoped: BTreeSet<String> = BTreeSet::new();
    for m in memos {
        if let Some(site) = &m.passkey_site {
            passkey_sites.insert(site.clone());
            match m.username.as_deref().filter(|u| !u.is_empty()) {
                Some(user) => {
                    passkey_accounts.insert((site.clone(), user.to_owned()));
                }
                None => {
                    passkey_unscoped.insert(site.clone());
                }
            }
        }
    }
    let has_saved_passkey = |site: &str, username: Option<&str>| -> bool {
        if !passkey_sites.contains(site) {
            return false;
        }
        match username.filter(|u| !u.is_empty()) {
            Some(user) => {
                passkey_unscoped.contains(site)
                    || passkey_accounts.contains(&(site.to_owned(), user.to_owned()))
            }
            None => true,
        }
    };

    // 2. Group reuse digests across all unlocked vaults, collapsing identical
    //    AccountKeys first.
    let mut by_digest: BTreeMap<[u8; 32], BTreeMap<AccountKey, Vec<usize>>> = BTreeMap::new();
    for (idx, m) in memos.iter().enumerate() {
        if let Some((digest, ref account)) = m.reuse {
            by_digest
                .entry(digest)
                .or_default()
                .entry(account.clone())
                .or_default()
                .push(idx);
        }
    }

    let mut counts = HealthCounts::default();
    let mut out = Vec::new();

    for (idx, m) in memos.iter().enumerate() {
        if target_vault.is_some_and(|v| v != m.vault_id) {
            continue;
        }
        let mut active = Vec::new();
        let mut ignored = Vec::new();
        let mut push = |finding: Finding| {
            if is_ignored(m, finding.kind()) {
                ignored.push(finding);
            } else {
                active.push(finding);
            }
        };

        // Breached password (HIBP range cache).
        if let Some(key) = m.hibp_key
            && let Some(&count) = hibp_counts.get(&key)
            && count > 0
        {
            push(Finding::Breached { count });
        }

        // Compromised website (breach date vs password-changed date).
        if m.kind == "login" && m.password_entry.is_some() {
            let breach = m
                .urls
                .iter()
                .filter_map(|u| directory::breach_for_url(u, refreshed_breaches))
                .max_by(|a, b| a.date.cmp(&b.date));
            if let Some(breach) = breach {
                let effective_date = m.password_changed.as_deref().or(m.fallback_date.as_deref());
                match effective_date {
                    Some(changed) if changed >= breach.date.as_str() => {}
                    Some(_) => push(Finding::SiteBreach {
                        title: breach.title,
                        date: breach.date,
                        date_known: true,
                    }),
                    None => push(Finding::SiteBreach {
                        title: breach.title,
                        date: breach.date,
                        date_known: false,
                    }),
                }
            }
        }

        // Reused password across distinct accounts.
        if let Some((digest, ref own_account)) = m.reuse
            && let Some(accounts) = by_digest.get(&digest)
            && accounts.len() > 1
        {
            let mut others = Vec::new();
            for (acct, indices) in accounts {
                if acct == own_account {
                    continue;
                }
                if let Some(&other_idx) = indices.first() {
                    let o = &memos[other_idx];
                    others.push(HealthPeer {
                        vault: o.vault_id.clone(),
                        vault_name: o.vault_name.clone(),
                        id: o.id.clone(),
                        label: o.label.clone(),
                        detail: o.detail.clone(),
                    });
                }
            }
            others.sort_by_key(|a| a.label.to_lowercase());
            push(Finding::Reused {
                count: accounts.len(),
                others,
            });
        }

        // Weak password.
        if let Some(weak) = m.weak {
            push(Finding::Weak {
                score: weak.score,
                reason: weak.reason,
            });
        }

        // 2FA and passkey upgrade opportunities (logins that aren't SSO links).
        if m.kind == "login" && !m.sign_in_with {
            let covered_by_passkey = m.urls.iter().any(|u| {
                crate::site::url_host(u)
                    .map(|h| registrable_domain(&h))
                    .is_some_and(|site| has_saved_passkey(&site, m.username.as_deref()))
            });

            if !m.has_otp
                && !covered_by_passkey
                && m.password_entry.is_some()
                && let Some(tfa) = m.urls.iter().find_map(|u| directory::tfa_for_url(u))
            {
                push(Finding::MissingTwoFactor {
                    doc_url: tfa.doc.clone(),
                });
            }

            if !covered_by_passkey
                && let Some(pk) = m.urls.iter().find_map(|u| directory::passkey_for_url(u))
            {
                push(Finding::PasskeyAvailable {
                    passwordless: pk.passwordless,
                    mfa: pk.mfa,
                    doc_url: pk.doc.clone(),
                });
            }
        }

        active.sort_by_key(Finding::kind);
        ignored.sort_by_key(Finding::kind);

        let mut has_danger = false;
        let mut has_caution = false;
        for f in &active {
            match f.kind() {
                FindingKind::Breached => {
                    counts.breached += 1;
                    has_danger = true;
                }
                FindingKind::SiteBreach => {
                    counts.site_breach += 1;
                    has_danger = true;
                }
                FindingKind::Reused => {
                    counts.reused += 1;
                    has_danger = true;
                }
                FindingKind::Weak => {
                    counts.weak += 1;
                    has_caution = true;
                }
                FindingKind::MissingTwoFactor => counts.missing_two_factor += 1,
                FindingKind::PasskeyAvailable => counts.passkeys_available += 1,
            }
        }
        counts.ignored += ignored.len();
        let risk = if has_danger {
            counts.risk_items += 1;
            Some(RiskLevel::Danger)
        } else if has_caution {
            counts.risk_items += 1;
            Some(RiskLevel::Caution)
        } else {
            None
        };

        if !active.is_empty() || !ignored.is_empty() || m.password_changed.is_some() {
            let _ = idx;
            out.push(ItemHealth {
                vault: m.vault_id.clone(),
                vault_name: m.vault_name.clone(),
                id: m.id.clone(),
                kind: m.kind.clone(),
                label: m.label.clone(),
                detail: m.detail.clone(),
                site_url: m.primary_url.clone(),
                change_url: m.change_url.clone(),
                password_changed: m.password_changed.clone(),
                risk,
                findings: active,
                ignored,
            });
        }
    }

    // Sort worst items first, then alphabetically by label.
    out.sort_by(|a, b| {
        let rank = |ih: &ItemHealth| ih.findings.first().map(Finding::kind);
        match (rank(a), rank(b)) {
            (Some(ka), Some(kb)) => ka.cmp(&kb),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
        .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
        .then_with(|| a.id.cmp(&b.id))
    });

    (counts, out)
}
