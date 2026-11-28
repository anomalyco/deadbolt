//! Offline directory tables for two-factor authentication, passkeys, site
//! breaches, change-password links, and shared backend credentials.

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::site::shared::{self, Group};
use crate::site::{registrable_domain, url_host, valid_domain};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TfaSite {
    pub doc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeySite {
    pub passwordless: bool,
    pub mfa: bool,
    pub doc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteBreach {
    pub domain: String,
    pub title: String,
    /// Approximate breach date (`YYYY-MM-DD`).
    pub date: String,
    /// When the breach was added to HIBP (`YYYY-MM-DD`).
    pub added: String,
}

#[derive(Deserialize)]
struct RawPasskey {
    #[serde(default)]
    p: bool,
    #[serde(default)]
    m: bool,
    #[serde(default)]
    d: Option<String>,
}

#[derive(Deserialize)]
struct RawBreach {
    t: String,
    d: String,
    a: String,
}

/// Inserts exact domain entries first, then rolls subdomain keys (such as
/// `mail.google.com` or `appleid.apple.com`) up to their registrable domain
/// when the registrable domain is a real site and has no entry of its own.
fn with_registrable_rollup<T: Clone>(exact: HashMap<String, T>) -> HashMap<String, T> {
    let mut map = exact;
    let rollups: Vec<(String, T)> = map
        .iter()
        .filter_map(|(host, value)| {
            let root = registrable_domain(host);
            (root != *host && valid_domain(&root)).then(|| (root, value.clone()))
        })
        .collect();
    for (root, value) in rollups {
        map.entry(root).or_insert(value);
    }
    map
}

static TFA: LazyLock<HashMap<String, TfaSite>> = LazyLock::new(|| {
    let raw: HashMap<String, String> =
        serde_json::from_str(include_str!("../../data/health/2fa.json")).unwrap_or_default();
    let exact = raw
        .into_iter()
        .map(|(k, doc)| {
            (
                k,
                TfaSite {
                    doc: (!doc.is_empty()).then_some(doc),
                },
            )
        })
        .collect();
    with_registrable_rollup(exact)
});

static PASSKEYS: LazyLock<HashMap<String, PasskeySite>> = LazyLock::new(|| {
    let raw: HashMap<String, RawPasskey> =
        serde_json::from_str(include_str!("../../data/health/passkeys.json")).unwrap_or_default();
    let exact = raw
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                PasskeySite {
                    passwordless: v.p,
                    mfa: v.m,
                    doc: v.d.filter(|d| !d.is_empty()),
                },
            )
        })
        .collect();
    with_registrable_rollup(exact)
});

static BREACHES: LazyLock<HashMap<String, SiteBreach>> = LazyLock::new(|| {
    let raw: HashMap<String, RawBreach> =
        serde_json::from_str(include_str!("../../data/health/breaches.json")).unwrap_or_default();
    let exact = raw
        .into_iter()
        .map(|(domain, v)| {
            (
                domain.clone(),
                SiteBreach {
                    domain,
                    title: v.t,
                    date: v.d,
                    added: v.a,
                },
            )
        })
        .collect();
    with_registrable_rollup(exact)
});

static CHANGE_URLS: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    let raw: HashMap<String, String> =
        serde_json::from_str(include_str!("../../data/health/change-urls.json"))
            .unwrap_or_default();
    with_registrable_rollup(raw)
});

/// Maps every domain in a shared-credential group (or `from` -> `to` migration)
/// to one canonical domain for reuse deduplication.
static SHARED_GROUPS: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    for group in shared::groups() {
        let (members, canonical) = match group {
            Group::Shared(sites) => (sites, sites.first()),
            Group::Moved { from, to } => (from, to.first()),
        };
        if let Some(canonical) = canonical {
            for member in members {
                map.insert(member.clone(), canonical.clone());
            }
        }
    }
    map
});

/// Walks from `url`'s host (without `www.`) up to its registrable domain.
fn lookup_host<'a, T>(url: &str, table: &'a HashMap<String, T>) -> Option<&'a T> {
    let raw_host = url_host(url)?;
    let host = raw_host.strip_prefix("www.").unwrap_or(&raw_host);
    let site = registrable_domain(host);
    if !valid_domain(&site) {
        return None;
    }
    let mut name = host;
    loop {
        if let Some(found) = table.get(name) {
            return Some(found);
        }
        if name == site {
            return None;
        }
        name = name.split_once('.')?.1;
    }
}

pub fn tfa_for_url(url: &str) -> Option<&'static TfaSite> {
    lookup_host(url, &TFA)
}

pub fn passkey_for_url(url: &str) -> Option<&'static PasskeySite> {
    lookup_host(url, &PASSKEYS)
}

/// Looks up a site breach for `url`, preferring a newer entry in `refreshed`
/// (from a live `/api/v3/breaches` refresh) over the bundled snapshot.
pub fn breach_for_url(
    url: &str,
    refreshed: Option<&BTreeMap<String, SiteBreach>>,
) -> Option<SiteBreach> {
    let raw_host = url_host(url)?;
    let host = raw_host.strip_prefix("www.").unwrap_or(&raw_host);
    let site = registrable_domain(host);
    if !valid_domain(&site) {
        return None;
    }
    let bundled = lookup_host(url, &BREACHES).cloned();
    let live = refreshed.and_then(|extra| extra.get(host).or_else(|| extra.get(&site)).cloned());
    match (bundled, live) {
        (Some(a), Some(b)) => Some(if b.date >= a.date { b } else { a }),
        (a, b) => a.or(b),
    }
}

pub fn change_password_url(url: &str) -> Option<&'static str> {
    lookup_host(url, &CHANGE_URLS).map(String::as_str)
}

/// Canonical registrable domain for account-equivalence checks, folding Apple
/// `shared-credentials.json` groups onto one representative domain.
pub fn canonical_account_site(url: &str) -> Option<String> {
    let host = url_host(url)?;
    let site = registrable_domain(&host);
    if !valid_domain(&site) {
        return None;
    }
    if let Some(canonical) = SHARED_GROUPS.get(&site) {
        return Some(canonical.clone());
    }
    Some(site)
}
