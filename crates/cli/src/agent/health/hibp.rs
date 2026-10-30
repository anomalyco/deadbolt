//! Opt-in Have I Been Pwned range queries (`Add-Padding: true`) and encrypted
//! `store.redb` caching.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use data_encoding::HEXLOWER;
use deadbolt_core::health::{SiteBreach, hibp_parts};
use deadbolt_store::Unlocked;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinSet;
use url::Url;
use zeroize::Zeroizing;

use crate::agent::session::{get_json, now, set_json};

const RANGE_SERVICE: &str = "https://api.pwnedpasswords.com/";
const BREACHES_URL: &str = "https://haveibeenpwned.com/api/v3/breaches";
/// Debug-only loopback override for deterministic integration tests.
const HIBP_OVERRIDE: &str = "DEADBOLT_HIBP_URL";

pub const META_HIBP_CACHE: &str = "cli/hibp-cache";
pub const META_SITE_BREACHES: &str = "cli/site-breaches";

const CLEAN_TTL_DAYS: u32 = 14;
pub const BREACHES_TTL_SECS: u64 = 7 * 24 * 3600;
const MAX_CACHE_ENTRIES: usize = 16_384;
const MAX_RANGE_BYTES: usize = 512 * 1024;
const MAX_BREACHES_BYTES: usize = 8 * 1024 * 1024;
const CONCURRENCY: usize = 8;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HibpCache {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked: Option<u64>,
    pub entries: BTreeMap<String, HibpEntry>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HibpEntry {
    pub count: u64,
    /// UTC day (`secs / 86_400`) when checked.
    pub day: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredBreaches {
    pub fetched_at: u64,
    pub breaches: BTreeMap<String, SiteBreach>,
}

impl HibpCache {
    pub fn load(store: &Unlocked) -> Self {
        get_json(store, META_HIBP_CACHE)
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    pub fn save(&mut self, store: &Unlocked) -> Result<()> {
        while self.entries.len() > MAX_CACHE_ENTRIES {
            // Evict oldest clean (`count == 0`) entry first; else oldest overall.
            let victim = self
                .entries
                .iter()
                .filter(|(_, e)| e.count == 0)
                .min_by_key(|(_, e)| e.day)
                .or_else(|| self.entries.iter().min_by_key(|(_, e)| e.day))
                .map(|(k, _)| k.clone());
            let Some(victim) = victim else { break };
            self.entries.remove(&victim);
        }
        set_json(store, META_HIBP_CACHE, self)
    }

    /// Cached breach count for `key` if still fresh at `today_day`.
    /// Breached passwords (`count > 0`) never expire; clean passwords expire
    /// after 14–15 days (1-day deterministic jitter per key).
    pub fn fresh_count(&self, key: &[u8; 32], today_day: u32) -> Option<u64> {
        let hex = HEXLOWER.encode(key);
        let entry = self.entries.get(&hex)?;
        if entry.count > 0 {
            return Some(entry.count);
        }
        let jitter = u32::from(key[0] & 1);
        (today_day.saturating_sub(entry.day) < CLEAN_TTL_DAYS + jitter).then_some(0)
    }

    /// Map of all cached counts (`[u8; 32]` -> `u64`) for `evaluate`.
    pub fn counts_map(&self) -> BTreeMap<[u8; 32], u64> {
        self.entries
            .iter()
            .filter_map(|(hex, entry)| {
                let bytes: [u8; 32] = HEXLOWER.decode(hex.as_bytes()).ok()?.try_into().ok()?;
                Some((bytes, entry.count))
            })
            .collect()
    }
}

pub fn load_site_breaches(store: &Unlocked) -> Option<StoredBreaches> {
    get_json(store, META_SITE_BREACHES).ok().flatten()
}

struct Endpoints {
    range_base: Url,
    breaches: Url,
    client: reqwest::Client,
}

impl Endpoints {
    fn new() -> Result<Self> {
        let (range_base, breaches) = urls(crate::config::test_env(HIBP_OVERRIDE).as_deref())?;
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let client = reqwest::Client::builder()
            .user_agent("deadbolt")
            .https_only(range_base.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(20))
            .build()
            .context("setting up HTTPS for breach checks")?;
        Ok(Self {
            range_base,
            breaches,
            client,
        })
    }
}

fn urls(override_url: Option<&str>) -> Result<(Url, Url)> {
    let Some(over) = override_url.filter(|s| !s.trim().is_empty()) else {
        return Ok((Url::parse(RANGE_SERVICE)?, Url::parse(BREACHES_URL)?));
    };
    let mut base = Url::parse(over).with_context(|| format!("{HIBP_OVERRIDE} {over}"))?;
    let loopback = matches!(base.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(base.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback());
    if !loopback || !matches!(base.scheme(), "http" | "https") {
        bail!("{HIBP_OVERRIDE} must be a URL on 127.0.0.1 or [::1]");
    }
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path()));
    }
    let breaches = base.join("breaches")?;
    Ok((base, breaches))
}

/// Candidate password prepared for an online check without retaining its
/// plaintext string.
pub struct Candidate {
    pub prefix: [u8; 5],
    pub suffix: Zeroizing<[u8; 35]>,
    pub hibp_key: [u8; 32],
}

impl Candidate {
    pub fn from_password(hibp_cache_key: &[u8; 32], password: &str) -> Self {
        let (prefix, suffix, hibp_key) = hibp_parts(hibp_cache_key, password);
        Self {
            prefix,
            suffix,
            hibp_key,
        }
    }
}

fn shuffle<T>(slice: &mut [T]) {
    if slice.len() <= 1 {
        return;
    }
    let mut rnd = vec![0u8; slice.len() * 4];
    if getrandom::fill(&mut rnd).is_err() {
        return;
    }
    for i in (1..slice.len()).rev() {
        let chunk = &rnd[i * 4..(i + 1) * 4];
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as usize;
        slice.swap(i, word % (i + 1));
    }
}

async fn fetch_range(client: &reqwest::Client, base: &Url, prefix: [u8; 5]) -> Result<([u8; 5], String)> {
    let prefix_str = std::str::from_utf8(&prefix).unwrap_or("00000");
    let url = base.join(&format!("range/{prefix_str}"))?;
    let mut resp = client
        .get(url.clone())
        .header("Add-Padding", "true")
        .send()
        .await
        .with_context(|| format!("querying {url}"))?;
    if !resp.status().is_success() {
        bail!("HIBP range check returned {}", resp.status());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_RANGE_BYTES {
            bail!("HIBP range response exceeded size limit");
        }
    }
    let text = String::from_utf8(body).context("HIBP range response is not UTF-8")?;
    Ok((prefix, text))
}

/// Parses a `SUFFIX:COUNT` body, ignoring `:0` padding rows, and returns the
/// observed count for each candidate suffix in `bucket`.
pub fn match_bucket(body: &str, candidates: &[Candidate]) -> Vec<([u8; 32], u64)> {
    let mut suffix_counts: BTreeMap<[u8; 35], u64> = BTreeMap::new();
    for line in body.lines() {
        let line = line.trim();
        let Some((sfx, cnt)) = line.split_once(':') else {
            continue;
        };
        let Ok(count) = cnt.trim().parse::<u64>() else {
            continue;
        };
        // Padded entries always carry `:0` and are discarded.
        if count == 0 || sfx.len() != 35 {
            continue;
        }
        let mut upper = [0u8; 35];
        for (dst, src) in upper.iter_mut().zip(sfx.as_bytes()) {
            *dst = src.to_ascii_uppercase();
        }
        suffix_counts.insert(upper, count);
    }
    candidates
        .iter()
        .map(|cand| {
            let count = suffix_counts.get(&*cand.suffix).copied().unwrap_or(0);
            (cand.hibp_key, count)
        })
        .collect()
}

/// Queries unique 5-hex SHA-1 prefixes for `candidates` (shuffled, up to 8 in
/// flight), stopping immediately if `interrupts` fires (lock or shutdown).
pub async fn query_candidates(
    candidates: Vec<Candidate>,
    interrupts: &mut watch::Receiver<u64>,
) -> Result<Vec<([u8; 32], u64)>> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let endpoints = Endpoints::new()?;
    let mut buckets: BTreeMap<[u8; 5], Vec<Candidate>> = BTreeMap::new();
    for cand in candidates {
        buckets.entry(cand.prefix).or_default().push(cand);
    }
    let mut prefixes: Vec<[u8; 5]> = buckets.keys().copied().collect();
    shuffle(&mut prefixes);

    let mut out = Vec::new();
    let mut tasks = JoinSet::new();
    let mut iter = prefixes.into_iter();

    for _ in 0..CONCURRENCY {
        if let Some(p) = iter.next() {
            let client = endpoints.client.clone();
            let base = endpoints.range_base.clone();
            tasks.spawn(async move { fetch_range(&client, &base, p).await });
        }
    }

    while !tasks.is_empty() {
        let joined = tokio::select! {
            res = tasks.join_next() => match res {
                Some(r) => r,
                None => break,
            },
            _ = interrupts.changed() => {
                tasks.abort_all();
                bail!("locked during breach check");
            }
        };
        let (prefix, body) = joined.context("breach query task panicked")??;
        if let Some(cands) = buckets.remove(&prefix) {
            out.extend(match_bucket(&body, &cands));
        }
        if let Some(p) = iter.next() {
            let client = endpoints.client.clone();
            let base = endpoints.range_base.clone();
            tasks.spawn(async move { fetch_range(&client, &base, p).await });
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiBreach {
    title: String,
    #[serde(default)]
    domain: String,
    breach_date: String,
    added_date: String,
    #[serde(default)]
    data_classes: Vec<String>,
    #[serde(default)]
    is_verified: bool,
    #[serde(default)]
    is_fabricated: bool,
    #[serde(default)]
    is_retired: bool,
    #[serde(default)]
    is_spam_list: bool,
}

/// Downloads the full HIBP site-breach list (`GET /api/v3/breaches`, sending
/// zero user domains). Errors are non-fatal when bundled breaches exist.
pub async fn fetch_site_breaches(
    interrupts: &mut watch::Receiver<u64>,
) -> Result<StoredBreaches> {
    let endpoints = Endpoints::new()?;
    let url = endpoints.breaches.clone();
    let req = async {
        let mut resp = endpoints.client.get(url.clone()).send().await?;
        if !resp.status().is_success() {
            bail!("HIBP breaches endpoint returned {}", resp.status());
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_BREACHES_BYTES {
                bail!("HIBP breaches response exceeded size limit");
            }
        }
        let raw: Vec<ApiBreach> = serde_json::from_slice(&body)?;
        let mut map: BTreeMap<String, SiteBreach> = BTreeMap::new();
        for b in raw {
            let domain = b.domain.trim().to_lowercase();
            let domain = domain.strip_suffix('.').unwrap_or(&domain).to_owned();
            if domain.is_empty()
                || !b.is_verified
                || b.is_fabricated
                || b.is_retired
                || b.is_spam_list
                || !b.data_classes.iter().any(|c| c == "Passwords")
            {
                continue;
            }
            let date = b.breach_date.get(..10).unwrap_or(&b.breach_date).to_owned();
            let added = b.added_date.get(..10).unwrap_or(&b.added_date).to_owned();
            let replace = map.get(&domain).is_none_or(|prev| date > prev.date);
            if replace {
                map.insert(
                    domain.clone(),
                    SiteBreach {
                        domain,
                        title: b.title,
                        date,
                        added,
                    },
                );
            }
        }
        Ok::<_, anyhow::Error>(StoredBreaches {
            fetched_at: now(),
            breaches: map,
        })
    };
    tokio::select! {
        res = req => res,
        _ = interrupts.changed() => bail!("locked during breach list refresh"),
    }
}
