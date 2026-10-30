//! Key selection, `ssh.toml` rules, `~/.ssh/known_hosts` host matching and
//! `cli/ssh-used` host-key ranking (`docs/ssh-agent.md`).

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use deadbolt_core::{Item, VaultId};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use ssh_key::known_hosts::{HostPatterns, KnownHosts, Marker};
use ssh_key::{HashAlg, PublicKey};

use super::super::session::{Loaded, get_json, hex, set_json};
use super::bind::BoundHop;
use super::keys::ParsedKey;
use super::wire::Identity;

const META_SSH_USED: &str = "cli/ssh-used";
const MAX_HOSTS_REMEMBERED: usize = 512;
const MAX_KEYS_PER_HOST: usize = 16;

type HmacSha1 = Hmac<Sha1>;

/// Optional `$XDG_CONFIG_HOME/deadbolt/ssh.toml` (modelled on 1Password's
/// `agent.toml`, plus `hosts` and `allow_forwarding`).
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshToml {
    #[serde(default)]
    pub allow_forwarding: Option<bool>,
    #[serde(default, rename = "ssh-keys")]
    pub keys: Vec<KeyRule>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRule {
    pub item: Option<String>,
    pub vault: Option<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    pub allow_forwarding: Option<bool>,
}

/// An eligible `ssh` item resolved against `ssh.toml` and the current vault state.
pub struct EligibleKey {
    pub vault_id: VaultId,
    pub vault_name: String,
    pub item: Item,
    pub title: String,
    pub pubkey_blob: Vec<u8>,
    #[cfg(test)]
    pub fingerprint: String,
    pub comment: String,
    pub allow_forwarding: Option<bool>,
    pub hosts: Vec<String>,
}

impl SshToml {
    /// Loads `ssh.toml` if it exists; `Ok(None)` when absent so default-vault
    /// selection applies.
    pub fn load(path: &Path) -> Result<Option<Self>> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text)
                .map(Some)
                .with_context(|| format!("reading {}", path.display())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("reading {}", path.display())),
        }
    }
}

/// Selects and orders the keys to offer for `bound` (`REQUEST_IDENTITIES`) or
/// to authorize for `SIGN_REQUEST`.
pub fn eligible_keys(
    s: &Loaded,
    ssh_toml: Option<&SshToml>,
    known_hosts: Option<&str>,
    bound: Option<&BoundHop>,
) -> Vec<EligibleKey> {
    let mut out = Vec::new();
    let mut seen: HashSet<(VaultId, String)> = HashSet::new();

    match ssh_toml {
        None => {
            if let Ok(default_vault) = s.resolve(None)
                && let Some(v) = s.held(&default_vault)
            {
                for item in v.items() {
                    if let Some(el) = build_eligible(default_vault, v.name(), item, &[], None)
                        && seen.insert((el.vault_id, el.item.id.to_string()))
                    {
                        out.push(el);
                    }
                }
                out.sort_by(|a, b| {
                    a.title
                        .to_lowercase()
                        .cmp(&b.title.to_lowercase())
                        .then_with(|| a.item.id.to_string().cmp(&b.item.id.to_string()))
                });
            }
        }
        Some(cfg) => {
            for rule in &cfg.keys {
                let mut rule_keys = Vec::new();
                for (vid, v) in &s.vaults {
                    if let Some(vq) = &rule.vault
                        && !vault_matches(*vid, v.name(), vq)
                    {
                        continue;
                    }
                    for item in v.items() {
                        if let Some(iq) = &rule.item
                            && !item_matches(&item, iq)
                        {
                            continue;
                        }
                        if let Some(el) =
                            build_eligible(*vid, v.name(), item, &rule.hosts, rule.allow_forwarding)
                            && seen.insert((el.vault_id, el.item.id.to_string()))
                        {
                            rule_keys.push(el);
                        }
                    }
                }
                rule_keys.sort_by(|a, b| {
                    a.title
                        .to_lowercase()
                        .cmp(&b.title.to_lowercase())
                        .then_with(|| a.item.id.to_string().cmp(&b.item.id.to_string()))
                });
                out.extend(rule_keys);
            }
        }
    }

    // Filter out host-scoped keys unless `bound` carries a verified server
    // hostkey matching one of `hosts` in `known_hosts`.
    out.retain(|k| {
        if k.hosts.is_empty() {
            return true;
        }
        let (Some(hop), Some(kh)) = (bound, known_hosts) else {
            return false;
        };
        k.hosts
            .iter()
            .any(|pattern| hostkey_matches_host(kh, &hop.hostkey, pattern))
    });

    // When `bound` names a server hostkey, bubble keys previously approved for
    // that server hostkey to the front (most recent first), avoiding OpenSSH's
    // 6-key `MaxAuthTries` cap without altering the relative order of the rest.
    if let Some(hop) = bound {
        let used = used_for_host(s, &hop.fingerprint);
        if !used.is_empty() {
            out.sort_by(|a, b| {
                let rank_a = used.get(&key_ref(a.vault_id, &a.item));
                let rank_b = used.get(&key_ref(b.vault_id, &b.item));
                match (rank_a, rank_b) {
                    (Some(ta), Some(tb)) => tb.cmp(ta),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                }
            });
        }
    }

    out
}

pub fn to_identities(keys: &[EligibleKey]) -> Vec<Identity> {
    keys.iter()
        .map(|k| Identity {
            pubkey_blob: k.pubkey_blob.clone(),
            comment: k.comment.clone(),
        })
        .collect()
}

/// Records that `(vault_id, item)` signed for `hostkey_fingerprint` at `now`.
pub fn record_used(
    s: &Loaded,
    hostkey_fingerprint: &str,
    vault_id: VaultId,
    item: &Item,
    now: u64,
) -> Result<()> {
    let mut all: BTreeMap<String, BTreeMap<String, u64>> =
        get_json(&s.store, META_SSH_USED)?.unwrap_or_default();
    let host_map = all.entry(hostkey_fingerprint.to_owned()).or_default();
    host_map.insert(key_ref(vault_id, item), now);
    while host_map.len() > MAX_KEYS_PER_HOST {
        let Some(oldest) = host_map
            .iter()
            .min_by_key(|(_, at)| **at)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        host_map.remove(&oldest);
    }
    while all.len() > MAX_HOSTS_REMEMBERED {
        let Some(oldest_host) = all
            .iter()
            .min_by_key(|(_, m)| m.values().copied().max().unwrap_or(0))
            .map(|(h, _)| h.clone())
        else {
            break;
        };
        all.remove(&oldest_host);
    }
    set_json(&s.store, META_SSH_USED, &all)
}

/// Reads `$DEADBOLT_KNOWN_HOSTS` (debug/test switch) else `~/.ssh/known_hosts`.
pub fn read_known_hosts() -> Option<String> {
    let path = crate::config::test_env("DEADBOLT_KNOWN_HOSTS")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            crate::config::env("HOME")
                .ok()
                .filter(|h| !h.is_empty())
                .map(|h| PathBuf::from(h).join(".ssh").join("known_hosts"))
        })?;
    std::fs::read_to_string(path).ok()
}

/// Finds an unhashed hostname in `known_hosts` whose public key equals
/// `hostkey` (used to label Touch ID prompts when possible).
pub fn known_host_label(known_hosts: &str, hostkey: &PublicKey) -> Option<String> {
    let target_fp = hostkey.fingerprint(HashAlg::Sha256);
    let mut found = None;
    for entry in KnownHosts::new(known_hosts).flatten() {
        if entry.public_key().fingerprint(HashAlg::Sha256) != target_fp {
            continue;
        }
        if entry.marker() == Some(&Marker::Revoked) {
            return None;
        }
        if found.is_none()
            && let HostPatterns::Patterns(patterns) = entry.host_patterns()
        {
            for pat in patterns {
                if !pat.starts_with('!') && !pat.contains(['*', '?']) {
                    found = Some(super::wire::clean_label(pat));
                    break;
                }
            }
        }
    }
    found
}

/// Checks whether `known_hosts` associates `hostkey` with `host` (supporting
/// plain patterns, `[host]:port`, `*`/`?` globs, negations and `|1|salt|hash`
/// HMAC-SHA1 hashed entries).
pub fn hostkey_matches_host(known_hosts: &str, hostkey: &PublicKey, host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    let target_fp = hostkey.fingerprint(HashAlg::Sha256);
    let mut matched = false;
    for entry in KnownHosts::new(known_hosts).flatten() {
        if entry.public_key().fingerprint(HashAlg::Sha256) != target_fp {
            continue;
        }
        if entry.marker() == Some(&Marker::Revoked) {
            return false;
        }
        match entry.host_patterns() {
            HostPatterns::Patterns(patterns) => {
                let mut line_match = false;
                let mut negated = false;
                for pat in patterns {
                    let (neg, pat) = match pat.strip_prefix('!') {
                        Some(rest) => (true, rest),
                        None => (false, pat.as_str()),
                    };
                    if glob_match(&pat.to_ascii_lowercase(), &host) {
                        if neg {
                            negated = true;
                        } else {
                            line_match = true;
                        }
                    }
                }
                if line_match && !negated {
                    matched = true;
                }
            }
            HostPatterns::HashedName { salt, hash } => {
                if hashed_host_matches(salt, hash, &host) {
                    matched = true;
                }
            }
        }
    }
    matched
}

fn hashed_host_matches(salt: &[u8], expected: &[u8; 20], host: &str) -> bool {
    let Ok(mut mac) = HmacSha1::new_from_slice(salt) else {
        return false;
    };
    mac.update(host.as_bytes());
    mac.verify_slice(expected).is_ok()
}

fn glob_match(pattern: &str, text: &str) -> bool {
    // Also let `github.com` match `[github.com]:22` or bare `pattern == text`.
    if pattern_matches(pattern.as_bytes(), text.as_bytes()) {
        return true;
    }
    if let Some(inner) = pattern.strip_prefix('[').and_then(|p| p.split_once("]:"))
        && !text.starts_with('[')
    {
        return pattern_matches(inner.0.as_bytes(), text.as_bytes());
    }
    false
}

fn pattern_matches(pat: &[u8], text: &[u8]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (None, 0usize);
    while ti < text.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == b'*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

fn used_for_host(s: &Loaded, hostkey_fingerprint: &str) -> BTreeMap<String, u64> {
    get_json::<BTreeMap<String, BTreeMap<String, u64>>>(&s.store, META_SSH_USED)
        .ok()
        .flatten()
        .and_then(|mut all| all.remove(hostkey_fingerprint))
        .unwrap_or_default()
}

fn key_ref(vault_id: VaultId, item: &Item) -> String {
    format!("{}:{}", hex(vault_id.as_bytes()), item.id)
}

fn vault_matches(id: VaultId, name: &str, query: &str) -> bool {
    let q = query.trim();
    name.eq_ignore_ascii_case(q)
        || (q.len() >= 4
            && q.bytes().all(|b| b.is_ascii_hexdigit())
            && id.to_string().starts_with(&q.to_ascii_lowercase()))
}

fn item_matches(item: &Item, query: &str) -> bool {
    let q = query.trim();
    let lower = q.to_lowercase();
    deadbolt_core::listing::label(item).to_lowercase() == lower
        || (lower.len() >= 4
            && lower.bytes().all(|b| b.is_ascii_hexdigit())
            && item.id.to_string().starts_with(&lower))
}

fn build_eligible(
    vault_id: VaultId,
    vault_name: &str,
    item: Item,
    hosts: &[String],
    allow_forwarding: Option<bool>,
) -> Option<EligibleKey> {
    if item.deleted || item.kind != "ssh" {
        return None;
    }
    let private = item.fields.get("private-key")?.value.as_str();
    let passphrase = item.fields.get("passphrase").map(|f| f.value.as_str());
    let parsed = ParsedKey::parse(private, passphrase).ok()?;
    let pubkey_blob = parsed.public_blob().ok()?;
    #[cfg(test)]
    let fingerprint = parsed.fingerprint();
    let title = deadbolt_core::listing::label(&item);
    let comment = item
        .fields
        .get("comment")
        .map(|f| f.value.trim())
        .filter(|c| !c.is_empty())
        .map(str::to_owned)
        .or_else(|| parsed.comment())
        .unwrap_or_else(|| title.clone());
    Some(EligibleKey {
        vault_id,
        vault_name: vault_name.to_owned(),
        item,
        title,
        pubkey_blob,
        #[cfg(test)]
        fingerprint,
        comment,
        allow_forwarding,
        hosts: hosts.to_vec(),
    })
}

#[cfg(test)]
#[path = "select_tests.rs"]
mod select_tests;
