//! Agent-side password health: incremental memoization off the session lock,
//! synced finding dismissals, and opt-in HIBP checks.

pub mod hibp;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use data_encoding::HEXLOWER;
use deadbolt_core::autofill::value;
use deadbolt_core::health::{
    IGNORE_ALWAYS, ItemMemo, audited_password_field, build_memo, evaluate, item_fingerprint,
};
use deadbolt_core::{DataOp, Item, ItemId, VaultId};
use deadbolt_store::Unlocked;
use tracing::warn;
use zeroize::Zeroizing;

use super::items::Listing;
use super::session::{Loaded, now, set_json};
use super::{Agent, ErrorCode, caller, fail};
use crate::config::{Config, set_breach_checks};
use crate::import::MirrorVersion;
use crate::import::onepassword::date as op_date;
use crate::protocol::{CallerInfo, Command, HealthReport, Reply};
use hibp::{
    BREACHES_TTL_SECS, Candidate, HibpCache, HibpEntry, META_SITE_BREACHES, StoredBreaches,
    fetch_site_breaches, load_site_breaches, query_candidates,
};

const HIBP_KDF_CONTEXT: &str = "deadbolt 2026-10-30 hibp cache key v1";
const BACKGROUND_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 3600);

pub struct State {
    reuse_key: Zeroizing<[u8; 32]>,
    hibp_key: Zeroizing<[u8; 32]>,
    memos: BTreeMap<(VaultId, ItemId), ItemMemo>,
    hibp_cache: HibpCache,
    site_breaches: Option<StoredBreaches>,
}

impl State {
    pub fn new(store: &Unlocked) -> Self {
        let mut reuse_key = Zeroizing::new([0u8; 32]);
        let _ = getrandom::fill(reuse_key.as_mut_slice());
        let hibp_key = Zeroizing::new(blake3::derive_key(
            HIBP_KDF_CONTEXT,
            store.device_secret(),
        ));
        Self {
            reuse_key,
            hibp_key,
            memos: BTreeMap::new(),
            hibp_cache: HibpCache::load(store),
            site_breaches: load_site_breaches(store),
        }
    }
}

fn fallback_date(item: &Item) -> Option<String> {
    let source = item.source.as_ref()?;
    let version = MirrorVersion::parse(&source.version)?;
    (version.updated > 0)
        .then(|| op_date(version.updated))
        .filter(|d| deadbolt_core::item::valid_date(d))
}

struct PendingItem {
    vault_id: VaultId,
    vault_hex: String,
    vault_name: String,
    item: Item,
    fallback: Option<String>,
}

impl Agent {
    /// Handles `Health`, `HealthIgnore`, and `BreachChecksSet` after checking
    /// that the caller is not an AI agent.
    pub(super) async fn health_command(
        self: &Arc<Self>,
        caller: &CallerInfo,
        command: Command,
    ) -> Result<Reply> {
        if caller::is_ai(caller) {
            return Err(fail(
                ErrorCode::Forbidden,
                "AI agents may not inspect or change password health",
            ));
        }
        match command {
            Command::Health { vault, online } => {
                let want_online = online
                    || Config::load(&self.paths.config)
                        .map(|c| c.breach_checks())
                        .unwrap_or(false);
                if online {
                    self.run_online_breach_check(true).await?;
                } else if want_online {
                    // Best-effort online pass when opted in: offline health
                    // still returns if the network is down.
                    if let Err(err) = self.run_online_breach_check(false).await {
                        warn!("background HIBP check skipped: {err:#}");
                    }
                }
                let report = self.compute_health_report(vault.as_deref()).await?;
                Ok(Reply::Health { report })
            }
            Command::HealthIgnore {
                vault,
                query,
                kind,
                ignored,
            } => {
                self.with(|s| {
                    let vid = s.resolve(vault.as_deref())?;
                    let item = Listing::new(s.vault(&vid)).find(&query)?.clone();
                    let at = if ignored {
                        if kind.binds_to_password() {
                            Some(item.password_entry.unwrap_or(IGNORE_ALWAYS))
                        } else {
                            Some(IGNORE_ALWAYS)
                        }
                    } else {
                        None
                    };
                    s.update(vid, |v, secret| {
                        Ok(v.write(
                            secret,
                            vec![DataOp::ignore(item.id, kind.as_str(), at)],
                        )?)
                    })?;
                    Ok(())
                })?;
                self.sync_now.notify_one();
                let report = self.compute_health_report(vault.as_deref()).await?;
                self.watchers.health();
                Ok(Reply::Health { report })
            }
            Command::BreachChecksSet { enabled } => {
                // Require the store unlocked so changing security settings
                // matches the active session.
                self.with(|_| Ok(()))?;
                set_breach_checks(&self.paths.config, enabled)?;
                if enabled && let Err(err) = self.run_online_breach_check(false).await {
                    warn!("initial HIBP check after opt-in failed: {err:#}");
                }
                self.watchers.health();
                Ok(Reply::Done)
            }
            _ => bail!("not a health command"),
        }
    }

    /// Recomputes `ItemMemo`s for any new or modified items off the session
    /// lock. Returns `true` if any memo changed.
    pub(super) async fn sync_health_memos(&self) -> Result<bool> {
        let (reuse_key, hibp_key, pending, pruned) = self.with(|s| {
            let reuse_key = *s.health.reuse_key;
            let hibp_key = *s.health.hibp_key;
            let mut live_keys = std::collections::BTreeSet::new();
            let mut pending = Vec::new();
            for (&vid, vault) in &s.vaults {
                let vname = vault.name().to_owned();
                let vhex = vid.to_string();
                for item in vault.items() {
                    let key = (vid, item.id);
                    live_keys.insert(key);
                    let fp = item_fingerprint(&reuse_key, &vname, &item);
                    let unchanged = s
                        .health
                        .memos
                        .get(&key)
                        .is_some_and(|m| m.fingerprint == fp);
                    if !unchanged {
                        let fallback = fallback_date(&item);
                        pending.push(PendingItem {
                            vault_id: vid,
                            vault_hex: vhex.clone(),
                            vault_name: vname.clone(),
                            item,
                            fallback,
                        });
                    }
                }
            }
            let before_len = s.health.memos.len();
            s.health.memos.retain(|k, _| live_keys.contains(k));
            let pruned = s.health.memos.len() != before_len;
            Ok((reuse_key, hibp_key, pending, pruned))
        })?;

        if pending.is_empty() {
            return Ok(pruned);
        }

        let reuse_key = Zeroizing::new(reuse_key);
        let worker_reuse = reuse_key.clone();
        let hibp_key = Zeroizing::new(hibp_key);
        let built: Vec<(VaultId, ItemId, ItemMemo)> = tokio::task::spawn_blocking(move || {
            pending
                .into_iter()
                .map(|p| {
                    let id = p.item.id;
                    let memo = build_memo(
                        &worker_reuse,
                        &hibp_key,
                        &p.vault_hex,
                        &p.vault_name,
                        &p.item,
                        p.fallback,
                    );
                    (p.vault_id, id, memo)
                })
                .collect()
        })
        .await?;

        self.with(|s| {
            if *s.health.reuse_key != *reuse_key {
                return Ok(false);
            }
            let mut inserted = false;
            for (vid, iid, memo) in built {
                let Some(vault) = s.vaults.get(&vid) else {
                    continue;
                };
                let Some(current) = vault.item(&iid).filter(|i| !i.deleted) else {
                    continue;
                };
                if item_fingerprint(&s.health.reuse_key, vault.name(), &current) == memo.fingerprint
                {
                    s.health.memos.insert((vid, iid), memo);
                    inserted = true;
                }
            }
            Ok(pruned || inserted)
        })
    }

    pub(super) async fn compute_health_report(
        &self,
        vault_query: Option<&str>,
    ) -> Result<HealthReport> {
        self.sync_health_memos().await?;
        let breach_checks_enabled = Config::load(&self.paths.config)
            .map(|c| c.breach_checks())
            .unwrap_or(false);
        self.with(|s| {
            let target_vault = match vault_query {
                Some("*") => None,
                other => {
                    if s.vaults.is_empty() {
                        None
                    } else {
                        Some(s.resolve(other)?.to_string())
                    }
                }
            };
            let memos: Vec<ItemMemo> = s.health.memos.values().cloned().collect();
            let hibp_counts = s.health.hibp_cache.counts_map();
            let refreshed = s.health.site_breaches.as_ref().map(|b| &b.breaches);
            let (counts, items) = evaluate(
                &memos,
                target_vault.as_deref(),
                &hibp_counts,
                refreshed,
            );
            Ok(HealthReport {
                vault: target_vault,
                counts,
                items,
                breach_checks_enabled,
                breach_last_checked: s.health.hibp_cache.last_checked,
            })
        })
    }

    /// Queries uncached or expired passwords against HIBP (and refreshes the
    /// site breach list weekly). When `strict` is true (`--online`), network
    /// errors are returned to the caller.
    pub(super) async fn run_online_breach_check(&self, strict: bool) -> Result<bool> {
        let mut interrupts = self.interrupts.subscribe();
        let now_secs = now();
        let today_day = (now_secs / 86_400) as u32;

        let (candidates, need_site_breaches) = self.with(|s| {
            let hibp_key = *s.health.hibp_key;
            let mut candidates = Vec::new();
            for vault in s.vaults.values() {
                for item in vault.items() {
                    let Some(pw_field) = audited_password_field(&item.kind) else {
                        continue;
                    };
                    let Some(pw) = value(&item, pw_field) else {
                        continue;
                    };
                    let cand = Candidate::from_password(&hibp_key, pw);
                    if s.health
                        .hibp_cache
                        .fresh_count(&cand.hibp_key, today_day)
                        .is_none()
                    {
                        candidates.push(cand);
                    }
                }
            }
            let need_breaches = s
                .health
                .site_breaches
                .as_ref()
                .is_none_or(|b| now_secs.saturating_sub(b.fetched_at) >= BREACHES_TTL_SECS);
            Ok((candidates, need_breaches))
        })?;

        let mut changed = false;

        if !candidates.is_empty() {
            match query_candidates(candidates, &mut interrupts).await {
                Ok(results) => {
                    if interrupts.has_changed().unwrap_or(true) {
                        return Err(fail(ErrorCode::Locked, "locked during breach check"));
                    }
                    let checked_at = now();
                    let day = (checked_at / 86_400) as u32;
                    self.with(|s| {
                        let Loaded { store, health, .. } = &mut **s;
                        for (key, count) in results {
                            health
                                .hibp_cache
                                .entries
                                .insert(HEXLOWER.encode(&key), HibpEntry { count, day });
                        }
                        health.hibp_cache.last_checked = Some(checked_at);
                        health.hibp_cache.save(store)
                    })?;
                    changed = true;
                }
                Err(err) if strict => return Err(err),
                Err(err) => warn!("HIBP range check failed: {err:#}"),
            }
        } else if strict {
            // Even when every password hit the local cache, update `last_checked`
            // on an explicit manual check so the UI reflects it.
            let checked_at = now();
            self.with(|s| {
                let Loaded { store, health, .. } = &mut **s;
                health.hibp_cache.last_checked = Some(checked_at);
                health.hibp_cache.save(store)
            })?;
            changed = true;
        }

        if need_site_breaches {
            match fetch_site_breaches(&mut interrupts).await {
                Ok(breaches) => {
                    if !interrupts.has_changed().unwrap_or(true) {
                        let _ = self.with(|s| {
                            set_json(&s.store, META_SITE_BREACHES, &breaches)?;
                            s.health.site_breaches = Some(breaches);
                            Ok(())
                        });
                        changed = true;
                    }
                }
                // Bundled `breaches.json` already covers offline site breaches,
                // so a custom range-only test server or offline run need not
                // serve `/breaches`.
                Err(err) => warn!("HIBP site-breach list refresh skipped: {err:#}"),
            }
        }

        Ok(changed)
    }
}

/// Runs on unlock (`Session::health_task`): warms the `zxcvbn` memo in the
/// background without delaying unlock, and when `breach_checks = true`, checks
/// uncached/expired HIBP entries once a day while unlocked.
pub async fn run_background(agent: Arc<Agent>) {
    if let Ok(true) = agent.sync_health_memos().await {
        agent.watchers.health();
    }
    let mut interval = tokio::time::interval(BACKGROUND_REFRESH_INTERVAL);
    loop {
        interval.tick().await;
        let enabled = Config::load(&agent.paths.config)
            .map(|c| c.breach_checks())
            .unwrap_or(false);
        if !enabled {
            continue;
        }
        match agent.run_online_breach_check(false).await {
            Ok(true) => agent.watchers.health(),
            Ok(false) => {}
            Err(_) => return,
        }
    }
}
