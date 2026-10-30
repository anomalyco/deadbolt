//! Approval policy, serialized Touch ID prompt queue, denial cooldowns and
//! optional 15-minute terminal-tab grants for SSH signing (`docs/ssh-agent.md`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use deadbolt_core::VaultId;
use tokio::sync::watch;

use super::super::activity::anchor;
use super::super::{Agent, ErrorCode, biometric, caller, fail, session};
use super::bind::BoundHop;
use super::select::known_host_label;
use super::wire::{SignTarget, clean_label};
use crate::browser::host::Bucket;
use crate::config::{Config, SshApproval};
use crate::protocol::CallerInfo;

const MAX_QUEUED_PER_ANCHOR: usize = 3;
const MAX_DENIALS: usize = 3;
const DENIAL_WINDOW_SECS: u64 = 10 * 60;
const GRANT_IDLE_SECS: u64 = 15 * 60;
const GRANT_MAX_SECS: u64 = 60 * 60;
const LOCKED_TICKET_SECS: u64 = 15;
const LOOK_RATE: (u32, Duration) = (20, Duration::from_secs(1));
const MAX_ANCHOR_BUCKETS: usize = 512;

#[derive(Debug, Clone)]
struct SshGrant {
    tty: String,
    session_started: Option<u64>,
    vault_id: VaultId,
    item_id: String,
    created: u64,
    last_used: u64,
}

impl SshGrant {
    fn live(&self, now: u64) -> bool {
        now.saturating_sub(self.last_used) < GRANT_IDLE_SECS
            && now.saturating_sub(self.created) < GRANT_MAX_SECS
    }

    fn matches(&self, caller: &CallerInfo, vault_id: VaultId, item_id: &str, now: u64) -> bool {
        let Some(tty) = &caller.tty else {
            return false;
        };
        self.live(now)
            && &self.tty == tty
            && self.session_started == caller.session_started
            && self.vault_id == vault_id
            && self.item_id == item_id
    }
}

/// One-time ticket issued on a single `ssh.sock` connection when a locked
/// store unlocked via Touch ID specifically for a `session-bind`-verified
/// local server host key, sparing a second back-to-back tap 50 ms later.
#[derive(Debug, Clone)]
pub struct UnlockTicket {
    pub session_id: Vec<u8>,
    pub hostkey_blob: Vec<u8>,
    pub issued_at: u64,
}

impl UnlockTicket {
    pub fn matches(&self, target: &SignTarget, hop: Option<&BoundHop>, now: u64) -> bool {
        if now.saturating_sub(self.issued_at) > LOCKED_TICKET_SECS {
            return false;
        }
        let (Some(hop), SignTarget::UserAuth { session_id, .. }) = (hop, target) else {
            return false;
        };
        !hop.is_forwarding
            && session_id == &self.session_id
            && hop.hostkey_blob == self.hostkey_blob
    }
}

#[derive(Default)]
pub struct PolicyState {
    prompt_gate: tokio::sync::Mutex<()>,
    active_cancel: Mutex<Option<Arc<biometric::CancelHandle>>>,
    waiters: Mutex<HashMap<String, usize>>,
    denials: Mutex<HashMap<String, Vec<u64>>>,
    grants: Mutex<Vec<SshGrant>>,
    look_rates: Mutex<HashMap<String, Bucket>>,
}

struct QueueGuard<'a> {
    waiters: &'a Mutex<HashMap<String, usize>>,
    key: String,
}

impl Drop for QueueGuard<'_> {
    fn drop(&mut self) {
        let mut map = self.waiters.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = map.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.key);
            }
        }
    }
}

impl PolicyState {
    pub fn clear_on_lock(&self) {
        self.cancel_prompt();
        self.grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    pub fn cancel_prompt(&self) {
        if let Some(cancel) = self
            .active_cancel
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            cancel.cancel();
        }
    }

    pub fn check_look_rate(&self, caller: &CallerInfo) -> Result<()> {
        let now = Instant::now();
        let mut rates = self.look_rates.lock().unwrap_or_else(|e| e.into_inner());
        if rates.len() >= MAX_ANCHOR_BUCKETS {
            rates.clear();
        }
        let ok = rates
            .entry(anchor(caller))
            .or_insert_with(|| Bucket::new(LOOK_RATE, now))
            .take(now);
        if !ok {
            return Err(fail(
                ErrorCode::RateLimited,
                "too many SSH key lookups from this caller; try again shortly",
            ));
        }
        Ok(())
    }

    pub(super) fn check_cooldown(&self, key: &str, now: u64) -> Result<()> {
        let mut map = self.denials.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(times) = map.get_mut(key) {
            times.retain(|&t| now.saturating_sub(t) < DENIAL_WINDOW_SECS);
            if times.len() >= MAX_DENIALS {
                return Err(fail(
                    ErrorCode::RateLimited,
                    "too many cancelled SSH approval prompts from this caller; paused for 10 minutes",
                ));
            }
            if times.is_empty() {
                map.remove(key);
            }
        }
        Ok(())
    }

    fn record_denial(&self, key: &str, now: u64) {
        let mut map = self.denials.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_ANCHOR_BUCKETS && !map.contains_key(key) {
            map.clear();
        }
        let times = map.entry(key.to_owned()).or_default();
        times.retain(|&t| now.saturating_sub(t) < DENIAL_WINDOW_SECS);
        times.push(now);
    }

    fn use_grant(&self, caller: &CallerInfo, vault_id: VaultId, item_id: &str, now: u64) -> bool {
        let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        grants.retain(|g| g.live(now));
        if let Some(grant) = grants
            .iter_mut()
            .find(|g| g.matches(caller, vault_id, item_id, now))
        {
            grant.last_used = now;
            return true;
        }
        false
    }

    fn save_grant(&self, caller: &CallerInfo, vault_id: VaultId, item_id: &str, now: u64) {
        let Some(tty) = caller.tty.clone() else {
            return;
        };
        let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        grants.retain(|g| g.live(now) && !g.matches(caller, vault_id, item_id, now));
        grants.push(SshGrant {
            tty,
            session_started: caller.session_started,
            vault_id,
            item_id: item_id.to_owned(),
            created: now,
            last_used: now,
        });
    }

    fn enqueue(&self, key: &str) -> Result<QueueGuard<'_>> {
        let mut map = self.waiters.lock().unwrap_or_else(|e| e.into_inner());
        let count = map.entry(key.to_owned()).or_default();
        if *count >= MAX_QUEUED_PER_ANCHOR {
            return Err(fail(
                ErrorCode::RateLimited,
                "too many SSH approval prompts waiting for this caller",
            ));
        }
        *count += 1;
        Ok(QueueGuard {
            waiters: &self.waiters,
            key: key.to_owned(),
        })
    }
}

pub struct SignContext<'a> {
    pub caller: &'a CallerInfo,
    pub vault_id: VaultId,
    pub vault_name: &'a str,
    pub item_id: &'a str,
    pub item_title: &'a str,
    pub target: &'a SignTarget,
    pub dest_hop: Option<&'a BoundHop>,
    pub first_hop: Option<&'a BoundHop>,
    pub forwarded: bool,
    pub known_hosts: Option<&'a str>,
}

pub fn format_sign_reason(ctx: &SignContext<'_>) -> String {
    let vault = clean_label(ctx.vault_name);
    let title = clean_label(ctx.item_title);
    let who = clean_label(&ctx.caller.label);
    let via = if ctx.forwarded {
        match ctx.first_hop {
            Some(hop) => format!(" (forwarded via {})", hop.fingerprint),
            None => " (forwarded)".into(),
        }
    } else {
        String::new()
    };
    match ctx.target {
        SignTarget::UserAuth { username, .. } => {
            let user = clean_label(username);
            let host = match ctx.dest_hop {
                Some(hop) => ctx
                    .known_hosts
                    .and_then(|kh| known_host_label(kh, &hop.hostkey))
                    .map(|name| format!("{name} ({})", hop.fingerprint))
                    .unwrap_or_else(|| hop.fingerprint.clone()),
                None => "unverified host".into(),
            };
            format!("sign in as \"{user}\" to {host}{via} with {vault} › {title} ({who})")
        }
        SignTarget::SshSig { namespace } => {
            let ns = clean_label(namespace);
            format!("sign a \"{ns}\" message{via} with {vault} › {title} ({who})")
        }
        SignTarget::Raw { .. } => {
            format!("sign raw data{via} with {vault} › {title} ({who})")
        }
    }
}

impl Agent {
    /// Approves one SSH signature (`ssh.sock` or `Command::SshSign`).
    pub(super) async fn approve_ssh_sign(
        &self,
        ctx: &SignContext<'_>,
        mut ticket: Option<&mut Option<UnlockTicket>>,
        mut client_closed: watch::Receiver<bool>,
    ) -> Result<()> {
        let now = session::now();
        let anchor_key = anchor(ctx.caller);
        let policy = &self.ssh.policy;
        policy.check_cooldown(&anchor_key, now)?;

        // Check debug-only test override (`DEADBOLT_TEST_SSH_APPROVE=allow|deny`).
        if let Some(mode) = crate::config::test_env("DEADBOLT_TEST_SSH_APPROVE") {
            return match mode.trim() {
                "allow" => Ok(()),
                "deny" => {
                    policy.record_denial(&anchor_key, now);
                    Err(fail(ErrorCode::Forbidden, "SSH approval denied"))
                }
                other => Err(anyhow!("unknown DEADBOLT_TEST_SSH_APPROVE={other:?}")),
            };
        }

        // Single-use ticket from a locked `REQUEST_IDENTITIES` Touch ID tap on
        // this exact bound connection.
        if let Some(slot) = ticket.as_mut()
            && let Some(tok) = slot.take()
            && tok.matches(ctx.target, ctx.dest_hop, now)
        {
            return Ok(());
        }

        let approval_mode = Config::load(&self.paths.config)
            .map(|c| c.ssh_approval())
            .unwrap_or_default();
        let eligible_for_grant = approval_mode == SshApproval::FifteenMinutes
            && ctx.caller.tty.is_some()
            && !caller::is_ai(ctx.caller)
            && !ctx.forwarded
            && !matches!(ctx.target, SignTarget::Raw { .. });

        if eligible_for_grant && policy.use_grant(ctx.caller, ctx.vault_id, ctx.item_id, now) {
            return Ok(());
        }

        if !self.can_verify() {
            return Err(fail(
                ErrorCode::Forbidden,
                "SSH key approval requires Touch ID; enable it in Deadbolt Settings or run `deadbolt touchid on`",
            ));
        }

        let _queued = policy.enqueue(&anchor_key)?;
        let _gate = tokio::select! {
            guard = policy.prompt_gate.lock() => guard,
            _ = wait_closed(&mut client_closed) => {
                return Err(anyhow!("SSH client disconnected while waiting for Touch ID"));
            }
        };
        // Re-check cooldown and grant in case an earlier queued request from
        // the same terminal tab just granted or tripped cooldown.
        let now = session::now();
        policy.check_cooldown(&anchor_key, now)?;
        if eligible_for_grant && policy.use_grant(ctx.caller, ctx.vault_id, ctx.item_id, now) {
            return Ok(());
        }

        let reason = format_sign_reason(ctx);
        let _busy = self.busy();
        match self.prompt_ssh_touch_id(&reason, &mut client_closed).await {
            Ok(()) => {
                if eligible_for_grant {
                    policy.save_grant(ctx.caller, ctx.vault_id, ctx.item_id, session::now());
                }
                Ok(())
            }
            Err(PromptOutcome::UserDenied(err)) => {
                policy.record_denial(&anchor_key, session::now());
                Err(fail(ErrorCode::Forbidden, err.to_string()))
            }
            Err(PromptOutcome::Aborted(err)) => Err(err),
        }
    }

    /// Unlocks a locked store on `ssh.sock` (`REQUEST_IDENTITIES`) when
    /// `touch_id_ready` is true, returning an optional single-use
    /// [`UnlockTicket`] when the connection is already bound to a local server.
    pub(super) async fn unlock_for_ssh(
        self: &Arc<Self>,
        caller: &CallerInfo,
        dest_hop: Option<&BoundHop>,
        known_hosts: Option<&str>,
    ) -> Result<Option<UnlockTicket>> {
        let now = session::now();
        let anchor_key = anchor(caller);
        self.ssh.policy.check_cooldown(&anchor_key, now)?;

        let st = self.status();
        if st.unlocked {
            return Ok(None);
        }
        if !st.touch_id_ready {
            return Err(fail(ErrorCode::Locked, "Deadbolt is locked"));
        }

        let local_hop = dest_hop.filter(|h| !h.is_forwarding);
        let reason = match local_hop {
            Some(hop) => {
                let host = known_hosts
                    .and_then(|kh| known_host_label(kh, &hop.hostkey))
                    .unwrap_or_else(|| hop.fingerprint.clone());
                format!(
                    "unlock Deadbolt and sign in to {host} ({})",
                    clean_label(&caller.label)
                )
            }
            None => format!("unlock Deadbolt for {}", clean_label(&caller.label)),
        };
        let _busy = self.busy();
        let was_leader = match self.unlock_biometric_with_reason(None, &reason).await {
            Ok(was_leader) => was_leader,
            Err(err) => {
                if err.to_string().contains("cancelled") || err.to_string().contains("timed out") {
                    self.ssh.policy.record_denial(&anchor_key, session::now());
                }
                return Err(err);
            }
        };
        Ok(local_hop.filter(|_| was_leader).map(|hop| UnlockTicket {
            session_id: hop.session_id.clone(),
            hostkey_blob: hop.hostkey_blob.clone(),
            issued_at: session::now(),
        }))
    }

    async fn prompt_ssh_touch_id(
        &self,
        reason: &str,
        client_closed: &mut watch::Receiver<bool>,
    ) -> std::result::Result<(), PromptOutcome> {
        let token = self
            .with(|s| Ok(s.store.biometric_token()?))
            .map_err(PromptOutcome::Aborted)?
            .ok_or_else(|| PromptOutcome::Aborted(anyhow!("Touch ID is not set up")))?;

        let cancel = biometric::CancelHandle::new();
        *self
            .ssh
            .policy
            .active_cancel
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(cancel.clone());

        let unseal = {
            let cancel = cancel.clone();
            let reason = reason.to_owned();
            #[cfg(test)]
            let hook = self
                .biometric_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            tokio::task::spawn_blocking(move || {
                #[cfg(test)]
                if let Some(hook) = hook {
                    return hook(&cancel);
                }
                biometric::unseal_token(
                    &token,
                    session::now(),
                    &reason,
                    &cancel,
                    biometric::PROMPT_TIMEOUT,
                )
            })
        };

        let unsealed = tokio::select! {
            res = unseal => res,
            () = wait_closed(client_closed) => {
                cancel.cancel();
                *self.ssh.policy.active_cancel.lock().unwrap_or_else(|e| e.into_inner()) = None;
                return Err(PromptOutcome::Aborted(anyhow!("SSH client disconnected")));
            }
        };
        *self
            .ssh
            .policy
            .active_cancel
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;

        let key = match unsealed.map_err(|e| PromptOutcome::Aborted(e.into()))? {
            Ok(key) => key,
            Err(biometric::UnlockError::Cancelled) => {
                if cancel.is_cancelled() {
                    return Err(PromptOutcome::Aborted(anyhow!(
                        "Touch ID prompt was cancelled"
                    )));
                }
                return Err(PromptOutcome::UserDenied(anyhow!("Touch ID was cancelled")));
            }
            Err(biometric::UnlockError::Unavailable(msg)) if msg.contains("timed out") => {
                return Err(PromptOutcome::UserDenied(anyhow!("Touch ID timed out")));
            }
            Err(err) => return Err(PromptOutcome::Aborted(anyhow!("Touch ID failed: {err}"))),
        };
        let valid = self
            .with(|s| Ok(s.store.check_biometric(&key)?))
            .map_err(PromptOutcome::Aborted)?;
        if !valid {
            return Err(PromptOutcome::Aborted(anyhow!(
                "Touch ID returned a key this vault doesn't know"
            )));
        }
        Ok(())
    }
}

enum PromptOutcome {
    UserDenied(anyhow::Error),
    Aborted(anyhow::Error),
}

async fn wait_closed(rx: &mut watch::Receiver<bool>) {
    if *rx.borrow() {
        return;
    }
    #[expect(
        clippy::let_underscore_must_use,
        reason = "dropped sender also means the connection closed"
    )]
    let _ = rx.wait_for(|closed| *closed).await;
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod policy_tests;
