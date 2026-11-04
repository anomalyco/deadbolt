//! The daemon's view of itself: the vault session, the idle timeout that locks
//! it, and the status a client reads.

use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Result, bail};
use deadbolt_net::PeerId;
use tokio::time::Instant;
use tracing::info;

use super::{Daemon, ErrorCode, Session, biometric, caller, fail, session, sync};
use crate::client::{protocol, version};
use crate::config::Config;
use crate::protocol::Status;

impl Daemon {
    /// Waits within the startup budget; the background loop owns the fallback.
    pub(super) async fn wait_ready(&self) -> Result<()> {
        let mut ready = self.ready.subscribe();
        let deadline = Instant::now() + sync::STARTUP_TIMEOUT;
        loop {
            // Mark this version observed before checking the session so a lock
            // between the check and changed() cannot be missed.
            let is_ready = *ready.borrow_and_update();
            self.with(|_| Ok(()))?;
            if is_ready {
                return Ok(());
            }
            match tokio::time::timeout_at(deadline, ready.changed()).await {
                Ok(changed) => changed?,
                Err(_) => {
                    self.with(|_| Ok(()))?;
                    bail!("waiting for membership sync");
                }
            }
        }
    }

    /// Checks readiness before serving vault data to a pairing peer.
    pub(super) fn with_data<T>(&self, f: impl FnOnce(&mut Session) -> Result<T>) -> Result<T> {
        self.with(|s| {
            if !*self.ready.borrow() {
                bail!("waiting for membership sync");
            }
            f(s)
        })
    }

    /// Runs `f` on the unlocked session.
    pub(super) fn with<T>(&self, f: impl FnOnce(&mut Session) -> Result<T>) -> Result<T> {
        let mut guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let Some(session) = guard.as_mut() else {
            return Err(if deadbolt_store::is_initialized(&self.paths.data) {
                fail(ErrorCode::Locked, "locked: run `deadbolt unlock`")
            } else {
                fail(
                    ErrorCode::NotInitialized,
                    "this device is not set up; run `deadbolt init` or `deadbolt join`",
                )
            });
        };
        session.ensure_usable()?;
        let result = f(session);
        if session.append_uncertain {
            // The old membership may have been revoked on disk. Quarantine
            // synchronously, before another request or startup retry can run.
            self.refresh(session);
            self.ready.send_replace(false);
            session.sync_task.take();
            session.health_task.take();
            self.cancel_biometric_prompt();
            self.interrupt_op();
            self.watchers.locked();
            // Keep the failed handle until explicit lock/unlock: recovery must
            // close the node/store and authenticate/replay, never reuse it.
            session.ensure_usable()?;
        }
        // Publish even if `f` failed: it may have committed earlier changes.
        if !session.changes.is_empty() {
            self.watchers.changed(&std::mem::take(&mut session.changes));
        }
        result
    }

    /// Updates the membership gate and closes open sync connections to devices
    /// that are no longer members of any vault.
    pub(super) fn refresh(&self, session: &Session) {
        *self.members.write().unwrap_or_else(|e| e.into_inner()) = session.peer_set();
        let closed = session.node.enforce_membership();
        if closed > 0 {
            info!(closed, "closed sync connections to removed devices");
        }
        if session.unavailable.is_empty()
            && !session.vaults.is_empty()
            && !session.vaults.values().any(|v| v.is_member(&session.id))
        {
            drop(session.store.clear_biometric());
            self.biometric_was_enrolled.store(false, Ordering::SeqCst);
            *self
                .biometric_slot
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = None;
        }
    }

    pub(super) fn is_touch_id_available(&self) -> bool {
        #[cfg(test)]
        if let Some(override_val) = *self
            .touch_id_available_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
        {
            return override_val;
        }
        biometric::cached_status().is_available()
    }

    pub(super) async fn refresh_touch_id_available(&self) -> bool {
        #[cfg(test)]
        if let Some(override_val) = *self
            .touch_id_available_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
        {
            return override_val;
        }
        tokio::task::spawn_blocking(|| biometric::refresh_status().is_available())
            .await
            .unwrap_or(false)
    }

    pub(super) fn status(&self) -> Status {
        let initialized = deadbolt_store::is_initialized(&self.paths.data);
        let touch_id_available = self.is_touch_id_available();
        let touch_id_cfg = Config::load(&self.paths.config)
            .map(|c| c.touch_id())
            .unwrap_or(false);
        let touch_id_enabled = touch_id_available && touch_id_cfg;
        let now = session::now();
        let slot = *self
            .biometric_slot
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let was_enrolled = slot.is_some() || self.biometric_was_enrolled.load(Ordering::SeqCst);
        let slot_ready = touch_id_enabled && initialized && slot.is_some_and(|m| m.is_ready(now));
        let touch_id_ready = slot_ready;
        let touch_id_reset = touch_id_enabled && initialized && was_enrolled && !slot_ready;

        let guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let session = guard.as_ref().filter(|s| !s.append_uncertain);
        let connected: HashSet<PeerId> = session
            .map(|s| s.node.connected_peers().into_iter().collect())
            .unwrap_or_default();
        let peers = session.map(|s| s.peer_set()).unwrap_or_default();
        let idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let unlocked = session.is_some();
        Status {
            pid: std::process::id(),
            version: version(),
            protocol: protocol(),
            program: std::env::current_exe()
                .ok()
                .map(|p| p.display().to_string()),
            home: self.paths.data.display().to_string(),
            initialized,
            unlocked,
            locks_in_secs: idle
                .deadline
                .filter(|_| unlocked)
                .map(|d| d.saturating_duration_since(Instant::now()).as_secs()),
            device: session.map(|s| s.device_info(&s.id, &connected)),
            vaults: session.map(|s| s.vault_infos()).unwrap_or_default(),
            peers_online: session
                .map(|s| peers.iter().filter(|p| s.online(p, &connected)).count())
                .unwrap_or_default(),
            peers: peers.len(),
            touch_id_available,
            touch_id_enabled,
            touch_id_ready,
            touch_id_reset,
            // Filled in for the connection that asked (`handle`).
            caller: caller::nobody(),
            update: self
                .update
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        }
    }

    pub(super) fn touch(&self) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        idle.deadline = idle.timeout.map(|t| Instant::now() + t);
    }

    pub(super) async fn check_idle(&self) {
        let expired = {
            let idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
            idle.deadline.is_some_and(|d| Instant::now() >= d)
                && self.busy.load(Ordering::SeqCst) == 0
        };
        if expired {
            info!("idle timeout; locking");
            self.lock().await;
        }
    }

    /// The idle timeout `timeout_secs` asks for: `Some(0)` is never, `None`
    /// the configured one.
    pub(super) fn requested_timeout(&self, timeout_secs: Option<u64>) -> Result<Option<Duration>> {
        Ok(match timeout_secs {
            Some(0) => None,
            Some(secs) => Some(Duration::from_secs(secs)),
            None => Config::load(&self.paths.config)?.unlock_timeout()?,
        })
    }

    pub(super) fn set_timeout(&self, timeout_secs: Option<u64>) -> Result<()> {
        let timeout = self.requested_timeout(timeout_secs)?;
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        idle.timeout = timeout;
        idle.deadline = timeout.map(|t| Instant::now() + t);
        Ok(())
    }

    /// Sets the idle timeout `timeout_secs` asks for if it's no longer than
    /// the current one, returning whether it did. An unlock request while
    /// unlocked may always shorten it; only a verified passphrase or finger
    /// may lengthen it or make it never.
    pub(super) fn tighten_timeout(&self, timeout_secs: Option<u64>) -> Result<bool> {
        let timeout = self.requested_timeout(timeout_secs)?;
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let tighter = match (timeout, idle.timeout) {
            (_, None) => true,
            (Some(new), Some(current)) => new <= current,
            (None, Some(_)) => false,
        };
        if tighter {
            idle.timeout = timeout;
            idle.deadline = timeout.map(|t| Instant::now() + t);
        }
        Ok(tighter)
    }
}
