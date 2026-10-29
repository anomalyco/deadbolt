//! Unlocking (passphrase and Touch ID), locking, and reconnecting.

use deadbolt_client::protocol::Status;
use rune::Tx;

use crate::agent::{Failure, Job};

use super::{App, Screen, take_secret};

type BiometricResult = Result<Status, (Failure, Option<Box<Status>>)>;

impl App {
    pub(super) fn on_unlocked(&mut self, result: Result<Status, Failure>, tx: &mut Tx) {
        self.unlocking = false;
        match result {
            // The status says where to go: the vault, or onboarding if it has none.
            Ok(status) => {
                self.unlock_error = None;
                self.on_status(status, tx);
            }
            Err(failure) if self.screen == Screen::Locked => {
                self.unlock_error = Some(unlock_message(&failure));
                self.passphrase.focused = true;
            }
            Err(_) => {}
        }
    }

    pub(super) fn on_unlocked_biometric(&mut self, result: BiometricResult, tx: &mut Tx) {
        self.touch_id_unlocking = false;
        if self.screen != Screen::Locked {
            return;
        }
        match result {
            Ok(status) => {
                self.unlock_error = None;
                self.on_status(status, tx);
                if self.panel_phase() == Some(crate::panel::Phase::Open) {
                    self.window_focused = true;
                    if let Some(windows) = &self.windows {
                        windows.focus_panel();
                    }
                }
            }
            Err((failure, status)) => {
                if let Some(st) = status {
                    self.status = Some(*st);
                } else if failure.message.contains("Touch ID was reset")
                    && let Some(st) = &mut self.status
                {
                    st.touch_id_ready = false;
                    st.touch_id_reset = true;
                }
                self.unlock_error = biometric_unlock_message(&failure, self.touch_id_reset());
                self.passphrase.focused = true;
                if self.panel.is_some() && !self.window_focused {
                    self.dismiss(tx);
                }
            }
        }
    }

    pub(super) fn on_touch_id_set(&mut self, enabled: bool, result: BiometricResult, tx: &mut Tx) {
        self.touch_id_busy = false;
        match result {
            Ok(status) => {
                self.touch_id_error = None;
                self.on_status(status, tx);
            }
            Err((failure, status)) => {
                if let Some(st) = status {
                    self.on_status(*st, tx);
                } else if let Some(st) = &mut self.status {
                    st.touch_id_enabled = !enabled;
                }
                if failure.locked() {
                    if self.screen != Screen::Locked {
                        self.on_locked(tx);
                    }
                } else {
                    self.touch_id_error = Some(failure.message);
                }
            }
        }
    }

    pub fn touch_id_available(&self) -> bool {
        self.status.as_ref().is_some_and(|s| s.touch_id_available)
    }

    pub fn touch_id_enabled(&self) -> bool {
        self.status.as_ref().is_some_and(|s| s.touch_id_enabled)
    }

    pub fn touch_id_ready(&self) -> bool {
        self.status.as_ref().is_some_and(|s| s.touch_id_ready)
    }

    pub fn touch_id_reset(&self) -> bool {
        self.status.as_ref().is_some_and(|s| s.touch_id_reset)
    }

    pub fn busy_unlocking(&self) -> bool {
        self.unlocking || self.touch_id_unlocking
    }

    /// True when the lock screen is frontmost and should auto-prompt Touch ID
    /// once (launch while locked, main window regaining focus, or panel summon).
    pub fn should_auto_prompt_touch_id(&self) -> bool {
        let active = match self.panel_phase() {
            Some(phase) => phase == crate::panel::Phase::Open,
            None => self.window_focused,
        };
        active
            && self.screen == Screen::Locked
            && self.touch_id_ready()
            && !self.touch_id_prompted
            && !self.busy_unlocking()
            && self.passphrase.text.is_empty()
    }

    /// Prompts Touch ID to unlock the store.
    pub fn unlock_touch_id(&mut self) {
        if self.busy_unlocking() || !self.touch_id_ready() {
            return;
        }
        self.touch_id_prompted = true;
        self.unlock_error = None;
        if self.agent.is_live() {
            self.touch_id_unlocking = true;
            self.agent.send(Job::UnlockBiometric);
        }
    }

    /// The main window gained or lost focus. Focusing the locked window
    /// prompts Touch ID once if a biometric slot is ready; background lock
    /// events wait until the user brings the window forward.
    pub fn main_focus(&mut self, focused: bool, _tx: &mut Tx) {
        self.window_focused = focused;
        if !focused {
            // The macOS Touch ID sheet takes key-window status while it is up;
            // only a genuine focus loss outside a Touch ID prompt resets
            // `touch_id_prompted` for the next time the user returns.
            if !self.touch_id_unlocking {
                self.touch_id_prompted = false;
            }
            return;
        }
        if self.should_auto_prompt_touch_id() {
            self.unlock_touch_id();
        }
    }

    /// Toggles "Unlock with Touch ID" in the Settings popover.
    pub fn toggle_touch_id(&mut self) {
        if self.touch_id_busy || !self.touch_id_available() {
            return;
        }
        let next = !self.touch_id_enabled();
        self.touch_id_error = None;
        if let Some(status) = &mut self.status {
            status.touch_id_enabled = next;
        }
        if self.agent.is_live() {
            self.touch_id_busy = true;
            self.agent.send(Job::TouchIdSet(next));
        }
    }

    pub fn submit_unlock(&mut self) {
        if self.unlocking {
            return;
        }
        if self.passphrase.text.is_empty() {
            if self.touch_id_ready() && !self.touch_id_unlocking {
                self.unlock_touch_id();
            }
            return;
        }
        self.unlocking = true;
        self.unlock_error = None;
        self.agent
            .send(Job::Unlock(take_secret(&mut self.passphrase)));
    }

    /// The passphrase changed: clear the last unlock error.
    pub fn passphrase_changed(&mut self) {
        self.unlock_error = None;
    }

    pub fn lock(&mut self) {
        self.touch_id_prompted = true;
        self.agent.send(Job::Lock);
    }

    pub fn retry(&mut self) {
        self.touch_id_prompted = false;
        self.show(Screen::Connecting);
        self.agent.send(Job::Connect);
    }
}

pub(super) fn unlock_message(failure: &Failure) -> String {
    // "Too many wrong passphrases. Try again in 30 s.", as the agent says.
    if failure.code == Some(deadbolt_client::protocol::ErrorCode::RateLimited) {
        return failure.message.clone();
    }
    if failure.message.contains("passphrase") || failure.message.contains("decrypt") {
        "That passphrase didn't unlock this device.".into()
    } else {
        failure.message.clone()
    }
}

pub(super) fn biometric_unlock_message(failure: &Failure, reset: bool) -> Option<String> {
    if reset
        || failure.message.contains("Touch ID was reset")
        || failure.message.contains("cancelled")
    {
        None
    } else {
        Some("Touch ID couldn't unlock this device. Enter your passphrase.".into())
    }
}
