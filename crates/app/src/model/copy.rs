//! Secret clipboard copies, countdowns, and revealing secret fields.

use std::time::Duration;

use deadbolt_client::protocol::AppAction;
use rune::{SecretCopy, SecretState, Tx};
use zeroize::Zeroize;

use super::App;

/// How long a copied secret stays on the clipboard, by default.
pub const CLEAR_AFTER: f64 = 30.0;
/// How long "Clipboard cleared" stays before the notice leaves.
const CLEARED_NOTICE: f64 = 1.6;
/// A copy Rune clears this close to the countdown's end expired on time,
/// rather than being cleared early by a lock elsewhere.
const EXPIRY_SLACK: f64 = 0.5;
/// The countdown bar's full width, in points.
pub const BAR_W: f32 = 272.0;

/// A secret on the clipboard and its countdown.
pub struct Copy {
    /// The field it came from, for the copy button's checkmark.
    pub item: String,
    pub field: String,
    pub at: f64,
    /// Seconds until the clear.
    pub lasts: f64,
    /// Rune's handle to the copy, until this countdown clears it or ends.
    pub copied: Option<SecretCopy>,
    /// When the clipboard was cleared (or the copy failed), for the closing notice.
    pub cleared_at: Option<f64>,
    /// The whole seconds the notice shows.
    pub shown: u32,
    /// The countdown bar's rect, emptying linearly on the render clock.
    pub bar: rune::Tween<[f32; 4]>,
    pub error: Option<String>,
    /// `at` is stamped from the first frame's clock after the copy, so an
    /// idle stretch before pressing ⏎ never shortens or wipes the countdown.
    started: bool,
}

impl Copy {
    pub fn remaining(&self, now: f64) -> f64 {
        (self.lasts - (now - self.at)).max(0.0)
    }
}

impl App {
    /// Copies a field of the selected item, waiting for its values if needed.
    pub fn copy_selected(&mut self, field: &str, tx: &mut Tx) {
        if self.selected.is_some() {
            self.copy_field(field, tx);
        }
    }

    /// Copies a field of the shown item; its otp (`"otp"` names whichever
    /// field the code comes from) copies the current code. Before its values
    /// come, it copies once they do.
    pub fn copy_field(&mut self, field: &str, tx: &mut Tx) {
        if self.detail.is_none() {
            if self.selected.is_some() {
                self.pending_copy = Some((self.seq, field.into()));
                self.hurry();
            }
            return;
        }
        let code = self
            .otp
            .as_ref()
            .map(|o| (o.field.clone(), field == "otp" || field == o.field));
        let (field, value) = match code {
            Some((code_field, true)) => match self.code_for_copy() {
                Some(code) => (code_field, code),
                None => return,
            },
            _ => {
                // Another copy replaces a code still on its way.
                if let Some(otp) = &mut self.otp {
                    otp.copy_next = false;
                }
                let Some(item) = &self.detail else { return };
                let Some(info) = item.fields.iter().find(|f| f.name == field) else {
                    self.notice = Some(match field {
                        "otp" => format!("{} has no one-time code", item.label),
                        _ => format!("{} has no {field}", item.label),
                    });
                    return;
                };
                (field.to_owned(), info.value.clone())
            }
        };
        self.put_on_clipboard(field, value, tx);
    }

    /// Copies `value`, the shown item's `field`, and starts its countdown.
    pub(super) fn put_on_clipboard(&mut self, field: String, mut value: String, tx: &mut Tx) {
        let Some(item) = self.detail.as_ref().or_else(|| self.selected_item()) else {
            value.zeroize();
            return;
        };
        let saved = (item.id.clone(), item.label.clone());
        self.copy_value(Some(saved), field, value, tx);
    }

    /// Puts `value` on the clipboard, concealed, to clear after the countdown:
    /// `field` of the saved item `item` (id, title), or of a form not saved
    /// yet. Every copy of a value goes through here, so a saved item's is
    /// always reported for Activity. `item` and `field` mark the item's copy
    /// button while it lasts.
    pub(crate) fn copy_value(
        &mut self,
        item: Option<(String, String)>,
        field: String,
        value: String,
        tx: &mut Tx,
    ) {
        if let Some((id, title)) = &item {
            self.report_item(AppAction::Copy, id, title, &field);
        }
        let item = item.map(|(id, _)| id).unwrap_or_default();
        let lasts = Duration::from_secs_f64(self.clear_after);
        let copied = tx.copy_secret(value, lasts);
        self.copy = Some(Copy {
            item,
            field,
            at: self.clock,
            lasts: self.clear_after,
            cleared_at: None,
            shown: self.clear_after.ceil() as u32,
            bar: rune::Tween::linear([0.0, 0.0, BAR_W, 2.0], [0.0, 0.0, 0.0, 2.0], lasts),
            copied: Some(copied),
            error: None,
            started: false,
        });
        self.panel_copied(tx);
        tx.wake_after(self.next_tick(self.clear_after));
    }

    /// When the countdown next needs a look: as its whole seconds change while
    /// it shows, else at its end (the quick panel's copy, once the panel has
    /// moved on). The bar needs no wakes.
    fn next_tick(&self, remaining: f64) -> Duration {
        let shows = self
            .panel
            .as_ref()
            .is_none_or(|p| matches!(p.phase, crate::panel::Phase::Copied { .. }));
        let next_second = remaining - (remaining.ceil() - 1.0) + 1e-3;
        Duration::from_secs_f64(if shows {
            next_second.min(remaining)
        } else {
            remaining
        })
    }

    /// Advances the countdown; clears the clipboard when it runs out. True
    /// when the notice's text changes; the bar moves on its own.
    pub(super) fn tick_copy(&mut self, now: f64, tx: &mut Tx) -> bool {
        let Some(copy) = &mut self.copy else {
            return false;
        };
        if let Some(cleared) = copy.cleared_at {
            if now - cleared >= CLEARED_NOTICE - 1e-3 {
                self.copy = None;
                return true;
            }
            return false;
        }
        if !std::mem::replace(&mut copy.started, true) {
            copy.at = now;
        }
        let mut remaining = copy.remaining(now);
        match copy.copied.as_ref().map(SecretCopy::state) {
            Some(SecretState::Failed(error)) => {
                copy.copied = None;
                copy.error = Some(format!("Couldn't copy: {error}"));
                copy.cleared_at = Some(now);
                tx.wake_after(Duration::from_secs_f64(CLEARED_NOTICE));
                self.panel_copy_failed();
                return true;
            }
            // Something else was copied since (in either window or another app),
            // or a lock cleared it early: this countdown ends quietly; the
            // clipboard is no longer this one's to clear.
            Some(SecretState::Replaced) => {
                self.copy = None;
                return true;
            }
            Some(SecretState::Cleared) if remaining > EXPIRY_SLACK => {
                self.copy = None;
                return true;
            }
            // Rune's own timer, on the wall clock, beat this one to the clear.
            Some(SecretState::Cleared) => remaining = 0.0,
            _ => {}
        }
        if remaining <= 0.0 {
            if let Some(c) = copy.copied.take() {
                c.clear_now();
            }
            copy.cleared_at = Some(now);
            tx.wake_after(Duration::from_secs_f64(CLEARED_NOTICE));
            return true;
        }
        let shown = remaining.ceil() as u32;
        let changed = shown != copy.shown;
        copy.shown = shown;
        tx.wake_after(self.next_tick(remaining));
        changed
    }

    /// Whether a copy is still counting down to its clear.
    pub fn copy_pending(&self) -> bool {
        self.copy.as_ref().is_some_and(|c| c.copied.is_some())
    }

    /// Clears the clipboard now, whichever window copied (lock, quit).
    pub fn clear_clipboard(&mut self, tx: &mut Tx) {
        self.copy = None;
        tx.clear_secret_clipboard();
    }

    pub fn toggle_reveal(&mut self, field: &str) {
        match self.revealed.iter().position(|f| f == field) {
            Some(i) => {
                self.revealed.remove(i);
            }
            None => {
                if self.detail.is_some() {
                    self.report(AppAction::Reveal, field);
                }
                self.revealed.push(field.into());
                self.hurry();
            }
        }
    }
}
