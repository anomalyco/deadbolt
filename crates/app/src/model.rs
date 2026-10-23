//! The app's state and what each input and agent reply does to it. No
//! drawing here; `view.rs` reads this.

use std::time::Duration;

use deadbolt_client::protocol::{FieldInfo, ItemInfo, Status};
use rune::{Key, KeyEvent, TextEdit, Tx};
use zeroize::Zeroize;

use crate::agent::{Agent, Done, Failure, Job};
use crate::clipboard::{Clipboard, Copied};
use crate::secret::SecretEdit;

/// How long a copied secret stays on the clipboard.
pub const CLEAR_AFTER: f64 = 30.0;
/// How long "Clipboard cleared" stays before the notice leaves.
const CLEARED_NOTICE: f64 = 1.6;
/// Countdown bar updates while a copy is on the clipboard (the bar smooths between them).
const TICK: Duration = Duration::from_millis(100);
/// The countdown bar's full width, in points.
pub const BAR_W: f32 = 272.0;
/// How often to notice a lock from elsewhere (the CLI, the idle timeout).
const STATUS_EVERY: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq)]
pub enum Screen {
    Connecting,
    /// No device set up yet; the CLI does that for now.
    NotSetUp,
    Locked,
    Vault,
    Failed(String),
}

/// A secret on the clipboard and its countdown.
pub struct Copy {
    /// "Password", "Username", …
    pub what: String,
    /// The field it came from, for the copy button's checkmark.
    pub item: String,
    pub field: String,
    pub at: f64,
    pub copied: Option<Copied>,
    /// When the clipboard was cleared (or the copy failed), for the closing notice.
    pub cleared_at: Option<f64>,
    /// The whole seconds the notice shows.
    pub shown: u32,
    pub error: Option<String>,
}

impl Copy {
    pub fn remaining(&self, now: f64) -> f64 {
        (CLEAR_AFTER - (now - self.at)).max(0.0)
    }
}

pub struct App {
    pub agent: Agent,
    pub clipboard: Clipboard,
    pub screen: Screen,
    pub status: Option<Status>,
    pub passphrase: SecretEdit,
    pub unlocking: bool,
    pub unlock_error: Option<String>,
    pub search: TextEdit,
    pub items: Vec<ItemInfo>,
    pub loaded: bool,
    pub selected: Option<String>,
    /// The selected item with its values.
    pub detail: Option<ItemInfo>,
    pub revealed: Vec<String>,
    pub copy: Option<Copy>,
    pub notice: Option<String>,
    pub reduced_motion: bool,
    /// Seconds on Rune's clock (virtual when headless).
    pub clock: f64,
    /// The countdown bar's presented rect, set on each tick without rebuilding the view.
    pub bar: rune::Live<[f32; 4]>,
    seq: u64,
    /// A copy waiting for its item's values: (seq, field).
    pending_copy: Option<(u64, String)>,
    next_status: f64,
}

impl App {
    pub fn new(agent: Agent, clipboard: Clipboard) -> App {
        App {
            agent,
            clipboard,
            screen: Screen::Connecting,
            status: None,
            passphrase: SecretEdit::default(),
            unlocking: false,
            unlock_error: None,
            search: TextEdit::new(""),
            items: Vec::new(),
            loaded: false,
            selected: None,
            detail: None,
            revealed: Vec::new(),
            copy: None,
            notice: None,
            reduced_motion: false,
            clock: 0.0,
            bar: rune::Live::new([0.0, 0.0, BAR_W, 2.0]),
            seq: 0,
            pending_copy: None,
            next_status: STATUS_EVERY.as_secs_f64(),
        }
    }

    // ---------------------------------------------------------------------------------------
    // Agent replies

    /// Applies what the agent sent back. True when anything changed.
    pub fn poll(&mut self, now: f64, tx: &mut Tx) -> bool {
        self.clock = now;
        let mut changed = false;
        for done in self.agent.drain() {
            self.apply(done, tx);
            changed = true;
        }
        changed |= self.tick_copy(now, tx);
        if self.screen == Screen::Vault && now >= self.next_status {
            self.next_status = now + STATUS_EVERY.as_secs_f64();
            self.agent.send(Job::Status);
            tx.wake_after(STATUS_EVERY);
        }
        changed
    }

    pub fn apply(&mut self, done: Done, tx: &mut Tx) {
        match done {
            Done::Connected(Ok(status)) | Done::Status(Some(status)) => self.on_status(status, tx),
            Done::Connected(Err(failure)) => self.screen = Screen::Failed(failure.message),
            Done::Status(None) => self.fail("The agent stopped.".into(), tx),
            Done::Unlocked(result) => {
                self.unlocking = false;
                match result {
                    Ok(()) => {
                        self.unlock_error = None;
                        self.agent.send(Job::Status);
                        self.agent.send(Job::List);
                        self.enter_vault(tx);
                    }
                    Err(failure) => {
                        self.unlock_error = Some(unlock_message(&failure));
                        self.passphrase.mask.focused = true;
                    }
                }
            }
            Done::Locked(result) => match result {
                Ok(()) => self.on_locked(tx),
                Err(failure) => self.notice = Some(failure.message),
            },
            Done::Items(result) => match result {
                Ok(items) => {
                    self.items = items;
                    self.loaded = true;
                    self.keep_selection_visible();
                }
                Err(failure) => self.on_failure(failure, tx),
            },
            Done::Item { seq, result } => {
                if seq != self.seq {
                    if let Ok(mut item) = result {
                        forget(&mut item);
                    }
                    return;
                }
                match result {
                    Ok(item) => {
                        self.set_detail(Some(item));
                        if let Some((pending, field)) = self.pending_copy.take()
                            && pending == seq
                        {
                            self.copy_field(&field, tx);
                        }
                    }
                    Err(failure) => self.on_failure(failure, tx),
                }
                // The selected item's fields land in place, not animated: the selection
                // moved under the user's own hand.
                tx.instant();
            }
        }
    }

    fn on_status(&mut self, status: Status, tx: &mut Tx) {
        let screen = if !status.initialized {
            Screen::NotSetUp
        } else if !status.unlocked {
            Screen::Locked
        } else {
            Screen::Vault
        };
        let was = self.screen.clone();
        self.status = Some(status);
        match (&was, &screen) {
            (Screen::Vault, Screen::Vault) => {}
            (_, Screen::Vault) => {
                self.agent.send(Job::List);
                self.enter_vault(tx);
            }
            (Screen::Vault, Screen::Locked) => self.on_locked(tx),
            (_, Screen::Locked) => {
                self.screen = Screen::Locked;
                self.passphrase.mask.focused = true;
            }
            _ => self.screen = screen,
        }
    }

    fn enter_vault(&mut self, tx: &mut Tx) {
        self.screen = Screen::Vault;
        self.search.focused = true;
        self.next_status = self.clock + STATUS_EVERY.as_secs_f64();
        tx.wake_after(STATUS_EVERY);
    }

    fn on_failure(&mut self, failure: Failure, tx: &mut Tx) {
        if failure.locked() {
            self.on_locked(tx);
        } else {
            self.notice = Some(failure.message);
        }
    }

    fn fail(&mut self, message: String, tx: &mut Tx) {
        self.forget_vault(tx);
        self.screen = Screen::Failed(message);
    }

    /// The store is locked: drop everything read from it.
    fn on_locked(&mut self, tx: &mut Tx) {
        self.forget_vault(tx);
        if let Some(status) = &mut self.status {
            status.unlocked = false;
        }
        self.screen = Screen::Locked;
        self.passphrase.clear();
        self.passphrase.mask.focused = true;
    }

    fn forget_vault(&mut self, _tx: &mut Tx) {
        self.clear_clipboard();
        self.set_detail(None);
        self.items.clear();
        self.loaded = false;
        self.selected = None;
        self.search = TextEdit::new("");
        self.pending_copy = None;
        self.notice = None;
    }

    fn set_detail(&mut self, item: Option<ItemInfo>) {
        if let Some(mut old) = std::mem::replace(&mut self.detail, item) {
            forget(&mut old);
        }
        self.revealed.clear();
    }

    // ---------------------------------------------------------------------------------------
    // Unlock

    pub fn submit_unlock(&mut self) {
        if self.unlocking || self.passphrase.is_empty() {
            return;
        }
        self.unlocking = true;
        self.unlock_error = None;
        self.agent.send(Job::Unlock(self.passphrase.take()));
    }

    pub fn lock(&mut self) {
        self.agent.send(Job::Lock);
    }

    pub fn retry(&mut self) {
        self.screen = Screen::Connecting;
        self.agent.send(Job::Connect);
    }

    // ---------------------------------------------------------------------------------------
    // The list

    /// The items matching the search: every word must appear in the label,
    /// the username or expiry, the type or the short id.
    pub fn visible(&self) -> Vec<&ItemInfo> {
        let words: Vec<String> = self
            .search
            .text
            .split_whitespace()
            .map(str::to_lowercase)
            .collect();
        self.items
            .iter()
            .filter(|item| {
                let hay = [
                    Some(item.label.as_str()),
                    item.detail.as_deref(),
                    Some(item.kind.as_str()),
                    Some(item.short.as_str()),
                ];
                words.iter().all(|w| {
                    hay.iter()
                        .flatten()
                        .any(|h| h.to_lowercase().contains(w.as_str()))
                })
            })
            .collect()
    }

    pub fn selected_item(&self) -> Option<&ItemInfo> {
        let id = self.selected.as_deref()?;
        self.items.iter().find(|i| i.id == id)
    }

    /// After the list or the search changed: keep the selection if it still
    /// matches, else select the first match.
    pub fn keep_selection_visible(&mut self) {
        let visible = self.visible();
        let keep = self
            .selected
            .as_deref()
            .is_some_and(|id| visible.iter().any(|i| i.id == id));
        if !keep {
            let first = visible.first().map(|i| i.id.clone());
            self.select(first);
        }
    }

    pub fn select(&mut self, id: Option<String>) {
        if id == self.selected {
            return;
        }
        self.selected = id.clone();
        self.notice = None;
        self.set_detail(None);
        self.pending_copy = None;
        self.seq += 1;
        if let Some(id) = id {
            self.agent.send(Job::Get { id, seq: self.seq });
        }
    }

    fn step(&mut self, by: isize) {
        let visible = self.visible();
        if visible.is_empty() {
            return;
        }
        let at = self
            .selected
            .as_deref()
            .and_then(|id| visible.iter().position(|i| i.id == id));
        let next = match at {
            Some(i) => (i as isize + by).clamp(0, visible.len() as isize - 1) as usize,
            None => 0,
        };
        let id = visible[next].id.clone();
        self.select(Some(id));
    }

    /// Keys in the search field, before its editor. True when handled.
    pub fn search_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        match ev.key {
            Key::Up => self.step(-1),
            Key::Down => self.step(1),
            Key::Enter => {
                let field = if ev.mods.shift {
                    "username"
                } else {
                    self.primary_field()
                };
                self.copy_selected(field, tx);
            }
            Key::Escape if !self.search.text.is_empty() => {
                self.search.clear();
                self.keep_selection_visible();
            }
            Key::Escape => {}
            _ => return false,
        }
        true
    }

    fn primary_field(&self) -> &'static str {
        match self.selected_item().map(|i| i.kind.as_str()) {
            Some("card") => "number",
            _ => "password",
        }
    }

    // ---------------------------------------------------------------------------------------
    // Copying

    /// Copies a field of the selected item, waiting for its values if needed.
    pub fn copy_selected(&mut self, field: &str, tx: &mut Tx) {
        if self.selected.is_none() {
            return;
        }
        if self.detail.is_some() {
            self.copy_field(field, tx);
        } else {
            self.pending_copy = Some((self.seq, field.into()));
        }
    }

    pub fn copy_field(&mut self, field: &str, tx: &mut Tx) {
        let Some(item) = &self.detail else { return };
        let Some(info) = item.fields.iter().find(|f| f.name == field) else {
            self.notice = Some(format!("{} has no {field}", item.label));
            return;
        };
        let (copied, error) = match self.clipboard.copy(&info.value) {
            Ok(copied) => (Some(copied), None),
            Err(error) => (None, Some(format!("Couldn't copy: {error}"))),
        };
        let item = item.id.clone();
        self.copy = Some(Copy {
            what: title_case(field),
            item,
            field: field.into(),
            at: self.clock,
            cleared_at: error.as_ref().map(|_| self.clock),
            shown: CLEAR_AFTER as u32,
            copied,
            error,
        });
        self.bar.set([0.0, 0.0, BAR_W, 2.0]);
        tx.wake_after(TICK);
    }

    /// Advances the countdown; clears the clipboard when it runs out. True
    /// when the notice's text changes; the bar moves through `bar` alone.
    fn tick_copy(&mut self, now: f64, tx: &mut Tx) -> bool {
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
        let remaining = copy.remaining(now);
        self.bar
            .set([0.0, 0.0, BAR_W * (remaining / CLEAR_AFTER) as f32, 2.0]);
        if remaining <= 0.0 {
            if let Some(c) = copy.copied.take() {
                self.clipboard.clear(c);
            }
            copy.cleared_at = Some(now);
            tx.wake_after(Duration::from_secs_f64(CLEARED_NOTICE));
            return true;
        }
        tx.wake_after(TICK);
        let shown = remaining.ceil() as u32;
        let changed = shown != copy.shown;
        copy.shown = shown;
        changed
    }

    /// Clears our copy off the clipboard now (lock, quit).
    pub fn clear_clipboard(&mut self) {
        if let Some(copy) = self.copy.take()
            && let Some(c) = copy.copied
        {
            self.clipboard.clear(c);
        }
    }

    pub fn toggle_reveal(&mut self, field: &str) {
        match self.revealed.iter().position(|f| f == field) {
            Some(i) => {
                self.revealed.remove(i);
            }
            None => self.revealed.push(field.into()),
        }
    }

    /// App-level keys, before the focused field.
    pub fn on_key(&mut self, ev: &KeyEvent, _tx: &mut Tx) -> bool {
        match ev.key {
            Key::Command('l') if self.screen == Screen::Vault => {
                self.lock();
                true
            }
            _ => false,
        }
    }
}

/// Wipes an item's values.
pub fn forget(item: &mut ItemInfo) {
    for FieldInfo { value, .. } in &mut item.fields {
        value.zeroize();
    }
}

fn unlock_message(failure: &Failure) -> String {
    if failure.message.contains("passphrase") || failure.message.contains("decrypt") {
        "That passphrase didn't unlock this device.".into()
    } else {
        failure.message.clone()
    }
}

pub fn title_case(name: &str) -> String {
    if matches!(name, "url" | "otp" | "cvv" | "pin") {
        return name.to_uppercase();
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Is this field type secret (masked until revealed)?
pub fn is_secret(kind: &str) -> bool {
    matches!(kind, "secret" | "otp")
}
