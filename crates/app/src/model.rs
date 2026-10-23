//! The app's state and what each input and agent reply does to it. No
//! drawing here; `view.rs` reads this.

use std::time::Duration;

use deadbolt_client::protocol::{Change, FieldInfo, ItemInfo, Status};
use rune::{Key, KeyEvent, TextEdit, Tx};
use zeroize::Zeroize;

use crate::agent::{Agent, Done, Failure, Job};
use crate::clipboard::{Clipboard, Copied};
use crate::onboarding::Onboarding;
use crate::onboarding::worker::Worker;
use crate::secret::SecretEdit;

/// How long a copied secret stays on the clipboard, by default.
pub const CLEAR_AFTER: f64 = 30.0;
/// How long "Clipboard cleared" stays before the notice leaves.
const CLEARED_NOTICE: f64 = 1.6;
/// Countdown bar updates while a copy is on the clipboard (the bar smooths between them).
const TICK: Duration = Duration::from_millis(100);
/// The countdown bar's full width, in points.
pub const BAR_W: f32 = 272.0;

#[derive(Clone, Debug, PartialEq)]
pub enum Screen {
    Connecting,
    /// No device set up yet, or one with no vault: create or join one.
    Onboarding,
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
    /// Seconds until the clear.
    pub lasts: f64,
    pub copied: Option<Copied>,
    /// When the clipboard was cleared (or the copy failed), for the closing notice.
    pub cleared_at: Option<f64>,
    /// The whole seconds the notice shows.
    pub shown: u32,
    pub error: Option<String>,
}

impl Copy {
    pub fn remaining(&self, now: f64) -> f64 {
        (self.lasts - (now - self.at)).max(0.0)
    }
}

pub struct App {
    pub installer: Option<crate::install::Installer>,
    pub agent: Agent,
    pub clipboard: Clipboard,
    /// How long a copied secret stays on the clipboard.
    pub clear_after: f64,
    pub screen: Screen,
    pub status: Option<Status>,
    pub passphrase: SecretEdit,
    pub onboarding: Onboarding,
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
    /// Set in the quick panel's `App` only.
    pub panel: Option<crate::panel::Panel>,
    /// Handles to both windows, when the app runs both (not headless or in tests).
    pub windows: Option<crate::panel::window::Windows>,
    /// Seconds on Rune's clock (virtual when headless).
    pub clock: f64,
    /// The countdown bar's presented rect, set on each tick without rebuilding the view.
    pub bar: rune::Live<[f32; 4]>,
    /// Bumped whenever what was read from the store is forgotten: a list
    /// fetched in an older generation is dropped.
    generation: u64,
    /// Tells the current `Job::Get` from older ones; also bumped on forgetting.
    seq: u64,
    /// A copy waiting for its item's values: (seq, field).
    pending_copy: Option<(u64, String)>,
}

impl App {
    pub fn new(agent: Agent, clipboard: Clipboard) -> App {
        App {
            installer: None,
            agent,
            clipboard,
            clear_after: CLEAR_AFTER,
            screen: Screen::Connecting,
            status: None,
            passphrase: SecretEdit::default(),
            onboarding: Onboarding::new(Worker::offline()),
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
            panel: None,
            windows: None,
            clock: 0.0,
            bar: rune::Live::new([0.0, 0.0, BAR_W, 2.0]),
            generation: 0,
            seq: 0,
            pending_copy: None,
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
        changed |= self.poll_onboarding(now, tx);
        changed |= self.tick_copy(now, tx);
        if let Some(installer) = &mut self.installer {
            changed |= installer.poll(now);
            // The page and Settings belong to the vault; leaving it closes them.
            if self.screen != Screen::Vault && (installer.open || installer.settings_open) {
                installer.open = false;
                installer.settings_open = false;
                changed = true;
            }
        }
        changed |= self.poll_panel(now, tx);
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
                    // The status says where to go: the vault, or onboarding if it has none.
                    Ok(status) => {
                        self.unlock_error = None;
                        self.on_status(status, tx);
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
            // A reply from before a lock (or stop) can land after it: drop
            // anything from an older generation or for a screen that's gone.
            Done::Items { generation, result } => {
                if generation != self.generation || self.screen != Screen::Vault {
                    return;
                }
                // The panel's list lands just after it opens; it opens at rest.
                if self.panel.is_some() && !self.loaded {
                    tx.instant();
                }
                match result {
                    Ok(items) => self.on_items(items),
                    Err(failure) => self.on_failure(failure, tx),
                }
            }
            // Dropping a stale item wipes its values (`agent::Values`).
            Done::Item { seq, result } => {
                if seq != self.seq || self.screen != Screen::Vault {
                    return;
                }
                match result {
                    Ok(item) => {
                        let item = item.take();
                        // A new selection's fields land in place, not animated: the
                        // selection moved under the user's own hand. A refresh of the
                        // shown item animates what changed.
                        if self.detail.as_ref().is_none_or(|d| d.id != item.id) {
                            tx.instant();
                        }
                        self.set_detail(Some(item));
                        if let Some((pending, field)) = self.pending_copy.take()
                            && pending == seq
                        {
                            self.copy_field(&field, tx);
                        }
                    }
                    Err(failure) => self.on_failure(failure, tx),
                }
            }
            Done::Changed(change) => self.on_change(change, tx),
            Done::WatchLost => self.on_agent_gone(tx),
        }
    }

    /// A change the agent streamed. It says what changed; this refetches.
    fn on_change(&mut self, change: Change, tx: &mut Tx) {
        match change {
            // The stream is (again) live, or it dropped changes: fetch it all.
            Change::Watching | Change::Resync => {
                self.agent.send(Job::Status);
                self.refresh();
            }
            Change::Locked if self.screen == Screen::Vault => self.on_locked(tx),
            // Onboarding decides from the status whether it can carry on.
            Change::Locked if self.screen == Screen::Onboarding => self.agent.send(Job::Status),
            Change::Unlocked if self.screen != Screen::Vault => self.agent.send(Job::Status),
            Change::Vaults => {
                self.agent.send(Job::Status);
                self.refresh();
            }
            Change::Devices { .. } => self.agent.send(Job::Status),
            Change::Items { vault } if self.shows(&vault) => self.refresh(),
            Change::Stopping => self.on_agent_gone(tx),
            Change::Locked | Change::Unlocked | Change::Items { .. } => {}
        }
    }

    /// Whether the list shows `vault`: the default vault, or any when that
    /// isn't known.
    fn shows(&self, vault: &str) -> bool {
        self.status
            .as_ref()
            .and_then(|s| s.vaults.iter().find(|v| v.default))
            .is_none_or(|v| v.id == vault)
    }

    /// Refetches the list, and with it the selected item.
    fn refresh(&mut self) {
        if self.screen == Screen::Vault {
            self.list();
        }
    }

    /// Fetches the list for the current generation.
    pub(crate) fn list(&self) {
        self.agent.send(Job::List {
            generation: self.generation,
        });
    }

    /// The current generation, for tagging a list reply in tests and scenes.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// A list arrived. The selection and the search stay; if the selected
    /// item is still there and this replaced a list, its values are fetched
    /// again in place.
    fn on_items(&mut self, items: Vec<ItemInfo>) {
        let refresh = self.loaded;
        let before = self.selected.clone();
        self.items = items;
        self.loaded = true;
        self.keep_selection_visible();
        if refresh
            && self.selected == before
            && let Some(id) = self.selected.clone()
        {
            self.seq += 1;
            if let Some((pending, _)) = &mut self.pending_copy {
                *pending = self.seq;
            }
            self.agent.send(Job::Get { id, seq: self.seq });
        }
    }

    /// The agent stopped, which locked the store. The watch thread finds the
    /// next agent; unlocking starts one.
    fn on_agent_gone(&mut self, tx: &mut Tx) {
        if self.screen == Screen::Vault {
            self.on_locked(tx);
        }
    }

    fn on_status(&mut self, status: Status, tx: &mut Tx) {
        let ready = status.initialized;
        let screen = if !status.initialized {
            Screen::Onboarding
        } else if !status.unlocked {
            Screen::Locked
        } else if status.vaults.is_empty() {
            Screen::Onboarding
        } else {
            Screen::Vault
        };
        let was = self.screen.clone();
        self.status = Some(status);
        if was == Screen::Onboarding && self.onboarding.busy() {
            // A create or join is running or its moment is showing; it moves on by itself.
            self.onboarding.device_ready |= ready;
            return;
        }
        match (&was, &screen) {
            (Screen::Onboarding, Screen::Onboarding) => self.onboarding.device_ready = ready,
            (_, Screen::Onboarding) => {
                self.forget_vault(tx);
                self.begin_onboarding(ready);
            }
            (Screen::Vault, Screen::Vault) => {}
            (_, Screen::Vault) => {
                self.list();
                self.enter_vault(tx);
            }
            (Screen::Vault, Screen::Locked) => self.on_locked(tx),
            (_, Screen::Locked) => {
                self.forget_onboarding();
                self.screen = Screen::Locked;
                self.passphrase.mask.focused = true;
            }
            _ => self.screen = screen,
        }
    }

    pub(crate) fn enter_vault(&mut self, _tx: &mut Tx) {
        self.forget_onboarding();
        self.screen = Screen::Vault;
        self.search.focused = true;
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
        self.forget_onboarding();
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

    /// The window is closing: clear our clipboard copies, wipe what we read
    /// and typed, and hang up a join.
    pub fn close(&mut self, tx: &mut Tx) {
        self.forget_vault(tx);
        self.passphrase.clear();
        self.forget_onboarding();
        self.onboarding.worker.stop();
    }

    fn forget_vault(&mut self, _tx: &mut Tx) {
        self.clear_clipboard();
        self.forget_items();
    }

    /// Forgets what was read from the store and the search, and drops any
    /// reply still on its way. A copy keeps counting down.
    pub(crate) fn forget_items(&mut self) {
        self.generation += 1;
        self.seq += 1;
        self.set_detail(None);
        self.items.clear();
        self.loaded = false;
        self.selected = None;
        self.search = TextEdit::new("");
        self.pending_copy = None;
        self.notice = None;
    }

    /// Replaces the shown values, wiping the old ones. Revealed fields stay
    /// revealed only while the same item is shown.
    fn set_detail(&mut self, item: Option<ItemInfo>) {
        let same = matches!((&self.detail, &item), (Some(a), Some(b)) if a.id == b.id);
        if let Some(mut old) = std::mem::replace(&mut self.detail, item) {
            forget(&mut old);
        }
        if !same {
            self.revealed.clear();
        }
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

    /// A key in the passphrase field. Any change to the passphrase clears
    /// the last unlock error.
    pub fn passphrase_key(&mut self, ev: &KeyEvent) -> bool {
        self.panel_active();
        let edits = self.passphrase.edits();
        let handled = self.passphrase.key(ev);
        if self.passphrase.edits() != edits {
            self.unlock_error = None;
        }
        handled
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
        if let Some(handled) = self.overlay_key(ev) {
            return handled;
        }
        if self.panel_shortcut(ev, tx) {
            return true;
        }
        match ev.key {
            Key::Up | Key::Down => {
                self.step(if ev.key == Key::Up { -1 } else { 1 });
                if let Some(id) = &self.selected {
                    tx.scroll_into_view(format!("item-{id}"));
                }
            }
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
        let copied_ok = error.is_none();
        self.copy = Some(Copy {
            what: title_case(field),
            item,
            field: field.into(),
            at: self.clock,
            lasts: self.clear_after,
            cleared_at: error.as_ref().map(|_| self.clock),
            shown: self.clear_after.ceil() as u32,
            copied,
            error,
        });
        self.bar.set([0.0, 0.0, BAR_W, 2.0]);
        if copied_ok {
            self.panel_copied(tx);
        }
        tx.wake_after(self.next_tick(self.clear_after));
    }

    /// When the countdown next needs a look: every `TICK` while it shows, else
    /// at its end (the quick panel's copy, once the panel has moved on).
    fn next_tick(&self, remaining: f64) -> Duration {
        let shows = self
            .panel
            .as_ref()
            .is_none_or(|p| matches!(p.phase, crate::panel::Phase::Copied { .. }));
        if shows {
            TICK
        } else {
            Duration::from_secs_f64(remaining)
        }
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
        // The other window copied since (or a lock cleared it): this countdown
        // ends quietly; the clipboard is no longer this one's to clear.
        if copy.copied.is_some_and(|c| !self.clipboard.holds(c)) {
            self.copy = None;
            return true;
        }
        let remaining = copy.remaining(now);
        self.bar
            .set([0.0, 0.0, BAR_W * (remaining / copy.lasts) as f32, 2.0]);
        if remaining <= 0.0 {
            if let Some(c) = copy.copied.take() {
                self.clipboard.clear(c);
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
    pub fn clear_clipboard(&mut self) {
        self.copy = None;
        self.clipboard.clear_latest();
    }

    pub fn toggle_reveal(&mut self, field: &str) {
        match self.revealed.iter().position(|f| f == field) {
            Some(i) => {
                self.revealed.remove(i);
            }
            None => self.revealed.push(field.into()),
        }
    }

    /// The install page is showing in place of the vault.
    pub fn installing(&self) -> bool {
        self.screen == Screen::Vault && self.installer.as_ref().is_some_and(|i| i.open)
    }

    /// Keys for the Settings popover or the install page, which sit over the
    /// vault: Escape closes them, Tab moves between their buttons, and
    /// nothing else reaches the vault behind. `None` when neither is open.
    fn overlay_key(&mut self, ev: &KeyEvent) -> Option<bool> {
        // The quick panel has no Settings or install offer; its keys are its own.
        if self.screen != Screen::Vault || self.panel.is_some() {
            return None;
        }
        let installer = self.installer.as_mut()?;
        if !installer.settings_open && !installer.open {
            return None;
        }
        match ev.key {
            Key::Escape if installer.settings_open => installer.settings_open = false,
            Key::Escape => installer.close(),
            Key::Tab => return Some(false),
            _ => {}
        }
        Some(true)
    }

    /// App-level keys: before the focused field when there is none, after it otherwise.
    pub fn on_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        if let Some(handled) = self.overlay_key(ev) {
            return handled;
        }
        if self.panel_shortcut(ev, tx) {
            return true;
        }
        match ev.key {
            Key::Command('l') if self.screen == Screen::Vault => {
                self.lock();
                true
            }
            _ if self.screen == Screen::Onboarding => crate::onboarding::key(self, ev, tx),
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

#[cfg(test)]
mod tests {
    use deadbolt_client::protocol::Change;
    use rune::{Env, Runtime};

    use super::{App, Screen};
    use crate::agent::{Done, Values};

    fn vault() -> Runtime<App> {
        let app = rune::tooling::initial_state(&crate::spec(), Some("vault"));
        Runtime::new(
            app,
            crate::view::app,
            (820.0, 540.0),
            Env {
                system_dark: true,
                scale: 1.0,
            },
        )
    }

    fn panel(scene: &str) -> Runtime<App> {
        let app = rune::tooling::initial_state(&crate::panel::spec(), Some(scene));
        let mut rt = Runtime::new(
            app,
            crate::panel::view::panel,
            crate::panel::SIZE,
            Env {
                system_dark: true,
                scale: 1.0,
            },
        );
        rt.poll = Some(|s, now, tx| s.poll(now, tx));
        rt.frame(0.0);
        rt
    }

    fn forgotten(app: &App) -> bool {
        app.items.is_empty() && app.detail.is_none() && app.selected.is_none() && !app.loaded
    }

    /// A list or an item fetched before a lock, a stop or a lost watch can land
    /// after it. It must not bring the values back, not even once the vault is
    /// open again.
    #[test]
    fn replies_from_before_a_lock_are_dropped() {
        let ends: [fn() -> Done; 3] = [
            || Done::Changed(Change::Locked),
            || Done::Changed(Change::Stopping),
            || Done::WatchLost,
        ];
        for end in ends {
            let mut rt = vault();
            let unlocked = rt.state.status.clone();
            let (generation, seq) = (rt.state.generation, rt.state.seq);
            let item = rt.state.detail.clone().expect("the scene shows an item");
            let items = rt.state.items.clone();
            let late = |rt: &mut Runtime<App>| {
                let (item, items) = (item.clone(), items.clone());
                rt.update(|s, tx| {
                    s.apply(
                        Done::Item {
                            seq,
                            result: Ok(Values::new(item)),
                        },
                        tx,
                    );
                    s.apply(
                        Done::Items {
                            generation,
                            result: Ok(items),
                        },
                        tx,
                    );
                });
            };

            rt.update(|s, tx| s.apply(end(), tx));
            assert_eq!(rt.state.screen, Screen::Locked);
            late(&mut rt);
            assert!(forgotten(&rt.state), "repopulated while locked");

            // Unlocked again (the new list is in flight): the old replies still don't count.
            rt.update(|s, tx| s.apply(Done::Status(unlocked.clone()), tx));
            assert_eq!(rt.state.screen, Screen::Vault);
            late(&mut rt);
            assert!(forgotten(&rt.state), "repopulated after unlocking");
        }
    }

    /// Rune doesn't poll a hidden window, so the panel forgets everything as
    /// it hides; a lock and the replies to what it asked before, landing
    /// while it's hidden, bring nothing back.
    #[test]
    fn a_hidden_panel_keeps_nothing() {
        let mut rt = panel("filtering");
        let item = rt.state.detail.clone().expect("the scene shows an item");
        let items = rt.state.items.clone();
        let (generation, seq) = (rt.state.generation, rt.state.seq);
        rt.update(|s, tx| s.dismiss(tx));
        for _ in 0..30 {
            rt.frame(1.0 / 60.0);
        }
        assert_eq!(rt.state.panel_phase(), Some(crate::panel::Phase::Hidden));
        assert!(forgotten(&rt.state));
        assert_eq!(rt.state.search.text, "", "the query too");

        rt.update(|s, tx| {
            s.apply(Done::Changed(Change::Locked), tx);
            s.apply(
                Done::Item {
                    seq,
                    result: Ok(Values::new(item)),
                },
                tx,
            );
            s.apply(
                Done::Items {
                    generation,
                    result: Ok(items),
                },
                tx,
            );
        });
        assert_eq!(rt.state.screen, Screen::Locked);
        assert!(forgotten(&rt.state));
    }
}
