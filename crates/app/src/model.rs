//! The app's state and what each input and agent reply does to it. No
//! drawing here; `view.rs` reads this.

use std::time::Duration;

use deadbolt_client::protocol::{
    AppAction, Change, Code, FieldInfo, ItemInfo, Status, code_field, noun, primary_field,
};
use rune::{Key, KeyEvent, SecretCopy, SecretState, TextEdit, Tx};
use zeroize::{Zeroize, Zeroizing};

use crate::agent::{Agent, Done, Failure, Job};
use crate::onboarding::Onboarding;
use crate::onboarding::worker::Worker;

/// How long a copied secret stays on the clipboard, by default.
pub const CLEAR_AFTER: f64 = 30.0;
/// How long "Clipboard cleared" stays before the notice leaves.
const CLEARED_NOTICE: f64 = 1.6;
/// A copy Rune clears this close to the countdown's end expired on time,
/// rather than being cleared early by a lock elsewhere.
const EXPIRY_SLACK: f64 = 0.5;
/// The countdown bar's full width, in points.
pub const BAR_W: f32 = 272.0;
/// The one-time code's countdown bar, in points.
pub const CODE_BAR: [f32; 2] = [40.0, 3.0];
/// How long after a code's period ends the next is asked for, so the
/// agent's clock is past the boundary too.
pub const CODE_SLACK: f64 = 0.05;

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
}

impl Copy {
    pub fn remaining(&self, now: f64) -> f64 {
        (self.lasts - (now - self.at)).max(0.0)
    }
}

/// The shown item's one-time code. The agent computes each one; the app
/// never holds the secret. Wiped when dropped.
pub struct Otp {
    pub item: String,
    /// The field it comes from (`code_field`).
    pub field: String,
    pub code: Option<Zeroizing<String>>,
    /// Why there's no code: an otp value saved before codes were checked.
    pub error: Option<String>,
    /// When the code stops being valid, on Rune's clock.
    pub until: f64,
    /// When it stops, in unix seconds: a new value is a new period.
    valid_until: u64,
    /// Counts periods, so each period's countdown bar is a new one.
    pub turns: u64,
    /// The countdown bar's rect, emptying linearly over the rest of the period.
    pub bar: rune::Tween<[f32; 4]>,
    /// A request for the next code is out.
    fetching: bool,
    /// Copy the next code that lands: none was current when asked.
    copy_next: bool,
    /// A wake is set for when the next is due.
    woken: bool,
}

impl Otp {
    fn new(item: String, field: String) -> Otp {
        let [_, h] = CODE_BAR;
        Otp {
            item,
            field,
            code: None,
            error: None,
            until: 0.0,
            valid_until: 0,
            turns: 0,
            bar: rune::Tween::linear([0.0; 4], [0.0, 0.0, 0.0, h], Duration::ZERO),
            fetching: false,
            copy_next: false,
            woken: false,
        }
    }

    /// The code, while it's valid at `now`.
    pub fn current(&self, now: f64) -> Option<&Zeroizing<String>> {
        self.code.as_ref().filter(|_| now < self.until)
    }
}

pub struct App {
    pub installer: Option<crate::install::Installer>,
    /// The vault footer's Settings popover is open.
    pub settings_open: bool,
    /// A design direction a scene draws instead of today's vault (`direction`).
    pub look: Option<crate::direction::Look>,
    /// The quick panel's global shortcut (the main window's).
    pub hotkey: crate::shortcut::Hotkey,
    /// The default shortcut isn't registered globally, so ⇧⌘Space inside
    /// Deadbolt opens and closes the panel (`panel::window::is_shortcut`).
    pub shortcut_fallback: bool,
    pub agent: Agent,
    /// How long a copied secret stays on the clipboard.
    pub clear_after: f64,
    pub screen: Screen,
    pub status: Option<Status>,
    pub passphrase: TextEdit,
    pub onboarding: Onboarding,
    pub unlocking: bool,
    pub unlock_error: Option<String>,
    /// Whether the main window currently has focus.
    pub window_focused: bool,
    /// A Touch ID prompt is in flight on the agent thread.
    pub touch_id_unlocking: bool,
    /// Touch ID was already auto-prompted for this lock/focus session.
    pub touch_id_prompted: bool,
    /// A Settings toggle to enable or disable Touch ID is in flight.
    pub touch_id_busy: bool,
    /// Why enabling or disabling Touch ID failed, shown in Settings.
    pub touch_id_error: Option<String>,
    pub search: TextEdit,
    pub items: Vec<ItemInfo>,
    pub loaded: bool,
    pub selected: Option<String>,
    /// The selected item with its values.
    pub detail: Option<ItemInfo>,
    pub revealed: Vec<String>,
    /// The shown item's one-time code, when it has an otp.
    pub otp: Option<Otp>,
    pub copy: Option<Copy>,
    pub notice: Option<String>,
    pub import: crate::import::Import,
    pub mirror: crate::mirror::Mirror,
    pub activity: crate::activity::Activity,
    /// Adding, changing or deleting an item.
    pub edit: crate::edit::Edit,
    /// The list's pane in the vault's shell: its width and whether it shows.
    pub sidebar: rune_kit::shell::PaneState,
    /// `--reduced-motion`; otherwise Rune follows the system's setting.
    pub reduced_motion: bool,
    /// Set in the quick panel's `App` only.
    pub panel: Option<crate::panel::Panel>,
    /// Handles to both windows, when the app runs both (not headless or in tests).
    pub windows: Option<crate::panel::window::Windows>,
    /// Seconds on Rune's clock (virtual when headless).
    pub clock: f64,
    /// Bumped whenever what was read from the store is forgotten: a list
    /// fetched in an older generation is dropped.
    generation: u64,
    /// Tells the current `Job::Get` from older ones; also bumped on forgetting.
    seq: u64,
    /// A copy waiting for its item's values: (seq, field).
    pending_copy: Option<(u64, String)>,
}

impl App {
    pub fn new(agent: Agent) -> App {
        App {
            installer: None,
            settings_open: false,
            look: None,
            hotkey: crate::shortcut::Hotkey::default(),
            shortcut_fallback: true,
            agent,
            clear_after: CLEAR_AFTER,
            screen: Screen::Connecting,
            status: None,
            passphrase: TextEdit::new("").secure(),
            onboarding: Onboarding::new(Worker::offline()),
            unlocking: false,
            unlock_error: None,
            window_focused: false,
            touch_id_unlocking: false,
            touch_id_prompted: false,
            touch_id_busy: false,
            touch_id_error: None,
            search: TextEdit::new(""),
            items: Vec::new(),
            loaded: false,
            selected: None,
            detail: None,
            revealed: Vec::new(),
            otp: None,
            copy: None,
            notice: None,
            import: crate::import::Import::default(),
            mirror: crate::mirror::Mirror::default(),
            activity: crate::activity::Activity::default(),
            edit: crate::edit::Edit::default(),
            // Narrow enough to leave the toolbar its search field and Lock at
            // the window's smallest.
            sidebar: rune_kit::shell::PaneState::new(272.0).range(200.0, 312.0),
            reduced_motion: false,
            panel: None,
            windows: None,
            clock: 0.0,
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
        self.tick_code(now, tx);
        changed |= self.tick_import(now);
        if let Some(installer) = &mut self.installer {
            changed |= installer.poll(now);
        }
        // The install page and Settings belong to the vault; leaving it closes them.
        if self.screen != Screen::Vault && (self.installing() || self.settings_open) {
            if let Some(installer) = &mut self.installer {
                installer.open = false;
            }
            self.close_settings();
            changed = true;
        }
        changed |= self.poll_panel(now, tx);
        changed
    }

    pub fn apply(&mut self, done: Done, tx: &mut Tx) {
        match done {
            Done::Connected(Ok(status)) => {
                self.on_status(status, tx);
                if self.should_auto_prompt_touch_id() {
                    self.unlock_touch_id();
                }
            }
            Done::Status(Some(status)) => self.on_status(status, tx),
            Done::Connected(Err(failure)) => self.show(Screen::Failed(failure.message)),
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
                        self.passphrase.focused = true;
                    }
                }
            }
            Done::UnlockedBiometric(result) => {
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
                        self.unlock_error =
                            biometric_unlock_message(&failure, self.touch_id_reset());
                        self.passphrase.focused = true;
                        if self.panel.is_some() && !self.window_focused {
                            self.dismiss(tx);
                        }
                    }
                }
            }
            Done::TouchIdSet { enabled, result } => {
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
            Done::Locked(result) => match result {
                Ok(()) => {
                    self.on_locked(tx);
                    if !self.panel_inert() {
                        self.agent.send(Job::Status);
                    }
                }
                Err(failure) => self.notice = Some(failure.message),
            },
            // A reply from before a lock (or stop) can land after it: drop
            // anything from an older generation, for a screen that's gone, or
            // for a panel that's confirming a copy or going.
            Done::Items { generation, result } => {
                if generation != self.generation
                    || self.screen != Screen::Vault
                    || self.panel_inert()
                {
                    return;
                }
                // The panel's list lands just after it opens; it opens at rest.
                if self.panel.is_some() && !self.loaded {
                    tx.instant();
                }
                match result {
                    Ok(items) => self.on_items(items, tx),
                    Err(failure) => self.on_failure(failure, tx),
                }
            }
            // Dropping a stale item wipes its values (`agent::Values`).
            Done::Item { seq, result } => {
                if seq != self.seq || self.screen != Screen::Vault || self.panel_inert() {
                    return;
                }
                match result {
                    Ok(values) => {
                        let (item, code) = values.take();
                        // A new selection's fields land in place, not animated: the
                        // selection moved under the user's own hand. A refresh of the
                        // shown item animates what changed, and so does a saved form
                        // giving way to what it saved.
                        let saved = self.editing();
                        if !saved && self.detail.as_ref().is_none_or(|d| d.id != item.id) {
                            tx.instant();
                        }
                        self.edit_item_landed(&item);
                        self.set_detail(Some(item));
                        if let Some(code) = code {
                            self.on_code(code, tx);
                        }
                        if let Some((pending, field)) = self.pending_copy.take()
                            && pending == seq
                        {
                            self.copy_field(&field, tx);
                        }
                    }
                    Err(failure) => {
                        self.edit_item_failed();
                        self.on_failure(failure, tx);
                    }
                }
            }
            Done::Code { seq, result } => {
                if seq != self.seq || self.screen != Screen::Vault || self.panel_inert() {
                    return;
                }
                self.on_code(result, tx);
            }
            Done::Imported {
                seq,
                applied,
                result,
            } => self.on_imported(seq, applied, result, tx),
            Done::Mirrored { seq, result } => self.on_mirrored(seq, result, tx),
            Done::Saved { seq, result } => self.on_saved(seq, result, tx),
            Done::Removed { seq, result } => self.on_removed(seq, result, tx),
            Done::Generated { seq, result } => self.on_generated(seq, result, tx),
            Done::Activity { seq, result } => self.on_activity(seq, result, tx),
            Done::Reported => {}
            Done::Changed(change) => self.on_change(change, tx),
            Done::WatchLost => self.on_agent_gone(tx),
        }
    }

    /// A change the agent streamed. It says what changed; this refetches.
    fn on_change(&mut self, change: Change, tx: &mut Tx) {
        // A panel that's confirming a copy or going only follows the vault
        // closing; its summon fetches the rest.
        if self.panel_inert() && !matches!(change, Change::Locked | Change::Stopping) {
            return;
        }
        match change {
            // The stream is (again) live, or it dropped changes: fetch it all.
            Change::Watching | Change::Resync => {
                self.agent.send(Job::Status);
                self.refresh();
            }
            Change::Locked if self.screen == Screen::Vault => {
                self.on_locked(tx);
                if !self.panel_inert() {
                    self.agent.send(Job::Status);
                }
            }
            // Onboarding decides from the status whether it can carry on.
            Change::Locked if self.screen == Screen::Onboarding => self.agent.send(Job::Status),
            Change::Unlocked if self.screen != Screen::Vault => self.agent.send(Job::Status),
            Change::Vaults => {
                self.agent.send(Job::Status);
                self.refresh();
            }
            Change::Devices { .. } => self.agent.send(Job::Status),
            Change::Activity => self.on_activity_changed(),
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
    pub(crate) fn refresh(&mut self) {
        if self.screen == Screen::Vault {
            self.list();
        }
    }

    /// Fetches the list for the current generation.
    pub(crate) fn list(&self) {
        if self.panel_inert() {
            return;
        }
        self.agent.send(Job::List {
            generation: self.generation,
        });
    }

    /// The current generation, for tagging a list reply in tests and scenes.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The current item request, for tagging an item reply in tests.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// A list arrived. The selection and the search stay; if the selected
    /// item is still there and this replaced a list, its values are fetched
    /// again in place. If it's gone (deleted, or no longer matching), the
    /// next one replaces it at once, so its fields never fade under the new
    /// title.
    fn on_items(&mut self, items: Vec<ItemInfo>, tx: &mut Tx) {
        let refresh = self.loaded;
        let before = self.selected.clone();
        self.items = items;
        self.loaded = true;
        self.edit_items_landed();
        self.keep_selection_visible();
        if before.is_some() && self.selected != before {
            tx.instant();
        }
        // A form can hold the selection on an item deleted elsewhere; there's
        // nothing left to fetch.
        if refresh
            && self.selected == before
            && let Some(id) = self.selected.clone()
            && self.items.iter().any(|i| i.id == id)
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

    fn on_status(&mut self, mut status: Status, tx: &mut Tx) {
        if self.touch_id_busy
            && let Some(prev) = &self.status
        {
            status.touch_id_enabled = prev.touch_id_enabled;
        }
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
                self.show(Screen::Locked);
                self.passphrase.focused = true;
            }
            _ => self.show(screen),
        }
    }

    /// Every screen change after start-up comes through here. Leaving Locked
    /// wipes a part-typed passphrase, however it was left: an unlock from the
    /// other window or the CLI, the agent stopping, onboarding.
    pub(crate) fn show(&mut self, screen: Screen) {
        if screen != Screen::Locked {
            self.passphrase.clear();
        }
        if screen != self.screen {
            self.import.hover = false;
        }
        self.screen = screen;
    }

    pub(crate) fn enter_vault(&mut self, _tx: &mut Tx) {
        self.forget_onboarding();
        self.show(Screen::Vault);
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
        self.show(Screen::Failed(message));
    }

    /// The store is locked: drop everything read from it.
    pub(crate) fn on_locked(&mut self, tx: &mut Tx) {
        self.forget_vault(tx);
        if let Some(status) = &mut self.status {
            status.unlocked = false;
            if !status.touch_id_enabled || status.touch_id_reset {
                status.touch_id_ready = false;
            }
        }
        self.touch_id_unlocking = false;
        // A lock while the main window is frontmost (⌘L, Lock button, or idle
        // timeout) stays at rest until the user asks for Touch ID or leaves and
        // returns; a lock while in the background waits to auto-prompt on focus.
        self.touch_id_prompted = self.window_focused && self.panel.is_none();
        self.show(Screen::Locked);
        self.passphrase.clear();
        self.passphrase.focused = true;
    }

    /// The window is closing: clear our clipboard copies, wipe what we read
    /// and typed, and hang up a join.
    pub fn close(&mut self, tx: &mut Tx) {
        self.forget_vault(tx);
        self.passphrase.clear();
        self.forget_onboarding();
        self.onboarding.worker.stop();
    }

    fn forget_vault(&mut self, tx: &mut Tx) {
        self.clear_clipboard(tx);
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
        self.forget_import();
        self.forget_edit();
        self.mirror.forget();
        self.activity.forget();
    }

    /// Replaces the shown values, wiping the old ones. Revealed fields stay
    /// revealed only while the same item is shown, and its code while it
    /// still has one from the same field.
    pub(crate) fn set_detail(&mut self, item: Option<ItemInfo>) {
        let same = matches!((&self.detail, &item), (Some(a), Some(b)) if a.id == b.id);
        let code = item
            .as_ref()
            .and_then(|i| Some((i.id.clone(), i.fields[code_field(&i.fields)?].name.clone())));
        if let Some(mut old) = std::mem::replace(&mut self.detail, item) {
            forget(&mut old);
        }
        if !same {
            self.revealed.clear();
        }
        let keep = matches!((&self.otp, &code), (Some(o), Some((item, field))) if &o.item == item && &o.field == field);
        if !keep {
            self.otp = code.map(|(item, field)| Otp::new(item, field));
        }
    }

    // ---------------------------------------------------------------------------------------
    // One-time codes

    /// A code (or why there is none) for the shown item. Its countdown runs
    /// on the render clock; the next is asked for once this one's period
    /// ends (`tick_code`).
    pub(crate) fn on_code(&mut self, result: Result<Code, Failure>, tx: &mut Tx) {
        let now = self.clock;
        let Some(otp) = &mut self.otp else { return };
        otp.fetching = false;
        let code = match result {
            Ok(code) => code,
            Err(failure) if failure.locked() => return self.on_locked(tx),
            Err(failure) => {
                otp.code = None;
                otp.error = Some(failure.message);
                if std::mem::take(&mut otp.copy_next) {
                    self.notice = otp.error.clone();
                }
                return;
            }
        };
        let period = code.period.max(1) as f64;
        let remaining = (code.remaining_ms as f64 / 1000.0).clamp(0.0, period);
        if code.valid_until != otp.valid_until {
            otp.valid_until = code.valid_until;
            otp.turns += 1;
        }
        otp.code = Some(code.code.clone());
        otp.error = None;
        otp.until = now + remaining;
        otp.woken = false;
        let [w, h] = CODE_BAR;
        otp.bar = rune::Tween::linear(
            [0.0, 0.0, w * (remaining / period) as f32, h],
            [0.0, 0.0, 0.0, h],
            Duration::from_secs_f64(remaining),
        );
        // The code that just came is the one asked for, however little of
        // its period is left.
        if std::mem::take(&mut otp.copy_next) {
            let field = otp.field.clone();
            self.put_on_clipboard(field, code.code.to_string(), tx);
        }
    }

    /// `CODE_SLACK` after a code's period ends, asks for the next, waking
    /// for that moment (set from the first poll after the code came, so a
    /// scene's code wakes too). The quick panel shows no code, so it asks
    /// only when one is copied.
    fn tick_code(&mut self, now: f64, tx: &mut Tx) {
        if self.panel.is_some() {
            return;
        }
        let Some(otp) = &mut self.otp else { return };
        if otp.fetching || otp.code.is_none() {
            return;
        }
        let due = otp.until + CODE_SLACK;
        if now < due - 1e-3 {
            if !std::mem::replace(&mut otp.woken, true) {
                tx.wake_after(Duration::from_secs_f64(due - now));
            }
            return;
        }
        otp.fetching = true;
        self.agent.send(Job::Code {
            id: otp.item.clone(),
            seq: self.seq,
        });
    }

    /// The shown item's code, or `None` after asking the agent for the next
    /// one, which is copied as it lands.
    fn code_for_copy(&mut self) -> Option<String> {
        let now = self.clock;
        let otp = self.otp.as_mut()?;
        if let Some(code) = otp.current(now) {
            return Some(code.to_string());
        }
        if let Some(error) = &otp.error {
            self.notice = Some(error.clone());
            return None;
        }
        otp.copy_next = true;
        if !otp.fetching {
            otp.fetching = true;
            self.agent.send(Job::Code {
                id: otp.item.clone(),
                seq: self.seq,
            });
        }
        None
    }

    // ---------------------------------------------------------------------------------------
    // Unlock

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

    // ---------------------------------------------------------------------------------------
    // The list

    /// The items matching the search: every word must appear in the label,
    /// the detail (username, expiry, SSH key comment, identity email), the
    /// type ("ssh", "SSH key") or the short id.
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
                    Some(noun(&item.kind, 1)),
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
        // An open form keeps its item selected, even when the search hides it.
        if self.editing() {
            return;
        }
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
        self.edit.delete = None;
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

    /// Keys in the search field (the vault's and the panel's), before its
    /// editor. True when handled.
    pub fn search_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        if let Some(handled) = self.overlay_key(ev) {
            return handled;
        }
        if let Some(handled) = self.import_key(ev) {
            return handled;
        }
        if let Some(handled) = self.edit_key(ev) {
            return handled;
        }
        if self.panel_shortcut(ev, tx) {
            return true;
        }
        self.list_key(ev, tx)
    }

    /// The vault's keys wherever focus is, after overlays and the import view
    /// (`on_key`): the list's, and ⌘F and ⌘K to the search.
    fn vault_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        let chord = |c| ev.is_command(c) && !ev.mods.shift && !ev.mods.alt && !ev.mods.ctrl;
        if chord('f') || chord('k') {
            self.focus_search();
            return true;
        }
        self.list_key(ev, tx)
    }

    /// ↑↓ select, ⏎, ⇧⏎ and ⌥⏎ copy, esc clears the search.
    fn list_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        match ev.key {
            Key::Up | Key::Down => {
                // The selection moves under the user's hand: the item replaces at
                // once, and a hidden list opens to show where it went.
                tx.instant();
                self.sidebar.set_open(true);
                self.step(if ev.key == Key::Up { -1 } else { 1 });
                if let Some(id) = &self.selected {
                    tx.scroll_into_view(format!("item-{id}"));
                }
            }
            Key::Enter => {
                let field = if ev.mods.alt {
                    "otp"
                } else if ev.mods.shift {
                    "username"
                } else {
                    self.primary_field()
                };
                self.copy_selected(field, tx);
            }
            Key::Escape if !self.search.text.is_empty() => {
                // As typing does, clearing the search replaces the list at once.
                tx.instant();
                self.search.clear();
                self.search_changed();
            }
            Key::Escape => {}
            _ => return false,
        }
        true
    }

    /// The search changed: the list it filters shows (a hidden sidebar opens,
    /// the import view closes), and the selection follows it. An import
    /// that's running, or a preview in an empty vault, stays, and so does
    /// the item it hides until it's gone (`on_imported`, `cancel_import`).
    pub fn search_changed(&mut self) {
        if self.panel_inert() {
            return;
        }
        self.sidebar.set_open(true);
        if self.import.showing() && !self.items.is_empty() {
            self.cancel_import();
        }
        if !self.import.showing() {
            self.keep_selection_visible();
        }
    }

    /// The quick panel's clear button: an empty search, still focused.
    pub fn clear_search(&mut self) {
        self.search.clear();
        self.search.focused = true;
        self.search_changed();
    }

    /// Focuses the search field with its text selected, so typing replaces it.
    pub fn focus_search(&mut self) {
        self.search.focused = true;
        self.search.set_selection(0, self.search.text.len());
    }

    /// What ⏎ copies, as a key hint: none once the item's values are in and
    /// it has no such field.
    pub fn enter_hint(&self) -> Option<&'static str> {
        let item = self.selected_item()?;
        let field = self.primary_field();
        let lacks = self
            .detail
            .as_ref()
            .is_some_and(|d| d.id == item.id && !d.fields.iter().any(|f| f.name == field));
        (!lacks).then(|| copy_label(&item.kind))
    }

    /// Whether ⇧⏎ has a username to copy: a login's row carries it.
    pub fn has_username(&self) -> bool {
        self.selected_item()
            .is_some_and(|i| i.kind == "login" && i.detail.is_some())
    }

    /// What ⏎ copies: the field the item is for (`protocol::primary_field`).
    fn primary_field(&self) -> &'static str {
        self.selected_item()
            .and_then(|i| primary_field(&i.kind))
            .unwrap_or("password")
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

    /// Copies a field of the shown item; its otp (`"otp"` names whichever
    /// field the code comes from) copies the current code.
    pub fn copy_field(&mut self, field: &str, tx: &mut Tx) {
        if self.detail.is_none() {
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
    fn put_on_clipboard(&mut self, field: String, value: String, tx: &mut Tx) {
        let Some(item) = &self.detail else { return };
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
                self.report(AppAction::Reveal, field);
                self.revealed.push(field.into());
            }
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
        let installing = self.installing();
        if !self.settings_open && !installing {
            return None;
        }
        // Import Passwords… leaves either for the import view, as the menu
        // item does; without native menus the key is the only way.
        if crate::import::is_shortcut(ev) && !self.hotkey.recorder.is_recording() {
            return None;
        }
        match ev.key {
            Key::Escape if self.settings_open => self.close_settings(),
            Key::Escape => {
                if let Some(installer) = &mut self.installer {
                    installer.close();
                }
            }
            Key::Tab => return Some(false),
            _ => {}
        }
        Some(true)
    }

    /// Closes the Settings popover; a recording in it is cancelled.
    pub fn close_settings(&mut self) {
        self.settings_open = false;
        self.hotkey.recorder.cancel();
        self.hotkey.reset_error = None;
        self.touch_id_error = None;
        self.mirror.result = None;
        self.activity.forget();
    }

    /// App-level keys: before the focused field when there is none, after it
    /// otherwise. In the vault that includes the list's keys, so they work
    /// with focus on a button or nowhere.
    pub fn on_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        if let Some(handled) = self.overlay_key(ev) {
            return handled;
        }
        if let Some(handled) = self.import_key(ev) {
            return handled;
        }
        if let Some(handled) = self.edit_key(ev) {
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
            Key::Enter if self.screen == Screen::Locked => {
                self.submit_unlock();
                true
            }
            _ if self.screen == Screen::Vault
                && self.panel.is_none()
                && rune_kit::shell::is_sidebar_toggle(ev) =>
            {
                self.sidebar.toggle();
                true
            }
            _ if self.screen == Screen::Vault && self.panel.is_none() => self.vault_key(ev, tx),
            _ if self.screen == Screen::Onboarding => crate::onboarding::key(self, ev, tx),
            _ => false,
        }
    }
}

/// The selected item has a one-time code ⌥⏎ can copy.
pub fn has_code(s: &App) -> bool {
    let selected = s.selected_item().map(|i| i.id.as_str());
    s.otp
        .as_ref()
        .is_some_and(|o| o.error.is_none() && Some(o.item.as_str()) == selected)
}

/// Groups a code's digits for reading: 123 456, 123 4567, 1234 5678.
pub fn group_code(code: &str) -> String {
    let at = code.len() / 2;
    match (code.get(..at), code.get(at..)) {
        (Some(a), Some(b)) if code.len() >= 6 => format!("{a} {b}"),
        _ => code.to_owned(),
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

fn biometric_unlock_message(failure: &Failure, reset: bool) -> Option<String> {
    if reset
        || failure.message.contains("Touch ID was reset")
        || failure.message.contains("cancelled")
    {
        None
    } else {
        Some("Touch ID couldn't unlock this device. Enter your passphrase.".into())
    }
}

/// A field name as words, with initialisms in capitals: "url" is "URL",
/// "private-key" is "private key", "national-id" is "national ID", and a
/// passkey's "rp-id" is "site".
pub fn field_words(name: &str) -> String {
    if name == "rp-id" {
        return "site".into();
    }
    name.split('-')
        .map(|word| {
            if matches!(word, "url" | "otp" | "cvv" | "pin" | "id" | "ssh") {
                word.to_uppercase()
            } else {
                word.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A field name as a label: "Private key", "National ID", "URL".
pub fn title_case(name: &str) -> String {
    let words = field_words(name);
    let mut chars = words.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Takes a passphrase out of its secure field, leaving the field empty and
/// still focused. The text moves into the `Zeroizing`, never copied.
pub fn take_secret(field: &mut TextEdit) -> Zeroizing<String> {
    let secret = Zeroizing::new(std::mem::take(&mut field.text));
    field.clear();
    secret
}

/// What ⏎ does for an item of `kind`, as a key hint.
pub fn copy_label(kind: &str) -> &'static str {
    match kind {
        "card" => "Copy number",
        "note" => "Copy note",
        "ssh" => "Copy private key",
        "identity" => "Copy email",
        "passkey" => "Copy username",
        _ => "Copy password",
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

    use super::{App, Screen, take_secret};
    use crate::agent::{Done, Values};

    #[test]
    fn take_secret_empties_the_field() {
        let mut f = rune::TextEdit::new("").secure();
        f.paste("hunter22");
        f.focused = true;
        assert_eq!(take_secret(&mut f).as_str(), "hunter22");
        assert_eq!((f.text.as_str(), f.focus, f.anchor), ("", 0, 0));
        assert!(f.focused && f.is_secure());
    }

    fn vault() -> Runtime<App> {
        main("vault")
    }

    fn main(scene: &str) -> Runtime<App> {
        let app = rune::tooling::initial_state(&crate::spec(), Some(scene));
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

    /// The panel forgets everything as it hides; a lock and the replies to
    /// what it asked before, landing while it's hidden, bring nothing back.
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

    /// A part-typed passphrase goes as soon as either window leaves Locked
    /// without it: unlocked elsewhere (the other window, the CLI), the agent
    /// gone, or the device reset to onboarding.
    #[test]
    fn leaving_locked_wipes_a_part_typed_passphrase() {
        let windows: [fn() -> Runtime<App>; 2] = [|| main("locked"), || panel("locked")];
        let exits: [fn(&App) -> Done; 3] = [
            |s| {
                let mut status = s.status.clone().expect("the scene has a status");
                status.unlocked = true;
                Done::Status(Some(status))
            },
            |_| Done::Status(None),
            |s| {
                let mut status = s.status.clone().expect("the scene has a status");
                status.initialized = false;
                Done::Status(Some(status))
            },
        ];
        for window in windows {
            for exit in exits {
                let mut rt = window();
                assert_eq!(rt.state.screen, Screen::Locked);
                rt.update(|s, _| {
                    s.passphrase.paste("hunt");
                    s.passphrase_changed();
                });
                rt.update(|s, tx| {
                    let done = exit(s);
                    s.apply(done, tx);
                });
                assert_ne!(rt.state.screen, Screen::Locked);
                assert_eq!(rt.state.passphrase.text, "", "left {:?}", rt.state.screen);
            }
        }
    }

    #[test]
    fn touch_id_auto_prompts_on_launch_and_focus_never_on_background_lock() {
        use crate::agent::{Agent, Failure, Job};

        let mut rt = vault();
        let (agent, jobs, _replies) = Agent::scripted();
        rt.state.agent = agent;
        if let Some(st) = &mut rt.state.status {
            st.touch_id_available = true;
            st.touch_id_enabled = true;
        }
        let mut locked_status = rt.state.status.clone().unwrap();
        locked_status.unlocked = false;
        locked_status.touch_id_ready = true;

        // Window loses focus (user switches to another app), then agent locks in background.
        rt.update(|s, tx| s.main_focus(false, tx));
        rt.update(|s, tx| {
            s.apply(Done::Changed(Change::Locked), tx);
            s.apply(Done::Status(Some(locked_status.clone())), tx);
        });
        assert_eq!(rt.state.screen, Screen::Locked);
        assert!(
            !jobs.try_iter().any(|j| matches!(j, Job::UnlockBiometric)),
            "background lock must not prompt Touch ID"
        );

        // User brings the window forward: Touch ID auto-prompts once.
        rt.update(|s, tx| s.main_focus(true, tx));
        assert!(
            jobs.try_iter().any(|j| matches!(j, Job::UnlockBiometric)),
            "focusing the locked window prompts Touch ID"
        );
        assert!(rt.state.touch_id_unlocking);

        // The macOS Touch ID sheet takes and returns focus when cancelled;
        // it must not re-prompt in a loop.
        rt.update(|s, tx| s.main_focus(false, tx));
        rt.update(|s, tx| {
            s.apply(
                Done::UnlockedBiometric(Err((
                    Failure {
                        code: None,
                        message: "Touch ID was cancelled: user cancel".into(),
                    },
                    Some(Box::new(locked_status.clone())),
                ))),
                tx,
            );
            s.main_focus(true, tx);
        });
        assert!(
            !jobs.try_iter().any(|j| matches!(j, Job::UnlockBiometric)),
            "cancelling Touch ID must not loop on focus return"
        );
        assert_eq!(rt.state.unlock_error, None);
        assert!(rt.state.passphrase.focused);

        // If the biometric slot was reset, the lock screen says so and hides Use Touch ID.
        let mut reset_status = locked_status.clone();
        reset_status.touch_id_ready = false;
        reset_status.touch_id_reset = true;
        rt.update(|s, tx| {
            s.unlock_touch_id();
            s.apply(
                Done::UnlockedBiometric(Err((
                    Failure {
                        code: None,
                        message:
                            "Touch ID was reset (expired after 14 days); enter your passphrase"
                                .into(),
                    },
                    Some(Box::new(reset_status)),
                ))),
                tx,
            );
        });
        rt.frame(1.0 / 60.0);
        assert!(rt.state.touch_id_reset());
        assert!(!rt.state.touch_id_ready());
        assert!(
            rt.elements().iter().any(|e| {
                e.text
                    .as_deref()
                    .is_some_and(|t| t.contains("Touch ID was reset; enter your passphrase"))
            }),
            "shows reset notice"
        );
        assert!(rt.find("touch-id").is_none());

        // When Touch ID is enabled in config.toml before a biometric slot has ever
        // been enrolled (`touch_id_reset == false`, `touch_id_ready == false`),
        // the lock screen asks for the passphrase once rather than claiming a reset.
        let mut never_enrolled_status = locked_status.clone();
        never_enrolled_status.touch_id_ready = false;
        never_enrolled_status.touch_id_reset = false;
        rt.update(|s, tx| {
            s.apply(Done::Status(Some(never_enrolled_status)), tx);
        });
        rt.frame(1.0 / 60.0);
        assert!(!rt.state.touch_id_reset());
        assert!(!rt.state.touch_id_ready());
        assert!(
            rt.elements().iter().any(|e| {
                e.text.as_deref().is_some_and(|t| {
                    t.contains("Enter your passphrase once to finish turning on Touch ID")
                })
            }),
            "shows first-time finish setup notice instead of reset notice"
        );

        // Hidden main window (`window_focused == false` on `--panel` launch) does not
        // auto-prompt on `Connected` until the window is actually focused.
        let mut hidden = App::new(Agent::offline());
        let (hidden_agent, hidden_jobs, _hidden_replies) = Agent::scripted();
        hidden.agent = hidden_agent;
        assert!(!hidden.window_focused);
        hidden.apply(
            Done::Connected(Ok(locked_status.clone())),
            &mut rune::Tx::default(),
        );
        assert_eq!(hidden.screen, Screen::Locked);
        assert!(
            !hidden_jobs
                .try_iter()
                .any(|j| matches!(j, Job::UnlockBiometric)),
            "unfocused main window must not auto-prompt on Connected"
        );
        hidden.main_focus(true, &mut rune::Tx::default());
        assert!(
            hidden_jobs
                .try_iter()
                .any(|j| matches!(j, Job::UnlockBiometric)),
            "focusing main window after Connected prompts Touch ID"
        );
    }

    #[test]
    fn quick_panel_touch_id_unlocks_and_dismisses_if_unfocused_on_cancel() {
        use crate::agent::{Agent, Failure, Job};
        use crate::panel::Phase;

        let mut rt = panel("locked-touch-id");
        let (agent, jobs, _replies) = Agent::scripted();
        rt.state.agent = agent;
        let locked_status = rt.state.status.clone().unwrap();
        let mut unlocked_status = locked_status.clone();
        unlocked_status.unlocked = true;
        unlocked_status.touch_id_ready = false;

        // Summoning the locked panel marks it focused and auto-prompts Touch ID.
        rt.update(|s, tx| s.summon(tx));
        assert!(rt.state.window_focused);
        assert!(
            jobs.try_iter().any(|j| matches!(j, Job::UnlockBiometric)),
            "summon prompts Touch ID"
        );
        assert!(rt.state.touch_id_unlocking);

        // Focus loss while the Touch ID sheet is up does not immediately dismiss the panel.
        rt.update(|s, tx| s.panel_focus(false, tx));
        assert_eq!(rt.state.panel_phase(), Some(Phase::Open));

        // If the Touch ID prompt fails/cancels while the panel is still unfocused
        // (user clicked away to another app), the panel dismisses itself.
        rt.update(|s, tx| {
            s.apply(
                Done::UnlockedBiometric(Err((
                    Failure {
                        code: None,
                        message: "Touch ID prompt was cancelled".into(),
                    },
                    Some(Box::new(locked_status)),
                ))),
                tx,
            );
        });
        assert!(matches!(
            rt.state.panel_phase(),
            Some(Phase::Closing { .. })
        ));

        // Summon again and complete Touch ID: the panel enters the vault and
        // re-arms focus so a subsequent blur dismisses it.
        rt.update(|s, tx| s.summon(tx));
        rt.update(|s, tx| s.panel_focus(false, tx));
        rt.update(|s, tx| {
            s.apply(Done::UnlockedBiometric(Ok(unlocked_status)), tx);
        });
        assert_eq!(rt.state.screen, Screen::Vault);
        assert_eq!(rt.state.panel_phase(), Some(Phase::Open));
        assert!(rt.state.search.focused);
        assert!(rt.state.window_focused);

        rt.update(|s, tx| s.panel_focus(false, tx));
        assert!(matches!(
            rt.state.panel_phase(),
            Some(Phase::Closing { .. })
        ));
    }

    #[test]
    fn settings_touch_id_toggle_sends_command_and_reverts_on_failure() {
        use crate::agent::{Agent, Failure, Job};

        let mut rt = main("settings-touch-id");
        let (agent, jobs, _replies) = Agent::scripted();
        rt.state.agent = agent;
        assert!(rt.state.touch_id_enabled());
        let initial_status = rt.state.status.clone().unwrap();

        rt.update(|s, _| s.toggle_touch_id());
        assert!(!rt.state.touch_id_enabled());
        assert!(rt.state.touch_id_busy);
        assert!(jobs.try_iter().any(|j| matches!(j, Job::TouchIdSet(false))));

        // While `touch_id_busy` is true, an incoming Status reply (e.g. from watch)
        // must not flip the switch back to its pre-toggle value.
        rt.update(|s, tx| {
            s.apply(Done::Status(Some(initial_status.clone())), tx);
        });
        assert!(
            !rt.state.touch_id_enabled(),
            "pending toggle value preserved across intermediate Status replies"
        );

        // On TouchIdSet failure, the fresh Status from the agent restores the switch.
        rt.update(|s, tx| {
            s.apply(
                Done::TouchIdSet {
                    enabled: false,
                    result: Err((
                        Failure {
                            code: None,
                            message: "Touch ID failed".into(),
                        },
                        Some(Box::new(initial_status)),
                    )),
                },
                tx,
            );
        });
        assert!(
            rt.state.touch_id_enabled(),
            "restored from fresh Status on failure"
        );
        assert_eq!(rt.state.touch_id_error.as_deref(), Some("Touch ID failed"));
    }
}
