//! The app's state and what each agent reply does to it. No drawing here;
//! `view.rs` reads this, and `model/{unlock,selection,copy,otp}` and
//! `keys.rs` hold each capability's transitions.

mod copy;
mod favorite;
mod otp;
mod selection;
mod unlock;

#[cfg(test)]
mod tests;

pub use copy::{BAR_W, CLEAR_AFTER, Copy};
pub use favorite::{sort_items, tag_token};
pub use otp::{CODE_BAR, CODE_SLACK, Otp, group_code, has_code};
pub use selection::HOLD;

use deadbolt_client::protocol::{Change, FieldInfo, ItemInfo, Status, code_field};
use rune::{TextEdit, Tx};
use zeroize::{Zeroize, Zeroizing};

use crate::agent::{Agent, Done, Failure, Job};
use crate::onboarding::Onboarding;
use crate::onboarding::worker::Worker;

#[derive(Clone, Debug, PartialEq)]
pub enum Screen {
    Connecting,
    /// No device set up yet, or one with no vault: create or join one.
    Onboarding,
    Locked,
    Vault,
    Failed(String),
}

pub struct App {
    pub installer: Option<crate::install::Installer>,
    /// Settings shows in the item's place (⌘,).
    pub settings_open: bool,
    /// Where the keys are past the search: a field, ⌘K's actions, the ? sheet.
    pub nav: crate::keys::Nav,
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
    /// Filter inside `⌘K`'s tag picker (`palette::tags`).
    pub tag_filter: TextEdit,
    pub items: Vec<ItemInfo>,
    pub loaded: bool,
    pub selected: Option<String>,
    /// The selected item with its values.
    pub detail: Option<ItemInfo>,
    /// Pages ready before their values land (`cache`).
    pub cache: crate::cache::Cache,
    /// The page shown before a selection with nothing to show yet, and
    /// since when on the frame clock, kept whole for `HOLD`.
    held: Option<(String, Option<f64>)>,
    /// Tells the newest batch of `Job::Peek`s from older ones.
    peeks: u64,
    /// `seq` when the cache was last cleared: an item asked for before is
    /// left out of it.
    cleared_seq: u64,
    pub revealed: Vec<String>,
    /// The shown item's one-time code, when it has an otp.
    pub otp: Option<Otp>,
    pub copy: Option<Copy>,
    pub notice: Option<String>,
    pub import: crate::import::Import,
    pub mirror: crate::mirror::Mirror,
    pub activity: crate::activity::Activity,
    pub agents: crate::agents::Agents,
    /// Recently Deleted, in the item's place (⇧⌘⌫).
    pub trash: crate::trash::Trash,
    pub health: crate::health::Health,
    pub ssh: crate::ssh::Ssh,
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
    /// Tells the newest `Job::Favorite` from older ones.
    fav_seq: u64,
    /// A copy waiting for its item's values: (seq, field).
    pending_copy: Option<(u64, String)>,
}

impl App {
    pub fn new(agent: Agent) -> App {
        App {
            installer: None,
            settings_open: false,
            nav: crate::keys::Nav::default(),
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
            tag_filter: TextEdit::new(""),
            items: Vec::new(),
            loaded: false,
            selected: None,
            detail: None,
            cache: crate::cache::Cache::default(),
            held: None,
            peeks: 0,
            cleared_seq: 0,
            revealed: Vec::new(),
            otp: None,
            copy: None,
            notice: None,
            import: crate::import::Import::default(),
            mirror: crate::mirror::Mirror::default(),
            activity: crate::activity::Activity::default(),
            agents: crate::agents::Agents::default(),
            trash: crate::trash::Trash::default(),
            health: crate::health::Health::default(),
            ssh: crate::ssh::Ssh::default(),
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
            fav_seq: 0,
            pending_copy: None,
        }
    }

    // ---------------------------------------------------------------------------------------
    // Agent replies

    /// Applies what the agent sent back. True when anything changed.
    pub fn poll(&mut self, now: f64, tx: &mut Tx) -> bool {
        self.clock = now;
        let mut changed = false;
        for done in self.agent.drain(now) {
            self.apply(done, tx);
            changed = true;
        }
        changed |= self.poll_onboarding(now, tx);
        changed |= self.tick_held(now, tx);
        changed |= self.tick_copy(now, tx);
        self.tick_code(now, tx);
        changed |= self.tick_import(now);
        if let Some(installer) = &mut self.installer {
            installer.stamp_copy(now, tx);
            changed |= installer.poll(now);
        }
        // The install page, Settings, Recently Deleted and Security belong to
        // the vault; leaving it closes them.
        if self.screen != Screen::Vault
            && (self.installing() || self.settings_open || self.trash.open || self.security_open())
        {
            if let Some(installer) = &mut self.installer {
                installer.open = false;
            }
            self.close_settings();
            self.trash.forget();
            self.close_security();
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
            Done::Unlocked(result) => self.on_unlocked(result, tx),
            Done::UnlockedBiometric(result) => self.on_unlocked_biometric(result, tx),
            Done::TouchIdSet { enabled, result } => self.on_touch_id_set(enabled, result, tx),
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
                if generation != self.generation || !self.accepts_vault_replies() {
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
            Done::Item { seq, result } => self.on_item(seq, result, tx),
            Done::Peeked { id, epoch, result } => self.on_peeked(id, epoch, result, tx),
            Done::Code { seq, result } => {
                if seq != self.seq || !self.accepts_vault_replies() {
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
            Done::Favorited { seq, result } => self.on_favorited(seq, result, tx),
            Done::Removed { seq, result } => self.on_removed(seq, result, tx),
            Done::Generated { seq, result } => self.on_generated(seq, result, tx),
            Done::SshGenerated { seq, result } => self.on_ssh_generated(seq, result),
            Done::FileSaved(result) => match result {
                Ok(name) => self.notice = Some(format!("Saved {name}")),
                Err(failure) if failure.locked() => self.on_locked(tx),
                Err(failure) => self.notice = Some(crate::onboarding::sentence(&failure.message)),
            },
            Done::Activity { seq, result } => self.on_activity(seq, result, tx),
            Done::Agents { seq, result } => self.on_agents(seq, result, tx),
            Done::Trash { seq, result } => self.on_trash(seq, result, tx),
            Done::TrashItem { seq, result } => self.on_trash_item(seq, result, tx),
            Done::Health { seq, result } => self.on_health(seq, result, tx),
            Done::BreachChecksSet {
                seq,
                enabled,
                result,
            } => self.on_breach_checks_set(seq, enabled, result, tx),
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
            Change::Activity => {
                self.on_activity_changed();
                self.on_agents_changed();
            }
            Change::Health => self.request_health(false),
            Change::Update => self.agent.send(Job::Status),
            Change::Items { vault } if self.shows(&vault) => {
                self.refresh();
                self.on_trash_changed();
            }
            Change::Stopping => self.on_agent_gone(tx),
            // Another launch (`deadbolt app`): only the main window's watch hears it.
            Change::Activate { token } => {
                if let Some(windows) = &self.windows {
                    windows.activate_main(token);
                }
            }
            Change::Locked | Change::Unlocked | Change::Items { .. } => {}
        }
    }

    /// The vault is up and taking replies (not locked, and not a panel that
    /// has already copied or started closing).
    pub(super) fn accepts_vault_replies(&self) -> bool {
        self.screen == Screen::Vault && !self.panel_inert()
    }

    /// Whether the list shows `vault`: the default vault, or any when that
    /// isn't known.
    fn shows(&self, vault: &str) -> bool {
        self.status
            .as_ref()
            .and_then(|s| s.vaults.iter().find(|v| v.default))
            .is_none_or(|v| v.id == vault)
    }

    /// Refetches the list, and with it the selected item. What the cache
    /// kept may have changed too.
    pub(crate) fn refresh(&mut self) {
        self.forget_pages();
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
        if self.panel.is_none() {
            self.request_health(false);
        }
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
            self.agent.send(Job::Get {
                id,
                seq: self.seq,
                cached: false,
            });
        }
    }

    /// The agent stopped, which locked the store. The watch thread finds the
    /// next agent; unlocking starts one.
    fn on_agent_gone(&mut self, tx: &mut Tx) {
        if self.screen == Screen::Vault {
            self.on_locked(tx);
        }
    }

    pub(crate) fn on_status(&mut self, mut status: Status, tx: &mut Tx) {
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
    /// wipes a part-typed passphrase and any stale unlock error, however it
    /// was left: an unlock from the other window or the CLI, the agent
    /// stopping, onboarding.
    pub(crate) fn show(&mut self, screen: Screen) {
        if screen != Screen::Locked {
            self.passphrase.clear();
            self.passphrase.focused = false;
            self.unlock_error = None;
            self.unlocking = false;
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

    pub(super) fn on_failure(&mut self, failure: Failure, tx: &mut Tx) {
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
        self.unlocking = false;
        self.unlock_error = None;
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
        self.fav_seq += 1;
        self.set_detail(None);
        self.forget_pages();
        for item in &mut self.items {
            forget(item);
        }
        self.items.clear();
        self.loaded = false;
        self.selected = None;
        self.search = TextEdit::new("");
        self.tag_filter = TextEdit::new("");
        self.nav = crate::keys::Nav::default();
        self.pending_copy = None;
        self.notice = None;
        self.forget_import();
        self.forget_edit();
        self.mirror.forget();
        self.activity.forget();
        self.agents.forget();
        self.trash.forget();
        self.health.forget();
    }

    /// Replaces the shown values, wiping the old ones. Revealed fields stay
    /// revealed only while the same item is shown, and its code while it
    /// still has one from the same field.
    /// A Show pressed on the selection's page before its values came counts
    /// as the same item.
    pub(crate) fn set_detail(&mut self, item: Option<ItemInfo>) {
        let same = match (&self.detail, &item) {
            (Some(a), Some(b)) => a.id == b.id,
            (None, Some(b)) => self.selected.as_deref() == Some(b.id.as_str()),
            _ => false,
        };
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

    /// The install page is showing in place of the vault.
    pub fn installing(&self) -> bool {
        self.screen == Screen::Vault && self.installer.as_ref().is_some_and(|i| i.open)
    }

    /// Closes Settings; a recording in it is cancelled.
    pub fn close_settings(&mut self) {
        self.settings_open = false;
        self.nav.row = 0;
        self.hotkey.recorder.cancel();
        self.hotkey.reset_error = None;
        self.touch_id_error = None;
        self.mirror.result = None;
        self.activity.forget();
        self.agents.forget();
    }
}

/// Wipes an item's values and tags.
pub fn forget(item: &mut ItemInfo) {
    for FieldInfo { value, .. } in &mut item.fields {
        value.zeroize();
    }
    for tag in &mut item.tags {
        tag.zeroize();
    }
}

/// A field name as words, with initialisms in capitals: "url" is "URL",
/// "private-key" is "private key", "national-id" is "national ID", and a
/// passkey's "rp-id" is "site".
pub fn field_words(name: &str) -> String {
    match name {
        "rp-id" => return "site".into(),
        // An identity's address lines, and `region` as forms usually ask.
        "address-line1" => return "address line 1".into(),
        "address-line2" => return "address line 2".into(),
        "address-line3" => return "address line 3".into(),
        "region" => return "state / region".into(),
        "billing" => return "billing address".into(),
        "ssid" => return "network name (SSID)".into(),
        "iban" => return "IBAN".into(),
        "swift" => return "SWIFT / BIC".into(),
        _ => {}
    }
    name.split('-')
        .map(|word| {
            if matches!(word, "url" | "otp" | "cvv" | "pin" | "id" | "ssh" | "api") {
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
        "ssh" => "Copy public key",
        "identity" => "Copy email",
        "passkey" => "Copy username",
        "api" => "Copy credential",
        "license" => "Copy license key",
        "bank" => "Copy account number",
        "document" => "Save file…",
        "passport" | "driver-license" | "id-document" => "Copy number",
        "membership" => "Copy member ID",
        "crypto" => "Copy recovery phrase",
        _ => "Copy password",
    }
}

/// Is this field type secret (masked until revealed)?
pub fn is_secret(kind: &str) -> bool {
    matches!(kind, "secret" | "otp")
}
