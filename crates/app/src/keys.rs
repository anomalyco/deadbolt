//! The vault's keyboard: everything without a mouse. The search has the keys
//! first; ⇥ moves into the item's fields and back out, ⌘K opens the actions
//! for the item, ? lists every shortcut, ⌘, has Settings, ⇧⌘⌫ Recently
//! Deleted, and Esc backs out of each. `SHORTCUTS` is the map the ? sheet and Settings show.

use deadbolt_client::protocol::FieldInfo;
use rune::{Key, KeyEvent, Tx};

use crate::model::{App, Screen, is_secret};

/// Every shortcut, as the ? sheet and Settings list them.
pub const SHORTCUTS: &[(&[&str], &str)] = &[
    (&["⌘", "F"], "Search"),
    (&["↑", "↓"], "Move (or J K)"),
    (&["⌘", "1–9"], "Jump to an item"),
    (&["↵"], "Copy password"),
    (&["⇧", "↵"], "Copy username"),
    (&["⌥", "↵"], "Copy code"),
    (&["O"], "Open the website"),
    (&["⇥"], "Into the fields"),
    (&["Space"], "Show a secret"),
    (&["⌘", "K"], "Actions"),
    (&["⌘", "N"], "New item"),
    (&["⌃", "⇥"], "Its type, while new"),
    (&["⌘", "E"], "Edit"),
    (&["⌘", "D"], "Favorite"),
    (&["⌘", "⌫"], "Delete"),
    (&["⇧", "⌘", "⌫"], "Recently deleted"),
    (&["⌘", ","], "Settings"),
    (&["⌘", "L"], "Lock"),
    (&["⇧", "⌘", "Space"], "Quick panel"),
    (&["⇧", "⌘", "I"], "Import"),
    (&["?"], "Shortcuts"),
];

/// Where the keys are, past the search.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Nav {
    /// ⇥ moved into the item: the shown field the keys act on.
    pub field: Option<usize>,
    /// ⌘K's actions are open, on this row.
    pub palette: Option<usize>,
    /// ⌘K's `Filter by tag…` sub-view is open, on `tag_row`.
    pub palette_tags: bool,
    pub tag_row: usize,
    /// The ? sheet shows.
    pub sheet: bool,
    /// The Settings row the keys are on.
    pub row: usize,
}

/// Whether the item page shows this field. A passkey shows its site,
/// username, date and notes; its credential id and user handle are the
/// site's bookkeeping, and the agent never sends its private key.
pub fn shown(kind: &str, field: &str) -> bool {
    kind != "passkey" || matches!(field, "rp-id" | "username" | "created" | "notes")
}

pub(crate) fn plain(ev: &KeyEvent) -> bool {
    !ev.mods.cmd && !ev.mods.shift && !ev.mods.alt && !ev.mods.ctrl
}

pub(crate) fn chord(ev: &KeyEvent, c: char) -> bool {
    ev.is_command(c) && !ev.mods.shift && !ev.mods.alt && !ev.mods.ctrl
}

/// J and K, ↑ and ↓: -1, 1 or none.
pub(crate) fn step(ev: &KeyEvent, letters: bool) -> Option<isize> {
    if !plain(ev) {
        return None;
    }
    match &ev.key {
        Key::Up => Some(-1),
        Key::Down => Some(1),
        Key::Text(t) if letters && t == "k" => Some(-1),
        Key::Text(t) if letters && t == "j" => Some(1),
        _ => None,
    }
}

impl App {
    /// The selected item's fields as its page shows them, in order.
    pub fn shown_fields(&self) -> Vec<&FieldInfo> {
        let Some(item) = self.selected_item() else {
            return Vec::new();
        };
        let Some(full) = self.page().filter(|d| d.id == item.id) else {
            return Vec::new();
        };
        full.fields
            .iter()
            .filter(|f| shown(&full.kind, &f.name))
            .collect()
    }

    /// The field ⇥ moved into, if it's still there.
    pub fn focused_field(&self) -> Option<&FieldInfo> {
        self.shown_fields().get(self.nav.field?).copied()
    }

    /// Whether letters type into the search rather than acting.
    fn typing(&self) -> bool {
        self.search.focused
    }

    /// The main window's vault keys, before the overlays and the list
    /// (`search_key`, `on_key`): ⌘K's actions and the ? sheet take every key
    /// while open, then ⌘, and ⇥, then the keys of the field ⇥ moved into.
    /// `None` for keys they leave alone.
    pub(crate) fn nav_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> Option<bool> {
        if self.screen != Screen::Vault || self.installing() {
            return None;
        }
        if self.nav.palette.is_some() {
            if self.nav.palette_tags {
                return Some(self.palette_tags_key(ev, tx));
            }
            self.palette_key(ev, tx);
            return Some(true);
        }
        if self.panel.is_some() {
            return chord(ev, 'k').then(|| {
                self.open_palette();
                true
            });
        }
        if self.nav.sheet {
            if matches!(ev.key, Key::Escape | Key::Enter) || is_question(ev) {
                self.nav.sheet = false;
            }
            // Locking still locks.
            return (!chord(ev, 'l')).then_some(true);
        }
        if chord(ev, ',') {
            if self.settings_open {
                self.close_settings();
                self.search.focused = true;
            } else {
                self.open_settings();
            }
            return Some(true);
        }
        if is_trash_shortcut(ev) {
            self.toggle_trash();
            return Some(true);
        }
        if self.settings_open || self.trash.open {
            return None;
        }
        // The form and the import view have keys of their own.
        let free = !self.editing() && !self.import.showing() && !self.drop_hovering();
        if !free || self.edit.delete.is_some() {
            return None;
        }
        if chord(ev, 'k') {
            self.open_palette();
            return Some(true);
        }
        if chord(ev, 'd') {
            self.toggle_favorite(tx);
            return Some(true);
        }
        if is_question(ev) && (!self.typing() || self.search.text.is_empty()) {
            self.nav.sheet = true;
            return Some(true);
        }
        if let Key::Command(c @ '1'..='9') = ev.key
            && ev.mods.cmd
            && !ev.mods.shift
            && !ev.mods.alt
            && !ev.mods.ctrl
        {
            let at = c as usize - '1' as usize;
            if let Some(id) = self.visible().get(at).map(|i| i.id.clone()) {
                tx.instant();
                self.select_by_hand(id.clone(), 0);
                tx.scroll_into_view(format!("item-{id}"));
            }
            return Some(true);
        }
        if chord(ev, 'o') || (!self.typing() && is_letter(ev, "o")) {
            self.open_site(tx);
            return Some(true);
        }
        if self.nav.field.is_some() {
            return self.field_key(ev, tx);
        }
        if ev.key == Key::Tab && !ev.mods.cmd && !ev.mods.alt && !ev.mods.ctrl {
            if !ev.mods.shift && !self.shown_fields().is_empty() {
                tx.instant();
                self.nav.field = Some(0);
                self.search.focused = false;
            }
            return Some(true);
        }
        if !self.typing()
            && let Some(by) = step(ev, true).filter(|_| matches!(ev.key, Key::Text(_)))
        {
            self.move_selection(by, tx);
            return Some(true);
        }
        None
    }

    /// Keys on the field ⇥ moved into: ↑↓ (or J K) move between fields, Space
    /// shows or hides a secret, ↵ copies it, and ⇥ or Esc go back to the search.
    /// `None` for keys it leaves to the vault (⌘L, ⌘F, ⌘N, ⌘E, ⌘⌫, ⇧⌘I, ⇧⌘B, typing).
    fn field_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> Option<bool> {
        let count = self.shown_fields().len();
        let Some(at) = self.nav.field.filter(|at| *at < count) else {
            self.nav.field = None;
            return None;
        };
        if let Some(by) = step(ev, true) {
            let next = (at as isize + by).clamp(0, count as isize - 1) as usize;
            tx.instant();
            self.nav.field = Some(next);
            tx.scroll_into_view(format!("field-{}", self.shown_fields()[next].name));
            return Some(true);
        }
        let field = self.shown_fields()[at].clone();
        match &ev.key {
            Key::Tab | Key::Escape if !ev.mods.cmd && !ev.mods.alt && !ev.mods.ctrl => {
                tx.instant();
                self.leave_fields();
            }
            Key::Text(t) if t == " " && plain(ev) => {
                if is_secret(&field.kind) && field.kind != "otp" {
                    self.toggle_reveal(&field.name);
                }
            }
            Key::Enter if !ev.mods.cmd && !ev.mods.ctrl && (ev.mods.shift || ev.mods.alt) => {
                return Some(self.list_key(ev, tx));
            }
            Key::Enter if plain(ev) => self.copy_field(&field.name, tx),
            // Typing goes back to the search with what was typed (`vault_key` / `search`).
            Key::Text(t)
                if !ev.mods.cmd && !ev.mods.alt && !ev.mods.ctrl && !t.trim().is_empty() =>
            {
                self.nav.field = None;
                return None;
            }
            _ => {
                if chord(ev, 'd') {
                    self.toggle_favorite(tx);
                    return Some(true);
                }
                if chord(ev, 'n')
                    || chord(ev, 'e')
                    || crate::import::is_shortcut(ev)
                    || (ev.key == Key::Backspace
                        && ev.mods.cmd
                        && !ev.mods.shift
                        && !ev.mods.alt
                        && !ev.mods.ctrl)
                {
                    self.nav.field = None;
                }
                return None;
            }
        }
        Some(true)
    }

    /// Back from the fields to the search.
    pub fn leave_fields(&mut self) {
        self.nav.field = None;
        self.search.focused = true;
    }

    /// ↑↓, J and K on the list: the item replaces at once, and a hidden list
    /// opens to show where the selection went.
    pub(crate) fn move_selection(&mut self, by: isize, tx: &mut Tx) {
        tx.instant();
        self.sidebar.set_open(true);
        self.step(by);
        if let Some(id) = &self.selected {
            tx.scroll_into_view(format!("item-{id}"));
        }
    }

    /// O and ⌘O: the item's website in the browser.
    pub fn open_site(&mut self, tx: &mut Tx) {
        let Some(url) = self.site() else { return };
        if let Err(e) = tx.open_url(&url) {
            self.notice = Some(format!("Couldn't open {url}: {e}"));
        }
    }

    /// The selected item's website, with a scheme if it had none: a login's
    /// URL field, or a passkey's relying party (a domain, so always https).
    /// Only an http or https address with a host is one.
    pub fn site(&self) -> Option<String> {
        let full = self.page()?;
        let (name, kind) = if full.kind == "passkey" {
            ("rp-id", "text")
        } else {
            ("url", "url")
        };
        let field = full.fields.iter().find(|f| f.name == name)?;
        if field.kind != kind {
            return None;
        }
        web_address(field.value.trim(), kind == "url")
    }

    /// The vault's keys wherever focus is, after overlays and the import view
    /// (`on_key`): the list's, ⌘F to the search, and typing into it from
    /// anywhere, the list hidden or not.
    pub(crate) fn vault_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        if chord(ev, 'f') {
            self.nav.field = None;
            self.sidebar.set_open(true);
            self.focus_search();
            return true;
        }
        if let Key::Text(t) = &ev.key
            && !ev.mods.cmd
            && !ev.mods.alt
            && !ev.mods.ctrl
            && !t.trim().is_empty()
            && !self.search.focused
            && !self.editing()
        {
            tx.instant();
            self.nav.field = None;
            self.search.focused = true;
            self.search.set_caret(self.search.text.len());
            self.search.insert(t);
            self.search_changed();
            return true;
        }
        self.list_key(ev, tx)
    }

    /// ↑↓ select, ⏎, ⇧⏎ and ⌥⏎ copy, esc clears the search.
    pub(crate) fn list_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        if let Some(by) = step(ev, false) {
            self.move_selection(by, tx);
            return true;
        }
        match ev.key {
            Key::Enter if !ev.mods.cmd && !ev.mods.ctrl => {
                let field = match (ev.mods.shift, ev.mods.alt) {
                    (false, true) => "otp",
                    (true, false) => "username",
                    (false, false) => self.primary_field(),
                    (true, true) => return false,
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

    /// ⌘,: Settings in the item's place, on its first row.
    pub fn open_settings(&mut self) {
        if self.editing() || self.deleting() {
            return;
        }
        self.cancel_delete();
        self.import.hover = false;
        self.trash.forget();
        self.settings_open = true;
        self.nav = Nav::default();
        self.search.focused = false;
    }

    /// Keys that act before the search editor and before the vault's list:
    /// the quick-panel fallback, ⌘K / ? / ⌘, / ⇥ fields, Settings or the
    /// install page, the import view, and the form or delete confirm.
    fn intercept_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> Option<bool> {
        if !self.hotkey.recorder.is_recording() && self.panel_shortcut(ev, tx) {
            return Some(true);
        }
        if let Some(handled) = self.nav_key(ev, tx) {
            return Some(handled);
        }
        if let Some(handled) = self.overlay_key(ev, tx) {
            return Some(handled);
        }
        if let Some(handled) = self.import_key(ev) {
            return Some(handled);
        }
        self.edit_key(ev, tx)
    }

    /// Keys in the search field (the vault's and the panel's), before its
    /// editor. True when handled.
    pub fn search_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        self.intercept_key(ev, tx)
            .unwrap_or_else(|| self.list_key(ev, tx))
    }

    /// Keys for Settings or the install page, which sit in the vault's place:
    /// Escape closes them, Settings' rows take the arrows, ↵ and Space, and
    /// nothing else reaches the vault behind. `None` when neither is open.
    fn overlay_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> Option<bool> {
        // The quick panel has no Settings or install offer; its keys are its own.
        if self.screen != Screen::Vault || self.panel.is_some() {
            return None;
        }
        let installing = self.installing();
        if !self.settings_open && !installing && !self.trash.open {
            return None;
        }
        // Import Passwords… leaves either for the import view, as the menu
        // item does; without native menus the key is the only way.
        if crate::import::is_shortcut(ev) && !self.hotkey.recorder.is_recording() {
            return None;
        }
        // Locking still locks.
        if chord(ev, 'l') && !self.hotkey.recorder.is_recording() {
            return None;
        }
        if self.settings_open {
            return Some(self.settings_key(ev, tx));
        }
        if self.trash.open {
            return Some(self.trash_key(ev, tx));
        }
        match ev.key {
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

    /// App-level keys: before the focused field when there is none, after it
    /// otherwise. In the vault that includes the list's keys, so they work
    /// with focus on a button or nowhere.
    pub fn on_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        if let Some(handled) = self.intercept_key(ev, tx) {
            return handled;
        }
        match ev.key {
            _ if self.screen == Screen::Vault && chord(ev, 'l') => {
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

/// ⇧⌘⌫: Recently Deleted.
pub(crate) fn is_trash_shortcut(ev: &KeyEvent) -> bool {
    ev.key == Key::Backspace && ev.mods.cmd && ev.mods.shift && !ev.mods.alt && !ev.mods.ctrl
}

fn is_question(ev: &KeyEvent) -> bool {
    matches!(&ev.key, Key::Text(t) if t == "?") && !ev.mods.cmd && !ev.mods.alt && !ev.mods.ctrl
}

pub(crate) fn is_letter(ev: &KeyEvent, letter: &str) -> bool {
    matches!(&ev.key, Key::Text(t) if t == letter) && plain(ev)
}

/// `value` as an address the browser may open, `https://` added when it has
/// no scheme (or always, for a bare domain): only http and https with a host,
/// so nothing else the system knows how to open (a `file:`, a custom app
/// scheme) is reached from a vault value.
fn web_address(value: &str, may_have_scheme: bool) -> Option<String> {
    if value.is_empty() || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    let address = if value.contains("://") {
        if !may_have_scheme {
            return None;
        }
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    let parsed = url::Url::parse(&address).ok()?;
    (matches!(parsed.scheme(), "http" | "https") && parsed.host().is_some()).then_some(address)
}

#[cfg(test)]
mod tests {
    use super::web_address;

    #[test]
    fn only_web_addresses_open() {
        for (value, opens) in [
            ("github.com", "https://github.com"),
            ("https://github.com/login", "https://github.com/login"),
            ("http://router.local:8080/", "http://router.local:8080/"),
            ("HTTPS://Example.com", "HTTPS://Example.com"),
        ] {
            assert_eq!(web_address(value, true).as_deref(), Some(opens), "{value}");
        }
        for value in [
            "",
            "file:///etc/passwd",
            "file://localhost/Applications/Calculator.app",
            "javascript:alert(1)",
            "javascript://%0aalert(1)",
            "ftp://example.com",
            "x-apple.systempreferences://",
            "vscode://file/tmp/x",
            "smb://server/share",
            "https://",
            "https://exa mple.com",
            "https://example.com/\n",
        ] {
            assert_eq!(web_address(value, true), None, "{value:?}");
        }
        assert_eq!(
            web_address("example.com", false).as_deref(),
            Some("https://example.com")
        );
        assert_eq!(web_address("http://example.com", false), None);
    }
}
