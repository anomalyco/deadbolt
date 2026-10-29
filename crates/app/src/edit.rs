//! Adding, changing and deleting items, in the detail pane. ⌘N opens a form
//! for a new login (or card), ⌘E one for the selected item, and ⌘⌫ asks to
//! delete it in place. The agent checks what's saved; its refusal shows on
//! the field it names. An edit saves only the fields it changed, in one
//! change, so another device's edit to the other fields stays. If the item
//! changes or goes elsewhere while it's open, the form says so and keeps
//! what was typed. Passwords come from the agent's generator.
//! Locking, or the agent stopping, wipes the form wherever it was.

mod form;
pub mod view;

pub use form::{Conflict, Form, Input, Problem, editable};

use deadbolt_client::protocol::{AppAction, ItemInfo};
use rune::{Key, KeyEvent, TextEdit, Tx};
use zeroize::Zeroizing;

use crate::agent::{Failure, Job};
use crate::model::{App, Screen};
use crate::onboarding::sentence;
use form::problem;

/// The generator's lengths, from the length control.
pub const LENGTHS: [usize; 5] = [16, 20, 24, 32, 64];
/// The agent's default length.
const DEFAULT_LENGTH: usize = 24;
/// The menu items.
pub const NEW: &str = "New Item";
pub const EDIT: &str = "Edit Item";
pub const DELETE: &str = "Delete Item…";
/// What ⌘N can add, in the order its picker shows them.
pub const KINDS: [&str; 5] = ["login", "card", "note", "ssh", "identity"];

pub struct Edit {
    pub form: Option<Form>,
    /// Deleting the selected item: asked, or under way.
    pub delete: Option<Delete>,
    /// The generator's length and symbols, kept from one form to the next.
    pub length: usize,
    pub symbols: bool,
    /// Tells the current save's or delete's reply from older ones; bumped on
    /// forgetting.
    seq: u64,
    /// Tags each generator request, apart from `seq`, so a regenerate can't
    /// orphan a save's reply.
    generations: u64,
    /// Stands in for a field that's gone, or one that's saving, when an edit
    /// handler asks for it. Secure, and emptied each time it's handed out.
    scratch: TextEdit,
}

impl Default for Edit {
    fn default() -> Edit {
        Edit {
            form: None,
            delete: None,
            length: DEFAULT_LENGTH,
            symbols: true,
            seq: 0,
            generations: 0,
            scratch: TextEdit::new("").secure(),
        }
    }
}

impl Edit {
    fn scratch(&mut self) -> &mut TextEdit {
        self.scratch.clear();
        &mut self.scratch
    }
}

pub struct Delete {
    pub id: String,
    pub label: String,
    /// The request is on its way.
    pub busy: bool,
    pub error: Option<String>,
}

/// What kind of field a key reaches (`App::form_key`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// A one-line field.
    Line,
    /// A one-line value that wraps, in a text area (`Input::wraps`).
    Wrapped,
    /// A text area.
    Lines,
    /// A secret's text area: masked, and ⏎ breaks the line there too.
    SecretLines,
}

impl App {
    /// Whether ⌘N, ⌘E, ⌘⌫ and their menus may act: the main window's vault,
    /// with its list and item showing (not Settings, the install page, the
    /// import view or a file dragged over the window) and no delete on its way.
    pub fn edits(&self) -> bool {
        self.screen == Screen::Vault
            && self.panel.is_none()
            && !self.settings_open
            && !self.installing()
            && !self.import.showing()
            && !self.drop_hovering()
            && !self.deleting()
    }

    /// A menu's New Item, Edit Item or Delete Item…: only where ⌘N, ⌘E and
    /// ⌘⌫ would act, and then with the main window in front.
    pub fn from_menu(&mut self, act: fn(&mut App)) {
        if !self.edits() {
            return;
        }
        act(self);
        if let Some(windows) = &self.windows {
            windows.open_main();
        }
    }

    /// A delete is on its way to the agent: the selection, the search and
    /// the pane hold until it answers.
    pub fn deleting(&self) -> bool {
        self.edit.delete.as_ref().is_some_and(|d| d.busy)
    }

    pub fn editing(&self) -> bool {
        self.edit.form.is_some()
    }

    /// The current form request's tag, for answering it in tests and scenes.
    pub fn edit_seq(&self) -> u64 {
        self.edit.seq
    }

    /// The generator request the open form waits on, likewise.
    pub fn generating(&self) -> Option<u64> {
        self.edit.form.as_ref().and_then(|f| f.generating)
    }

    /// A save is on its way: the form takes no changes until it answers.
    pub fn saving(&self) -> bool {
        self.edit.form.as_ref().is_some_and(|f| f.saving)
    }

    /// ⌘N: a form for a new login. A form already open stays.
    pub fn new_item(&mut self) {
        if !self.edits() || !self.loaded || !self.leave_edit() {
            return;
        }
        self.edit.delete = None;
        self.edit.form = Some(Form::new("login", "", None));
        self.search.focused = false;
        self.generate();
    }

    /// The new item's type picker: the form changes to that type, keeping
    /// its name and any field both types have.
    pub fn pick_kind(&mut self, kind: &str) {
        let Some(form) = self.edit.form.as_mut().filter(|f| f.is_new() && !f.saving) else {
            return;
        };
        if form.kind == kind {
            return;
        }
        let mut next = Form::new(kind, "", None);
        std::mem::swap(&mut next.name, &mut form.name);
        for input in &mut next.fields {
            let Some(old) = form.fields.iter_mut().find(|f| f.name == input.name) else {
                continue;
            };
            // A secret never moves into a plain field (a secure note's body
            // into a login's notes); plain text moving into a secret is masked.
            if old.secret() && !input.secret() {
                continue;
            }
            std::mem::swap(&mut input.edit, &mut old.edit);
            if input.secret() {
                input.edit.set_secure(true);
            }
        }
        *form = next;
        if form.generates().is_some() {
            self.generate();
        }
    }

    /// ⌃⇥ and ⌃⇧⇥ in a new item's form: the next or last type, round from the ends.
    fn step_kind(&mut self, by: isize) {
        let Some(at) = self
            .edit
            .form
            .as_ref()
            .and_then(|f| KINDS.iter().position(|k| *k == f.kind))
        else {
            return;
        };
        let next = (at as isize + by).rem_euclid(KINDS.len() as isize) as usize;
        self.pick_kind(KINDS[next]);
    }

    /// ⌘E: a form for the selected item, once its values are here.
    pub fn edit_selected(&mut self) {
        if !self.edits() || self.editing() {
            return;
        }
        let Some(item) = self
            .detail
            .as_ref()
            .filter(|d| self.selected.as_deref() == Some(d.id.as_str()) && editable(&d.kind))
        else {
            return;
        };
        let form = Form::new(&item.kind, &item.label, Some(item));
        self.edit.delete = None;
        self.edit.form = Some(form);
        self.search.focused = false;
    }

    /// Closes the form, wiping what was typed. The search takes focus back.
    /// A form that's saving stays until the agent answers.
    pub fn cancel_edit(&mut self) {
        if self.saving() {
            return;
        }
        self.edit.scratch.clear();
        if self.edit.form.take().is_some() {
            self.edit.seq += 1;
            self.search.focused = true;
            self.keep_selection_visible();
        }
    }

    /// Before the selection moves away from an open form: a form without
    /// changes closes; one with changes stays and says so. True when the
    /// selection may move.
    pub fn leave_edit(&mut self) -> bool {
        if self.deleting() {
            return false;
        }
        match &mut self.edit.form {
            None => true,
            Some(form) if form.changed() || form.saving => {
                form.nudge = true;
                false
            }
            Some(_) => {
                self.cancel_edit();
                true
            }
        }
    }

    /// ⌘S, ⏎ or Save. Nothing to save closes the form.
    pub fn save(&mut self) {
        let Some(form) = &mut self.edit.form else {
            return;
        };
        if form.saving {
            return;
        }
        // Only a value that was changed keeps to one line: one left as it
        // came is kept byte for byte.
        let base = form.base.as_ref();
        for input in &mut form.fields {
            if base.and_then(|b| b.value(&input.name)) != Some(input.edit.text.as_str()) {
                input.unwrap_lines();
            }
        }
        let mut changes = match form.changes() {
            Ok(changes) => changes,
            Err(problem) => {
                form.problem = Some(problem);
                return;
            }
        };
        let base = form.saves_over().map(|b| b.0.id.clone());
        if base.is_some() && changes.is_empty() {
            self.cancel_edit();
            return;
        }
        form.problem = None;
        form.nudge = false;
        form.saving = true;
        // A password still on its way would change the form under the save.
        form.generating = None;
        self.edit.seq += 1;
        let seq = self.edit.seq;
        let fields = std::mem::take(&mut changes.set);
        let job = match base {
            Some(id) => Job::Save {
                id,
                name: changes.name.take(),
                fields,
                unset: std::mem::take(&mut changes.unset),
                seq,
            },
            None => Job::Create {
                kind: form.kind.clone(),
                name: changes.name.take().filter(|n| !n.is_empty()),
                fields,
                seq,
            },
        };
        self.agent.send(job);
    }

    /// The form's "Show theirs": the item as it is now, without what was typed.
    pub fn reload_edit(&mut self) {
        let Some(form) = &self.edit.form else { return };
        if form.conflict != Some(Conflict::Changed) || form.saving {
            return;
        }
        let Some(item) = self
            .detail
            .as_ref()
            .filter(|d| form.id.as_deref() == Some(d.id.as_str()))
        else {
            return;
        };
        self.edit.form = Some(Form::new(&item.kind, &item.label, Some(item)));
        self.search.focused = false;
    }

    /// A field changed: its problem has been seen to.
    pub fn form_changed(&mut self) {
        if let Some(form) = &mut self.edit.form {
            form.problem = None;
            form.nudge = false;
        }
    }

    /// A wrapping one-line field changed: it keeps to one line.
    pub fn wrapped_changed(&mut self, field: usize) {
        if let Some(input) = self
            .edit
            .form
            .as_mut()
            .and_then(|f| f.fields.get_mut(field))
        {
            input.unwrap_lines();
        }
        self.form_changed();
    }

    /// ⏎ in a text area that isn't secret breaks the line: Rune submits a
    /// plain ⏎ there.
    pub fn break_line(&mut self, field: usize) {
        if self.edit.form.as_ref().is_some_and(|f| !f.saving) {
            self.input_mut(field).insert("\n");
            self.form_changed();
        }
    }

    /// Reveals a secret field's value in place, or masks it again. It stays
    /// secure (no copy, cut or undo), and Rune masks it as it goes. A kept
    /// value is loaded to show, then edited like any other; hidden again
    /// unchanged, it's kept again. Either way the field is focused, alone.
    pub fn toggle_shown(&mut self, field: usize) {
        let Some(form) = &mut self.edit.form else {
            return;
        };
        if form.saving || !form.fields.get(field).is_some_and(Input::secret) {
            return;
        }
        let saved = form
            .base
            .as_ref()
            .and_then(|b| b.value(&form.fields[field].name));
        let input = &mut form.fields[field];
        let mut shown = None;
        if input.edit.is_revealed() {
            input.edit.set_revealed(false);
            if input.lines && saved == Some(input.edit.text.as_str()) {
                input.keep();
            }
        } else {
            if input.keeps()
                && let Some(saved) = saved
            {
                input.edit.replace_text(saved.to_owned());
                let end = saved.len();
                input.edit.set_selection(end, end);
            }
            // Shown, it's an ordinary field: emptied on purpose, it's emptied.
            input.kept = false;
            input.edit.set_revealed(true);
            shown = form.base.as_ref().map(|_| input.name.clone());
        }
        // Show and Hide are pressed to edit on: focus goes back to the field.
        self.search.focused = false;
        form.name.focused = false;
        for (i, input) in form.fields.iter_mut().enumerate() {
            input.edit.focused = i == field;
        }
        if let Some(name) = shown {
            self.report(AppAction::Reveal, &name);
        }
    }

    /// The field's edit, for its input's handlers. A field that's gone (the
    /// form closed, or changed type) or saving gets a scratch one.
    pub fn input_mut(&mut self, field: usize) -> &mut TextEdit {
        if let Some(form) = self.edit.form.as_mut().filter(|f| !f.saving)
            && let Some(input) = form.fields.get_mut(field)
        {
            return &mut input.edit;
        }
        self.edit.scratch()
    }

    pub fn name_mut(&mut self) -> &mut TextEdit {
        if let Some(form) = self.edit.form.as_mut().filter(|f| !f.saving) {
            return &mut form.name;
        }
        self.edit.scratch()
    }

    // ---------------------------------------------------------------------------------------
    // The generator

    /// Asks the agent for a password at the form's length and symbols.
    pub fn generate(&mut self) {
        let Some(form) = self
            .edit
            .form
            .as_mut()
            .filter(|f| f.generates().is_some() && !f.saving)
        else {
            return;
        };
        self.edit.generations += 1;
        form.generating = Some(self.edit.generations);
        self.agent.send(Job::Generate {
            length: self.edit.length,
            symbols: self.edit.symbols,
            seq: self.edit.generations,
        });
    }

    pub fn set_length(&mut self, length: usize) {
        if self.edit.length != length && !self.saving() {
            self.edit.length = length;
            self.generate();
        }
    }

    pub fn toggle_symbols(&mut self) {
        if self.saving() {
            return;
        }
        self.edit.symbols = !self.edit.symbols;
        self.generate();
    }

    pub(crate) fn on_generated(
        &mut self,
        seq: u64,
        result: Result<Zeroizing<String>, Failure>,
        tx: &mut Tx,
    ) {
        let Some(form) = &mut self.edit.form else {
            return;
        };
        if form.generating != Some(seq) {
            return;
        }
        form.generating = None;
        let Some(at) = form.generates() else { return };
        match result {
            Ok(mut password) => {
                let input = &mut form.fields[at];
                input.edit.replace_text(std::mem::take(&mut *password));
                // A password the person didn't type shows, so they see what they got.
                input.edit.set_revealed(true);
                form.generated += 1;
                if form.problem_for("password").is_some() {
                    form.problem = None;
                }
            }
            Err(failure) if failure.locked() => self.on_locked(tx),
            Err(failure) => {
                form.problem = Some(Problem {
                    field: Some("password".into()),
                    message: format!("Couldn't generate a password: {}", failure.message),
                })
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Deleting

    /// ⌘⌫: asks, in place, to delete the selected item.
    pub fn ask_delete(&mut self) {
        if !self.edits() || self.editing() {
            return;
        }
        let Some(item) = self.selected_item() else {
            return;
        };
        let delete = Delete {
            id: item.id.clone(),
            label: item.label.clone(),
            busy: false,
            error: None,
        };
        if self.edit.delete.as_ref().is_none_or(|d| d.id != delete.id) {
            self.edit.delete = Some(delete);
        }
    }

    /// The confirm's Delete (or ⏎).
    pub fn delete_now(&mut self) {
        let Some(delete) = self.edit.delete.as_mut().filter(|d| !d.busy) else {
            return;
        };
        delete.busy = true;
        delete.error = None;
        self.edit.seq += 1;
        self.agent.send(Job::Remove {
            id: delete.id.clone(),
            seq: self.edit.seq,
        });
    }

    pub fn cancel_delete(&mut self) {
        if self.edit.delete.as_ref().is_some_and(|d| !d.busy) {
            self.edit.delete = None;
        }
    }

    pub(crate) fn on_removed(&mut self, seq: u64, result: Result<ItemInfo, Failure>, tx: &mut Tx) {
        if seq != self.edit.seq || self.screen != Screen::Vault {
            return;
        }
        let Some(delete) = &mut self.edit.delete else {
            return;
        };
        match result {
            Ok(item) => {
                self.edit.delete = None;
                self.cache.remove(&item.id);
                // The next item down takes its place (or the one above, at the end).
                let visible = self.visible();
                let next = visible
                    .iter()
                    .position(|i| i.id == item.id)
                    .and_then(|at| {
                        visible
                            .get(at + 1)
                            .or_else(|| at.checked_sub(1).and_then(|p| visible.get(p)))
                    })
                    .map(|i| i.id.clone());
                self.items.retain(|i| i.id != item.id);
                self.select(next);
                self.list();
            }
            Err(failure) if failure.locked() => self.on_locked(tx),
            Err(failure) => {
                delete.busy = false;
                delete.error = Some(sentence(&failure.message));
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Saving, and what other devices do meanwhile

    pub(crate) fn on_saved(&mut self, seq: u64, result: Result<ItemInfo, Failure>, tx: &mut Tx) {
        if seq != self.edit.seq || self.screen != Screen::Vault {
            return;
        }
        let Some(form) = &mut self.edit.form else {
            return;
        };
        match result {
            Ok(item) => {
                // The list shows it at once; the refetch confirms it. The form
                // stays until the item's values land, then swaps to them.
                let id = item.id.clone();
                form.landing = Some(id.clone());
                // What the cache kept of it is from before.
                self.forget_pages();
                match self.items.iter_mut().find(|i| i.id == id) {
                    Some(listed) => *listed = item,
                    None => {
                        let at = self.items.partition_point(|i| {
                            (i.label.to_lowercase(), &i.id) < (item.label.to_lowercase(), &item.id)
                        });
                        self.items.insert(at, item);
                    }
                }
                // A search that would hide it gives way.
                if !self.visible().iter().any(|i| i.id == id) {
                    self.search.clear();
                }
                if self.selected.as_deref() == Some(id.as_str()) {
                    // The same item: fetch its new values.
                    self.selected = None;
                }
                self.select(Some(id.clone()));
                self.list();
                tx.scroll_into_view(format!("item-{id}"));
            }
            Err(failure) if failure.locked() => self.on_locked(tx),
            Err(failure) => {
                form.saving = false;
                form.problem = Some(problem(&failure.message));
            }
        }
    }

    /// An item's values landed (`Done::Item`): a form waiting for them
    /// closes; one open on that item learns whether it changed elsewhere.
    pub(crate) fn edit_item_landed(&mut self, item: &ItemInfo) {
        let Some(form) = &mut self.edit.form else {
            return;
        };
        if form.landing.as_deref() == Some(item.id.as_str()) {
            self.edit.form = None;
            self.search.focused = true;
            return;
        }
        if form.saving || form.id.as_deref() != Some(item.id.as_str()) {
            return;
        }
        if form.base.as_ref().is_some_and(|b| !b.same(item)) {
            form.conflict = Some(Conflict::Changed);
        }
    }

    /// The saved item's values didn't come: it's saved, so the form closes
    /// rather than wait.
    pub(crate) fn edit_item_failed(&mut self) {
        if self.edit.form.as_ref().is_some_and(|f| f.landing.is_some()) {
            self.edit.form = None;
            self.search.focused = true;
        }
    }

    /// A new list landed: an item open in the form, or asked to be deleted,
    /// may have gone.
    pub(crate) fn edit_items_landed(&mut self) {
        let items = &self.items;
        let gone = |id: &str| !items.iter().any(|i| i.id == id);
        if let Some(form) = &mut self.edit.form
            && !form.saving
            && form.id.as_deref().is_some_and(gone)
        {
            form.conflict = Some(Conflict::Deleted);
        }
        if self
            .edit
            .delete
            .as_ref()
            .is_some_and(|d| !d.busy && gone(&d.id))
        {
            self.edit.delete = None;
        }
    }

    /// Wipes the form and drops replies still on their way.
    pub(crate) fn forget_edit(&mut self) {
        let seq = self.edit.seq + 1;
        self.edit.form = None;
        self.edit.delete = None;
        self.edit.seq = seq;
        self.edit.scratch.clear();
    }

    /// Keys for the form and the delete confirm, before the list's: ⌘N, ⌘E
    /// and ⌘⌫ start them; in the form ⌘S and ⏎ save and esc cancels; in the
    /// confirm ⏎ deletes and esc cancels. `None` for keys they leave alone.
    pub(crate) fn edit_key(&mut self, ev: &KeyEvent) -> Option<bool> {
        if self.screen != Screen::Vault || self.panel.is_some() {
            return None;
        }
        if self.deleting() {
            // Only locking, the sidebar and the quick panel get past "Deleting…".
            let through = ev.is_command('l')
                || rune_kit::shell::is_sidebar_toggle(ev)
                || crate::panel::window::is_shortcut(ev);
            return (!through).then_some(true);
        }
        if !self.edits() {
            return None;
        }
        let plain = !ev.mods.shift && !ev.mods.alt && !ev.mods.ctrl;
        let chord = |c| ev.is_command(c) && plain;
        if self.editing() {
            match ev.key {
                Key::Escape => self.cancel_edit(),
                _ if chord('s') => self.save(),
                // Every Enter is the form's: ⌘⏎ saves, and ⏎ does outside the
                // search; other chords do nothing rather than reach the list.
                Key::Enter => {
                    let save = (ev.mods.cmd && plain)
                        || (ev.mods == rune::Mods::default() && !self.search.focused);
                    if save {
                        self.save();
                    }
                }
                _ if chord('n') => self.new_item(),
                // An unchanged form gives way to the next item; one with
                // changes keeps the selection and says so.
                Key::Up | Key::Down => {
                    if self.leave_edit() {
                        return None;
                    }
                }
                _ => return None,
            }
            return Some(true);
        }
        if chord('n') {
            self.new_item();
            return Some(true);
        }
        if chord('e') {
            self.edit_selected();
            return Some(true);
        }
        // In the search, ⌘⌫ clears what's typed first.
        let typing = self.search.focused && !self.search.text.is_empty();
        if ev.key == Key::Backspace && ev.mods.cmd && plain && !typing {
            self.ask_delete();
            return Some(true);
        }
        let delete = self.edit.delete.as_ref()?;
        match ev.key {
            Key::Enter if ev.mods == rune::Mods::default() => self.delete_now(),
            Key::Escape if !delete.busy => self.cancel_delete(),
            Key::Escape | Key::Enter => {}
            // Moving on cancels it.
            _ => {
                self.cancel_delete();
                return None;
            }
        }
        Some(true)
    }

    /// ⌘C in a secret field, which Rune won't copy from: its selection goes
    /// to the clipboard concealed and clears with the countdown, as a copied
    /// item's password does.
    pub fn copy_secret_input(&mut self, field: usize, ev: &KeyEvent, tx: &mut Tx) -> bool {
        if !ev.is_command('c') || ev.mods.shift || ev.mods.alt || ev.mods.ctrl {
            return false;
        }
        let Some(form) = self.edit.form.as_ref() else {
            return false;
        };
        let Some(input) = form.fields.get(field).filter(|i| i.secret()) else {
            return false;
        };
        let selected = input.edit.selected();
        if !selected.is_empty() {
            let saved = form
                .base
                .as_ref()
                .map(|b| (b.0.id.clone(), b.0.label.clone()));
            let (name, value) = (input.name.clone(), selected.to_owned());
            self.copy_value(saved, name, value, tx);
        }
        true
    }

    /// Keys in a form field, before its editor: esc cancels the form rather
    /// than leaving the field, ⌘S and ⌘⏎ save. Enter with other modifiers
    /// does nothing in a one-line field (it would submit); a text area keeps
    /// them for its lines. True when handled.
    pub fn form_key(&mut self, ev: &KeyEvent, field: Field) -> bool {
        let plain = !ev.mods.shift && !ev.mods.alt && !ev.mods.ctrl;
        let cmd_enter = ev.mods.cmd && plain;
        match (&ev.key, field) {
            (Key::Escape, _) => self.cancel_edit(),
            (Key::Tab, _) if ev.mods.ctrl && !ev.mods.cmd && !ev.mods.alt => {
                self.step_kind(if ev.mods.shift { -1 } else { 1 })
            }
            // A secret's text area submits ⌘⏎ itself (its `on_submit` saves);
            // other ⌘ and ⌃ chords would submit too, so they do nothing.
            (Key::Enter, Field::SecretLines) if cmd_enter => return false,
            (Key::Enter, Field::SecretLines) if ev.mods.cmd || ev.mods.ctrl => {}
            (Key::Enter, Field::SecretLines) => return false,
            (Key::Enter, _) if cmd_enter => self.save(),
            (Key::Enter, Field::Line | Field::Wrapped) if ev.mods != rune::Mods::default() => {}
            // A one-line value in a text area: ⏎ saves rather than breaking it.
            (Key::Enter, Field::Wrapped) => self.save(),
            _ if ev.is_command('s') && plain => self.save(),
            _ if ev.is_command('n') && plain => self.new_item(),
            _ => return false,
        }
        true
    }
}
