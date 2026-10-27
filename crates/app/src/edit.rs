//! Adding, changing and deleting items, in the detail pane. ⌘N opens a form
//! for a new login (or card), ⌘E one for the selected item, and ⌘⌫ asks to
//! delete it in place. The agent checks what's saved; its refusal shows on
//! the field it names. An edit saves only the fields it changed, in one
//! change, so another device's edit to the other fields stays. If the item
//! changes or goes elsewhere while it's open, the form says so and keeps
//! what was typed. Passwords come from the agent's generator.
//! Locking, or the agent stopping, wipes the form wherever it was.

pub mod view;

use deadbolt_client::protocol::{FieldInfo, FieldInput, ItemInfo};
use rune::{Key, KeyEvent, TextEdit, Tx};
use zeroize::{Zeroize, Zeroizing};

use crate::agent::{Failure, Job};
use crate::model::{App, Screen, is_secret, title_case};

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

/// A built-in item type's fields: name, field type, required, spans lines.
/// The agent's schema (`deadbolt_core::item`) is the authority; this is the
/// form's layout.
fn schema(kind: &str) -> &'static [(&'static str, &'static str, bool, bool)] {
    match kind {
        "login" => &[
            ("username", "text", false, false),
            ("password", "secret", false, false),
            ("url", "url", false, false),
            ("otp", "otp", false, false),
            ("notes", "note", false, true),
        ],
        "card" => &[
            ("cardholder", "text", false, false),
            ("number", "secret", true, false),
            ("expiry", "month", false, false),
            ("cvv", "secret", false, false),
            ("pin", "secret", false, false),
            ("brand", "text", false, false),
            ("notes", "note", false, true),
        ],
        "note" => &[("notes", "secret", false, true)],
        "ssh" => &[
            ("private-key", "secret", true, true),
            ("public-key", "text", false, false),
            ("fingerprint", "text", false, false),
            ("passphrase", "secret", false, false),
            ("comment", "text", false, false),
            ("notes", "note", false, true),
        ],
        "identity" => &[
            ("name", "text", false, false),
            ("email", "email", false, false),
            ("phone", "text", false, false),
            ("address", "note", false, true),
            ("birthday", "date", false, false),
            ("national-id", "secret", false, false),
            ("passport", "secret", false, false),
            ("license", "secret", false, false),
            ("notes", "note", false, true),
        ],
        _ => &[],
    }
}

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

fn scratch() -> TextEdit {
    let mut edit = TextEdit::new("");
    edit.set_secure(true);
    edit
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
            scratch: scratch(),
        }
    }
}

pub struct Form {
    /// The item being changed; `None` for a new one.
    pub id: Option<String>,
    pub kind: String,
    pub name: TextEdit,
    pub fields: Vec<Input>,
    /// The item as it was when the form opened, to save only what changed
    /// and to tell when another device changes it meanwhile.
    base: Option<Snapshot>,
    pub conflict: Option<Conflict>,
    /// A save is on its way, or saved and waiting for the item's values.
    pub saving: bool,
    /// Saved: the form stays until this item's values land, then swaps to them.
    landing: Option<String>,
    pub problem: Option<Problem>,
    /// Asked to leave while it holds changes.
    pub nudge: bool,
    /// The generator's request in flight.
    generating: Option<u64>,
    /// Passwords generated so far, so each one swaps in (`view`).
    pub generated: u64,
}

pub struct Input {
    pub name: String,
    /// The field type: `secret` and `otp` fields are always masked.
    pub kind: String,
    pub required: bool,
    /// Values span lines: a text area, masked for a secret.
    pub lines: bool,
    pub edit: TextEdit,
    /// The item has a value the agent keeps back (a one-time password's
    /// secret): left empty, it stays; typed into, it's replaced.
    pub held: bool,
    /// A secret text area for a value the item has: left empty, it stands
    /// for that value, kept; typed or pasted into, it's replaced. Show loads
    /// the value to edit in place (`App::toggle_shown`).
    pub kept: bool,
}

impl Drop for Input {
    /// A closed form wipes every field, not only its secrets.
    fn drop(&mut self) {
        self.wipe();
    }
}

impl Drop for Form {
    /// The name goes with the fields.
    fn drop(&mut self) {
        self.name.set_secure(true);
        self.name.clear();
    }
}

impl Input {
    fn new(name: &str, kind: &str, required: bool, lines: bool, value: String) -> Input {
        let mut edit = TextEdit::new(value);
        if is_secret(kind) {
            edit.set_secure(true);
        }
        Input {
            name: name.into(),
            kind: kind.into(),
            required,
            lines,
            edit,
            held: false,
            kept: false,
        }
    }

    pub fn secret(&self) -> bool {
        is_secret(&self.kind)
    }

    /// One line that may run long (an SSH public key or fingerprint): a text
    /// area that wraps, where ⏎ saves as in any one-line field.
    pub fn wraps(&self) -> bool {
        !self.lines && matches!(self.name.as_str(), "public-key" | "fingerprint")
    }

    /// Standing for the item's value, with nothing typed in its place.
    pub fn keeps(&self) -> bool {
        self.kept && self.value().is_none()
    }

    /// Lets the item's value stand: an empty, hidden editor, never holding
    /// the value itself, so nothing typed into it can be taken as an edit of
    /// a value it can't show.
    fn keep(&mut self) {
        self.edit.set_revealed(false);
        self.edit.clear();
        self.kept = true;
    }

    /// Drops the line breaks a hard-wrapped paste left in a wrapping one-line
    /// value (`wraps`), where they'd hide among its soft wraps.
    fn unwrap_lines(&mut self) {
        if !self.wraps() || !self.edit.text.contains(['\r', '\n']) {
            return;
        }
        let (a, b) = self.edit.range();
        let at = |byte: usize, text: &str| byte - text[..byte].matches(['\r', '\n']).count();
        let (a, b) = (at(a, &self.edit.text), at(b, &self.edit.text));
        let text = self.edit.text.replace(['\r', '\n'], "");
        self.edit.replace_text(text);
        self.edit.set_selection(a, b);
    }

    /// Masks and empties the field: Rune wipes a secure edit's buffers as
    /// they're replaced and dropped, and keeps no undo history for it.
    fn wipe(&mut self) {
        self.edit.set_secure(true);
        self.edit.set_revealed(false);
        self.edit.clear();
    }

    /// The value to save, if any: text is trimmed; secrets and text that
    /// spans lines are kept as typed (a private key's final line break too),
    /// unless they're only whitespace.
    fn value(&self) -> Option<&str> {
        let text = self.edit.text.as_str();
        if text.trim().is_empty() {
            None
        } else if self.secret() || self.lines {
            Some(text)
        } else {
            Some(text.trim())
        }
    }
}

/// Why the form wasn't saved, on the field it's about (`None` for the form).
#[derive(Clone, Debug, PartialEq)]
pub struct Problem {
    pub field: Option<String>,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conflict {
    /// Another device changed the item while it was open here.
    Changed,
    /// Another device deleted it.
    Deleted,
}

pub struct Delete {
    pub id: String,
    pub label: String,
    /// The request is on its way.
    pub busy: bool,
    pub error: Option<String>,
}

/// An item's values, wiped when dropped.
struct Snapshot(ItemInfo);

impl Drop for Snapshot {
    fn drop(&mut self) {
        crate::model::forget(&mut self.0);
    }
}

impl Snapshot {
    fn value(&self, field: &str) -> Option<&str> {
        self.0
            .fields
            .iter()
            .find(|f| f.name == field)
            .map(|f| f.value.as_str())
    }

    fn same(&self, item: &ItemInfo) -> bool {
        fn fields(i: &ItemInfo) -> Vec<(&str, &str)> {
            i.fields
                .iter()
                .map(|f| (f.name.as_str(), f.value.as_str()))
                .collect()
        }
        self.0.label == item.label && fields(&self.0) == fields(item)
    }
}

/// What a save sends, wiped when dropped unless sent.
#[derive(Default)]
struct Changes {
    name: Option<String>,
    set: Vec<FieldInput>,
    unset: Vec<String>,
}

impl Drop for Changes {
    fn drop(&mut self) {
        for f in &mut self.set {
            f.value.zeroize();
        }
    }
}

impl Changes {
    fn is_empty(&self) -> bool {
        self.name.is_none() && self.set.is_empty() && self.unset.is_empty()
    }
}

impl Form {
    fn new(kind: &str, name: &str, item: Option<&ItemInfo>) -> Form {
        let mut fields: Vec<Input> = schema(kind)
            .iter()
            .map(|&(field, ty, required, lines)| {
                let had = item.and_then(|i| i.fields.iter().find(|f| f.name == field));
                let value = had.map(|f| f.value.clone()).unwrap_or_default();
                let kept = lines && is_secret(ty) && !value.is_empty();
                let mut input = Input::new(field, ty, required, lines, value);
                input.held = had.is_some_and(|f| f.value.is_empty());
                if kept {
                    input.keep();
                }
                input
            })
            .collect();
        // Fields the schema doesn't know (an import's extras, or a type this
        // build doesn't know) follow, as they are.
        for FieldInfo {
            name: field,
            kind: ty,
            value,
        } in item.map_or(&[][..], |i| &i.fields[..])
        {
            if !fields.iter().any(|f| &f.name == field) {
                let lines = ty == "note" || value.contains('\n');
                let mut input = Input::new(field, ty, false, lines, value.clone());
                input.held = value.is_empty();
                if lines && input.secret() && !value.is_empty() {
                    input.keep();
                }
                fields.push(input);
            }
        }
        let mut name = TextEdit::new(name);
        name.focused = true;
        Form {
            id: item.map(|i| i.id.clone()),
            kind: kind.into(),
            name,
            fields,
            base: item.map(|i| Snapshot(i.clone())),
            conflict: None,
            saving: false,
            landing: None,
            problem: None,
            nudge: false,
            generating: None,
            generated: 0,
        }
    }

    pub fn is_new(&self) -> bool {
        self.id.is_none()
    }

    /// The field the generator fills: a login's password.
    pub fn generates(&self) -> Option<usize> {
        (self.kind == "login")
            .then(|| self.fields.iter().position(|f| f.name == "password"))
            .flatten()
    }

    /// What saving would send. A new item (or one deleted meanwhile, saved
    /// again as new) sends every field with a value; an edit, only the
    /// fields that changed, and empties the ones that were cleared.
    fn changes(&self) -> Result<Changes, Problem> {
        let mut changes = Changes::default();
        for input in &self.fields {
            let value = if input.keeps() {
                self.base.as_ref().and_then(|b| b.value(&input.name))
            } else {
                input.value()
            };
            if input.required && value.is_none() {
                return Err(Problem {
                    field: Some(input.name.clone()),
                    message: format!("{} can't be empty.", title_case(&input.name)),
                });
            }
            let was = self.saves_over().and_then(|b| b.value(&input.name));
            match (value, was) {
                // Left as it came (a public key with a line break from an
                // import, say), it isn't trimmed into a change.
                (Some(v), Some(w)) if v == w || input.edit.text.as_str() == w => {}
                (Some(v), _) => changes.set.push(FieldInput {
                    name: input.name.clone(),
                    kind: Some(input.kind.clone()),
                    value: v.to_owned(),
                }),
                (None, Some(_)) if input.held => {}
                (None, Some(_)) => changes.unset.push(input.name.clone()),
                (None, None) => {}
            }
        }
        let name = self.name.text.trim();
        match self.saves_over() {
            Some(base) if name != base.0.label => changes.name = Some(name.to_owned()),
            None if !name.is_empty() => changes.name = Some(name.to_owned()),
            _ => {}
        }
        Ok(changes)
    }

    /// The item a save changes, unless it's new or gone.
    fn saves_over(&self) -> Option<&Snapshot> {
        self.base
            .as_ref()
            .filter(|_| self.conflict != Some(Conflict::Deleted))
    }

    /// Whether leaving would lose something typed.
    pub fn changed(&self) -> bool {
        match self.changes() {
            Ok(c) if self.saves_over().is_some() => !c.is_empty(),
            // A new item: anything typed (a generated password counts).
            _ => {
                !self.name.text.trim().is_empty() || self.fields.iter().any(|f| f.value().is_some())
            }
        }
    }

    pub fn problem_for(&self, field: &str) -> Option<&str> {
        self.problem
            .as_ref()
            .filter(|p| p.field.as_deref() == Some(field))
            .map(|p| p.message.as_str())
    }
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
        if !self.edits() || !self.loaded {
            return;
        }
        // An unchanged form gives way; one with changes stays and says so.
        if !self.leave_edit() {
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

    /// ⌘E: a form for the selected item, once its values are here.
    pub fn edit_selected(&mut self) {
        if !self.edits() || self.editing() {
            return;
        }
        let Some(item) = self
            .detail
            .as_ref()
            .filter(|d| self.selected.as_deref() == Some(d.id.as_str()))
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
        let form = Form::new(&item.kind, &item.label, Some(item));
        self.edit.form = Some(form);
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
        }
        // Show and Hide are pressed to edit on: focus goes back to the field.
        self.search.focused = false;
        form.name.focused = false;
        for (i, input) in form.fields.iter_mut().enumerate() {
            input.edit.focused = i == field;
        }
    }

    /// The field's edit, for its input's handlers. A field that's gone (the
    /// form closed, or changed type) or saving gets a scratch one.
    pub fn input_mut(&mut self, field: usize) -> &mut TextEdit {
        match self
            .edit
            .form
            .as_mut()
            .filter(|f| !f.saving)
            .and_then(|f| f.fields.get_mut(field))
        {
            Some(input) => &mut input.edit,
            None => {
                self.edit.scratch.clear();
                &mut self.edit.scratch
            }
        }
    }

    pub fn name_mut(&mut self) -> &mut TextEdit {
        match self.edit.form.as_mut().filter(|f| !f.saving) {
            Some(form) => &mut form.name,
            None => {
                self.edit.scratch.clear();
                &mut self.edit.scratch
            }
        }
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
        let Some(input) = self
            .edit
            .form
            .as_ref()
            .and_then(|f| f.fields.get(field))
            .filter(|i| i.secret())
        else {
            return false;
        };
        let selected = input.edit.selected();
        if !selected.is_empty() {
            let (name, value) = (input.name.clone(), selected.to_owned());
            self.copy_value(String::new(), name, value, tx);
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

/// The agent's refusal, on the field it names where it names one.
fn problem(message: &str) -> Problem {
    let after = |prefix: &str| message.find(prefix).map(|at| &message[at + prefix.len()..]);
    if let Some((field, reason)) = after("invalid value for ").and_then(|r| r.split_once(": ")) {
        let label = title_case(field);
        let message = if let Some(range) = reason
            .strip_prefix("must be ")
            .and_then(|r| r.strip_suffix(" digits"))
        {
            format!("{label} must be {} digits.", range.replace('-', " to "))
        } else {
            match reason {
                "empty" => format!("{label} can't be empty."),
                "not a month (YYYY-MM)" => format!("{label} must be a month, like 08/29."),
                "not an absolute URL" => {
                    format!("{label} must be a web address, like example.com.")
                }
                "not an email address" => format!("{label} must be an email address."),
                reason => sentence(&format!("{label}: {reason}")),
            }
        };
        return Problem {
            field: Some(field.to_owned()),
            message,
        };
    }
    if let Some(field) = after("missing required field ") {
        return Problem {
            field: Some(field.to_owned()),
            message: format!("{} can't be empty.", title_case(field)),
        };
    }
    if message.contains("invalid item name") {
        return Problem {
            field: Some("name".into()),
            message: "A name is up to 128 characters, on one line.".into(),
        };
    }
    Problem {
        field: None,
        message: sentence(message),
    }
}

/// A message as a sentence: capitalised, with a full stop.
fn sentence(message: &str) -> String {
    let mut chars = message.trim().chars();
    let mut out: String = match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => return String::new(),
    };
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(fields: &[(&str, &str, &str)]) -> ItemInfo {
        ItemInfo {
            id: "a1".into(),
            short: "a1".into(),
            kind: "login".into(),
            label: "GitHub".into(),
            detail: None,
            fields: fields
                .iter()
                .map(|&(name, kind, value)| FieldInfo {
                    name: name.into(),
                    kind: kind.into(),
                    value: value.into(),
                })
                .collect(),
        }
    }

    fn set(form: &mut Form, field: &str, value: &str) {
        let input = form.fields.iter_mut().find(|f| f.name == field).unwrap();
        input.edit.replace_text(value);
    }

    #[test]
    fn an_edit_sends_only_what_changed() {
        let item = item(&[
            ("password", "secret", "pw-1"),
            ("username", "text", "dax"),
            ("notes", "note", "old"),
            ("pet", "text", "rex"),
        ]);
        let mut form = Form::new("login", &item.label, Some(&item));
        assert!(!form.changed());
        assert!(form.changes().unwrap().is_empty());
        let names: Vec<&str> = form.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            ["username", "password", "url", "otp", "notes", "pet"]
        );

        set(&mut form, "username", "  kit ");
        set(&mut form, "notes", " \n");
        set(&mut form, "url", "github.com");
        let c = form.changes().unwrap();
        let sent: Vec<(&str, &str)> = c
            .set
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(sent, [("username", "kit"), ("url", "github.com")]);
        assert_eq!(c.unset, ["notes"]);
        assert_eq!(c.name, None);
        assert!(form.changed());

        form.name.replace_text("");
        assert_eq!(form.changes().unwrap().name.as_deref(), Some(""));
        set(&mut form, "password", "  ");
        assert_eq!(form.changes().unwrap().unset, ["password", "notes"]);
    }

    #[test]
    fn an_item_deleted_meanwhile_saves_as_new() {
        let item = item(&[("password", "secret", "pw-1")]);
        let mut form = Form::new("login", &item.label, Some(&item));
        form.conflict = Some(Conflict::Deleted);
        let c = form.changes().unwrap();
        assert_eq!(c.set.len(), 1);
        assert_eq!(c.name.as_deref(), Some("GitHub"));
    }

    #[test]
    fn a_wiped_field_is_masked_and_empty() {
        for (name, kind) in [("username", "text"), ("password", "secret")] {
            let mut input = Input::new(name, kind, false, false, "dax-hunter22".into());
            input.edit.set_revealed(true);
            input.wipe();
            assert!(input.edit.is_secure() && input.edit.text.is_empty());
            assert!(!input.edit.is_revealed());
        }
    }

    #[test]
    fn secrets_start_masked() {
        let form = Form::new("card", "", None);
        let masked: Vec<&str> = form
            .fields
            .iter()
            .filter(|f| f.edit.is_secure())
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(masked, ["number", "cvv", "pin"]);
        assert!(form.generates().is_none());
        assert!(Form::new("login", "", None).generates().is_some());
    }

    #[test]
    fn the_agents_refusals_land_on_their_fields() {
        let p = problem("invalid value for number: must be 12-19 digits");
        assert_eq!(p.field.as_deref(), Some("number"));
        assert_eq!(p.message, "Number must be 12 to 19 digits.");
        let p = problem("invalid value for expiry: not a month (YYYY-MM)");
        assert_eq!(p.message, "Expiry must be a month, like 08/29.");
        let p = problem("missing required field password");
        assert_eq!(
            (p.field.as_deref(), p.message.as_str()),
            (Some("password"), "Password can't be empty.")
        );
        let p = problem("invalid item name: use 1-128 characters without control characters");
        assert_eq!(p.field.as_deref(), Some("name"));
        let p = problem("the vault is read-only");
        assert_eq!(
            (p.field, p.message.as_str()),
            (None, "The vault is read-only.")
        );
    }
}
