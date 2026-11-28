//! Pure form state, item field schema, change diffing and daemon refusal parsing.

use deadbolt_core::item::SchemaField;
use deadbolt_core::tag::fold_tag;
use deadbolt_proto::daemon::{FieldInfo, FieldInput, ItemInfo};
use rune::TextEdit;
use zeroize::Zeroize;

use crate::model::{is_secret, title_case};
use crate::onboarding::sentence;

/// Whether the app edits items of this type. A passkey is made by a site
/// through the browser, and its private key never reaches the app: it can
/// only be deleted here.
pub fn editable(kind: &str) -> bool {
    kind != "passkey"
}

/// Fields the form leaves out: a login's sign-in provider and the login it
/// signs in with, and a card's billing identity, which link to other items
/// by id and have no picker here yet, and a login's taught form, which the
/// browser writes (`deadbolt_core::site::recipe`). The form neither shows nor sends them,
/// so an edit leaves an item's values for them as they are, and saving an
/// item deleted meanwhile as new carries them over (`Form::changes`).
pub const LINKS: &[(&str, &str)] = &[
    ("login", "sign-in-with"),
    ("login", "sign-in-account"),
    ("login", "autofill-recipe"),
    ("card", "billing"),
];

/// Fields a kind's form puts first, ahead of the schema's order: a login
/// asks for its username before its password, a card for its holder.
const FIRST: &[(&str, &[&str])] = &[("login", &["username"]), ("card", &["cardholder"])];

fn linked(kind: &str, field: &str) -> bool {
    LINKS.iter().any(|&(k, f)| k == kind && f == field)
}

/// A built-in item type's fields as the form lays them out. The daemon's
/// schema (`deadbolt_core::item`) says each one's type, whether it's
/// required and whether it spans lines; the form only reorders (`FIRST`)
/// and leaves out links (`LINKS`). A passkey has none: it isn't edited here.
fn schema(kind: &str) -> impl Iterator<Item = &'static SchemaField> + '_ {
    let all = deadbolt_core::item::schema(kind)
        .filter(|_| editable(kind))
        .map_or(&[][..], |s| s.fields);
    let first = FIRST
        .iter()
        .find(|(k, _)| *k == kind)
        .map_or(&[][..], |(_, f)| *f);
    let lead = first
        .iter()
        .filter_map(move |name| all.iter().find(|f| f.name == *name));
    let rest = all
        .iter()
        .filter(move |f| !first.contains(&f.name) && !linked(kind, f.name));
    lead.chain(rest)
}

pub struct Form {
    /// The item being changed; `None` for a new one.
    pub id: Option<String>,
    pub kind: String,
    pub name: TextEdit,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub tag_input: TextEdit,
    pub tag_active: Option<usize>,
    pub fields: Vec<Input>,
    /// The item as it was when the form opened, to save only what changed
    /// and to tell when another device changes it meanwhile.
    pub(super) base: Option<Snapshot>,
    pub conflict: Option<Conflict>,
    /// A save is on its way, or saved and waiting for the item's values.
    pub saving: bool,
    /// Saved: the form stays until this item's values land, then swaps to them.
    pub(super) landing: Option<String>,
    pub problem: Option<Problem>,
    /// Asked to leave while it holds changes.
    pub nudge: bool,
    /// The generator's request in flight.
    pub(super) generating: Option<u64>,
    /// Passwords generated so far, so each one swaps in (`view`).
    pub generated: u64,
    /// Opened from a password-health `Fix` action.
    pub fixing: bool,
    /// Copy the first generated Fix candidate to the concealed clipboard.
    pub(super) copy_generated_once: bool,
}

pub struct Input {
    pub name: String,
    /// The field type: `secret` and `otp` fields are always masked.
    pub kind: String,
    pub required: bool,
    /// Values span lines: a text area, masked for a secret.
    pub lines: bool,
    pub edit: TextEdit,
    /// The item has a value the daemon keeps back (a one-time password's
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
    /// The name and tags go with the fields.
    fn drop(&mut self) {
        self.name.set_secure(true);
        self.name.clear();
        self.tag_input.set_secure(true);
        self.tag_input.clear();
        for tag in &mut self.tags {
            tag.zeroize();
        }
    }
}

impl Input {
    fn from_item(
        name: &str,
        kind: &str,
        required: bool,
        lines: bool,
        saved: Option<&str>,
    ) -> Input {
        let secret = is_secret(kind);
        let kept = lines && secret && saved.is_some_and(|v| !v.is_empty());
        let value = match saved {
            Some(v) if !kept => v.to_owned(),
            _ => String::new(),
        };
        let mut edit = TextEdit::new(value);
        // A file's value (its name, or a chosen file's name and contents)
        // is never drawn as text, but held as securely as a secret.
        if secret || kind == "file" {
            edit.set_secure(true);
        }
        Input {
            name: name.into(),
            kind: kind.into(),
            required,
            lines,
            edit,
            held: saved.is_some_and(str::is_empty),
            kept,
        }
    }

    pub fn secret(&self) -> bool {
        is_secret(&self.kind)
    }

    /// A file: chosen with Choose File…, never typed (`App::choose_field_file`).
    pub fn file(&self) -> bool {
        self.kind == "file"
    }

    /// One line that may run long (an SSH public key or fingerprint, a
    /// wallet's address): a text area that wraps, where ⏎ saves as in any
    /// one-line field.
    pub fn wraps(&self) -> bool {
        !self.lines
            && !self.secret()
            && matches!(self.name.as_str(), "public-key" | "fingerprint" | "address")
    }

    /// Standing for the item's value, with nothing typed in its place.
    pub fn keeps(&self) -> bool {
        self.kept && self.value().is_none()
    }

    /// Lets the item's value stand: an empty, hidden editor, never holding
    /// the value itself, so nothing typed into it can be taken as an edit of
    /// a value it can't show.
    pub(super) fn keep(&mut self) {
        self.edit.set_revealed(false);
        self.edit.clear();
        self.kept = true;
    }

    /// Drops the line breaks a hard-wrapped paste left in a wrapping one-line
    /// value (`wraps`), where they'd hide among its soft wraps.
    pub(super) fn unwrap_lines(&mut self) {
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
    pub(super) fn wipe(&mut self) {
        self.edit.set_secure(true);
        self.edit.set_revealed(false);
        self.edit.clear();
    }

    /// The value to save, if any: text is trimmed; secrets and text that
    /// spans lines are kept as typed (a private key's final line break too),
    /// unless they're only whitespace.
    pub(super) fn value(&self) -> Option<&str> {
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

/// An item's values (`FieldInfo` is `ZeroizeOnDrop`).
pub(super) struct Snapshot(pub(super) ItemInfo);

impl Snapshot {
    pub(super) fn value(&self, field: &str) -> Option<&str> {
        self.0
            .fields
            .iter()
            .find(|f| f.name == field)
            .map(|f| f.value.as_str())
    }

    pub(super) fn same(&self, item: &ItemInfo) -> bool {
        self.0.label == item.label
            && self.0.favorite == item.favorite
            && self.0.tags == item.tags
            && self.0.fields.len() == item.fields.len()
            && self
                .0
                .fields
                .iter()
                .zip(&item.fields)
                .all(|(a, b)| a.name == b.name && a.value == b.value)
    }
}

/// What a save sends (`FieldInput` is `ZeroizeOnDrop`).
#[derive(Default)]
pub(super) struct Changes {
    pub(super) name: Option<String>,
    pub(super) set: Vec<FieldInput>,
    pub(super) unset: Vec<String>,
    pub(super) favorite: Option<bool>,
    pub(super) add_tags: Vec<String>,
    pub(super) remove_tags: Vec<String>,
}

impl Changes {
    pub(super) fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.set.is_empty()
            && self.unset.is_empty()
            && self.favorite.is_none()
            && self.add_tags.is_empty()
            && self.remove_tags.is_empty()
    }
}

impl Form {
    pub(super) fn new(kind: &str, name: &str, item: Option<&ItemInfo>) -> Form {
        let mut fields: Vec<Input> = schema(kind)
            .map(|spec| {
                let saved = item
                    .and_then(|i| i.fields.iter().find(|f| f.name == spec.name))
                    .map(|f| f.value.as_str());
                Input::from_item(
                    spec.name,
                    spec.kind.as_str(),
                    spec.required,
                    spec.multiline,
                    saved,
                )
            })
            .collect();
        // Fields the schema doesn't know (an import's extras, or a type this
        // build doesn't know) follow, as they are; links stay out of sight.
        for FieldInfo {
            name: field,
            kind: ty,
            value,
        } in item.map_or(&[][..], |i| &i.fields[..])
        {
            if !linked(kind, field) && !fields.iter().any(|f| &f.name == field) {
                let lines = ty == "note" || (ty != "file" && value.contains('\n'));
                fields.push(Input::from_item(field, ty, false, lines, Some(value)));
            }
        }
        let mut name = TextEdit::new(name);
        name.focused = true;
        Form {
            id: item.map(|i| i.id.clone()),
            kind: kind.into(),
            name,
            favorite: item.is_some_and(|i| i.favorite),
            tags: item.map(|i| i.tags.clone()).unwrap_or_default(),
            tag_input: TextEdit::new(""),
            tag_active: None,
            fields,
            base: item.map(|i| Snapshot(i.clone())),
            conflict: None,
            saving: false,
            landing: None,
            problem: None,
            nudge: false,
            generating: None,
            generated: 0,
            fixing: false,
            copy_generated_once: false,
        }
    }

    pub fn is_new(&self) -> bool {
        self.id.is_none()
    }

    /// The field the generator fills: a login's password, or the audited
    /// password/passphrase field when fixing a security finding.
    pub fn generates(&self) -> Option<usize> {
        if self.kind == "login" {
            self.fields.iter().position(|f| f.name == "password")
        } else if self.fixing {
            self.fixable_password_field()
        } else {
            None
        }
    }

    pub(crate) fn generating_seq(&self) -> Option<u64> {
        self.generating
    }

    pub(crate) fn set_generating(&mut self, seq: Option<u64>) {
        self.generating = seq;
    }

    /// What saving would send. A new item (or one deleted meanwhile, saved
    /// again as new) sends every field with a value; an edit, only the
    /// fields that changed, and empties the ones that were cleared.
    pub(super) fn changes(&self) -> Result<Changes, Problem> {
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
                    message: format!("{} can’t be empty.", title_case(&input.name)),
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
        // An edit leaves the links alone; a save as new carries them over.
        if self.saves_over().is_none()
            && let Some(base) = &self.base
        {
            for f in base.0.fields.iter().filter(|f| linked(&self.kind, &f.name)) {
                changes.set.push(FieldInput {
                    name: f.name.clone(),
                    kind: Some(f.kind.clone()),
                    value: f.value.clone(),
                });
            }
        }
        let name = self.name.text.trim();
        match self.saves_over() {
            Some(base) if name != base.0.label => changes.name = Some(name.to_owned()),
            None if !name.is_empty() => changes.name = Some(name.to_owned()),
            _ => {}
        }
        let mut effective_tags = self.tags.clone();
        if !self
            .tag_input
            .text
            .trim()
            .trim_start_matches('#')
            .is_empty()
        {
            super::tags::push_clean_tag(&mut effective_tags, &self.tag_input.text)?;
        }
        match self.saves_over() {
            Some(base) => {
                if self.favorite != base.0.favorite {
                    changes.favorite = Some(self.favorite);
                }
                for tag in &effective_tags {
                    if !base.0.tags.contains(tag) {
                        changes.add_tags.push(tag.clone());
                    }
                }
                for old in &base.0.tags {
                    if !effective_tags.iter().any(|t| fold_tag(t) == fold_tag(old)) {
                        changes.remove_tags.push(old.clone());
                    }
                }
            }
            None => {
                if self.favorite {
                    changes.favorite = Some(true);
                }
                changes.add_tags = effective_tags;
            }
        }
        Ok(changes)
    }

    /// The item a save changes, unless it's new or gone.
    pub(super) fn saves_over(&self) -> Option<&Snapshot> {
        self.base
            .as_ref()
            .filter(|_| self.conflict != Some(Conflict::Deleted))
    }

    /// Whether leaving would lose something typed.
    pub fn changed(&self) -> bool {
        if self.saves_over().is_some() {
            self.changes().map_or(true, |c| !c.is_empty())
        } else {
            !self.name.text.trim().is_empty()
                || self.favorite
                || !self.tags.is_empty()
                || !self.tag_input.text.trim().is_empty()
                || self.fields.iter().any(|f| f.keeps() || f.value().is_some())
        }
    }

    pub fn problem_for(&self, field: &str) -> Option<&str> {
        self.problem
            .as_ref()
            .filter(|p| p.field.as_deref() == Some(field))
            .map(|p| p.message.as_str())
    }
}

/// The daemon's refusal, on the field it names where it names one.
pub(super) fn problem(message: &str) -> Problem {
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
                "empty" => format!("{label} can’t be empty."),
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
            message: format!("{} can’t be empty.", title_case(field)),
        };
    }
    if message.contains("invalid item name") {
        return Problem {
            field: Some("name".into()),
            message: "A name is up to 128 characters, on one line.".into(),
        };
    }
    if message.contains("invalid tag") || message.contains("too many tags") {
        return Problem {
            field: Some("tags".into()),
            message: sentence(message),
        };
    }
    Problem {
        field: None,
        message: sentence(message),
    }
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
            favorite: false,
            tags: Vec::new(),
            deleted_at: None,
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
            ("username", "text", "sam"),
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

        set(&mut form, "username", "  alex ");
        set(&mut form, "notes", " \n");
        set(&mut form, "url", "github.com");
        let c = form.changes().unwrap();
        let sent: Vec<(&str, &str)> = c
            .set
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(sent, [("username", "alex"), ("url", "github.com")]);
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
    fn clearing_a_required_field_marks_an_existing_item_changed() {
        let card = ItemInfo {
            kind: "card".into(),
            ..item(&[("number", "secret", "4242424242424242")])
        };
        let mut form = Form::new("card", &card.label, Some(&card));
        form.name.clear();
        set(&mut form, "number", "");
        assert!(form.changes().is_err());
        assert!(form.changed());
    }

    #[test]
    fn a_wiped_field_is_masked_and_empty() {
        for (name, kind) in [("username", "text"), ("password", "secret")] {
            let mut input = Input::from_item(name, kind, false, false, Some("sam-hunter22"));
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

    /// Every field of every built-in type is in its form or one of `LINKS`
    /// (a passkey, not edited here, has none), so the app's form and the
    /// daemon's schema can't drift apart.
    #[test]
    fn every_schema_field_is_in_its_form_or_left_out_on_purpose() {
        for spec in deadbolt_core::item::schemas() {
            let form = Form::new(spec.kind, "", None);
            if !editable(spec.kind) {
                assert!(form.fields.is_empty(), "{}", spec.kind);
                continue;
            }
            for field in spec.fields {
                let input = form.fields.iter().find(|f| f.name == field.name);
                match input {
                    Some(input) => {
                        assert!(!linked(spec.kind, field.name), "{}", field.name);
                        assert_eq!(input.kind, field.kind.as_str(), "{}", field.name);
                        assert_eq!(input.required, field.required, "{}", field.name);
                        assert_eq!(input.lines, field.multiline, "{}", field.name);
                        assert_eq!(input.secret(), field.kind.is_secret(), "{}", field.name);
                    }
                    None => assert!(
                        linked(spec.kind, field.name),
                        "{}.{} is missing from the form",
                        spec.kind,
                        field.name
                    ),
                }
            }
            assert_eq!(
                form.fields.len() + LINKS.iter().filter(|(k, _)| *k == spec.kind).count(),
                spec.fields.len(),
                "{} has fields the schema doesn't",
                spec.kind
            );
        }
        for &(kind, field) in LINKS {
            let schema = deadbolt_core::item::schema(kind).unwrap();
            assert!(schema.field(field).is_some(), "{kind}.{field} is gone");
        }
        let names = |kind| -> Vec<String> {
            Form::new(kind, "", None)
                .fields
                .iter()
                .map(|f| f.name.clone())
                .collect()
        };
        assert_eq!(names("card")[..2], ["cardholder", "number"]);
    }

    /// The links a form leaves out stay on an edit and travel with a save
    /// as new.
    const RECIPE: &str = r#"{"v":1,"origin":"https://bank.example","pathPattern":"/","clusterFingerprint":"aa","slots":[{"role":"username","nthInput":0}]}"#;

    #[test]
    fn links_are_kept_but_not_shown() {
        let login = item(&[
            ("password", "secret", "pw-1"),
            ("sign-in-with", "text", "google"),
            ("sign-in-account", "text", "0a1b2c3d"),
            ("autofill-recipe", "text", RECIPE),
        ]);
        let hidden = |name: &str| name.starts_with("sign-in") || name == "autofill-recipe";
        let mut form = Form::new("login", &login.label, Some(&login));
        assert!(form.fields.iter().all(|f| !hidden(&f.name)));
        set(&mut form, "password", "pw-2");
        let c = form.changes().unwrap();
        assert!(c.unset.is_empty());
        assert!(c.set.iter().all(|f| !hidden(&f.name)));

        form.conflict = Some(Conflict::Deleted);
        let c = form.changes().unwrap();
        let sent: Vec<&str> = c.set.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            sent,
            [
                "password",
                "sign-in-with",
                "sign-in-account",
                "autofill-recipe"
            ]
        );
    }

    #[test]
    fn the_daemons_refusals_land_on_their_fields() {
        let p = problem("invalid value for number: must be 12-19 digits");
        assert_eq!(p.field.as_deref(), Some("number"));
        assert_eq!(p.message, "Number must be 12 to 19 digits.");
        let p = problem("invalid value for expiry: not a month (YYYY-MM)");
        assert_eq!(p.message, "Expiry must be a month, like 08/29.");
        let p = problem("missing required field password");
        assert_eq!(
            (p.field.as_deref(), p.message.as_str()),
            (Some("password"), "Password can’t be empty.")
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
