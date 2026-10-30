//! Adding, changing and deleting items, headless: the vault scene with a
//! scripted agent, so each test sees the jobs the app sends and answers them
//! as the agent would. `agent.rs` runs the same against a real agent;
//! `delete` covers conflicts, deletion, menus and 1Password sync, `restore`
//! covers Recently Deleted, and `secrets` covers secret fields, concealed
//! copies and kept multi-line keys.

mod delete;
mod restore;
mod secrets;

use std::sync::mpsc::{Receiver, Sender};

use deadbolt_app::agent::{Agent, Done, Failure, Job, Values};
use deadbolt_app::edit::{Conflict, Input};
use deadbolt_app::model::App;
use deadbolt_client::protocol::{Change, FieldInfo, ItemInfo};
use rune::{Env, Key, KeyEvent, Mods, Runtime};
use zeroize::Zeroizing;

pub(super) const FRAME: f64 = 1.0 / 60.0;

pub(super) struct Rig {
    pub(super) rt: Runtime<App>,
    pub(super) jobs: Receiver<Job>,
    pub(super) replies: Sender<Done>,
}

pub(super) fn rig(scene: &str) -> Rig {
    let app = rune::tooling::initial_state(&deadbolt_app::spec(), Some(scene));
    let mut rt = Runtime::new(
        app,
        deadbolt_app::view::app,
        (820.0, 540.0),
        Env {
            system_dark: true,
            scale: 1.0,
        },
    );
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
    let (agent, jobs, replies) = Agent::scripted();
    rt.state.agent = agent;
    let mut rig = Rig { rt, jobs, replies };
    rig.settle(1.0);
    rig
}

pub(super) type Fields = Vec<(String, String)>;

pub(super) fn pairs(fields: &[(String, String)]) -> Vec<(&str, &str)> {
    fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

impl Rig {
    pub(super) fn settle(&mut self, seconds: f64) {
        for _ in 0..(seconds / FRAME).round() as usize {
            self.rt.frame(FRAME);
        }
    }

    pub(super) fn press(&mut self, key: Key, mods: Mods) {
        self.rt.key(KeyEvent { key, mods });
        self.settle(0.05);
    }

    /// ⌘N, then ⏎ in its type list: a new login, its name focused.
    pub(super) fn new_item(&mut self) {
        self.command('n');
        self.tap(Key::Enter);
        self.settle(0.05);
    }

    pub(super) fn command(&mut self, c: char) {
        self.press(Key::Command(c), cmd());
    }

    pub(super) fn tap(&mut self, key: Key) {
        self.press(key, Mods::default());
    }

    pub(super) fn type_text(&mut self, text: &str) {
        for c in text.chars() {
            self.rt.key(KeyEvent {
                key: Key::Text(c.into()),
                mods: Mods::default(),
            });
        }
        self.settle(0.05);
    }

    pub(super) fn reply(&mut self, done: Done) {
        self.replies.send(done).unwrap();
        self.settle(0.1);
    }

    pub(super) fn sent(&self) -> Vec<Job> {
        self.jobs.try_iter().collect()
    }

    pub(super) fn shows(&self, s: &str) -> bool {
        self.rt
            .elements()
            .iter()
            .any(|e| e.text.as_deref() == Some(s))
    }

    /// Types into the open form's field `name`, as the person would.
    pub(super) fn fill(&mut self, name: &str, value: &str) {
        self.rt.update(|s, _| {
            let form = s.edit.form.as_mut().unwrap();
            let input = form.fields.iter_mut().find(|f| f.name == name).unwrap();
            input.edit.replace_text(value);
            s.form_changed();
        });
        self.settle(0.05);
    }

    /// Focuses the open form's field `name`, as a click would.
    pub(super) fn focus(&mut self, name: &str) {
        let name = name.to_owned();
        self.rt.update(move |s, _| {
            s.search.focused = false;
            let form = s.edit.form.as_mut().unwrap();
            form.name.focused = false;
            for input in &mut form.fields {
                input.edit.focused = input.name == name;
            }
        });
        self.settle(0.05);
    }

    pub(super) fn input(&self, name: &str) -> &Input {
        let form = self.rt.state.edit.form.as_ref().unwrap();
        form.fields.iter().find(|f| f.name == name).unwrap()
    }

    pub(super) fn value(&self, name: &str) -> String {
        self.input(name).edit.text.to_string()
    }

    /// Presses at the middle of `path`, with no frame after.
    pub(super) fn click_at(&mut self, path: &str) {
        let (x, y) = self.rt.find(path).unwrap();
        self.rt.pointer_down(x, y);
        self.rt.pointer_up(x, y);
    }

    pub(super) fn click_row(&mut self, id: &str) {
        self.click_at(&format!("item-{id}"));
        self.settle(0.1);
    }

    /// (rect, opacity) of the innermost element keyed `key`.
    pub(super) fn at(&self, key: &str) -> Option<([f32; 4], f32)> {
        self.rt
            .elements()
            .into_iter()
            .rfind(|e| e.key.as_deref() == Some(key))
            .map(|e| (e.rect, e.opacity))
    }

    pub(super) fn height(&self, key: &str) -> f32 {
        self.at(key).unwrap().0[3]
    }

    /// Elements carrying `secret` as text, the masked field's or anything else's.
    pub(super) fn plaintext(&self, secret: &str) -> Vec<String> {
        self.rt
            .elements()
            .iter()
            .filter(|e| e.text.as_deref().is_some_and(|t| t.contains(secret)))
            .map(|e| e.path.clone())
            .collect()
    }

    pub(super) fn take_generate(&self) -> u64 {
        self.sent()
            .into_iter()
            .find_map(|j| match j {
                Job::Generate { seq, .. } => Some(seq),
                _ => None,
            })
            .expect("expected a generate")
    }

    pub(super) fn take_get(&self, target: Option<&str>) -> u64 {
        self.sent()
            .into_iter()
            .find_map(|j| match j {
                Job::Get { id, seq, .. } if target.is_none_or(|t| id == t) => Some(seq),
                _ => None,
            })
            .expect("the selected item is fetched")
    }

    pub(super) fn take_create(&self) -> (u64, String, Option<String>, Fields) {
        match self.sent().pop() {
            Some(Job::Create {
                kind,
                name,
                fields,
                seq,
                ..
            }) => (
                seq,
                kind,
                name,
                fields
                    .iter()
                    .map(|f| (f.name.clone(), f.value.clone()))
                    .collect(),
            ),
            _ => panic!("expected a create"),
        }
    }

    pub(super) fn take_save(&self) -> (u64, String, Option<String>, Fields, Vec<String>) {
        match self.sent().pop() {
            Some(Job::Save {
                id,
                name,
                fields,
                unset,
                seq,
                ..
            }) => (
                seq,
                id,
                name,
                fields
                    .iter()
                    .map(|f| (f.name.clone(), f.value.clone()))
                    .collect(),
                unset,
            ),
            _ => panic!("expected a save"),
        }
    }

    pub(super) fn take_remove(&self) -> (u64, String) {
        match self.sent().pop() {
            Some(Job::Remove { id, seq }) => (seq, id),
            _ => panic!("expected a remove"),
        }
    }

    pub(super) fn github(&self) -> ItemInfo {
        let item = self.rt.state.detail.clone().unwrap();
        assert_eq!(item.label, "github.com");
        item
    }

    /// Another device changes the vault: the app refetches the list, then the
    /// selected item, and gets these.
    pub(super) fn synced(&mut self, items: Vec<ItemInfo>, item: Option<ItemInfo>) {
        let vault = self.rt.state.status.clone().unwrap().vaults[0].id.clone();
        self.sent();
        self.reply(Done::Changed(Change::Items { vault }));
        let generation = self.rt.state.generation();
        self.reply(Done::Items {
            generation,
            result: Ok(items),
        });
        if let Some(item) = item {
            let seq = self.take_get(None);
            self.reply(Done::Item {
                seq,
                result: Ok(Values::new(item)),
            });
        }
    }

    pub(super) fn sync_password(&mut self, password: &str) {
        let mut theirs = self.rt.state.detail.clone().unwrap();
        for f in &mut theirs.fields {
            if f.name == "password" {
                f.value = password.into();
            }
        }
        let items = self.rt.state.items.clone();
        self.synced(items, Some(theirs));
    }
}

pub(super) fn cmd() -> Mods {
    Mods {
        cmd: true,
        ..Mods::default()
    }
}

pub(super) fn shift() -> Mods {
    Mods {
        shift: true,
        ..Mods::default()
    }
}

pub(super) fn alt() -> Mods {
    Mods {
        alt: true,
        ..Mods::default()
    }
}

pub(super) fn ctrl() -> Mods {
    Mods {
        ctrl: true,
        ..Mods::default()
    }
}

pub(super) fn info(id: &str, kind: &str, label: &str) -> ItemInfo {
    ItemInfo {
        id: id.into(),
        short: id[..4].into(),
        kind: kind.into(),
        label: label.into(),
        detail: None,
        fields: Vec::new(),
        source: None,
        favorite: false,
        tags: Vec::new(),
        deleted_at: None,
    }
}

pub(super) fn failure(message: &str) -> Failure {
    Failure {
        code: None,
        message: message.into(),
    }
}

/// Each of a new login's fields is named for what it holds, the generated
/// password's too, though a wrapper sits around it.
#[test]
fn form_fields_are_named_for_assistive_tech() {
    let mut r = rig("vault");
    r.new_item();
    let labels: Vec<String> =
        r.rt.elements()
            .iter()
            .filter(|e| e.role == "textbox")
            .filter_map(|e| e.label.clone())
            .collect();
    for name in ["Name", "Username", "Password", "URL", "Notes"] {
        assert!(labels.iter().any(|l| l == name), "{name} in {labels:?}");
    }
    assert!(!labels.iter().any(|l| l == "Required"), "{labels:?}");
}

#[test]
fn cmd_n_opens_a_new_login_with_a_generated_password() {
    let mut r = rig("vault");
    r.sent();
    r.command('n');
    let form = r.rt.state.edit.form.as_ref().expect("a form");
    assert!(form.is_new() && form.kind == "login");
    // The type list opens with it, its filter focused.
    assert!(r.rt.state.types_open() && r.rt.state.edit.types.filter.focused);
    let seq = match r.sent().as_slice() {
        [
            Job::Generate {
                length: 24,
                symbols: true,
                seq,
            },
        ] => *seq,
        _ => panic!("expected one generate"),
    };
    assert!(r.shows("Login") && r.shows("Card"));
    r.tap(Key::Escape);

    r.reply(Done::Generated {
        seq,
        result: Ok(Zeroizing::new("Vq7#mRz2!pKx9@wLt4&nBe8z".into())),
    });
    assert_eq!(r.value("password"), "Vq7#mRz2!pKx9@wLt4&nBe8z");
    let password = r.input("password");
    assert!(password.edit.is_secure() && password.edit.is_revealed());
    assert!(!r.shows("Vq7#mRz2!pKx9@wLt4&nBe8z"), "never as text");

    // A new length and no symbols ask again; the older answer is dropped.
    r.rt.update(|s, _| s.set_length(32));
    r.rt.update(|s, _| s.toggle_symbols());
    let asked: Vec<(usize, bool, u64)> = r
        .sent()
        .into_iter()
        .filter_map(|j| match j {
            Job::Generate {
                length,
                symbols,
                seq,
            } => Some((length, symbols, seq)),
            _ => None,
        })
        .collect();
    assert_eq!(asked.len(), 2);
    assert_eq!((asked[1].0, asked[1].1), (32, false));
    r.reply(Done::Generated {
        seq: asked[0].2,
        result: Ok(Zeroizing::new("stale".into())),
    });
    assert_eq!(r.value("password"), "Vq7#mRz2!pKx9@wLt4&nBe8z");
    r.reply(Done::Generated {
        seq: asked[1].2,
        result: Ok(Zeroizing::new("abcdefghijklmnopqrstuvwxyzABCDEF".into())),
    });
    assert_eq!(r.value("password"), "abcdefghijklmnopqrstuvwxyzABCDEF");

    // A card has nothing to generate.
    r.rt.update(|s, _| s.choose_type("card"));
    assert!(r.sent().is_empty());
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert_eq!(form.kind, "card");
    assert!(form.generates().is_none());
}

#[test]
fn switching_a_new_items_type_keeps_focus_and_ctrl_tab_working() {
    let mut r = rig("vault");
    r.new_item();
    r.focus("password");
    r.press(Key::Tab, ctrl());
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert_eq!(form.kind, "note");
    assert!(form.name.focused, "falls back to name when password goes");

    // ⌃⇥ keeps cycling even when no field is focused.
    r.rt.update(|s, _| s.edit.form.as_mut().unwrap().name.focused = false);
    r.press(Key::Tab, ctrl());
    assert_eq!(r.rt.state.edit.form.as_ref().unwrap().kind, "card");
}

#[test]
fn a_new_login_saves_and_is_selected() {
    let mut r = rig("vault");
    r.new_item();
    r.type_text("Linear");
    r.fill("username", "kit");
    r.fill("password", "pw-linear");
    r.sent();
    r.command('s');
    let (seq, kind, name, created) = r.take_create();
    assert_eq!((kind.as_str(), name.as_deref()), ("login", Some("Linear")));
    assert_eq!(
        pairs(&created),
        [("username", "kit"), ("password", "pw-linear")]
    );
    assert!(r.rt.state.edit.form.as_ref().unwrap().saving && r.shows("Saving…"));

    let id = "9e9e0000000000000000000000000000";
    r.reply(Done::Saved {
        seq,
        result: Ok(info(id, "login", "Linear 2")),
    });
    assert_eq!(r.rt.state.selected.as_deref(), Some(id));
    assert!(r.rt.state.items.iter().any(|i| i.id == id));
    let sent = r.sent();
    let get = sent
        .iter()
        .find_map(|j| match j {
            Job::Get { id: got, seq, .. } if got == id => Some(*seq),
            _ => None,
        })
        .expect("its values are fetched");
    assert!(sent.iter().any(|j| matches!(j, Job::List { .. })));
    assert!(r.rt.state.editing(), "the form stays until they land");

    let mut item = info(id, "login", "Linear 2");
    item.fields = vec![FieldInfo {
        name: "password".into(),
        kind: "secret".into(),
        value: "pw-linear".into(),
    }];
    r.reply(Done::Item {
        seq: get,
        result: Ok(Values::new(item)),
    });
    assert!(!r.rt.state.editing() && r.rt.state.search.focused);
    assert_eq!(
        r.rt.state.selected_item().map(|i| i.label.as_str()),
        Some("Linear 2")
    );
}

/// A new login, its password generated, saved: the create's tag.
fn save_new_login(r: &mut Rig, password: Option<&str>) -> u64 {
    r.sent();
    r.new_item();
    let generate = r.take_generate();
    if let Some(password) = password {
        r.reply(Done::Generated {
            seq: generate,
            result: Ok(Zeroizing::new(password.into())),
        });
    }
    r.type_text("Linear");
    r.command('s');
    r.take_create().0
}

/// The saved item lands: listed, selected and fetched. The fetch's tag.
fn saved(r: &mut Rig, seq: u64, id: &str) -> u64 {
    r.reply(Done::Saved {
        seq,
        result: Ok(info(id, "login", "Linear")),
    });
    r.take_get(Some(id))
}

/// While a save waits on the agent the form takes nothing: no generator,
/// type, typing, cancel or esc. The save's answer still lands.
#[test]
fn a_saving_form_holds_until_the_agent_answers() {
    let mut r = rig("vault");
    let seq = save_new_login(&mut r, Some("Vq7#mRz2!pKx9@wLt4&nBe8z"));
    assert!(r.rt.state.saving());
    let length = r.rt.state.edit.length;

    r.rt.update(|s, _| {
        s.generate();
        s.set_length(64);
        s.toggle_symbols();
        s.choose_type("card");
        s.name_mut().replace_text("Typed meanwhile");
        s.input_mut(0).replace_text("typed meanwhile");
        s.cancel_edit();
    });
    r.tap(Key::Escape);
    let form = r.rt.state.edit.form.as_ref().expect("the form stays");
    assert!(form.saving && form.kind == "login" && form.name.text.as_str() == "Linear");
    assert_eq!(r.value("username"), "");
    assert_eq!(r.value("password"), "Vq7#mRz2!pKx9@wLt4&nBe8z");
    assert_eq!(r.rt.state.edit.length, length);
    assert!(r.rt.state.edit.symbols);
    assert!(!r.sent().iter().any(|j| matches!(j, Job::Generate { .. })));
    assert!(r.rt.state.generating().is_none());

    let id = "9e9e0000000000000000000000000000";
    let get = saved(&mut r, seq, id);
    let mut item = info(id, "login", "Linear");
    item.fields = vec![FieldInfo {
        name: "password".into(),
        kind: "secret".into(),
        value: "Vq7#mRz2!pKx9@wLt4&nBe8z".into(),
    }];
    r.reply(Done::Item {
        seq: get,
        result: Ok(Values::new(item)),
    });
    assert!(!r.rt.state.editing(), "the save landed and the form closed");
}

/// A password still being generated when Save is pressed doesn't land in
/// the form after it.
#[test]
fn a_password_generated_after_save_is_dropped() {
    let mut r = rig("vault");
    r.sent();
    r.new_item();
    let pending = r.take_generate();
    r.fill("password", "typed-password");
    r.command('s');
    let (seq, ..) = r.take_create();
    r.reply(Done::Generated {
        seq: pending,
        result: Ok(Zeroizing::new("late-Generated-9".into())),
    });
    assert_eq!(r.value("password"), "typed-password");

    // A refusal gives the form back as it was sent.
    r.reply(Done::Saved {
        seq,
        result: Err(failure("the vault is read-only")),
    });
    assert!(!r.rt.state.edit.form.as_ref().unwrap().saving);
    assert_eq!(r.value("password"), "typed-password");
}

/// Saved, but its values fail to come: it's saved, so the form closes
/// rather than wait on them.
#[test]
fn a_saved_form_closes_when_its_values_fail_to_come() {
    let mut r = rig("vault");
    let seq = save_new_login(&mut r, Some("Vq7#mRz2!pKx9@wLt4&nBe8z"));
    let get = saved(&mut r, seq, "9e9e0000000000000000000000000000");
    assert!(r.rt.state.editing(), "waiting on its values");
    r.reply(Done::Item {
        seq: get,
        result: Err(failure("the agent couldn't read it")),
    });
    assert!(!r.rt.state.editing() && r.rt.state.search.focused);
}

/// While saving, the type switch and the generator's controls are disabled.
#[test]
fn a_saving_forms_controls_are_disabled() {
    let mut r = rig("vault");
    save_new_login(&mut r, Some("Vq7#mRz2!pKx9@wLt4&nBe8z"));
    let enabled = |r: &Rig, label: &str| {
        r.rt.elements()
            .iter()
            .filter(|e| e.label.as_deref() == Some(label))
            .any(|e| e.focusable)
    };
    for label in ["Card", "64", "Symbols", "Generate a new password"] {
        assert!(!enabled(&r, label), "{label} is disabled");
    }
}

#[test]
fn an_edit_sends_only_what_changed_in_one_set() {
    let mut r = rig("vault");
    let github = r.github();
    r.command('e');
    let form = r.rt.state.edit.form.as_ref().expect("a form");
    assert_eq!(form.id.as_deref(), Some(github.id.as_str()));
    assert_eq!(form.name.text.as_str(), "github.com");
    assert_eq!(r.value("username"), "dax");
    // Unchanged, ⌘S just closes it.
    r.sent();
    r.command('s');
    assert!(!r.rt.state.editing() && r.sent().is_empty());

    r.command('e');
    r.fill("username", "kit");
    r.fill("notes", "");
    r.command('s');
    let (_, id, name, fields, unset) = r.take_save();
    assert_eq!((id, name), (github.id, None));
    assert_eq!(pairs(&fields), [("username", "kit")]);
    assert_eq!(unset, ["notes"]);
}

#[test]
fn a_refusal_shows_on_its_field_and_keeps_the_form() {
    let mut r = rig("vault");
    r.new_item();
    r.rt.update(|s, _| s.choose_type("card"));
    r.fill("number", "4242");
    r.sent();
    r.tap(Key::Enter);
    let (seq, ..) = r.take_create();
    r.reply(Done::Saved {
        seq,
        result: Err(failure("invalid value for number: must be 12-19 digits")),
    });
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert!(!form.saving);
    assert_eq!(
        form.problem_for("number"),
        Some("Number must be 12 to 19 digits.")
    );
    assert!(r.shows("Number must be 12 to 19 digits."));
    assert_eq!(r.value("number"), "4242", "what was typed stays");

    // Typing again clears it; an empty required field is caught here.
    r.fill("number", "");
    assert!(r.rt.state.edit.form.as_ref().unwrap().problem.is_none());
    r.command('s');
    assert!(r.shows("Number can't be empty.") && r.sent().is_empty());
}

#[test]
fn esc_cancels_and_the_selection_waits_for_a_changed_form() {
    let mut r = rig("vault");
    let selected = r.rt.state.selected.clone();
    r.command('e');
    r.tap(Key::Escape);
    assert!(!r.rt.state.editing() && r.rt.state.search.focused);

    let other =
        r.rt.state
            .items
            .iter()
            .find(|i| Some(&i.id) != selected.as_ref())
            .unwrap()
            .id
            .clone();
    let github = r.github();

    // A click on the item being edited leaves the form as it is.
    r.command('e');
    r.click_row(&github.id);
    assert!(r.rt.state.editing() && r.rt.state.edit.form.as_ref().unwrap().name.focused);
    assert!(!r.rt.state.search.focused);

    // An unchanged form gives way to another item, leaving as it goes.
    r.click_at(&format!("item-{other}"));
    r.rt.frame(FRAME);
    let (_, opacity) = r.at("form").expect("the form leaves, not vanishes");
    assert!(opacity > 0.0, "still fading: {opacity}");
    r.settle(0.5);
    assert!(r.at("form").is_none() && !r.rt.state.editing());
    assert_eq!(r.rt.state.selected.as_ref(), Some(&other));
    r.sent();
    r.click_row(selected.as_ref().unwrap());
    let seq = r.take_get(None);
    r.reply(Done::Item {
        seq,
        result: Ok(Values::new(github)),
    });

    // A changed form holds the selection and says so.
    r.command('e');
    r.fill("username", "kit");
    r.tap(Key::Down);
    assert_eq!(r.rt.state.selected, selected);
    r.click_row(&other);
    assert_eq!(r.rt.state.selected, selected);
    assert!(r.rt.state.edit.form.as_ref().unwrap().nudge);
    assert!(r.shows("Save or cancel your changes first."));

    // ⌘L locks, and the form goes with what it held.
    r.command('l');
    r.reply(Done::Locked(Ok(())));
    assert!(r.rt.state.edit.form.is_none());
}

#[test]
fn an_edit_from_another_device_is_told_and_what_was_typed_stays() {
    let mut r = rig("vault");
    r.command('e');
    r.fill("username", "kit");
    r.sync_password("their-password");
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert_eq!(form.conflict, Some(Conflict::Changed));
    assert_eq!(r.value("username"), "kit");
    assert!(r.shows("Changed on another device"));

    // Saving sends only ours, so theirs stays.
    r.sent();
    r.command('s');
    let (_, _, _, fields, unset) = r.take_save();
    assert_eq!(pairs(&fields), [("username", "kit")]);
    assert!(unset.is_empty());
}

/// "Show theirs" drops what was typed for the other device's version, and
/// the form, not the search, takes the keys.
#[test]
fn show_theirs_reloads_the_form_from_the_other_device() {
    let mut r = rig("vault");
    r.command('e');
    r.fill("username", "kit");
    r.sync_password("their-password");
    assert!(r.shows("Show theirs"));
    // The fields make room for the notice first.
    r.settle(0.4);
    let [x, y, w, h] =
        r.rt.elements()
            .iter()
            .find(|e| e.text.as_deref() == Some("Show theirs"))
            .unwrap()
            .rect;
    r.rt.pointer_down(x + w / 2.0, y + h / 2.0);
    r.rt.pointer_up(x + w / 2.0, y + h / 2.0);
    r.settle(0.3);

    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert!(form.conflict.is_none() && !form.changed());
    assert_eq!(r.value("username"), "dax");
    assert_eq!(r.value("password"), "their-password");
    assert!(!r.shows("Changed on another device"));

    // Pressed without moving focus (as VoiceOver does) while the search
    // has it, the form's name takes the keys, never both at once.
    r.fill("username", "kit");
    r.sync_password("newer-password");
    r.click_at("search");
    r.settle(0.1);
    assert!(r.rt.state.search.focused);
    r.rt.update(|s, _| s.reload_edit());
    assert_eq!(r.value("password"), "newer-password");
    assert!(r.rt.state.edit.form.as_ref().unwrap().name.focused);
    assert!(!r.rt.state.search.focused, "the form has the keys");
}

/// ⌘N over an unchanged edit opens a new item in its place.
#[test]
fn cmd_n_replaces_an_unchanged_edit() {
    let mut r = rig("vault");
    r.command('e');
    assert!(!r.rt.state.edit.form.as_ref().unwrap().is_new());
    r.command('n');
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert!(form.is_new() && !form.nudge);

    // One with changes stays, and says so. (The first esc closes the
    // type list, the second the form.)
    r.tap(Key::Escape);
    r.tap(Key::Escape);
    r.command('e');
    r.fill("username", "kit");
    r.command('n');
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert!(!form.is_new() && form.nudge);
}

/// While a form is open, Enter with any other modifier does nothing: it
/// neither copies from the list nor saves, from a field or from nowhere.
#[test]
fn enter_chords_in_a_form_never_reach_the_list() {
    let mut r = rig("vault");
    r.command('e');
    r.fill("username", "kit");
    let chords = [
        shift(),
        alt(),
        ctrl(),
        Mods {
            shift: true,
            cmd: true,
            ..Mods::default()
        },
    ];
    for focused in [true, false] {
        r.rt.update(move |s, _| {
            if let Some(form) = &mut s.edit.form {
                form.name.focused = focused;
            }
        });
        r.settle(0.05);
        r.sent();
        for mods in chords {
            r.press(Key::Enter, mods);
        }
        assert!(r.rt.state.copy.is_none() && r.rt.state.editing() && r.sent().is_empty());
        assert_eq!(r.value("username"), "kit");
    }

    // Notes keep ⇧⏎ for themselves.
    r.focus("notes");
    r.press(Key::Enter, chords[0]);
    assert!(r.rt.state.copy.is_none() && r.rt.state.editing() && r.sent().is_empty());
}

/// Add offers an identity, laid out as the core's schema has it: its name
/// and address in the parts forms ask for.
#[test]
fn add_offers_an_identity_in_parts() {
    let mut r = rig("vault");
    r.command('n');
    assert!(r.shows("Identity"), "the picker offers it");
    r.rt.update(|s, _| s.choose_type("identity"));
    r.settle(0.3);
    let form = r.rt.state.edit.form.as_ref().unwrap();
    let names: Vec<&str> = form.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "honorific",
            "given-name",
            "additional-name",
            "family-name",
            "nickname",
            "organization",
            "job-title",
            "email",
            "phone",
            "address-line1",
            "address-line2",
            "address-line3",
            "city",
            "region",
            "postal-code",
            "country",
            "birthday",
            "national-id",
            "passport",
            "license",
            "notes"
        ]
    );
    assert!(
        (r.height("field-address-line1") - r.height("field-phone")).abs() < 1.0,
        "an address line is one line"
    );
    r.rt.update(|s, _| s.edit.form.as_mut().unwrap().name.replace_text("Home"));
    r.fill("given-name", "Dax");
    r.fill("address-line1", "1 Main St");
    r.fill("city", "Springfield");
    r.sent();
    r.command('s');
    let (_, kind, name, fields) = r.take_create();
    assert_eq!((kind.as_str(), name.as_deref()), ("identity", Some("Home")));
    assert_eq!(
        pairs(&fields),
        [
            ("given-name", "Dax"),
            ("address-line1", "1 Main St"),
            ("city", "Springfield")
        ]
    );
}

/// ⏎ in a text area that isn't secret (a login's notes, an identity's)
/// breaks the line, as in a secure note's body: Rune would submit it. ⌘⏎
/// saves.
#[test]
fn enter_breaks_the_line_in_notes() {
    let mut r = rig("vault");
    r.new_item();
    r.focus("notes");
    r.sent();
    r.type_text("first");
    r.tap(Key::Enter);
    r.type_text("second");
    assert_eq!(r.value("notes"), "first\nsecond");
    assert!(r.rt.state.editing());
    r.press(Key::Enter, cmd());
    let (_, _, _, fields) = r.take_create();
    assert_eq!(pairs(&fields).last(), Some(&("notes", "first\nsecond")));

    let mut r = rig("vault");
    r.new_item();
    r.rt.update(|s, _| s.choose_type("identity"));
    r.focus("notes");
    r.type_text("1 Main St");
    r.tap(Key::Enter);
    r.type_text("Springfield");
    assert_eq!(r.value("notes"), "1 Main St\nSpringfield");
    assert!(r.rt.state.editing());
}

/// A login needs no password, as the core has it (an import brings some
/// without one), so a form left without one still saves.
#[test]
fn a_login_saves_without_a_password() {
    let mut r = rig("vault");
    r.new_item();
    r.fill("username", "kit");
    r.fill("password", "");
    r.sent();
    r.command('s');
    assert_eq!(pairs(&r.take_create().3), [("username", "kit")]);
}

/// The picker offers every type, each with its own fields in the core's
/// schema order.
#[test]
fn add_offers_every_type() {
    let mut r = rig("vault");
    r.command('n');
    r.settle(0.3);
    // ⌘N opens with the type list showing, each type by its full name.
    assert!(r.rt.state.types_open());
    for label in [
        "Login",
        "Secure note",
        "API credential",
        "Database",
        "Wi-Fi network",
    ] {
        assert!(r.shows(label), "the list offers {label}");
    }
    for (kind, first, count) in [
        ("api", "credential", 8),
        ("database", "type", 8),
        ("server", "url", 5),
        ("wifi", "ssid", 4),
        ("license", "product", 9),
        ("bank", "bank", 8),
        ("document", "file", 2),
        ("passport", "full-name", 12),
        ("driver-license", "full-name", 12),
        ("id-document", "full-name", 7),
        ("membership", "organization", 9),
        ("crypto", "recovery-phrase", 5),
    ] {
        r.rt.update(|s, _| s.choose_type(kind));
        r.settle(0.05);
        let form = r.rt.state.edit.form.as_ref().unwrap();
        assert_eq!(form.kind, kind);
        assert_eq!(form.fields[0].name, first, "{kind}");
        assert_eq!(form.fields.len(), count, "{kind}");
    }
    // An API credential needs its credential, as the agent says.
    r.rt.update(|s, _| s.choose_type("api"));
    r.fill("username", "deploy-bot");
    r.command('s');
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert_eq!(
        form.problem_for("credential"),
        Some("Credential can't be empty.")
    );
    r.fill("credential", "sk_live_1");
    r.sent();
    r.command('s');
    let (_, kind, _, fields) = r.take_create();
    assert_eq!(kind, "api");
    assert_eq!(
        pairs(&fields),
        [("credential", "sk_live_1"), ("username", "deploy-bot")]
    );
}

/// A document's file is chosen, not typed: the app reads it and sends its
/// name and contents; one over 10 MiB says so on the field.
#[test]
fn a_document_takes_a_chosen_file() {
    let dir = tempfile::tempdir().unwrap();
    let scan = dir.path().join("scan.pdf");
    std::fs::write(&scan, b"%PDF").unwrap();
    let big = dir.path().join("big.bin");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(10 * 1024 * 1024 + 1)
        .unwrap();

    let mut r = rig("vault");
    r.new_item();
    r.rt.update(|s, _| s.choose_type("document"));
    r.settle(0.3);
    assert!(r.shows("No file chosen") && r.shows("Choose File…"));
    r.click_at("choose");
    r.settle(0.05);
    let (kind, _) = r.rt.file_dialog().expect("an Open dialog");
    assert_eq!(kind, rune::FileDialogKind::Open);
    r.rt.resolve_file_dialog(Some(big)).unwrap();
    r.settle(0.05);
    let form = r.rt.state.edit.form.as_ref().unwrap();
    let problem = form.problem_for("file").unwrap();
    assert!(problem.contains("larger than 10 MiB"), "{problem}");

    r.click_at("choose");
    r.settle(0.05);
    r.rt.resolve_file_dialog(Some(scan)).unwrap();
    r.settle(0.05);
    assert!(r.shows("scan.pdf") && r.shows("Choose Another…"));
    assert!(r.rt.state.edit.form.as_ref().unwrap().problem.is_none());
    r.rt.update(|s, _| s.edit.form.as_mut().unwrap().name.replace_text("Scan"));
    r.sent();
    r.command('s');
    let (_, kind, name, fields) = r.take_create();
    assert_eq!((kind.as_str(), name.as_deref()), ("document", Some("Scan")));
    assert_eq!(pairs(&fields), [("file", "scan.pdf\nJVBERg==")]);
}

/// ⌘N opens the type list with its filter focused: typing narrows it,
/// ↑↓ move, ⏎ picks and the name takes focus; esc closes it, and ⌘T,
/// or a press on the type row, opens it again.
#[test]
fn typing_picks_a_new_items_type() {
    let mut r = rig("vault");
    r.command('n');
    r.settle(0.3);
    assert!(r.rt.state.types_open());
    assert!(r.rt.state.edit.types.filter.focused);
    r.type_text("api");
    assert!(r.shows("API credential") && !r.shows("Secure note"));
    r.tap(Key::Enter);
    r.settle(0.1);
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert_eq!(form.kind, "api");
    assert!(form.name.focused && !r.rt.state.types_open());
    assert!(r.shows("API credential"), "the type row names it");

    // Typed fields stay through a change of type.
    r.rt.update(|s, _| s.edit.form.as_mut().unwrap().name.replace_text("Deploy"));
    r.fill("username", "deploy-bot");
    r.command('t');
    assert!(r.rt.state.types_open());
    r.type_text("key");
    assert!(r.shows("SSH key") && r.shows("API credential") && !r.shows("Login"));
    // SSH key first, then API credential: ↓ moves to it, ↑ back.
    r.tap(Key::Down);
    assert_eq!(r.rt.state.edit.types.active, 1);
    r.tap(Key::Up);
    r.tap(Key::Enter);
    r.settle(0.1);
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert_eq!(form.kind, "ssh");
    assert_eq!(form.name.text, "Deploy");

    r.command('t');
    r.type_text("db");
    r.tap(Key::Escape);
    r.settle(0.1);
    assert!(
        !r.rt.state.types_open() && r.rt.state.editing(),
        "esc closes only the list"
    );
    assert_eq!(r.rt.state.edit.form.as_ref().unwrap().kind, "ssh");

    r.click_at("type");
    r.settle(0.5);
    assert!(r.rt.state.types_open());
    r.click_at("type-wifi");
    r.settle(0.1);
    assert_eq!(r.rt.state.edit.form.as_ref().unwrap().kind, "wifi");
    assert!(!r.rt.state.types_open());
}
