//! Adding, changing and deleting items, headless: the vault scene with a
//! scripted agent, so each test sees the jobs the app sends and answers them
//! as the agent would. `agent.rs` runs the same against a real agent.

#![cfg(test)]

use std::sync::mpsc::{Receiver, Sender};

use deadbolt_app::agent::{Agent, Done, Failure, Job, Values};
use deadbolt_app::edit::Conflict;
use deadbolt_app::model::{App, Screen};
use deadbolt_client::protocol::{Change, FieldInfo, ItemInfo};
use rune::{Env, Key, KeyEvent, Mods, Runtime};
use zeroize::Zeroizing;

const FRAME: f64 = 1.0 / 60.0;

struct Rig {
    rt: Runtime<App>,
    jobs: Receiver<Job>,
    replies: Sender<Done>,
}

fn rig(scene: &str) -> Rig {
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

impl Rig {
    fn settle(&mut self, seconds: f64) {
        for _ in 0..(seconds / FRAME).round() as usize {
            self.rt.frame(FRAME);
        }
    }

    fn press(&mut self, key: Key, mods: Mods) {
        self.rt.key(KeyEvent { key, mods });
        self.settle(0.05);
    }

    fn command(&mut self, c: char) {
        self.press(Key::Command(c), cmd());
    }

    fn tap(&mut self, key: Key) {
        self.press(key, Mods::default());
    }

    fn type_text(&mut self, text: &str) {
        for c in text.chars() {
            self.rt.key(KeyEvent {
                key: Key::Text(c.into()),
                mods: Mods::default(),
            });
        }
        self.settle(0.05);
    }

    fn reply(&mut self, done: Done) {
        self.replies.send(done).unwrap();
        self.settle(0.1);
    }

    fn sent(&self) -> Vec<Job> {
        self.jobs.try_iter().collect()
    }

    fn shows(&self, s: &str) -> bool {
        self.rt
            .elements()
            .iter()
            .any(|e| e.text.as_deref() == Some(s))
    }

    /// Types into the open form's field `name`, as the person would.
    fn fill(&mut self, name: &str, value: &str) {
        self.rt.update(|s, _| {
            let form = s.edit.form.as_mut().unwrap();
            let input = form.fields.iter_mut().find(|f| f.name == name).unwrap();
            input.edit.replace_text(value);
            s.form_changed();
        });
        self.settle(0.05);
    }

    fn value(&self, name: &str) -> String {
        let form = self.rt.state.edit.form.as_ref().unwrap();
        let input = form.fields.iter().find(|f| f.name == name).unwrap();
        input.edit.text.to_string()
    }

    fn click_row(&mut self, id: &str) {
        let (x, y) = self.rt.find(&format!("item-{id}")).unwrap();
        self.rt.pointer_down(x, y);
        self.rt.pointer_up(x, y);
        self.settle(0.1);
    }

    fn selected_label(&self) -> Option<String> {
        self.rt.state.selected_item().map(|i| i.label.clone())
    }

    fn github(&self) -> ItemInfo {
        let item = self.rt.state.detail.clone().unwrap();
        assert_eq!(item.label, "github.com");
        item
    }

    /// Another device changes the vault: the app refetches the list, then the
    /// selected item, and gets these.
    fn synced(&mut self, items: Vec<ItemInfo>, item: Option<ItemInfo>) {
        let vault = self.rt.state.status.clone().unwrap().vaults[0].id.clone();
        self.sent();
        self.reply(Done::Changed(Change::Items { vault }));
        let generation = self.rt.state.generation();
        self.reply(Done::Items {
            generation,
            result: Ok(items),
        });
        if let Some(item) = item {
            let seq = self
                .sent()
                .into_iter()
                .find_map(|j| match j {
                    Job::Get { seq, .. } => Some(seq),
                    _ => None,
                })
                .expect("the selected item is fetched");
            self.reply(Done::Item {
                seq,
                result: Ok(Values::new(item)),
            });
        }
    }
}

fn cmd() -> Mods {
    Mods {
        cmd: true,
        ..Mods::default()
    }
}

fn info(id: &str, kind: &str, label: &str) -> ItemInfo {
    ItemInfo {
        id: id.into(),
        short: id[..4].into(),
        kind: kind.into(),
        label: label.into(),
        detail: None,
        fields: Vec::new(),
        source: None,
    }
}

fn failure(message: &str) -> Failure {
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
    r.command('n');
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
    assert!(form.is_new());
    assert_eq!(form.kind, "login");
    assert!(form.name.focused, "the name takes focus");
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

    r.reply(Done::Generated {
        seq,
        result: Ok(Zeroizing::new("Vq7#mRz2!pKx9@wLt4&nBe8z".into())),
    });
    assert_eq!(r.value("password"), "Vq7#mRz2!pKx9@wLt4&nBe8z");
    let form = r.rt.state.edit.form.as_ref().unwrap();
    let password = form.fields.iter().find(|f| f.name == "password").unwrap();
    assert!(password.edit.is_secure(), "the field stays secure");
    assert!(
        password.edit.is_revealed(),
        "a generated password shows, in place"
    );
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
    r.rt.update(|s, _| s.pick_kind("card"));
    assert!(r.sent().is_empty());
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert_eq!(form.kind, "card");
    assert!(form.generates().is_none());
}

#[test]
fn a_new_login_saves_and_is_selected() {
    let mut r = rig("vault");
    r.command('n');
    r.type_text("Linear");
    r.fill("username", "kit");
    r.fill("password", "pw-linear");
    r.sent();
    r.command('s');
    let (seq, created) = match r.sent().pop() {
        Some(Job::Create {
            kind,
            name,
            fields,
            seq,
        }) => {
            assert_eq!(kind, "login");
            assert_eq!(name.as_deref(), Some("Linear"));
            let fields: Vec<(String, String)> = fields
                .iter()
                .map(|f| (f.name.clone(), f.value.clone()))
                .collect();
            (seq, fields)
        }
        _ => panic!("expected a create"),
    };
    assert_eq!(
        created,
        [
            ("username".to_string(), "kit".to_string()),
            ("password".to_string(), "pw-linear".to_string())
        ]
    );
    assert!(r.rt.state.edit.form.as_ref().unwrap().saving);
    assert!(r.shows("Saving…"));

    let id = "9e9e0000000000000000000000000000";
    r.reply(Done::Saved {
        seq,
        result: Ok(info(id, "login", "Linear 2")),
    });
    assert_eq!(r.rt.state.selected.as_deref(), Some(id));
    assert!(
        r.rt.state.items.iter().any(|i| i.id == id),
        "listed at once"
    );
    let sent = r.sent();
    let get = sent
        .iter()
        .find_map(|j| match j {
            Job::Get { id: got, seq } if got == id => Some(*seq),
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
    assert!(!r.rt.state.editing());
    assert!(r.rt.state.search.focused, "the search has the keys again");
    assert_eq!(r.selected_label().as_deref(), Some("Linear 2"));
}

/// A new login, its password generated, saved: the create's tag, and what
/// was sent.
fn save_new_login(r: &mut Rig, password: Option<&str>) -> u64 {
    r.sent();
    r.command('n');
    let generate = match r.sent().as_slice() {
        [Job::Generate { seq, .. }] => *seq,
        _ => panic!("expected one generate"),
    };
    if let Some(password) = password {
        r.reply(Done::Generated {
            seq: generate,
            result: Ok(Zeroizing::new(password.into())),
        });
    }
    r.type_text("Linear");
    r.command('s');
    match r.sent().pop() {
        Some(Job::Create { seq, .. }) => seq,
        _ => panic!("expected a create"),
    }
}

/// The saved item lands: listed, selected and fetched. The fetch's tag.
fn saved(r: &mut Rig, seq: u64, id: &str) -> u64 {
    r.reply(Done::Saved {
        seq,
        result: Ok(info(id, "login", "Linear")),
    });
    r.sent()
        .into_iter()
        .find_map(|j| match j {
            Job::Get { id: got, seq } if got == id => Some(seq),
            _ => None,
        })
        .expect("its values are fetched")
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
        s.pick_kind("card");
        s.name_mut().replace_text("Typed meanwhile");
        s.input_mut(0).replace_text("typed meanwhile");
        s.cancel_edit();
    });
    r.tap(Key::Escape);
    let form = r.rt.state.edit.form.as_ref().expect("the form stays");
    assert!(form.saving);
    assert_eq!(form.kind, "login");
    assert_eq!(form.name.text.as_str(), "Linear");
    assert_eq!(r.value("username"), "");
    assert_eq!(r.value("password"), "Vq7#mRz2!pKx9@wLt4&nBe8z");
    assert_eq!(r.rt.state.edit.length, length);
    assert!(r.rt.state.edit.symbols);
    let generated = r.sent().iter().any(|j| matches!(j, Job::Generate { .. }));
    assert!(!generated, "nothing asked of the generator");
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
    let pending = {
        r.sent();
        r.command('n');
        match r.sent().as_slice() {
            [Job::Generate { seq, .. }] => *seq,
            _ => panic!("expected one generate"),
        }
    };
    r.fill("password", "typed-password");
    r.command('s');
    let seq = match r.sent().pop() {
        Some(Job::Create { seq, .. }) => seq,
        _ => panic!("expected a create"),
    };
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
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert!(!form.saving);
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
    assert!(!r.rt.state.editing());
    assert!(r.rt.state.search.focused);
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
    assert!(!r.rt.state.editing());
    assert!(r.sent().is_empty());

    r.command('e');
    r.fill("username", "kit");
    r.fill("notes", "");
    r.command('s');
    match r.sent().pop() {
        Some(Job::Save {
            id,
            name,
            fields,
            unset,
            ..
        }) => {
            assert_eq!(id, github.id);
            assert_eq!(name, None);
            let fields: Vec<(&str, &str)> = fields
                .iter()
                .map(|f| (f.name.as_str(), f.value.as_str()))
                .collect();
            assert_eq!(fields, [("username", "kit")]);
            assert_eq!(unset, ["notes"]);
        }
        _ => panic!("expected a save"),
    }
}

#[test]
fn a_refusal_shows_on_its_field_and_keeps_the_form() {
    let mut r = rig("vault");
    r.command('n');
    r.rt.update(|s, _| s.pick_kind("card"));
    r.fill("number", "4242");
    r.sent();
    r.tap(Key::Enter);
    let seq = match r.sent().pop() {
        Some(Job::Create { seq, .. }) => seq,
        _ => panic!("⏎ saves"),
    };
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
    assert!(r.shows("Number can't be empty."));
    assert!(r.sent().is_empty(), "nothing sent");
}

#[test]
fn esc_cancels_and_the_selection_waits_for_a_changed_form() {
    let mut r = rig("vault");
    let selected = r.rt.state.selected.clone();
    r.command('e');
    r.tap(Key::Escape);
    assert!(!r.rt.state.editing());
    assert!(r.rt.state.search.focused);

    let other =
        r.rt.state
            .items
            .iter()
            .find(|i| Some(&i.id) != selected.as_ref())
            .unwrap()
            .id
            .clone();
    let github = r.github();
    let click = |r: &mut Rig, id: &str| r.click_row(id);

    // A click on the item being edited leaves the form as it is.
    r.command('e');
    click(&mut r, &github.id);
    assert!(r.rt.state.editing(), "the form stays");
    assert!(r.rt.state.edit.form.as_ref().unwrap().name.focused);
    assert!(!r.rt.state.search.focused);

    // An unchanged form gives way to another item, leaving as it goes.
    let (x, y) = r.rt.find(&format!("item-{other}")).unwrap();
    r.rt.pointer_down(x, y);
    r.rt.pointer_up(x, y);
    r.rt.frame(FRAME);
    let (_, opacity) = at(&r.rt, "form").expect("the form leaves, not vanishes");
    assert!(opacity > 0.0, "still fading: {opacity}");
    r.settle(0.5);
    assert!(at(&r.rt, "form").is_none());
    assert!(!r.rt.state.editing());
    assert_eq!(r.rt.state.selected.as_ref(), Some(&other));
    r.sent();
    click(&mut r, selected.as_ref().unwrap());
    let seq = r
        .sent()
        .into_iter()
        .find_map(|j| match j {
            Job::Get { seq, .. } => Some(seq),
            _ => None,
        })
        .unwrap();
    r.reply(Done::Item {
        seq,
        result: Ok(Values::new(github)),
    });

    // A changed form holds the selection and says so.
    r.command('e');
    r.fill("username", "kit");
    r.tap(Key::Down);
    assert_eq!(r.rt.state.selected, selected);
    click(&mut r, &other);
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
    let github = r.github();
    r.command('e');
    r.fill("username", "kit");

    let mut theirs = github.clone();
    for f in &mut theirs.fields {
        if f.name == "password" {
            f.value = "their-password".into();
        }
    }
    let items = r.rt.state.items.clone();
    r.synced(items.clone(), Some(theirs));
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert_eq!(form.conflict, Some(Conflict::Changed));
    assert_eq!(r.value("username"), "kit");
    assert!(r.shows("Changed on another device"));

    // Saving sends only ours, so theirs stays.
    r.sent();
    r.command('s');
    match r.sent().pop() {
        Some(Job::Save { fields, unset, .. }) => {
            let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
            assert_eq!(names, ["username"]);
            assert!(unset.is_empty());
        }
        _ => panic!("expected a save"),
    }
}

/// "Show theirs" drops what was typed for the other device's version, and
/// the form, not the search, takes the keys.
#[test]
fn show_theirs_reloads_the_form_from_the_other_device() {
    let mut r = rig("vault");
    let github = r.github();
    r.command('e');
    r.fill("username", "kit");
    let mut theirs = github.clone();
    for f in &mut theirs.fields {
        if f.name == "password" {
            f.value = "their-password".into();
        }
    }
    let items = r.rt.state.items.clone();
    r.synced(items, Some(theirs));
    assert!(r.shows("Show theirs"));
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
    assert_eq!(form.conflict, None);
    assert!(!form.changed());
    assert_eq!(r.value("username"), "dax");
    assert_eq!(r.value("password"), "their-password");
    assert!(!r.shows("Changed on another device"));

    // Pressed without moving focus (as VoiceOver does) while the search
    // has it, the form's name takes the keys, never both at once.
    r.fill("username", "kit");
    let mut newer = r.rt.state.detail.clone().unwrap();
    for f in &mut newer.fields {
        if f.name == "password" {
            f.value = "newer-password".into();
        }
    }
    let items = r.rt.state.items.clone();
    r.synced(items, Some(newer));
    let (x, y) = r.rt.find("search").unwrap();
    r.rt.pointer_down(x, y);
    r.rt.pointer_up(x, y);
    r.settle(0.1);
    assert!(r.rt.state.search.focused);
    r.rt.update(|s, _| s.reload_edit());
    assert_eq!(r.value("password"), "newer-password");
    assert!(r.rt.state.edit.form.as_ref().unwrap().name.focused);
    assert!(!r.rt.state.search.focused, "the form has the keys");
}

/// Elements carrying `secret` as text, the masked field's or anything else's.
fn plaintext(r: &Rig, secret: &str) -> Vec<String> {
    r.rt.elements()
        .iter()
        .filter(|e| e.text.as_deref().is_some_and(|t| t.contains(secret)))
        .map(|e| e.path.clone())
        .collect()
}

/// Generated (and so revealed) the password field stays secure: its value
/// is drawn in place, never carried as text in the tree. Not while shown,
/// nor when another replaces it, it's hidden, the form closes or the vault
/// locks; and whatever closes the form masks every field.
#[test]
fn a_shown_password_never_lingers_in_plain_text() {
    let generate = |r: &mut Rig, password: &str| {
        let seq = r
            .sent()
            .into_iter()
            .find_map(|j| match j {
                Job::Generate { seq, .. } => Some(seq),
                _ => None,
            })
            .expect("a generate");
        r.replies
            .send(Done::Generated {
                seq,
                result: Ok(Zeroizing::new(password.into())),
            })
            .unwrap();
        r.rt.frame(FRAME);
        r.rt.frame(FRAME);
    };
    let mut r = rig("vault");
    r.sent();
    r.command('n');
    generate(&mut r, "first-Generated-1");
    assert!(plaintext(&r, "first-Generated-1").is_empty(), "shown");
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert!(
        form.fields
            .iter()
            .filter(|f| f.secret())
            .all(|f| f.edit.is_secure())
    );
    assert!(form.fields[1].edit.is_revealed());

    r.rt.update(|s, _| s.generate());
    generate(&mut r, "second-Generated-2");
    assert!(plaintext(&r, "first-Generated-1").is_empty(), "replaced");
    assert!(plaintext(&r, "second-Generated-2").is_empty(), "shown");

    r.rt.key(KeyEvent {
        key: Key::Escape,
        mods: Mods::default(),
    });
    r.rt.frame(FRAME);
    assert!(plaintext(&r, "second-Generated-2").is_empty(), "cancelled");

    r.command('n');
    generate(&mut r, "third-Generated-3");
    let revealed = |r: &Rig| {
        r.rt.state.edit.form.as_ref().unwrap().fields[1]
            .edit
            .is_revealed()
    };
    r.rt.update(|s, _| s.toggle_shown(1));
    r.rt.frame(FRAME);
    assert!(
        !revealed(&r) && plaintext(&r, "third-Generated-3").is_empty(),
        "hidden"
    );
    r.rt.update(|s, _| s.toggle_shown(1));
    r.rt.frame(FRAME);
    assert!(
        revealed(&r) && plaintext(&r, "third-Generated-3").is_empty(),
        "shown again"
    );
    r.replies.send(Done::Locked(Ok(()))).unwrap();
    r.rt.frame(FRAME);
    r.rt.frame(FRAME);
    assert_eq!(r.rt.state.screen, Screen::Locked);
    assert!(plaintext(&r, "third-Generated-3").is_empty(), "locked");
}

/// ⌘C in a password field copies through the secret path: concealed, and
/// cleared after the countdown.
#[test]
fn copying_from_a_password_field_clears_after_the_countdown() {
    // Shown or not: revealing changes only how the field is drawn.
    for revealed in [false, true] {
        let mut r = rig("vault");
        let board = rune::clipboard::memory();
        r.rt.use_clipboard(&board);
        r.rt.state.clear_after = 1.0;
        let text = || board.text().map(|t| t.as_str().to_owned());
        r.command('e');
        r.rt.update(|s, _| {
            s.search.focused = false;
            let form = s.edit.form.as_mut().unwrap();
            form.name.focused = false;
            let input = form
                .fields
                .iter_mut()
                .find(|f| f.name == "password")
                .unwrap();
            input.edit.focused = true;
            input.edit.set_revealed(revealed);
        });
        r.settle(0.05);
        r.command('a');
        r.command('x');
        assert_eq!(
            r.value("password"),
            "correct-horse-battery-staple",
            "⌘X cuts nothing"
        );
        assert_eq!(text(), None, "nor copies anything");
        r.command('c');
        let copy = r.rt.state.copy.as_ref().expect("a secret copy");
        assert_eq!(copy.field, "password");
        assert!(copy.copied.is_some());
        assert_eq!(text().as_deref(), Some("correct-horse-battery-staple"));
        r.settle(1.5);
        assert_eq!(text(), None, "{revealed}: cleared after the countdown");
    }
}

/// ⌘N over an unchanged edit opens a new item in its place.
#[test]
fn cmd_n_replaces_an_unchanged_edit() {
    let mut r = rig("vault");
    r.command('e');
    assert!(!r.rt.state.edit.form.as_ref().unwrap().is_new());
    r.command('n');
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert!(form.is_new(), "a new item's form");
    assert!(!form.nudge);

    // One with changes stays, and says so.
    r.tap(Key::Escape);
    r.command('e');
    r.fill("username", "kit");
    r.command('n');
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert!(!form.is_new() && form.nudge);
}

#[test]
fn an_item_deleted_elsewhere_saves_back_as_new() {
    let mut r = rig("vault");
    let github = r.github();
    r.command('e');
    r.fill("username", "kit");
    let items: Vec<ItemInfo> =
        r.rt.state
            .items
            .iter()
            .filter(|i| i.id != github.id)
            .cloned()
            .collect();
    r.synced(items, None);
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert_eq!(form.conflict, Some(Conflict::Deleted));
    assert!(r.shows("Deleted on another device"));
    let fetched = r.sent().into_iter().any(|j| matches!(j, Job::Get { .. }));
    assert!(!fetched, "the deleted item isn't fetched");
    r.settle(0.5);
    assert!(r.sent().is_empty());
    assert!(r.rt.state.notice.is_none());
    r.command('s');
    match r.sent().pop() {
        Some(Job::Create { name, fields, .. }) => {
            assert_eq!(name.as_deref(), Some("github.com"));
            assert!(fields.iter().any(|f| f.name == "password"));
        }
        _ => panic!("expected a create"),
    }
}

#[test]
fn delete_asks_in_place_and_the_next_item_takes_its_place() {
    let mut r = rig("vault");
    let github = r.github();
    let visible: Vec<String> = r.rt.state.visible().iter().map(|i| i.id.clone()).collect();
    let next = visible[visible.iter().position(|i| *i == github.id).unwrap() + 1].clone();
    let backspace = |r: &mut Rig| r.press(Key::Backspace, cmd());

    backspace(&mut r);
    assert!(r.shows("Delete “github.com”?"));
    r.tap(Key::Escape);
    r.settle(0.3);
    assert!(r.rt.state.edit.delete.is_none());
    assert!(!r.shows("Delete “github.com”?"));

    // In a search with text, ⌘⌫ is the field's.
    r.type_text("git");
    assert_eq!(r.rt.state.search.text, "git");
    backspace(&mut r);
    assert_eq!(r.rt.state.search.text, "");
    assert!(r.rt.state.edit.delete.is_none());

    backspace(&mut r);
    r.sent();
    r.tap(Key::Enter);
    let seq = match r.sent().pop() {
        Some(Job::Remove { id, seq }) => {
            assert_eq!(id, github.id);
            seq
        }
        _ => panic!("expected a remove"),
    };
    assert!(r.shows("Deleting…"));

    // Until the agent answers, the selection, the search and the pane hold.
    r.tap(Key::Down);
    r.type_text("li");
    r.command('n');
    r.command('e');
    r.press(Key::Backspace, cmd());
    r.click_row(&next);
    assert_eq!(r.rt.state.selected.as_deref(), Some(github.id.as_str()));
    assert_eq!(r.rt.state.search.text, "");
    assert!(r.rt.state.edit.form.is_none());
    assert!(r.shows("Deleting…"));
    assert!(r.sent().is_empty());

    r.reply(Done::Removed {
        seq,
        result: Ok(info(&github.id, "login", "github.com")),
    });
    assert!(r.rt.state.edit.delete.is_none());
    assert!(!r.rt.state.items.iter().any(|i| i.id == github.id));
    assert_eq!(r.rt.state.selected.as_deref(), Some(next.as_str()));
}

/// ⌘N, ⌘E and ⌘⌫, or their menu items, act only on the vault's list and
/// item: not over Settings (its Touch ID switch too), the import view or the
/// lock screen waiting on Touch ID.
#[test]
fn edit_keys_wait_for_the_vault() {
    for scene in [
        "settings",
        "settings-touch-id",
        "import-preview",
        "locked-touch-id",
    ] {
        let mut r = rig(scene);
        let screen = r.rt.state.screen.clone();
        r.command('n');
        r.command('e');
        r.press(Key::Backspace, cmd());
        for act in [App::new_item, App::edit_selected, App::ask_delete] {
            r.rt.update(|s, _| s.from_menu(act));
        }
        assert!(r.rt.state.edit.form.is_none(), "{scene}: no form");
        assert!(r.rt.state.edit.delete.is_none(), "{scene}: no confirm");
        assert_eq!(r.rt.state.screen, screen, "{scene}: stays");
        let generate = r.jobs.try_iter().any(|j| matches!(j, Job::Generate { .. }));
        assert!(!generate, "{scene}: nothing asked of the agent");
    }
}

#[test]
fn a_failed_delete_says_why_in_the_confirm() {
    let mut r = rig("vault");
    r.press(Key::Backspace, cmd());
    r.sent();
    r.tap(Key::Enter);
    let seq = match r.sent().pop() {
        Some(Job::Remove { seq, .. }) => seq,
        _ => panic!("expected a remove"),
    };
    r.reply(Done::Removed {
        seq,
        result: Err(failure("the vault is read-only")),
    });
    assert!(r.shows("The vault is read-only."));
    assert!(r.shows("Delete"));
    assert_eq!(r.rt.state.screen, Screen::Vault);
}

/// (rect, opacity) of the innermost element keyed `key`.
fn at(rt: &Runtime<App>, key: &str) -> Option<([f32; 4], f32)> {
    rt.elements()
        .into_iter()
        .rfind(|e| e.key.as_deref() == Some(key))
        .map(|e| (e.rect, e.opacity))
}

/// The delete button grows into its confirm; with Reduce Motion the
/// confirm fades in where it lands.
#[test]
fn the_delete_button_grows_into_its_confirm() {
    let mut r = rig("vault");
    r.rt.key(KeyEvent {
        key: Key::Backspace,
        mods: cmd(),
    });
    r.rt.frame(FRAME);
    r.rt.frame(FRAME);
    let (early, _) = at(&r.rt, "delete-confirm").expect("the confirm");
    r.settle(1.0);
    let (rest, opacity) = at(&r.rt, "delete-confirm").unwrap();
    assert!(
        early[2] < rest[2] - 40.0,
        "it grows from the button ({} -> {})",
        early[2],
        rest[2]
    );
    assert_eq!(opacity, 1.0);

    let mut r = rig("vault");
    r.rt.state.reduced_motion = true;
    r.settle(0.1);
    r.rt.key(KeyEvent {
        key: Key::Backspace,
        mods: cmd(),
    });
    r.rt.frame(FRAME);
    r.rt.frame(FRAME);
    let (early, fade) = at(&r.rt, "delete-confirm").expect("the confirm");
    r.settle(1.0);
    let (rest, _) = at(&r.rt, "delete-confirm").unwrap();
    assert_eq!(early, rest, "nothing grows");
    assert!(fade < 1.0, "it fades in (opacity {fade})");
}

/// A 1×1 grey PNG: the backdrop of a `--desktop` run.
const BACKDROP: [u8; 69] = [
    137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0,
    0, 0, 144, 119, 83, 222, 0, 0, 0, 12, 73, 68, 65, 84, 120, 156, 99, 104, 104, 104, 0, 0, 3, 4,
    1, 129, 75, 211, 210, 16, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
];

/// The keys of the main window's elements after `steps`, in a headless
/// `--desktop` run of `scene`, where both windows run and reach each other
/// as they do live. None without a GPU to run headless on.
fn main_after(scene: &str, steps: serde_json::Value) -> Option<Vec<String>> {
    let dir = tempfile::tempdir().unwrap();
    let (script, tree, backdrop) = (
        dir.path().join("script.json"),
        dir.path().join("tree.json"),
        dir.path().join("backdrop.png"),
    );
    std::fs::write(&script, steps.to_string()).unwrap();
    std::fs::write(&backdrop, BACKDROP).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_deadbolt-app"))
        .args(["--window", "main", "--scene", scene, "--at", "0.6"])
        .args(["--size", "1200x800", "--scale", "1", "--desktop"])
        .arg(&backdrop)
        .arg("--script")
        .arg(&script)
        .arg("--tree")
        .arg(&tree)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() && stderr.contains("no GPU adapter") {
        eprintln!("skipped: headless runs need a GPU ({stderr})");
        return None;
    }
    assert!(out.status.success(), "{stderr}");
    let tree: serde_json::Value = serde_json::from_slice(&std::fs::read(&tree).unwrap()).unwrap();
    let keys = tree["elements"].as_array().unwrap().iter();
    Some(
        keys.filter_map(|e| e["key"].as_str().map(str::to_owned))
            .collect(),
    )
}

/// The menus' New Item, Edit Item and Delete Item… act on the main window,
/// and do nothing from the quick panel or over Settings.
#[test]
fn the_menus_add_edit_and_delete() {
    use deadbolt_app::edit::{DELETE, EDIT, NEW};
    let menu = |item: &str| serde_json::json!({"t": 0.2, "menu": item});
    let shows = |keys: &[String], key: &str| keys.iter().any(|k| k == key);
    let Some(keys) = main_after("vault", serde_json::json!([menu(NEW)])) else {
        return;
    };
    assert!(
        shows(&keys, "kinds"),
        "New Item: the new item's type picker"
    );
    let keys = main_after("vault", serde_json::json!([menu(EDIT)])).unwrap();
    assert!(
        shows(&keys, "form") && !shows(&keys, "kinds"),
        "Edit Item: a form"
    );
    let keys = main_after("vault", serde_json::json!([menu(DELETE)])).unwrap();
    assert!(shows(&keys, "delete-confirm"), "Delete Item…: the confirm");

    let up = serde_json::json!({"t": 0.1, "shortcut": deadbolt_app::shortcut::DEFAULT});
    let keys = main_after("vault", serde_json::json!([up, menu(NEW)])).unwrap();
    assert!(!shows(&keys, "form"), "nothing from the quick panel");
    let keys = main_after("settings", serde_json::json!([menu(NEW)])).unwrap();
    assert!(!shows(&keys, "form"), "nothing over Settings");
}

/// While a form is open, Enter with any other modifier does nothing: it
/// neither copies from the list nor saves, from a field or from nowhere.
#[test]
fn enter_chords_in_a_form_never_reach_the_list() {
    let mut r = rig("vault");
    r.command('e');
    r.fill("username", "kit");
    let chords = [
        Mods {
            shift: true,
            ..Mods::default()
        },
        Mods {
            alt: true,
            ..Mods::default()
        },
        Mods {
            ctrl: true,
            ..Mods::default()
        },
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
        assert!(r.rt.state.copy.is_none(), "nothing copied");
        assert!(r.rt.state.editing(), "still editing");
        assert!(r.sent().is_empty(), "nothing saved");
        assert_eq!(r.value("username"), "kit");
    }

    // Notes keep ⇧⏎ for themselves.
    r.rt.update(|s, _| {
        let form = s.edit.form.as_mut().unwrap();
        let notes = form.fields.iter_mut().find(|f| f.name == "notes").unwrap();
        notes.edit.focused = true;
    });
    r.settle(0.05);
    r.press(Key::Enter, chords[0]);
    assert!(r.rt.state.copy.is_none() && r.rt.state.editing());
    assert!(r.sent().is_empty());
}

/// Add offers an identity, laid out as the core's schema has it, and its
/// address is a text area whose line breaks are saved as typed.
#[test]
fn add_offers_an_identity_with_a_multi_line_address() {
    let mut r = rig("vault");
    r.command('n');
    assert!(r.shows("Identity"), "the picker offers it");
    r.rt.update(|s, _| s.pick_kind("identity"));
    r.settle(0.3);
    let form = r.rt.state.edit.form.as_ref().unwrap();
    let names: Vec<&str> = form.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "name",
            "email",
            "phone",
            "address",
            "birthday",
            "national-id",
            "passport",
            "license",
            "notes"
        ]
    );
    let height = |key: &str| at(&r.rt, key).unwrap().0[3];
    assert!(
        height("field-address") > height("field-phone") + 10.0,
        "the address is a text area"
    );
    r.rt.update(|s, _| s.edit.form.as_mut().unwrap().name.replace_text("Dax Raad"));
    r.fill("name", "Dax Raad");
    r.fill("address", "1 Main St\nSpringfield");
    r.sent();
    r.command('s');
    match r.sent().pop() {
        Some(Job::Create {
            kind, name, fields, ..
        }) => {
            assert_eq!(kind, "identity");
            assert_eq!(name.as_deref(), Some("Dax Raad"));
            let fields: Vec<(&str, &str)> = fields
                .iter()
                .map(|f| (f.name.as_str(), f.value.as_str()))
                .collect();
            assert_eq!(
                fields,
                [("name", "Dax Raad"), ("address", "1 Main St\nSpringfield")]
            );
        }
        _ => panic!("expected a save"),
    }
}

/// Focuses the open form's field `name`, as a click would.
fn focus(r: &mut Rig, name: &str) {
    let name = name.to_owned();
    r.rt.update(move |s, _| {
        s.search.focused = false;
        let form = s.edit.form.as_mut().unwrap();
        form.name.focused = false;
        for input in &mut form.fields {
            input.edit.focused = input.name == name;
        }
    });
    r.settle(0.05);
}

fn input<'a>(r: &'a Rig, name: &str) -> &'a deadbolt_app::edit::Input {
    let form = r.rt.state.edit.form.as_ref().unwrap();
    form.fields.iter().find(|f| f.name == name).unwrap()
}

fn created(r: &mut Rig) -> (String, Vec<(String, String)>) {
    match r.sent().pop() {
        Some(Job::Create { kind, fields, .. }) => (
            kind,
            fields
                .iter()
                .map(|f| (f.name.clone(), f.value.clone()))
                .collect(),
        ),
        _ => panic!("expected a create"),
    }
}

/// Add offers a secure note and an SSH key. A note's body is a secure text
/// area: ⏎ breaks the line, a paste keeps its line breaks (CRLF as LF), and
/// what's saved is exactly what was typed, hidden or shown.
#[test]
fn add_offers_a_secure_note_whose_body_keeps_its_lines() {
    let mut r = rig("vault");
    r.command('n');
    assert!(r.shows("Secure note") && r.shows("SSH key"));
    r.rt.update(|s, _| s.pick_kind("note"));
    r.settle(0.05);
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert_eq!(form.kind, "note");
    let names: Vec<&str> = form.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["notes"]);
    assert!(input(&r, "notes").edit.is_secure());

    focus(&mut r, "notes");
    assert!(r.rt.has_secure_focus());
    r.sent();
    r.type_text("Front door: 4417");
    r.tap(Key::Enter);
    r.type_text("Garage: 0932");
    r.tap(Key::Enter);
    r.rt.paste("Shed: 1111\r\nGate:\t2222\r\n");
    r.settle(0.05);
    let body = "Front door: 4417\nGarage: 0932\nShed: 1111\nGate:\t2222\n";
    assert_eq!(r.value("notes"), body);
    assert!(
        r.rt.state.editing() && r.sent().is_empty(),
        "⏎ saved nothing"
    );
    assert!(plaintext(&r, "4417").is_empty(), "hidden");
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.05);
    assert!(input(&r, "notes").edit.is_revealed());
    assert!(plaintext(&r, "4417").is_empty(), "shown, never as text");

    r.command('s');
    let (kind, fields) = created(&mut r);
    assert_eq!(kind, "note");
    assert_eq!(fields, [("notes".to_owned(), body.to_owned())]);
}

/// Picking another type keeps what both have, but a secret never moves into
/// a plain field, and plain text moving into a secret is masked.
#[test]
fn picking_a_type_never_moves_a_secret_into_plain_text() {
    let mut r = rig("vault");
    r.command('n');
    r.fill("notes", "plain words");
    assert!(
        !plaintext(&r, "plain words").is_empty(),
        "a login's notes are text"
    );
    r.rt.update(|s, _| s.pick_kind("note"));
    r.settle(0.5);
    assert_eq!(r.value("notes"), "plain words");
    assert!(input(&r, "notes").edit.is_secure(), "masked as it moves");
    assert!(plaintext(&r, "plain words").is_empty(), "drawn masked");

    r.fill("notes", "Front door: 4417");
    r.rt.update(|s, _| s.pick_kind("card"));
    r.settle(0.5);
    assert_eq!(r.value("notes"), "", "the secret stays behind");
    assert!(!input(&r, "notes").edit.is_secure());
    assert!(plaintext(&r, "4417").is_empty(), "never drawn as text");
    r.rt.update(|s, _| s.pick_kind("login"));
    r.settle(0.5);
    assert!(plaintext(&r, "4417").is_empty());
}

/// An SSH key's private key is a secure text area too. Hidden, the saved
/// key isn't in it: left empty, it's kept and not sent (an edit sends only
/// what changed); what's pasted or typed into it replaces it, its line
/// breaks and final newline saved as they came.
#[test]
fn an_ssh_keys_private_key_is_edited_in_place() {
    let mut r = rig("ssh");
    r.command('e');
    let form = r.rt.state.edit.form.as_ref().expect("a form");
    assert_eq!(form.kind, "ssh");
    assert_eq!(r.value("private-key"), "", "kept, not loaded");
    assert!(input(&r, "private-key").keeps());
    assert!(input(&r, "private-key").edit.is_secure());
    assert!(!r.rt.state.edit.form.as_ref().unwrap().changed());
    r.fill("comment", "ci@anoma.ly");
    r.sent();
    r.command('s');
    match r.sent().pop() {
        Some(Job::Save { fields, unset, .. }) => {
            let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
            assert_eq!(names, ["comment"], "the untouched key isn't sent");
            assert!(unset.is_empty(), "{unset:?}");
        }
        _ => panic!("expected a save"),
    }

    let mut r = rig("ssh");
    r.command('e');
    focus(&mut r, "private-key");
    // Hidden, a paste replaces the whole key.
    let pasted = "-----BEGIN OPENSSH PRIVATE KEY-----\r\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\r\n-----END OPENSSH PRIVATE KEY-----\r\n";
    r.rt.paste(pasted);
    r.settle(0.05);
    let typed = pasted.replace("\r\n", "\n");
    assert_eq!(r.value("private-key"), typed);
    assert!(plaintext(&r, "b3BlbnNz").is_empty());
    r.sent();
    // ⌘⏎ is the field's own submit, which saves.
    r.press(Key::Enter, cmd());
    match r.sent().pop() {
        Some(Job::Save { fields, .. }) => {
            let sent: Vec<(&str, &str)> = fields
                .iter()
                .map(|f| (f.name.as_str(), f.value.as_str()))
                .collect();
            assert_eq!(sent, [("private-key", typed.as_str())]);
        }
        _ => panic!("expected a save"),
    }
}

/// In a secret's text area ⏎ (and ⇧⏎, ⌥⏎) breaks the line, ⌘⏎ and ⌘S save,
/// other ⌘ and ⌃ chords do nothing, and esc cancels.
#[test]
fn keys_in_a_secret_text_area() {
    let mut r = rig("vault");
    r.command('n');
    r.rt.update(|s, _| s.pick_kind("ssh"));
    focus(&mut r, "private-key");
    r.sent();
    r.type_text("a");
    for mods in [
        Mods::default(),
        Mods {
            shift: true,
            ..Mods::default()
        },
        Mods {
            alt: true,
            ..Mods::default()
        },
    ] {
        r.press(Key::Enter, mods);
    }
    r.type_text("b");
    assert_eq!(r.value("private-key"), "a\n\n\nb");
    for mods in [
        Mods {
            ctrl: true,
            ..Mods::default()
        },
        Mods {
            cmd: true,
            shift: true,
            ..Mods::default()
        },
    ] {
        r.press(Key::Enter, mods);
    }
    assert_eq!(r.value("private-key"), "a\n\n\nb");
    assert!(r.rt.state.editing() && r.sent().is_empty(), "nothing saved");
    assert!(r.rt.state.copy.is_none());

    r.command('s');
    let (kind, fields) = created(&mut r);
    assert_eq!(kind, "ssh");
    assert_eq!(fields, [("private-key".to_owned(), "a\n\n\nb".to_owned())]);

    let mut r = rig("vault");
    r.command('n');
    r.rt.update(|s, _| s.pick_kind("note"));
    focus(&mut r, "notes");
    r.type_text("x");
    r.tap(Key::Escape);
    assert!(!r.rt.state.editing(), "esc cancels");
}

/// ⌘C in a secret's text area copies its selection through the secret
/// path, hidden or shown; ⌘X cuts nothing.
#[test]
fn copying_from_a_secret_text_area_clears_after_the_countdown() {
    for revealed in [false, true] {
        let mut r = rig("ssh");
        let board = rune::clipboard::memory();
        r.rt.use_clipboard(&board);
        r.rt.state.clear_after = 1.0;
        let text = || board.text().map(|t| t.as_str().to_owned());
        r.command('e');
        focus(&mut r, "private-key");
        // Shown, the saved key; hidden, one typed in its place.
        if revealed {
            r.rt.update(|s, _| s.toggle_shown(0));
        } else {
            r.rt.paste("-----BEGIN PRIVATE KEY-----\nnew\n");
        }
        r.settle(0.05);
        let key = r.value("private-key");
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----\n"), "{key:?}");
        r.command('a');
        r.command('x');
        assert_eq!(r.value("private-key"), key, "⌘X cuts nothing");
        assert_eq!(text(), None);
        r.command('c');
        let copy = r.rt.state.copy.as_ref().expect("a secret copy");
        assert_eq!(copy.field, "private-key");
        assert_eq!(text().as_deref(), Some(key.as_str()), "{revealed}");
        r.settle(1.5);
        assert_eq!(text(), None, "{revealed}: cleared after the countdown");
    }
}

/// A private key shown in the form is drawn in place, never carried as
/// text: not shown, hidden, cancelled, nor after a lock.
#[test]
fn a_shown_private_key_never_lingers_in_plain_text() {
    let mut r = rig("ssh");
    r.command('e');
    let secret = "MC4CAQAw";
    assert!(plaintext(&r, secret).is_empty(), "hidden");
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.05);
    assert!(input(&r, "private-key").edit.is_revealed());
    assert!(plaintext(&r, secret).is_empty(), "shown");
    r.rt.update(|s, _| s.toggle_shown(0));
    r.rt.frame(FRAME);
    assert!(plaintext(&r, secret).is_empty(), "hidden again");
    r.rt.update(|s, _| s.toggle_shown(0));
    r.rt.frame(FRAME);
    r.tap(Key::Escape);
    assert!(!r.rt.state.editing());
    assert!(plaintext(&r, secret).is_empty(), "cancelled");

    r.command('e');
    r.rt.update(|s, _| s.toggle_shown(0));
    r.rt.frame(FRAME);
    r.replies.send(Done::Locked(Ok(()))).unwrap();
    r.rt.frame(FRAME);
    r.rt.frame(FRAME);
    assert_eq!(r.rt.state.screen, Screen::Locked);
    assert!(plaintext(&r, secret).is_empty(), "locked");
}

/// A public key is one line that wraps where it runs long, and ⏎ there
/// saves rather than breaking it.
#[test]
fn a_public_key_wraps_in_the_form_and_enter_saves() {
    let mut r = rig("ssh");
    r.command('e');
    let height = |r: &Rig, key: &str| at(&r.rt, key).unwrap().0[3];
    assert!(
        height(&r, "field-public-key") > height(&r, "field-comment") + 10.0,
        "the public key wraps"
    );
    r.fill("public-key", "ssh-ed25519 AAAAnew ci@anoma.ly");
    focus(&mut r, "public-key");
    r.sent();
    r.tap(Key::Enter);
    assert_eq!(r.value("public-key"), "ssh-ed25519 AAAAnew ci@anoma.ly");
    match r.sent().pop() {
        Some(Job::Save { fields, .. }) => {
            let sent: Vec<(&str, &str)> = fields
                .iter()
                .map(|f| (f.name.as_str(), f.value.as_str()))
                .collect();
            assert_eq!(sent, [("public-key", "ssh-ed25519 AAAAnew ci@anoma.ly")]);
        }
        _ => panic!("expected a save"),
    }
}

/// ⏎ in a text area that isn't secret (a login's notes, an address)
/// breaks the line, as in a secure note's body: Rune would submit it. ⌘⏎
/// saves.
#[test]
fn enter_breaks_the_line_in_notes() {
    let mut r = rig("vault");
    r.command('n');
    focus(&mut r, "notes");
    r.sent();
    r.type_text("first");
    r.tap(Key::Enter);
    r.type_text("second");
    assert_eq!(r.value("notes"), "first\nsecond");
    assert!(r.rt.state.editing());
    r.press(Key::Enter, cmd());
    match r.sent().pop() {
        Some(Job::Create { fields, .. }) => {
            let notes = fields.iter().find(|f| f.name == "notes").expect("notes");
            assert_eq!(notes.value, "first\nsecond");
        }
        _ => panic!("expected a create"),
    }

    let mut r = rig("vault");
    r.command('n');
    r.rt.update(|s, _| s.pick_kind("identity"));
    focus(&mut r, "address");
    r.type_text("1 Main St");
    r.tap(Key::Enter);
    r.type_text("Springfield");
    assert_eq!(r.value("address"), "1 Main St\nSpringfield");
    assert!(r.rt.state.editing());
}

const NEW_KEY: &str =
    "-----BEGIN OPENSSH PRIVATE KEY-----\nnew\n-----END OPENSSH PRIVATE KEY-----\n";

/// Presses at the middle of `path`, with no frame after.
fn click_at(r: &mut Rig, path: &str) {
    let (x, y) = r.rt.find(path).unwrap();
    r.rt.pointer_down(x, y);
    r.rt.pointer_up(x, y);
}

fn saved_fields(r: &mut Rig) -> (Vec<(String, String)>, Vec<String>) {
    match r.sent().pop() {
        Some(Job::Save { fields, unset, .. }) => (
            fields
                .iter()
                .map(|f| (f.name.clone(), f.value.clone()))
                .collect(),
            unset,
        ),
        _ => panic!("expected a save"),
    }
}

/// A kept key is replaced by what's typed or pasted into it, even in the
/// frame it's clicked into: there's nothing in it to add to.
#[test]
fn a_kept_key_is_replaced_by_what_goes_into_it() {
    let key = "field-private-key/value";
    let mut r = rig("ssh");
    r.command('e');
    click_at(&mut r, key);
    r.rt.paste(NEW_KEY);
    r.settle(0.1);
    assert_eq!(r.value("private-key"), NEW_KEY);
    r.sent();
    r.command('s');
    assert_eq!(
        saved_fields(&mut r).0,
        [("private-key".to_owned(), NEW_KEY.to_owned())]
    );

    let mut r = rig("ssh");
    r.command('e');
    click_at(&mut r, key);
    for c in "ab".chars() {
        r.rt.key(KeyEvent {
            key: Key::Text(c.into()),
            mods: Mods::default(),
        });
    }
    r.settle(0.1);
    assert_eq!(r.value("private-key"), "ab");
}

/// Keys that select or move in a kept key change nothing: it's still kept,
/// and nothing is sent.
#[test]
fn selecting_in_a_kept_key_changes_nothing() {
    let mut r = rig("ssh");
    r.command('e');
    focus(&mut r, "private-key");
    let shift = Mods {
        shift: true,
        ..Mods::default()
    };
    let ctrl_shift = Mods {
        ctrl: true,
        shift: true,
        ..Mods::default()
    };
    r.command('a');
    for (key, mods) in [
        (Key::Left, shift),
        (Key::End, shift),
        (Key::Left, ctrl_shift),
        (Key::Command('a'), ctrl_shift),
        (Key::Command('e'), ctrl_shift),
        (Key::Home, Mods::default()),
    ] {
        r.press(key, mods);
    }
    assert!(r.rt.state.editing());
    assert!(input(&r, "private-key").keeps());
    assert!(!r.rt.state.edit.form.as_ref().unwrap().changed());
    r.sent();
    r.command('s');
    assert!(!r.rt.state.editing(), "nothing to save closes the form");
    assert!(r.sent().is_empty());
}

/// A new item's key is typed as it comes, however fast.
#[test]
fn a_new_key_keeps_every_character_typed() {
    let mut r = rig("vault");
    r.command('n');
    r.rt.update(|s, _| s.pick_kind("ssh"));
    r.settle(0.1);
    click_at(&mut r, "field-private-key/value");
    for c in "abcdef".chars() {
        r.rt.key(KeyEvent {
            key: Key::Text(c.into()),
            mods: Mods::default(),
        });
        r.rt.frame(FRAME);
    }
    r.settle(0.1);
    assert_eq!(r.value("private-key"), "abcdef");
}

/// Show loads a kept key to edit in place. Hidden again unchanged, it's kept
/// again and not sent; hidden after an edit, the edit stays, whole.
#[test]
fn show_loads_a_kept_key_and_hide_keeps_an_edit() {
    let mut r = rig("ssh");
    let saved =
        r.rt.state
            .detail
            .as_ref()
            .and_then(|d| d.fields.iter().find(|f| f.name == "private-key"))
            .map(|f| f.value.clone())
            .unwrap();
    r.command('e');
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.1);
    assert_eq!(r.value("private-key"), saved, "loaded to show");
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.1);
    assert_eq!(r.value("private-key"), "", "unchanged, kept again");
    assert!(input(&r, "private-key").keeps());
    r.fill("comment", "ci@anoma.ly");
    r.sent();
    r.command('s');
    assert_eq!(saved_fields(&mut r).0.len(), 1, "the key isn't sent");

    let mut r = rig("ssh");
    r.command('e');
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.1);
    r.type_text("x");
    let edited = format!("{saved}x");
    assert_eq!(r.value("private-key"), edited);
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.1);
    let key = input(&r, "private-key");
    assert!(!key.edit.is_revealed());
    assert_eq!(r.value("private-key"), edited, "hidden, the edit stays");
    // Hidden, typing adds to it as usual.
    r.type_text("y");
    assert_eq!(r.value("private-key"), format!("{edited}y"));
    r.sent();
    r.command('s');
    assert_eq!(
        saved_fields(&mut r).0,
        [("private-key".to_owned(), format!("{edited}y"))]
    );
}

/// A note's body is removed on purpose: Show, select all, delete. A private
/// key can't be.
#[test]
fn a_shown_note_cleared_on_purpose_is_removed() {
    let mut r = rig("note");
    r.command('e');
    focus(&mut r, "notes");
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.1);
    r.command('a');
    r.tap(Key::Backspace);
    assert_eq!(r.value("notes"), "");
    assert!(!input(&r, "notes").keeps());
    r.sent();
    r.command('s');
    let (fields, unset) = saved_fields(&mut r);
    assert!(fields.is_empty(), "{fields:?}");
    assert_eq!(unset, ["notes"]);

    let mut r = rig("ssh");
    r.command('e');
    focus(&mut r, "private-key");
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.1);
    r.command('a');
    r.tap(Key::Backspace);
    r.sent();
    r.command('s');
    assert!(r.sent().is_empty());
    let form = r.rt.state.edit.form.as_ref().expect("still open");
    assert!(form.problem_for("private-key").is_some());
}

/// Typed into while kept, then shown and emptied on purpose, a note is
/// removed and a private key is refused: shown, it's no longer kept.
#[test]
fn a_kept_secret_typed_into_then_shown_and_emptied_isnt_kept() {
    let mut r = rig("note");
    r.command('e');
    focus(&mut r, "notes");
    r.type_text("draft");
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.1);
    assert_eq!(
        r.value("notes"),
        "draft",
        "what was typed, not the saved body"
    );
    r.command('a');
    r.tap(Key::Backspace);
    assert!(!input(&r, "notes").keeps());
    r.sent();
    r.command('s');
    let (fields, unset) = saved_fields(&mut r);
    assert!(fields.is_empty(), "{fields:?}");
    assert_eq!(unset, ["notes"]);

    let mut r = rig("ssh");
    r.command('e');
    focus(&mut r, "private-key");
    r.type_text("x");
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.1);
    r.command('a');
    r.tap(Key::Backspace);
    r.sent();
    r.command('s');
    assert!(r.sent().is_empty());
    let form = r.rt.state.edit.form.as_ref().expect("still open");
    assert!(form.problem_for("private-key").is_some());
}

/// Only whitespace typed into a kept secret, unseen behind the mask, keeps
/// the saved value rather than removing it.
#[test]
fn whitespace_typed_into_a_kept_secret_keeps_it() {
    let mut r = rig("note");
    r.command('e');
    focus(&mut r, "notes");
    r.type_text(" ");
    r.tap(Key::Enter);
    assert!(input(&r, "notes").keeps());
    r.rt.update(|s, _| {
        s.edit.form.as_mut().unwrap().name.replace_text("Renamed");
        s.form_changed();
    });
    r.settle(0.05);
    r.sent();
    r.command('s');
    let (fields, unset) = saved_fields(&mut r);
    assert!(unset.is_empty(), "{unset:?}");
    assert!(fields.iter().all(|(name, _)| name != "notes"), "{fields:?}");
}

/// Show and Hide focus their field, and only it.
#[test]
fn show_and_hide_focus_the_field_alone() {
    fn focused(r: &Rig) -> Vec<&str> {
        let s = &r.rt.state;
        let form = s.edit.form.as_ref().unwrap();
        let mut on: Vec<&str> = form
            .fields
            .iter()
            .filter(|f| f.edit.focused)
            .map(|f| f.name.as_str())
            .collect();
        if form.name.focused {
            on.push("name");
        }
        if s.search.focused {
            on.push("search");
        }
        on
    }
    let r = rig("edit-ssh-revealed");
    assert_eq!(focused(&r), ["private-key"]);

    let reveal = "field-private-key/value/secret-lines/actions/reveal";
    let mut r = rig("ssh");
    r.command('e');
    assert_eq!(focused(&r), ["name"]);
    for shown in [true, false] {
        click_at(&mut r, reveal);
        r.settle(0.1);
        assert_eq!(input(&r, "private-key").edit.is_revealed(), shown);
        assert_eq!(focused(&r), ["private-key"], "shown {shown}");
        assert!(r.rt.has_secure_focus());
    }
}

/// A public key that came with line breaks (from the CLI or an import) is
/// kept as it came: the form isn't changed on open, and saving something
/// else leaves it alone.
#[test]
fn a_public_key_left_alone_is_kept_as_it_came() {
    let mut r = rig("ssh");
    let came = "ssh-ed25519 AAAAC3Nz\naC1lZDI1 ci@anoma.ly\n";
    r.rt.update(move |s, _| {
        let detail = s.detail.as_mut().unwrap();
        let key = detail
            .fields
            .iter_mut()
            .find(|f| f.name == "public-key")
            .unwrap();
        key.value = came.into();
    });
    r.command('e');
    assert_eq!(r.value("public-key"), came);
    assert!(!r.rt.state.edit.form.as_ref().unwrap().changed());
    r.fill("comment", "ci@anoma.ly");
    r.sent();
    r.command('s');
    match r.sent().pop() {
        Some(Job::Save { fields, .. }) => {
            let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
            assert_eq!(names, ["comment"]);
        }
        _ => panic!("expected a save"),
    }
    assert_eq!(r.value("public-key"), came);
}

/// A wrapping one-line value (a public key, a fingerprint) keeps to one
/// line: a hard-wrapped paste loses its line breaks, which would hide among
/// the soft wraps.
#[test]
fn a_pasted_public_key_keeps_to_one_line() {
    let mut r = rig("ssh");
    r.command('e');
    focus(&mut r, "public-key");
    r.command('a');
    r.rt.paste("ssh-ed25519 AAAAC3Nz\r\naC1lZDI1\nNTE5 ci@anoma.ly\n");
    r.settle(0.05);
    assert_eq!(
        r.value("public-key"),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ci@anoma.ly"
    );
    r.type_text("!");
    assert!(
        r.value("public-key").ends_with("ci@anoma.ly!"),
        "the caret stays at the end"
    );
    let height = |r: &Rig, key: &str| at(&r.rt, key).unwrap().0[3];
    assert!(
        height(&r, "field-fingerprint") > height(&r, "field-comment") + 10.0,
        "the fingerprint wraps"
    );
    r.sent();
    r.tap(Key::Enter);
    match r.sent().pop() {
        Some(Job::Save { fields, .. }) => {
            let key = fields.iter().find(|f| f.name == "public-key").unwrap();
            assert_eq!(key.value, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ci@anoma.ly!");
        }
        _ => panic!("expected a save"),
    }
}

/// The agent keeps a login's one-time password back, so the form never has
/// it: left empty it stays, and typed into, it's replaced.
#[test]
fn an_edit_keeps_a_one_time_password_it_never_sees() {
    let shows: fn(&Rig) -> Vec<String> = |r| {
        r.rt.elements()
            .iter()
            .filter(|e| !e.exiting)
            .filter_map(|e| e.label.clone())
            .filter(|l| l.starts_with("Show "))
            .collect()
    };
    let mut r = rig("vault");
    r.command('e');
    assert_eq!(r.value("otp"), "");
    assert_eq!(shows(&r), ["Show Password"], "nothing to show");
    r.sent();
    r.command('s');
    assert!(!r.rt.state.editing());
    assert!(r.sent().is_empty());

    r.command('e');
    r.fill("otp", "JBSWY3DPEHPK3PXP");
    assert_eq!(shows(&r).len(), 2, "a typed one shows: {:?}", shows(&r));
    r.command('s');
    match r.sent().pop() {
        Some(Job::Save { fields, unset, .. }) => {
            let fields: Vec<(&str, &str)> = fields
                .iter()
                .map(|f| (f.name.as_str(), f.value.as_str()))
                .collect();
            assert_eq!(fields, [("otp", "JBSWY3DPEHPK3PXP")]);
            assert!(unset.is_empty(), "{unset:?}");
        }
        _ => panic!("expected a save"),
    }
}

/// A login needs no password, as the core has it (an import brings some
/// without one), so a form left without one still saves.
#[test]
fn a_login_saves_without_a_password() {
    let mut r = rig("vault");
    r.command('n');
    r.fill("username", "kit");
    r.fill("password", "");
    r.sent();
    r.command('s');
    match r.sent().pop() {
        Some(Job::Create { fields, .. }) => {
            let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
            assert_eq!(names, ["username"]);
        }
        _ => panic!("expected a create"),
    }
}
