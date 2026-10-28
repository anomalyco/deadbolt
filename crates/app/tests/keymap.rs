//! The vault's keyboard past the search: J K and ⌘1–9 on the list, ⇥ into
//! the fields and back, O, ⌘K's actions, the ? sheet, ⌘, Settings and the
//! new item's type, all without a mouse.

#![cfg(test)]

use deadbolt_app::model::App;
use rune::{Env, Key, KeyEvent, Mods, Runtime};

const FRAME: f64 = 1.0 / 60.0;

fn scene(name: &str) -> Runtime<App> {
    let app = rune::tooling::initial_state(&deadbolt_app::spec(), Some(name));
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
    settle(&mut rt, 1.0);
    rt
}

fn settle(rt: &mut Runtime<App>, seconds: f64) {
    for _ in 0..(seconds / FRAME).round() as usize {
        rt.frame(FRAME);
    }
}

fn press(rt: &mut Runtime<App>, key: Key, mods: Mods) {
    rt.key(KeyEvent { key, mods });
    rt.frame(FRAME);
}

fn tap(rt: &mut Runtime<App>, key: Key) {
    press(rt, key, Mods::default());
}

fn text(rt: &mut Runtime<App>, t: &str) {
    tap(rt, Key::Text(t.into()));
}

fn command(rt: &mut Runtime<App>, c: char) {
    let mods = Mods {
        cmd: true,
        ..Mods::default()
    };
    press(rt, Key::Command(c), mods);
}

/// Nothing focused, as after a click on empty space.
fn blur(rt: &mut Runtime<App>) {
    rt.update(|_, tx| tx.blur());
    settle(rt, 0.1);
    assert!(!rt.state.search.focused);
}

fn at(rt: &Runtime<App>) -> usize {
    let visible = rt.state.visible();
    let id = rt.state.selected.as_deref().unwrap();
    visible.iter().position(|i| i.id == id).unwrap()
}

fn copied(rt: &Runtime<App>) -> Option<&str> {
    rt.state.copy.as_ref().map(|c| c.field.as_str())
}

#[test]
fn j_k_and_command_digits_move_through_the_list() {
    let mut rt = scene("vault");
    blur(&mut rt);
    let start = at(&rt);
    text(&mut rt, "j");
    assert_eq!(at(&rt), start + 1, "J moves down");
    text(&mut rt, "k");
    assert_eq!(at(&rt), start, "K moves up");
    assert_eq!(rt.state.search.text, "", "neither typed");

    // In the search they type, and ↑↓ move.
    command(&mut rt, 'f');
    text(&mut rt, "j");
    assert_eq!(rt.state.search.text, "j");
    tap(&mut rt, Key::Escape);

    command(&mut rt, '1');
    assert_eq!(at(&rt), 0, "⌘1");
    command(&mut rt, '4');
    assert_eq!(at(&rt), 3, "⌘4");
    let count = rt.state.visible().len();
    command(&mut rt, '9');
    assert_eq!(at(&rt), 3, "⌘9 past the end does nothing ({count} items)");
}

#[test]
fn tab_moves_into_the_fields_and_back() {
    let mut rt = scene("vault");
    assert!(rt.state.search.focused);
    let fields: Vec<String> = rt
        .state
        .shown_fields()
        .iter()
        .map(|f| f.name.clone())
        .collect();
    assert_eq!(fields[0], "password");

    tap(&mut rt, Key::Tab);
    assert_eq!(rt.state.nav.field, Some(0), "⇥ into the first field");
    assert!(!rt.state.search.focused);
    assert!(
        rt.find("h-field-copy").is_some(),
        "the foot says what ⏎ does"
    );

    // Space shows and hides the secret the keys are on.
    text(&mut rt, " ");
    assert!(rt.state.revealed.iter().any(|f| f == "password"));
    text(&mut rt, " ");
    assert!(rt.state.revealed.is_empty());

    // ↓ and J move between fields, stopping at the last; ⏎ copies the one it's on.
    tap(&mut rt, Key::Down);
    assert_eq!(rt.state.nav.field, Some(1));
    tap(&mut rt, Key::Enter);
    assert_eq!(copied(&rt), Some(fields[1].as_str()));
    for _ in 0..fields.len() + 2 {
        text(&mut rt, "j");
    }
    assert_eq!(rt.state.nav.field, Some(fields.len() - 1));
    text(&mut rt, "k");
    assert_eq!(rt.state.nav.field, Some(fields.len() - 2));

    // ⇥ (or Esc) goes back to the search, and the list keys work again.
    tap(&mut rt, Key::Tab);
    assert_eq!(rt.state.nav.field, None);
    assert!(rt.state.search.focused);
    tap(&mut rt, Key::Tab);
    tap(&mut rt, Key::Escape);
    assert_eq!(rt.state.nav.field, None, "Esc leaves the fields too");
    assert!(rt.state.search.focused);

    // A new selection leaves the fields.
    tap(&mut rt, Key::Tab);
    command(&mut rt, '1');
    assert_eq!(rt.state.nav.field, None);
}

#[test]
fn enter_shift_enter_and_option_enter_copy_from_the_list() {
    let mut rt = scene("vault");
    tap(&mut rt, Key::Enter);
    assert_eq!(copied(&rt), Some("password"));
    let shift = Mods {
        shift: true,
        ..Mods::default()
    };
    press(&mut rt, Key::Enter, shift);
    assert_eq!(copied(&rt), Some("username"));
    let alt = Mods {
        alt: true,
        ..Mods::default()
    };
    press(&mut rt, Key::Enter, alt);
    assert_eq!(copied(&rt), Some("otp"));
}

#[test]
fn o_opens_the_website() {
    let mut rt = scene("vault");
    // In the search, O types.
    text(&mut rt, "o");
    assert_eq!(rt.state.search.text, "o");
    assert!(rt.take_url_requests().is_empty());
    tap(&mut rt, Key::Escape);

    blur(&mut rt);
    text(&mut rt, "o");
    assert_eq!(
        rt.take_url_requests(),
        vec!["https://github.com".to_owned()]
    );
    command(&mut rt, 'f');
    command(&mut rt, 'o');
    assert_eq!(
        rt.take_url_requests(),
        vec!["https://github.com".to_owned()],
        "⌘O from the search"
    );
}

#[test]
fn command_k_lists_the_actions_and_runs_one() {
    let mut rt = scene("vault");
    command(&mut rt, 'k');
    assert_eq!(rt.state.nav.palette, Some(0));
    assert!(rt.find("actions").is_some());
    assert!(rt.find("action-copy").is_some());
    assert!(rt.find("action-edit").is_some());

    // Keys stay in the card: ↓ and J move, typing doesn't search.
    tap(&mut rt, Key::Down);
    text(&mut rt, "j");
    assert_eq!(rt.state.nav.palette, Some(2));
    text(&mut rt, "x");
    assert_eq!(rt.state.search.text, "");
    tap(&mut rt, Key::Escape);
    assert_eq!(rt.state.nav.palette, None, "Esc closes it");
    assert_eq!(rt.state.search.text, "");

    // ↵ runs the row and closes it: the first copies the password.
    command(&mut rt, 'k');
    tap(&mut rt, Key::Enter);
    assert_eq!(rt.state.nav.palette, None);
    assert_eq!(copied(&rt), Some("password"));

    // ⌘K again closes it.
    command(&mut rt, 'k');
    command(&mut rt, 'k');
    assert_eq!(rt.state.nav.palette, None);

    // Its Edit opens the form.
    command(&mut rt, 'k');
    let edit = deadbolt_app::palette::actions(&rt.state)
        .iter()
        .position(|a| *a == deadbolt_app::palette::Action::Edit)
        .unwrap();
    for _ in 0..edit {
        tap(&mut rt, Key::Down);
    }
    tap(&mut rt, Key::Enter);
    assert!(rt.state.editing());
}

#[test]
fn question_mark_shows_every_shortcut() {
    let mut rt = scene("vault");
    // An empty search takes ? as the sheet; one being typed takes it as text.
    text(&mut rt, "?");
    assert!(rt.state.nav.sheet);
    assert!(rt.find("sheet").is_some());
    text(&mut rt, "j");
    assert!(rt.state.nav.sheet, "other keys wait");
    tap(&mut rt, Key::Escape);
    assert!(!rt.state.nav.sheet);

    text(&mut rt, "g");
    text(&mut rt, "?");
    assert!(!rt.state.nav.sheet);
    assert_eq!(rt.state.search.text, "g?");
}

#[test]
fn command_comma_opens_settings_and_its_rows_take_the_keys() {
    let mut rt = scene("vault");
    let selected = rt.state.selected.clone();
    command(&mut rt, ',');
    assert!(rt.state.settings_open);
    assert!(rt.find("settings").is_some());
    let rows = deadbolt_app::settings::rows(&rt.state);
    assert_eq!(rt.state.nav.row, 0);

    // ↓ and J move between rows, never the list.
    tap(&mut rt, Key::Down);
    assert_eq!(rt.state.nav.row, 1);
    text(&mut rt, "j");
    assert_eq!(rt.state.nav.row, 2.min(rows.len() - 1));
    text(&mut rt, "k");
    text(&mut rt, "k");
    text(&mut rt, "k");
    assert_eq!(rt.state.nav.row, 0);
    assert_eq!(rt.state.selected, selected);

    // ←→ and Space step the clear-after time on its row.
    let clear = rows
        .iter()
        .position(|r| *r == deadbolt_app::settings::Row::Clear)
        .unwrap();
    rt.update(move |s, _| s.nav.row = clear);
    let before = rt.state.clear_after;
    tap(&mut rt, Key::Right);
    let after = rt.state.clear_after;
    assert!(after > before, "→ steps up: {before} → {after}");
    tap(&mut rt, Key::Left);
    assert_eq!(rt.state.clear_after, before);
    text(&mut rt, " ");
    assert_eq!(rt.state.clear_after, after, "Space steps too");

    // ↵ on the shortcut's row starts recording.
    let shortcut = rows
        .iter()
        .position(|r| *r == deadbolt_app::settings::Row::Shortcut)
        .unwrap();
    rt.update(move |s, _| s.nav.row = shortcut);
    tap(&mut rt, Key::Enter);
    assert!(rt.state.hotkey.recorder.is_recording());
    tap(&mut rt, Key::Escape);
    settle(&mut rt, 0.1);
    assert!(!rt.state.hotkey.recorder.is_recording());
    assert!(rt.state.settings_open, "Esc stopped the recording first");

    // ↵ on the last row, Activity, shows the agent's entries, and again hides them.
    rt.update(move |s, _| s.nav.row = 99);
    tap(&mut rt, Key::Down);
    assert_eq!(rows.last(), Some(&deadbolt_app::settings::Row::Activity));
    tap(&mut rt, Key::Enter);
    assert!(rt.state.activity.open);
    tap(&mut rt, Key::Enter);
    assert!(!rt.state.activity.open);

    // Esc leaves, back to the search; ⌘, toggles too.
    tap(&mut rt, Key::Escape);
    assert!(!rt.state.settings_open);
    assert!(rt.state.search.focused);
    command(&mut rt, ',');
    command(&mut rt, ',');
    assert!(!rt.state.settings_open);
}

#[test]
fn control_tab_picks_the_new_items_type() {
    let mut rt = scene("vault");
    command(&mut rt, 'n');
    settle(&mut rt, 0.1);
    let kind = |rt: &Runtime<App>| rt.state.edit.form.as_ref().unwrap().kind.clone();
    assert_eq!(kind(&rt), "login");
    let ctrl = Mods {
        ctrl: true,
        ..Mods::default()
    };
    press(&mut rt, Key::Tab, ctrl);
    assert_eq!(kind(&rt), "card");
    let back = Mods {
        ctrl: true,
        shift: true,
        ..Mods::default()
    };
    press(&mut rt, Key::Tab, back);
    press(&mut rt, Key::Tab, back);
    assert_eq!(kind(&rt), "identity", "round from the start");
}
