//! The quick panel's global shortcut, headless and offline: a conflict at
//! launch shows a calm notice and keeps ⇧⌘Space working inside Deadbolt,
//! Settings' recorder changes, saves and resets it, and headless scripts reach
//! the panel through it and through the menus' "Open Quick Panel".

#![cfg(test)]

use std::path::Path;
use std::process::Command;

use deadbolt_app::model::App;
use deadbolt_app::panel::window::{FLAG, OPEN};
use deadbolt_app::shortcut::{self, Hotkey};
use rune::{Env, Mods, PhysicalInput, PhysicalKeyCode, Runtime, Shortcut, ShortcutError};
use serde_json::{Value, json};

const FRAME: f64 = 1.0 / 60.0;

fn main_window(hotkey: Hotkey) -> Runtime<App> {
    let mut app = rune::tooling::initial_state(&deadbolt_app::spec(), Some("vault"));
    app.hotkey = hotkey;
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
    rt.update(|s, _| s.start_shortcut(false));
    settle(&mut rt, 0.6);
    rt
}

fn settle(rt: &mut Runtime<App>, seconds: f64) {
    for _ in 0..(seconds / FRAME).round() as usize {
        rt.frame(FRAME);
    }
}

fn shows(rt: &Runtime<App>, s: &str) -> bool {
    rt.elements()
        .iter()
        .any(|e| e.text.as_deref().is_some_and(|t| t.contains(s)) && e.opacity > 0.99)
}

fn press(rt: &mut Runtime<App>, key: &str) {
    let (x, y) = rt.find(key).unwrap_or_else(|| panic!("{key} is on screen"));
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    settle(rt, 0.5);
}

/// Presses and releases `chord` on the physical keyboard.
fn chord(rt: &mut Runtime<App>, chord: &Shortcut) {
    physical(rt, chord.physical_key(), chord.modifiers());
}

fn physical(rt: &mut Runtime<App>, key: PhysicalKeyCode, mods: Mods) {
    for pressed in [true, false] {
        rt.physical_input(PhysicalInput::Key {
            key,
            mods,
            pressed,
            repeat: false,
        });
        rt.frame(FRAME);
    }
    settle(rt, 0.3);
}

fn parse(s: &str) -> Shortcut {
    s.parse().unwrap()
}

#[test]
fn a_conflict_at_launch_shows_a_notice_that_leads_to_settings() {
    let default = shortcut::default();
    let mut rt = main_window(Hotkey::new(Some(default.clone()), vec![default.clone()]));
    assert_eq!(rt.state.hotkey.error, Some(ShortcutError::Conflict));
    let head = format!("{} isn't available", shortcut::name(&default));
    assert!(shows(&rt, &head), "the notice says which shortcut");
    assert!(shows(
        &rt,
        "Another app is using it, so the quick panel can't open from anywhere."
    ));
    assert!(rt.state.shortcut_fallback, "it still works inside Deadbolt");

    press(&mut rt, "choose");
    assert!(rt.state.settings_open, "Choose another… opens Settings");
    assert!(rt.find("recorder").is_some(), "with the recorder");
    press(&mut rt, "settings-trigger");
    assert!(!rt.state.settings_open);

    press(&mut rt, "dismiss");
    assert!(rt.find("shortcut-notice").is_none(), "Not now puts it away");
}

/// When the desktop says who holds a chord (macOS's own shortcuts, another
/// Rune app), the notice, Settings and the recorder name it.
#[test]
fn a_known_holder_is_named() {
    let default = shortcut::default();
    let taken = parse("ctrl+alt+j");
    let hotkey = Hotkey::new(Some(default.clone()), vec![default.clone(), taken.clone()]);
    let mut rt = main_window(hotkey.taken_by("Spotlight"));
    assert!(shows(
        &rt,
        "Spotlight is using it, so the quick panel can't open from anywhere."
    ));
    rt.update(|s, _| s.settings_open = true);
    settle(&mut rt, 0.5);
    let in_use = |chord| format!("{} is in use by Spotlight.", shortcut::name(chord));
    assert!(shows(&rt, &in_use(&default)), "Settings says who");

    press(&mut rt, "recorder");
    chord(&mut rt, &taken);
    assert!(shows(&rt, &in_use(&taken)), "and so does the recorder");
}

#[test]
fn a_registered_shortcut_shows_no_notice_and_turns_the_fallback_off() {
    let rt = main_window(Hotkey::new(Some(shortcut::default()), Vec::new()));
    assert!(rt.state.hotkey.registered());
    assert!(rt.find("shortcut-notice").is_none());
    assert!(!rt.state.shortcut_fallback);
}

#[test]
fn the_recorder_changes_saves_and_resets_the_shortcut() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("app-shortcut");
    let taken = parse("ctrl+alt+j");
    let hotkey = Hotkey::new(shortcut::load(&file), vec![taken.clone()]).saving_to(file.clone());
    let mut rt = main_window(hotkey);
    rt.update(|s, _| s.settings_open = true);
    settle(&mut rt, 0.5);
    assert!(
        rt.find("reset").is_none(),
        "the default has nothing to reset"
    );

    // A chord another app holds: shown in place, the old one kept, nothing saved.
    press(&mut rt, "recorder");
    chord(&mut rt, &taken);
    let refusal = format!("{} is in use by another app.", shortcut::name(&taken));
    assert!(shows(&rt, &refusal), "it names the chord");
    assert!(!shows(&rt, &ShortcutError::Conflict.to_string()));
    assert_eq!(
        rt.state.hotkey.recorder.refused(),
        Some(&taken),
        "and keeps it on the keycaps"
    );
    assert_eq!(rt.state.hotkey.shortcut, Some(shortcut::default()));
    assert!(
        rt.state.hotkey.recorder.is_recording(),
        "it waits for another"
    );
    assert!(!file.exists());

    let chosen = parse("ctrl+alt+k");
    chord(&mut rt, &chosen);
    assert_eq!(rt.state.hotkey.shortcut.as_ref(), Some(&chosen));
    assert!(rt.state.hotkey.registered());
    assert!(!rt.state.hotkey.recorder.is_recording());
    assert_eq!(shortcut::load(&file).as_ref(), Some(&chosen), "saved");
    assert!(
        !rt.state.shortcut_fallback,
        "the fallback is for ⇧⌘Space only"
    );

    press(&mut rt, "reset");
    assert_eq!(rt.state.hotkey.shortcut, Some(shortcut::default()));
    assert_eq!(
        rt.state.hotkey.recorder.shortcut(),
        Some(&shortcut::default())
    );
    assert!(!file.exists(), "the default saves as no file");
    assert!(rt.find("reset").is_none());

    // Backspace clears it, and a cleared shortcut stays cleared.
    press(&mut rt, "recorder");
    physical(&mut rt, PhysicalKeyCode::Backspace, Mods::default());
    assert_eq!(rt.state.hotkey.shortcut, None);
    assert!(!rt.state.hotkey.registered());
    assert_eq!(shortcut::load(&file), None);
    assert!(rt.find("reset").is_some(), "Reset brings it back");
    assert!(rt.find("retry").is_none(), "nothing to try again");
    let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(names.len(), 1, "no temporary file left beside it");
}

fn needs_modifier() -> &'static str {
    if cfg!(target_os = "macos") {
        "Add ⌘, ⌃ or ⌥."
    } else {
        "Add Ctrl, Alt or Super."
    }
}

/// A bare key (or one with only Shift) would be taken from typing in every
/// app, so the recorder refuses it in place and keeps the old shortcut.
#[test]
fn the_recorder_refuses_a_chord_without_a_modifier() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("app-shortcut");
    let hotkey = Hotkey::new(Some(shortcut::default()), Vec::new()).saving_to(file.clone());
    let mut rt = main_window(hotkey);
    rt.update(|s, _| s.settings_open = true);
    settle(&mut rt, 0.5);
    press(&mut rt, "recorder");
    let shift = Mods {
        shift: true,
        ..Mods::default()
    };
    for (key, mods) in [
        (PhysicalKeyCode::Space, Mods::default()),
        (PhysicalKeyCode::KeyA, Mods::default()),
        (PhysicalKeyCode::Enter, shift),
    ] {
        physical(&mut rt, key, mods);
        assert!(shows(&rt, needs_modifier()), "{key:?} with {mods:?}");
        assert_eq!(rt.state.hotkey.shortcut, Some(shortcut::default()));
        assert!(rt.state.hotkey.registered(), "the old one still works");
        assert!(rt.state.hotkey.recorder.is_recording());
    }
    assert!(!file.exists(), "nothing saved");

    let chosen = parse("ctrl+alt+k");
    chord(&mut rt, &chosen);
    assert_eq!(rt.state.hotkey.shortcut.as_ref(), Some(&chosen));
    assert!(!shows(&rt, needs_modifier()));

    // Nor is a saved chord Rune would refuse: it falls back to the default.
    for bare in ["space", "shift+a"] {
        std::fs::write(&file, format!("{bare}\n")).unwrap();
        assert_eq!(shortcut::load(&file), Some(shortcut::default()), "{bare}");
    }
}

/// Function keys type nothing, so F1–F24 can be a shortcut alone.
#[test]
fn the_recorder_takes_a_function_key_alone() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("app-shortcut");
    let hotkey = Hotkey::new(Some(shortcut::default()), Vec::new()).saving_to(file.clone());
    let mut rt = main_window(hotkey);
    rt.update(|s, _| s.settings_open = true);
    settle(&mut rt, 0.5);
    for key in [
        PhysicalKeyCode::F1,
        PhysicalKeyCode::F13,
        PhysicalKeyCode::F24,
    ] {
        press(&mut rt, "recorder");
        physical(&mut rt, key, Mods::default());
        let taken = Shortcut::from_physical_key(key, Mods::default()).unwrap();
        assert_eq!(rt.state.hotkey.shortcut.as_ref(), Some(&taken), "{key:?}");
        assert!(rt.state.hotkey.registered());
        assert!(!shows(&rt, needs_modifier()));
        assert_eq!(shortcut::load(&file), Some(taken), "saved and read back");
    }
}

/// ⇧⌘Space was taken at launch. Settings says so, with Try again, and
/// recording ⇧⌘Space again also tries again, once the other app lets go.
#[test]
fn a_shortcut_taken_at_launch_can_be_tried_again() {
    let default = shortcut::default();
    let mut rt = main_window(Hotkey::new(Some(default.clone()), vec![default.clone()]));
    rt.update(|s, _| s.settings_open = true);
    settle(&mut rt, 0.5);
    let in_use = format!("{} is in use by another app.", shortcut::name(&default));
    assert!(shows(&rt, &in_use), "Settings says why");
    assert_eq!(
        rt.state.hotkey.recorder.shortcut(),
        Some(&default),
        "the recorder still shows it"
    );
    assert!(rt.find("reset").is_none(), "it's already the default");

    press(&mut rt, "retry");
    assert!(!rt.state.hotkey.registered(), "still taken");
    assert!(shows(&rt, &in_use));

    rt.state.hotkey.set_taken(Vec::new());
    press(&mut rt, "recorder");
    chord(&mut rt, &default);
    assert!(
        rt.state.hotkey.registered(),
        "recording it again registers it"
    );
    assert_eq!(rt.state.hotkey.error, None);
    assert!(!shows(&rt, &in_use));
    assert!(rt.find("retry").is_none());
    assert!(!rt.state.shortcut_fallback);

    // Try again does the same.
    let mut rt = main_window(Hotkey::new(Some(default.clone()), vec![default.clone()]));
    rt.update(|s, _| s.settings_open = true);
    settle(&mut rt, 0.5);
    rt.state.hotkey.set_taken(Vec::new());
    press(&mut rt, "retry");
    assert!(rt.state.hotkey.registered());
    assert!(rt.find("retry").is_none());
    press(&mut rt, "settings-trigger");
    assert!(
        rt.find("shortcut-notice").is_none(),
        "the notice has gone too"
    );
}

/// Reset's error names the default the way the recorder's does, and goes
/// once recording starts.
#[test]
fn a_refused_reset_says_why_until_recording_starts() {
    let default = shortcut::default();
    let other = parse("ctrl+alt+k");
    let mut rt = main_window(Hotkey::new(Some(other), vec![default.clone()]));
    rt.update(|s, _| s.settings_open = true);
    settle(&mut rt, 0.5);
    press(&mut rt, "reset");
    let in_use = format!("{} is in use by another app.", shortcut::name(&default));
    assert!(shows(&rt, &in_use));
    assert!(!shows(&rt, &ShortcutError::Conflict.to_string()));

    press(&mut rt, "recorder");
    assert!(!shows(&rt, &in_use), "recording puts it away");
    physical(&mut rt, PhysicalKeyCode::Escape, Mods::default());
    assert!(!shows(&rt, &in_use), "and it stays away");
}

#[test]
fn escape_cancels_a_recording_before_it_closes_settings() {
    let mut rt = main_window(Hotkey::new(Some(shortcut::default()), Vec::new()));
    rt.update(|s, _| s.settings_open = true);
    settle(&mut rt, 0.5);
    press(&mut rt, "recorder");
    assert!(rt.state.hotkey.recorder.is_recording());
    physical(&mut rt, PhysicalKeyCode::Escape, Mods::default());
    assert!(!rt.state.hotkey.recorder.is_recording());
    assert!(rt.state.settings_open, "Settings stays");
    assert_eq!(rt.state.hotkey.shortcut, Some(shortcut::default()));
}

#[test]
fn an_unreadable_saved_shortcut_falls_back_to_the_default() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("app-shortcut");
    assert_eq!(shortcut::load(&file), Some(shortcut::default()));
    std::fs::write(&file, "not a shortcut\n").unwrap();
    assert_eq!(shortcut::load(&file), Some(shortcut::default()));
    std::fs::write(&file, "\n").unwrap();
    assert_eq!(shortcut::load(&file), None);
}

/// Runs the panel headless with `events`, and returns its card's opacity at
/// the end. None without a GPU to run headless on.
fn card_after(args: &[&str], events: Value) -> Option<f64> {
    let dir = tempfile::tempdir().unwrap();
    let (script, tree) = (dir.path().join("script.json"), dir.path().join("tree.json"));
    std::fs::write(&script, events.to_string()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_deadbolt-app"))
        .args(["--window", "panel", "--scene", "empty"])
        .args(args)
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
    Some(card(&tree))
}

fn card(tree: &Path) -> f64 {
    let tree: Value = serde_json::from_slice(&std::fs::read(tree).unwrap()).unwrap();
    tree["elements"]
        .as_array()
        .unwrap()
        .iter()
        .rfind(|e| e["key"] == "card")
        .map_or(0.0, |e| e["opacity"].as_f64().unwrap())
}

#[test]
fn a_headless_shortcut_step_toggles_the_panel() {
    let press = |t: f64| json!({"t": t, "shortcut": shortcut::DEFAULT});
    let Some(away) = card_after(&[], json!([press(0.1)])) else {
        return;
    };
    assert!(away < 0.01, "the first press sends it away ({away})");
    let back = card_after(&[], json!([press(0.1), press(1.0)])).unwrap();
    assert_eq!(back, 1.0, "the second brings it back");
}

/// "Open Quick Panel" brings the panel back from the app menu (by title) and
/// the Dock menu (by id), and leaves an open one up.
#[test]
fn the_menus_open_the_panel() {
    let away = json!({"t": 0.1, "shortcut": shortcut::DEFAULT});
    for item in [OPEN, "dock-quick"] {
        let open = json!({"t": 1.0, "menu": item});
        let Some(card) = card_after(&[], json!([away.clone(), open])) else {
            return;
        };
        assert_eq!(card, 1.0, "{item} brings it back");
    }
    let open = json!({"t": 0.1, "menu": OPEN});
    assert_eq!(card_after(&[], json!([open])).unwrap(), 1.0);
}

/// `--panel` starts with the panel up; the shortcut is what brings it back
/// after it goes, so nothing quits.
#[test]
fn a_panel_start_opens_the_panel_and_the_shortcut_brings_it_back() {
    let press = |t: f64| json!({"t": t, "shortcut": shortcut::DEFAULT});
    let Some(up) = card_after(&[FLAG], json!([])) else {
        return;
    };
    assert_eq!(up, 1.0);
    let back = card_after(&[FLAG], json!([press(0.1), press(1.0)])).unwrap();
    assert_eq!(back, 1.0);
}
