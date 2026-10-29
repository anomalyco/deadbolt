//! Importing in the app against a real agent: an export dropped on the
//! window or picked with Choose File… is previewed, then imported, cancelled,
//! or forgotten on locking. The exports are made up.

// The agent reads the test switches these set (`DEADBOLT_NET`,
// `DEADBOLT_KDF`, `DEADBOLT_TEST_*`) only in a debug build.
#![cfg(debug_assertions)]

use std::path::PathBuf;

use deadbolt_app::agent::{Agent, Job, Window};
use deadbolt_app::import::Phase;
use deadbolt_app::install::Installer;
use deadbolt_app::model::{App, Screen};
use deadbolt_app::view::Severity;
use rune::{Env, FileDialogKind, Key, KeyEvent, Mods, Runtime};

use crate::support::{Device, PASSPHRASE, key, shows, until};

/// A Bitwarden unencrypted JSON export: a login, a card and a secure note
/// come across; a bank account and a login with nothing in it don't.
const BITWARDEN: &str = r#"{
  "encrypted": false,
  "folders": [{ "id": "4f5e2a3b-0c1d-4e2f-9a8b-7c6d5e4f3a2b", "name": "Work" }],
  "items": [
    {
      "passwordHistory": [{ "lastUsedDate": "2024-01-02T03:04:05.000Z", "password": "old-pw-111" }],
      "id": "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "folderId": "4f5e2a3b-0c1d-4e2f-9a8b-7c6d5e4f3a2b",
      "type": 1,
      "name": "GitHub",
      "notes": "notes-secret-222",
      "favorite": true,
      "login": {
        "uris": [{ "match": null, "uri": "https://github.com/login" }],
        "username": "dax",
        "password": "github-secret-444"
      }
    },
    {
      "id": "3b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 3,
      "name": null,
      "favorite": false,
      "card": {
        "cardholderName": "Dax Raad",
        "brand": "Visa",
        "number": "4242 4242 4242 4242",
        "expMonth": "4",
        "expYear": "2027",
        "code": "555"
      }
    },
    { "id": "6b1c", "type": 2, "name": "Wifi", "notes": "wifi-secret-666", "favorite": false, "secureNote": { "type": 0 } },
    { "id": "7b1c", "type": 1, "name": null, "favorite": false, "login": { "username": null, "password": null } },
    { "id": "8b1c", "type": 6, "name": "Bank", "favorite": false }
  ]
}"#;

const SECRETS: &[&str] = &[
    "old-pw-111",
    "github-secret-444",
    // The card's label shows its last four, as the CLI's does.
    "4242 4242",
    "42424242",
    "wifi-secret-666",
    "nopass-secret-777",
];

/// `BITWARDEN` with a password on its empty login: what the file holds if
/// it's exported again after the preview.
fn bitwarden_again() -> String {
    BITWARDEN.replace(r#""password": null"#, r#""password": "nopass-secret-777""#)
}

/// A Bitwarden export of a bank account alone, which Deadbolt doesn't take.
const UNSUPPORTED_ONLY: &str = r#"{
  "encrypted": false,
  "folders": [],
  "items": [
    { "id": "8b1c", "type": 6, "name": "Bank", "favorite": false }
  ]
}"#;

/// The app for a set-up `device`, unlocked in its vault.
fn vault(device: &Device) -> Runtime<App> {
    let mut rt = Runtime::new(
        App::new(Agent::spawn(device.paths(), device.launch(), Window::Main)),
        deadbolt_app::view::app,
        (820.0, 540.0),
        Env {
            system_dark: true,
            scale: 1.0,
        },
    );
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
    rt.state.agent.send(Job::Connect);
    until(&mut rt, "the vault or the lock", |s| {
        matches!(s.screen, Screen::Vault | Screen::Locked)
    });
    if rt.state.screen == Screen::Locked {
        for c in PASSPHRASE.chars() {
            rt.key(key(Key::Text(c.into())));
        }
        rt.key(key(Key::Enter));
    }
    until(&mut rt, "the vault", |s| {
        s.screen == Screen::Vault && s.loaded
    });
    // Let the vault finish arriving, so presses land on what's drawn.
    for _ in 0..40 {
        rt.frame(1.0 / 60.0);
    }
    rt
}

fn device() -> Device {
    let device = Device::new();
    device.run(&["init", "--device-name", "alpha"]);
    device
}

/// Two frames per step: Rune holds a drag for one frame's build when the
/// state changed that frame, as a change from the agent's watch can.
fn drop_file(rt: &mut Runtime<App>, path: PathBuf) {
    rt.drag_files(vec![path.clone()], Some((600.0, 300.0)));
    rt.frame(1.0 / 60.0);
    rt.frame(1.0 / 60.0);
    assert!(rt.state.drop_hovering(), "the drop zone lights up");
    rt.drop_files(vec![path], Some((600.0, 300.0)));
    rt.frame(1.0 / 60.0);
    rt.frame(1.0 / 60.0);
    assert!(!rt.state.drop_hovering());
}

fn previewing(s: &App) -> bool {
    matches!(s.import.phase, Phase::Preview(_))
}

fn no_secrets(rt: &Runtime<App>) {
    for e in rt.elements() {
        for text in [&e.text, &e.label].into_iter().flatten() {
            for secret in SECRETS {
                assert!(!text.contains(secret), "{secret} shows: {text}");
            }
        }
    }
}

fn press(rt: &mut Runtime<App>, key: &str) {
    let (x, y) = rt.find(key).unwrap_or_else(|| panic!("{key} is on screen"));
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    rt.frame(1.0 / 60.0);
}

#[test]
fn a_dropped_export_is_previewed_then_imported() {
    let device = device();
    let file = device.file("bitwarden_export.json", BITWARDEN);
    let mut rt = vault(&device);
    assert!(shows(&rt, "Drop an export here") && shows(&rt, "Choose File…"));

    drop_file(&mut rt, file);
    until(&mut rt, "the preview", previewing);
    assert!(shows(&rt, "Import from Bitwarden"));
    assert!(shows(&rt, "bitwarden_export.json"));
    assert!(shows(&rt, "1 new login · 1 card · 1 secure note"));
    assert!(shows(&rt, "Skipped 1 bank account, 1 empty item"));
    assert!(shows(&rt, "Import 3 items"));
    no_secrets(&rt);
    assert!(
        device.output(&["ls"]).is_empty(),
        "a preview imports nothing"
    );

    // Return imports; the label says so until the items arrive.
    rt.key(key(Key::Enter));
    rt.frame(1.0 / 60.0);
    assert!(matches!(rt.state.import.phase, Phase::Importing(_)));
    until(&mut rt, "the imported items", |s| {
        s.items.len() == 3 && s.import.phase == Phase::Idle
    });
    assert!(shows(&rt, "Imported 3 from Bitwarden"));
    assert!(!rt.state.import.showing());
    // The note lists by its name, never its body.
    assert!(shows(&rt, "Wifi") && shows(&rt, "Secure note"));
    no_secrets(&rt);
    assert_eq!(device.output(&["ls"]).lines().count(), 3);
}

#[test]
fn an_export_already_imported_has_nothing_new() {
    let device = device();
    let file = device.file("export.json", BITWARDEN);
    device.run(&["import", file.to_str().unwrap()]);
    let mut rt = vault(&device);
    until(&mut rt, "the items", |s| s.items.len() == 3);

    // ⇧⌘I opens the import view in a vault with items.
    import_passwords(&mut rt);
    assert!(rt.state.import.open && shows(&rt, "Drop an export here"));

    drop_file(&mut rt, file);
    until(&mut rt, "the preview", previewing);
    assert!(
        rt.elements().iter().any(|e| e
            .text
            .as_deref()
            .is_some_and(|t| t.starts_with("Everything in this export is already in "))),
        "says there's nothing new"
    );
    assert!(!shows(&rt, "Import 0 items"));
    rt.key(key(Key::Enter));
    rt.frame(1.0 / 60.0);
    assert!(!rt.state.import.showing(), "Done closes it");
    assert_eq!(rt.state.items.len(), 3);
}

#[test]
fn a_file_that_isnt_an_export_says_so() {
    let device = device();
    let mut rt = vault(&device);

    // Not a file the window takes: no highlight while it's dragged, and a
    // caution once it's dropped.
    let notes = device.file("notes.txt", "hello");
    rt.drag_files(vec![notes.clone()], Some((600.0, 300.0)));
    rt.frame(1.0 / 60.0);
    rt.frame(1.0 / 60.0);
    assert!(!rt.state.drop_hovering());
    assert_eq!(rt.state.import.error, None);
    assert_eq!(rt.find("import-error"), None);
    rt.drop_files(vec![notes.clone()], Some((600.0, 300.0)));
    rt.frame(1.0 / 60.0);
    rt.frame(1.0 / 60.0);
    let error = rt.state.import.error.clone().expect("a caution");
    assert_eq!(error.severity, Severity::Caution);
    assert_eq!(error.title, "notes.txt isn't an export Deadbolt can read");
    assert!(shows(&rt, &error.title));
    assert_eq!(rt.state.import.phase, Phase::Idle);

    // With an export among them, the export wins.
    let export = device.file("export.json", BITWARDEN);
    rt.drop_files(vec![notes, export], Some((600.0, 300.0)));
    rt.frame(1.0 / 60.0);
    until(&mut rt, "the preview", previewing);
    assert_eq!(rt.state.import.error, None);

    // JSON that isn't an export: the person's to change, so a caution.
    drop_file(&mut rt, device.file("package.json", r#"{"name": "x"}"#));
    until(&mut rt, "the error", |s| s.import.error.is_some());
    let error = rt.state.import.error.clone().unwrap();
    assert_eq!(error.severity, Severity::Caution);
    assert_eq!(
        error.title,
        "package.json isn't an export Deadbolt can read"
    );
    assert!(shows(&rt, &error.title));

    // An encrypted export says how to export it instead.
    let encrypted = device.file("encrypted.json", r#"{"encrypted": true, "items": []}"#);
    drop_file(&mut rt, encrypted);
    until(&mut rt, "the next error", |s| {
        s.import
            .error
            .as_ref()
            .is_some_and(|e| e.title.starts_with("encrypted.json"))
    });
    let error = rt.state.import.error.clone().unwrap();
    assert_eq!(
        error.body,
        "This is an encrypted export; export as unencrypted .json."
    );

    // The drop zone stays live: a good export after it previews.
    drop_file(&mut rt, device.file("export.json", BITWARDEN));
    until(&mut rt, "the preview", previewing);
    assert_eq!(rt.state.import.error, None);
}

#[test]
fn choose_file_previews_the_chosen_export() {
    let device = device();
    let file = device.file("export.json", BITWARDEN);
    let mut rt = vault(&device);

    // Cancelling the dialog leaves the vault as it was: the view isn't
    // opened by Choose File…, so a vault that gains items isn't left on it.
    assert!(!rt.state.import.open);
    press(&mut rt, "choose");
    let (kind, options) = rt.file_dialog().expect("an Open dialog");
    assert_eq!(kind, FileDialogKind::Open);
    assert_eq!(options.title, "Import Passwords");
    assert!(!rt.state.import.open, "not open while the dialog is up");
    rt.resolve_file_dialog(None).unwrap();
    rt.frame(1.0 / 60.0);
    assert_eq!(rt.state.import.phase, Phase::Idle);
    assert_eq!(rt.state.import.error, None);
    assert!(!rt.state.import.open);

    press(&mut rt, "choose");
    rt.resolve_file_dialog(Some(file)).unwrap();
    until(&mut rt, "the preview", previewing);
    assert!(shows(&rt, "1 new login · 1 card · 1 secure note"));
}

#[test]
fn cancelling_a_preview_imports_nothing() {
    let device = device();
    let mut rt = vault(&device);
    drop_file(&mut rt, device.file("export.json", BITWARDEN));
    until(&mut rt, "the preview", previewing);

    rt.key(key(Key::Escape));
    rt.frame(1.0 / 60.0);
    assert_eq!(rt.state.import.phase, Phase::Idle);
    assert!(!rt.state.import.showing());
    assert!(shows(&rt, "Drop an export here"));
    assert!(device.output(&["ls"]).is_empty());
}

#[test]
fn locking_forgets_the_import() {
    let device = device();
    let mut rt = vault(&device);
    drop_file(&mut rt, device.file("export.json", BITWARDEN));
    until(&mut rt, "the preview", previewing);

    device.run(&["lock"]);
    until(&mut rt, "the lock", |s| s.screen == Screen::Locked);
    assert_eq!(rt.state.import.phase, Phase::Idle);
    assert!(!rt.state.import.showing() && rt.state.import.error.is_none());

    for c in PASSPHRASE.chars() {
        rt.key(key(Key::Text(c.into())));
    }
    rt.key(key(Key::Enter));
    until(&mut rt, "the vault", |s| {
        s.screen == Screen::Vault && s.loaded
    });
    assert!(rt.find("import-preview").is_none(), "the preview is gone");
    assert!(rt.find("drop-zone").is_some());
    assert!(device.output(&["ls"]).is_empty());
}

#[test]
fn a_file_changed_since_its_preview_is_previewed_again() {
    let device = device();
    let file = device.file("export.json", BITWARDEN);
    let mut rt = vault(&device);
    drop_file(&mut rt, file.clone());
    until(&mut rt, "the preview", previewing);
    assert!(shows(&rt, "1 new login · 1 card · 1 secure note"));
    assert!(!shows(&rt, "changed since the preview"));

    // Exported again before Import: nothing unpreviewed is written.
    std::fs::write(&file, bitwarden_again()).unwrap();
    rt.key(key(Key::Enter));
    until(
        &mut rt,
        "the fresh preview",
        |s| matches!(&s.import.phase, Phase::Preview(p) if p.changed),
    );
    assert!(shows(&rt, "export.json changed since the preview"));
    assert!(shows(&rt, "2 new logins · 1 card · 1 secure note"));
    assert!(shows(&rt, "Import 4 items"));
    assert!(device.output(&["ls"]).is_empty(), "nothing was imported");
    no_secrets(&rt);

    // Import now brings in what that preview showed.
    rt.key(key(Key::Enter));
    until(&mut rt, "the imported items", |s| {
        s.items.len() == 4 && s.import.phase == Phase::Idle
    });
    assert_eq!(device.output(&["ls"]).lines().count(), 4);
}

#[test]
fn a_file_changed_into_something_else_says_it_isnt_an_export() {
    let device = device();
    let file = device.file("export.json", BITWARDEN);
    let mut rt = vault(&device);
    drop_file(&mut rt, file.clone());
    until(&mut rt, "the preview", previewing);

    std::fs::write(&file, "this is not an export\n").unwrap();
    rt.key(key(Key::Enter));
    until(&mut rt, "the error", |s| s.import.error.is_some());
    let error = rt.state.import.error.clone().unwrap();
    assert_eq!(error.severity, Severity::Caution, "{error:?}");
    assert_eq!(error.title, "export.json isn't an export Deadbolt can read");
    assert!(!error.body.contains("; import a"), "{error:?}");
    assert_eq!(rt.state.import.phase, Phase::Idle);
    assert!(device.output(&["ls"]).is_empty(), "nothing was imported");
}

#[test]
fn an_export_with_nothing_deadbolt_takes_says_so() {
    let device = device();
    let mut rt = vault(&device);
    drop_file(&mut rt, device.file("bank.json", UNSUPPORTED_ONLY));
    until(&mut rt, "the preview", previewing);
    assert!(shows(&rt, "Nothing in this export can be imported"));
    assert!(!shows(&rt, "Everything in this export is already in"));
    assert!(shows(&rt, "Skipped 1 bank account"));
    rt.key(key(Key::Enter));
    rt.frame(1.0 / 60.0);
    assert!(!rt.state.import.showing(), "Done closes it");
    assert!(device.output(&["ls"]).is_empty());
}

/// A scene, offline, settled.
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
    rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
    for _ in 0..60 {
        rt.frame(1.0 / 60.0);
    }
    rt
}

fn import_passwords(rt: &mut Runtime<App>) {
    rt.key(KeyEvent {
        key: Key::Command('i'),
        mods: Mods {
            cmd: true,
            shift: true,
            ..Mods::default()
        },
    });
    rt.frame(1.0 / 60.0);
}

fn rect(rt: &Runtime<App>, key: &str) -> [f32; 4] {
    rt.elements()
        .into_iter()
        .rfind(|e| e.key.as_deref() == Some(key))
        .unwrap_or_else(|| panic!("{key} is on screen"))
        .rect
}

/// The import button's rolling label sits where a plain button's would.
#[test]
fn the_rolling_label_is_centred_in_its_button() {
    let rt = scene("import-preview");
    let button = rect(&rt, "import");
    let label = rect(&rt, "import-label");
    let (left, right) = (
        label[0] - button[0],
        button[0] + button[2] - (label[0] + label[2]),
    );
    assert!(
        (left - right).abs() < 0.5,
        "insets {left} and {right}; button {button:?}, label {label:?}"
    );
}

/// The selected item is hidden under the import view, so Return and
/// ⇧Return don't copy from it; ↑↓ go back to it without moving.
#[test]
fn keys_dont_reach_the_item_under_the_import_view() {
    let mut rt = scene("import");
    let selected = rt.state.selected.clone();
    assert!(selected.is_some() && rt.state.search.focused && rt.state.import.showing());
    for shift in [false, true] {
        rt.key(KeyEvent {
            key: Key::Enter,
            mods: Mods {
                shift,
                ..Mods::default()
            },
        });
        rt.frame(1.0 / 60.0);
        assert!(rt.state.copy.is_none(), "copied with shift {shift}");
        assert!(rt.state.import.showing());
    }
    rt.key(key(Key::Down));
    rt.frame(1.0 / 60.0);
    assert!(!rt.state.import.showing());
    assert_eq!(rt.state.selected, selected, "back to the item, unmoved");

    rt.key(key(Key::Enter));
    rt.frame(1.0 / 60.0);
    assert!(rt.state.copy.is_some(), "Return copies once it shows");
}

/// A drag the window stops hearing about (Escape, or the install page
/// opening over the vault) doesn't leave the import view up.
#[test]
fn a_drag_cut_short_doesnt_stick() {
    let export = PathBuf::from("/fixture/export.1pux");
    let mut rt = scene("vault");
    rt.drag_files(vec![export.clone()], Some((600.0, 300.0)));
    rt.frame(1.0 / 60.0);
    rt.frame(1.0 / 60.0);
    assert!(rt.state.drop_hovering() && rt.find("drop-zone").is_some());
    rt.key(key(Key::Escape));
    rt.frame(1.0 / 60.0);
    assert!(!rt.state.drop_hovering() && rt.find("drop-zone").is_none());
    rt.drag_files_leave();
    rt.frame(1.0 / 60.0);

    rt.state.installer = Some(Installer::fixture());
    rt.drag_files(vec![export], Some((600.0, 300.0)));
    rt.frame(1.0 / 60.0);
    rt.frame(1.0 / 60.0);
    assert!(rt.state.drop_hovering());
    rt.state.show_installer();
    rt.frame(1.0 / 60.0);
    assert!(!rt.state.drop_hovering());
    // The drag ends over the install page, which takes no drops.
    rt.drag_files_leave();
    rt.frame(1.0 / 60.0);
    rt.state.installer.as_mut().unwrap().close();
    rt.frame(1.0 / 60.0);
    assert!(!rt.state.drop_hovering() && rt.find("drop-zone").is_none());
}

/// ⇧⌘I from the install page leaves it as Close would, so its offer in the
/// vault stays answered; with the page shut, the offer is left alone. From
/// Settings it closes them, unless the shortcut recorder is recording.
#[test]
fn import_passwords_leaves_the_install_page_and_settings() {
    let mut rt = scene("install-command");
    import_passwords(&mut rt);
    let installer = rt.state.installer.as_ref().unwrap();
    assert!(!installer.open && !installer.offering());
    assert!(rt.state.import.open && rt.find("drop-zone").is_some());

    let mut rt = scene("command-offer");
    import_passwords(&mut rt);
    assert!(rt.state.import.open);
    assert!(rt.state.installer.as_ref().unwrap().offering());

    let mut rt = scene("settings");
    rt.state.hotkey.recorder().begin();
    import_passwords(&mut rt);
    assert!(
        rt.state.settings_open && !rt.state.import.open,
        "recording it"
    );
    rt.state.hotkey.recorder().cancel();
    import_passwords(&mut rt);
    assert!(!rt.state.settings_open && rt.state.import.open);

    // Dropping an export while Settings is open leaves Settings for the import view.
    let mut rt = scene("settings");
    assert!(rt.state.settings_open);
    rt.drop_files(
        vec![PathBuf::from("/fixture/export.1pux")],
        Some((600.0, 300.0)),
    );
    rt.frame(1.0 / 60.0);
    assert!(!rt.state.settings_open && rt.state.import.showing());
}

/// A dialog answering after its import was cancelled is ignored; a Choose
/// File… while it's still up takes it over rather than asking for another.
#[test]
fn a_dialog_answers_the_latest_choose_file() {
    let export = PathBuf::from("/fixture/export.1pux");
    let mut rt = scene("empty");
    press(&mut rt, "choose");
    assert!(rt.file_dialog().is_some());
    rt.key(key(Key::Escape));
    rt.frame(1.0 / 60.0);
    assert_eq!(rt.state.import.phase, Phase::Idle);
    rt.resolve_file_dialog(Some(export.clone())).unwrap();
    rt.frame(1.0 / 60.0);
    assert_eq!(rt.state.import.phase, Phase::Idle, "a stale answer");
    assert!(!rt.state.import.open);

    press(&mut rt, "choose");
    rt.key(key(Key::Escape));
    rt.frame(1.0 / 60.0);
    press(&mut rt, "choose");
    assert_eq!(rt.state.import.phase, Phase::Choosing);
    rt.frame(1.0 / 60.0);
    assert_eq!(rt.state.import.error, None, "no second dialog to refuse");
    rt.resolve_file_dialog(Some(export)).unwrap();
    rt.frame(1.0 / 60.0);
    assert!(matches!(rt.state.import.phase, Phase::Reading { .. }));
    assert!(rt.file_dialog().is_none());
}
