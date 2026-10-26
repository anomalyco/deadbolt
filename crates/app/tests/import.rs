//! Importing in the app against a real agent: an export dropped on the
//! window or picked with Choose File… is previewed, then imported, cancelled,
//! or forgotten on locking. The exports are made up.

#![cfg(test)]

mod support;

use std::path::PathBuf;

use deadbolt_app::agent::{Agent, Job};
use deadbolt_app::import::Phase;
use deadbolt_app::model::{App, Screen};
use deadbolt_app::onboarding::Severity;
use rune::{Env, FileDialogKind, FileDialogs, Key, KeyEvent, Mods, Runtime, ScriptedFileDialog};

use support::{Device, PASSPHRASE, key, shows, until};

/// A Bitwarden unencrypted JSON export: a login and a card come across; a
/// login without a password and a secure note don't.
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
    { "id": "7b1c", "type": 1, "name": "Nopass", "favorite": false, "login": { "username": "x", "password": null } }
  ]
}"#;

const SECRETS: &[&str] = &[
    "old-pw-111",
    "github-secret-444",
    // The card's label shows its last four, as the CLI's does.
    "4242 4242",
    "42424242",
    "wifi-secret-666",
];

/// The app for a set-up `device`, unlocked in its vault.
fn vault(device: &Device) -> Runtime<App> {
    let mut rt = Runtime::new(
        App::new(Agent::spawn(device.paths(), device.launch())),
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
    rt
}

fn device() -> Device {
    let device = Device::new();
    device.run(&["init", "--device-name", "alpha"]);
    device
}

fn drop_file(rt: &mut Runtime<App>, path: PathBuf) {
    rt.drag_files(vec![path.clone()], Some((600.0, 300.0)));
    rt.frame(1.0 / 60.0);
    assert!(rt.state.import.hover, "the drop zone lights up");
    rt.drop_files(vec![path], Some((600.0, 300.0)));
    rt.frame(1.0 / 60.0);
    assert!(!rt.state.import.hover);
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
    assert!(shows(&rt, "1 new login · 1 card"));
    assert!(shows(
        &rt,
        "Skipped 1 login without password, 1 secure note"
    ));
    assert!(shows(&rt, "Import 2 items"));
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
        s.items.len() == 2 && s.import.phase == Phase::Idle
    });
    assert!(shows(&rt, "Imported 2 from Bitwarden"));
    assert!(!rt.state.import.showing());
    no_secrets(&rt);
    assert_eq!(device.output(&["ls"]).lines().count(), 2);
}

#[test]
fn an_export_already_imported_has_nothing_new() {
    let device = device();
    let file = device.file("export.json", BITWARDEN);
    device.run(&["import", file.to_str().unwrap()]);
    let mut rt = vault(&device);
    until(&mut rt, "the items", |s| s.items.len() == 2);

    // ⇧⌘I opens the import view in a vault with items.
    rt.key(KeyEvent {
        key: Key::Command('i'),
        mods: Mods {
            cmd: true,
            shift: true,
            ..Mods::default()
        },
    });
    rt.frame(1.0 / 60.0);
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
    assert_eq!(rt.state.items.len(), 2);
}

#[test]
fn a_file_that_isnt_an_export_says_so() {
    let device = device();
    let mut rt = vault(&device);

    // Not a file the window takes: no highlight, and dropping does nothing.
    let notes = device.file("notes.txt", "hello");
    rt.drag_files(vec![notes.clone()], Some((600.0, 300.0)));
    rt.frame(1.0 / 60.0);
    assert!(!rt.state.import.hover);
    rt.drop_files(vec![notes], Some((600.0, 300.0)));
    rt.frame(1.0 / 60.0);
    assert_eq!(rt.state.import.phase, Phase::Idle);

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
    rt.state.dialogs = FileDialogs::scripted([
        ScriptedFileDialog {
            kind: FileDialogKind::Open,
            path: None,
        },
        ScriptedFileDialog {
            kind: FileDialogKind::Open,
            path: Some(file),
        },
    ]);

    // Cancelling the dialog leaves the drop zone as it was.
    press(&mut rt, "choose");
    until(&mut rt, "the cancelled dialog", |s| {
        s.import.phase == Phase::Idle
    });
    assert_eq!(rt.state.import.error, None);

    press(&mut rt, "choose");
    until(&mut rt, "the preview", previewing);
    assert!(shows(&rt, "1 new login · 1 card"));
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
    for _ in 0..60 {
        rt.frame(1.0 / 60.0);
    }
    rt
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
