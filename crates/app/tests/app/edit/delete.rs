//! Deleting items, remote deletion conflicts, passkeys, menus and 1Password sync.

use deadbolt_app::agent::{Done, Failure, Job};
use deadbolt_app::edit::Conflict;
use deadbolt_app::model::{App, Screen};
use deadbolt_client::protocol::{ErrorCode, ItemInfo, MirrorAction, MirrorItem, MirrorReport};
use rune::{Key, KeyEvent};

use super::{FRAME, Rig, cmd, failure, info, rig};

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
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_deadbolt-ui"))
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
    assert!(!r.sent().into_iter().any(|j| matches!(j, Job::Get { .. })));
    r.settle(0.5);
    assert!(r.sent().is_empty() && r.rt.state.notice.is_none());
    r.command('s');
    let (_, _, name, fields) = r.take_create();
    assert_eq!(name.as_deref(), Some("github.com"));
    assert!(fields.iter().any(|(name, _)| name == "password"));
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
    assert!(r.rt.state.edit.delete.is_none() && !r.shows("Delete “github.com”?"));

    // In a search with text, ⌘⌫ is the field's.
    r.type_text("git");
    assert_eq!(r.rt.state.search.text, "git");
    backspace(&mut r);
    assert_eq!(r.rt.state.search.text, "");
    assert!(r.rt.state.edit.delete.is_none());

    backspace(&mut r);
    r.sent();
    r.tap(Key::Enter);
    let (seq, id) = r.take_remove();
    assert_eq!(id, github.id);
    assert!(r.shows("Deleting…"));

    // Until the agent answers, the selection, the search and the pane hold.
    r.tap(Key::Down);
    r.type_text("li");
    r.command('n');
    r.command('e');
    backspace(&mut r);
    r.click_row(&next);
    assert_eq!(r.rt.state.selected.as_deref(), Some(github.id.as_str()));
    assert_eq!(r.rt.state.search.text, "");
    assert!(r.rt.state.edit.form.is_none() && r.shows("Deleting…") && r.sent().is_empty());

    r.reply(Done::Removed {
        seq,
        result: Ok(info(&github.id, "login", "github.com")),
    });
    assert!(r.rt.state.edit.delete.is_none());
    assert!(!r.rt.state.items.iter().any(|i| i.id == github.id));
    assert_eq!(r.rt.state.selected.as_deref(), Some(next.as_str()));
}

/// A passkey shows its site, username and date, and can only be deleted.
#[test]
fn a_passkey_shows_its_site_and_is_only_deleted() {
    let mut r = rig("passkey");
    let item = r.rt.state.detail.clone().unwrap();
    assert_eq!(item.kind, "passkey");
    for (label, value) in [
        ("Site", "github.com"),
        ("Username", "thdxr"),
        ("Created", "2026-10-27"),
    ] {
        assert!(r.shows(label) && r.shows(value), "{label}");
    }
    for hidden in [
        "field-credential-id",
        "field-user-handle",
        "field-private-key",
    ] {
        assert!(r.rt.find(hidden).is_none(), "{hidden}");
    }
    let labelled = |label: &str| {
        r.rt.elements()
            .iter()
            .any(|e| !e.exiting && e.label.as_deref() == Some(label))
    };
    assert!(labelled("Copy username") && !labelled("Copy created"));
    assert!(r.rt.find("edit").is_none(), "no Edit button");
    assert!(r.shows("Copy username") && r.rt.find("h-code").is_none());
    r.command('e');
    r.rt.update(|s, _| s.from_menu(App::edit_selected));
    r.settle(0.1);
    assert!(r.rt.state.edit.form.is_none());

    r.press(Key::Backspace, cmd());
    assert!(r.shows("Delete “github.com”?"));
    r.tap(Key::Enter);
    assert_eq!(r.take_remove().1, item.id);
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
        assert!(r.rt.state.edit.form.is_none() && r.rt.state.edit.delete.is_none());
        assert_eq!(r.rt.state.screen, screen, "{scene}: stays");
        assert!(!r.jobs.try_iter().any(|j| matches!(j, Job::Generate { .. })));
    }
}

#[test]
fn a_failed_delete_says_why_in_the_confirm() {
    let mut r = rig("vault");
    r.press(Key::Backspace, cmd());
    r.sent();
    r.tap(Key::Enter);
    let (seq, _) = r.take_remove();
    r.reply(Done::Removed {
        seq,
        result: Err(failure("the vault is read-only")),
    });
    assert!(r.shows("The vault is read-only.") && r.shows("Delete"));
    assert_eq!(r.rt.state.screen, Screen::Vault);
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
    let (early, _) = r.at("delete-confirm").expect("the confirm");
    r.settle(1.0);
    let (rest, opacity) = r.at("delete-confirm").unwrap();
    assert!(early[2] < rest[2] - 40.0, "{} -> {}", early[2], rest[2]);
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
    let (early, fade) = r.at("delete-confirm").expect("the confirm");
    r.settle(1.0);
    let (rest, _) = r.at("delete-confirm").unwrap();
    assert_eq!(early, rest, "nothing grows");
    assert!(fade < 1.0, "it fades in (opacity {fade})");
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
    assert!(shows(&keys, "type-row") && shows(&keys, "type-list"));
    let keys = main_after("vault", serde_json::json!([menu(EDIT)])).unwrap();
    assert!(shows(&keys, "form") && !shows(&keys, "type-row"));
    let keys = main_after("vault", serde_json::json!([menu(DELETE)])).unwrap();
    assert!(shows(&keys, "delete-confirm"));

    let up = serde_json::json!({"t": 0.1, "shortcut": deadbolt_app::shortcut::DEFAULT});
    let keys = main_after("vault", serde_json::json!([up, menu(NEW)])).unwrap();
    assert!(!shows(&keys, "form"), "nothing from the quick panel");
    let keys = main_after("settings", serde_json::json!([menu(NEW)])).unwrap();
    assert!(!shows(&keys, "form"), "nothing over Settings");
}

/// A mirrored item says where it's from, and editing it warns that the
/// next sync puts the source's version back, but still saves.
#[test]
fn a_mirrored_item_warns_on_edit_but_saves() {
    let mut r = rig("vault");
    r.command('e');
    assert!(!r.shows("From 1Password"));
    r.tap(Key::Escape);

    let mut r = rig("mirrored");
    let github = r.github();
    assert!(r.shows("Login · From 1Password"));
    r.command('e');
    assert!(r.shows("From 1Password"));
    r.fill("username", "kit");
    r.sent();
    r.command('s');
    assert_eq!(r.take_save().1, github.id, "the edit saves");
}

#[test]
fn syncing_from_1password_says_what_it_did() {
    let mut r = rig("vault");
    r.sent();
    r.rt.update(|s, _| {
        s.sync_one_password();
        s.sync_one_password();
    });
    assert!(matches!(r.sent()[..], [Job::SyncOnePassword { seq: 1 }]));
    assert!(r.rt.state.mirror.syncing);
    let item = |action| MirrorItem {
        action,
        title: "github.com".into(),
        reason: None,
    };
    let report = MirrorReport {
        applied: true,
        unchanged: 3,
        items: vec![
            item(MirrorAction::Update),
            item(MirrorAction::Add),
            item(MirrorAction::Skip),
        ],
        warnings: Vec::new(),
        dropped: Vec::new(),
    };
    r.reply(Done::Mirrored {
        seq: 1,
        result: Ok(report),
    });
    assert!(!r.rt.state.mirror.syncing);
    assert_eq!(
        r.rt.state.mirror.result,
        Some(Ok("1 updated, 1 added".into()))
    );

    r.rt.update(|s, _| s.sync_one_password());
    r.reply(Done::Mirrored {
        seq: 2,
        result: Err(failure("1Password is locked")),
    });
    assert_eq!(
        r.rt.state.mirror.result,
        Some(Err("1Password is locked".into()))
    );
    r.rt.update(|s, _| s.close_settings());
    assert_eq!(r.rt.state.mirror.result, None);

    // Deadbolt locked meanwhile: the window locks too.
    r.rt.update(|s, _| s.sync_one_password());
    r.reply(Done::Mirrored {
        seq: 3,
        result: Err(Failure {
            code: Some(ErrorCode::Locked),
            message: "locked".into(),
        }),
    });
    assert_eq!(r.rt.state.screen, Screen::Locked);
}

#[test]
fn a_sync_from_1password_ends_with_the_lock() {
    let report = || MirrorReport {
        applied: true,
        unchanged: 3,
        items: Vec::new(),
        warnings: Vec::new(),
        dropped: Vec::new(),
    };
    let mut r = rig("vault");
    r.rt.update(|s, _| s.sync_one_password());
    r.reply(Done::Mirrored {
        seq: 1,
        result: Ok(report()),
    });
    assert!(r.rt.state.mirror.result.is_some());
    r.rt.update(|s, _| s.sync_one_password());
    r.command('l');
    r.reply(Done::Locked(Ok(())));
    assert!(!r.rt.state.mirror.syncing && r.rt.state.mirror.result.is_none());

    // Its reply comes once another has started (after an unlock): it is
    // not the new sync's.
    r.rt.update(|s, _| s.sync_one_password());
    r.reply(Done::Mirrored {
        seq: 2,
        result: Ok(report()),
    });
    assert!(r.rt.state.mirror.syncing && r.rt.state.mirror.result.is_none());
    r.reply(Done::Mirrored {
        seq: 4,
        result: Ok(report()),
    });
    assert_eq!(r.rt.state.mirror.result, Some(Ok("Up to date".into())));
}
