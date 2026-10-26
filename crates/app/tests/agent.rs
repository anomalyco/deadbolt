//! The app against a real agent in a temporary home: first run (create, and
//! join between two agents), unlock, search, copy, lock. Drives Rune's
//! runtime headless (no window, no GPU) and an in-memory clipboard. Builds
//! the CLI from this repository for the agent.

#![cfg(test)]

mod support;

use std::time::{Duration, Instant};

use deadbolt_app::agent::{Agent, Job};
use deadbolt_app::model::{App, Screen};
use deadbolt_app::onboarding::worker::{ALREADY_SET_UP, NewDevice, Progress, Stage, Worker};
use deadbolt_app::onboarding::{Flow, Severity, Step};
use rune::{Env, Key, KeyEvent, Mods, Runtime};

use support::{Device, PASSPHRASE, key, shows, until};

#[test]
fn unlock_search_copy_lock() {
    let device = Device::new();
    device.run(&["init"]);
    device.run(&[
        "new",
        "login",
        "username=dax",
        "url=github.com",
        "password=hunter22",
    ]);
    device.run(&[
        "new",
        "login",
        "username=ops",
        "url=fly.io",
        "password=flyfly",
    ]);
    device.run(&["lock"]);

    let board = rune::clipboard::memory();
    let agent = Agent::spawn(device.paths(), device.launch());
    let mut rt = Runtime::new(
        App::new(agent),
        deadbolt_app::view::app,
        (820.0, 540.0),
        Env {
            system_dark: false,
            scale: 1.0,
        },
    );
    rt.use_clipboard(&board);
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
    rt.state.agent.send(deadbolt_app::agent::Job::Connect);

    until(&mut rt, "the locked screen", |s| s.screen == Screen::Locked);
    assert!(shows(&rt, "Deadbolt"));

    // A wrong passphrase stays on the unlock screen and says so.
    for c in "nope".chars() {
        rt.key(key(Key::Text(c.into())));
    }
    rt.frame(1.0 / 60.0);
    assert!(rt.has_secure_focus(), "a secure field takes it");
    assert!(
        !rt.elements()
            .iter()
            .any(|e| e.text.as_deref().is_some_and(|t| t.contains("nope")))
    );
    rt.key(key(Key::Enter));
    until(&mut rt, "the unlock error", |s| s.unlock_error.is_some());
    assert_eq!(rt.state.screen, Screen::Locked);

    // Typing clears the error; the agent stopping meanwhile is no obstacle.
    device.run(&["agent", "stop"]);
    rt.key(key(Key::Text(PASSPHRASE[..1].into())));
    rt.frame(1.0 / 60.0);
    assert_eq!(rt.state.unlock_error, None);
    rt.key(key(Key::Backspace));
    for c in PASSPHRASE.chars() {
        rt.key(key(Key::Text(c.into())));
    }
    rt.key(key(Key::Enter));
    until(&mut rt, "the vault", |s| {
        s.screen == Screen::Vault && s.loaded && s.detail.is_some()
    });
    assert!(shows(&rt, "github.com") && shows(&rt, "fly.io"));

    // Typing filters; the first match is selected and its fields load.
    for c in "fly".chars() {
        rt.key(key(Key::Text(c.into())));
    }
    until(&mut rt, "fly.io's fields", |s| {
        s.detail.as_ref().is_some_and(|d| d.label == "fly.io")
    });
    let visible: Vec<&str> = rt
        .state
        .visible()
        .iter()
        .map(|i| i.label.as_str())
        .collect();
    assert_eq!(visible, ["fly.io"]);

    // Enter copies the password and starts the countdown.
    rt.key(key(Key::Enter));
    rt.frame(1.0 / 60.0);
    assert_eq!(text(&board).as_deref(), Some("flyfly"));
    assert!(shows(&rt, "Copied, clears in 0:30"));

    // Shift+Enter copies the username in its place.
    rt.key(KeyEvent {
        key: Key::Enter,
        mods: Mods {
            shift: true,
            ..Mods::default()
        },
    });
    rt.frame(1.0 / 60.0);
    assert_eq!(text(&board).as_deref(), Some("ops"));

    // Escape, in the focused search field, clears the search; ↓ then moves
    // the selection to the next item.
    rt.key(key(Key::Escape));
    rt.frame(1.0 / 60.0);
    assert_eq!(rt.state.search.text, "");
    assert_eq!(rt.state.visible().len(), 2);
    let first = rt.state.selected.clone();
    rt.key(key(Key::Down));
    rt.frame(1.0 / 60.0);
    assert_ne!(rt.state.selected, first, "↓ moves the selection");

    // Locking clears our copy off the clipboard and forgets the vault.
    rt.key(KeyEvent {
        key: Key::Command('l'),
        mods: Mods {
            cmd: true,
            ..Mods::default()
        },
    });
    until(&mut rt, "the lock", |s| s.screen == Screen::Locked);
    assert_eq!(text(&board), None);
    assert!(rt.state.items.is_empty() && rt.state.detail.is_none());
}

/// The quick panel on its own agent connection: summoned locked, it unlocks
/// in place, filters, copies with ⏎ and closes itself.
#[test]
fn quick_panel_unlock_filter_copy() {
    use deadbolt_app::panel::Phase;
    let device = Device::new();
    device.run(&["init"]);
    device.run(&[
        "new",
        "login",
        "username=dax",
        "url=github.com",
        "password=hunter22",
    ]);
    device.run(&[
        "new",
        "login",
        "username=ops",
        "url=fly.io",
        "password=flyfly",
    ]);
    device.run(&["lock"]);

    let board = rune::clipboard::memory();
    let agent = Agent::spawn(device.paths(), device.launch());
    let mut rt = Runtime::new(
        App::panel(agent),
        deadbolt_app::panel::view::panel,
        deadbolt_app::panel::SIZE,
        Env {
            system_dark: true,
            scale: 1.0,
        },
    );
    rt.use_clipboard(&board);
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.on_key = Some(|s, ev, tx| s.panel_key(ev, tx));
    rt.update(|s, tx| s.summon(tx));

    until(&mut rt, "the locked panel", |s| s.screen == Screen::Locked);
    assert!(shows(&rt, "Unlock Deadbolt"));
    type_text(&mut rt, PASSPHRASE);
    rt.key(key(Key::Enter));
    until(&mut rt, "the vault in the panel", |s| {
        s.screen == Screen::Vault && s.loaded && s.detail.is_some()
    });
    assert!(rt.state.search.focused, "the search takes the keys");

    type_text(&mut rt, "fly");
    until(&mut rt, "fly.io's fields", |s| {
        s.detail.as_ref().is_some_and(|d| d.label == "fly.io")
    });
    let visible: Vec<&str> = rt
        .state
        .visible()
        .iter()
        .map(|i| i.label.as_str())
        .collect();
    assert_eq!(visible, ["fly.io"]);
    assert!(shows(&rt, "fly.io"));

    rt.key(key(Key::Enter));
    rt.frame(1.0 / 60.0);
    assert_eq!(text(&board).as_deref(), Some("flyfly"));
    assert!(matches!(rt.state.panel_phase(), Some(Phase::Copied { .. })));
    until(&mut rt, "the panel to close", |s| {
        s.panel_phase() == Some(Phase::Hidden)
    });
    assert_eq!(
        text(&board).as_deref(),
        Some("flyfly"),
        "closing keeps the copy until it clears"
    );

    // Opened again: an empty search over both items, ready for ⇧⏎.
    rt.update(|s, tx| s.summon(tx));
    until(&mut rt, "the first item's fields", |s| s.detail.is_some());
    assert_eq!(rt.state.search.text, "");
    assert_eq!(rt.state.visible().len(), 2);
    rt.key(KeyEvent {
        key: Key::Enter,
        mods: Mods {
            shift: true,
            ..Mods::default()
        },
    });
    rt.frame(1.0 / 60.0);
    assert_eq!(text(&board).as_deref(), Some("ops"));
}

#[test]
fn the_clipboard_clears_itself_unless_something_else_was_copied() {
    let board = rune::clipboard::memory();
    let mut rt = Runtime::new(
        App::new(Agent::offline()),
        deadbolt_app::view::app,
        (820.0, 540.0),
        Env {
            system_dark: false,
            scale: 1.0,
        },
    );
    rt.use_clipboard(&board);
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.state.clear_after = 1.0;
    // The "copied" scene's state, by hand: a vault with one item's fields.
    rt.state.screen = Screen::Vault;
    rt.state.detail = Some(deadbolt_client::protocol::ItemInfo {
        id: "a".into(),
        short: "a".into(),
        kind: "login".into(),
        label: "x".into(),
        detail: None,
        fields: vec![deadbolt_client::protocol::FieldInfo {
            name: "password".into(),
            kind: "secret".into(),
            value: "pw".into(),
        }],
    });
    rt.frame(0.0);
    rt.update(|s, tx| s.copy_field("password", tx));
    rt.frame(1.0 / 60.0);
    assert_eq!(text(&board).as_deref(), Some("pw"));
    for _ in 0..25 {
        rt.frame(0.05);
    }
    assert_eq!(text(&board), None, "cleared after a second");

    rt.update(|s, tx| s.copy_field("password", tx));
    rt.frame(1.0 / 60.0);
    board.set_text("mine");
    for _ in 0..25 {
        rt.frame(0.05);
    }
    assert_eq!(
        text(&board).as_deref(),
        Some("mine"),
        "a later copy of the user's own survives"
    );
}

/// The app for `device`, as `run` builds it, before it connects.
fn app(device: &Device) -> Runtime<App> {
    let mut app = App::new(Agent::spawn(device.paths(), device.launch()));
    app.onboarding.worker = Worker::new(device.paths(), device.launch());
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
    rt.state.agent.send(Job::Connect);
    rt
}

fn text(board: &rune::clipboard::MemoryClipboard) -> Option<String> {
    board.text().map(|t| t.as_str().to_owned())
}

fn type_text(rt: &mut Runtime<App>, text: &str) {
    for c in text.chars() {
        rt.key(key(Key::Text(c.into())));
    }
    rt.frame(1.0 / 60.0);
}

/// Picks `flow` on the welcome screen and fills the form for a new device.
fn fill_form(rt: &mut Runtime<App>, flow: Flow, name: &str) {
    until(rt, "the welcome screen", |s| s.screen == Screen::Onboarding);
    assert!(shows(rt, "Deadbolt"));
    rt.update(|s, _| s.choose(flow));
    rt.update(|s, _| s.onboarding.device = rune::TextEdit::new(name));
    rt.frame(1.0 / 60.0);
    type_text(rt, PASSPHRASE);
    rt.key(key(Key::Enter));
    rt.frame(1.0 / 60.0);
    type_text(rt, PASSPHRASE);
    assert!(
        !rt.elements()
            .iter()
            .any(|e| e.text.as_deref().is_some_and(|t| t.contains(PASSPHRASE))),
        "the passphrase never shows"
    );
    rt.key(key(Key::Enter));
}

#[test]
fn create_a_vault_in_the_app() {
    let device = Device::new();
    let mut rt = app(&device);
    fill_form(&mut rt, Flow::Create, "alpha");
    until(&mut rt, "creating", |s| {
        matches!(s.onboarding.step, Step::Working(_) | Step::Done { .. })
    });
    until(&mut rt, "the moment", |s| {
        matches!(s.onboarding.step, Step::Done { .. })
    });
    assert!(shows(&rt, "Vault created"));
    until(&mut rt, "the empty vault", |s| {
        s.screen == Screen::Vault && s.loaded
    });
    assert!(rt.state.items.is_empty());
    assert!(rt.state.onboarding.passphrase.text.is_empty(), "wiped");
    until(&mut rt, "the vault's name", |s| {
        s.status.as_ref().is_some_and(|st| !st.vaults.is_empty())
    });
    assert!(shows(&rt, "personal is empty"));
    // The CLI sees the device and vault the app made.
    assert!(device.output(&["vault", "ls"]).contains("personal"));
    assert!(device.output(&["status"]).contains("alpha"));
}

/// Shows a ticket on `device`'s app and pairs it from `inviter`; returns the
/// inviter's `deadbolt pair` once the code is up.
fn pair_to_code(rt: &mut Runtime<App>, inviter: &Device, form: bool) -> std::process::Child {
    if form {
        fill_form(rt, Flow::Join, "beta");
    } else {
        rt.update(|s, _| s.submit_join());
    }
    until(rt, "the ticket", |s| s.onboarding.ticket.is_some());
    assert!(shows(rt, "Pair from your other device"));
    let ticket = rt.state.onboarding.ticket.as_ref().unwrap().text.clone();
    let pair = inviter.spawn(&["pair", &ticket, "--yes"]);
    until(rt, "the code", |s| {
        matches!(s.onboarding.step, Step::Confirm { .. })
    });
    let Step::Confirm { code, vault, .. } = &rt.state.onboarding.step else {
        unreachable!()
    };
    assert!(code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(vault, "personal");
    pair
}

#[test]
fn join_from_another_device_in_the_app() {
    let inviter = Device::new();
    inviter.run(&["init"]);
    inviter.run(&[
        "new",
        "login",
        "username=dax",
        "url=github.com",
        "password=hunter22",
    ]);
    let device = Device::new();
    let mut rt = app(&device);
    let mut pair = pair_to_code(&mut rt, &inviter, true);
    rt.update(|s, _| s.answer_code(true));
    until(&mut rt, "joined", |s| {
        matches!(s.onboarding.step, Step::Done { .. })
    });
    assert!(shows(&rt, "Joined personal"));
    until(&mut rt, "the synced vault", |s| {
        s.screen == Screen::Vault && s.items.len() == 1
    });
    assert_eq!(rt.state.items[0].label, "github.com");
    assert!(
        pair.wait().unwrap().success(),
        "the inviter added this device"
    );
}

#[test]
fn declining_or_cancelling_a_join_keeps_the_device_set_up() {
    let inviter = Device::new();
    inviter.run(&["init"]);
    let device = Device::new();
    let mut rt = app(&device);

    // The codes "don't match": nothing is shared and both sides stop.
    let mut pair = pair_to_code(&mut rt, &inviter, true);
    rt.update(|s, _| s.answer_code(false));
    until(&mut rt, "the caution notice", |s| {
        s.onboarding.step == Step::Join && s.onboarding.notice.is_some()
    });
    let notice = rt.state.onboarding.notice.clone().unwrap();
    assert_eq!(notice.severity, Severity::Caution, "{notice:?}");
    assert!(!pair.wait().unwrap().success(), "the inviter stopped too");
    until(&mut rt, "the device set up", |s| s.onboarding.device_ready);

    // A second try needs no passphrase; cancelling it hangs up.
    rt.update(|s, _| s.submit_join());
    until(&mut rt, "the ticket", |s| s.onboarding.ticket.is_some());
    rt.key(key(Key::Escape));
    until(&mut rt, "the neutral notice", |s| {
        s.onboarding.step == Step::Join
            && s.onboarding
                .notice
                .as_ref()
                .is_some_and(|n| n.severity == Severity::Neutral)
    });
    assert!(shows(&rt, "Join cancelled"));
    assert!(rt.state.onboarding.ticket.is_none());
    assert!(device.output(&["vault", "ls"]).trim().is_empty());
}

#[test]
fn cancelling_a_join_during_setup_waits_for_it() {
    let device = Device::new().with_slow_kdf();
    let mut rt = app(&device);
    fill_form(&mut rt, Flow::Join, "beta");
    until(&mut rt, "the slow setup", |s| {
        s.onboarding.stage == Some(Stage::Protecting)
    });
    rt.key(key(Key::Escape));
    rt.frame(1.0 / 60.0);
    assert_eq!(
        rt.state.onboarding.step,
        Step::Working(Flow::Join),
        "it waits for the setup the agent is running"
    );
    until(&mut rt, "the neutral notice", |s| {
        s.onboarding.step == Step::Join && s.onboarding.notice.is_some()
    });
    let o = &rt.state.onboarding;
    // The form matches the agent: set up, so no passphrase to type again
    // (one typed now would never be used).
    assert!(o.device_ready, "the form still asks for a passphrase");
    let notice = o.notice.clone().unwrap();
    assert_eq!(notice.severity, Severity::Neutral, "{notice:?}");
    assert!(notice.body.contains("set up now"), "{notice:?}");
    assert!(o.ticket.is_none(), "no ticket after the cancel");
    assert!(device.output(&["status"]).contains("beta"));
}

/// Runs `worker` until it reports the end of its request, collecting what it said.
fn finish(worker: &mut Worker) -> Vec<Progress> {
    let start = Instant::now();
    let mut seen = Vec::new();
    loop {
        let (progress, _) = worker.drain(0.0);
        for p in progress {
            let end = matches!(p, Progress::Created(_) | Progress::Joined(_));
            seen.push(p);
            if end {
                return seen;
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out: {seen:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_device_set_up_meanwhile_refuses_the_new_passphrase() {
    let device = Device::new();
    // Set up behind the screen's back, after it showed the form.
    device.run(&["init"]);
    let new_device = || {
        Some(NewDevice {
            name: "beta".into(),
            passphrase: zeroize::Zeroizing::new("another passphrase".into()),
        })
    };
    let mut worker = Worker::new(device.paths(), device.launch());
    worker.create(new_device(), "work".into());
    let seen = finish(&mut worker);
    assert!(
        matches!(seen.last(), Some(Progress::Created(Err(f))) if f.message == ALREADY_SET_UP),
        "{seen:?}"
    );
    worker.join(new_device());
    let seen = finish(&mut worker);
    assert!(
        matches!(seen.last(), Some(Progress::Joined(Err(f))) if f.message == ALREADY_SET_UP),
        "{seen:?}"
    );
    assert!(!seen.iter().any(|p| matches!(p, Progress::Ticket(_))));
    assert!(!device.output(&["vault", "ls"]).contains("work"));
    // The passphrase it was set up with still unlocks it.
    device.run(&["lock"]);
    device.run(&["unlock"]);
}

/// The app follows the agent with no input of its own: items written
/// elsewhere appear, locks and unlocks from the CLI carry over, and a
/// restarted agent is found again.
#[test]
fn the_app_follows_the_agent() {
    let device = Device::new();
    device.run(&["init"]);
    device.run(&[
        "new",
        "login",
        "username=dax",
        "url=github.com",
        "password=hunter22",
    ]);
    let mut rt = app(&device);
    until(&mut rt, "the vault", |s| {
        s.screen == Screen::Vault && s.loaded && s.detail.is_some()
    });
    let selected = rt.state.selected.clone();

    device.run(&[
        "new",
        "login",
        "username=ops",
        "url=fly.io",
        "password=flyfly",
    ]);
    until(&mut rt, "the new item", |s| s.items.len() == 2);
    assert!(shows(&rt, "fly.io"));
    assert_eq!(rt.state.selected, selected, "the selection stays");
    assert!(rt.state.detail.is_some(), "the selected item stays shown");

    device.run(&["lock"]);
    until(&mut rt, "the lock", |s| s.screen == Screen::Locked);
    assert!(rt.state.items.is_empty() && rt.state.detail.is_none());

    device.run(&["unlock"]);
    until(&mut rt, "the vault again", |s| {
        s.screen == Screen::Vault && s.items.len() == 2
    });

    device.run(&["agent", "stop"]);
    until(&mut rt, "the lock when the agent stops", |s| {
        s.screen == Screen::Locked
    });

    // A new agent, unlocked from the CLI: the app finds it on its own.
    device.run(&["unlock"]);
    until(&mut rt, "the vault from the new agent", |s| {
        s.screen == Screen::Vault && s.items.len() == 2
    });
}

/// The selected item deleted from the CLI: the next one replaces it in the
/// frame the list lands, and nothing of the old item, its revealed password
/// least of all, fades out under the new title.
#[test]
fn a_deleted_selection_goes_at_once() {
    let device = Device::new();
    device.run(&["init"]);
    for (url, user, password) in [
        ("github.com", "dax", "hunter22"),
        ("fly.io", "ops", "flyfly"),
    ] {
        let (url, user, password) = (
            format!("url={url}"),
            format!("username={user}"),
            format!("password={password}"),
        );
        device.run(&["new", "login", &user, &url, &password]);
    }
    let mut rt = app(&device);
    until(&mut rt, "the vault", |s| {
        s.screen == Screen::Vault && s.items.len() == 2 && s.detail.is_some()
    });
    assert_eq!(rt.state.selected_item().unwrap().label, "fly.io");
    rt.update(|s, _| s.revealed.push("password".into()));
    for _ in 0..30 {
        rt.frame(1.0 / 60.0);
    }
    assert!(shows(&rt, "flyfly"), "the password shows");

    device.run(&["rm", "fly.io"]);
    let start = Instant::now();
    while rt.state.items.len() == 2 {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "the delete lands"
        );
        rt.frame(1.0 / 60.0);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(rt.state.selected_item().unwrap().label, "github.com");
    let elements = rt.elements();
    let old: Vec<_> = elements
        .iter()
        .filter(|e| {
            let field = e.key.as_deref().is_some_and(|k| k.starts_with("field-"));
            let text = e.text.as_deref();
            (field && e.opacity < 1.0) || matches!(text, Some("flyfly" | "ops" | "fly.io"))
        })
        .map(|e| (e.key.clone(), e.text.clone(), e.opacity))
        .collect();
    assert!(old.is_empty(), "the old item lingers: {old:?}");
}
