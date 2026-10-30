//! The app against a real agent in a temporary home: first run (create, and
//! join between two agents), unlock, search, copy, lock. Drives Rune's
//! runtime headless (no window, no GPU) and an in-memory clipboard. Builds
//! the CLI from this repository for the agent.

// The agent reads the test switches these set (`DEADBOLT_NET`,
// `DEADBOLT_KDF`, `DEADBOLT_TEST_*`) only in a debug build.
#![cfg(debug_assertions)]

use std::time::{Duration, Instant};

use deadbolt_app::agent::{Agent, Job, Window};
use deadbolt_app::model::{App, Screen};
use deadbolt_app::onboarding::worker::{ALREADY_SET_UP, NewDevice, Progress, Stage, Worker};
use deadbolt_app::onboarding::{Flow, Step};
use deadbolt_app::view::Severity;
use rune::{Env, Key, KeyEvent, Mods, Runtime};

use crate::support::{Device, PASSPHRASE, key, shows, until};

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
    let agent = Agent::spawn(device.paths(), device.launch(), Window::Main);
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
    let agent = Agent::spawn(device.paths(), device.launch(), Window::Panel);
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

/// Another launch (`deadbolt app`, `app-activate`) reaches the main window's
/// watch, never the quick panel's, and bringing the window forward leaves
/// what it shows as it was. Headless runs drop window requests, so the
/// focus itself isn't seen here.
#[test]
fn a_second_launch_reaches_the_main_window_not_the_panel() {
    use deadbolt_client::protocol::{Command, Reply};

    let device = Device::new();
    device.run(&["init"]);
    device.run(&["lock"]);
    let paths = device.paths();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let activate = |token: &str| {
        let command = Command::AppActivate {
            token: Some(token.into()),
        };
        runtime
            .block_on(deadbolt_client::simple(&paths, command))
            .unwrap()
    };

    let mut panel = Runtime::new(
        App::panel(Agent::spawn(paths.clone(), device.launch(), Window::Panel)),
        deadbolt_app::panel::view::panel,
        deadbolt_app::panel::SIZE,
        Env {
            system_dark: true,
            scale: 1.0,
        },
    );
    panel.poll = Some(|s, now, tx| s.poll(now, tx));
    panel.update(|s, tx| s.summon(tx));
    until(&mut panel, "the locked panel", |s| {
        s.screen == Screen::Locked
    });
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        matches!(activate("first"), Reply::NoApp),
        "the panel's watch isn't the app's"
    );

    // The main window opens meanwhile; the next launch brings it forward.
    let main = rune::App::new(deadbolt_app::spec());
    let quick = rune::App::new(deadbolt_app::panel::spec());
    let mut rt = Runtime::new(
        App::new(Agent::spawn(paths.clone(), device.launch(), Window::Main)),
        deadbolt_app::view::app,
        (820.0, 540.0),
        Env {
            system_dark: true,
            scale: 1.0,
        },
    );
    rt.state.windows = Some(deadbolt_app::panel::window::Windows::new(
        main.handle(),
        quick.handle(),
    ));
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
    rt.state.agent.send(Job::Connect);
    until(&mut rt, "the locked screen", |s| s.screen == Screen::Locked);
    assert!(matches!(activate("second"), Reply::Activated));
    for _ in 0..30 {
        rt.frame(1.0 / 60.0);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(rt.state.screen, Screen::Locked);
    assert!(rt.has_secure_focus(), "the passphrase field keeps the keys");
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
        source: None,
        favorite: false,
        tags: Vec::new(),
        deleted_at: None,
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
    let mut app = App::new(Agent::spawn(device.paths(), device.launch(), Window::Main));
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

/// Shows a code on `device`'s app and pairs it from `inviter`; returns the
/// inviter's `deadbolt pair`.
fn pair_from(rt: &mut Runtime<App>, inviter: &Device, form: bool) -> std::process::Child {
    if form {
        fill_form(rt, Flow::Join, "beta");
    } else {
        rt.update(|s, _| s.submit_join());
    }
    until(rt, "the code", |s| s.onboarding.code.is_some());
    assert!(shows(rt, "Pair from your other device"));
    let code = rt.state.onboarding.code.as_ref().unwrap().clone();
    assert_eq!(code.split('-').count(), 4, "{}", code.as_str());
    assert!(shows(rt, &format!("deadbolt pair {}", code.as_str())));
    inviter.spawn(&["pair", &code])
}

#[test]
fn join_from_another_device_in_the_app() {
    let inviter = Device::new();
    inviter.run(&["init", "--device-name", "studio"]);
    inviter.run(&[
        "new",
        "login",
        "username=dax",
        "url=github.com",
        "password=hunter22",
    ]);
    let device = Device::new();
    let mut rt = app(&device);
    let mut pair = pair_from(&mut rt, &inviter, true);
    until(&mut rt, "joined", |s| {
        matches!(s.onboarding.step, Step::Done { .. })
    });
    assert!(shows(&rt, "Joined personal"));
    assert!(
        matches!(&rt.state.onboarding.step, Step::Done { from: Some(from), .. } if from == "studio"),
        "{:?}",
        rt.state.onboarding.step
    );
    assert!(rt.state.onboarding.code.is_none(), "the code is wiped");
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
fn cancelling_a_join_keeps_the_device_set_up_and_ends_the_code() {
    let inviter = Device::new();
    inviter.run(&["init"]);
    let device = Device::new();
    let mut rt = app(&device);
    for form in [true, false] {
        // The second try needs no passphrase.
        if form {
            fill_form(&mut rt, Flow::Join, "beta");
        } else {
            rt.update(|s, _| s.submit_join());
        }
        until(&mut rt, "the code", |s| s.onboarding.code.is_some());
        let code = rt.state.onboarding.code.as_ref().unwrap().clone();
        rt.key(key(Key::Escape));
        until(&mut rt, "the neutral notice", |s| {
            s.onboarding.step == Step::Join
                && s.onboarding
                    .notice
                    .as_ref()
                    .is_some_and(|n| n.severity == Severity::Neutral)
        });
        assert!(shows(&rt, "Join cancelled"));
        assert!(rt.state.onboarding.code.is_none());
        until(&mut rt, "the device set up", |s| s.onboarding.device_ready);
        // The cancelled code no longer works.
        let mut pair =
            inviter.spawn_with(&["pair", &code], &[("DEADBOLT_TEST_PAIR_FIND_SECS", "2")]);
        assert!(!pair.wait().unwrap().success());
    }
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
    assert!(o.code.is_none(), "no code after the cancel");
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
    assert!(!seen.iter().any(|p| matches!(p, Progress::Code(_))));
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
    // Shown as a secure label, so never as text.
    let value = rt
        .elements()
        .into_iter()
        .find(|e| e.path.ends_with("field-password/value"))
        .expect("the password shows");
    assert!(rt.element_is_secure(&value.path), "a secure label");
    assert_eq!((value.role, value.text), ("text", None));
    assert!(!shows(&rt, "flyfly"));

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

/// The open form's field `name`.
fn form_value(s: &App, name: &str) -> String {
    let form = s.edit.form.as_ref().expect("a form");
    let input = form.fields.iter().find(|f| f.name == name).unwrap();
    input.edit.text.to_string()
}

fn fill(rt: &mut Runtime<App>, name: &str, value: &str) {
    rt.update(|s, _| {
        let form = s.edit.form.as_mut().expect("a form");
        let input = form.fields.iter_mut().find(|f| f.name == name).unwrap();
        input.edit.replace_text(value);
        s.form_changed();
    });
    rt.frame(1.0 / 60.0);
}

fn command(c: char) -> KeyEvent {
    KeyEvent {
        key: Key::Command(c),
        mods: Mods {
            cmd: true,
            ..Mods::default()
        },
    }
}

/// Adding, changing and deleting against a real agent: ⌘N with the agent's
/// generated password, an edit that changes one field and empties another,
/// and a delete, each as the CLI then sees it.
#[test]
fn add_edit_and_delete_items() {
    let device = Device::new();
    device.run(&["init"]);
    device.run(&[
        "new",
        "login",
        "username=dax",
        "url=github.com",
        "password=hunter22",
    ]);
    let agent = Agent::spawn(device.paths(), device.launch(), Window::Main);
    let mut rt = Runtime::new(
        App::new(agent),
        deadbolt_app::view::app,
        (820.0, 540.0),
        Env {
            system_dark: false,
            scale: 1.0,
        },
    );
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
    rt.state.agent.send(Job::Connect);
    until(&mut rt, "the vault", |s| {
        s.screen == Screen::Vault && s.loaded && s.detail.is_some()
    });

    // ⌘N: a new login, its password from the agent's generator.
    rt.key(command('n'));
    until(&mut rt, "a generated password", |s| {
        s.editing() && !form_value(s, "password").is_empty()
    });
    let password = form_value(&rt.state, "password");
    assert_eq!(password.chars().count(), 24);
    // ⏎ in the type list keeps Login and puts the name in focus.
    rt.key(key(Key::Enter));
    for c in "Linear".chars() {
        rt.key(key(Key::Text(c.into())));
    }
    fill(&mut rt, "username", "kit");
    rt.key(command('s'));
    until(&mut rt, "the new login, selected", |s| {
        !s.editing()
            && s.selected_item().is_some_and(|i| i.label == "Linear")
            && s.detail.as_ref().is_some_and(|d| d.label == "Linear")
    });
    assert_eq!(rt.state.items.len(), 2);
    assert_eq!(device.output(&["get", "Linear"]).trim(), password);
    assert_eq!(
        device.output(&["get", "-f", "username", "Linear"]).trim(),
        "kit"
    );

    // ⌘E: a new URL, the username emptied, saved as one change.
    rt.key(command('e'));
    rt.frame(1.0 / 60.0);
    assert_eq!(form_value(&rt.state, "username"), "kit");
    fill(&mut rt, "username", "");
    fill(&mut rt, "url", "linear.app");
    rt.key(command('s'));
    until(&mut rt, "the edit, saved", |s| {
        !s.editing()
            && s.detail.as_ref().is_some_and(|d| {
                d.fields.iter().any(|f| f.value == "https://linear.app")
                    && !d.fields.iter().any(|f| f.name == "username")
            })
    });
    assert_eq!(
        device.output(&["get", "-f", "url", "Linear"]).trim(),
        "https://linear.app"
    );
    assert_eq!(device.output(&["get", "Linear"]).trim(), password);

    // ⌘⌫ asks; ⏎ deletes, and github.com takes its place.
    rt.key(KeyEvent {
        key: Key::Backspace,
        mods: Mods {
            cmd: true,
            ..Mods::default()
        },
    });
    rt.frame(1.0 / 60.0);
    assert!(shows(&rt, "Delete “Linear”?"));
    rt.key(key(Key::Enter));
    until(&mut rt, "the delete", |s| {
        s.items.len() == 1 && s.detail.as_ref().is_some_and(|d| d.label == "github.com")
    });
    assert!(!device.output(&["ls"]).contains("Linear"));
}
