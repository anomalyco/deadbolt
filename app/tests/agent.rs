//! The app against a real agent in a temporary home: unlock, search, copy,
//! lock. Drives Rune's runtime headless (no window, no GPU) and an in-memory
//! clipboard. Builds the CLI from this repository for the agent.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use deadbolt_app::agent::Agent;
use deadbolt_app::clipboard::Clipboard;
use deadbolt_app::model::{App, Screen};
use deadbolt_client::{Launch, Paths};
use rune::{Env, Key, KeyEvent, Mods, Runtime};

const PASSPHRASE: &str = "correct horse";

/// Builds `deadbolt` and returns its path.
fn deadbolt() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml");
    let out = Command::new(env!("CARGO"))
        .args([
            "build",
            "--quiet",
            "-p",
            "deadbolt-cli",
            "--message-format=json",
            "--manifest-path",
        ])
        .arg(&manifest)
        .stderr(Stdio::inherit())
        .output()
        .expect("running cargo");
    assert!(out.status.success(), "building deadbolt-cli failed");
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter(|l| l.contains("\"executable\"") && l.contains("\"name\":\"deadbolt\""))
        .find_map(|l| {
            let at = l.find("\"executable\":\"")? + "\"executable\":\"".len();
            Some(PathBuf::from(&l[at..at + l[at..].find('"')?]))
        })
        .expect("cargo reported no deadbolt executable")
}

struct Device {
    _dir: tempfile::TempDir,
    bin: PathBuf,
    vars: HashMap<&'static str, OsString>,
}

impl Device {
    fn new() -> Device {
        let dir = tempfile::Builder::new().prefix("db").tempdir().unwrap();
        let path = |name: &str| dir.path().join(name).into_os_string();
        let vars = HashMap::from([
            ("DEADBOLT_HOME", path("home")),
            ("XDG_RUNTIME_DIR", path("run")),
            ("XDG_STATE_HOME", path("state")),
            ("XDG_CONFIG_HOME", path("config")),
            ("DEADBOLT_NET", "local".into()),
            ("DEADBOLT_KDF", "fast".into()),
        ]);
        Device {
            _dir: dir,
            bin: deadbolt(),
            vars,
        }
    }

    fn run(&self, args: &[&str]) {
        let status = Command::new(&self.bin)
            .args(args)
            .envs(&self.vars)
            .env("DEADBOLT_PASSPHRASE", PASSPHRASE)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "deadbolt {args:?} failed");
    }

    fn paths(&self) -> Paths {
        Paths::from_vars(|name| {
            self.vars
                .get(name)
                .cloned()
                .or_else(|| std::env::var_os(name))
        })
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        Command::new(&self.bin)
            .args(["agent", "stop"])
            .envs(&self.vars)
            .stdout(Stdio::null())
            .status()
            .ok();
    }
}

fn key(key: Key) -> KeyEvent {
    KeyEvent {
        key,
        mods: Mods::default(),
    }
}

/// Runs frames until `done` holds, the way a window would between wake-ups.
fn until(rt: &mut Runtime<App>, what: &str, done: impl Fn(&App) -> bool) {
    let start = Instant::now();
    while !done(&rt.state) {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for {what}; screen {:?}",
            rt.state.screen
        );
        rt.frame(1.0 / 60.0);
        std::thread::sleep(Duration::from_millis(5));
    }
    rt.frame(1.0 / 60.0);
}

fn shows(rt: &Runtime<App>, s: &str) -> bool {
    rt.elements().iter().any(|e| e.text.as_deref() == Some(s))
}

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

    let (clipboard, board) = Clipboard::memory();
    let agent = Agent::spawn(
        device.paths(),
        Launch {
            program: device.bin.clone(),
            version: None,
        },
    );
    let mut rt = Runtime::new(
        App::new(agent, clipboard),
        deadbolt_app::view::app,
        (820.0, 540.0),
        Env {
            system_dark: false,
            scale: 1.0,
        },
    );
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
    rt.state.agent.send(deadbolt_app::agent::Job::Connect);

    until(&mut rt, "the locked screen", |s| s.screen == Screen::Locked);
    assert!(shows(&rt, "Deadbolt is locked"));

    // A wrong passphrase stays on the unlock screen and says so.
    for c in "nope".chars() {
        rt.key(key(Key::Text(c.into())));
    }
    rt.frame(1.0 / 60.0);
    assert!(shows(&rt, "••••"), "the field shows dots");
    assert!(
        !rt.elements()
            .iter()
            .any(|e| e.text.as_deref().is_some_and(|t| t.contains("nope")))
    );
    rt.key(key(Key::Enter));
    until(&mut rt, "the unlock error", |s| s.unlock_error.is_some());
    assert_eq!(rt.state.screen, Screen::Locked);

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
    assert_eq!(board.lock().unwrap().as_deref(), Some("flyfly"));
    assert!(shows(&rt, "Password copied"));

    // Shift+Enter copies the username in its place.
    rt.key(KeyEvent {
        key: Key::Enter,
        mods: Mods {
            shift: true,
            ..Mods::default()
        },
    });
    rt.frame(1.0 / 60.0);
    assert_eq!(board.lock().unwrap().as_deref(), Some("ops"));

    // Locking clears our copy off the clipboard and forgets the vault.
    rt.key(KeyEvent {
        key: Key::Command('l'),
        mods: Mods {
            cmd: true,
            ..Mods::default()
        },
    });
    until(&mut rt, "the lock", |s| s.screen == Screen::Locked);
    assert_eq!(*board.lock().unwrap(), None);
    assert!(rt.state.items.is_empty() && rt.state.detail.is_none());
}

#[test]
fn the_clipboard_clears_itself_unless_something_else_was_copied() {
    let (clipboard, board) = Clipboard::memory();
    let mut rt = Runtime::new(
        App::new(Agent::offline(), clipboard),
        deadbolt_app::view::app,
        (820.0, 540.0),
        Env {
            system_dark: false,
            scale: 1.0,
        },
    );
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
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
    assert_eq!(board.lock().unwrap().as_deref(), Some("pw"));
    for _ in 0..(31 * 20) {
        rt.frame(0.05);
    }
    assert_eq!(*board.lock().unwrap(), None, "cleared after 30 s");

    rt.update(|s, tx| s.copy_field("password", tx));
    rt.frame(1.0 / 60.0);
    *board.lock().unwrap() = Some("mine".into());
    for _ in 0..(31 * 20) {
        rt.frame(0.05);
    }
    assert_eq!(
        board.lock().unwrap().as_deref(),
        Some("mine"),
        "a later copy of the user's own survives"
    );
}
