//! A real agent in a temporary home for the app's tests, and running the
//! headless runtime until something shows.

#![allow(dead_code, reason = "each test crate uses some of it")]

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use deadbolt_app::model::App;
use deadbolt_client::{Launch, Paths};
use rune::{Key, KeyEvent, Mods, Runtime};

pub const PASSPHRASE: &str = "correct horse";

/// `DEADBOLT_BIN`, else the `deadbolt` cargo already built next to this test
/// (`cargo test --workspace` builds it for the CLI's own tests), else one
/// built here into the test's own target dir, which doesn't wait on the outer
/// build's lock but compiles the CLI from scratch.
pub fn deadbolt() -> PathBuf {
    if let Some(bin) = std::env::var_os("DEADBOLT_BIN") {
        return bin.into();
    }
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.parent()?.join("deadbolt")));
    if let Some(bin) = sibling.filter(|bin| bin.is_file()) {
        return bin;
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli");
    let out = Command::new(env!("CARGO"))
        .args([
            "build",
            "--quiet",
            "-p",
            "deadbolt-cli",
            "--message-format=json",
        ])
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--target-dir")
        .arg(&target)
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

pub struct Device {
    _dir: tempfile::TempDir,
    bin: PathBuf,
    vars: HashMap<&'static str, OsString>,
}

impl Device {
    pub fn new() -> Device {
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

    /// Production Argon2 instead of the fast test setting: seconds in a debug
    /// build, long enough to act while it runs.
    pub fn with_slow_kdf(mut self) -> Device {
        self.vars.insert("DEADBOLT_KDF", "default".into());
        self
    }

    pub fn run(&self, args: &[&str]) {
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

    pub fn output(&self, args: &[&str]) -> String {
        let out = Command::new(&self.bin)
            .args(args)
            .envs(&self.vars)
            .env("DEADBOLT_PASSPHRASE", PASSPHRASE)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "deadbolt {args:?} failed");
        String::from_utf8(out.stdout).unwrap()
    }

    pub fn spawn(&self, args: &[&str]) -> std::process::Child {
        Command::new(&self.bin)
            .args(args)
            .envs(&self.vars)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    /// How the app starts this device's agent: a script that runs `deadbolt`
    /// with the device's environment, as the app's own would have. The app
    /// checks the agent is that `deadbolt` before sending a passphrase, as
    /// `agent::launch` has it do for the bundle's own.
    pub fn launch(&self) -> Launch {
        let bin = std::fs::canonicalize(&self.bin).unwrap();
        deadbolt_client::set_agent_check(Box::new(move |socket| {
            let helper = bin.with_file_name("deadbolt-enclave");
            deadbolt_client::peer::check(&socket, &helper, &bin)
        }));
        let script = self._dir.path().join("deadbolt");
        let mut body = String::from("#!/bin/sh\nexec env");
        for (name, value) in &self.vars {
            body.push_str(&format!(" {name}='{}'", value.to_string_lossy()));
        }
        body.push_str(&format!(" '{}' \"$@\"\n", self.bin.display()));
        std::fs::write(&script, body).unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        Launch { program: script }
    }

    /// Writes `text` to a file named `name` in the device's temporary dir.
    pub fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self._dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    pub fn paths(&self) -> Paths {
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

pub fn key(key: Key) -> KeyEvent {
    KeyEvent {
        key,
        mods: Mods::default(),
    }
}

/// Runs frames until `done` holds, the way a window would between wake-ups.
pub fn until(rt: &mut Runtime<App>, what: &str, done: impl Fn(&App) -> bool) {
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

pub fn shows(rt: &Runtime<App>, s: &str) -> bool {
    rt.elements().iter().any(|e| e.text.as_deref() == Some(s))
}
