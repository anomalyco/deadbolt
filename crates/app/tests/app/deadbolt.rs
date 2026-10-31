//! The `deadbolt` binary the app is built into, for the tests that run it:
//! a real agent (`support`), and the app itself as `deadbolt ui` headless.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// `deadbolt ui`: the app in its own process, taking Rune's flags.
pub fn ui() -> Command {
    let mut command = Command::new(deadbolt());
    command.arg("ui");
    command
}

/// `DEADBOLT_BIN`, else the `deadbolt` cargo already built next to this test
/// (`cargo test --workspace` builds it for the CLI's own tests), else one
/// built here into the test's own target dir, which doesn't wait on the outer
/// build's lock but compiles the CLI from scratch.
pub fn deadbolt() -> PathBuf {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(find_deadbolt).clone()
}

fn find_deadbolt() -> PathBuf {
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
