//! Removes what Deadbolt's old SSH agent left behind on machines that ran
//! `deadbolt ssh on`: its `ssh.sock`, the `~/.deadbolt/ssh.sock` link and the
//! login unit it installed. Each start finds nothing to do after the first.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use deadbolt_client::paths::Paths;
use tracing::{info, warn};

pub fn run(paths: &Paths) {
    remove(&paths.socket.with_file_name("ssh.sock"));
    // The link and login unit were only ever made for the default store.
    if std::env::var_os("DEADBOLT_HOME").is_some_and(|h| !h.is_empty()) {
        return;
    }
    let Some(home) = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
    else {
        return;
    };
    let link = home.join(".deadbolt").join("ssh.sock");
    if fs::symlink_metadata(&link).is_ok_and(|m| m.file_type().is_symlink()) {
        remove(&link);
        drop(fs::remove_dir(home.join(".deadbolt")));
    }
    remove_login_unit(&home);
}

#[cfg(target_os = "macos")]
fn remove_login_unit(home: &Path) {
    const LABEL: &str = "pw.deadbolt.agent";
    let plist = home.join(format!("Library/LaunchAgents/{LABEL}.plist"));
    if !plist.exists() {
        return;
    }
    // Booting out the job launchd started this process from would stop it.
    if std::env::var_os("XPC_SERVICE_NAME").is_none_or(|name| name != LABEL) {
        let uid = rustix::process::getuid().as_raw();
        quietly(Command::new("launchctl").args(["bootout", &format!("gui/{uid}/{LABEL}")]));
    }
    remove(&plist);
}

#[cfg(target_os = "linux")]
fn remove_login_unit(home: &Path) {
    const UNIT: &str = "deadbolt-agent.service";
    let unit = home.join(".config/systemd/user").join(UNIT);
    if !unit.exists() {
        return;
    }
    // `disable` without `--now` leaves this process running.
    quietly(Command::new("systemctl").args(["--user", "disable", UNIT]));
    remove(&unit);
    quietly(Command::new("systemctl").args(["--user", "daemon-reload"]));
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn remove_login_unit(_home: &Path) {}

fn quietly(command: &mut Command) {
    drop(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
}

fn remove(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => info!(path = %path.display(), "removed the old SSH agent's file"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => warn!("removing {}: {err}", path.display()),
    }
}
