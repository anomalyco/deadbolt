//! The daemon's old name. Older builds called it the agent, at `agent.sock`
//! and `agent.lock` beside ours, and run it as `deadbolt agent`.
//!
//! A process of the old name still running holds the store open, so a new
//! daemon stops it first. An older build's `deadbolt update` stops it itself,
//! then starts this build as `deadbolt agent` and waits for an answer at
//! `agent.sock`: [`link`] points that at our socket until we stop.

use std::fs;
use std::path::{Path, PathBuf};

use deadbolt_client::paths::Paths;
use tracing::{info, warn};

fn old(paths: &Paths) -> Paths {
    Paths {
        socket: paths.socket.with_file_name("agent.sock"),
        lock: paths.lock.with_file_name("agent.lock"),
        ..paths.clone()
    }
}

/// Stops a daemon of the old name and removes its files. Call holding our
/// lock, before binding: a link at the old socket is one of ours that
/// outlived its daemon, never a process to stop.
pub async fn stop(paths: &Paths) {
    let old = old(paths);
    if !is_link(&old.socket) {
        match deadbolt_client::stop(&old).await {
            Ok(true) => info!("stopped the daemon running under its old name"),
            Ok(false) => {}
            Err(error) => warn!("stopping the daemon running under its old name: {error}"),
        }
    }
    for path in [&old.socket, &old.lock] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => warn!("removing {}: {error}", path.display()),
        }
    }
}

/// Points the old socket at ours, for the older build's update waiting there.
/// Returns the link to remove on stopping.
pub fn link(paths: &Paths) -> Option<PathBuf> {
    let link = old(paths).socket;
    let ours = paths.socket.file_name()?;
    match std::os::unix::fs::symlink(ours, &link) {
        Ok(()) => Some(link),
        Err(error) => {
            warn!("linking {}: {error}", link.display());
            None
        }
    }
}

fn is_link(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(dir: &Path) -> Paths {
        Paths {
            data: dir.join("data"),
            config: dir.join("config.toml"),
            socket: dir.join("daemon.sock"),
            lock: dir.join("daemon.lock"),
            log: dir.join("daemon.log"),
        }
    }

    #[tokio::test]
    async fn the_old_names_files_go_and_the_link_reaches_ours() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let link = link(&paths).unwrap();
        assert_eq!(fs::read_link(&link).unwrap(), Path::new("daemon.sock"));
        fs::write(dir.path().join("agent.lock"), b"").unwrap();
        // A leftover link is removed without stopping anything through it.
        stop(&paths).await;
        assert!(!dir.path().join("agent.sock").exists() && !is_link(&link));
        assert!(!dir.path().join("agent.lock").exists());
    }
}
