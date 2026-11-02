//! Where deadbolt keeps its files.
//!
//! ```text
//! $DEADBOLT_HOME or $XDG_DATA_HOME/deadbolt       the encrypted store (store.redb)
//! $XDG_CONFIG_HOME/deadbolt/config.toml           settings (see config.rs)
//! $XDG_STATE_HOME/deadbolt<suffix>/daemon.log     daemon log
//! $XDG_RUNTIME_DIR/deadbolt<suffix>/daemon.sock   control socket (0600, dir 0700)
//! $XDG_RUNTIME_DIR/deadbolt<suffix>/daemon.lock   single-instance lock
//! ```
//!
//! Older builds named these `agent.*`; the daemon stops a process still on
//! `agent.sock` when it starts (`daemon/legacy.rs` in the CLI).
//!
//! Without `XDG_RUNTIME_DIR` (e.g. a non-login ssh session) the runtime dir is
//! `/run/user/<uid>/deadbolt<suffix>` if that directory exists, so every
//! session of the same user finds the same daemon; otherwise
//! `$TMPDIR/deadbolt<suffix>-<uid>`.
//! `<suffix>` is empty for `$HOME/.local/share/deadbolt`; other stores use
//! `-<hash of the data directory>`, regardless of which variable selects it.
//!
//! The daemon takes the runtime dir only if it is a directory of this user's,
//! not a symlink, and makes it 0700 ([`secure_dir`]): the fallback in a shared
//! `$TMPDIR` could have been made by someone else first.

use std::env;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Paths {
    pub data: PathBuf,
    pub config: PathBuf,
    pub socket: PathBuf,
    pub lock: PathBuf,
    pub log: PathBuf,
}

impl Paths {
    pub fn get() -> Self {
        Self::from_vars(|name| env::var_os(name))
    }

    /// Where the browser extension's "Learn this site" sessions are logged,
    /// one JSON-lines file per session, beside the daemon's log.
    pub fn learn_dir(&self) -> PathBuf {
        self.log.with_file_name("learn")
    }

    /// The paths for an environment given by `vars` instead of the process's
    /// own (`$TMPDIR` aside), e.g. for a test that starts its own daemon.
    pub fn from_vars(vars: impl Fn(&str) -> Option<OsString>) -> Self {
        let var = |name: &str| vars(name).filter(|v| !v.is_empty()).map(PathBuf::from);
        let home = vars("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        let xdg = |variable: &str, fallback: &[&str]| {
            var(variable).unwrap_or_else(|| {
                fallback
                    .iter()
                    .fold(home.clone(), |path, part| path.join(part))
            })
        };
        let data = var("DEADBOLT_HOME")
            .unwrap_or_else(|| xdg("XDG_DATA_HOME", &[".local", "share"]).join("deadbolt"));
        let suffix = if data == home.join(".local/share/deadbolt") {
            String::new()
        } else {
            let hash = blake3::hash(data.as_os_str().as_encoded_bytes());
            format!("-{}", &hash.to_hex()[..8])
        };
        let uid = user_id();
        let runtime = match var("XDG_RUNTIME_DIR").or_else(|| user_runtime_dir(uid)) {
            Some(dir) => dir.join(format!("deadbolt{suffix}")),
            None => env::temp_dir().join(format!("deadbolt{suffix}-{uid}")),
        };
        let state = xdg("XDG_STATE_HOME", &[".local", "state"]).join(format!("deadbolt{suffix}"));
        Self {
            data,
            config: xdg("XDG_CONFIG_HOME", &[".config"])
                .join("deadbolt")
                .join("config.toml"),
            socket: runtime.join("daemon.sock"),
            lock: runtime.join("daemon.lock"),
            log: state.join("daemon.log"),
        }
    }
}

/// `/run/user/<uid>`, if it exists and belongs to `uid`.
fn user_runtime_dir(uid: u32) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let dir = PathBuf::from(format!("/run/user/{uid}"));
    let meta = std::fs::metadata(&dir).ok()?;
    (meta.is_dir() && meta.uid() == uid).then_some(dir)
}

fn user_id() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Checks that `dir` is a directory of this user's, not a symlink, and
/// makes it 0700 if it isn't. The checks and the change are on one open
/// handle, so the path can't be swapped in between.
pub fn secure_dir(dir: &Path) -> io::Result<()> {
    use rustix::fs::{FileType, Mode, OFlags};
    let refuse = |why: &str| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} {why}", dir.display()),
        )
    };
    let handle = rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| match error {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => {
            refuse("is not a directory (a symlink?)")
        }
        error => io::Error::from(error),
    })?;
    let stat = rustix::fs::fstat(&handle)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(refuse("is not a directory"));
    }
    if stat.st_uid != user_id() {
        return Err(refuse(&format!(
            "belongs to uid {}, not this user ({})",
            stat.st_uid,
            user_id()
        )));
    }
    if Mode::from_raw_mode(stat.st_mode).bits() & 0o7777 != 0o700 {
        rustix::fs::fchmod(&handle, Mode::from_raw_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn paths(overrides: &[(&str, &str)]) -> Paths {
        Paths::from_vars(|name| {
            overrides
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
                .or_else(|| {
                    match name {
                        "HOME" => Some("/home/test"),
                        "XDG_RUNTIME_DIR" => Some("/run/test"),
                        "XDG_STATE_HOME" => Some("/state/test"),
                        _ => None,
                    }
                    .map(OsString::from)
                })
        })
    }

    #[test]
    fn different_xdg_stores_have_separate_daemon_files() {
        let default = paths(&[]);
        let office = paths(&[("XDG_DATA_HOME", "/profiles/office")]);
        let personal = paths(&[("XDG_DATA_HOME", "/profiles/personal")]);
        assert_eq!(office.data, Path::new("/profiles/office/deadbolt"));
        assert_eq!(personal.data, Path::new("/profiles/personal/deadbolt"));
        for (left, right) in [
            (&default, &office),
            (&default, &personal),
            (&office, &personal),
        ] {
            assert_ne!(left.socket, right.socket);
            assert_ne!(left.lock, right.lock);
            assert_ne!(left.log, right.log);
        }
    }

    #[test]
    fn the_same_store_uses_the_same_daemon_through_either_override() {
        for (xdg, data) in [
            (
                "/home/test/.local/share",
                "/home/test/.local/share/deadbolt",
            ),
            ("/profiles/office", "/profiles/office/deadbolt"),
        ] {
            let xdg = paths(&[("XDG_DATA_HOME", xdg)]);
            let explicit = paths(&[("DEADBOLT_HOME", data)]);
            assert_eq!(xdg.data, Path::new(data));
            assert_eq!(explicit.data, Path::new(data));
            assert_eq!(xdg.socket, explicit.socket);
            assert_eq!(xdg.lock, explicit.lock);
            assert_eq!(xdg.log, explicit.log);
        }
    }

    #[test]
    fn the_default_store_keeps_its_daemon_files() {
        for overrides in [
            &[][..],
            &[("XDG_DATA_HOME", "/home/test/.local/share")][..],
            &[("DEADBOLT_HOME", "/home/test/.local/share/deadbolt")][..],
            &[("DEADBOLT_HOME", ""), ("XDG_DATA_HOME", "")][..],
        ] {
            let paths = paths(overrides);
            assert_eq!(paths.data, Path::new("/home/test/.local/share/deadbolt"));
            assert_eq!(paths.socket, Path::new("/run/test/deadbolt/daemon.sock"));
            assert_eq!(paths.lock, Path::new("/run/test/deadbolt/daemon.lock"));
            assert_eq!(paths.log, Path::new("/state/test/deadbolt/daemon.log"));
        }
    }

    #[test]
    fn an_explicit_non_default_store_keeps_its_daemon_files() {
        let paths = paths(&[("DEADBOLT_HOME", "/profiles/office/deadbolt")]);
        assert_eq!(
            paths.socket,
            Path::new("/run/test/deadbolt-43a31408/daemon.sock")
        );
        assert_eq!(
            paths.lock,
            Path::new("/run/test/deadbolt-43a31408/daemon.lock")
        );
        assert_eq!(
            paths.log,
            Path::new("/state/test/deadbolt-43a31408/daemon.log")
        );
    }

    #[test]
    fn an_explicit_store_takes_precedence_over_xdg_data_home() {
        let explicit = paths(&[("DEADBOLT_HOME", "/vault")]);
        let both = paths(&[("DEADBOLT_HOME", "/vault"), ("XDG_DATA_HOME", "/other")]);
        assert_eq!(both.data, Path::new("/vault"));
        assert_eq!(both.socket, explicit.socket);
        assert_eq!(both.lock, explicit.lock);
        assert_eq!(both.log, explicit.log);
    }

    #[test]
    fn a_runtime_dir_is_ours_and_private() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("deadbolt");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        secure_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o700);

        let link = root.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let refused = secure_dir(&link).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied, "{refused}");

        let file = root.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(secure_dir(&file).is_err());

        // Someone else's directory, as `/` is.
        if user_id() != 0 {
            let refused = secure_dir(Path::new("/")).unwrap_err();
            assert!(refused.to_string().contains("belongs to uid"), "{refused}");
        }
    }
}
