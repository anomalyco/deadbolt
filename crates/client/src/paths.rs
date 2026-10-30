//! Where deadbolt keeps its files.
//!
//! ```text
//! $DEADBOLT_HOME or $XDG_DATA_HOME/deadbolt       the encrypted store (store.redb)
//! $XDG_CONFIG_HOME/deadbolt/config.toml           settings (see config.rs)
//! $XDG_STATE_HOME/deadbolt<suffix>/agent.log      agent log
//! $XDG_RUNTIME_DIR/deadbolt<suffix>/agent.sock    control socket (0600, dir 0700)
//! $XDG_RUNTIME_DIR/deadbolt<suffix>/agent.lock    single-instance lock
//! ```
//!
//! Without `XDG_RUNTIME_DIR` (e.g. a non-login ssh session) the runtime dir is
//! `/run/user/<uid>/deadbolt<suffix>` if that directory exists, so every
//! session of the same user finds the same agent; otherwise
//! `$TMPDIR/deadbolt<suffix>-<uid>`.
//! `<suffix>` is empty by default and `-<hash of DEADBOLT_HOME>` when
//! `DEADBOLT_HOME` is set, so every store gets its own agent.
//!
//! The agent takes the runtime dir only if it is a directory of this user's,
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
    pub ssh_link: Option<PathBuf>,
}

impl Paths {
    pub fn get() -> Self {
        Self::from_vars(|name| env::var_os(name))
    }

    /// Where the browser extension's "Learn this site" sessions are logged,
    /// one JSON-lines file per session, beside the agent's log.
    pub fn learn_dir(&self) -> PathBuf {
        self.log.with_file_name("learn")
    }

    /// Where the SSH agent listens inside the agent's `0700` runtime directory.
    pub fn ssh_socket(&self) -> PathBuf {
        self.socket.with_file_name("ssh.sock")
    }

    /// Optional local SSH key selection rules (`$XDG_CONFIG_HOME/deadbolt/ssh.toml`).
    pub fn ssh_config(&self) -> PathBuf {
        self.config.with_file_name("ssh.toml")
    }

    /// Stable `~/.deadbolt/ssh.sock` symlink for the default store, omitted
    /// whenever `DEADBOLT_HOME` or a test runtime socket is in use.
    pub fn ssh_link(&self) -> Option<PathBuf> {
        self.ssh_link.clone()
    }

    /// The path SSH clients (`IdentityAgent`, `SSH_AUTH_SOCK`) should connect to.
    pub fn ssh_client_socket(&self) -> PathBuf {
        self.ssh_link().unwrap_or_else(|| self.ssh_socket())
    }

    /// The paths for an environment given by `vars` instead of the process's
    /// own (`$TMPDIR` aside), e.g. for a test that starts its own agent.
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
        let suffix = match var("DEADBOLT_HOME") {
            Some(home) => {
                let hash = blake3::hash(home.as_os_str().as_encoded_bytes());
                format!("-{}", &hash.to_hex()[..8])
            }
            None => String::new(),
        };
        let data = var("DEADBOLT_HOME")
            .unwrap_or_else(|| xdg("XDG_DATA_HOME", &[".local", "share"]).join("deadbolt"));
        let uid = user_id();
        let runtime = match var("XDG_RUNTIME_DIR").or_else(|| user_runtime_dir(uid)) {
            Some(dir) => dir.join(format!("deadbolt{suffix}")),
            None => env::temp_dir().join(format!("deadbolt{suffix}-{uid}")),
        };
        let state = xdg("XDG_STATE_HOME", &[".local", "state"]).join(format!("deadbolt{suffix}"));
        let ssh_link = (var("DEADBOLT_HOME").is_none() && var("HOME").is_some())
            .then(|| home.join(".deadbolt").join("ssh.sock"));
        Self {
            data,
            config: xdg("XDG_CONFIG_HOME", &[".config"])
                .join("deadbolt")
                .join("config.toml"),
            socket: runtime.join("agent.sock"),
            lock: runtime.join("agent.lock"),
            log: state.join("agent.log"),
            ssh_link,
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
