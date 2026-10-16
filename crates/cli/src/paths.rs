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

use std::env;
use std::path::PathBuf;

fn home() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir)
}

fn var(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn xdg(variable: &str, fallback: &[&str]) -> PathBuf {
    var(variable).unwrap_or_else(|| fallback.iter().fold(home(), |path, part| path.join(part)))
}

fn suffix() -> String {
    match var("DEADBOLT_HOME") {
        Some(home) => {
            let hash = blake3::hash(home.as_os_str().as_encoded_bytes());
            format!("-{}", &hash.to_hex()[..8])
        }
        None => String::new(),
    }
}

pub struct Paths {
    pub data: PathBuf,
    pub config: PathBuf,
    pub socket: PathBuf,
    pub lock: PathBuf,
    pub log: PathBuf,
}

impl Paths {
    pub fn get() -> Self {
        let suffix = suffix();
        let data = var("DEADBOLT_HOME")
            .unwrap_or_else(|| xdg("XDG_DATA_HOME", &[".local", "share"]).join("deadbolt"));
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
            socket: runtime.join("agent.sock"),
            lock: runtime.join("agent.lock"),
            log: state.join("agent.log"),
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
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}
