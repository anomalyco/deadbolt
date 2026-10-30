//! `$XDG_CONFIG_HOME/deadbolt/config.toml`:
//!
//! ```toml
//! # Lock the agent after this long without a deadbolt command (idle timeout).
//! # "never" (the default) keeps it unlocked until `deadbolt lock`, the agent
//! # stops, or the machine reboots. Units: s, m, h, d.
//! unlock_timeout = "8h"
//!
//! # Lock when this computer sleeps or its screen locks (default true).
//! # macOS sees both as they happen; Linux sees sleep on wake.
//! lock_on_sleep = true
//!
//! # Unlock with Touch ID on macOS after unlocking once with your passphrase
//! # (default false).
//! touch_id = true
//!
//! # Unpacked copies of the browser extension that `deadbolt update` keeps
//! # current (`deadbolt browser install --extension-dir <dir>` adds one,
//! # `deadbolt browser uninstall --extension-dir <dir>` removes it), each
//! # with the build it gets: "native" (talking to `deadbolt browser-host`)
//! # or "standalone" (its own vault in the browser). `deadbolt browser
//! # switch` changes a directory's build.
//! [[extensions]]
//! dir = "/Users/me/Deadbolt Extension"
//! build = "native"
//!
//! [[extensions]]
//! dir = "/Users/me/Deadbolt Standalone"
//! build = "standalone"
//! ```
//!
//! Older configs' single `extension_dir` and `extension_build` are read as
//! one entry, and written back in this form the next time it changes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Runtime switches are read once when the agent starts. Both are for
/// tests and development only ([`test_env`]).
pub struct Environment {
    pub local_net: bool,
    pub kdf: deadbolt_store::KdfParams,
}

impl Environment {
    pub fn load() -> Self {
        Self {
            local_net: test_env("DEADBOLT_NET").as_deref() == Some("local"),
            kdf: if test_env("DEADBOLT_KDF").as_deref() == Some("fast") {
                deadbolt_store::KdfParams {
                    m_cost_kib: 64,
                    t_cost: 1,
                    p_cost: 1,
                }
            } else {
                deadbolt_store::KdfParams::DEFAULT
            },
        }
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "configuration boundary for process environment"
)]
pub fn env(name: &str) -> Result<String, std::env::VarError> {
    std::env::var(name)
}

/// A switch for tests and development (`DEADBOLT_NET`, `DEADBOLT_KDF`,
/// `DEADBOLT_TEST_*`): read only in debug builds, so nothing in a release
/// build's environment, which a caller can set for the agent it starts,
/// weakens the store's KDF, cuts it off the network or makes it claim
/// another build. Release builds always act as if it's unset.
pub fn test_env(name: &str) -> Option<String> {
    if cfg!(any(debug_assertions, test)) {
        env(name).ok()
    } else {
        None
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "wall-clock adapter for display and address-book timestamps"
)]
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[expect(
    clippy::disallowed_methods,
    reason = "wall-clock adapter for noticing that the computer slept, and for one-time codes"
)]
pub fn wall_clock() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlock_timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_on_sleep: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub touch_id: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breach_checks: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<ExtensionDir>,
    /// The single directory older configs registered, moved into
    /// `extensions` on load.
    #[serde(default, skip_serializing)]
    extension_dir: Option<PathBuf>,
    #[serde(default, skip_serializing)]
    extension_build: Option<ExtensionBuild>,
}

/// An unpacked extension `deadbolt update` keeps current, and its build.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionDir {
    pub dir: PathBuf,
    #[serde(default)]
    pub build: ExtensionBuild,
}

/// The two builds of the browser extension (`extension/scripts/build.ts`).
/// Both have the same extension id, so one replaces the other in a profile.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionBuild {
    /// Fills from the agent through `deadbolt browser-host`.
    #[default]
    Native,
    /// Its own vault in the browser, a device of its own.
    Standalone,
}

impl ExtensionBuild {
    /// The release service target of the `extension` artifact.
    pub fn target(self) -> &'static str {
        match self {
            Self::Native => "chromium",
            Self::Standalone => "chromium-standalone",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Standalone => "standalone",
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).with_context(|| format!("reading {}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Parses `config.toml`, moving an older config's single extension
    /// directory into `extensions`.
    fn parse(text: &str) -> Result<Self> {
        let mut cfg: Self = toml::from_str(text)?;
        let build = cfg.extension_build.take().unwrap_or_default();
        if let Some(dir) = cfg.extension_dir.take()
            && !cfg.extensions.iter().any(|e| e.dir == dir)
        {
            cfg.extensions.insert(0, ExtensionDir { dir, build });
        }
        Ok(cfg)
    }

    /// The registered extension directory `dir` (absolute, as registered).
    pub fn extension(&self, dir: &Path) -> Option<&ExtensionDir> {
        self.extensions.iter().find(|e| e.dir == dir)
    }

    /// The configured idle timeout; `None` means never.
    pub fn unlock_timeout(&self) -> Result<Option<Duration>> {
        self.unlock_timeout
            .as_deref()
            .map_or(Ok(None), parse_timeout)
    }

    /// Whether to lock when the computer sleeps or its screen locks.
    pub fn lock_on_sleep(&self) -> bool {
        self.lock_on_sleep.unwrap_or(true)
    }

    /// Whether Touch ID unlock is enabled in `config.toml`.
    pub fn touch_id(&self) -> bool {
        self.touch_id.unwrap_or(false)
    }

    /// Whether opt-in Have I Been Pwned breach checks are enabled in `config.toml`.
    pub fn breach_checks(&self) -> bool {
        self.breach_checks.unwrap_or(false)
    }
}

/// Updates `touch_id` in `path` (`config.toml`), preserving other settings.
pub fn set_touch_id(path: &Path, enabled: bool) -> Result<()> {
    change(path, |cfg| cfg.touch_id = Some(enabled))
}

/// Updates `breach_checks` in `path` (`config.toml`), preserving other settings.
pub fn set_breach_checks(path: &Path, enabled: bool) -> Result<()> {
    change(path, |cfg| cfg.breach_checks = Some(enabled))
}

/// Today's UTC date as `YYYY-MM-DD`.
pub fn today_utc() -> String {
    utc_date(now())
}

/// `secs` (since the Unix epoch) as a UTC `YYYY-MM-DD` date.
pub fn utc_date(secs: u64) -> String {
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Records an extension directory `deadbolt update` keeps current, and which
/// build it gets (replacing the build of one already registered).
pub fn set_extension_dir(path: &Path, dir: &Path, build: ExtensionBuild) -> Result<()> {
    change(path, |cfg| {
        match cfg.extensions.iter_mut().find(|e| e.dir == dir) {
            Some(entry) => entry.build = build,
            None => cfg.extensions.push(ExtensionDir {
                dir: dir.to_path_buf(),
                build,
            }),
        }
    })
}

/// Stops `deadbolt update` keeping `dir` current; false if it wasn't
/// registered.
pub fn remove_extension_dir(path: &Path, dir: &Path) -> Result<bool> {
    if Config::load(path)?.extension(dir).is_none() {
        return Ok(false);
    }
    change(path, |cfg| cfg.extensions.retain(|e| e.dir != dir))?;
    Ok(true)
}

/// Changes `path` (`config.toml`) with `edit`, preserving other settings.
fn change(path: &Path, edit: impl FnOnce(&mut Config)) -> Result<()> {
    let mut cfg = Config::load(path)?;
    edit(&mut cfg);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let body = toml::to_string_pretty(&cfg).context("serializing config.toml")?;
    std::fs::write(path, body).with_context(|| format!("writing {}", path.display()))
}

/// Parses `30s`, `15m`, `8h`, `1d` (a bare number is seconds), or
/// `never`/`off`/`0` for no timeout.
pub fn parse_timeout(text: &str) -> Result<Option<Duration>> {
    let text = text.trim();
    if matches!(text, "never" | "off" | "none" | "0") {
        return Ok(None);
    }
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let Ok(number) = number.parse::<u64>() else {
        bail!("invalid duration '{text}' (try 30s, 15m, 8h, 1d or never)");
    };
    let scale = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => bail!("invalid duration '{text}' (try 30s, 15m, 8h, 1d or never)"),
    };
    Ok(Some(Duration::from_secs(number.saturating_mul(scale))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts() {
        assert_eq!(parse_timeout("never").unwrap(), None);
        assert_eq!(parse_timeout("0").unwrap(), None);
        assert_eq!(parse_timeout("90").unwrap(), Some(Duration::from_secs(90)));
        assert_eq!(
            parse_timeout("15m").unwrap(),
            Some(Duration::from_secs(900))
        );
        assert_eq!(
            parse_timeout("2h").unwrap(),
            Some(Duration::from_secs(7200))
        );
        assert!(parse_timeout("2x").is_err());
        assert!(parse_timeout("m").is_err());
    }

    #[test]
    fn lock_on_sleep_is_on_unless_turned_off() {
        let parse = |text: &str| toml::from_str::<Config>(text).unwrap().lock_on_sleep();
        assert!(parse(""));
        assert!(parse("lock_on_sleep = true"));
        assert!(!parse("lock_on_sleep = false\nunlock_timeout = \"8h\""));
    }

    #[test]
    fn migrates_the_single_extension_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "touch_id = true\nextension_dir = \"/ext\"\nextension_build = \"standalone\"\n",
        )
        .unwrap();
        let standalone = ExtensionDir {
            dir: "/ext".into(),
            build: ExtensionBuild::Standalone,
        };
        assert_eq!(
            Config::load(&path).unwrap().extensions,
            std::slice::from_ref(&standalone)
        );

        set_extension_dir(&path, Path::new("/other"), ExtensionBuild::Native).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("extension_dir"), "{text}");
        let cfg = Config::load(&path).unwrap();
        assert!(cfg.touch_id());
        let native = ExtensionDir {
            dir: "/other".into(),
            build: ExtensionBuild::Native,
        };
        assert_eq!(cfg.extensions, [standalone.clone(), native.clone()]);

        assert!(remove_extension_dir(&path, Path::new("/ext")).unwrap());
        assert!(!remove_extension_dir(&path, Path::new("/ext")).unwrap());
        assert_eq!(Config::load(&path).unwrap().extensions, [native]);
    }

    #[test]
    fn set_touch_id_preserves_existing_settings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deadbolt/config.toml");
        set_touch_id(&path, true).unwrap();
        assert!(Config::load(&path).unwrap().touch_id());

        std::fs::write(&path, "unlock_timeout = \"4h\"\nlock_on_sleep = false\n").unwrap();
        set_touch_id(&path, true).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert!(cfg.touch_id());
        assert!(!cfg.lock_on_sleep());
        assert_eq!(cfg.unlock_timeout.as_deref(), Some("4h"));

        set_touch_id(&path, false).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert!(!cfg.touch_id());
        assert!(!cfg.lock_on_sleep());
        assert_eq!(cfg.unlock_timeout.as_deref(), Some("4h"));
    }
}
