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
//! # An unpacked copy of the browser extension that `deadbolt update` keeps
//! # current (`deadbolt browser install --extension-dir <dir>` sets it).
//! extension_dir = "/Users/me/Deadbolt Extension"
//! ```

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Runtime switches are read once when the agent starts.
pub struct Environment {
    pub local_net: bool,
    pub kdf: deadbolt_store::KdfParams,
}

impl Environment {
    pub fn load() -> Self {
        Self {
            local_net: env("DEADBOLT_NET").as_deref() == Ok("local"),
            kdf: if env("DEADBOLT_KDF").as_deref() == Ok("fast") {
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
    pub extension_dir: Option<PathBuf>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("reading {}", path.display()))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
        }
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
}

/// Updates `touch_id` in `path` (`config.toml`), preserving other settings.
pub fn set_touch_id(path: &Path, enabled: bool) -> Result<()> {
    change(path, |cfg| cfg.touch_id = Some(enabled))
}

/// Records the extension directory `deadbolt update` keeps current.
pub fn set_extension_dir(path: &Path, dir: &Path) -> Result<()> {
    change(path, |cfg| cfg.extension_dir = Some(dir.to_path_buf()))
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
