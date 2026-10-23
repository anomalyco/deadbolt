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
//! ```

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

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
    reason = "wall-clock adapter for noticing that the computer slept"
)]
pub fn wall_clock() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub unlock_timeout: Option<String>,
    #[serde(default)]
    pub lock_on_sleep: Option<bool>,
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
}
