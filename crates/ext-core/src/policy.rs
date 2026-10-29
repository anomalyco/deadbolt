//! Rules the browser's vault keeps that don't need a browser, so the host
//! tests them: what the lock preset asks of it, and what a login needs.

/// The browser's lock preset (docs/extension-device.md). The service worker
/// enforces the idle and screen-lock rules; it sends the preset with every
/// unlock and every change, and the worker keeps it so Strict's passphrase
/// check holds even for a request that skips the service worker's own check.
/// A worker that hasn't been told assumes Strict: it fails closed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Preset {
    #[default]
    Strict,
    Comfortable,
    Relaxed,
}

impl Preset {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "strict" => Some(Self::Strict),
            "comfortable" => Some(Self::Comfortable),
            "relaxed" => Some(Self::Relaxed),
            _ => None,
        }
    }

    /// Whether showing or copying a password asks for the passphrase every time.
    pub fn reauth(self) -> bool {
        self == Self::Strict
    }
}

/// Whether a password may be shown under `preset`. Under Strict only with a
/// passphrase, which the caller then checks against the open store.
pub fn may_reveal(preset: Preset, passphrase_given: bool) -> bool {
    !preset.reauth() || passphrase_given
}

/// A login's title as saved: trimmed, and never empty.
pub fn login_title(title: &str) -> Result<&str, &'static str> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A login needs a title");
    }
    Ok(title)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_needs_a_passphrase_to_reveal() {
        assert!(!may_reveal(Preset::Strict, false));
        assert!(may_reveal(Preset::Strict, true));
        assert!(may_reveal(Preset::Comfortable, false));
        assert!(may_reveal(Preset::Relaxed, false));
    }

    #[test]
    fn an_untold_worker_is_strict() {
        assert_eq!(Preset::default(), Preset::Strict);
        assert!(!may_reveal(Preset::default(), false));
    }

    #[test]
    fn presets_parse_by_name_only() {
        assert_eq!(Preset::parse("strict"), Some(Preset::Strict));
        assert_eq!(Preset::parse("comfortable"), Some(Preset::Comfortable));
        assert_eq!(Preset::parse("relaxed"), Some(Preset::Relaxed));
        assert_eq!(Preset::parse("Strict"), None);
        assert_eq!(Preset::parse(""), None);
    }

    #[test]
    fn a_login_title_is_trimmed_and_never_empty() {
        assert_eq!(login_title("  Acme "), Ok("Acme"));
        assert!(login_title("").is_err());
        assert!(login_title("   ").is_err());
    }
}
