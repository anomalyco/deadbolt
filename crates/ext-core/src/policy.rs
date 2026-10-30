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

/// Only an explicit preset change or a command that opens the vault may
/// change the worker's policy. Other payloads cannot downgrade Strict.
pub fn accepts_preset(command: &str) -> bool {
    matches!(
        command,
        "device-preset" | "device-create" | "device-unlock" | "device-join-finish"
    )
}

/// Whether this form fill needs a passphrase. Comfortable and Relaxed follow
/// the native Touch-ID-off rule: an explicit pick is enough.
pub fn card_reauth(preset: Preset, sensitive: bool) -> bool {
    preset == Preset::Strict && sensitive
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
        assert!(Preset::Strict.reauth());
        assert!(!Preset::Comfortable.reauth());
        assert!(!Preset::Relaxed.reauth());
    }

    #[test]
    fn only_strict_card_secrets_require_reauthentication() {
        assert!(card_reauth(Preset::Strict, true));
        assert!(!card_reauth(Preset::Comfortable, true));
        assert!(!card_reauth(Preset::Relaxed, true));
        assert!(!card_reauth(Preset::Strict, false));
        assert!(card_reauth(Preset::default(), true));
    }

    #[test]
    fn an_untold_worker_is_strict() {
        assert_eq!(Preset::default(), Preset::Strict);
        assert!(Preset::default().reauth());
    }

    #[test]
    fn presets_parse_by_name_only() {
        for command in [
            "device-preset",
            "device-create",
            "device-unlock",
            "device-join-finish",
        ] {
            assert!(accepts_preset(command), "{command}");
        }
        for command in [
            "device-secret",
            "fill-form",
            "fill",
            "save",
            "check",
            "device-join-start",
            "device-status",
            "device-biometric-check",
            "unknown",
        ] {
            assert!(!accepts_preset(command), "{command}");
        }
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
