//! Rules the browser's vault keeps that don't need a browser, so the host
//! tests them: what the lock preset asks of it, and what a login needs.

/// The browser's lock preset (docs/extension-device.md). The service worker
/// enforces the idle and screen-lock rules; it sends the preset with every
/// unlock and every change, and the worker keeps it so Strict's passphrase
/// check holds even for a request that skips the service worker's own check.
/// A worker that hasn't been told assumes Strict: it fails closed.
/// UntilQuit has no idle or screen lock: the vault stays open until the
/// browser quits, the worker is lost or someone chooses Lock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Preset {
    #[default]
    Strict,
    Comfortable,
    Relaxed,
    UntilQuit,
}

impl Preset {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "strict" => Some(Self::Strict),
            "comfortable" => Some(Self::Comfortable),
            "relaxed" => Some(Self::Relaxed),
            "until-quit" => Some(Self::UntilQuit),
            _ => None,
        }
    }

    /// Whether showing or copying a password asks for the passphrase every time.
    pub fn reauth(self) -> bool {
        self == Self::Strict
    }

    /// Whether changing from `self` to `to` needs the passphrase or a PRF
    /// key first: only a change to UntilQuit does, since it ends idle and
    /// screen locking. Other changes don't ask yet.
    pub fn change_needs_proof(self, to: Self) -> bool {
        to == Self::UntilQuit && self != Self::UntilQuit
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

/// The preset a command carries, if it's one that may set it: any other
/// command's `preset` field is ignored, so it can't loosen the worker's.
pub fn preset_from(command: &str, preset: Option<&str>) -> Option<Preset> {
    accepts_preset(command)
        .then_some(preset)
        .flatten()
        .and_then(Preset::parse)
}

/// Whether this form fill needs a passphrase. Comfortable, Relaxed and
/// UntilQuit follow the native Touch-ID-off rule: an explicit pick is enough.
pub fn card_reauth(preset: Preset, sensitive: bool) -> bool {
    preset == Preset::Strict && sensitive
}

/// Native skips verification when discouraged; Strict substitutes a local
/// passphrase for the native preferred-UV prompt, without asserting Touch ID UV.
pub fn passkey_reauth(preset: Preset, discouraged: bool) -> bool {
    preset == Preset::Strict && !discouraged
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
        assert!(!Preset::UntilQuit.reauth());
    }

    #[test]
    fn only_a_change_to_until_quit_needs_proof() {
        for from in [Preset::Strict, Preset::Comfortable, Preset::Relaxed] {
            assert!(from.change_needs_proof(Preset::UntilQuit), "{from:?}");
            for to in [Preset::Strict, Preset::Comfortable, Preset::Relaxed] {
                assert!(!from.change_needs_proof(to), "{from:?} to {to:?}");
            }
        }
        assert!(!Preset::UntilQuit.change_needs_proof(Preset::UntilQuit));
        assert!(!Preset::UntilQuit.change_needs_proof(Preset::Strict));
        assert!(Preset::default().change_needs_proof(Preset::UntilQuit));
    }

    #[test]
    fn only_strict_card_secrets_require_reauthentication() {
        assert!(card_reauth(Preset::Strict, true));
        assert!(!card_reauth(Preset::Comfortable, true));
        assert!(!card_reauth(Preset::Relaxed, true));
        assert!(!card_reauth(Preset::UntilQuit, true));
        assert!(!card_reauth(Preset::Strict, false));
        assert!(card_reauth(Preset::default(), true));
    }

    #[test]
    fn strict_passkeys_follow_the_native_verification_preference() {
        assert!(passkey_reauth(Preset::Strict, false));
        assert!(!passkey_reauth(Preset::Strict, true));
        assert!(!passkey_reauth(Preset::Comfortable, false));
        assert!(!passkey_reauth(Preset::Relaxed, false));
        assert!(!passkey_reauth(Preset::UntilQuit, false));
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
        assert_eq!(Preset::parse("until-quit"), Some(Preset::UntilQuit));
        assert_eq!(Preset::parse("Strict"), None);
        assert_eq!(Preset::parse("until_quit"), None);
        assert_eq!(Preset::parse(""), None);
    }

    #[test]
    fn only_accepting_commands_carry_until_quit() {
        for command in [
            "fill-form",
            "fill",
            "hello",
            "device-secret",
            "device-status",
            "unknown",
        ] {
            assert_eq!(preset_from(command, Some("until-quit")), None, "{command}");
            assert_eq!(preset_from(command, Some("relaxed")), None, "{command}");
        }
        assert_eq!(
            preset_from("device-preset", Some("until-quit")),
            Some(Preset::UntilQuit)
        );
        assert_eq!(
            preset_from("device-unlock", Some("until-quit")),
            Some(Preset::UntilQuit)
        );
        assert_eq!(preset_from("device-preset", Some("forever")), None);
        assert_eq!(preset_from("device-preset", None), None);
    }

    #[test]
    fn a_login_title_is_trimmed_and_never_empty() {
        assert_eq!(login_title("  Acme "), Ok("Acme"));
        assert!(login_title("").is_err());
        assert!(login_title("   ").is_err());
    }
}
