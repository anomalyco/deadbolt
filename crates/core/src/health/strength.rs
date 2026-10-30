//! Password strength estimation with `zxcvbn`, schema scoping, and site-rule
//! ceiling checks.

use serde::{Deserialize, Serialize};
use zxcvbn::matching::patterns::MatchPattern;

use crate::Item;
use crate::autofill::{urls, value};
use crate::listing::label;
use crate::site::registrable_domain;
use crate::site_password::site_caps_weak;

/// Shortest passphrase onboarding accepts.
pub const MIN_PASSPHRASE_CHARS: usize = 8;

/// Why a password scored as weak (`score <= 2`, `< 10^8` guesses).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WeakReason {
    TooShort,
    Context,
    Common,
    Pattern,
    Guessable,
}

impl WeakReason {
    pub fn summary(self, score: u8) -> &'static str {
        match self {
            Self::TooShort => "Too short",
            Self::Context => "Contains username or site name",
            Self::Common => "Common word or leaked pattern",
            Self::Pattern => "Predictable keyboard or sequence pattern",
            Self::Guessable if score <= 1 => "Very easy to guess",
            Self::Guessable => "Easy to guess",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeakScore {
    /// `zxcvbn` score `0..=2`.
    pub score: u8,
    pub reason: WeakReason,
}

/// Passphrase levels for vault creation (`onboarding.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PassphraseStrength {
    TooShort,
    Weak,
    Fair,
    Strong,
}

/// Which field of item type `kind` is a human-chosen password audited for
/// strength and breaches. Card/bank/membership PINs, API tokens, private keys,
/// recovery phrases, notes, numbers, and extra secret fields are excluded.
pub fn audited_password_field(kind: &str) -> Option<&'static str> {
    match kind {
        "login" | "database" | "server" | "wifi" | "crypto" => Some("password"),
        "ssh" => Some("passphrase"),
        _ => None,
    }
}

/// Evaluates `password` with `zxcvbn` against `context` and immediately drops
/// `zxcvbn::Entropy` so matched token slices are never retained.
pub fn check_weak(password: &str, context: &[&str]) -> Option<WeakScore> {
    if password.is_empty() {
        return None;
    }
    let entropy = zxcvbn::zxcvbn(password, context);
    let score = u8::from(entropy.score());
    let reason = if password.chars().count() < 8 {
        WeakReason::TooShort
    } else {
        classify_sequence(entropy.sequence())
    };
    // `zxcvbn`'s 3-token additive floor (`10_000^2 = 10^8`) bumps
    // `<username><site><2 digits>` into score 3 even when no random span protects it.
    let context_exposed = score == 3
        && reason == WeakReason::Context
        && entropy.guesses_log10() < 9.0
        && !entropy
            .sequence()
            .iter()
            .any(|m| m.pattern == MatchPattern::BruteForce && m.j + 1 - m.i >= 4);
    drop(entropy);
    if score <= 2 {
        Some(WeakScore { score, reason })
    } else if context_exposed {
        Some(WeakScore { score: 2, reason })
    } else {
        None
    }
}

fn classify_sequence(sequence: &[zxcvbn::Match]) -> WeakReason {
    let mut has_common = false;
    let mut has_pattern = false;
    for m in sequence {
        match &m.pattern {
            MatchPattern::Dictionary(dict) => {
                if format!("{:?}", dict.dictionary_name) == "UserInputs" {
                    return WeakReason::Context;
                }
                has_common = true;
            }
            MatchPattern::Spatial(_)
            | MatchPattern::Repeat(_)
            | MatchPattern::Sequence(_)
            | MatchPattern::Date(_)
            | MatchPattern::Regex(_) => {
                has_pattern = true;
            }
            MatchPattern::BruteForce => {}
        }
    }
    if has_common {
        WeakReason::Common
    } else if has_pattern {
        WeakReason::Pattern
    } else {
        WeakReason::Guessable
    }
}

/// Scores an item's password if it has an audited password field and isn't
/// capped below 60 bits by the site's own `password-rules.json` quirk.
pub fn item_weak(item: &Item) -> Option<WeakScore> {
    let field_name = audited_password_field(&item.kind)?;
    let password = value(item, field_name)?;
    if item.kind == "login" && urls(item).any(site_caps_weak) {
        return None;
    }
    let tokens = context_tokens(item);
    let refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
    check_weak(password, &refs)
}

fn context_tokens(item: &Item) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_words = |text: &str| {
        if text.len() >= 3 {
            out.push(text.to_owned());
        }
        for part in text.split(|c: char| !c.is_alphanumeric()) {
            if part.chars().count() >= 3 {
                out.push(part.to_owned());
            }
        }
    };
    if let Some(user) = value(item, "username") {
        push_words(user);
    }
    if let Some(name) = &item.name {
        push_words(name);
    } else {
        push_words(&label(item));
    }
    for url in urls(item) {
        if let Some(host) = crate::site::url_host(url) {
            let site = registrable_domain(&host);
            if let Some((stem, _)) = site.split_once('.') {
                push_words(stem);
            }
        }
    }
    for extra in ["ssid", "database", "host", "network", "comment"] {
        if let Some(v) = value(item, extra) {
            push_words(v);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Evaluates a device unlock passphrase for first-run onboarding.
pub fn passphrase_strength(passphrase: &str) -> PassphraseStrength {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return PassphraseStrength::TooShort;
    }
    let entropy = zxcvbn::zxcvbn(passphrase, &["deadbolt", "personal", "vault"]);
    let score = u8::from(entropy.score());
    let log10 = entropy.guesses_log10();
    drop(entropy);
    match score {
        0 | 1 => PassphraseStrength::Weak,
        2 => PassphraseStrength::Fair,
        3 if log10 < 9.5 => PassphraseStrength::Fair,
        _ => PassphraseStrength::Strong,
    }
}
