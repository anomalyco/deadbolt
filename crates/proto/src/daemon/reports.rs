use std::collections::BTreeMap;
use std::fmt;

use deadbolt_core::listing::{KINDS, noun, sign_in_name};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A one-time code and when it stops being valid.
#[derive(Clone, Serialize, Deserialize)]
pub struct Code {
    pub code: Zeroizing<String>,
    /// Seconds each code lasts.
    pub period: u64,
    /// Unix seconds when the next code takes over.
    pub valid_until: u64,
    /// Milliseconds until then, from the daemon's clock; at least 1.
    pub remaining_ms: u64,
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Code")
            .field("code", &"<redacted>")
            .field("period", &self.period)
            .field("valid_until", &self.valid_until)
            .field("remaining_ms", &self.remaining_ms)
            .finish()
    }
}

/// What an import did, or would do. Counts only, never values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReport {
    pub source: ImportSource,
    /// New items by item type; duplicates are not counted here.
    pub new: BTreeMap<String, usize>,
    /// Items already in the vault, or earlier in the export.
    pub duplicates: usize,
    /// Items not imported, by reason.
    pub skipped: Vec<Tally>,
    /// Values not imported or imported differently, by reason.
    pub warnings: Vec<Tally>,
    /// What deadbolt has no place for (folders, favorites, attachments, ...).
    pub dropped: Vec<Tally>,
    /// The new logins' sign-in methods ("Sign in with Google").
    #[serde(default)]
    pub sign_in: SignInCounts,
}

/// The new logins that sign in with another account.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignInCounts {
    /// By provider ([`super::SignIn::provider`]).
    pub providers: BTreeMap<String, usize>,
    /// How many of them are linked to the login they sign in with.
    pub linked: usize,
}

/// The app an export came from, detected from its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImportSource {
    Bitwarden,
    OnePassword,
    ApplePasswords,
    /// A CSV with recognizable columns, such as a browser's export.
    Csv,
}

impl fmt::Display for ImportSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bitwarden => "Bitwarden",
            Self::OnePassword => "1Password",
            Self::ApplePasswords => "Apple Passwords",
            Self::Csv => "CSV",
        })
    }
}

/// A count of something, named in the singular and the plural.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tally {
    pub count: usize,
    pub one: String,
    pub many: String,
}

impl fmt::Display for Tally {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = if self.count == 1 {
            &self.one
        } else {
            &self.many
        };
        write!(f, "{} {what}", self.count)
    }
}

impl ImportReport {
    /// How many new items of type `kind`.
    pub fn count(&self, kind: &str) -> usize {
        self.new.get(kind).copied().unwrap_or(0)
    }

    /// How many new items in all.
    pub fn total(&self) -> usize {
        self.new.values().sum()
    }

    /// New items by type, in [`KINDS`] order then by identifier, leaving out
    /// types with none: `[("login", 12), ("note", 3)]`.
    pub fn counts(&self) -> Vec<(&str, usize)> {
        let known = KINDS.iter().map(|(kind, ..)| *kind);
        let other = self
            .new
            .keys()
            .map(String::as_str)
            .filter(|k| !KINDS.iter().any(|(kind, ..)| kind == k));
        known
            .chain(other)
            .map(|kind| (kind, self.count(kind)))
            .filter(|(_, n)| *n > 0)
            .collect()
    }

    /// The report as lines of text; `applied` is false for a preview.
    pub fn lines(&self, applied: bool) -> Vec<String> {
        // Logins and cards always, the other types when there are some.
        let mut kinds = vec!["login", "card"];
        kinds.extend(
            self.counts()
                .into_iter()
                .map(|(kind, _)| kind)
                .filter(|kind| !matches!(*kind, "login" | "card")),
        );
        let counts: Vec<String> = kinds
            .into_iter()
            .map(|kind| format!("{} {}", noun(kind, 2), self.count(kind)))
            .collect();
        let mut lines = vec![format!(
            "{} {} from {} ({})",
            if applied {
                "imported"
            } else {
                "dry run: would import"
            },
            self.total(),
            self.source,
            counts.join(", ")
        )];
        let methods: usize = self.sign_in.providers.values().sum();
        if methods > 0 {
            let mut providers: Vec<(&String, &usize)> = self.sign_in.providers.iter().collect();
            providers.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
            let providers: Vec<String> = providers
                .into_iter()
                .map(|(p, n)| format!("{} {n}", sign_in_name(p)))
                .collect();
            let methods = Tally {
                count: methods,
                one: "sign-in method".into(),
                many: "sign-in methods".into(),
            };
            lines.push(format!("kept {methods} ({})", providers.join(", ")));
            if self.sign_in.linked > 0 {
                lines.push(format!("linked {} to their accounts", self.sign_in.linked));
            }
        }
        if self.duplicates > 0 {
            let duplicates = Tally {
                count: self.duplicates,
                one: "duplicate".into(),
                many: "duplicates".into(),
            };
            lines.push(format!("skipped {duplicates}"));
        }
        lines.extend(self.skipped.iter().map(|t| format!("skipped {t}")));
        lines.extend(self.warnings.iter().map(|t| format!("warning: {t}")));
        if !self.dropped.is_empty() {
            let dropped: Vec<String> = self.dropped.iter().map(Tally::to_string).collect();
            lines.push(format!("dropped: {}", dropped.join(", ")));
        }
        lines
    }
}
