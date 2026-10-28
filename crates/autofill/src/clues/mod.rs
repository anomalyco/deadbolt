//! Clue tables: the vocabulary and weights that score fields and forms.
//!
//! The tables are TOML files under `crates/autofill/rules/`, embedded at build
//! time: one file per field type (`rules/fields/<type>.toml`), shared lists the
//! field types include (`rules/fields/<name>.toml` with `name = …`), and one
//! file per form kind (`rules/forms/<kind>.toml`). Every entry carries a `why`.
//! See the crate README for the format.
//!
//! Loading normalises every phrase with [`crate::text`] and compiles all of
//! them into one [`Matcher`] for fields and one for forms, so a single pass
//! over a field's text finds the hits for every type.

mod index;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub use index::{Hit, Matcher, Texts};

use crate::classify::{FieldType, FormKind};
use crate::snapshot::Element;
use crate::text;

/// Which text a clue reads.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    /// What a person reads: labels, placeholder, aria text, title; for forms,
    /// the form's text and header, the page title and headings and its buttons.
    Display,
    /// What a developer wrote: id, name, class and test ids; for forms, the
    /// form's id, name and action and the frame's URL.
    Code,
    #[default]
    Both,
}

impl Channel {
    pub fn has_display(self) -> bool {
        matches!(self, Channel::Display | Channel::Both)
    }

    pub fn has_code(self) -> bool {
        matches!(self, Channel::Code | Channel::Both)
    }
}

/// How a phrase matches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Whole words: `pass` doesn't match "passport". In code text a phrase of
    /// four or more letters also matches inside run-together names
    /// (`txtpassword`); shorter ones need a word boundary (`user_pwd`, `userPwd`).
    #[default]
    Word,
    /// Letters and digits only, anywhere: `signin` matches "/auth/sign-in".
    Sanitised,
}

/// One weighted phrase, with its alternatives. It counts once per channel.
#[derive(Debug, Clone)]
pub struct Clue {
    /// `<table>:<phrase>`, for traces.
    pub id: String,
    /// The phrase and its alternatives, normalised with [`text::words`] and trimmed.
    pub phrases: Vec<String>,
    pub score: i32,
    pub channel: Channel,
    pub mode: Mode,
    pub why: String,
}

/// A score for an autocomplete token (`prefix-*` matches by prefix).
#[derive(Debug, Clone)]
pub struct TokenWeight {
    pub id: String,
    pub token: String,
    pub score: i32,
}

impl TokenWeight {
    pub fn matches(&self, token: &str) -> bool {
        match self.token.strip_suffix('*') {
            Some(prefix) => token.starts_with(prefix),
            None => token == self.token,
        }
    }
}

/// A score for an element type; `None` is the `*` entry for every element not listed.
#[derive(Debug, Clone)]
pub struct ElementWeight {
    pub id: String,
    pub element: Option<Element>,
    pub score: i32,
}

/// A score for an `inputmode` value.
#[derive(Debug, Clone)]
pub struct InputModeWeight {
    pub id: String,
    pub mode: String,
    pub score: i32,
}

/// Everything that scores one field type.
#[derive(Debug, Clone)]
pub struct FieldTable {
    pub ty: FieldType,
    pub clues: Vec<Clue>,
    pub autocomplete: Vec<TokenWeight>,
    pub elements: Vec<ElementWeight>,
    pub input_modes: Vec<InputModeWeight>,
}

impl FieldTable {
    /// The weight for `element`: its own entry, else the `*` entry, else 0.
    pub fn element_weight(&self, element: Element) -> Option<&ElementWeight> {
        self.elements
            .iter()
            .find(|e| e.element == Some(element))
            .or_else(|| self.elements.iter().find(|e| e.element.is_none()))
    }
}

/// Everything that scores one form kind from text.
#[derive(Debug, Clone)]
pub struct FormTable {
    pub kind: FormKind,
    pub clues: Vec<Clue>,
}

/// The compiled rules.
#[derive(Debug)]
pub struct Rules {
    /// One per [`FieldType::ALL`], in that order.
    pub fields: Vec<FieldTable>,
    /// One per [`FormKind::SCORED`], in that order.
    pub forms: Vec<FormTable>,
    /// Hits are `(table index into fields, clue index)`.
    pub field_matcher: Matcher,
    /// Hits are `(table index into forms, clue index)`.
    pub form_matcher: Matcher,
}

/// Why the rule files failed to load.
#[derive(Debug, thiserror::Error)]
pub enum RulesError {
    #[error("{file}: {source}")]
    Toml {
        file: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("{file}: needs exactly one of `type`, `kind` or `name`")]
    Header { file: String },
    #[error("{file}: unknown {what} `{value}`")]
    Unknown {
        file: String,
        what: &'static str,
        value: String,
    },
    #[error("{file}: entry `{entry}` has no `why`")]
    MissingWhy { file: String, entry: String },
    #[error("{file}: phrase `{phrase}` normalises to nothing")]
    EmptyPhrase { file: String, phrase: String },
    #[error("{table}: phrase `{phrase}` appears twice")]
    Duplicate { table: String, phrase: String },
    #[error("{table}: no table for {what}")]
    Missing { table: String, what: &'static str },
    #[error("building the matcher: {0}")]
    Matcher(#[from] aho_corasick::BuildError),
}

/// The embedded rule files, as (path, contents).
pub const FILES: &[(&str, &str)] = &[
    (
        "fields/username.toml",
        include_str!("../../rules/fields/username.toml"),
    ),
    (
        "fields/email.toml",
        include_str!("../../rules/fields/email.toml"),
    ),
    (
        "fields/phone.toml",
        include_str!("../../rules/fields/phone.toml"),
    ),
    (
        "fields/password.toml",
        include_str!("../../rules/fields/password.toml"),
    ),
    (
        "fields/new-password.toml",
        include_str!("../../rules/fields/new-password.toml"),
    ),
    (
        "fields/otp.toml",
        include_str!("../../rules/fields/otp.toml"),
    ),
    (
        "fields/captcha.toml",
        include_str!("../../rules/fields/captcha.toml"),
    ),
    (
        "fields/not-a-login-field.toml",
        include_str!("../../rules/fields/not-a-login-field.toml"),
    ),
    (
        "fields/non-login-autocomplete.toml",
        include_str!("../../rules/fields/non-login-autocomplete.toml"),
    ),
    (
        "forms/login.toml",
        include_str!("../../rules/forms/login.toml"),
    ),
    (
        "forms/signup.toml",
        include_str!("../../rules/forms/signup.toml"),
    ),
    (
        "forms/change-password.toml",
        include_str!("../../rules/forms/change-password.toml"),
    ),
    (
        "forms/reset.toml",
        include_str!("../../rules/forms/reset.toml"),
    ),
    ("forms/mfa.toml", include_str!("../../rules/forms/mfa.toml")),
    (
        "forms/newsletter.toml",
        include_str!("../../rules/forms/newsletter.toml"),
    ),
];

// ---- File format ------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(rename = "type")]
    field_type: Option<String>,
    kind: Option<String>,
    name: Option<String>,
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    clue: Vec<RawClue>,
    #[serde(default)]
    autocomplete: Vec<RawToken>,
    #[serde(default)]
    element: Vec<RawElement>,
    #[serde(default)]
    inputmode: Vec<RawInputMode>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClue {
    phrase: String,
    #[serde(default)]
    langs: Vec<String>,
    score: i32,
    #[serde(default)]
    channel: Channel,
    #[serde(default)]
    mode: Mode,
    #[serde(default)]
    why: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawToken {
    token: String,
    score: i32,
    #[serde(default)]
    why: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawElement {
    element: String,
    score: i32,
    #[serde(default)]
    why: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInputMode {
    mode: String,
    score: i32,
    #[serde(default)]
    why: String,
}

/// A parsed file's contents, before includes are resolved.
#[derive(Debug, Default, Clone)]
struct Parts {
    include: Vec<String>,
    clues: Vec<Clue>,
    autocomplete: Vec<TokenWeight>,
    elements: Vec<ElementWeight>,
    input_modes: Vec<InputModeWeight>,
}

fn table_name(file: &str) -> &str {
    file.rsplit('/')
        .next()
        .unwrap_or(file)
        .trim_end_matches(".toml")
}

fn parse_file(file: &str, source: &str) -> Result<(RawHeader, Parts), RulesError> {
    let raw: RawFile = toml::from_str(source).map_err(|source| RulesError::Toml {
        file: file.to_owned(),
        source,
    })?;
    let header = match (raw.field_type, raw.kind, raw.name) {
        (Some(t), None, None) => RawHeader::Field(FieldType::from_rule_name(&t).ok_or_else(
            || RulesError::Unknown {
                file: file.to_owned(),
                what: "field type",
                value: t,
            },
        )?),
        (None, Some(k), None) => RawHeader::Form(FormKind::from_rule_name(&k).ok_or_else(
            || RulesError::Unknown {
                file: file.to_owned(),
                what: "form kind",
                value: k,
            },
        )?),
        (None, None, Some(n)) => RawHeader::Shared(n),
        _ => {
            return Err(RulesError::Header {
                file: file.to_owned(),
            });
        }
    };
    let table = table_name(file);
    let need_why = |why: &str, entry: &str| {
        if why.trim().is_empty() {
            Err(RulesError::MissingWhy {
                file: file.to_owned(),
                entry: entry.to_owned(),
            })
        } else {
            Ok(())
        }
    };
    let mut parts = Parts {
        include: raw.include,
        ..Parts::default()
    };
    for c in raw.clue {
        need_why(&c.why, &c.phrase)?;
        let mut phrases = Vec::with_capacity(1 + c.langs.len());
        for p in std::iter::once(&c.phrase).chain(&c.langs) {
            let normalised = text::words(p).trim().to_owned();
            if normalised.is_empty() {
                return Err(RulesError::EmptyPhrase {
                    file: file.to_owned(),
                    phrase: p.clone(),
                });
            }
            phrases.push(normalised);
        }
        parts.clues.push(Clue {
            id: format!("{table}:{}", phrases[0]),
            phrases,
            score: c.score,
            channel: c.channel,
            mode: c.mode,
            why: c.why,
        });
    }
    for t in raw.autocomplete {
        need_why(&t.why, &t.token)?;
        parts.autocomplete.push(TokenWeight {
            id: format!("{table}:ac={}", t.token),
            token: t.token.to_lowercase(),
            score: t.score,
        });
    }
    for e in raw.element {
        need_why(&e.why, &e.element)?;
        let element = if e.element == "*" {
            None
        } else {
            Some(
                Element::parse(&e.element).ok_or_else(|| RulesError::Unknown {
                    file: file.to_owned(),
                    what: "element",
                    value: e.element.clone(),
                })?,
            )
        };
        parts.elements.push(ElementWeight {
            id: format!("{table}:element={}", e.element),
            element,
            score: e.score,
        });
    }
    for m in raw.inputmode {
        need_why(&m.why, &m.mode)?;
        parts.input_modes.push(InputModeWeight {
            id: format!("{table}:inputmode={}", m.mode),
            mode: m.mode.to_lowercase(),
            score: m.score,
        });
    }
    Ok((header, parts))
}

enum RawHeader {
    Field(FieldType),
    Form(FormKind),
    Shared(String),
}

/// Fails when two clues of one table would match the same text on the same
/// channel: the same words on display, or the same letters in code (where
/// "user name" and "username" both match `username`).
fn check_duplicates(table: &str, clues: &[Clue]) -> Result<(), RulesError> {
    let mut seen: BTreeSet<(String, bool)> = BTreeSet::new();
    for clue in clues {
        for phrase in &clue.phrases {
            for (on, code) in [
                (clue.channel.has_display(), false),
                (clue.channel.has_code(), true),
            ] {
                if !on {
                    continue;
                }
                let key = if code || clue.mode == Mode::Sanitised {
                    text::squash(phrase)
                } else {
                    phrase.clone()
                };
                if !seen.insert((key, code)) {
                    return Err(RulesError::Duplicate {
                        table: table.to_owned(),
                        phrase: phrase.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

impl Rules {
    /// The rules built into this crate.
    pub fn embedded() -> Result<Rules, RulesError> {
        Rules::load(FILES)
    }

    /// Loads rules from (path, TOML) pairs.
    pub fn load(files: &[(&str, &str)]) -> Result<Rules, RulesError> {
        let mut fields: BTreeMap<FieldType, Parts> = BTreeMap::new();
        let mut forms: BTreeMap<FormKind, Parts> = BTreeMap::new();
        let mut shared: BTreeMap<String, Parts> = BTreeMap::new();
        for (file, source) in files {
            let (header, parts) = parse_file(file, source)?;
            match header {
                RawHeader::Field(t) => {
                    fields.insert(t, parts);
                }
                RawHeader::Form(k) => {
                    forms.insert(k, parts);
                }
                RawHeader::Shared(n) => {
                    shared.insert(n, parts);
                }
            }
        }

        let mut field_tables = Vec::new();
        for ty in FieldType::ALL {
            let own = fields.remove(&ty).ok_or_else(|| RulesError::Missing {
                table: ty.rule_name().to_owned(),
                what: "field type",
            })?;
            let mut table = FieldTable {
                ty,
                clues: own.clues,
                autocomplete: own.autocomplete,
                elements: own.elements,
                input_modes: own.input_modes,
            };
            for name in &own.include {
                let inc = shared.get(name).ok_or_else(|| RulesError::Unknown {
                    file: format!("fields/{}.toml", ty.rule_name()),
                    what: "include",
                    value: name.clone(),
                })?;
                table.clues.extend(inc.clues.iter().cloned());
                table.autocomplete.extend(inc.autocomplete.iter().cloned());
                table.elements.extend(inc.elements.iter().cloned());
                table.input_modes.extend(inc.input_modes.iter().cloned());
            }
            check_duplicates(ty.rule_name(), &table.clues)?;
            field_tables.push(table);
        }

        let mut form_tables = Vec::new();
        for kind in FormKind::SCORED {
            let own = forms.remove(&kind).ok_or_else(|| RulesError::Missing {
                table: kind.rule_name().to_owned(),
                what: "form kind",
            })?;
            check_duplicates(kind.rule_name(), &own.clues)?;
            form_tables.push(FormTable {
                kind,
                clues: own.clues,
            });
        }

        let field_matcher = Matcher::build(field_tables.iter().map(|t| t.clues.as_slice()))?;
        let form_matcher = Matcher::build(form_tables.iter().map(|t| t.clues.as_slice()))?;
        Ok(Rules {
            fields: field_tables,
            forms: form_tables,
            field_matcher,
            form_matcher,
        })
    }

    pub fn field_table(&self, ty: FieldType) -> &FieldTable {
        &self.fields[ty as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_load() {
        let rules = Rules::embedded().unwrap();
        assert_eq!(rules.fields.len(), FieldType::ALL.len());
        assert_eq!(rules.forms.len(), FormKind::SCORED.len());
        for (i, t) in rules.fields.iter().enumerate() {
            assert_eq!(t.ty as usize, i);
        }
    }

    #[test]
    fn every_entry_has_a_why() {
        // Loading already enforces it; this checks the raw files directly too.
        for (file, source) in FILES {
            let raw: RawFile = toml::from_str(source).unwrap();
            for c in &raw.clue {
                assert!(!c.why.trim().is_empty(), "{file}: {} has no why", c.phrase);
            }
            for t in &raw.autocomplete {
                assert!(!t.why.trim().is_empty(), "{file}: {} has no why", t.token);
            }
            for e in &raw.element {
                assert!(!e.why.trim().is_empty(), "{file}: {} has no why", e.element);
            }
            for m in &raw.inputmode {
                assert!(!m.why.trim().is_empty(), "{file}: {} has no why", m.mode);
            }
        }
    }

    #[test]
    fn missing_why_is_rejected() {
        let files = [(
            "forms/x.toml",
            "kind = \"login\"\n[[clue]]\nphrase = \"sign in\"\nscore = 3\n",
        )];
        assert!(matches!(
            parse_file(files[0].0, files[0].1),
            Err(RulesError::MissingWhy { .. })
        ));
    }

    #[test]
    fn no_duplicate_phrases_per_table() {
        let rules = Rules::embedded().unwrap();
        for t in &rules.fields {
            check_duplicates(t.ty.rule_name(), &t.clues).unwrap();
        }
        for t in &rules.forms {
            check_duplicates(t.kind.rule_name(), &t.clues).unwrap();
        }
        let dup = "kind = \"login\"\n[[clue]]\nphrase = \"Sign in\"\nscore = 3\nwhy = \"a\"\n[[clue]]\nphrase = \"sign-in\"\nscore = 1\nwhy = \"b\"\n";
        let (_, parts) = parse_file("forms/login.toml", dup).unwrap();
        assert!(matches!(
            check_duplicates("login", &parts.clues),
            Err(RulesError::Duplicate { .. })
        ));
    }

    #[test]
    fn same_phrase_on_separate_channels_is_allowed() {
        let ok = "kind = \"login\"\n[[clue]]\nphrase = \"login\"\nscore = 3\nchannel = \"display\"\nwhy = \"a\"\n[[clue]]\nphrase = \"login\"\nscore = 2\nchannel = \"code\"\nwhy = \"b\"\n";
        let (_, parts) = parse_file("forms/login.toml", ok).unwrap();
        check_duplicates("login", &parts.clues).unwrap();
    }

    #[test]
    fn token_wildcards_match_prefixes() {
        let w = TokenWeight {
            id: String::new(),
            token: "cc-*".into(),
            score: -6,
        };
        assert!(w.matches("cc-number"));
        assert!(!w.matches("current-password"));
    }
}
