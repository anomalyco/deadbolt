//! Import: maps another password manager's export to deadbolt items. The
//! agent runs it for `Command::Import`; the format is detected from the
//! text: Bitwarden's JSON, 1Password's 1PUX `export.data` or CSV, Apple
//! Passwords' CSV, or any CSV with recognizable columns.
//!
//! Everything is mapped and validated before anything is written. Nothing
//! here prints a field value: JSON is parsed untyped so parse errors cannot
//! quote it, CSV errors name only a position, and problems are only counted.
//! Duplicates are left to the agent, which knows what the vault holds.

mod bitwarden;
mod csv;
pub mod onepassword;
pub mod op;
pub mod tags;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use deadbolt_core::item::{check_create, check_field, check_new_value, valid_item_name};
use deadbolt_core::{Field, FieldType, Schema, Source, schema};
use serde_json::Value;

use crate::items::with_scheme;
use crate::protocol::{ExportFile, ImportReport, ImportSource, Tally};

/// What every "not an export" error ends with.
const SUPPORTED: &str = "import a 1Password .1pux or .csv, an Apple Passwords or browser .csv, or a Bitwarden .json export";

/// An item to create.
pub struct Imported {
    pub kind: &'static str,
    pub name: Option<String>,
    pub fields: BTreeMap<String, Field>,
    pub favorite: bool,
    pub tags: BTreeSet<String>,
    /// Where it came from, for an export that says (1Password's).
    pub source: Option<Source>,
    /// For a login that signs in with another (`sign-in-with`), the
    /// 1Password item that one is, by vault and item id as in its source id
    /// ([`onepassword::source_key`]). The agent links it at import, as
    /// `sign-in-account`, once that item is here.
    pub sign_in_link: Option<(String, String)>,
}

impl Imported {
    pub fn digest(&self) -> String {
        digest(
            self.kind,
            self.name.as_deref(),
            &self.fields,
            self.favorite,
            &self.tags,
        )
    }
}

/// How an item here came to be a copy of a 1Password item, which says what
/// a sync may do with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {
    /// Added by a sync, which deletes it once it is gone from 1Password.
    Sync,
    /// Made here or imported, then taken over by a sync, which releases it
    /// once it is gone from 1Password.
    Adopted,
    /// Imported from a .1pux and not mirrored: only a record of where it
    /// came from, so a sync can take it over rather than add it again.
    Import,
}

/// A 1Password copy's version: when the original last changed (Unix
/// seconds), a digest of the item as last written here, and its
/// [`Origin`]. A sync compares the time with the original's and the digest
/// with the item's own, to leave alone, without fetching it, an item that
/// changed on neither side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorVersion {
    pub updated: i64,
    pub digest: String,
    pub origin: Origin,
    /// For an item taken over, the fields 1Password last wrote: a later
    /// sync removes those 1Password no longer has, and keeps the rest,
    /// which are the item's own.
    pub fields: BTreeSet<String>,
    /// For an item taken over, the case-folded tags 1Password last wrote:
    /// a later sync removes those 1Password deleted and leaves Deadbolt-only
    /// tags untouched.
    pub tags: BTreeSet<String>,
}

impl MirrorVersion {
    /// Whether a sync keeps it up to date.
    pub fn mirrored(&self) -> bool {
        self.origin != Origin::Import
    }

    /// `updated:digest`, then `:import`, or `:adopted:` and the fields'
    /// names joined by commas (followed optionally by `:` and unpadded
    /// base64url folded tags joined by commas), unless a sync added it.
    pub fn parse(version: &str) -> Option<Self> {
        let mut parts = version.split(':');
        let updated = parts.next()?.parse().ok()?;
        let digest = parts.next()?.to_string();
        let mut fields = BTreeSet::new();
        let mut tags = BTreeSet::new();
        let origin = match parts.next() {
            None => Origin::Sync,
            Some("adopted") => {
                let names = parts.next()?;
                fields.extend(names.split(',').filter(|n| !n.is_empty()).map(String::from));
                if let Some(encoded_tags) = parts.next() {
                    for part in encoded_tags.split(',').filter(|s| !s.is_empty()) {
                        let bytes = data_encoding::BASE64URL_NOPAD
                            .decode(part.as_bytes())
                            .ok()?;
                        tags.insert(String::from_utf8(bytes).ok()?);
                    }
                }
                Origin::Adopted
            }
            Some("import") => Origin::Import,
            Some(_) => return None,
        };
        parts.next().is_none().then_some(Self {
            updated,
            digest,
            origin,
            fields,
            tags,
        })
    }
}

impl std::fmt::Display for MirrorVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.updated, self.digest)?;
        match self.origin {
            Origin::Sync => Ok(()),
            Origin::Adopted => {
                let names: Vec<&str> = self.fields.iter().map(String::as_str).collect();
                write!(f, ":adopted:{}", names.join(","))?;
                if !self.tags.is_empty() {
                    let encoded: Vec<String> = self
                        .tags
                        .iter()
                        .map(|t| data_encoding::BASE64URL_NOPAD.encode(t.as_bytes()))
                        .collect();
                    write!(f, ":{}", encoded.join(","))?;
                }
                Ok(())
            }
            Origin::Import => f.write_str(":import"),
        }
    }
}

/// The digest part of a [`MirrorVersion`].
pub fn digest(
    kind: &str,
    name: Option<&str>,
    fields: &BTreeMap<String, Field>,
    favorite: bool,
    tags: &BTreeSet<String>,
) -> String {
    let mut h = blake3::Hasher::new_derive_key("deadbolt 2026-10-30 mirror digest v2");
    fn put(h: &mut blake3::Hasher, s: &str) {
        h.update(&(s.len() as u64).to_le_bytes());
        h.update(s.as_bytes());
    }
    put(&mut h, kind);
    put(&mut h, name.unwrap_or_default());
    for (field, value) in fields {
        put(&mut h, field);
        put(&mut h, value.kind.as_str());
        put(&mut h, &value.value);
    }
    h.update(&[u8::from(favorite)]);
    h.update(&(tags.len() as u64).to_le_bytes());
    for tag in tags {
        put(&mut h, tag);
    }
    h.finalize().to_hex()[..32].to_string()
}

/// Maps an export to items to create, and what was left out.
#[cfg(test)]
pub fn parse(text: &str) -> Result<(Vec<Imported>, ImportReport)> {
    parse_with(text, &[])
}

/// Maps an export, with the attachments that came beside its text (a
/// `.1pux`'s, see `deadbolt_client::export`).
pub fn parse_with(text: &str, files: &[ExportFile]) -> Result<(Vec<Imported>, ImportReport)> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let start = text.trim_start();
    if start.is_empty() {
        bail!("the export is empty");
    }
    let (items, summary) = if start.starts_with(['{', '[']) {
        // Untyped first: serde's typed errors could quote values from the file.
        let export: Value = serde_json::from_str(text).map_err(|e| {
            anyhow!(
                "not a JSON file (line {} column {}); {SUPPORTED}",
                e.line(),
                e.column()
            )
        })?;
        if export.get("accounts").is_some() {
            onepassword::export(&export, files)?
        } else if export.get("items").is_some() || export.get("encrypted").is_some() {
            bitwarden::export(&export)?
        } else {
            bail!("not a known JSON export; {SUPPORTED}");
        }
    } else {
        csv::export(text)?
    };
    Ok((items, summary.report()))
}

/// What a mapping did besides producing items.
pub struct Summary {
    source: ImportSource,
    new: BTreeMap<String, usize>,
    skipped: BTreeMap<Reason, usize>,
    warnings: BTreeMap<Reason, usize>,
    dropped: BTreeMap<Reason, usize>,
}

/// A reason, singular and plural.
type Reason = (&'static str, &'static str);

const BANK_ACCOUNT: Reason = ("bank account", "bank accounts");
const DRIVERS_LICENSE: Reason = ("driver's license", "driver's licenses");
const PASSPORT: Reason = ("passport", "passports");
const UNKNOWN_TYPE: Reason = ("item of unknown type", "items of unknown type");
const ARCHIVED: Reason = ("archived item", "archived items");
const NO_PRIVATE_KEY: Reason = (
    "SSH key without a private key",
    "SSH keys without a private key",
);
const EMPTY: Reason = ("empty item", "empty items");
const NO_NUMBER: Reason = (
    "card without a valid number",
    "cards without a valid number",
);
const BAD_CVV: Reason = (
    "invalid card code (cvv) kept as an extra field",
    "invalid card codes (cvv) kept as extra fields",
);
const BAD_OTP: Reason = (
    "one-time password that is not a TOTP secret kept as an extra field",
    "one-time passwords that are not TOTP secrets kept as extra fields",
);
const BAD_EXPIRY: Reason = (
    "invalid card expiry kept as an extra field",
    "invalid card expiries kept as extra fields",
);
const BAD_EMAIL: Reason = (
    "invalid email address kept as text",
    "invalid email addresses kept as text",
);
const BAD_BIRTHDAY: Reason = (
    "invalid birthday kept as text",
    "invalid birthdays kept as text",
);
const BAD_COUNTRY: Reason = (
    "country that is not an ISO code kept as an extra field",
    "countries that are not ISO codes kept as extra fields",
);
const URL_AS_TEXT: Reason = (
    "URL that is not an absolute URL kept as text",
    "URLs that are not absolute URLs kept as text",
);
const INVALID: Reason = (
    "item that could not be imported",
    "items that could not be imported",
);
const ATTACHMENT: Reason = ("attachment", "attachments");
const MISSING_ATTACHMENT: Reason = (
    "attachment missing from the export",
    "attachments missing from the export",
);
const BIG_ATTACHMENT: Reason = (
    "attachment over the 10 MiB an item's files hold",
    "attachments over the 10 MiB an item's files hold",
);
const MISSING_FILE: Reason = (
    "document whose file is missing from the export",
    "documents whose files are missing from the export",
);
const BIG_FILE: Reason = (
    "document whose file is over 10 MiB",
    "documents whose files are over 10 MiB",
);
const BAD_VALUE: Reason = (
    "value that doesn't fit its field kept as an extra field",
    "values that don't fit their fields kept as extra fields",
);
const PASSWORD_HISTORY: Reason = ("item's password history", "items' password history");
const PASSKEYS: Reason = ("item's passkeys", "items' passkeys");
const LINKED_FIELD: Reason = ("linked field", "linked fields");
const COLUMN: Reason = ("unrecognized column", "unrecognized columns");

impl Summary {
    fn new(source: ImportSource) -> Self {
        Self {
            source,
            new: BTreeMap::new(),
            skipped: BTreeMap::new(),
            warnings: BTreeMap::new(),
            dropped: BTreeMap::new(),
        }
    }

    fn skip(&mut self, reason: Reason) {
        *self.skipped.entry(reason).or_default() += 1;
    }

    fn warn(&mut self, reason: Reason) {
        *self.warnings.entry(reason).or_default() += 1;
    }

    fn drop_some(&mut self, reason: Reason, n: usize) {
        if n > 0 {
            *self.dropped.entry(reason).or_default() += n;
        }
    }

    /// Adds another summary's counts to these.
    fn merge(&mut self, other: Summary) {
        let add = |to: &mut BTreeMap<Reason, usize>, from: BTreeMap<Reason, usize>| {
            for (reason, n) in from {
                *to.entry(reason).or_default() += n;
            }
        };
        for (kind, n) in other.new {
            *self.new.entry(kind).or_default() += n;
        }
        add(&mut self.skipped, other.skipped);
        add(&mut self.warnings, other.warnings);
        add(&mut self.dropped, other.dropped);
    }

    /// Why an item was skipped, for a summary of that one item.
    fn skip_reason(&self) -> Option<&'static str> {
        self.skipped.keys().next().map(|(one, _)| *one)
    }

    /// Counts a mapped item.
    fn add(&mut self, item: &Imported) {
        *self.new.entry(item.kind.into()).or_default() += 1;
    }

    fn report(self) -> ImportReport {
        let tallies = |map: BTreeMap<Reason, usize>| {
            map.into_iter()
                .map(|((one, many), count)| Tally {
                    count,
                    one: one.into(),
                    many: many.into(),
                })
                .collect()
        };
        ImportReport {
            source: self.source,
            new: self.new,
            duplicates: 0,
            skipped: tallies(self.skipped),
            warnings: tallies(self.warnings),
            dropped: tallies(self.dropped),
            sign_in: Default::default(),
        }
    }
}

/// A JSON scalar as text; numbers and booleans too. Blank is `None`.
fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// A string value; numbers and booleans as text. Blank and missing are `None`.
fn text(value: &Value, key: &str) -> Option<String> {
    scalar(value.get(key)?)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn number(value: &Value, key: &str) -> Option<i64> {
    match value.get(key)? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// A field name from another app as a deadbolt field name: lowercase
/// ASCII letters, digits, `-` and `_`, starting with a letter, at most 64.
pub fn field_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' {
            out.push(c);
        } else if (c.is_whitespace() || c.is_ascii_punctuation()) && !out.ends_with('-') {
            out.push('-');
        }
    }
    let out = out.trim_matches('-');
    let out = match out.chars().next() {
        None => "field".to_string(),
        Some(c) if c.is_ascii_lowercase() => out.to_string(),
        Some(_) => format!("field-{out}"),
    };
    truncate(&out, 64)
}

fn truncate(name: &str, max: usize) -> String {
    name[..name.len().min(max)]
        .trim_end_matches('-')
        .to_string()
}

/// `base`, else `base-2`, `base-3`, ... whichever is not taken; the taken
/// set includes every field of the item's schema.
#[expect(
    clippy::expect_used,
    reason = "the finite set of imported fields cannot exhaust numeric suffixes"
)]
fn unique(base: &str, taken: &BTreeSet<String>) -> String {
    if !taken.contains(base) {
        return base.to_string();
    }
    (2..)
        .map(|n| {
            let suffix = format!("-{n}");
            format!("{}{suffix}", truncate(base, 64 - suffix.len()))
        })
        .find(|name| !taken.contains(name))
        .expect("some suffix is free")
}

/// An item label: control characters become spaces, at most 128 characters.
fn item_name(name: Option<String>) -> Option<String> {
    let name: String = name?
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(128)
        .collect();
    let name = name.trim().to_string();
    valid_item_name(&name).then_some(name)
}

/// The non-blank parts, trimmed and joined by `sep`; `None` if all are blank.
fn join(parts: impl IntoIterator<Item = Option<String>>, sep: &str) -> Option<String> {
    let parts: Vec<String> = parts
        .into_iter()
        .flatten()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    (!parts.is_empty()).then(|| parts.join(sep))
}

/// A postal address as lines: the street lines, "city, region postcode",
/// then the country.
fn address(
    street: impl IntoIterator<Item = Option<String>>,
    city: Option<String>,
    region: Option<String>,
    postcode: Option<String>,
    country: Option<String>,
) -> Option<String> {
    let town = join([city, join([region, postcode], " ")], ", ");
    join(street.into_iter().chain([town, country]), "\n")
}

/// `M/YY`, `MM/YYYY` and the like as `YYYY-MM`, if they form one.
fn month(month: &str, year: &str) -> Option<String> {
    let month = month.trim();
    let m = month
        .parse::<u8>()
        .ok()
        .filter(|m| (1..=12).contains(m) && month.bytes().all(|b| b.is_ascii_digit()))?;
    crate::items::format_month(m, year)
}

#[expect(clippy::expect_used, reason = "login is a built-in schema")]
fn url_field(uri: &str) -> Field {
    let field = Field::new(FieldType::Url, with_scheme(uri.to_string()));
    let login = schema("login").expect("built-in type");
    if check_field(login, "url", &field).is_ok() {
        field
    } else {
        Field::new(FieldType::Text, uri)
    }
}

fn valid(schema: &Schema, name: &str, field: &Field) -> bool {
    check_field(schema, name, field).is_ok() && check_new_value(name, field).is_ok()
}

/// Builds one item's fields, naming extras so they never collide.
/// Blank values are left out everywhere: deadbolt has no empty fields.
struct Builder {
    schema: &'static Schema,
    fields: BTreeMap<String, Field>,
    /// URL values already added, so each is added once.
    urls: BTreeSet<String>,
}

impl Builder {
    #[expect(clippy::expect_used, reason = "callers pass only built-in item types")]
    fn new(kind: &str) -> Self {
        let schema = schema(kind).expect("built-in type");
        Self {
            schema,
            fields: BTreeMap::new(),
            urls: BTreeSet::new(),
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "mapping code passes known fields of its built-in schema"
    )]
    fn kind(&self, name: &str) -> FieldType {
        self.schema.field(name).expect("known field").kind.clone()
    }

    /// Whether every required field of the type has a value.
    fn has_required(&self) -> bool {
        self.schema
            .fields
            .iter()
            .filter(|f| f.required)
            .all(|f| self.fields.contains_key(f.name))
    }

    /// The bytes the item's files hold so far.
    fn file_bytes(&self) -> usize {
        self.fields
            .values()
            .filter(|f| f.kind == FieldType::File)
            .filter_map(|f| deadbolt_core::item::file_parts(&f.value).1)
            .filter_map(deadbolt_core::item::file_size)
            .sum()
    }

    /// Sets a known field; `false` if the value is invalid for it. If the
    /// field is already set, the value becomes an extra field instead.
    fn known(&mut self, name: &str, value: Option<String>) -> bool {
        let Some(value) = value.filter(|v| !v.trim().is_empty()) else {
            return true;
        };
        let mut field = Field::new(self.kind(name), value);
        if !valid(self.schema, name, &field) {
            return false;
        }
        if self.fields.contains_key(name) {
            self.extra(name, field.kind.clone(), std::mem::take(&mut field.value));
        } else {
            self.fields.insert(name.into(), field);
        }
        true
    }

    /// Sets a known field, or keeps a value that is invalid for it as an
    /// extra field, with a warning: an import never drops a value silently.
    fn known_or_extra(
        &mut self,
        name: &str,
        value: Option<String>,
        reason: Reason,
        summary: &mut Summary,
    ) {
        let Some(value) = value.filter(|v| !v.trim().is_empty()) else {
            return;
        };
        if !self.known(name, Some(value.clone())) {
            let kind = if self.kind(name).is_secret() {
                FieldType::Secret
            } else {
                FieldType::Text
            };
            self.extra(name, kind, value);
            summary.warn(reason);
        }
    }

    /// Adds an extra field under a free name based on `base`. A value that
    /// isn't valid for `kind` becomes secret or text. A `base` naming one of
    /// the schema's fields that is still unset fills it if the value is valid
    /// there and no less secret; otherwise the schema's names stay free for
    /// its own fields.
    fn extra(&mut self, base: &str, kind: FieldType, value: String) {
        if value.trim().is_empty() {
            return;
        }
        if let Some(known) = self.schema.field(base)
            && !self.fields.contains_key(base)
            && (known.kind == kind || known.kind.is_secret())
        {
            let field = Field::new(known.kind.clone(), value.clone());
            if valid(self.schema, base, &field) {
                self.fields.insert(base.into(), field);
                return;
            }
        }
        let taken: BTreeSet<String> = self
            .fields
            .keys()
            .cloned()
            .chain(self.schema.fields.iter().map(|f| f.name.to_string()))
            .collect();
        let name = unique(base, &taken);
        let mut field = Field::new(kind, value);
        // Only `otp` gives codes, so an extra one-time password is a secret.
        if field.kind == FieldType::Otp || !valid(self.schema, &name, &field) {
            field.kind = if field.kind.is_secret() {
                FieldType::Secret
            } else {
                FieldType::Text
            };
        }
        self.fields.insert(name, field);
    }

    /// An identity's postal address in its parts: the street's lines (each
    /// value may hold several) as `address-line1` to `address-line3`, the
    /// fourth line on joined to the third, the country as its ISO code, or
    /// kept as an extra field with a warning.
    fn postal_address(
        &mut self,
        street: impl IntoIterator<Item = Option<String>>,
        [city, region, postcode, country]: [Option<String>; 4],
        summary: &mut Summary,
    ) {
        let lines: Vec<String> = street
            .into_iter()
            .flatten()
            .flat_map(|s| s.lines().map(|l| l.trim().to_string()).collect::<Vec<_>>())
            .filter(|l| !l.is_empty())
            .collect();
        for (i, name) in ["address-line1", "address-line2"].iter().enumerate() {
            self.known(name, lines.get(i).cloned());
        }
        self.known(
            "address-line3",
            join(lines.iter().skip(2).cloned().map(Some), ", "),
        );
        self.known("city", city);
        self.known("region", region);
        self.known("postal-code", postcode);
        let country = country.map(|c| deadbolt_core::item::country(&c).map_or(c, str::to_string));
        self.known_or_extra("country", country, BAD_COUNTRY, summary);
    }

    /// An identity's phone, in E.164 form when it reads as international.
    fn phone(&mut self, value: Option<String>) {
        let value = value.map(|v| deadbolt_core::item::phone(&v).unwrap_or(v));
        if !self.known("phone", value.clone()) {
            self.extra("phone", FieldType::Text, value.unwrap_or_default());
        }
    }

    /// The first absolute URL is `url`; the others are `url-2`, `url-3`,
    /// ... of type url, or text if they are not absolute URLs. A URL
    /// already added is left out.
    fn urls(&mut self, uris: impl IntoIterator<Item = String>, summary: &mut Summary) {
        for uri in uris {
            let uri = uri.trim();
            if uri.is_empty() {
                continue;
            }
            let mut field = url_field(uri);
            if !self.urls.insert(field.value.clone()) {
                continue;
            }
            if field.kind != FieldType::Url {
                summary.warn(URL_AS_TEXT);
            } else if !self.fields.contains_key("url") {
                self.fields.insert("url".into(), field);
                continue;
            }
            self.extra("url", field.kind.clone(), std::mem::take(&mut field.value));
        }
    }

    /// The item, or `None`, counted, if it is still not valid: one bad
    /// item never stops the others.
    fn finish(
        self,
        kind: &'static str,
        name: Option<String>,
        summary: &mut Summary,
    ) -> Option<Imported> {
        if self.fields.is_empty() && name.is_none() {
            summary.skip(EMPTY);
            return None;
        }
        if check_create(kind, name.as_deref(), &self.fields, None).is_err() {
            summary.skip(INVALID);
            return None;
        }
        Some(Imported {
            kind,
            name,
            fields: self.fields,
            favorite: false,
            tags: BTreeSet::new(),
            source: None,
            sign_in_link: None,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An item's fields as (name, type, value), sorted by name.
    pub fn fields(item: &Imported) -> Vec<(&str, &str, &str)> {
        item.fields
            .iter()
            .map(|(name, f)| (name.as_str(), f.kind.as_str(), f.value.as_str()))
            .collect()
    }

    pub fn lines(report: &ImportReport) -> Vec<String> {
        report.lines(true)
    }

    #[test]
    fn sanitizes_field_names() {
        for (name, expected) in [
            ("Recovery Code", "recovery-code"),
            ("  API--Key!! ", "api-key"),
            ("snake_case", "snake_case"),
            ("2FA", "field-2fa"),
            ("_x", "field-_x"),
            ("Pässwort", "psswort"),
            ("???", "field"),
            ("", "field"),
        ] {
            assert_eq!(field_name(name), expected, "{name:?}");
        }
        let long = field_name(&"a".repeat(100));
        assert_eq!(long.len(), 64);
        assert_eq!(field_name(&format!("{}-b", "a".repeat(63))), "a".repeat(63));
    }

    #[test]
    fn avoids_collisions() {
        let taken: BTreeSet<String> = ["password", "x", "x-2"].map(String::from).into();
        assert_eq!(unique("password", &taken), "password-2");
        assert_eq!(unique("x", &taken), "x-3");
        assert_eq!(unique("y", &taken), "y");
        let long = "a".repeat(64);
        let taken: BTreeSet<String> = [long.clone()].into();
        assert_eq!(unique(&long, &taken), format!("{}-2", "a".repeat(62)));
    }

    #[test]
    fn addresses() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(
            address(
                [s("1 Main St"), s(" "), s("Apt 2")],
                s("Springfield"),
                s("IL"),
                s("12345"),
                s("US")
            ),
            s("1 Main St\nApt 2\nSpringfield, IL 12345\nUS")
        );
        assert_eq!(address([None], None, None, s("12345"), None), s("12345"));
        assert_eq!(address([s("")], None, s(" "), None, None), None);
    }

    #[test]
    fn months() {
        assert_eq!(month("4", "27"), Some("2027-04".into()));
        assert_eq!(month(" 04 ", " 2031 "), Some("2031-04".into()));
        for (m, y) in [("13", "2031"), ("+1", "2031"), ("1", "203"), ("x", "27")] {
            assert_eq!(month(m, y), None, "{m}/{y}");
        }
    }

    #[test]
    fn detects_the_format_or_says_what_is_supported() {
        let source = |text: &str| parse(text).unwrap().1.source;
        assert_eq!(
            source(r#"{"encrypted": false, "items": []}"#),
            ImportSource::Bitwarden
        );
        assert_eq!(source(r#"{"accounts": []}"#), ImportSource::OnePassword);
        assert_eq!(
            source("\u{feff}Title,URL,Username,Password,Notes,OTPAuth\n"),
            ImportSource::ApplePasswords
        );
        assert_eq!(
            source("Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n"),
            ImportSource::OnePassword
        );
        assert_eq!(
            source("name,url,username,password,note\n"),
            ImportSource::Csv
        );
        for garbage in [
            "",
            "  \n",
            "hunter2-garbage",
            "hunter2,swordfish\nx,y\n",
            r#"{"hunter2": 1}"#,
            r#"{"items": [{"login": {"password": "hunter2"#,
            "[1, 2]",
        ] {
            let error = format!("{:#}", parse(garbage).err().unwrap());
            assert!(!error.contains("hunter2"), "{error}");
            assert!(
                error.contains("empty") || error.contains(SUPPORTED),
                "{garbage:?}: {error}"
            );
        }
    }

    #[test]
    fn urls_never_overwrite_or_repeat() {
        let mut summary = Summary::new(ImportSource::Csv);
        let mut b = Builder::new("card");
        b.known("number", Some("4242424242424242".into()));
        b.urls(
            ["https://a.example".into(), "b.example".into()],
            &mut summary,
        );
        b.urls(
            ["a.example".into(), " https://b.example ".into()],
            &mut summary,
        );
        let item = b.finish("card", None, &mut summary).unwrap();
        assert_eq!(
            fields(&item),
            [
                ("number", "secret", "4242424242424242"),
                ("url", "url", "https://a.example"),
                ("url-2", "url", "https://b.example"),
            ]
        );
    }

    #[test]
    fn an_item_that_is_still_invalid_is_skipped_and_counted() {
        let mut summary = Summary::new(ImportSource::Csv);
        assert!(
            Builder::new("card")
                .finish("card", Some("Visa".into()), &mut summary)
                .is_none()
        );
        assert!(
            Builder::new("note")
                .finish("note", None, &mut summary)
                .is_none()
        );
        assert_eq!(
            lines(&summary.report())[1..],
            [
                "skipped 1 empty item",
                "skipped 1 item that could not be imported"
            ]
        );
    }

    #[test]
    fn keeps_invalid_known_values_as_extra_fields() {
        let mut summary = Summary::new(ImportSource::Csv);
        let mut b = Builder::new("card");
        b.known("number", Some("4242424242424242".into()));
        b.known_or_extra("cvv", Some("12x".into()), BAD_CVV, &mut summary);
        b.known_or_extra("expiry", Some("13/2031".into()), BAD_EXPIRY, &mut summary);
        b.known_or_extra("cvv", Some("123".into()), BAD_CVV, &mut summary);
        b.extra("valid-from", FieldType::Month, "not a month".into());
        let item = b.finish("card", None, &mut summary).unwrap();
        assert_eq!(
            fields(&item),
            [
                ("cvv", "secret", "123"),
                ("cvv-2", "secret", "12x"),
                ("expiry-2", "text", "13/2031"),
                ("number", "secret", "4242424242424242"),
                ("valid-from", "text", "not a month"),
            ]
        );
        assert_eq!(
            lines(&summary.report())[1..],
            [
                "warning: 1 invalid card code (cvv) kept as an extra field",
                "warning: 1 invalid card expiry kept as an extra field",
            ]
        );
    }

    #[test]
    fn keeps_extra_and_non_totp_one_time_passwords_as_secrets() {
        let mut summary = Summary::new(ImportSource::Csv);
        let mut b = Builder::new("login");
        b.known("password", Some("pw".into()));
        let hotp = "otpauth://hotp/Site?secret=JBSWY3DPEHPK3PXP&counter=3";
        b.known_or_extra("otp", Some(hotp.into()), BAD_OTP, &mut summary);
        b.known_or_extra(
            "otp",
            Some("jbsw y3dp ehpk 3pxp".into()),
            BAD_OTP,
            &mut summary,
        );
        b.extra("backup", FieldType::Otp, "not base32!".into());
        // A valid one too: only `otp` gives codes.
        b.extra("spare", FieldType::Otp, "KRSXG5CTMVRXEZLU".into());
        let item = b.finish("login", None, &mut summary).unwrap();
        assert_eq!(
            fields(&item),
            [
                ("backup", "secret", "not base32!"),
                ("otp", "otp", "jbsw y3dp ehpk 3pxp"),
                ("otp-2", "secret", hotp),
                ("password", "secret", "pw"),
                ("spare", "secret", "KRSXG5CTMVRXEZLU"),
            ]
        );
        assert_eq!(
            lines(&summary.report())[1..],
            ["warning: 1 one-time password that is not a TOTP secret kept as an extra field"]
        );
    }
}
