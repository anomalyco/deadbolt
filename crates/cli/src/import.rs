//! `deadbolt import bitwarden`: maps Bitwarden's unencrypted JSON export
//! (`{encrypted, folders[], items[]}`, see bitwarden/clients
//! `libs/common/src/models/export`) to deadbolt items.
//!
//! Everything is mapped and validated before anything is written, and the
//! agent creates all items or none. Nothing here prints a field value: the
//! export is parsed as untyped JSON so parse errors cannot quote it, and
//! problems are only counted. There is no deduplication; importing the same
//! export twice creates every item twice.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::Subcommand;
use deadbolt_core::item::{check_create, check_field, valid_item_name};
use deadbolt_core::{Field, FieldType, Schema, schema};
use serde_json::Value;

use crate::items::{format_month, with_scheme};
use crate::paths::Paths;
use crate::protocol::{Command, FieldInput, NewItem, Reply};

#[derive(Subcommand)]
pub enum ImportCommand {
    /// Import Bitwarden's unencrypted JSON export (web vault: Tools > Export
    /// vault > .json). Imports logins and cards; other item types, folders,
    /// favorites, attachments and password history are skipped and counted.
    /// Re-running imports everything again (no deduplication).
    Bitwarden {
        /// The export file; stdin if omitted or `-`.
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
    },
}

pub async fn run(
    paths: &Paths,
    command: ImportCommand,
    vault: Option<String>,
    from_stdin: bool,
) -> Result<()> {
    let ImportCommand::Bitwarden { file } = command;
    let text = match file.filter(|f| f.as_os_str() != "-") {
        Some(file) => {
            std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?
        }
        None => {
            if std::io::stdin().is_terminal() {
                bail!("pass the export file, or pipe it on stdin");
            }
            if from_stdin {
                bail!("--passphrase-stdin cannot be used when the export comes from stdin");
            }
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .context("reading stdin")?;
            text
        }
    };
    let (items, summary) = bitwarden(&text)?;
    let reply = if items.is_empty() {
        None
    } else {
        Some(crate::request(paths, Command::ItemImport { vault, items }, from_stdin).await?)
    };
    match reply {
        None | Some(Reply::Done) => {}
        Some(_) => bail!("unexpected reply"),
    }
    for line in summary.lines() {
        println!("{line}");
    }
    Ok(())
}

/// What an import did besides creating items.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub logins: usize,
    pub cards: usize,
    /// Items not imported, by reason.
    pub skipped: BTreeMap<Reason, usize>,
    /// Values not imported or imported differently, by reason.
    pub warnings: BTreeMap<Reason, usize>,
    pub folders: usize,
    pub collections: usize,
    pub favorites: usize,
    pub attachments: usize,
    pub password_history: usize,
    pub passkeys: usize,
    pub linked_fields: usize,
}

/// A reason, singular and plural.
type Reason = (&'static str, &'static str);

const SECURE_NOTE: Reason = ("secure note", "secure notes");
const IDENTITY: Reason = ("identity", "identities");
const SSH_KEY: Reason = ("ssh key", "ssh keys");
const BANK_ACCOUNT: Reason = ("bank account", "bank accounts");
const DRIVERS_LICENSE: Reason = ("driver's license", "driver's licenses");
const PASSPORT: Reason = ("passport", "passports");
const UNKNOWN_TYPE: Reason = ("item of unknown type", "items of unknown type");
const NO_PASSWORD: Reason = ("login without password", "logins without password");
const NO_NUMBER: Reason = (
    "card without a valid number",
    "cards without a valid number",
);
const BAD_CVV: Reason = (
    "invalid card code (cvv) left out",
    "invalid card codes (cvv) left out",
);
const BAD_EXPIRY: Reason = (
    "invalid card expiry left out",
    "invalid card expiries left out",
);
const URL_AS_TEXT: Reason = (
    "URL that is not an absolute URL kept as text",
    "URLs that are not absolute URLs kept as text",
);

fn count(n: usize, (one, many): Reason) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

impl Summary {
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "imported {} (logins {}, cards {})",
            self.logins + self.cards,
            self.logins,
            self.cards
        )];
        for (what, n) in &self.skipped {
            lines.push(format!("skipped {}", count(*n, *what)));
        }
        for (what, n) in &self.warnings {
            lines.push(format!("warning: {}", count(*n, *what)));
        }
        let on_items = |n: usize| format!("on {}", count(n, ("item", "items")));
        let dropped: Vec<String> = [
            (self.folders, count(self.folders, ("folder", "folders"))),
            (
                self.collections,
                count(self.collections, ("collection", "collections")),
            ),
            (
                self.favorites,
                count(self.favorites, ("favorite", "favorites")),
            ),
            (
                self.attachments,
                count(self.attachments, ("attachment", "attachments")),
            ),
            (
                self.password_history,
                format!("password history {}", on_items(self.password_history)),
            ),
            (
                self.passkeys,
                format!("passkeys {}", on_items(self.passkeys)),
            ),
            (
                self.linked_fields,
                count(self.linked_fields, ("linked field", "linked fields")),
            ),
        ]
        .into_iter()
        .filter(|(n, _)| *n > 0)
        .map(|(_, text)| text)
        .collect();
        if !dropped.is_empty() {
            lines.push(format!("dropped: {}", dropped.join(", ")));
        }
        lines
    }
}

/// A string value; numbers and booleans as text. Empty and missing are `None`.
fn text(value: &Value, key: &str) -> Option<String> {
    match value.get(key)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
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

/// A Bitwarden custom field name as a deadbolt field name: lowercase
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
fn item_name(item: &Value) -> Option<String> {
    let name: String = text(item, "name")?
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(128)
        .collect();
    let name = name.trim().to_string();
    valid_item_name(&name).then_some(name)
}

/// `expMonth`/`expYear` as `YYYY-MM`. `None` if either is missing,
/// `Some(Err)` if they do not form a month.
fn expiry(card: &Value) -> Option<Result<String, ()>> {
    let month = text(card, "expMonth")?;
    let year = text(card, "expYear")?;
    let month = month.trim();
    let month = month
        .parse::<u8>()
        .ok()
        .filter(|m| (1..=12).contains(m) && month.bytes().all(|b| b.is_ascii_digit()));
    Some(month.and_then(|m| format_month(m, &year)).ok_or(()))
}

/// Builds one item's fields, tracking names so extras never collide.
struct Builder {
    schema: &'static Schema,
    fields: BTreeMap<String, Field>,
    taken: BTreeSet<String>,
}

impl Builder {
    fn new(kind: &str) -> Self {
        let schema = schema(kind).expect("built-in type");
        Self {
            schema,
            fields: BTreeMap::new(),
            taken: schema.fields.iter().map(|f| f.name.to_string()).collect(),
        }
    }

    /// Sets a known field; `false` if the value is invalid for it.
    fn known(&mut self, name: &str, value: Option<String>) -> bool {
        let Some(value) = value else { return true };
        let kind = self.schema.field(name).expect("known field").kind.clone();
        let field = Field::new(kind, value);
        if check_field(self.schema, name, &field).is_err() {
            return false;
        }
        self.fields.insert(name.into(), field);
        true
    }

    /// Adds an extra field under a free name based on `base`.
    fn extra(&mut self, base: &str, kind: FieldType, value: String) {
        let name = unique(base, &self.taken);
        self.taken.insert(name.clone());
        self.fields.insert(name, Field::new(kind, value));
    }

    fn custom_fields(&mut self, item: &Value, summary: &mut Summary) {
        for field in array(item, "fields") {
            let kind = match number(field, "type") {
                Some(0 | 2) => FieldType::Text,
                Some(3) => {
                    summary.linked_fields += 1;
                    continue;
                }
                _ => FieldType::Secret,
            };
            let Some(value) = text(field, "value") else {
                continue;
            };
            let name = field_name(&text(field, "name").unwrap_or_default());
            self.extra(&name, kind, value);
        }
    }

    fn finish(self, kind: &str, name: Option<String>) -> NewItem {
        NewItem {
            kind: kind.into(),
            name,
            fields: self
                .fields
                .into_iter()
                .map(|(name, mut field)| FieldInput {
                    name,
                    kind: Some(field.kind.to_string()),
                    value: std::mem::take(&mut field.value),
                })
                .collect(),
        }
    }
}

fn url_field(uri: &str) -> Field {
    let field = Field::new(FieldType::Url, with_scheme(uri.to_string()));
    let login = schema("login").expect("built-in type");
    if check_field(login, "url", &field).is_ok() {
        field
    } else {
        Field::new(FieldType::Text, uri)
    }
}

fn login(item: &Value, summary: &mut Summary) -> Option<NewItem> {
    let login = item.get("login").unwrap_or(&Value::Null);
    let mut b = Builder::new("login");
    let password = text(login, "password");
    if password.is_none() {
        *summary.skipped.entry(NO_PASSWORD).or_default() += 1;
        return None;
    }
    b.known("password", password);
    b.known("username", text(login, "username"));
    b.known("otp", text(login, "totp"));
    b.known("notes", text(item, "notes"));
    // The first absolute URL is `url`; the others are `url-2`, `url-3`, ...
    // of type url, or text if they are not absolute URLs.
    let mut url_set = false;
    for uri in array(login, "uris").iter().filter_map(|u| text(u, "uri")) {
        let mut field = url_field(uri.trim());
        if field.kind != FieldType::Url {
            *summary.warnings.entry(URL_AS_TEXT).or_default() += 1;
        } else if !url_set {
            url_set = true;
            b.fields.insert("url".into(), field);
            continue;
        }
        b.extra("url", field.kind.clone(), std::mem::take(&mut field.value));
    }
    if !array(login, "fido2Credentials").is_empty() {
        summary.passkeys += 1;
    }
    b.custom_fields(item, summary);
    summary.logins += 1;
    Some(b.finish("login", item_name(item)))
}

fn card(item: &Value, summary: &mut Summary) -> Option<NewItem> {
    let card = item.get("card").unwrap_or(&Value::Null);
    let mut b = Builder::new("card");
    let number = text(card, "number").map(|n| {
        n.chars()
            .filter(|c| !c.is_whitespace() && !matches!(c, '-' | '.'))
            .collect()
    });
    if number.is_none() || !b.known("number", number) {
        *summary.skipped.entry(NO_NUMBER).or_default() += 1;
        return None;
    }
    if !b.known("cvv", text(card, "code").map(|c| c.trim().to_string())) {
        *summary.warnings.entry(BAD_CVV).or_default() += 1;
    }
    match expiry(card) {
        Some(Ok(month)) => {
            b.known("expiry", Some(month));
        }
        Some(Err(())) => *summary.warnings.entry(BAD_EXPIRY).or_default() += 1,
        None => {}
    }
    b.known("cardholder", text(card, "cardholderName"));
    b.known("brand", text(card, "brand"));
    b.known("notes", text(item, "notes"));
    b.custom_fields(item, summary);
    summary.cards += 1;
    Some(b.finish("card", item_name(item)))
}

/// Maps a Bitwarden JSON export to items to create, and what was left out.
pub fn bitwarden(text: &str) -> Result<(Vec<NewItem>, Summary)> {
    // Untyped first: serde's typed errors could quote values from the file.
    let export: Value = serde_json::from_str(text).map_err(|e| {
        anyhow!(
            "not a JSON file (line {} column {}); export from Bitwarden as .json",
            e.line(),
            e.column()
        )
    })?;
    if export.get("encrypted").and_then(Value::as_bool) == Some(true) {
        bail!("this is an encrypted export; export as unencrypted .json");
    }
    let Some(items) = export.get("items").and_then(Value::as_array) else {
        bail!("not a Bitwarden JSON export: no \"items\" list");
    };
    let mut summary = Summary {
        folders: array(&export, "folders").len(),
        collections: array(&export, "collections").len(),
        ..Summary::default()
    };
    let mut out = Vec::new();
    for item in items {
        let skip = match number(item, "type") {
            Some(1) => None,
            Some(2) => Some(SECURE_NOTE),
            Some(3) => None,
            Some(4) => Some(IDENTITY),
            Some(5) => Some(SSH_KEY),
            Some(6) => Some(BANK_ACCOUNT),
            Some(7) => Some(DRIVERS_LICENSE),
            Some(8) => Some(PASSPORT),
            _ => Some(UNKNOWN_TYPE),
        };
        if let Some(skip) = skip {
            *summary.skipped.entry(skip).or_default() += 1;
            continue;
        }
        let mapped = if number(item, "type") == Some(1) {
            login(item, &mut summary)
        } else {
            card(item, &mut summary)
        };
        let Some(mapped) = mapped else { continue };
        if item.get("favorite").and_then(Value::as_bool) == Some(true) {
            summary.favorites += 1;
        }
        summary.attachments += array(item, "attachments").len();
        if !array(item, "passwordHistory").is_empty() {
            summary.password_history += 1;
        }
        check(&mapped).with_context(|| format!("mapping item {}", out.len() + 1))?;
        out.push(mapped);
    }
    Ok((out, summary))
}

/// The agent checks again; this keeps a mapping bug from failing late.
fn check(item: &NewItem) -> Result<()> {
    let fields = item
        .fields
        .iter()
        .map(|f| {
            let kind = FieldType::parse(f.kind.as_deref().unwrap_or("text"));
            (f.name.clone(), Field::new(kind, f.value.clone()))
        })
        .collect();
    check_create(&item.kind, item.name.as_deref(), &fields)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped like a real export from the Bitwarden web vault.
    const EXPORT: &str = r#"{
  "encrypted": false,
  "folders": [
    { "id": "4f5e2a3b-0c1d-4e2f-9a8b-7c6d5e4f3a2b", "name": "Work" },
    { "id": "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d", "name": "Finance" }
  ],
  "items": [
    {
      "passwordHistory": [
        { "lastUsedDate": "2024-01-02T03:04:05.000Z", "password": "old-hunter2" }
      ],
      "revisionDate": "2024-05-06T07:08:09.123Z",
      "creationDate": "2023-01-01T00:00:00.000Z",
      "deletedDate": null,
      "id": "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "organizationId": null,
      "folderId": "4f5e2a3b-0c1d-4e2f-9a8b-7c6d5e4f3a2b",
      "type": 1,
      "reprompt": 0,
      "name": "GitHub",
      "notes": "work account",
      "favorite": true,
      "fields": [
        { "name": "Recovery Code", "value": "rc-secret-1", "type": 1, "linkedId": null },
        { "name": "Notes", "value": "a text note", "type": 0, "linkedId": null },
        { "name": "notes", "value": "another", "type": 0, "linkedId": null },
        { "name": "2FA enabled?", "value": "true", "type": 2, "linkedId": null },
        { "name": "Username", "value": null, "type": 3, "linkedId": 100 },
        { "name": "empty", "value": "", "type": 0, "linkedId": null },
        { "name": null, "value": "unnamed-secret", "type": 1, "linkedId": null }
      ],
      "login": {
        "fido2Credentials": [],
        "uris": [
          { "match": null, "uri": "not a url" },
          { "match": null, "uri": "https://github.com/login" },
          { "match": 3, "uri": "github.com" },
          { "match": null, "uri": "androidapp://com.github.android" }
        ],
        "username": "dax",
        "password": "hunter2-github",
        "totp": "JBSWY3DPEHPK3PXP"
      },
      "collectionIds": null
    },
    {
      "id": "1b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "organizationId": null,
      "folderId": null,
      "type": 1,
      "reprompt": 0,
      "name": "No password",
      "notes": null,
      "favorite": false,
      "login": { "uris": [], "username": "someone", "password": null, "totp": null },
      "collectionIds": null
    },
    {
      "id": "2b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 1,
      "name": "",
      "favorite": false,
      "login": { "password": "minimal-pw" }
    },
    {
      "passwordHistory": null,
      "id": "3b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "organizationId": null,
      "folderId": "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d",
      "type": 3,
      "reprompt": 0,
      "name": "Visa",
      "notes": null,
      "favorite": false,
      "card": {
        "cardholderName": "Dax Raad",
        "brand": "Visa",
        "number": "4242 4242 4242 4242",
        "expMonth": "4",
        "expYear": "27",
        "code": "12x"
      },
      "collectionIds": null
    },
    {
      "id": "4b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 3,
      "name": "Amex",
      "favorite": false,
      "card": {
        "cardholderName": null,
        "brand": "Amex",
        "number": "378282246310005",
        "expMonth": "12",
        "expYear": null,
        "code": "1234"
      }
    },
    {
      "id": "5b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 3,
      "name": "Broken card",
      "favorite": false,
      "card": { "number": "1234", "expMonth": "1", "expYear": "2030", "code": "123" }
    },
    {
      "id": "6b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 2,
      "name": "Wifi",
      "notes": "the wifi password",
      "favorite": false,
      "secureNote": { "type": 0 }
    },
    {
      "id": "7b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 4,
      "name": "Me",
      "favorite": false,
      "identity": { "title": "Mr", "firstName": "Dax", "ssn": "000-00-0000" }
    },
    {
      "id": "8b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 5,
      "name": "Deploy key",
      "favorite": false,
      "sshKey": { "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----", "publicKey": "ssh-ed25519 AAAA", "keyFingerprint": "SHA256:x" }
    },
    {
      "id": "9b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 4,
      "name": "Also me",
      "favorite": false,
      "identity": {}
    }
  ]
}"#;

    fn fields(item: &NewItem) -> Vec<(&str, &str, &str)> {
        item.fields
            .iter()
            .map(|f| {
                (
                    f.name.as_str(),
                    f.kind.as_deref().unwrap(),
                    f.value.as_str(),
                )
            })
            .collect()
    }

    #[test]
    fn maps_a_bitwarden_export() {
        let (items, summary) = bitwarden(EXPORT).unwrap();
        assert_eq!(items.len(), 4);
        let github = &items[0];
        assert_eq!(
            (github.kind.as_str(), github.name.as_deref()),
            ("login", Some("GitHub"))
        );
        assert_eq!(
            fields(github),
            [
                ("field", "secret", "unnamed-secret"),
                ("field-2fa-enabled", "text", "true"),
                ("notes", "note", "work account"),
                ("notes-2", "text", "a text note"),
                ("notes-3", "text", "another"),
                ("otp", "otp", "JBSWY3DPEHPK3PXP"),
                ("password", "secret", "hunter2-github"),
                ("recovery-code", "secret", "rc-secret-1"),
                ("url", "url", "https://github.com/login"),
                ("url-2", "text", "not a url"),
                ("url-3", "url", "https://github.com"),
                ("url-4", "url", "androidapp://com.github.android"),
                ("username", "text", "dax"),
            ]
        );
        assert_eq!(items[1].name, None);
        assert_eq!(fields(&items[1]), [("password", "secret", "minimal-pw")]);
        assert_eq!(
            fields(&items[2]),
            [
                ("brand", "text", "Visa"),
                ("cardholder", "text", "Dax Raad"),
                ("expiry", "month", "2027-04"),
                ("number", "secret", "4242424242424242"),
            ]
        );
        assert_eq!(
            fields(&items[3]),
            [
                ("brand", "text", "Amex"),
                ("cvv", "secret", "1234"),
                ("number", "secret", "378282246310005"),
            ]
        );
        assert_eq!((summary.logins, summary.cards), (2, 2));
        assert_eq!(
            summary.lines(),
            [
                "imported 4 (logins 2, cards 2)",
                "skipped 1 card without a valid number",
                "skipped 2 identities",
                "skipped 1 login without password",
                "skipped 1 secure note",
                "skipped 1 ssh key",
                "warning: 1 URL that is not an absolute URL kept as text",
                "warning: 1 invalid card code (cvv) left out",
                "dropped: 2 folders, 1 favorite, password history on 1 item, 1 linked field",
            ]
        );
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
    fn card_expiry() {
        let card = |m: &str, y: &str| serde_json::json!({ "expMonth": m, "expYear": y });
        assert_eq!(expiry(&card("4", "27")), Some(Ok("2027-04".into())));
        assert_eq!(expiry(&card("12", "2031")), Some(Ok("2031-12".into())));
        assert_eq!(expiry(&card(" 04 ", " 27 ")), Some(Ok("2027-04".into())));
        assert_eq!(expiry(&card("", "2031")), None);
        assert_eq!(expiry(&serde_json::json!({ "expMonth": "1" })), None);
        assert_eq!(expiry(&card("1", "203")), Some(Err(())));
        assert_eq!(expiry(&card("1", "2x")), Some(Err(())));
        assert_eq!(expiry(&card("13", "2031")), Some(Err(())));
        assert_eq!(expiry(&card("+1", "2031")), Some(Err(())));
    }

    #[test]
    fn rejects_encrypted_and_foreign_files() {
        let encrypted = r#"{"encrypted": true, "passwordProtected": true, "salt": "x", "kdfType": 0, "kdfIterations": 600000, "encKeyValidation_DO_NOT_EDIT": "2.x", "data": "2.y"}"#;
        let error = bitwarden(encrypted).unwrap_err().to_string();
        assert_eq!(
            error,
            "this is an encrypted export; export as unencrypted .json"
        );
        assert!(bitwarden("{}").is_err());
        let error = bitwarden(r#"{"items": [{"login": {"password": "s3cret"#)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("s3cret"), "{error}");
    }

    #[test]
    fn counts_unsupported_types() {
        let export = r#"{"encrypted": false, "folders": [], "items": [
            {"type": 6, "name": "Bank"}, {"type": 7, "name": "DL"}, {"type": 8, "name": "PP"},
            {"type": 99, "name": "Future"}, {"name": "No type"}, {"type": "2", "name": "Note"},
            {"type": 3, "name": "No card", "card": null}
        ]}"#;
        let (items, summary) = bitwarden(export).unwrap();
        assert!(items.is_empty());
        assert_eq!(
            summary.lines(),
            [
                "imported 0 (logins 0, cards 0)",
                "skipped 1 bank account",
                "skipped 1 card without a valid number",
                "skipped 1 driver's license",
                "skipped 2 items of unknown type",
                "skipped 1 passport",
                "skipped 1 secure note",
            ]
        );
    }
}
