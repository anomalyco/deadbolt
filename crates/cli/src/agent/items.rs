//! Item commands: lookup, labels, input normalization and writes.
//!
//! Lookup is search. Every query word must match (case-insensitively) part
//! of the item's name, URL host, a login's username, a card's cardholder,
//! brand field or last four digits, an SSH key's comment, or an identity's
//! name or email; a word of 4+ hex digits also matches an id prefix. Secret
//! values (a secure note's body among them) and the derived label are never
//! searched.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use deadbolt_core::item::check_new_value;
use deadbolt_core::totp::Totp;
use deadbolt_core::{DataOp, Entry, Field, FieldType, Item, ItemId, Vault, VaultId, schema};
use zeroize::{Zeroize, Zeroizing};

use super::session::Loaded;
use crate::import::Imported;
use crate::items::{format_month, line, with_scheme};
use crate::protocol::{Code, FieldInfo, FieldInput, ImportReport, ItemInfo};

const MIN_SHORT: usize = 4;

/// The host of a URL, lowercased, without `www.`.
pub fn host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // An IPv6 address is bracketed and has colons of its own.
    let host = match host.strip_prefix('[') {
        Some(rest) => rest.find(']').map_or(host, |end| &host[..end + 2]),
        None => host.split(':').next().unwrap_or_default(),
    };
    let host = host.to_lowercase();
    host.strip_prefix("www.")
        .map(str::to_string)
        .unwrap_or(host)
}

fn value<'a>(item: &'a Item, field: &str) -> Option<&'a str> {
    item.fields.get(field).map(|f| f.value.as_str())
}

fn last_four(item: &Item) -> Option<&str> {
    let number = value(item, "number")?;
    Some(&number[number.len().saturating_sub(4)..])
}

/// The item's name, else a label derived from its fields.
pub fn label(item: &Item) -> String {
    if let Some(name) = &item.name {
        return name.clone();
    }
    match item.kind.as_str() {
        "login" => value(item, "url")
            .map(host)
            .filter(|h| !h.is_empty())
            .or_else(|| value(item, "username").map(str::to_string))
            .unwrap_or_else(|| "login".into()),
        "card" => format!(
            "{} •••• {}",
            value(item, "brand").unwrap_or("card"),
            last_four(item).unwrap_or_default()
        ),
        "ssh" => value(item, "comment").unwrap_or("SSH key").into(),
        "identity" => value(item, "name")
            .or_else(|| value(item, "email"))
            .unwrap_or("identity")
            .into(),
        // A secure note's body is secret: never a label.
        kind => kind.into(),
    }
}

/// A login's username, a card's expiry (`MM/YY`), an SSH key's comment or
/// fingerprint, an identity's email. A secure note has none.
fn detail(item: &Item) -> Option<String> {
    let first = |fields: &[&str]| {
        fields
            .iter()
            .find_map(|f| value(item, f))
            .map(str::to_string)
    };
    match item.kind.as_str() {
        "login" => first(&["username"]),
        "card" => value(item, "expiry")
            .and_then(|e| e.split_once('-'))
            .map(|(year, month)| format!("{month}/{}", &year[year.len().saturating_sub(2)..])),
        "ssh" => first(&["comment", "fingerprint"]),
        "identity" => first(&["email", "phone"]),
        _ => None,
    }
}

fn searchable(item: &Item) -> Vec<String> {
    let mut texts = Vec::new();
    texts.extend(item.name.clone());
    texts.extend(value(item, "url").map(host));
    let fields: &[&str] = match item.kind.as_str() {
        "login" => &["username"],
        "card" => &["cardholder", "brand"],
        "ssh" => &["comment", "fingerprint"],
        "identity" => &["name", "email", "phone"],
        _ => &[],
    };
    texts.extend(
        fields
            .iter()
            .filter_map(|f| value(item, f))
            .map(str::to_string),
    );
    if item.kind == "card" {
        texts.extend(last_four(item).map(str::to_string));
    }
    texts.into_iter().map(|t| t.to_lowercase()).collect()
}

fn matches(item: &Item, query: &[String]) -> bool {
    let texts = searchable(item);
    let id = item.id.to_string();
    query.iter().all(|word| {
        let word = word.to_lowercase();
        texts.iter().any(|t| t.contains(&word))
            || (word.len() >= MIN_SHORT
                && word.bytes().all(|b| b.is_ascii_hexdigit())
                && id.starts_with(&word))
    })
}

/// Shortest unique id prefix of `id` among `ids` (sorted), at least 4.
fn short_id(ids: &[String], id: &str) -> String {
    let common = |other: &String| {
        id.bytes()
            .zip(other.bytes())
            .take_while(|(a, b)| a == b)
            .count()
    };
    let at = ids
        .binary_search_by(|x| x.as_str().cmp(id))
        .unwrap_or_else(|i| i);
    let neighbours = [at.checked_sub(1), Some(at + 1)];
    let shared = neighbours
        .into_iter()
        .flatten()
        .filter_map(|i| ids.get(i))
        .filter(|other| *other != id)
        .map(common)
        .max()
        .unwrap_or(0);
    id[..(shared + 1).clamp(MIN_SHORT, id.len())].to_string()
}

struct Listing {
    items: Vec<Item>,
    ids: Vec<String>,
}

impl Listing {
    fn new(vault: &Vault) -> Self {
        let items = vault.items();
        let mut ids: Vec<String> = items.iter().map(|i| i.id.to_string()).collect();
        ids.sort();
        Self { items, ids }
    }

    fn info(&self, item: &Item, with_fields: bool) -> ItemInfo {
        let id = item.id.to_string();
        let mut fields = Vec::new();
        if with_fields {
            let known: Vec<&str> = schema(&item.kind)
                .map(|s| s.fields.iter().map(|f| f.name).collect())
                .unwrap_or_default();
            let order = known
                .iter()
                .copied()
                .filter(|name| item.fields.contains_key(*name))
                .chain(
                    item.fields
                        .keys()
                        .map(String::as_str)
                        .filter(|n| !known.contains(n)),
                );
            fields = order
                .map(|name| FieldInfo {
                    name: name.into(),
                    kind: item.fields[name].kind.to_string(),
                    value: item.fields[name].value.clone(),
                })
                .collect();
        }
        ItemInfo {
            short: short_id(&self.ids, &id),
            id,
            kind: item.kind.clone(),
            label: label(item),
            detail: detail(item),
            fields,
        }
    }

    fn find(&self, query: &[String]) -> Result<&Item> {
        let found: Vec<&Item> = self.items.iter().filter(|i| matches(i, query)).collect();
        let query = query.join(" ");
        match found.as_slice() {
            [item] => Ok(item),
            [] => bail!("no item matches {query:?}"),
            many => {
                let mut lines: Vec<String> = many
                    .iter()
                    .map(|item| line(&self.info(item, false)))
                    .collect();
                lines.sort();
                bail!(
                    "{query:?} matches {} items; add words or use the id:\n{}",
                    many.len(),
                    lines.join("\n")
                )
            }
        }
    }
}

/// Normalizes common input forms: card numbers without spaces or dashes,
/// `MM/YY` and `MM/YYYY` months, URLs without a scheme (https).
fn normalize(kind: &str, name: &str, field: &FieldType, value: String) -> String {
    if kind == "card" && name == "number" {
        return value
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
    }
    match field {
        FieldType::Month => {
            let parsed = value
                .split_once('/')
                .and_then(|(month, year)| format_month(month.trim().parse().ok()?, year));
            parsed.unwrap_or(value)
        }
        FieldType::Url => with_scheme(value),
        _ => value,
    }
}

/// Types and normalizes user input. Without an explicit type a field gets
/// the item type's field type, else its current type, else `text`.
fn fields(
    kind: &str,
    existing: Option<&Item>,
    inputs: Vec<FieldInput>,
) -> Result<Vec<(String, Field)>> {
    let mut seen = BTreeSet::new();
    inputs
        .into_iter()
        .map(|input| {
            if !seen.insert(input.name.clone()) {
                bail!("field {} given twice", input.name);
            }
            let field = match input.kind {
                Some(k) => FieldType::parse(&k),
                None => schema(kind)
                    .and_then(|s| s.field(&input.name))
                    .map(|f| f.kind.clone())
                    .or_else(|| existing?.fields.get(&input.name).map(|f| f.kind.clone()))
                    .unwrap_or(FieldType::Text),
            };
            let value = normalize(kind, &input.name, &field, input.value);
            let field = Field::new(field, value);
            check_new_value(&input.name, &field)?;
            Ok((input.name, field))
        })
        .collect()
}

fn write(s: &mut Loaded, vault: VaultId, ops: Vec<DataOp>) -> Result<Entry> {
    s.update(vault, |v, secret| Ok(v.write(secret, ops)?))
}

#[expect(
    clippy::expect_used,
    reason = "callers just wrote this item while holding the session lock"
)]
fn info(s: &Loaded, vault: VaultId, id: &ItemId) -> ItemInfo {
    let vault = s.vault(&vault);
    let item = vault.item(id).expect("just written");
    Listing::new(vault).info(&item, false)
}

pub fn get(s: &Loaded, vault: Option<&str>, query: &[String]) -> Result<ItemInfo> {
    let listing = Listing::new(s.vault(&s.resolve(vault)?));
    Ok(listing.info(listing.find(query)?, true))
}

/// The current one-time code of the item's `otp` field, else of its first
/// field of type otp, at `now` (since the unix epoch).
pub fn code(s: &Loaded, vault: Option<&str>, query: &[String], now: Duration) -> Result<Code> {
    let listing = Listing::new(s.vault(&s.resolve(vault)?));
    let item = listing.find(query)?;
    let field = item
        .fields
        .get("otp")
        .filter(|f| f.kind == FieldType::Otp)
        .or_else(|| item.fields.values().find(|f| f.kind == FieldType::Otp));
    let Some(field) = field else {
        bail!("{} has no one-time password", label(item));
    };
    let totp = Totp::parse(&field.value)
        .map_err(|e| anyhow!("the one-time password of {} is invalid: {e}", label(item)))?;
    let valid_until = totp.valid_until(now.as_secs());
    let remaining = Duration::from_secs(valid_until).saturating_sub(now);
    Ok(Code {
        code: Zeroizing::new(totp.code(now.as_secs())),
        period: totp.period(),
        valid_until,
        remaining_ms: remaining.as_millis() as u64,
    })
}

pub fn list(
    s: &Loaded,
    vault: Option<&str>,
    query: &[String],
    kind: Option<&str>,
) -> Result<Vec<ItemInfo>> {
    let listing = Listing::new(s.vault(&s.resolve(vault)?));
    let mut items: Vec<ItemInfo> = listing
        .items
        .iter()
        .filter(|i| kind.is_none_or(|k| i.kind == k) && matches(i, query))
        .map(|i| listing.info(i, false))
        .collect();
    items.sort_by_key(|i| (i.label.to_lowercase(), i.id.clone()));
    Ok(items)
}

pub fn create(
    s: &mut Loaded,
    vault: Option<&str>,
    kind: &str,
    name: Option<String>,
    inputs: Vec<FieldInput>,
) -> Result<ItemInfo> {
    let vault = s.resolve(vault)?;
    let fields = fields(kind, None, inputs)?;
    let name = name.filter(|n| !n.is_empty());
    let (id, _) = s.update(vault, |v, secret| {
        Ok(v.create_item(secret, kind, name, fields)?)
    })?;
    Ok(info(s, vault, &id))
}

/// What makes two items the same to an import: a login's URL host,
/// username and password, a card's number, an SSH key's private key. A
/// login without a URL host (a database, a Wi-Fi network) is also told
/// apart by its name. A secure note or an identity is the same only with
/// the same name and every field the same. Wiped when dropped.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Login {
        host: String,
        name: String,
        username: String,
        password: String,
    },
    Card {
        number: String,
    },
    Ssh {
        private_key: String,
    },
    Whole {
        kind: String,
        name: String,
        fields: Vec<(String, String)>,
    },
}

impl Drop for Key {
    fn drop(&mut self) {
        match self {
            Self::Login {
                host,
                name,
                username,
                password,
            } => {
                host.zeroize();
                name.zeroize();
                username.zeroize();
                password.zeroize();
            }
            Self::Card { number } => number.zeroize(),
            Self::Ssh { private_key } => private_key.zeroize(),
            Self::Whole { kind, name, fields } => {
                kind.zeroize();
                name.zeroize();
                for (field, value) in fields {
                    field.zeroize();
                    value.zeroize();
                }
            }
        }
    }
}

fn key(kind: &str, name: Option<&str>, fields: &BTreeMap<String, Field>) -> Option<Key> {
    let value = |field| {
        fields
            .get(field)
            .map_or(String::new(), |f: &Field| f.value.clone())
    };
    let whole = || Key::Whole {
        kind: kind.into(),
        name: name.unwrap_or_default().into(),
        fields: fields
            .iter()
            .map(|(field, f)| (field.clone(), f.value.clone()))
            .collect(),
    };
    match kind {
        // A login without a password (a server, an API credential, an SSO
        // account) is told apart by all of it, not by host and username.
        "login" if !fields.contains_key("password") => Some(whole()),
        "login" => {
            let host = fields
                .get("url")
                .filter(|f| f.kind == FieldType::Url)
                .map(|f| host(&f.value))
                .unwrap_or_default();
            let name = if host.is_empty() {
                name.unwrap_or_default().to_string()
            } else {
                String::new()
            };
            Some(Key::Login {
                host,
                name,
                username: value("username"),
                password: value("password"),
            })
        }
        "card" => Some(Key::Card {
            number: value("number")
                .chars()
                .filter(char::is_ascii_digit)
                .collect(),
        }),
        "ssh" => Some(Key::Ssh {
            private_key: value("private-key").trim().to_string(),
        }),
        "note" | "identity" => Some(whole()),
        _ => None,
    }
}

/// Imports a mapped export. Items the vault already has, or the export
/// repeats, are left out, so importing again changes nothing. With
/// `apply`, the rest are created, all or none.
pub fn import(
    s: &mut Loaded,
    vault: Option<&str>,
    (items, mut report): (Vec<Imported>, ImportReport),
    apply: bool,
) -> Result<ImportReport> {
    let vault = s.resolve(vault)?;
    let mut seen: BTreeSet<Key> = s
        .vault(&vault)
        .items()
        .iter()
        .filter_map(|item| key(&item.kind, item.name.as_deref(), &item.fields))
        .collect();
    let mut new = Vec::new();
    for item in items {
        if key(item.kind, item.name.as_deref(), &item.fields).is_some_and(|key| !seen.insert(key)) {
            report.duplicates += 1;
            if let Some(n) = report.new.get_mut(item.kind) {
                *n -= 1;
            }
            continue;
        }
        new.push((
            item.kind.to_string(),
            item.name,
            item.fields.into_iter().collect::<Vec<_>>(),
        ));
    }
    if apply && !new.is_empty() {
        s.update(vault, |v, secret| {
            v.create_items(secret, new)?;
            Ok(())
        })?;
    }
    Ok(report)
}

pub fn set(
    s: &mut Loaded,
    vault: Option<&str>,
    query: &[String],
    inputs: Vec<FieldInput>,
    name: Option<String>,
) -> Result<ItemInfo> {
    let vault = s.resolve(vault)?;
    let item = Listing::new(s.vault(&vault)).find(query)?.clone();
    let mut ops: Vec<DataOp> = fields(&item.kind, Some(&item), inputs)?
        .into_iter()
        .map(|(name, field)| DataOp::set(item.id, name, field))
        .collect();
    if let Some(name) = name {
        ops.push(DataOp::name(item.id, Some(name).filter(|n| !n.is_empty())));
    }
    if ops.is_empty() {
        bail!("nothing to change: give field=value assignments or --name");
    }
    write(s, vault, ops)?;
    Ok(info(s, vault, &item.id))
}

pub fn unset(
    s: &mut Loaded,
    vault: Option<&str>,
    query: &[String],
    field: &str,
) -> Result<ItemInfo> {
    let vault = s.resolve(vault)?;
    let item = Listing::new(s.vault(&vault)).find(query)?.clone();
    if !item.fields.contains_key(field) {
        bail!("{} has no field {field}", label(&item));
    }
    write(s, vault, vec![DataOp::remove(item.id, field)])?;
    Ok(info(s, vault, &item.id))
}

pub fn remove(s: &mut Loaded, vault: Option<&str>, query: &[String]) -> Result<ItemInfo> {
    let vault = s.resolve(vault)?;
    let listing = Listing::new(s.vault(&vault));
    let item = listing.find(query)?;
    let info = listing.info(item, false);
    write(s, vault, vec![DataOp::delete(item.id)])?;
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded(dir: &std::path::Path) -> Loaded {
        let params = deadbolt_store::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        };
        let mut loaded = Loaded::setup(dir, b"test", "test", params).unwrap();
        loaded.create_vault("personal").unwrap();
        loaded
    }

    fn import(s: &mut Loaded, export: &str, apply: bool) -> ImportReport {
        super::import(s, None, crate::import::parse(export).unwrap(), apply).unwrap()
    }

    fn count(s: &Loaded) -> usize {
        let vault = s.resolve(None).unwrap();
        s.vault(&vault).items().len()
    }

    fn input(name: &str, value: &str) -> FieldInput {
        FieldInput {
            name: name.into(),
            kind: None,
            value: value.into(),
        }
    }

    fn at(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    fn words(query: &str) -> Vec<String> {
        query.split(' ').map(String::from).collect()
    }

    #[test]
    fn codes_come_from_the_otp_field() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        // RFC 6238's SHA-1 secret, "12345678901234567890".
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let otp = format!("otpauth://totp/Site:dax?secret={secret}&digits=8&issuer=Site");
        let fields = vec![input("password", "pw"), input("otp", &otp)];
        create(&mut s, None, "login", Some("Site".into()), fields).unwrap();
        let code = code(&s, None, &words("site"), Duration::from_millis(59_250)).unwrap();
        assert_eq!(code.code.as_str(), "94287082");
        assert_eq!(
            (code.period, code.valid_until, code.remaining_ms),
            (30, 60, 750)
        );

        let fields = vec![input("password", "pw"), input("backup", "x")];
        create(&mut s, None, "login", Some("Plain".into()), fields).unwrap();
        let error = super::code(&s, None, &words("plain"), at(59)).unwrap_err();
        assert_eq!(error.to_string(), "Plain has no one-time password");
        let fields = vec![FieldInput {
            kind: Some("otp".into()),
            ..input("backup", &secret.to_lowercase())
        }];
        set(&mut s, None, &words("plain"), fields, None).unwrap();
        let code = super::code(&s, None, &words("plain"), at(59)).unwrap();
        assert_eq!(code.code.as_str(), "287082");
    }

    #[test]
    fn otp_values_must_be_totp_secrets_when_written() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let hotp = "otpauth://hotp/Site?secret=JBSWY3DPEHPK3PXP&counter=1";
        let fields = vec![input("password", "pw"), input("otp", hotp)];
        let error = create(&mut s, None, "login", Some("Site".into()), fields).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid value for otp: counter-based (HOTP) codes are not supported"
        );
        let fields = vec![input("password", "pw")];
        create(&mut s, None, "login", Some("Site".into()), fields).unwrap();
        let error = set(
            &mut s,
            None,
            &words("site"),
            vec![input("otp", "123456")],
            None,
        );
        assert_eq!(
            error.unwrap_err().to_string(),
            "invalid value for otp: the secret is not base32"
        );
        assert_eq!(count(&s), 1);

        // A value written before the check is still in the vault, and says why it has no code.
        let vault = s.resolve(None).unwrap();
        s.update(vault, |v, secret| {
            let fields = vec![
                ("password".to_string(), Field::new(FieldType::Secret, "pw")),
                ("otp".to_string(), Field::new(FieldType::Otp, hotp)),
            ];
            Ok(v.create_item(secret, "login", Some("Old".into()), fields)?)
        })
        .unwrap();
        let error = code(&s, None, &words("old"), at(59)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "the one-time password of Old is invalid: counter-based (HOTP) codes are not supported"
        );
    }

    #[test]
    fn imports_skip_duplicates_and_a_dry_run_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let export = "name,url,username,password\n\
            GitHub,https://github.com/login,dax,pw-1\n\
            GitHub again,https://www.GitHub.com/,dax,pw-1\n\
            Other user,https://github.com,kit,pw-1\n\
            New password,https://github.com,dax,pw-2\n\
            No url,,dax,pw-1\n\
            No url again,not a url,dax,pw-1\n\
            Prod DB,,postgres,pg-pw\n\
            Staging DB,,postgres,pg-pw\n\
            Prod DB,,postgres,pg-pw\n\
            ,,postgres,pg-pw\n\
            ,,postgres,pg-pw\n";
        let report = import(&mut s, export, false);
        assert_eq!((report.count("login"), report.duplicates), (8, 3));
        assert_eq!(count(&s), 0);
        let report = import(&mut s, export, true);
        assert_eq!((report.count("login"), report.duplicates), (8, 3));
        assert_eq!(count(&s), 8);
        let again = import(&mut s, export, true);
        assert_eq!((again.count("login"), again.duplicates), (0, 11));
        assert_eq!(
            again.lines(true)[..2],
            [
                "imported 0 from CSV (logins 0, cards 0)",
                "skipped 11 duplicates",
            ]
        );
        assert_eq!(count(&s), 8);
    }

    #[test]
    fn cards_are_the_same_by_number() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let vault = s.resolve(None).unwrap();
        let fields = vec![(
            "number".to_string(),
            Field::new(FieldType::Secret, "4242424242424242"),
        )];
        s.update(vault, |v, secret| {
            v.create_items(secret, [("card".to_string(), None, fields)])?;
            Ok(())
        })
        .unwrap();
        let export = r#"{"encrypted": false, "items": [
            {"type": 3, "name": "Visa", "card": {"number": "4242 4242 4242 4242", "code": "123"}},
            {"type": 3, "name": "Amex", "card": {"number": "378282246310005"}},
            {"type": 3, "name": "Amex", "card": {"number": "3782-822463-10005"}}
        ]}"#;
        let report = import(&mut s, export, true);
        assert_eq!((report.count("card"), report.duplicates), (1, 2));
        assert_eq!(count(&s), 2);
    }

    #[test]
    fn notes_ssh_keys_and_identities_import_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let export = r#"{"encrypted": false, "items": [
            {"type": 2, "name": "Alarm", "notes": "code 1234"},
            {"type": 2, "name": "Alarm", "notes": "code 1234"},
            {"type": 2, "name": "Alarm", "notes": "code 5678"},
            {"type": 5, "name": "Deploy", "sshKey": {"privateKey": "-----BEGIN KEY-----\nabc\n"}},
            {"type": 5, "name": "Deploy copy", "sshKey": {"privateKey": "-----BEGIN KEY-----\nabc"}},
            {"type": 4, "name": "Me", "identity": {"firstName": "Dax", "email": "dax@example.com"}},
            {"type": 4, "name": "Me", "identity": {"firstName": "Dax", "email": "dax@example.com"}}
        ]}"#;
        let report = import(&mut s, export, true);
        assert_eq!(
            (report.counts(), report.duplicates),
            (vec![("note", 2), ("ssh", 1), ("identity", 1)], 3)
        );
        assert_eq!(count(&s), 4);
        let again = import(&mut s, export, true);
        assert_eq!((again.total(), again.duplicates), (0, 7));
        assert_eq!(count(&s), 4);
    }

    #[test]
    fn logins_without_a_password_are_the_same_only_when_whole() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let export = r#"{"encrypted": false, "items": [
            {"type": 1, "name": "Prod DB", "login": {"username": "admin", "uris": [{"uri": "https://db.example.com"}]},
             "fields": [{"name": "port", "value": "5432", "type": 0}]},
            {"type": 1, "name": "Prod DB", "login": {"username": "admin", "uris": [{"uri": "https://db.example.com"}]},
             "fields": [{"name": "port", "value": "5433", "type": 0}]},
            {"type": 1, "name": "Prod DB", "login": {"username": "admin", "uris": [{"uri": "https://db.example.com"}]},
             "fields": [{"name": "port", "value": "5432", "type": 0}]}
        ]}"#;
        let report = import(&mut s, export, true);
        assert_eq!((report.count("login"), report.duplicates), (2, 1));
        assert_eq!(count(&s), 2);
        let again = import(&mut s, export, true);
        assert_eq!((again.total(), again.duplicates), (0, 3));
    }

    #[test]
    fn hosts() {
        for (url, host_) in [
            ("https://www.GitHub.com/login", "github.com"),
            (
                "https://user:pw@mail.example.org:8443/x?y",
                "mail.example.org",
            ),
            ("example.com/path", "example.com"),
            ("ssh://git@host", "host"),
            ("https://[::1]:8080/x", "[::1]"),
            ("https://[2001:DB8::1]", "[2001:db8::1]"),
            ("https://user@[::1]", "[::1]"),
        ] {
            assert_eq!(host(url), host_);
        }
    }

    fn item(kind: &str, name: Option<&str>, fields: &[(&str, &str)]) -> Item {
        Item {
            id: ItemId::from_bytes([0xee; 16]),
            kind: kind.into(),
            name: name.map(Into::into),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), Field::new(FieldType::Text, *v)))
                .collect(),
            deleted: false,
        }
    }

    #[test]
    fn search_skips_the_derived_label() {
        let q = |words: &[&str]| -> Vec<String> { words.iter().map(|w| w.to_string()).collect() };
        let unbranded = item("card", None, &[("number", "4242424242424242")]);
        let branded = item(
            "card",
            None,
            &[("number", "5555555555554444"), ("brand", "Visa")],
        );
        let named = item("card", Some("Travel"), &[("number", "6011000990139424")]);
        let login = item("login", None, &[("password", "x")]);
        let note = item("note", None, &[("notes", "body text")]);
        assert_eq!(label(&unbranded), "card •••• 4242");
        assert_eq!(label(&login), "login");
        assert_eq!((label(&note), detail(&note)), ("note".into(), None));
        assert!(!matches(&note, &q(&["body"])));
        let key = item(
            "ssh",
            None,
            &[("private-key", "k"), ("comment", "dax@laptop")],
        );
        assert_eq!(label(&key), "dax@laptop");
        assert!(matches(&key, &q(&["laptop"])));
        let printed = item(
            "ssh",
            None,
            &[("private-key", "k"), ("fingerprint", "SHA256:xyz")],
        );
        assert!(matches(&printed, &q(&["sha256:xyz"])));
        assert!(!matches(&printed, &q(&["k"])));
        let me = item(
            "identity",
            Some("Me"),
            &[("name", "Dax Raad"), ("email", "dax@example.com")],
        );
        assert_eq!(detail(&me).as_deref(), Some("dax@example.com"));
        assert!(matches(&me, &q(&["raad", "example"])));
        let phone = item("identity", None, &[("phone", "+1 555 0100")]);
        assert!(matches(&phone, &q(&["0100"])));
        // The type word and the label's filler match no item, branded or not.
        for words in [&["card"][..], &["login"], &["••••"]] {
            for it in [&unbranded, &branded, &named, &login] {
                assert!(!matches(it, &q(words)), "{words:?} matched {}", label(it));
            }
        }
        assert!(matches(&branded, &q(&["visa", "4444"])));
        assert!(matches(&unbranded, &q(&["4242"])));
        assert!(matches(&named, &q(&["travel", "9424"])));
    }

    #[test]
    fn short_ids_are_unique_prefixes() {
        let mut ids = vec!["abcd1234".to_string(), "abcd5678".into(), "ffff0000".into()];
        ids.sort();
        assert_eq!(short_id(&ids, "abcd1234"), "abcd1");
        assert_eq!(short_id(&ids, "abcd5678"), "abcd5");
        assert_eq!(short_id(&ids, "ffff0000"), "ffff");
    }

    #[test]
    fn normalizes_input() {
        let n = |k, name, f: FieldType, v: &str| normalize(k, name, &f, v.into());
        assert_eq!(
            n("card", "number", FieldType::Secret, "4242 4242-4242 4242"),
            "4242424242424242"
        );
        assert_eq!(n("card", "expiry", FieldType::Month, "4/27"), "2027-04");
        assert_eq!(n("card", "expiry", FieldType::Month, "12/2031"), "2031-12");
        assert_eq!(n("card", "expiry", FieldType::Month, "2031-12"), "2031-12");
        assert_eq!(n("card", "expiry", FieldType::Month, " 4 / 27 "), "2027-04");
        for bad in ["4/2x", "4/203", "x/27"] {
            assert_eq!(n("card", "expiry", FieldType::Month, bad), bad);
        }
        assert_eq!(
            n("login", "url", FieldType::Url, "github.com"),
            "https://github.com"
        );
        assert_eq!(n("login", "url", FieldType::Url, "ftp://x"), "ftp://x");
        assert_eq!(n("login", "url", FieldType::Url, ""), "");
    }
}
