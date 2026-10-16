//! Item commands: lookup, labels, input normalization and writes.
//!
//! Lookup is search. Every query word must match (case-insensitively) part
//! of the item's name, label, URL host, username, or for cards the
//! cardholder, brand field or last four digits; a word of 4+ hex digits also
//! matches an id prefix. Secret values are never searched.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use deadbolt_core::{DataOp, Entry, Field, FieldType, Item, ItemId, Vault, VaultId, schema};

use super::session::Session;
use crate::items::line;
use crate::protocol::{FieldInfo, FieldInput, ItemInfo};

const MIN_SHORT: usize = 4;

/// The host of a URL, lowercased, without `www.`.
pub fn host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host.split(':').next().unwrap_or_default().to_lowercase();
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
        kind => kind.into(),
    }
}

/// Login username or card expiry (`MM/YY`).
fn detail(item: &Item) -> Option<String> {
    match item.kind.as_str() {
        "login" => value(item, "username").map(str::to_string),
        "card" => value(item, "expiry")
            .and_then(|e| e.split_once('-'))
            .map(|(year, month)| format!("{month}/{}", &year[year.len().saturating_sub(2)..])),
        _ => None,
    }
}

fn searchable(item: &Item) -> Vec<String> {
    let mut texts = vec![label(item)];
    texts.extend(item.name.clone());
    texts.extend(value(item, "url").map(host));
    let fields: &[&str] = match item.kind.as_str() {
        "login" => &["username"],
        "card" => &["cardholder", "brand"],
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
            name: item.name.clone(),
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
            let parsed = value.split_once('/').and_then(|(month, year)| {
                let month: u8 = month.trim().parse().ok()?;
                let year = year.trim();
                let year = match year.len() {
                    2 => format!("20{year}"),
                    4 => year.to_string(),
                    _ => return None,
                };
                year.bytes()
                    .all(|b| b.is_ascii_digit())
                    .then(|| format!("{year}-{month:02}"))
            });
            parsed.unwrap_or(value)
        }
        FieldType::Url if !value.contains("://") && !value.is_empty() => format!("https://{value}"),
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
            Ok((input.name, Field::new(field, value)))
        })
        .collect()
}

fn write(s: &mut Session, vault: VaultId, ops: Vec<DataOp>) -> Result<Entry> {
    let secret = &s.secret;
    let entry = s
        .vaults
        .get_mut(&vault)
        .expect("resolved")
        .write(secret, ops)?;
    s.persist(std::slice::from_ref(&entry))?;
    Ok(entry)
}

fn info(s: &Session, vault: VaultId, id: &ItemId) -> ItemInfo {
    let vault = s.vault(&vault);
    let item = vault.item(id).expect("just written");
    Listing::new(vault).info(&item, false)
}

pub fn get(s: &Session, vault: Option<&str>, query: &[String]) -> Result<ItemInfo> {
    let listing = Listing::new(s.vault(&s.resolve(vault)?));
    Ok(listing.info(listing.find(query)?, true))
}

pub fn list(
    s: &Session,
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
    s: &mut Session,
    vault: Option<&str>,
    kind: &str,
    name: Option<String>,
    inputs: Vec<FieldInput>,
) -> Result<ItemInfo> {
    let vault = s.resolve(vault)?;
    let fields = fields(kind, None, inputs)?;
    let name = name.filter(|n| !n.is_empty());
    let secret = &s.secret;
    let (id, entry) = s
        .vaults
        .get_mut(&vault)
        .expect("resolved")
        .create_item(secret, kind, name, fields)?;
    s.persist(&[entry])?;
    Ok(info(s, vault, &id))
}

pub fn set(
    s: &mut Session,
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
    s: &mut Session,
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

pub fn remove(s: &mut Session, vault: Option<&str>, query: &[String]) -> Result<ItemInfo> {
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
        ] {
            assert_eq!(host(url), host_);
        }
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
        assert_eq!(
            n("login", "url", FieldType::Url, "github.com"),
            "https://github.com"
        );
        assert_eq!(n("login", "url", FieldType::Url, "ftp://x"), "ftp://x");
    }
}
