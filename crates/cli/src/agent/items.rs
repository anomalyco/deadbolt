//! Item commands: lookup, labels, input normalization and writes.
//!
//! Lookup is search. Every query word must match (case-insensitively) part
//! of the item's name, URL host, a login's username, a card's cardholder,
//! brand field or last four digits, an SSH key's comment, an identity's
//! name parts, organization, email or phone, or a passkey's relying party
//! or username, and the other types' plain identifying fields (see
//! `searchable`); a word of 4+ hex digits also matches an id prefix. Secret
//! values (a secure note's body among them) and the derived label are never
//! searched.
//!
//! A file field's contents leave only when asked for (`get` with `files`):
//! otherwise it comes back as its file name alone.
//!
//! A passkey's private key never leaves the agent: items come back without
//! it (see `passkeys`).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use deadbolt_core::totp::Totp;
use deadbolt_core::{
    DataOp, Entry, Field, FieldType, Item, ItemError, ItemId, Source, Vault, VaultId, schema,
    valid_name,
};
use zeroize::{Zeroize, Zeroizing};

use super::session::{Loaded, hex};
use crate::import::onepassword::source_key;
use crate::import::{Imported, MirrorVersion, digest};
use crate::items::line;
use crate::protocol::{Code, FieldInfo, FieldInput, ImportReport, ItemInfo, Tally};

const MIN_SHORT: usize = 4;

use deadbolt_core::listing::{detail, input_field, searchable};
pub use deadbolt_core::listing::{host, label};

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

pub(super) struct Listing {
    pub(super) items: Vec<Item>,
    ids: Vec<String>,
    /// A listing of deleted items, and when each was deleted.
    deleted: Option<BTreeMap<ItemId, u64>>,
}

impl Listing {
    pub(super) fn new(vault: &Vault) -> Self {
        Self::of(vault.items(), None)
    }

    /// The deleted items instead, newest first ([`Vault::deleted`]). Short
    /// ids are unique among them.
    pub(super) fn deleted(vault: &Vault) -> Self {
        let deleted = vault.deleted();
        let at = deleted
            .iter()
            .filter_map(|d| Some((d.item.id, d.at?)))
            .collect();
        Self::of(deleted.into_iter().map(|d| d.item).collect(), Some(at))
    }

    /// The live items, or with `deleted` the deleted ones.
    pub(super) fn pick(vault: &Vault, deleted: bool) -> Self {
        if deleted {
            Self::deleted(vault)
        } else {
            Self::new(vault)
        }
    }

    fn of(items: Vec<Item>, deleted: Option<BTreeMap<ItemId, u64>>) -> Self {
        let mut ids: Vec<String> = items.iter().map(|i| i.id.to_string()).collect();
        ids.sort();
        Self {
            items,
            ids,
            deleted,
        }
    }

    /// The item, without field values unless `with_fields`, and without
    /// one-time password secrets unless `with_otp` too. Files come as their
    /// names alone.
    pub(super) fn info(&self, item: &Item, with_fields: bool, with_otp: bool) -> ItemInfo {
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
                )
                .filter(|name| !super::passkeys::private(item, name));
            fields = order
                .map(|name| FieldInfo {
                    name: name.into(),
                    kind: item.fields[name].kind.to_string(),
                    value: match item.fields[name].kind {
                        FieldType::Otp if !with_otp => String::new(),
                        FieldType::File => {
                            deadbolt_core::item::file_parts(&item.fields[name].value)
                                .0
                                .to_string()
                        }
                        _ => item.fields[name].value.clone(),
                    },
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
            source: super::mirror::source_app(item.source.as_ref()),
            deleted_at: self
                .deleted
                .as_ref()
                .and_then(|at| at.get(&item.id).copied()),
        }
    }

    pub(super) fn find(&self, query: &[String]) -> Result<&Item> {
        let found: Vec<&Item> = self.items.iter().filter(|i| matches(i, query)).collect();
        let query = query.join(" ");
        match found.as_slice() {
            [item] => Ok(item),
            [] if self.deleted.is_some() => bail!("no deleted item matches {query:?}"),
            [] => bail!("no item matches {query:?}"),
            many => {
                let mut lines: Vec<String> = many
                    .iter()
                    .map(|item| line(&self.info(item, false, false)))
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

/// Types and normalizes user input ([`input_field`]).
fn fields(
    kind: &str,
    existing: Option<&Item>,
    inputs: Vec<FieldInput>,
) -> Result<Vec<(String, Field)>> {
    let mut seen = BTreeSet::new();
    inputs
        .into_iter()
        .map(|mut input| {
            if !seen.insert(input.name.clone()) {
                bail!("field {} given twice", input.name);
            }
            let value = std::mem::take(&mut input.value);
            let field = input_field(kind, existing, &input.name, input.kind.as_deref(), value)?;
            Ok((std::mem::take(&mut input.name), field))
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
    Listing::new(vault).info(&item, false, false)
}

/// One item with its values; one-time password secrets only with `otp`,
/// and the contents only of the file fields `files` names. With `deleted`,
/// one of the deleted items instead.
pub fn get(
    s: &Loaded,
    vault: Option<&str>,
    query: &[String],
    otp: bool,
    files: &[String],
    deleted: bool,
) -> Result<ItemInfo> {
    let listing = Listing::pick(s.vault(&s.resolve(vault)?), deleted);
    let item = listing.find(query)?;
    let mut info = listing.info(item, true, otp);
    if !files.is_empty() {
        let named = |f: &&mut FieldInfo| f.kind == "file" && files.contains(&f.name);
        for field in info.fields.iter_mut().filter(named) {
            if let Some(file) = item.fields.get(&field.name) {
                field.value.zeroize();
                field.value = file.value.clone();
            }
        }
    }
    Ok(info)
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
        // Never 0, which would read as already over.
        remaining_ms: (remaining.as_millis() as u64).max(1),
    })
}

/// Matching items by label, or with `deleted` the deleted ones newest first.
pub fn list(
    s: &Loaded,
    vault: Option<&str>,
    query: &[String],
    kind: Option<&str>,
    deleted: bool,
) -> Result<Vec<ItemInfo>> {
    let listing = Listing::pick(s.vault(&s.resolve(vault)?), deleted);
    let mut items: Vec<ItemInfo> = listing
        .items
        .iter()
        .filter(|i| kind.is_none_or(|k| i.kind == k) && matches(i, query))
        .map(|i| listing.info(i, false, false))
        .collect();
    if !deleted {
        items.sort_by_key(|i| (i.label.to_lowercase(), i.id.clone()));
    }
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
    // A sign-in link is the import's own doing, not the item's content.
    let whole = || Key::Whole {
        kind: kind.into(),
        name: name.unwrap_or_default().into(),
        fields: fields
            .iter()
            .filter(|(field, _)| *field != "sign-in-account")
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
        "note" | "identity" | "api" | "database" | "server" | "wifi" | "license" | "bank"
        | "document" | "passport" | "driver-license" | "membership" | "crypto" | "id-document" => {
            Some(whole())
        }
        _ => None,
    }
}

/// Where an item of an export is, or will be, here.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Here(ItemId),
    /// The export's new item at this index.
    New(usize),
}

/// A sign-in method that links to an account the import cannot find.
const UNLINKED: (&str, &str) = (
    "sign-in method links to an account not in this export (kept without the link)",
    "sign-in methods link to an account not in this export (kept without the link)",
);

/// Sign-in links written per entry.
const LINK_BATCH: usize = 256;

/// The source of an item imported from 1Password, as it records a digest
/// of the item as written: now with `field` as its `sign-in-account`.
fn relinked_source(v: &Vault, id: &ItemId, field: &Field) -> Option<DataOp> {
    let item = v.item(id)?;
    let source = item.source.as_ref()?;
    let mut version = MirrorVersion::parse(&source.version)?;
    let mut fields = item.fields.clone();
    fields.insert("sign-in-account".into(), field.clone());
    version.digest = digest(&item.kind, item.name.as_deref(), &fields);
    let source = Source {
        id: source.id.clone(),
        version: version.to_string(),
    };
    Some(DataOp::source(*id, Some(source)))
}

/// Imports a mapped export. Items the vault already has, or the export
/// repeats, are left out, so importing again changes nothing. With
/// `apply`, the rest are created, all or none.
///
/// A login that signs in with another ([`Imported::sign_in_link`]) is then
/// linked to it by `sign-in-account`: to the item created from that
/// 1Password item, or the one here it duplicates, or one here imported or
/// mirrored from it before. Item ids come from the entries that create
/// them, so the links are a second write.
pub fn import(
    s: &mut Loaded,
    vault: Option<&str>,
    (items, mut report): (Vec<Imported>, ImportReport),
    apply: bool,
) -> Result<ImportReport> {
    let vault = s.resolve(vault)?;
    let mut seen: BTreeMap<Key, Target> = BTreeMap::new();
    for item in s.vault(&vault).items() {
        if let Some(key) = key(&item.kind, item.name.as_deref(), &item.fields) {
            seen.entry(key).or_insert(Target::Here(item.id));
        }
    }
    // 1Password items by vault and item id: this vault's copies first.
    let mut copies: BTreeMap<(String, String), Target> = BTreeMap::new();
    let others = s.vaults.iter().filter(|(id, _)| **id != vault);
    for (_, v) in std::iter::once((&vault, s.vault(&vault))).chain(others) {
        for item in v.items() {
            if let Some((_, vault, id)) = item.source.as_ref().and_then(|s| source_key(&s.id)) {
                copies
                    .entry((vault.into(), id.into()))
                    .or_insert(Target::Here(item.id));
            }
        }
    }
    let mut new = Vec::new();
    let mut links = Vec::new();
    for item in items {
        let target = match key(item.kind, item.name.as_deref(), &item.fields) {
            Some(key) => match seen.get(&key) {
                Some(target) => Some(*target),
                None => {
                    seen.insert(key, Target::New(new.len()));
                    None
                }
            },
            None => None,
        };
        let target = target.unwrap_or(Target::New(new.len()));
        if let Some((_, vault, id)) = item.source.as_ref().and_then(|s| source_key(&s.id)) {
            copies.entry((vault.into(), id.into())).or_insert(target);
        }
        if target != Target::New(new.len()) {
            report.duplicates += 1;
            if let Some(n) = report.new.get_mut(item.kind) {
                *n -= 1;
            }
            continue;
        }
        if let Some(provider) = item.fields.get("sign-in-with") {
            *report
                .sign_in
                .providers
                .entry(provider.value.clone())
                .or_default() += 1;
            links.extend(item.sign_in_link.map(|link| (new.len(), link)));
        }
        new.push(DataOp::Create {
            kind: item.kind.to_string(),
            name: item.name,
            fields: item.fields,
            source: item.source,
        });
    }
    let given = links.len();
    let links: Vec<(usize, Target)> = links
        .into_iter()
        .filter_map(|(at, link)| {
            copies
                .get(&link)
                .copied()
                .filter(|to| *to != Target::New(at))
                .map(|to| (at, to))
        })
        .collect();
    report.sign_in.linked = links.len();
    if given > links.len() {
        report.warnings.push(Tally {
            count: given - links.len(),
            one: UNLINKED.0.into(),
            many: UNLINKED.1.into(),
        });
    }
    if apply && !new.is_empty() {
        s.update(vault, |v, secret| {
            let (ids, _) = v.create_items(secret, new)?;
            let mut ops = Vec::new();
            for (at, to) in links {
                let account = match to {
                    Target::Here(id) => id,
                    Target::New(i) => ids[i],
                };
                let id = ids[at];
                let field = Field::new(FieldType::Text, hex(account.as_bytes()));
                ops.extend(relinked_source(v, &id, &field));
                ops.push(DataOp::set(id, "sign-in-account", field));
            }
            for batch in ops.chunks(LINK_BATCH) {
                v.write(secret, batch.to_vec())?;
            }
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
    unset: &[String],
) -> Result<ItemInfo> {
    let vault = s.resolve(vault)?;
    let item = Listing::new(s.vault(&vault)).find(query)?.clone();
    let set = fields(&item.kind, Some(&item), inputs)?;
    let mut seen: BTreeSet<&str> = set.iter().map(|(name, _)| name.as_str()).collect();
    for field in unset {
        if !seen.insert(field) {
            bail!("field {field} given twice");
        }
    }
    let mut ops: Vec<DataOp> = set
        .into_iter()
        .map(|(name, field)| DataOp::set(item.id, name, field))
        .collect();
    // A field already gone (removed on another device) has nothing left to
    // remove, but the name must still be one the item could have.
    for field in unset {
        if item.fields.contains_key(field) {
            ops.push(DataOp::remove(item.id, field));
        } else if !valid_name(field) {
            return Err(ItemError::InvalidFieldName(field.clone()).into());
        } else if schema(&item.kind)
            .and_then(|s| s.field(field))
            .is_some_and(|f| f.required)
        {
            return Err(ItemError::RequiredField(field.clone()).into());
        }
    }
    if let Some(name) = name {
        ops.push(DataOp::name(item.id, Some(name).filter(|n| !n.is_empty())));
    }
    if ops.is_empty() && unset.is_empty() {
        bail!("nothing to change: give field=value assignments or --name");
    }
    if !ops.is_empty() {
        write(s, vault, ops)?;
    }
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

#[cfg(test)]
pub fn remove(s: &mut Loaded, vault: Option<&str>, query: &[String]) -> Result<ItemInfo> {
    let vault = s.resolve(vault)?;
    let listing = Listing::new(s.vault(&vault));
    let item = listing.find(query)?;
    let info = listing.info(item, false, false);
    write(
        s,
        vault,
        vec![DataOp::delete(item.id, crate::config::now())],
    )?;
    Ok(info)
}

/// Deletes the exact item selected before consent, never re-running a search.
pub(super) fn remove_id(s: &mut Loaded, vault: VaultId, id: ItemId) -> Result<ItemInfo> {
    let stored = s
        .vaults
        .get(&vault)
        .ok_or_else(|| anyhow!("no such vault"))?;
    let item = stored
        .item(&id)
        .filter(|item| !item.deleted)
        .ok_or_else(|| anyhow!("no such item"))?;
    let info = Listing::new(stored).info(&item, false, false);
    write(s, vault, vec![DataOp::delete(id, crate::config::now())])?;
    Ok(info)
}

/// Brings back the one deleted item `query` matches, as it was.
pub fn restore(s: &mut Loaded, vault: Option<&str>, query: &[String]) -> Result<ItemInfo> {
    let vault = s.resolve(vault)?;
    let id = Listing::deleted(s.vault(&vault)).find(query)?.id;
    write(s, vault, vec![DataOp::restore(id)])?;
    Ok(info(s, vault, &id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadbolt_core::listing::normalize;

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

    fn otp_input(name: &str, value: &str) -> FieldInput {
        FieldInput {
            name: name.into(),
            kind: Some("otp".into()),
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
        let fields = vec![otp_input("backup", &secret.to_lowercase())];
        set(&mut s, None, &words("plain"), fields, None, &[]).unwrap();
        let code = super::code(&s, None, &words("plain"), at(59)).unwrap();
        assert_eq!(code.code.as_str(), "287082");
    }

    /// Deleted items list newest first and only there, read by query with
    /// `deleted`, and a restore brings one back with its values.
    #[test]
    fn deleted_items_list_apart_and_restore() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        for name in ["Alpha", "Beta", "Gamma"] {
            let fields = vec![input("password", &format!("{name}-pw"))];
            create(&mut s, None, "login", Some(name.into()), fields).unwrap();
        }
        remove(&mut s, None, &words("alpha")).unwrap();
        remove(&mut s, None, &words("beta")).unwrap();
        let labels = |s: &Loaded, deleted| {
            list(s, None, &[], None, deleted)
                .unwrap()
                .into_iter()
                .map(|i| (i.label, i.deleted_at.is_some()))
                .collect::<Vec<_>>()
        };
        assert_eq!(labels(&s, false), [("Gamma".into(), false)]);
        // Both were deleted within the same second: then by id, so check
        // the set rather than the order.
        let mut gone = labels(&s, true);
        gone.sort();
        assert_eq!(gone, [("Alpha".into(), true), ("Beta".into(), true)]);
        assert!(get(&s, None, &words("alpha"), false, &[], false).is_err());
        let alpha = get(&s, None, &words("alpha"), false, &[], true).unwrap();
        assert_eq!(alpha.fields[0].value, "Alpha-pw");
        assert!(restore(&mut s, None, &words("gamma")).is_err());

        let back = restore(&mut s, None, &words("alpha")).unwrap();
        assert_eq!((back.label.as_str(), back.deleted_at), ("Alpha", None));
        let alpha = get(&s, None, &words("alpha"), false, &[], false).unwrap();
        assert_eq!(alpha.fields[0].value, "Alpha-pw");
        assert_eq!(labels(&s, true), [("Beta".into(), true)]);
    }

    /// Under a millisecond before the boundary still reads as time left.
    #[test]
    fn a_code_always_has_time_left() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let fields = vec![input("password", "pw"), input("otp", "JBSWY3DPEHPK3PXP")];
        create(&mut s, None, "login", Some("Site".into()), fields).unwrap();
        let code = code(&s, None, &words("site"), Duration::from_micros(59_999_700)).unwrap();
        assert_eq!((code.valid_until, code.remaining_ms), (60, 1));
    }

    /// Every field of type otp comes back empty unless asked for.
    #[test]
    fn items_leave_otp_secrets_out_unless_asked() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let extra = otp_input("backup", "KRSXG5CTMVRXEZLU");
        let fields = vec![
            input("password", "pw"),
            input("otp", "JBSWY3DPEHPK3PXP"),
            extra,
        ];
        create(&mut s, None, "login", Some("Site".into()), fields).unwrap();
        let values = |otp| {
            let item = get(&s, None, &words("site"), otp, &[], false).unwrap();
            item.fields
                .into_iter()
                .map(|f| (f.name.clone(), f.value.clone()))
                .collect::<Vec<_>>()
        };
        let pair = |a: &str, b: &str| (a.to_owned(), b.to_owned());
        assert_eq!(
            values(false),
            [pair("password", "pw"), pair("otp", ""), pair("backup", "")]
        );
        assert_eq!(
            values(true),
            [
                pair("password", "pw"),
                pair("otp", "JBSWY3DPEHPK3PXP"),
                pair("backup", "KRSXG5CTMVRXEZLU")
            ]
        );
    }

    /// Asking for one file sends that file alone: an item with five files
    /// near the item's cap between them still reads one at a time.
    #[test]
    fn a_get_carries_only_the_files_it_names() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let each = deadbolt_core::item::MAX_FILE / 5 - 1024;
        let fields: Vec<FieldInput> = (0..5u8)
            .map(|i| FieldInput {
                name: format!("part-{i}"),
                kind: Some("file".into()),
                value: deadbolt_core::item::file_value(&format!("{i}.bin"), &vec![i; each])
                    .to_string(),
            })
            .collect();
        create(&mut s, None, "note", Some("Parts".into()), fields).unwrap();
        // A sixth would take the item past the cap.
        let sixth = FieldInput {
            name: "part-5".into(),
            kind: Some("file".into()),
            value: deadbolt_core::item::file_value("5.bin", &vec![5; each]).to_string(),
        };
        let error = set(&mut s, None, &words("parts"), vec![sixth], None, &[]).unwrap_err();
        assert!(
            error.to_string().contains("at most 10 MiB together"),
            "{error}"
        );

        let item = get(
            &s,
            None,
            &words("parts"),
            false,
            &["part-3".to_string()],
            false,
        )
        .unwrap();
        for field in &item.fields {
            let (name, contents) = deadbolt_core::item::file_parts(&field.value);
            if field.name == "part-3" {
                let decoded = data_encoding::BASE64.decode(contents.unwrap().as_bytes());
                assert_eq!(decoded.unwrap(), vec![3; each]);
            } else {
                assert_eq!(contents, None, "{}", field.name);
                assert!(name.ends_with(".bin"));
            }
        }
        let reply = serde_json::to_string(&item).unwrap();
        assert!(
            reply.len() < each * 4 / 3 + 4096,
            "one file's worth: {}",
            reply.len()
        );
        let none = get(&s, None, &words("parts"), false, &[], false).unwrap();
        assert!(none.fields.iter().all(|f| !f.value.contains('\n')));
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
            &[],
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

    /// A 1PUX with "Sign in with" logins: one linked to an account later
    /// in the export, one without a link, one linked to an item not in it.
    fn sign_in_export(with_account: bool, with_rest: bool) -> String {
        let sso = |uuid: &str, title: &str, url: &str, value: &str| {
            format!(
                r#"{{"uuid": "{uuid}", "state": "active", "categoryUuid": "001", "updatedAt": 1,
                  "details": {{"sections": [{{"title": "", "fields": [
                    {{"title": "", "id": "sso", "value": {{"ssoLogin": {value}}}}}]}}]}},
                  "overview": {{"title": "{title}", "url": "{url}"}}}}"#
            )
        };
        let mut items = Vec::new();
        if with_rest {
            items.push(sso(
                "notion",
                "Notion",
                "https://www.notion.so",
                r#"{"provider": "google", "item": {"itemUuid": "gacct", "vaultUuid": "v1"}}"#,
            ));
            items.push(sso(
                "figma",
                "Figma",
                "https://figma.com",
                r#"{"provider": "twitter"}"#,
            ));
            items.push(sso(
                "linear",
                "Linear",
                "https://linear.app",
                r#"{"provider": "github", "item": {"itemUuid": "gone", "vaultUuid": "v1"}}"#,
            ));
        }
        if with_account {
            items.push(
                r#"{"uuid": "gacct", "state": "active", "categoryUuid": "001", "updatedAt": 1,
                  "details": {"loginFields": [
                    {"value": "dax@gmail.com", "designation": "username"},
                    {"value": "google-pw", "fieldType": "P", "designation": "password"}]},
                  "overview": {"title": "Google", "url": "https://accounts.google.com"}}"#
                    .to_string(),
            );
        }
        format!(
            r#"{{"accounts": [{{"attrs": {{"uuid": "USER"}}, "vaults": [{{"attrs": {{"uuid": "v1"}}, "items": [{}]}}]}}]}}"#,
            items.join(",")
        )
    }

    #[test]
    fn sign_in_methods_are_kept_and_linked_to_their_accounts() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let export = sign_in_export(true, true);
        let report = import(&mut s, &export, false);
        let lines = [
            "kept 3 sign-in methods (GitHub 1, Google 1, X 1)",
            "linked 1 to their accounts",
            "warning: 1 sign-in method links to an account not in this export (kept without the link)",
        ];
        assert_eq!(report.lines(false)[1..], lines);
        assert_eq!(count(&s), 0);
        let report = import(&mut s, &export, true);
        assert_eq!(report.lines(true)[1..], lines);
        let vault = s.resolve(None).unwrap();
        let named = |s: &Loaded, name: &str| {
            s.vault(&vault)
                .items()
                .into_iter()
                .find(|i| i.name.as_deref() == Some(name))
                .unwrap()
        };
        let google = named(&s, "Google");
        let notion = named(&s, "Notion");
        let value = |item: &Item, field: &str| item.fields.get(field).map(|f| f.value.clone());
        assert_eq!(value(&notion, "sign-in-with").as_deref(), Some("google"));
        assert_eq!(
            value(&notion, "sign-in-account"),
            Some(hex(google.id.as_bytes()))
        );
        assert_eq!(value(&notion, "password"), None);
        // Its source still records the digest of the item as it is.
        let version = MirrorVersion::parse(&notion.source.as_ref().unwrap().version).unwrap();
        assert_eq!(
            version.digest,
            digest(&notion.kind, notion.name.as_deref(), &notion.fields)
        );
        let figma = named(&s, "Figma");
        assert_eq!(value(&figma, "sign-in-with").as_deref(), Some("x"));
        assert_eq!(value(&named(&s, "Linear"), "sign-in-account"), None);
        let listed = list(&s, None, &words("notion"), None, false).unwrap();
        assert_eq!(listed[0].detail.as_deref(), Some("Sign in with Google"));
        // The link is not content: importing again adds nothing.
        let again = import(&mut s, &export, true);
        assert_eq!((again.total(), again.duplicates), (0, 4));
        assert_eq!(again.lines(true)[1..], ["skipped 4 duplicates"]);
        assert_eq!(count(&s), 4);
    }

    /// An account imported before, and so a duplicate now, is linked to.
    #[test]
    fn sign_in_methods_link_to_an_account_already_here() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        import(&mut s, &sign_in_export(true, false), true);
        let report = import(&mut s, &sign_in_export(true, true), true);
        assert_eq!((report.total(), report.duplicates), (3, 1));
        assert_eq!(report.sign_in.linked, 1);
        let vault = s.resolve(None).unwrap();
        let items = s.vault(&vault).items();
        let google = items
            .iter()
            .find(|i| i.name.as_deref() == Some("Google"))
            .unwrap();
        let notion = items
            .iter()
            .find(|i| i.name.as_deref() == Some("Notion"))
            .unwrap();
        assert_eq!(
            notion.fields["sign-in-account"].value,
            hex(google.id.as_bytes())
        );
    }

    /// The app saves an edit as one change: fields set, emptied ones
    /// removed and the name, in one entry.
    #[test]
    fn a_set_removes_its_unset_fields_in_the_same_entry() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let input = |name: &str, value: &str| FieldInput {
            name: name.into(),
            kind: None,
            value: value.into(),
        };
        let fields = vec![input("password", "pw-1"), input("notes", "old")];
        let id = create(&mut s, None, "login", None, fields).unwrap().id;
        let vault = s.resolve(None).unwrap();
        let before = s.vault(&vault).entries().len();
        let query = [id];
        let unset = ["notes".to_string()];
        let fields = vec![input("password", "pw-2")];
        let name = Some("GitHub".into());
        let item = set(&mut s, None, &query, fields, name, &unset).unwrap();
        assert_eq!(s.vault(&vault).entries().len(), before + 1);
        assert_eq!(item.label, "GitHub");
        let item = get(&s, None, &query, false, &[], false).unwrap();
        let fields: Vec<(&str, &str)> = item
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(fields, [("password", "pw-2")]);

        let card = vec![input("number", "4242424242424242")];
        let card = [create(&mut s, None, "card", None, card).unwrap().id];
        let required = ["number".to_string()];
        let error = set(&mut s, None, &card, vec![], None, &required).unwrap_err();
        assert!(error.to_string().contains("required"), "{error}");
        let twice = set(
            &mut s,
            None,
            &query,
            vec![input("url", "a.com")],
            None,
            &["url".into()],
        );
        assert!(twice.unwrap_err().to_string().contains("twice"));
        // The card's creation, and nothing refused.
        assert_eq!(s.vault(&vault).entries().len(), before + 2);
    }

    /// An edit that empties a field another device already removed still
    /// saves, and only its other changes are written. A name the item could
    /// never have, or a required field, is still refused.
    #[test]
    fn a_set_skips_unset_fields_already_gone() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let input = |name: &str, value: &str| FieldInput {
            name: name.into(),
            kind: None,
            value: value.into(),
        };
        let fields = vec![input("password", "pw-1"), input("url", "a.com")];
        let id = create(&mut s, None, "login", None, fields).unwrap().id;
        let vault = s.resolve(None).unwrap();
        let before = s.vault(&vault).entries().len();
        let query = [id];
        let gone = ["notes".to_string(), "pin-hint".to_string()];
        set(&mut s, None, &query, vec![], None, &gone).unwrap();
        assert_eq!(s.vault(&vault).entries().len(), before, "nothing to write");
        let unset = ["notes".to_string(), "url".to_string()];
        let item = set(
            &mut s,
            None,
            &query,
            vec![input("password", "pw-2")],
            None,
            &unset,
        );
        assert!(item.is_ok(), "{item:?}");
        assert_eq!(s.vault(&vault).entries().len(), before + 1);
        let item = get(&s, None, &query, false, &[], false).unwrap();
        let names: Vec<&str> = item.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["password"]);

        let bad = set(&mut s, None, &query, vec![], None, &["Not A Name".into()]);
        assert!(bad.unwrap_err().to_string().contains("invalid field name"));
        let card = vec![input("number", "4242424242424242")];
        let card = create(&mut s, None, "card", None, card).unwrap().id;
        let error = set(&mut s, None, &[card], vec![], None, &["expiry".into()]);
        assert!(error.is_ok(), "an optional field: {error:?}");
        assert_eq!(s.vault(&vault).entries().len(), before + 2);
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
            v.create_items(secret, [DataOp::create("card", None, fields)])?;
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
            ("https://bücher.de", "xn--bcher-kva.de"),
            // Labelled where autofill would fill it, not where it seems to go.
            ("https://evil.com\\@github.com", "evil.com"),
            ("https://evil.com\\@www.github.com/login", "evil.com"),
            ("https://github.com@evil.com", "evil.com"),
            ("https://exa mple.com", ""),
            ("", ""),
        ] {
            assert_eq!(host(url), host_, "{url}");
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
            source: None,
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
            &[
                ("given-name", "Dax"),
                ("family-name", "Raad"),
                ("email", "dax@example.com"),
            ],
        );
        assert_eq!(detail(&me).as_deref(), Some("dax@example.com"));
        assert!(matches(&me, &q(&["raad", "example"])));
        let unnamed = item(
            "identity",
            None,
            &[("given-name", "Dax"), ("family-name", "Raad")],
        );
        assert_eq!(label(&unnamed), "Dax Raad");
        // One made before names had parts still reads by its old name.
        let legacy = item("identity", None, &[("name", "Kit Langton")]);
        assert_eq!(label(&legacy), "Kit Langton");
        assert!(matches(&legacy, &q(&["langton"])));
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
    fn login_labels_use_the_browser_title_rules() {
        for (name, fields, expected) in [
            (
                Some("Personal"),
                vec![("url", "https://www.github.com")],
                "Personal",
            ),
            (None, vec![("url", "https://www.github.com")], "github.com"),
            (
                None,
                vec![("url", "https://[2001:DB8::1]")],
                "[2001:db8::1]",
            ),
            (None, vec![("url", "not a url"), ("username", "kit")], "kit"),
            (
                None,
                vec![("url", "https://www."), ("username", "kit")],
                "kit",
            ),
            (None, vec![("url", "https://www.")], "login"),
            (None, vec![("password", "never a title")], "login"),
        ] {
            assert_eq!(label(&item("login", name, &fields)), expected);
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
        assert_eq!(
            n("identity", "phone", FieldType::Text, "+1 (555) 010-0100"),
            "+15550100100"
        );
        assert_eq!(
            n("identity", "phone", FieldType::Text, "(555) 010-0100"),
            "(555) 010-0100"
        );
        assert_eq!(n("identity", "country", FieldType::Text, "gb"), "GB");
        assert_eq!(n("identity", "country", FieldType::Text, "Wales"), "Wales");
    }
}
