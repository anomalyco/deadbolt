//! Item commands: lookup, labels, input normalization and writes.
//!
//! Lookup is search. Every query word must match (case-insensitively) part
//! of the item's name, URL host, a login's username, a card's cardholder,
//! brand field or last four digits, an SSH key's comment, an identity's
//! name parts, organization, email or phone, a passkey's relying party or
//! username, the other types' plain identifying fields, or a tag (see
//! `searchable`); `#tag` filters on `/` tag boundaries, `is:favorite`
//! narrows to starred items, and a word of 4+ hex digits also matches an id
//! prefix. Secret values (a secure note's body among them) and the derived
//! label are never searched.
//!
//! A file field's contents leave only when asked for (`get` with `files`):
//! otherwise it comes back as its file name alone.
//!
//! A passkey's private key never leaves the agent: items come back without
//! it (see `passkeys`).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use deadbolt_core::tag::{MAX_TAGS, Query, fold_tag, item_has_tag, normalize_tag, tag_counts};
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
use crate::protocol::{Code, FieldInfo, FieldInput, ImportReport, ItemInfo, TagCount, Tally};

const MIN_SHORT: usize = 4;

use deadbolt_core::listing::{detail, input_field, searchable};
pub use deadbolt_core::listing::{host, label};

#[cfg(test)]
#[path = "items_tests.rs"]
mod tests;

pub(super) fn matches(item: &Item, query: &[String], has_any_tagged: bool) -> bool {
    let parsed = Query::from_words(query);
    if parsed.favorite && !item.favorite {
        return false;
    }
    if parsed.any_tag && has_any_tagged && item.tags.is_empty() {
        return false;
    }
    if !parsed
        .tags
        .iter()
        .all(|t| item_has_tag(item.tags.iter().map(String::as_str), t))
    {
        return false;
    }
    let texts = searchable(item);
    let id = item.id.to_string();
    parsed.words.iter().all(|word| {
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

    pub(super) fn has_any_tagged(&self) -> bool {
        self.items.iter().any(|i| !i.tags.is_empty())
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
            favorite: item.favorite,
            tags: item.tags.iter().cloned().collect(),
            deleted_at: self
                .deleted
                .as_ref()
                .and_then(|at| at.get(&item.id).copied()),
        }
    }

    pub(super) fn find(&self, query: &[String]) -> Result<&Item> {
        let any_tagged = self.has_any_tagged();
        let found: Vec<&Item> = self
            .items
            .iter()
            .filter(|i| matches(i, query, any_tagged))
            .collect();
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

fn clean_tags(raw: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Vec<String>> {
    let mut seen = BTreeMap::new();
    for t in raw {
        let raw = t.as_ref();
        let clean = normalize_tag(raw).ok_or_else(|| {
            anyhow!("invalid tag {raw:?}: use 1-128 characters with non-empty / segments")
        })?;
        seen.insert(fold_tag(&clean), clean);
    }
    if seen.len() > MAX_TAGS {
        return Err(ItemError::TooManyTags.into());
    }
    Ok(seen.into_values().collect())
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

/// "personal › GitHub": the one item `query` finds, without its values,
/// to name it in a Touch ID prompt.
pub fn named(s: &Loaded, vault: Option<&str>, query: &[String], deleted: bool) -> Result<String> {
    let vault = s.vault(&s.resolve(vault)?);
    let listing = Listing::pick(vault, deleted);
    let item = listing.find(query)?;
    Ok(format!("{} › {}", vault.name(), label(item)))
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

#[cfg(test)]
pub fn list(
    s: &Loaded,
    vault: Option<&str>,
    query: &[String],
    kind: Option<&str>,
    deleted: bool,
) -> Result<Vec<ItemInfo>> {
    list_filtered(s, vault, query, kind, deleted, &[], false)
}

/// Matching items (favorites first, then by label), or with `deleted` the
/// deleted ones newest first.
pub fn list_filtered(
    s: &Loaded,
    vault: Option<&str>,
    query: &[String],
    kind: Option<&str>,
    deleted: bool,
    filter_tags: &[String],
    favorites_only: bool,
) -> Result<Vec<ItemInfo>> {
    let listing = Listing::pick(s.vault(&s.resolve(vault)?), deleted);
    let any_tagged = listing.has_any_tagged();
    let mut items: Vec<ItemInfo> = listing
        .items
        .iter()
        .filter(|i| {
            kind.is_none_or(|k| i.kind == k)
                && (!favorites_only || i.favorite)
                && filter_tags
                    .iter()
                    .all(|t| item_has_tag(i.tags.iter().map(String::as_str), t))
                && matches(i, query, any_tagged)
        })
        .map(|i| listing.info(i, false, false))
        .collect();
    if !deleted {
        items.sort_by(|a, b| {
            (!a.favorite, a.label.to_lowercase(), &a.id).cmp(&(
                !b.favorite,
                b.label.to_lowercase(),
                &b.id,
            ))
        });
    }
    Ok(items)
}

pub fn tags(s: &Loaded, vault: Option<&str>) -> Result<Vec<TagCount>> {
    let items = s.vault(&s.resolve(vault)?).items();
    Ok(
        tag_counts(items.iter().map(|i| i.tags.iter().map(String::as_str)))
            .into_iter()
            .map(|(tag, count)| TagCount { tag, count })
            .collect(),
    )
}

pub fn create(
    s: &mut Loaded,
    vault: Option<&str>,
    kind: &str,
    name: Option<String>,
    inputs: Vec<FieldInput>,
) -> Result<ItemInfo> {
    create_with(s, vault, kind, name, inputs, false, Vec::new())
}

pub fn create_with(
    s: &mut Loaded,
    vault: Option<&str>,
    kind: &str,
    name: Option<String>,
    inputs: Vec<FieldInput>,
    favorite: bool,
    tags: Vec<String>,
) -> Result<ItemInfo> {
    let vault = s.resolve(vault)?;
    let fields = fields(kind, None, inputs)?;
    let tags = clean_tags(tags)?;
    let stamp = deadbolt_core::health::audited_password_field(kind)
        .is_some_and(|pw| fields.iter().any(|(n, _)| n == pw));
    let today = stamp.then(crate::config::today_utc);
    let name = name.filter(|n| !n.is_empty());
    let (id, _) = s.update(vault, |v, secret| {
        let (id, entry) = v.create_item_with(secret, kind, name, fields, favorite, tags)?;
        if let Some(date) = today {
            v.write(secret, vec![DataOp::password_changed(id, Some(date))])?;
        }
        Ok((id, entry))
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
    version.digest = digest(
        &item.kind,
        item.name.as_deref(),
        &fields,
        item.favorite,
        &item.tags,
    );
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
    let mut dates = Vec::new();
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
        if let Some(date) = item.password_changed {
            dates.push((new.len(), date));
        }
        new.push(DataOp::Create {
            kind: item.kind.to_string(),
            name: item.name,
            fields: item.fields,
            source: item.source,
            favorite: item.favorite,
            tags: item.tags,
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
            for (at, date) in dates {
                ops.push(DataOp::password_changed(ids[at], Some(date)));
            }
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

#[cfg(test)]
pub fn set(
    s: &mut Loaded,
    vault: Option<&str>,
    query: &[String],
    inputs: Vec<FieldInput>,
    name: Option<String>,
    unset: &[String],
) -> Result<ItemInfo> {
    set_with(s, vault, query, inputs, name, unset, None, &[], &[])
}

#[expect(
    clippy::too_many_arguments,
    reason = "ItemSet carries fields, name, unset, favorite and tag deltas in one atomic entry"
)]
pub fn set_with(
    s: &mut Loaded,
    vault: Option<&str>,
    query: &[String],
    inputs: Vec<FieldInput>,
    name: Option<String>,
    unset: &[String],
    favorite: Option<bool>,
    add_tags: &[String],
    remove_tags: &[String],
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
    let added = clean_tags(add_tags)?;
    let removed = clean_tags(remove_tags)?;
    for t in &removed {
        if added.iter().any(|a| fold_tag(a) == fold_tag(t)) {
            bail!("tag {t} given in both --tag and --untag");
        }
    }
    let pw_field = deadbolt_core::health::audited_password_field(&item.kind);
    let pw_changed = pw_field.and_then(|pw| {
        if let Some((_, next)) = set.iter().find(|(n, _)| n == pw) {
            let changed = item.fields.get(pw).is_none_or(|prev| {
                !deadbolt_core::autofill::same_password(Some(&prev.value), &next.value)
            });
            changed.then(|| Some(crate::config::today_utc()))
        } else if unset.iter().any(|n| n == pw) && item.fields.contains_key(pw) {
            Some(None)
        } else {
            None
        }
    });
    let mut ops: Vec<DataOp> = set
        .into_iter()
        .map(|(name, field)| DataOp::set(item.id, name, field))
        .collect();
    if let Some(date) = pw_changed {
        ops.push(DataOp::password_changed(item.id, date));
    }
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
    if let Some(fav) = favorite
        && item.favorite != fav
    {
        ops.push(DataOp::favorite(item.id, fav));
    }
    for t in &added {
        if !item.tags.contains(t) {
            ops.push(DataOp::tag_add(item.id, t.clone()));
        }
    }
    for t in &removed {
        if item.tags.iter().any(|e| fold_tag(e) == fold_tag(t)) {
            ops.push(DataOp::tag_remove(item.id, t.clone()));
        }
    }
    let nothing_given = ops.is_empty()
        && unset.is_empty()
        && favorite.is_none()
        && added.is_empty()
        && removed.is_empty();
    if nothing_given {
        bail!("nothing to change: give field=value assignments, --name, --favorite or --tag");
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
    let mut ops = vec![DataOp::remove(item.id, field)];
    if deadbolt_core::health::audited_password_field(&item.kind) == Some(field) {
        ops.push(DataOp::password_changed(item.id, None));
    }
    write(s, vault, ops)?;
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
