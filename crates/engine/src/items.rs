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
//! A passkey's private key never leaves the daemon: items come back without
//! it (see `passkeys`).

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use deadbolt_core::tag::{MAX_TAGS, Query, fold_tag, item_has_tag, normalize_tag, tag_counts};
use deadbolt_core::totp::Totp;
use deadbolt_core::v2::FrameId;
use deadbolt_core::{
    DataOp, Field, FieldType, Item, ItemError, ItemId, Vault, VaultId, schema, valid_name,
};
use zeroize::Zeroize;

use deadbolt_core::listing::{detail, input_field, searchable};
pub use deadbolt_core::listing::{host, label};
use deadbolt_proto::daemon::{Code, FieldInfo, FieldInput, ItemInfo, Secret, TagCount};

use crate::Engine;

const MIN_SHORT: usize = 4;

#[cfg(test)]
mod tests;

/// `short<TAB>label[<TAB>detail]`, as `ls` prints it.
pub fn line(item: &ItemInfo) -> String {
    match &item.detail {
        Some(detail) => format!("{}\t{}\t{detail}", item.short, item.label),
        None => format!("{}\t{}", item.short, item.label),
    }
}

pub fn matches(item: &Item, query: &[String], has_any_tagged: bool) -> bool {
    matches_parsed(item, &Query::from_words(query), has_any_tagged)
}

fn matches_parsed(item: &Item, parsed: &Query, has_any_tagged: bool) -> bool {
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
        // A whole item id names that item and no other, whatever text holds it
        // (the browser host changes an identity or card by its id).
        if word.len() == id.len() && word.bytes().all(|b| b.is_ascii_hexdigit()) {
            return word == id;
        }
        texts.iter().any(|t| t.contains(&word))
            || (word.len() >= MIN_SHORT
                && word.bytes().all(|b| b.is_ascii_hexdigit())
                && id.starts_with(&word))
    })
}

/// Shortest unique id prefix of `id` among `ids` (sorted), at least 4.
fn short_id(ids: &[String], id: &str) -> String {
    let at = ids
        .binary_search_by(|x| x.as_str().cmp(id))
        .unwrap_or_else(|i| i);
    let neighbours = [at.checked_sub(1), Some(at + 1)];
    short_between(
        id,
        neighbours
            .into_iter()
            .flatten()
            .filter_map(|i| ids.get(i).map(String::as_str)),
    )
}

fn short_between<'a>(id: &str, neighbours: impl Iterator<Item = &'a str>) -> String {
    let common = |other: &str| {
        id.bytes()
            .zip(other.bytes())
            .take_while(|(a, b)| a == b)
            .count()
    };
    let shared = neighbours
        .filter(|other| *other != id)
        .map(common)
        .max()
        .unwrap_or(0);
    id[..(shared + 1).clamp(MIN_SHORT, id.len())].to_string()
}

pub struct Listing {
    pub items: Vec<Item>,
    ids: Vec<String>,
    /// A listing of deleted items, and when each was deleted.
    deleted: Option<BTreeMap<ItemId, u64>>,
}

impl Listing {
    pub fn new(vault: &Vault) -> Self {
        Self::of(vault.items(), None)
    }

    /// The deleted items instead, newest first ([`Vault::deleted`]). Short
    /// ids are unique among them.
    pub fn deleted(vault: &Vault) -> Self {
        let deleted = vault.deleted();
        let at = deleted
            .iter()
            .filter_map(|d| Some((d.item.id, d.at?)))
            .collect();
        Self::of(deleted.into_iter().map(|d| d.item).collect(), Some(at))
    }

    /// The live items, or with `deleted` the deleted ones.
    pub fn pick(vault: &Vault, deleted: bool) -> Self {
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

    pub fn has_any_tagged(&self) -> bool {
        self.items.iter().any(|i| !i.tags.is_empty())
    }

    /// The item, without field values unless `with_fields`, and without
    /// one-time password secrets unless `with_otp` too. Files come as their
    /// names alone.
    pub fn info(&self, item: &Item, with_fields: bool, with_otp: bool) -> ItemInfo {
        self.info_with(item, with_fields, with_otp, true)
    }

    pub fn info_with(
        &self,
        item: &Item,
        with_fields: bool,
        with_otp: bool,
        with_ssh_private: bool,
    ) -> ItemInfo {
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
                .filter(|name| !crate::passkeys::private(item, name));
            fields = order
                .map(|name| FieldInfo {
                    name: name.into(),
                    kind: item.fields[name].kind.to_string(),
                    value: match item.fields[name].kind {
                        FieldType::Otp if !with_otp => String::new(),
                        _ if !with_ssh_private
                            && item.kind == "ssh"
                            && matches!(name, "private-key" | "passphrase") =>
                        {
                            String::new()
                        }
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
        summarize(
            item,
            short_id(&self.ids, &item.id.to_string()),
            fields,
            self.deleted
                .as_ref()
                .and_then(|at| at.get(&item.id).copied()),
        )
    }

    pub fn find(&self, query: &[String]) -> Result<&Item> {
        let parsed = Query::from_words(query);
        let tagged = parsed.any_tag && self.has_any_tagged();
        unique_match(
            self.items
                .iter()
                .filter(|i| matches_parsed(i, &parsed, tagged)),
            query,
            self.deleted.is_some(),
            |item| self.info(item, false, false),
        )
    }
}

/// Single-target writes search one materialized item at a time. Only on an
/// ambiguous query do we retain multiple rows, and then just public labels.
pub fn find_live(vault: &Vault, query: &[String]) -> Result<Item> {
    let parsed = Query::from_words(query);
    let tagged = parsed.any_tag && vault.iter_items().any(|i| !i.tags.is_empty());
    unique_match(
        vault
            .iter_items()
            .filter(|item| matches_parsed(item, &parsed, tagged)),
        query,
        false,
        |item| live_summary(vault, item),
    )
}

fn unique_match<T: Borrow<Item>>(
    mut found: impl Iterator<Item = T>,
    query: &[String],
    deleted: bool,
    describe: impl Fn(&Item) -> ItemInfo,
) -> Result<T> {
    let Some(first) = found.next() else {
        let query = query.join(" ");
        if deleted {
            bail!("no deleted item matches {query:?}");
        }
        bail!("no item matches {query:?}");
    };
    let Some(second) = found.next() else {
        return Ok(first);
    };
    let mut lines: Vec<_> = [first, second]
        .into_iter()
        .chain(found)
        .map(|item| line(&describe(item.borrow())))
        .collect();
    lines.sort();
    let query = query.join(" ");
    bail!(
        "{query:?} matches {} items; add words or use the id:\n{}",
        lines.len(),
        lines.join("\n")
    )
}

fn summarize(
    item: &Item,
    short: String,
    fields: Vec<FieldInfo>,
    deleted_at: Option<u64>,
) -> ItemInfo {
    ItemInfo {
        short,
        id: item.id.to_string(),
        kind: item.kind.clone(),
        label: label(item),
        detail: detail(item),
        fields,
        favorite: item.favorite,
        tags: item.tags.iter().cloned().collect(),
        deleted_at,
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

fn write(s: &mut Engine, vault: VaultId, ops: Vec<DataOp>) -> Result<FrameId> {
    s.update(vault, |v, author| Ok(v.write(author, ops)?))
}

/// The item just written, as listed. A write the vault took but doesn't
/// count (a frame the membership no longer counts) is an error, not a panic.
fn info(s: &Engine, vault: VaultId, id: &ItemId) -> Result<ItemInfo> {
    let vault = s.vault(&vault);
    let item = vault
        .item(id)
        .ok_or_else(|| anyhow!("{id} was written but doesn't count on this device yet"))?;
    Ok(live_summary(vault, &item))
}

// The caller already knows the precise item. Only its immediate live id
// neighbours can lengthen its display prefix; never copy unrelated secrets.
fn live_summary(vault: &Vault, item: &Item) -> ItemInfo {
    let neighbours = vault
        .live_neighbors(item.id)
        .map(|id| id.map(|i| i.to_string()));
    let short = short_between(
        &item.id.to_string(),
        neighbours.iter().filter_map(Option::as_deref),
    );
    summarize(item, short, Vec::new(), None)
}

/// One item with its values; one-time password secrets only with `otp`,
/// and the contents only of the file fields `files` names. With `deleted`,
/// one of the deleted items instead.
pub fn get(
    s: &Engine,
    vault: Option<&str>,
    query: &[String],
    otp: bool,
    ssh_private: bool,
    files: &[String],
    deleted: bool,
) -> Result<ItemInfo> {
    let listing = Listing::pick(s.vault(&s.resolve(vault)?), deleted);
    let item = listing.find(query)?;
    let mut info = listing.info_with(item, true, otp, ssh_private);
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
pub fn code(s: &Engine, vault: Option<&str>, query: &[String], now: Duration) -> Result<Code> {
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
        code: Secret::new(totp.code(now.as_secs())),
        period: totp.period(),
        valid_until,
        // Never 0, which would read as already over.
        remaining_ms: (remaining.as_millis() as u64).max(1),
    })
}

pub fn list(
    s: &Engine,
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
    s: &Engine,
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

pub fn tags(s: &Engine, vault: Option<&str>) -> Result<Vec<TagCount>> {
    let items = s.vault(&s.resolve(vault)?).items();
    Ok(
        tag_counts(items.iter().map(|i| i.tags.iter().map(String::as_str)))
            .into_iter()
            .map(|(tag, count)| TagCount { tag, count })
            .collect(),
    )
}

pub fn create(
    s: &mut Engine,
    vault: Option<&str>,
    kind: &str,
    name: Option<String>,
    inputs: Vec<FieldInput>,
) -> Result<ItemInfo> {
    create_with(s, vault, kind, name, inputs, false, Vec::new())
}

pub fn create_with(
    s: &mut Engine,
    vault: Option<&str>,
    kind: &str,
    name: Option<String>,
    inputs: Vec<FieldInput>,
    favorite: bool,
    tags: Vec<String>,
) -> Result<ItemInfo> {
    let vault = s.resolve(vault)?;
    let mut fields = fields(kind, None, inputs)?;
    if kind == "ssh" {
        derive_ssh_create(&mut fields);
    }
    let tags = clean_tags(tags)?;
    let stamp = deadbolt_core::health::audited_password_field(kind)
        .is_some_and(|pw| fields.iter().any(|(n, _)| n == pw));
    let today = stamp.then(|| s.today());
    let name = name.filter(|n| !n.is_empty());
    let (id, _) = s.update(vault, |v, secret| {
        let (id, entry) = v.create_item_with(secret, kind, name, fields, favorite, tags)?;
        if let Some(date) = today {
            v.write(secret, vec![DataOp::password_changed(id, Some(date))])?;
        }
        Ok((id, entry))
    })?;
    info(s, vault, &id)
}

fn derive_ssh_create(fields: &mut Vec<(String, Field)>) {
    let get = |name: &str| {
        fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, f)| f.value.as_str())
    };
    let Some(private_key) = get("private-key") else {
        return;
    };
    let Some((public_key, fingerprint, file_comment)) =
        crate::ssh_keys::derive_fields(private_key, get("passphrase"), get("comment"))
    else {
        return;
    };
    if !fields.iter().any(|(n, _)| n == "public-key") {
        fields.push(("public-key".into(), Field::new(FieldType::Text, public_key)));
    }
    if !fields.iter().any(|(n, _)| n == "fingerprint") {
        fields.push((
            "fingerprint".into(),
            Field::new(FieldType::Text, fingerprint),
        ));
    }
    if !fields.iter().any(|(n, _)| n == "comment")
        && let Some(comment) = file_comment
    {
        fields.push(("comment".into(), Field::new(FieldType::Text, comment)));
    }
}

pub fn set(
    s: &mut Engine,
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
    s: &mut Engine,
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
    let item = find_live(s.vault(&vault), query)?;
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
            changed.then(|| Some(s.today()))
        } else if unset.iter().any(|n| n == pw) && item.fields.contains_key(pw) {
            Some(None)
        } else {
            None
        }
    });
    let mut ops: Vec<DataOp> = set
        .iter()
        .cloned()
        .map(|(name, field)| DataOp::set(item.id, name, field))
        .collect();
    if let Some(date) = pw_changed {
        ops.push(DataOp::password_changed(item.id, date));
    }
    // When an SSH item's private key (or passphrase/comment) changes, keep
    // derived `public-key` and `fingerprint` in sync unless set explicitly.
    if item.kind == "ssh"
        && (set
            .iter()
            .any(|(n, _)| matches!(n.as_str(), "private-key" | "passphrase" | "comment"))
            || unset
                .iter()
                .any(|n| matches!(n.as_str(), "passphrase" | "comment")))
    {
        let merged = |name: &str| -> Option<&str> {
            if unset.iter().any(|u| u == name) {
                return None;
            }
            set.iter()
                .find(|(n, _)| n == name)
                .map(|(_, f)| f.value.as_str())
                .or_else(|| item.fields.get(name).map(|f| f.value.as_str()))
        };
        if let Some(private_key) = merged("private-key")
            && let Some((public_key, fingerprint, _)) =
                crate::ssh_keys::derive_fields(private_key, merged("passphrase"), merged("comment"))
        {
            if !seen.contains("public-key") {
                ops.push(DataOp::set(
                    item.id,
                    "public-key",
                    Field::new(FieldType::Text, public_key),
                ));
            }
            if !seen.contains("fingerprint") {
                ops.push(DataOp::set(
                    item.id,
                    "fingerprint",
                    Field::new(FieldType::Text, fingerprint),
                ));
            }
        }
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
    info(s, vault, &item.id)
}

pub fn unset(
    s: &mut Engine,
    vault: Option<&str>,
    query: &[String],
    field: &str,
) -> Result<ItemInfo> {
    let vault = s.resolve(vault)?;
    let item = find_live(s.vault(&vault), query)?;
    if !item.fields.contains_key(field) {
        bail!("{} has no field {field}", label(&item));
    }
    let mut ops = vec![DataOp::remove(item.id, field)];
    if deadbolt_core::health::audited_password_field(&item.kind) == Some(field) {
        ops.push(DataOp::password_changed(item.id, None));
    }
    write(s, vault, ops)?;
    info(s, vault, &item.id)
}

pub fn remove(s: &mut Engine, vault: Option<&str>, query: &[String]) -> Result<ItemInfo> {
    let vault = s.resolve(vault)?;
    let listing = Listing::new(s.vault(&vault));
    let item = listing.find(query)?;
    let info = listing.info(item, false, false);
    let delete = DataOp::delete(item.id, s.now());
    write(s, vault, vec![delete])?;
    Ok(info)
}

/// Deletes the exact item selected before consent, never re-running a search.
pub fn remove_id(s: &mut Engine, vault: VaultId, id: ItemId) -> Result<ItemInfo> {
    let stored = s
        .vaults
        .get(&vault)
        .ok_or_else(|| anyhow!("no such vault"))?;
    let item = stored
        .item(&id)
        .filter(|item| !item.deleted)
        .ok_or_else(|| anyhow!("no such item"))?;
    let info = live_summary(stored, &item);
    let now = s.now();
    write(s, vault, vec![DataOp::delete(id, now)])?;
    Ok(info)
}
/// Brings back the one deleted item `query` matches, as it was.
pub fn restore(s: &mut Engine, vault: Option<&str>, query: &[String]) -> Result<ItemInfo> {
    let vault = s.resolve(vault)?;
    let id = Listing::deleted(s.vault(&vault)).find(query)?.id;
    write(s, vault, vec![DataOp::restore(id)])?;
    info(s, vault, &id)
}
