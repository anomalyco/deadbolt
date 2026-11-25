//! Importing a mapped export (`crate::import`) into a vault: duplicates
//! of items already here are skipped, and sign-in methods are linked to
//! their accounts.

use std::collections::BTreeMap;

use anyhow::Result;
use deadbolt_core::{DataOp, Field, FieldType, Item, ItemId, Source};
use deadbolt_engine::items::host;
use zeroize::Zeroize;

use super::session::{Loaded, hex};
use crate::import::onepassword::source_key;
use crate::import::{Imported, MirrorVersion, digest};
use crate::protocol::{ImportReport, Tally};

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;

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
fn relinked_source(item: Item, field: &Field) -> Option<DataOp> {
    let source = item.source.as_ref()?;
    let mut version = MirrorVersion::parse(&source.version)?;
    let mut fields = item.fields;
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
    Some(DataOp::source(item.id, Some(source)))
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
                ops.extend(v.item(&id).and_then(|item| relinked_source(item, &field)));
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
