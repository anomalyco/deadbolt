//! Shared login fields and comparison rules for the native agent and browser device.

use std::cmp::Reverse;

use crate::site::{Closeness, closeness, url_host};
use crate::{DataOp, Field, FieldType, Item, ItemId};

/// How a submitted login compares with the site's saved logins, in priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    New,
    Update,
    Same,
}

/// Callers supply only live logins on the page's site. Without a username,
/// any username with the same password is `Same`, and nothing is `Update`.
pub fn check<'a>(
    items: impl IntoIterator<Item = &'a Item>,
    username: Option<&str>,
    password: &str,
) -> (Status, Vec<ItemId>) {
    let mut same = Vec::new();
    let mut other = Vec::new();
    for item in items {
        if !username.is_none_or(|u| same_username(value(item, "username"), u)) {
            continue;
        }
        if same_password(value(item, "password"), password) {
            same.push(item.id);
        } else {
            other.push(item.id);
        }
    }
    if !same.is_empty() {
        (Status::Same, same)
    } else if !other.is_empty() && username.is_some() {
        (Status::Update, other)
    } else {
        (Status::New, Vec::new())
    }
}

/// A login's name, else its URL host, username, or kind. Never a secret.
pub fn login_title(item: &Item) -> String {
    item.name.clone().unwrap_or_else(|| {
        value(item, "url")
            .and_then(url_host)
            .map(|host| {
                let host = host.strip_prefix("www.").unwrap_or(&host);
                if host.contains(':') {
                    format!("[{host}]")
                } else {
                    host.to_owned()
                }
            })
            .filter(|host| !host.is_empty())
            .or_else(|| value(item, "username").map(str::to_owned))
            .unwrap_or_else(|| "login".into())
    })
}

/// Closest site match, then starred, then most recently filled, title and username.
/// Callers break remaining ties by vault and item reference.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rank {
    closeness: Closeness,
    favorite: Reverse<bool>,
    used: Reverse<u64>,
    title: String,
    username: Option<String>,
}

pub fn rank(origin: &str, item: &Item, used: u64) -> Rank {
    Rank {
        closeness: urls(item)
            .filter_map(|url| closeness(origin, url))
            .min()
            .unwrap_or(Closeness::Site),
        favorite: Reverse(item.favorite),
        used: Reverse(used),
        title: login_title(item).to_lowercase(),
        username: value(item, "username").map(str::to_owned),
    }
}

/// A submitted page may update only the saved password, never other fields.
pub fn password_update(id: ItemId, password: &str) -> DataOp {
    DataOp::set(id, "password", Field::new(FieldType::Secret, password))
}

pub fn value<'a>(item: &'a Item, field: &str) -> Option<&'a str> {
    item.fields
        .get(field)
        .map(|f| f.value.as_str())
        .filter(|v| !v.is_empty())
}

/// A login's URLs: its fields of type url (`url`, and `url-2`… from imports).
pub fn urls(item: &Item) -> impl Iterator<Item = &str> {
    item.fields
        .values()
        .filter(|f| f.kind == FieldType::Url)
        .map(|f| f.value.as_str())
}

/// The `otp` field, else the first of type otp, as `ItemCode` picks it.
pub fn otp(item: &Item) -> Option<&Field> {
    item.fields
        .get("otp")
        .filter(|f| f.kind == FieldType::Otp)
        .or_else(|| item.fields.values().find(|f| f.kind == FieldType::Otp))
}

pub fn same_username(saved: Option<&str>, typed: &str) -> bool {
    saved.unwrap_or_default().trim().to_lowercase() == typed.trim().to_lowercase()
}

/// Constant-time: BLAKE3 hashes compare in constant time, and hashing
/// first hides the lengths too.
pub fn same_password(saved: Option<&str>, typed: &str) -> bool {
    blake3::hash(saved.unwrap_or_default().as_bytes()) == blake3::hash(typed.as_bytes())
}

/// The longest item name the vault takes.
const MAX_NAME: usize = 128;

/// A page title as an item name: runs of spaces and control characters
/// become one space, trimmed, and cut to [`MAX_NAME`] characters.
pub fn item_name(title: &str) -> String {
    let mut name = String::new();
    for word in title.split(|c: char| c.is_whitespace() || c.is_control()) {
        if word.is_empty() {
            continue;
        }
        if !name.is_empty() {
            name.push(' ');
        }
        name.push_str(word);
    }
    if let Some((end, _)) = name.char_indices().nth(MAX_NAME) {
        name.truncate(end);
        name.truncate(name.trim_end().len());
    }
    name
}
