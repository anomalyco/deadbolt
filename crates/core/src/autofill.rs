//! Shared login fields and comparison rules for the native agent and browser device.

use crate::{Field, FieldType, Item};

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
