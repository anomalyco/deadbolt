//! Cleaning tag and folder names from external password-manager exports.

use std::collections::{BTreeSet, HashMap};

use deadbolt_core::tag::{MAX_TAGS, fold_tag, import_tag};
use serde_json::Value;

use super::text;

/// Collects up to [`MAX_TAGS`] valid, case-deduplicated tags from raw strings.
pub fn collect(raw: impl IntoIterator<Item = impl AsRef<str>>) -> BTreeSet<String> {
    let mut by_folded = HashMap::new();
    for value in raw {
        if let Some(clean) = import_tag(value.as_ref()) {
            let key = fold_tag(&clean);
            if by_folded.len() < MAX_TAGS || by_folded.contains_key(&key) {
                by_folded.entry(key).or_insert(clean);
            }
        }
    }
    by_folded.into_values().collect()
}

/// Maps `[{ "id": "...", "name": "Work/AWS" }]` (Bitwarden folders or
/// collections) from `id` to normalized tag path.
pub fn id_map(entries: &[Value]) -> HashMap<String, String> {
    entries
        .iter()
        .filter_map(|entry| {
            let id = text(entry, "id")?;
            let name = text(entry, "name")?;
            if name.eq_ignore_ascii_case("No Folder") {
                return None;
            }
            Some((id, import_tag(&name)?))
        })
        .collect()
}
