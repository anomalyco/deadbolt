//! Item pages ready before their values land, so a new selection shows its
//! whole page on the frame it's made: what each recently shown or nearby
//! item's page draws while its secrets are hidden, read ahead of the
//! selection (`Job::Peek`).
//!
//! It holds no secret: a secret field's value is left out (a hidden secret
//! draws as twelve dots whatever its length), so Show and Copy still wait
//! for the selected item's own values (`App::detail`). What it keeps, the
//! page shows anyway: names, usernames, URLs, notes, and a one-time code
//! until its period ends. Every value is wiped as it leaves: evicted,
//! replaced, or cleared on a lock, the agent stopping, the panel hiding and
//! any change to the vault (`App::refresh`).

use std::collections::VecDeque;

use deadbolt_client::protocol::{Code, FieldInfo, ItemInfo};

use crate::model::{forget, is_secret};

/// Pages kept, at most: the rows around the selection and the last few
/// shown.
pub const CAP: usize = 32;

#[derive(Default)]
pub struct Cache {
    /// Bumped on clearing: a `Peek` from before is dropped.
    epoch: u64,
    /// Oldest first.
    entries: VecDeque<Entry>,
}

struct Entry {
    item: ItemInfo,
    /// The code with the app's clock when it came.
    code: Option<(Code, f64)>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        forget(&mut self.item);
    }
}

impl Cache {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Forgets every page, wiping them, and drops any `Peek` on its way.
    pub fn clear(&mut self) {
        self.epoch += 1;
        self.entries.clear();
    }

    pub fn remove(&mut self, id: &str) {
        self.entries.retain(|e| e.item.id != id);
    }

    pub fn contains(&self, id: &str) -> bool {
        self.entries.iter().any(|e| e.item.id == id)
    }

    /// The page of `id`: the item with every secret's value left out.
    pub fn get(&self, id: &str) -> Option<&ItemInfo> {
        self.entries
            .iter()
            .find(|e| e.item.id == id)
            .map(|e| &e.item)
    }

    /// `id`'s code as it stands at `now`, while its period lasts.
    pub fn code(&self, id: &str, now: f64) -> Option<Code> {
        let (code, at) = self
            .entries
            .iter()
            .find(|e| e.item.id == id)?
            .code
            .as_ref()?;
        let left = code.remaining_ms as f64 - (now - at) * 1000.0;
        (left >= 1.0).then(|| Code {
            remaining_ms: left as u64,
            ..code.clone()
        })
    }

    /// Keeps `item`'s page, without its secrets, and its code, the newest.
    pub fn insert(&mut self, item: &ItemInfo, code: Option<&Code>, now: f64) {
        self.remove(&item.id);
        let fields = item
            .fields
            .iter()
            .map(|f| FieldInfo {
                name: f.name.clone(),
                kind: f.kind.clone(),
                value: if is_secret(&f.kind) {
                    String::new()
                } else {
                    f.value.clone()
                },
            })
            .collect();
        self.entries.push_back(Entry {
            item: ItemInfo {
                id: item.id.clone(),
                short: item.short.clone(),
                kind: item.kind.clone(),
                label: item.label.clone(),
                detail: item.detail.clone(),
                fields,
                source: item.source.clone(),
                favorite: item.favorite,
                tags: item.tags.clone(),
            },
            code: code.map(|c| (c.clone(), now)),
        });
        while self.entries.len() > CAP {
            self.entries.pop_front();
        }
    }

    /// Updates `favorite` on a cached page if kept.
    pub fn set_favorite(&mut self, id: &str, favorite: bool) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.item.id == id) {
            entry.item.favorite = favorite;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str) -> ItemInfo {
        let field = |name: &str, kind: &str, value: &str| FieldInfo {
            name: name.into(),
            kind: kind.into(),
            value: value.into(),
        };
        ItemInfo {
            id: id.into(),
            short: id.into(),
            kind: "login".into(),
            label: id.into(),
            detail: Some("dax".into()),
            fields: vec![
                field("password", "secret", "hunter2"),
                field("username", "text", "dax"),
                field("otp", "otp", ""),
            ],
            source: None,
            favorite: false,
            tags: Vec::new(),
        }
    }

    #[test]
    fn a_page_keeps_no_secret() {
        let mut cache = Cache::default();
        cache.insert(&item("a"), None, 0.0);
        let page = cache.get("a").unwrap();
        let value = |name: &str| &page.fields.iter().find(|f| f.name == name).unwrap().value;
        assert_eq!(value("password"), "");
        assert_eq!(value("username"), "dax");
        assert_eq!(page.fields.len(), 3, "every field keeps its place");
    }

    #[test]
    fn it_keeps_the_newest_and_forgets_on_clear() {
        let mut cache = Cache::default();
        for i in 0..CAP + 5 {
            cache.insert(&item(&i.to_string()), None, 0.0);
        }
        assert_eq!(cache.len(), CAP);
        assert!(!cache.contains("0") && cache.contains(&(CAP + 4).to_string()));
        // Seeing one again makes it the newest.
        cache.insert(&item("5"), None, 0.0);
        cache.insert(&item("new"), None, 0.0);
        assert!(cache.contains("5") && !cache.contains("6"));
        let epoch = cache.epoch();
        cache.clear();
        assert!(cache.is_empty() && cache.epoch() != epoch);
    }

    #[test]
    fn a_code_lasts_its_period() {
        let mut cache = Cache::default();
        let code = Code {
            code: "123456".to_owned().into(),
            period: 30,
            valid_until: 1000,
            remaining_ms: 2_000,
        };
        cache.insert(&item("a"), Some(&code), 10.0);
        assert_eq!(cache.code("a", 11.5).unwrap().remaining_ms, 500);
        assert!(cache.code("a", 12.0).is_none());
    }
}
