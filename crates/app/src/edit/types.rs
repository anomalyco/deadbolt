//! The New Item form's type picker: one row with the type's icon, name
//! and a chevron, which opens a small floating list of every type with a
//! filter field on top. ⌘N opens the form with the list already open and
//! the filter focused, so "api⏎" lands in an API credential's form with its
//! name focused. Typing narrows the list by name and by synonyms ("key"
//! finds API credential and SSH key, "pdf" a document); ↑↓ move, ⏎ picks,
//! esc closes. ⌘T, Space or ⏎ on the row open it again.

use rune::{KeyEvent, Tx};

use super::KINDS;
use crate::model::App;

/// The picker's state: whether the list shows, its filter, and which of
/// the matching types the keys are on.
pub struct Types {
    pub open: bool,
    pub filter: rune::TextEdit,
    pub active: usize,
}

impl Default for Types {
    fn default() -> Types {
        Types {
            open: false,
            filter: rune::TextEdit::new(""),
            active: 0,
        }
    }
}

/// Words besides a type's name that find it.
fn synonyms(kind: &str) -> &'static [&'static str] {
    match kind {
        "login" => &["password", "website", "account", "sign in"],
        "note" => &["text", "secret"],
        "card" => &["credit", "debit", "payment"],
        "identity" => &["person", "address", "contact", "name"],
        "api" => &["key", "token", "bearer", "aws", "secret"],
        "ssh" => &["key"],
        "database" => &["db", "sql", "postgres", "mysql"],
        "server" => &["host", "machine", "vps"],
        "wifi" => &["wifi", "wireless", "router", "network", "ssid"],
        "document" => &["file", "pdf", "attachment", "scan"],
        "bank" => &["iban", "account", "routing", "swift"],
        "crypto" => &["wallet", "bitcoin", "ethereum", "seed", "recovery"],
        "license" => &["software", "serial", "product"],
        "passport" => &["travel"],
        "driver-license" => &["driving", "licence", "driver"],
        "id-document" => &["ssn", "social security", "national id"],
        "membership" => &["loyalty", "club", "gym"],
        _ => &[],
    }
}

/// Lower case without `-`, so "wifi" finds "Wi-Fi network".
fn plain(text: &str) -> String {
    text.to_lowercase().replace('-', "")
}

/// The types `query` finds, best first: the name starting with it, then a
/// word of the name, then a synonym, then the name holding it anywhere;
/// ties keep the picker's order. An empty query finds every type.
pub fn matches(query: &str) -> Vec<&'static str> {
    let query = plain(query.trim());
    if query.is_empty() {
        return KINDS.to_vec();
    }
    let mut found: Vec<(usize, &'static str)> = KINDS
        .iter()
        .filter_map(|kind| {
            let name = plain(crate::view::theme::kind_name(kind));
            let rank = if name.starts_with(&query) {
                0
            } else if name.split([' ', '\'']).any(|w| w.starts_with(&query)) {
                1
            } else if synonyms(kind).iter().any(|s| plain(s).starts_with(&query)) {
                2
            } else if name.contains(&query) {
                3
            } else {
                return None;
            };
            Some((rank, *kind))
        })
        .collect();
    found.sort_by_key(|(rank, _)| *rank);
    found.into_iter().map(|(_, kind)| kind).collect()
}

impl App {
    /// Whether the type list shows.
    pub fn types_open(&self) -> bool {
        self.edit.types.open
    }

    /// Opens the type list over a new item's form, the filter focused and
    /// empty, the keys on the current type.
    pub fn open_types(&mut self) {
        let Some(form) = self.edit.form.as_mut().filter(|f| f.is_new() && !f.saving) else {
            return;
        };
        form.name.focused = false;
        form.tag_input.focused = false;
        for input in &mut form.fields {
            input.edit.focused = false;
        }
        self.search.focused = false;
        let types = &mut self.edit.types;
        types.open = true;
        types.filter.clear();
        types.filter.focused = true;
        types.active = KINDS.iter().position(|k| *k == form.kind).unwrap_or(0);
    }

    /// Closes the type list; Rune gives focus back to the type row.
    pub fn close_types(&mut self) {
        let types = &mut self.edit.types;
        types.open = false;
        types.filter.focused = false;
        types.filter.clear();
    }

    /// ⌘T, or the row's press: opens the list, or closes it.
    pub fn toggle_types(&mut self) {
        if self.types_open() {
            self.close_types();
        } else {
            self.open_types();
        }
    }

    /// A type picked from the list: the form becomes that type (keeping
    /// the name and the fields both have) with its name focused.
    pub fn choose_type(&mut self, kind: &str) {
        self.close_types();
        self.pick_kind(kind);
        if let Some(form) = self.edit.form.as_mut() {
            form.tag_input.focused = false;
            for input in &mut form.fields {
                input.edit.focused = false;
            }
            form.name.focused = true;
        }
    }

    /// The filter changed: the keys go to the best match.
    pub fn types_filtered(&mut self) {
        self.edit.types.active = 0;
    }

    /// The pointer over a row of the list.
    pub fn hover_type(&mut self, at: usize) {
        self.edit.types.active = at;
    }

    /// Keys in the filter (and at the window while the list shows): ↑↓
    /// move, ⏎ picks, esc closes. True when handled.
    pub fn types_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        use rune::Key;
        if !self.types_open() || ev.mods.cmd || ev.mods.alt {
            return false;
        }
        let found = matches(&self.edit.types.filter.text);
        let types = &mut self.edit.types;
        match ev.key {
            Key::Escape => self.close_types(),
            Key::Enter => {
                if let Some(kind) = found.get(types.active.min(found.len().saturating_sub(1))) {
                    self.choose_type(kind);
                }
            }
            Key::Down | Key::Up if !found.is_empty() => {
                let by = if ev.key == Key::Down { 1 } else { -1 };
                types.active = (types.active.min(found.len() - 1) as isize + by)
                    .rem_euclid(found.len() as isize) as usize;
                tx.scroll_into_view(format!("type-{}", found[types.active]));
            }
            Key::Down | Key::Up => {}
            _ => return false,
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn typing_finds_types_by_name_and_synonym() {
        assert_eq!(matches("").len(), super::KINDS.len());
        assert_eq!(matches("api")[0], "api");
        assert_eq!(matches("key"), ["ssh", "api"]);
        for wifi in ["wifi", "wi-fi", "Wi-Fi", "wire"] {
            assert_eq!(matches(wifi)[0], "wifi", "{wifi}");
        }
        assert_eq!(matches("card")[0], "card");
        assert_eq!(matches("bank"), ["bank"]);
        assert_eq!(matches("iban"), ["bank"]);
        assert_eq!(matches("file"), ["document"]);
        assert_eq!(matches("pdf"), ["document"]);
        assert_eq!(matches("driver")[0], "driver-license");
        assert_eq!(matches("lic"), ["license", "driver-license"]);
        assert!(matches("zzz").is_empty());
    }
}
