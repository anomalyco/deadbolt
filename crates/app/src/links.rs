//! Incoming item links. Keep navigation separate from connection and unlock:
//! the current list must land before an ID prefix can select a complete ID.

use rune::Tx;

use crate::model::{App, Screen};

/// A bare ID is distinct from secret references, which require at least
/// an item and field separated by `/`. Never discard a link's suffix.
fn item_id(url: &str) -> Option<&str> {
    let id = url.strip_prefix("deadbolt://")?;
    ((4..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
    .then_some(id)
}

impl App {
    /// Registered only for live runs. A newer link replaces one still
    /// waiting for connection, unlock or the first item list.
    pub(crate) fn open_item_url(&mut self, url: &str, tx: &mut Tx) {
        let Some(id) = item_id(url) else {
            return;
        };
        if let Some(windows) = &self.windows {
            windows.open_main();
        }
        self.pending_link = Some(id.to_owned());
        self.follow_item_link(tx);
    }

    pub(crate) fn follow_item_link(&mut self, tx: &mut Tx) {
        if self.screen != Screen::Vault || !self.loaded {
            return;
        }
        let Some(prefix) = self.pending_link.take() else {
            return;
        };
        // Resolve IDs only: the daemon's text query also matches titles.
        let mut matches = self.items.iter().filter(|i| i.id.starts_with(&prefix));
        let id = match (matches.next(), matches.next()) {
            (Some(item), None) => item.id.clone(),
            (None, _) => {
                self.notice = Some("That item is not in the default vault.".into());
                return;
            }
            (Some(_), Some(_)) => {
                self.notice = Some("That item ID is ambiguous. Use a longer ID.".into());
                return;
            }
        };
        if self.open_item(&id, tx) {
            self.sidebar.set_open(true);
        } else {
            self.notice =
                Some("Finish the current edit or import before opening that item.".into());
        }
    }
}
