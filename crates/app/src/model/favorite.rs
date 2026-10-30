//! Starring items (`⌘D`), keeping favorites first in the list, and `#tag`
//! search filtering from chips and `⌘K`.

use deadbolt_client::protocol::ItemInfo;
use rune::Tx;

use super::App;
use crate::agent::{Failure, Job};

/// Sorts items favorites-first, then case-insensitively by label, then id.
pub fn sort_items(items: &mut [ItemInfo]) {
    items.sort_by(|a, b| {
        (!a.favorite, a.label.to_lowercase(), &a.id).cmp(&(
            !b.favorite,
            b.label.to_lowercase(),
            &b.id,
        ))
    });
}

/// Formats `tag` as a search token (`#work/aws` or `#"Tax 2026"`).
pub fn tag_token(tag: &str) -> String {
    if tag.chars().any(char::is_whitespace) {
        format!("#\"{tag}\"")
    } else {
        format!("#{tag}")
    }
}

impl App {
    /// `⌘D` or the star button: in an open form, flips `form.favorite`; in the
    /// vault, optimistically stars or unstars the selected item, re-sorts the
    /// list keeping it selected, and sends `Job::Favorite`.
    pub fn toggle_favorite(&mut self, tx: &mut Tx) {
        if self.editing() {
            self.toggle_form_favorite();
            return;
        }
        if !self.edits() {
            return;
        }
        let Some(id) = self.selected.clone() else {
            return;
        };
        let Some(at) = self.items.iter().position(|i| i.id == id) else {
            return;
        };
        let favorite = !self.items[at].favorite;
        tx.instant();
        self.items[at].favorite = favorite;
        if let Some(detail) = self.detail.as_mut().filter(|d| d.id == id) {
            detail.favorite = favorite;
        }
        self.cache.set_favorite(&id, favorite);
        sort_items(&mut self.items);
        tx.scroll_into_view(format!("item-{id}"));
        self.fav_seq += 1;
        self.agent.send(Job::Favorite {
            id,
            favorite,
            seq: self.fav_seq,
        });
    }

    pub(super) fn on_favorited(
        &mut self,
        seq: u64,
        result: Result<ItemInfo, Failure>,
        tx: &mut Tx,
    ) {
        if !self.accepts_vault_replies() {
            return;
        }
        match result {
            Ok(item) => {
                if seq == self.fav_seq {
                    if let Some(listed) = self.items.iter_mut().find(|i| i.id == item.id) {
                        listed.favorite = item.favorite;
                        listed.tags.clone_from(&item.tags);
                    }
                    if let Some(detail) = self.detail.as_mut().filter(|d| d.id == item.id) {
                        detail.favorite = item.favorite;
                        detail.tags.clone_from(&item.tags);
                    }
                    self.cache.set_favorite(&item.id, item.favorite);
                    sort_items(&mut self.items);
                }
            }
            Err(failure) => {
                self.on_failure(failure, tx);
                self.refresh();
            }
        }
    }

    /// Filters the vault by `tag` (`#tag `), or clears it when already filtering
    /// by that exact tag alone.
    pub fn filter_by_tag(&mut self, tag: &str, tx: &mut Tx) {
        if self.editing() && !self.leave_edit() {
            return;
        }
        let token = tag_token(tag);
        tx.instant();
        self.close_settings();
        self.close_trash();
        self.close_security();
        self.nav.field = None;
        self.sidebar.set_open(true);
        if self.search.text.trim().eq_ignore_ascii_case(&token) {
            self.search.clear();
        } else {
            let next = format!("{token} ");
            let end = next.len();
            self.search.replace_text(next);
            self.search.set_selection(end, end);
        }
        self.search.focused = true;
        self.search_changed();
    }
}
