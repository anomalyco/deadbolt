//! Filtering, selection, cached pages and read-ahead (`Job::Peek`).

use std::time::Duration;

use deadbolt_client::protocol::{AppAction, Code, ItemInfo, code_field, noun, primary_field};
use rune::Tx;

use crate::agent::{Failure, Job, Values};

use super::otp::Otp;
use super::{App, copy_label, forget, is_secret};

/// How long the page before stays, whole, when a new selection has nothing
/// to show yet, before the page gives way to its title alone.
pub const HOLD: f64 = 0.15;
/// The rows read ahead of the selection (`Job::Peek`) the way it's moving,
/// and behind it.
const AHEAD: isize = 4;
const BEHIND: isize = 2;

impl App {
    /// Dropping a stale item wipes its values (`agent::Values`); its page is
    /// kept for going back to it, unless the vault changed since.
    pub(super) fn on_item(&mut self, seq: u64, result: Result<Values, Failure>, tx: &mut Tx) {
        if !self.accepts_vault_replies() {
            return;
        }
        if seq != self.seq {
            if seq > self.cleared_seq
                && let Ok(values) = result
            {
                self.keep_page(values);
            }
            return;
        }
        match result {
            Ok(values) => {
                let (item, code) = values.take();
                if seq > self.cleared_seq {
                    self.cache_page(&item, code.as_ref());
                }
                self.held = None;
                let was_unloaded = self.detail.is_none();
                // A new selection's fields land in place, not animated: the
                // selection moved under the user's own hand. A refresh of the
                // shown item animates what changed, and so does a saved form
                // giving way to what it saved.
                let saved = self.editing();
                if !saved && self.detail.as_ref().is_none_or(|d| d.id != item.id) {
                    tx.instant();
                }
                self.edit_item_landed(&item);
                self.set_detail(Some(item));
                // A Show pressed on the cached page before its values landed
                // reveals the secret only now.
                if was_unloaded
                    && !self.revealed.is_empty()
                    && let Some(shown) = &self.detail
                {
                    for field in &self.revealed {
                        if shown
                            .fields
                            .iter()
                            .any(|f| &f.name == field && is_secret(&f.kind) && f.kind != "otp")
                        {
                            self.report_item(AppAction::Reveal, &shown.id, &shown.label, field);
                        }
                    }
                }
                let pending_field = self
                    .pending_copy
                    .take()
                    .filter(|(pending, _)| *pending == seq)
                    .map(|(_, field)| field);
                let copy_code = code.is_some()
                    && pending_field.as_deref().is_some_and(|field| {
                        self.otp
                            .as_ref()
                            .is_some_and(|o| field == "otp" || field == o.field)
                    });
                if copy_code && let Some(otp) = &mut self.otp {
                    otp.copy_next = true;
                }
                if let Some(code) = code {
                    self.on_code(code, tx);
                }
                if let Some(field) = pending_field.filter(|_| !copy_code) {
                    self.copy_field(&field, tx);
                }
            }
            Err(failure) => {
                self.edit_item_failed();
                self.on_failure(failure, tx);
            }
        }
    }

    pub(super) fn on_peeked(
        &mut self,
        id: String,
        epoch: u64,
        result: Result<Values, Failure>,
        tx: &mut Tx,
    ) {
        if epoch != self.cache.epoch() || !self.accepts_vault_replies() {
            return;
        }
        let values = match result {
            Ok(values) => values,
            Err(failure) if failure.locked() => return self.on_locked(tx),
            Err(_) => return,
        };
        self.keep_page(values);
        // The selection was waiting on it: its page shows at once.
        if self.selected.as_deref() == Some(id.as_str()) && self.detail.is_none() {
            tx.instant();
            self.show_cached(&id);
        }
    }

    /// The items matching the search: every word must appear in the label,
    /// the detail (username, expiry, SSH key comment, identity email), the
    /// type ("ssh", "SSH key") or the short id.
    pub fn visible(&self) -> Vec<&ItemInfo> {
        self.visible_at()
            .into_iter()
            .map(|at| &self.items[at])
            .collect()
    }

    /// [`App::visible`] as positions in `items`.
    pub fn visible_at(&self) -> Vec<usize> {
        let words: Vec<String> = self
            .search
            .text
            .split_whitespace()
            .map(str::to_lowercase)
            .collect();
        self.items
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                let hay = [
                    Some(item.label.as_str()),
                    item.detail.as_deref(),
                    Some(item.kind.as_str()),
                    Some(noun(&item.kind, 1)),
                    Some(item.short.as_str()),
                ];
                words
                    .iter()
                    .all(|w| hay.iter().flatten().any(|h| contains_folded(h, w)))
            })
            .map(|(at, _)| at)
            .collect()
    }

    pub fn selected_item(&self) -> Option<&ItemInfo> {
        let id = self.selected.as_deref()?;
        self.items.iter().find(|i| i.id == id)
    }

    /// After the list or the search changed: keep the selection if it still
    /// matches, else select the first match.
    pub fn keep_selection_visible(&mut self) {
        // An open form keeps its item selected, even when the search hides it.
        if self.editing() {
            return;
        }
        let visible = self.visible();
        let keep = self
            .selected
            .as_deref()
            .is_some_and(|id| visible.iter().any(|i| i.id == id));
        if !keep {
            let first = visible.first().map(|i| i.id.clone());
            self.select(first);
        }
    }

    /// Selects `id`. Its page shows at once if the cache has it, else the
    /// page before stays a moment (`HOLD`); its values are asked for.
    pub fn select(&mut self, id: Option<String>) {
        if id == self.selected {
            return;
        }
        let shown = self
            .page_view()
            .and_then(|(head, full)| full.map(|_| head.id.clone()));
        self.selected = id.clone();
        self.nav.field = None;
        self.notice = None;
        self.edit.delete = None;
        self.set_detail(None);
        self.pending_copy = None;
        self.seq += 1;
        let Some(id) = id else {
            self.held = None;
            return;
        };
        let cached = self.cache.contains(&id);
        if cached {
            self.show_cached(&id);
        } else if !self.holding() {
            // A page already held stays for the rest of its moment.
            self.held = shown.filter(|s| self.cache.contains(s)).map(|s| (s, None));
        }
        self.agent.send(Job::Get {
            id,
            seq: self.seq,
            cached,
        });
    }

    /// The user selects `id`: the rows around it are read ahead too, mostly
    /// `heading` (the way an arrow moved it: -1 or 1; 0 for a click or ⌘1–9).
    pub(crate) fn select_by_hand(&mut self, id: String, heading: isize) {
        self.select(Some(id));
        self.prefetch(heading);
    }

    /// The selection's page is in the cache: its code shows with it, until
    /// its own values come.
    pub(super) fn show_cached(&mut self, id: &str) {
        self.held = None;
        let Some(page) = self.cache.get(id) else {
            return;
        };
        let Some(at) = code_field(&page.fields) else {
            return;
        };
        let mut otp = Otp::new(id.to_owned(), page.fields[at].name.clone());
        if let Some(code) = self.cache.code(id, self.clock) {
            otp.land(&code, self.clock);
        }
        self.otp = Some(otp);
    }

    /// Reads ahead the rows around the selection the cache doesn't have,
    /// nearest first and mostly the way it's moving, replacing the batch
    /// before. Only in the main window, on a move of the user's
    /// (`select_by_hand`): a read counts as use for the agent's idle lock.
    fn prefetch(&mut self, d: isize) {
        if self.panel.is_some() || !self.agent.is_live() {
            return;
        }
        let visible = self.visible();
        let Some(at) = self
            .selected
            .as_deref()
            .and_then(|id| visible.iter().position(|i| i.id == id))
        else {
            return;
        };
        let order: Vec<isize> = if d == 0 {
            (1..AHEAD).flat_map(|n| [n, -n]).collect()
        } else {
            (1..=AHEAD)
                .map(|n| n * d)
                .chain((1..=BEHIND).map(|n| -n * d))
                .collect()
        };
        let ids: Vec<String> = order
            .into_iter()
            .filter_map(|by| visible.get(at.checked_add_signed(by)?))
            .filter(|i| !self.cache.contains(&i.id))
            .map(|i| i.id.clone())
            .collect();
        if ids.is_empty() {
            return;
        }
        self.peeks += 1;
        for id in ids {
            self.agent.send(Job::Peek {
                id,
                epoch: self.cache.epoch(),
                batch: self.peeks,
            });
        }
    }

    /// The selection's values are wanted now (a copy or Show on its cached
    /// page): ask for them ahead of the reads ahead.
    pub(super) fn hurry(&mut self) {
        if self.detail.is_none()
            && let Some(id) = self.selected.clone()
            && self.cache.contains(&id)
        {
            self.agent.send(Job::Get {
                id,
                seq: self.seq,
                cached: false,
            });
        }
    }

    fn cache_page(&mut self, item: &ItemInfo, code: Option<&Result<Code, Failure>>) {
        if self.items.iter().any(|i| i.id == item.id) {
            let landed = code.and_then(|c| c.as_ref().ok());
            self.cache.insert(item, landed, self.clock);
        }
    }

    /// Keeps an item's page from its values, then wipes them.
    pub(super) fn keep_page(&mut self, values: Values) {
        let (mut item, code) = values.take();
        self.cache_page(&item, code.as_ref());
        forget(&mut item);
    }

    /// Forgets every kept page: the vault changed, or was closed.
    pub(crate) fn forget_pages(&mut self) {
        self.cache.clear();
        self.cleared_seq = self.seq;
        self.held = None;
    }

    /// The fields the selection's page draws: its values once they're here,
    /// else the cache's page.
    pub fn page(&self) -> Option<&ItemInfo> {
        let id = self.selected.as_deref()?;
        match &self.detail {
            Some(d) if d.id == id => Some(d),
            _ => self.cache.get(id),
        }
    }

    /// What the page draws: the selection's row and its fields, or, for a
    /// moment after a selection with nothing to show yet, the page before
    /// it, whole.
    pub fn page_view(&self) -> Option<(&ItemInfo, Option<&ItemInfo>)> {
        let item = self.selected_item()?;
        if let Some(full) = self.page() {
            return Some((item, Some(full)));
        }
        if self.holding()
            && let Some(page) = self.held.as_ref().and_then(|(id, _)| self.cache.get(id))
        {
            return Some((page, Some(page)));
        }
        Some((item, None))
    }

    fn holding(&self) -> bool {
        self.held
            .as_ref()
            .is_some_and(|(_, since)| since.is_none_or(|s| self.clock < s + HOLD))
    }

    /// Lets a held page go once its moment is up, at once like any change
    /// of selection. `since` is stamped from the first frame's clock after
    /// the event, so an idle stretch before a click never eats into `HOLD`.
    pub(super) fn tick_held(&mut self, now: f64, tx: &mut Tx) -> bool {
        let Some((_, since)) = &mut self.held else {
            return false;
        };
        let since = *since.get_or_insert(now);
        if now < since + HOLD - 1e-9 {
            tx.wake_after(Duration::from_secs_f64(since + HOLD - now));
            return false;
        }
        tx.instant();
        self.held = None;
        true
    }

    pub(crate) fn step(&mut self, by: isize) {
        let visible = self.visible();
        if visible.is_empty() {
            return;
        }
        let at = self
            .selected
            .as_deref()
            .and_then(|id| visible.iter().position(|i| i.id == id));
        let next = match at {
            Some(i) => (i as isize + by).clamp(0, visible.len() as isize - 1) as usize,
            None => 0,
        };
        let id = visible[next].id.clone();
        self.select_by_hand(id, by.signum());
    }

    /// The search changed: the list it filters shows (a hidden sidebar opens,
    /// the import view closes), and the selection follows it. An import
    /// that's running, or a preview in an empty vault, stays, and so does
    /// the item it hides until it's gone (`on_imported`, `cancel_import`).
    pub fn search_changed(&mut self) {
        if self.panel_inert() {
            return;
        }
        self.sidebar.set_open(true);
        if self.import.showing() && !self.items.is_empty() {
            self.cancel_import();
        }
        if !self.import.showing() {
            self.keep_selection_visible();
        }
    }

    /// The quick panel's clear button: an empty search, still focused.
    pub fn clear_search(&mut self) {
        self.search.clear();
        self.search.focused = true;
        self.search_changed();
    }

    /// Focuses the search field with its text selected, so typing replaces it.
    pub fn focus_search(&mut self) {
        self.search.focused = true;
        self.search.set_selection(0, self.search.text.len());
    }

    /// What ⏎ copies, as a key hint: none once the item's page or values are
    /// in and it has no such field.
    pub fn enter_hint(&self) -> Option<&'static str> {
        let item = self.selected_item()?;
        let field = self.primary_field();
        let lacks = self
            .page()
            .is_some_and(|p| !p.fields.iter().any(|f| f.name == field));
        (!lacks).then(|| copy_label(&item.kind))
    }

    /// Whether ⇧⏎ has a username to copy: a login's row carries it.
    pub fn has_username(&self) -> bool {
        self.selected_item()
            .is_some_and(|i| i.kind == "login" && i.detail.is_some())
    }

    /// What ⏎ copies: the field the item is for (`protocol::primary_field`).
    pub(crate) fn primary_field(&self) -> &'static str {
        self.selected_item()
            .and_then(|i| primary_field(&i.kind))
            .unwrap_or("password")
    }
}

fn contains_folded(haystack: &str, lower_needle: &str) -> bool {
    if lower_needle.is_empty() {
        return true;
    }
    if haystack.is_ascii() && lower_needle.is_ascii() {
        let n = lower_needle.as_bytes();
        haystack
            .as_bytes()
            .windows(n.len())
            .any(|w| w.eq_ignore_ascii_case(n))
    } else {
        haystack.to_lowercase().contains(lower_needle)
    }
}
