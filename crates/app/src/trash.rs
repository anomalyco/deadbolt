//! Recently Deleted: a page in the item's place, as Settings is, while the
//! sidebar stays. The vault's deleted items, newest first, each saying when
//! it went; ↑↓ or J K move, ↵ or Space open one read-only, ⌘R or Restore
//! brings it back on every device, Esc steps back out. ⇧⌘⌫, ⌘K's Recently
//! deleted or the trash at the sidebar's foot open it. Nothing here purges:
//! a deleted item stays until it's restored.

use deadbolt_client::Paths;
use deadbolt_client::protocol::{Command, ItemInfo, Reply};
use rune::{Color, El, Key, KeyEvent, Transition, Tx, col, el, row, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Kit};

use crate::agent::{Done, Failure, Job, Values};
use crate::keys::{chord, plain, step};
use crate::model::{App, Screen, field_words, title_case};
use crate::view::theme::{FACT, PAGE_W, TITLE, kind_icon, kind_name};
use crate::view::{LIST_EDGE, hint, item_fields, masked_secret, scroll_col};

/// What a reload says: the item a restore brought back, if it asked for
/// one, and the deleted items left.
pub type Listing = (Option<ItemInfo>, Vec<ItemInfo>);

#[derive(Default)]
pub struct Trash {
    pub open: bool,
    pub loading: bool,
    /// The deleted items, newest first, without their values.
    pub items: Vec<ItemInfo>,
    /// The row the keys are on.
    pub row: usize,
    /// The item opened read-only, with its values; wiped when it goes.
    pub shown: Option<ItemInfo>,
    /// The item whose values are on their way.
    pub opening: Option<String>,
    /// The item a restore is on its way for.
    pub restoring: Option<String>,
    /// The last item restored, by name.
    pub restored: Option<String>,
    pub error: Option<String>,
    /// The list asked for: a reply to an earlier ask is dropped.
    seq: u64,
    /// The item asked for, likewise.
    item_seq: u64,
}

impl Trash {
    /// Closes the page, wipes what it showed, and drops replies on their way.
    pub(crate) fn forget(&mut self) {
        self.set_shown(None);
        let mut fresh = Trash::default();
        fresh.seq = self.seq + 1;
        fresh.item_seq = self.item_seq + 1;
        *self = fresh;
    }

    fn set_shown(&mut self, item: Option<ItemInfo>) {
        if let Some(mut old) = std::mem::replace(&mut self.shown, item) {
            crate::model::forget(&mut old);
        }
    }

    /// The list asked for, for tagging a reply in tests and scenes.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The item asked for, likewise.
    pub fn item_seq(&self) -> u64 {
        self.item_seq
    }

    /// The item the keys act on: the open one, else the row's.
    fn current(&self) -> Option<&ItemInfo> {
        match &self.shown {
            Some(item) => Some(item),
            None => self.items.get(self.row),
        }
    }

    /// The listed item `id` (without values), for its name and when it went.
    fn listed(&self, id: &str) -> Option<&ItemInfo> {
        self.items.iter().find(|i| i.id == id)
    }
}

impl Drop for Trash {
    fn drop(&mut self) {
        self.set_shown(None);
    }
}

impl App {
    /// ⇧⌘⌫: Recently Deleted in the item's place, on its newest item.
    pub fn open_trash(&mut self) {
        if self.screen != Screen::Vault || self.panel.is_some() {
            return;
        }
        if self.editing() || self.deleting() {
            return;
        }
        self.cancel_delete();
        self.import.hover = false;
        if self.settings_open {
            self.close_settings();
        }
        self.close_security();
        self.trash.forget();
        self.trash.open = true;
        self.nav = crate::keys::Nav::default();
        self.search.focused = false;
        self.load_trash(None);
    }

    /// Closes Recently Deleted, the keys back in the search.
    pub fn close_trash(&mut self) {
        self.trash.forget();
        self.search.focused = true;
    }

    pub fn toggle_trash(&mut self) {
        if self.trash.open {
            self.close_trash();
        } else {
            self.open_trash();
        }
    }

    fn load_trash(&mut self, restore: Option<String>) {
        self.trash.seq += 1;
        self.trash.loading = true;
        self.agent.send(Job::Trash {
            seq: self.trash.seq,
            restore,
        });
    }

    /// The vault's items changed (here or on another device): an open page
    /// asks again.
    pub(crate) fn on_trash_changed(&mut self) {
        if self.trash.open && self.trash.restoring.is_none() {
            self.load_trash(None);
        }
    }

    /// Opens the item `id` read-only.
    pub fn open_deleted(&mut self, id: &str) {
        if let Some(at) = self.trash.items.iter().position(|i| i.id == id) {
            self.trash.row = at;
        }
        self.trash.item_seq += 1;
        self.trash.opening = Some(id.to_owned());
        self.agent.send(Job::TrashItem {
            id: id.to_owned(),
            seq: self.trash.item_seq,
        });
    }

    /// Back from the open item to the list, on its row.
    pub fn close_deleted(&mut self) {
        self.trash.item_seq += 1;
        self.trash.opening = None;
        self.trash.set_shown(None);
    }

    /// Brings `id` back as it was deleted.
    pub fn restore(&mut self, id: &str) {
        if self.trash.restoring.is_some() {
            return;
        }
        self.trash.restoring = Some(id.to_owned());
        self.trash.error = None;
        self.load_trash(Some(id.to_owned()));
    }

    pub(crate) fn on_trash(&mut self, seq: u64, result: Result<Listing, Failure>, tx: &mut Tx) {
        if !self.trash.open || seq != self.trash.seq {
            return;
        }
        self.trash.loading = false;
        let restoring = self.trash.restoring.take();
        match result {
            Ok((restored, items)) => {
                // The page's first list lands at once; later ones (a restore,
                // another device) fade rows in place.
                if self.trash.items.is_empty() && restored.is_none() {
                    tx.instant();
                }
                let at = self.trash.current().map(|i| i.id.clone());
                self.trash.items = items;
                self.trash.error = None;
                if let Some(item) = restored {
                    self.trash.restored = Some(item.label);
                    // It's in the vault again; the list there catches up.
                    self.list();
                }
                // An open item that's no longer deleted (restored, here or
                // elsewhere) goes back to the list, on the row it was.
                let gone = |id: &str| !self.trash.items.iter().any(|i| i.id == id);
                let shown_gone = self.trash.shown.as_ref().is_some_and(|i| gone(&i.id));
                if shown_gone || self.trash.opening.as_deref().is_some_and(gone) {
                    self.close_deleted();
                }
                let last = self.trash.items.len().saturating_sub(1);
                self.trash.row =
                    match at.and_then(|id| self.trash.items.iter().position(|i| i.id == id)) {
                        Some(at) => at,
                        None => self.trash.row.min(last),
                    };
                if let Some(item) = self.trash.items.get(self.trash.row) {
                    tx.scroll_into_view(format!("trash-{}", item.id));
                }
            }
            Err(failure) if failure.locked() => {
                self.trash.forget();
                self.on_locked(tx);
            }
            Err(failure) => {
                let message = crate::onboarding::sentence(&failure.message);
                self.trash.error = Some(match restoring.and_then(|id| self.trash.listed(&id)) {
                    Some(item) => format!("Couldn't restore {}: {message}", item.label),
                    None => message,
                });
            }
        }
    }

    pub(crate) fn on_trash_item(&mut self, seq: u64, result: Result<Values, Failure>, tx: &mut Tx) {
        if !self.trash.open || seq != self.trash.item_seq {
            return;
        }
        self.trash.opening = None;
        match result {
            Ok(values) => {
                let (mut item, _) = values.take();
                item.deleted_at = self.trash.listed(&item.id).and_then(|i| i.deleted_at);
                self.trash.set_shown(Some(item));
            }
            Err(failure) if failure.locked() => {
                self.trash.forget();
                self.on_locked(tx);
            }
            Err(failure) => self.trash.error = Some(crate::onboarding::sentence(&failure.message)),
        }
    }

    /// The keys while Recently Deleted shows (`overlay_key`): they never
    /// reach the vault behind it.
    pub(crate) fn trash_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        let restore = chord(ev, 'r');
        if self.trash.shown.is_some() {
            match &ev.key {
                Key::Escape => self.close_deleted(),
                Key::Enter if plain(ev) => self.restore_current(),
                Key::Tab => return false,
                _ if restore => self.restore_current(),
                _ => {}
            }
            return true;
        }
        if let Some(by) = step(ev, true) {
            let last = self.trash.items.len().saturating_sub(1);
            self.trash.row = (self.trash.row as isize + by).clamp(0, last as isize) as usize;
            if let Some(item) = self.trash.items.get(self.trash.row) {
                tx.scroll_into_view(format!("trash-{}", item.id));
            }
            return true;
        }
        match &ev.key {
            Key::Escape => {
                tx.instant();
                self.close_trash();
            }
            Key::Enter if plain(ev) => self.open_current(),
            Key::Text(t) if t == " " && plain(ev) => self.open_current(),
            Key::Tab => return false,
            _ if restore => self.restore_current(),
            _ => {}
        }
        true
    }

    fn open_current(&mut self) {
        if let Some(id) = self.trash.items.get(self.trash.row).map(|i| i.id.clone()) {
            self.open_deleted(&id);
        }
    }

    fn restore_current(&mut self) {
        if let Some(id) = self.trash.current().map(|i| i.id.clone()) {
            self.restore(&id);
        }
    }
}

/// Restores `restore` if asked, then lists what's still deleted.
pub(crate) async fn run(paths: &Paths, seq: u64, restore: Option<String>) -> Done {
    let result: Result<Listing, Failure> = async {
        let restored = match restore {
            Some(id) => {
                let command = Command::ItemRestore {
                    vault: None,
                    query: vec![id],
                };
                let item = crate::agent::call(paths, command, |r| match r {
                    Reply::Item { item } => Some(item),
                    _ => None,
                })
                .await?;
                Some(item)
            }
            None => None,
        };
        let command = Command::ItemList {
            vault: None,
            query: Vec::new(),
            kind: None,
            deleted: true,
            tags: Vec::new(),
            favorites: false,
        };
        let items = crate::agent::call(paths, command, |r| match r {
            Reply::Items { items } => Some(items),
            _ => None,
        })
        .await?;
        Ok((restored, items))
    }
    .await;
    Done::Trash { seq, result }
}

/// A deleted item with its values.
pub(crate) async fn item(paths: &Paths, id: String, seq: u64) -> Done {
    let command = Command::ItemGet {
        vault: None,
        query: vec![id],
        otp: false,
        ssh_private: true,
        files: Vec::new(),
        deleted: true,
    };
    let result = crate::agent::call(paths, command, |r| match r {
        Reply::Item { item } => Some(Values::new(item)),
        _ => None,
    })
    .await;
    Done::TrashItem { seq, result }
}

/// "just now", "5 minutes ago", "yesterday", "3 days ago".
pub fn ago(at: u64, now: u64) -> String {
    let age = now.saturating_sub(at);
    let plural = |n: u64, unit: &str| {
        if n == 1 {
            format!("1 {unit} ago")
        } else {
            format!("{n} {unit}s ago")
        }
    };
    match age {
        0..60 => "just now".into(),
        60..3600 => plural(age / 60, "minute"),
        3600..86400 => plural(age / 3600, "hour"),
        86400..172800 => "yesterday".into(),
        _ => plural(age / 86400, "day"),
    }
}

/// "Login · Deleted 3 days ago".
fn about(item: &ItemInfo, now: u64) -> String {
    let kind = kind_name(&item.kind);
    match item.deleted_at {
        Some(at) => format!("{kind} · Deleted {}", ago(at, now)),
        None => format!("{kind} · Deleted"),
    }
}

/// The page, and the key hints along its foot.
pub fn page(s: &App, k: &Kit) -> El {
    let now = crate::activity::now();
    let body = match &s.trash.shown {
        Some(item) => shown(s, k, item, now),
        None => listing(s, k, now),
    };
    col()
        .key("trash")
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .child(
            scroll_col("trash-scroll")
                .w_full()
                .grow(1.0)
                .min_h(0.0)
                .scroll_margin(LIST_EDGE)
                .child(
                    col()
                        .key("trash-page")
                        .w_full()
                        .items_center()
                        .px(40.0)
                        .pt(4.0)
                        .pb(32.0)
                        .child(body),
                ),
        )
        .child(foot(s, k))
}

fn quiet(key: &str, words: String, ink: Color) -> El {
    text(words)
        .key(key.to_owned())
        .font(FACT.lh(16.0))
        .color(ink)
        .wrap()
        .w_full()
        .transition(Transition::opacity())
}

fn restore_button(s: &App, k: &Kit, id: &str, keys: bool) -> El {
    let busy = s.trash.restoring.as_deref() == Some(id);
    let mut button = Button::new(if busy { "Restoring…" } else { "Restore" })
        .variant(ButtonVariant::Neutral)
        .control_size(ControlSize::Regular)
        .disabled(s.trash.restoring.is_some())
        .help("Restore");
    if keys {
        button = button.shortcut("⌘R");
    }
    let id = id.to_owned();
    button
        .on_press(move |s: &mut App| s.restore(&id))
        .build(k)
        .key("restore")
}

/// The deleted items, newest first.
fn listing(s: &App, k: &Kit, now: u64) -> El {
    let t = &s.trash;
    let summary = if let Some(error) = &t.error {
        quiet("trash-error", error.clone(), k.c.danger.fg)
    } else if let Some(label) = &t.restored {
        quiet(
            "trash-restored",
            format!("Restored {label}. It's back in the vault on every device."),
            k.c.text_muted,
        )
    } else {
        quiet(
            "trash-about",
            "Deleted items stay here until you restore them.".into(),
            k.c.text_faint,
        )
    };
    let mut rows = col()
        .key("trash-rows")
        .role("listbox")
        .label("Deleted items")
        .w_full()
        .gap(2.0);
    if t.items.is_empty() && !t.loading {
        rows = rows.child(
            text("Nothing deleted")
                .key("trash-empty")
                .font(k.ty.text_small)
                .color(k.c.text_faint)
                .py(8.0)
                .transition(Transition::opacity()),
        );
    }
    for (at, item) in t.items.iter().enumerate() {
        rows = rows.child(deleted_row(s, k, item, at == t.row, now));
    }
    col()
        .key("trash-col")
        .w_full()
        .max_w(PAGE_W)
        .child(
            text("Recently Deleted")
                .key("title")
                .font(TITLE)
                .color(k.c.text_strong)
                .pb(6.0),
        )
        .child(col().key("trash-summary").w_full().pb(18.0).child(summary))
        .child(rows)
}

/// A deleted item: its kind's icon, its name over its kind and when it
/// went, and Restore. The row the keys are on fills; a restored row leaves
/// as the others close up over it.
fn deleted_row(s: &App, k: &Kit, item: &ItemInfo, on: bool, now: u64) -> El {
    let id = item.id.clone();
    row()
        .key(format!("trash-{}", item.id))
        .role("option")
        .label(format!("{}, {}", item.label, about(item, now)))
        .w_full()
        .min_h(56.0)
        .ml(-14.0)
        .mr(-14.0)
        .px(14.0)
        .py(10.0)
        .gap(12.0)
        .radius(10.0)
        .continuous_corners()
        .center_y()
        .fill(if on { k.c.layer_02 } else { Color::TRANSPARENT })
        .on_press(move |s: &mut App| s.open_deleted(&id))
        .child(
            rune::icon(kind_icon(&item.kind), 16.0)
                .key("icon")
                .color(if on { k.c.icon_base } else { k.c.icon_muted }),
        )
        .child(
            col()
                .key("words")
                .gap(2.0)
                .grow(1.0)
                .shrink()
                .min_w(0.0)
                .child(
                    text(item.label.clone())
                        .key("label")
                        .font(k.ty.ui_medium)
                        .color(k.c.text_strong)
                        .truncate_fade(),
                )
                .child(
                    text(about(item, now))
                        .key("about")
                        .font(FACT)
                        .color(k.c.text_faint)
                        .truncate(),
                ),
        )
        .child(restore_button(s, k, &item.id, false))
        .motion(rune::tok::motion::REFLOW)
        .transition(
            Transition::blur(3.0)
                .combined(Transition::scale(0.96))
                .springs(rune::SpringPair::new(
                    rune::tok::motion::SETTLE,
                    rune::tok::motion::SNAP,
                )),
        )
}

/// The open item, read-only: its head with Restore, then its fields, secrets
/// masked and nothing to copy.
fn shown(s: &App, k: &Kit, item: &ItemInfo, now: u64) -> El {
    let head = row()
        .key("head")
        .w_full()
        .gap(14.0)
        .center_y()
        .pb(12.0)
        .child(crate::vault::glyph_tile(k, &item.kind, 44.0, 11.0))
        .child(
            col()
                .key("titles")
                .gap(2.0)
                .grow(1.0)
                .shrink()
                .min_w(0.0)
                .child(
                    text(item.label.clone())
                        .key("title")
                        .font(TITLE)
                        .color(k.c.text_strong)
                        .truncate_fade(),
                )
                .child(
                    text(about(item, now))
                        .key("kind")
                        .font(k.ty.text_small)
                        .color(k.c.text_muted),
                ),
        )
        .child(restore_button(s, k, &item.id, true));
    let mut fields = col().key("fields").w_full().gap(2.0);
    for (at, (field, is_code)) in item_fields(item).enumerate() {
        let (label, value) = if is_code || field.kind == "otp" {
            ("One-time code".to_owned(), masked_secret())
        } else if crate::model::is_secret(&field.kind) {
            (title_case(&field.name), masked_secret())
        } else if field.kind == "file" {
            (
                title_case(&field.name),
                text(deadbolt_client::file::name(&field.value).to_owned()),
            )
        } else {
            (
                title_case(&field.name),
                text(field.value.trim_end_matches(['\r', '\n']).to_owned()).wrap_anywhere(),
            )
        };
        let el = col()
            .key(format!("field-{}", field.name))
            .label(format!("{}, read-only", field_words(&field.name)))
            .w_full()
            .min_h(56.0)
            .py(8.0)
            .gap(3.0)
            .child(
                text(label)
                    .key("name")
                    .font(k.ty.small_medium)
                    .color(k.c.text_faint),
            )
            .child(
                value
                    .key("value")
                    .min_w(0.0)
                    .w_full()
                    .font(k.ty.ui.lh(20.0))
                    .color(k.c.text_muted),
            );
        fields = fields.child(if field.name == "notes" && at > 0 {
            el.mt(16.0)
        } else {
            el
        });
    }
    col()
        .key(format!("trash-item-{}", item.id))
        .w_full()
        .max_w(PAGE_W)
        .children(
            s.trash
                .error
                .as_ref()
                .map(|e| quiet("trash-error", e.clone(), k.c.danger.fg).pb(12.0)),
        )
        .child(head)
        .child(
            el().key("rule")
                .w_full()
                .h(0.5)
                .mb(12.0)
                .fill(k.c.border_weak),
        )
        .child(fields)
}

/// What the keys do here, and where Esc goes.
fn foot(s: &App, k: &Kit) -> El {
    let h = |key: &str, keys: &[&str], label: &str| hint(k, key, keys, label);
    let hints = if s.trash.shown.is_some() {
        vec![
            h("h-restore", &["⏎"], "Restore"),
            h("h-back", &["esc"], "Back"),
        ]
    } else if s.trash.items.is_empty() {
        vec![h("h-close", &["esc"], "Close")]
    } else {
        vec![
            h("h-open", &["⏎"], "Open"),
            h("h-restore", &["⌘", "R"], "Restore"),
            h("h-close", &["esc"], "Close"),
        ]
    };
    row()
        .key("hints")
        .w_full()
        .h(36.0)
        .px(20.0)
        .gap(16.0)
        .center_y()
        .children(hints)
}

#[cfg(test)]
mod tests {
    use super::ago;

    #[test]
    fn ago_says_how_long_in_words() {
        let now = 1_000_000;
        assert_eq!(ago(now - 5, now), "just now");
        assert_eq!(ago(now - 60, now), "1 minute ago");
        assert_eq!(ago(now - 600, now), "10 minutes ago");
        assert_eq!(ago(now - 7_200, now), "2 hours ago");
        assert_eq!(ago(now - 90_000, now), "yesterday");
        assert_eq!(ago(now - 3 * 86_400, now), "3 days ago");
        assert_eq!(
            ago(now + 30, now),
            "just now",
            "a clock behind isn't negative"
        );
    }
}
