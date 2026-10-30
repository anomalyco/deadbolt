//! The open vault, Seer's shape: the list is the sidebar, with the search
//! under the traffic lights, two-line rows led by the item's kind and a foot
//! of who's here, Settings and Lock. The item is a page in the inset card
//! (`page`); ⌘, swaps it for Settings while the sidebar stays.
//!
//! Motion: none for a selection. A search replaces the list at once, and any
//! new selection (search, arrows, a click) moves the highlight to its row
//! and replaces the item's page on the same frame, so holding an arrow keeps
//! up with the key repeat.

pub mod page;

use std::borrow::Cow;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

use deadbolt_client::protocol::{ItemInfo, noun};
use rune::{El, GrowthSpec, Transition, col, el, icon, row, text};
use rune_kit::shell::{SplitView, Toolbar};
use rune_kit::{IconButton, IconButtonVariant, Keybind, Kit, TextInput};

use crate::model::App;
use crate::view::theme::{SLIDERS, kind_icon};
use crate::view::{LIST_EDGE, device_name, instant, scroll_col, tnum, vault_name};

pub(crate) use crate::view::theme::{FACT, glyph_tile, kind_name};

/// A list row: the item's label over its detail.
const ROW_H: f32 = 46.0;
const ROW_GAP: f32 = 2.0;
const ROWS_PAD: f32 = 6.0;

/// What a row says under its label: the item's detail, else its kind.
pub(crate) fn fact(item: &ItemInfo) -> String {
    item.detail
        .clone()
        .unwrap_or_else(|| kind_name(&item.kind).to_owned())
}

/// The vault: the sidebar and the page, with ⌘K's actions and the ? sheet
/// over it in `layer`.
pub fn view(s: &App, k: &Kit, inset: f32, reduced_motion: bool, layer: &mut Vec<El>) -> El {
    let main = if s.settings_open {
        crate::settings::page(s, k)
    } else {
        page::pane(s, k, layer)
    }
    .transition(instant());
    let mut toolbar = Toolbar::new();
    if !s.settings_open {
        toolbar = toolbar.trailing(page::toolbar(s, k).transition(instant()));
    }
    layer.extend(crate::palette::view(s, k).map(|card| over("palette-over", card, 72.0)));
    layer.extend(crate::sheet::view(s, k).map(|card| over("sheet-over", card, 96.0)));
    SplitView::new(main)
        .sidebar(&s.sidebar, |s: &mut App| &mut s.sidebar, sidebar(s, k))
        .toolbar(toolbar)
        .toolbar_in_panel()
        .hide_sidebar_toggle()
        .titlebar_inset(inset)
        .reduced_motion(reduced_motion)
        .build(k)
}

/// A card over the whole window, `top` from its top; appears and leaves at
/// once, and a press beside it closes it, as Esc does.
fn over(key: &str, card: El, top: f32) -> El {
    col()
        .key(key)
        .pin(Some(0.0), Some(0.0), Some(0.0), Some(0.0))
        .items_center()
        .pt(top)
        .transition(instant())
        .on_press_tx(|s: &mut App, tx| {
            tx.instant();
            s.close_palette();
            s.nav.sheet = false;
        })
        .child(card.on_press(|_: &mut App| {}))
}

fn sidebar(s: &App, k: &Kit) -> El {
    let visible = s.visible_at();
    col()
        .key("side")
        .w_full()
        .h_full()
        .child(
            col()
                .key("side-top")
                .w_full()
                .px(10.0)
                .pt(4.0)
                .pb(10.0)
                .child(search(s, k)),
        )
        .child(
            row()
                .key("vault-head")
                .w_full()
                .px(16.0)
                .pb(4.0)
                .center_y()
                .child(
                    text(vault_name(s, "Personal").to_owned())
                        .font(k.ty.small_medium)
                        .color(k.c.text_muted)
                        .grow(1.0)
                        .truncate(),
                )
                .children(s.loaded.then(|| {
                    text(visible.len().to_string())
                        .key("count")
                        .font(tnum(k.ty.small))
                        .color(k.c.text_faint)
                })),
        )
        .child(item_list(s, k, &visible).w_full().grow(1.0).min_h(0.0))
        .child(foot(s, k))
}

/// Scrollable virtualized item list shared by the vault sidebar and the quick panel.
pub(crate) fn item_list(s: &App, k: &Kit, visible: &[usize]) -> El {
    scroll_col("list")
        .scroll_margin(LIST_EDGE)
        .child(rows_of(s, k, visible))
}

/// The search, quiet until typed in: no ring, ⌘F at its end. It keeps the
/// keys (`search_key`): typing filters the list live, and ↑↓, ⏎ and Esc act
/// on it.
fn search(s: &App, k: &Kit) -> El {
    let mut input = TextInput::new(&s.search)
        .placeholder("Search")
        .width(None)
        .height(30.0)
        .plain()
        .leading_icon(k.glyph.search)
        .leading_icon_size(14.0)
        .on_edit(|s: &mut App| &mut s.search)
        .on_key(|s: &mut App, ev, tx| s.search_key(ev, tx))
        .on_change(|s: &mut App, _| s.search_changed());
    if s.search.text.is_empty() && !s.search.focused {
        input = input.trailing(Keybind::new(&["⌘", "F"]).build(k));
    }
    el().key("search-box")
        .w_full()
        .radius(8.0)
        .continuous_corners()
        .fill(if k.dark { k.c.layer_01 } else { k.c.layer_02 })
        .child(input.build(k).key("search").label("Search items"))
}

/// The visible items (positions in `s.items`) as virtual rows, or why there
/// are none. Only the rows in the scroll window are built.
fn rows_of(s: &App, k: &Kit, visible: &[usize]) -> El {
    let rows = col()
        .key("rows")
        .role("listbox")
        .label("Items")
        .w_full()
        .gap(ROW_GAP)
        .px(ROWS_PAD)
        .py(ROWS_PAD)
        .growth(GrowthSpec {
            spring: rune::tok::motion::REFLOW,
            edge: rune::edge::NO_MASK,
        });
    if !s.loaded {
        return rows.virtualize(ROW_H);
    }
    if s.items.is_empty() {
        return rows.virtualize(ROW_H).child(empty(
            k,
            "empty",
            "No items yet",
            "What you add shows up here and on your other devices.",
        ));
    }
    if visible.is_empty() {
        return rows.virtualize(ROW_H).child(empty(
            k,
            "no-match",
            "No matches",
            &format!("Nothing matches “{}”.", s.search.text.trim()),
        ));
    }
    // The keys change only when the visible ids do (a search, a sync, a sort).
    let version = Ids(visible.iter().map(|&at| s.items[at].id.as_str()));
    let keys: Rc<[usize]> = visible.into();
    let items = keys.clone();
    let k = Rc::new(k.clone());
    rows.virtual_rows(
        keys.len(),
        ROW_H,
        move |s: &App, i| {
            let id = keys
                .get(i)
                .and_then(|&at| s.items.get(at))
                .map(|item| &item.id);
            id.map_or(Cow::Borrowed(""), |id| format!("item-{id}").into())
        },
        move |s: &App, i| {
            let Some(item) = items.get(i).and_then(|&at| s.items.get(at)) else {
                return el();
            };
            let on = !s.settings_open && s.selected.as_deref() == Some(item.id.as_str());
            let jump = if i < 9 && on { i + 1 } else { 0 };
            rune::memo(
                format!("item-{}", item.id),
                (&item.label, &item.detail, &item.kind, on, jump),
                || list_row(&k, item, i, on),
            )
        },
    )
    .virtual_rows_version(version)
}

/// Hashes the visible ids in order, for `virtual_rows_version`.
struct Ids<'a, I: Iterator<Item = &'a str> + Clone>(I);

impl<'a, I: Iterator<Item = &'a str> + Clone> Hash for Ids<'a, I> {
    fn hash<H: Hasher>(&self, h: &mut H) {
        for id in self.0.clone() {
            id.hash(h);
        }
    }
}

fn empty(k: &Kit, key: &str, title: &str, body: &str) -> El {
    col()
        .key(key)
        .w_full()
        .px(10.0)
        .py(24.0)
        .gap(4.0)
        .arrives_whole()
        .transition(Transition::opacity())
        .child(text(title).font(k.ty.ui_medium).color(k.c.text_base))
        .child(
            text(body)
                .font(k.ty.text_small)
                .color(k.c.text_muted)
                .wrap()
                .w_full(),
        )
}

/// Row `i`: the kind's glyph, the label over the detail, and ⌘1–⌘9 on the
/// selected one of the first nine. Rows take no focus: the keys stay with
/// the search, and a press selects while the search keeps focus.
fn list_row(k: &Kit, item: &ItemInfo, i: usize, on: bool) -> El {
    let id = item.id.clone();
    let lines = col()
        .key("lines")
        .gap(1.0)
        .grow(1.0)
        .shrink()
        .min_w(0.0)
        .child(
            text(item.label.clone())
                .key("label")
                .font(k.ty.ui)
                .color(if on { k.c.text_strong } else { k.c.text_base })
                .truncate(),
        )
        .child(
            text(fact(item))
                .key("subtitle")
                .font(FACT)
                .color(k.c.text_faint)
                .truncate(),
        );
    row()
        .key(format!("item-{}", item.id))
        .label(match &item.detail {
            Some(d) => format!("{}, {d} · {}", item.label, noun(&item.kind, 1)),
            None => format!("{}, {}", item.label, noun(&item.kind, 1)),
        })
        .w_full()
        .h(ROW_H)
        .px(10.0)
        .gap(10.0)
        .center_y()
        .focusable(false)
        .focus_selected(on)
        .preserve_focus_on_press(true)
        .arrives_whole()
        .children(on.then(|| {
            el().key("highlight")
                .pin(Some(0.0), Some(0.0), Some(0.0), Some(0.0))
                .radius(8.0)
                .continuous_corners()
                .fill(k.c.pressed)
                .transition(instant())
        }))
        .child(icon(kind_icon(&item.kind), 16.0).key("icon").color(if on {
            k.c.icon_base
        } else {
            k.c.icon_muted
        }))
        .child(lines)
        .children((i < 9 && on).then(|| {
            text(format!("⌘{}", i + 1))
                .key("jump")
                .font(k.ty.small)
                .color(k.c.text_faint)
        }))
        .on_press_tx(move |s: &mut App, tx| s.press_row(&id, tx))
        .role("option")
        // A search replaces the list at once (an edit is instant: no
        // `animate_edit_layout`). Rows an agent change adds or removes fade
        // in place while the rest slide to their new places.
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

impl App {
    /// A row pressed: the item replaces at once, unless the import view
    /// swaps back to it or a form gives way with its exit.
    fn press_row(&mut self, id: &str, tx: &mut rune::Tx) {
        if self.panel_inert() {
            return;
        }
        // The item being edited stays as it is, focus and all.
        if self.edit.form.as_ref().and_then(|f| f.id.as_deref()) == Some(id) {
            return;
        }
        let was_editing = self.editing();
        if !self.leave_edit() {
            return;
        }
        if self.settings_open {
            self.close_settings();
        }
        // Focus somewhere else (nothing, Lock) comes back to the search.
        self.search.focused = true;
        if !self.import.showing() && !was_editing {
            tx.instant();
        }
        self.cancel_import();
        self.select_by_hand(id.to_owned(), 0);
    }
}

/// Where the vault lives and who's here, then Settings and Lock.
fn foot(s: &App, k: &Kit) -> El {
    let peers = s.status.as_ref().map_or(0, |st| st.peers_online);
    let device = device_name(s).unwrap_or("This device");
    let about = match peers {
        0 => device.to_owned(),
        n => format!("{device} · {n} online"),
    };
    let settings = IconButton::new(&SLIDERS)
        .variant(IconButtonVariant::GhostMuted)
        .label("Settings")
        .help("Settings")
        .shortcut("⌘,")
        .on_press_tx(|s: &mut App, tx| {
            tx.instant();
            if s.settings_open {
                s.close_settings();
                s.search.focused = true;
            } else {
                s.open_settings();
            }
        })
        .build(k)
        .key("settings-trigger");
    let settings = if s.settings_open {
        row()
            .key("settings-on")
            .radius(6.0)
            .fill(k.c.pressed)
            .child(settings)
    } else {
        settings
    };
    row()
        .key("foot")
        .w_full()
        .h(44.0)
        .pl(16.0)
        .pr(8.0)
        .gap(2.0)
        .center_y()
        .child(
            row()
                .key("presence")
                .gap(7.0)
                .center_y()
                .grow(1.0)
                .shrink()
                .min_w(0.0)
                .child(el().size(6.0, 6.0).radius(3.0).fill(if peers > 0 {
                    k.c.success.icon
                } else {
                    k.c.icon_faint
                }))
                .child(
                    text(about)
                        .key("presence-label")
                        .font(k.ty.small)
                        .color(k.c.text_muted)
                        .truncate(),
                ),
        )
        .children(crate::panel::window::entry(s, k))
        .child(settings)
        .child(
            IconButton::new(k.glyph.lock)
                .variant(IconButtonVariant::GhostMuted)
                .label("Lock")
                .help("Lock")
                .shortcut("⌘L")
                .on_press(|s: &mut App| s.lock())
                .build(k)
                .key("lock"),
        )
}
