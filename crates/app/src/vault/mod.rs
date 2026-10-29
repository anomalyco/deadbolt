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

use deadbolt_client::protocol::{ItemInfo, noun};
use rune::{Anim, El, Icon, ScrollSpec, TextStyle, Transition, col, el, icon, row, text};
use rune_kit::shell::{SplitView, Toolbar};
use rune_kit::{IconButton, IconButtonVariant, Keybind, Kit, TextInput};

use crate::model::App;
use crate::view::LIST_EDGE;

/// A list row: the item's label over its detail.
const ROW_H: f32 = 46.0;
const ROW_GAP: f32 = 2.0;
const ROWS_PAD: f32 = 6.0;
/// The 11.5/440 second line Seer's rows use.
pub(crate) const FACT: TextStyle = TextStyle::new(11.5, 440.0).lh(14.0);

macro_rules! glyph {
    ($name:literal, $body:literal) => {
        Icon {
            name: $name,
            view: 16.0,
            body: $body,
        }
    };
}

static LOGIN: Icon = glyph!(
    "kind-login",
    r#"<circle cx="5.25" cy="10.75" r="2.75" stroke="currentColor" stroke-width="1.25"/><path d="M7.2 8.8L13 3M10.6 5.4l1.6 1.6M12.1 3.9l1.15 1.15" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
static CARD: Icon = glyph!(
    "kind-card",
    r#"<rect x="2.25" y="3.75" width="11.5" height="8.5" rx="1.75" stroke="currentColor" stroke-width="1.25"/><path d="M2.25 6.75h11.5M4.75 9.75h2.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
static NOTE: Icon = glyph!(
    "kind-note",
    r#"<path d="M4 2.75h5.25l2.75 2.75v7.75H4z" stroke="currentColor" stroke-width="1.25" stroke-linejoin="round"/><path d="M6.25 8.25h3.5M6.25 10.5h2.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
static SSH: Icon = glyph!(
    "kind-ssh",
    r#"<rect x="2.25" y="3" width="11.5" height="10" rx="1.75" stroke="currentColor" stroke-width="1.25"/><path d="M5 6.5l1.75 1.5L5 9.5M8.5 10h2.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
static IDENTITY: Icon = glyph!(
    "kind-identity",
    r#"<circle cx="8" cy="5.75" r="2.5" stroke="currentColor" stroke-width="1.25"/><path d="M3.5 13.25c.6-2.3 2.4-3.5 4.5-3.5s3.9 1.2 4.5 3.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
static PASSKEY: Icon = glyph!(
    "kind-passkey",
    r#"<circle cx="6" cy="5.5" r="2.25" stroke="currentColor" stroke-width="1.25"/><path d="M2.5 12.75c.4-2 1.8-3.25 3.5-3.25.8 0 1.5.25 2.1.7" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/><circle cx="11.25" cy="9" r="1.75" stroke="currentColor" stroke-width="1.25"/><path d="M11.25 10.75v2.75M11.25 12.25h1.25" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
pub(crate) static SLIDERS: Icon = glyph!(
    "sliders",
    r#"<path d="M2.75 5h6M11.75 5h1.5M2.75 11h1.5M7.25 11h6" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/><circle cx="10.25" cy="5" r="1.5" stroke="currentColor" stroke-width="1.25"/><circle cx="5.75" cy="11" r="1.5" stroke="currentColor" stroke-width="1.25"/>"#
);

pub(crate) fn kind_icon(kind: &str) -> &'static Icon {
    match kind {
        "card" => &CARD,
        "note" => &NOTE,
        "ssh" => &SSH,
        "identity" => &IDENTITY,
        "passkey" => &PASSKEY,
        _ => &LOGIN,
    }
}

/// "Login", "Card", "Secure note", "SSH key"…
pub(crate) fn kind_name(kind: &str) -> &'static str {
    match kind {
        "card" => "Card",
        "note" => "Secure note",
        "ssh" => "SSH key",
        "identity" => "Identity",
        "passkey" => "Passkey",
        _ => "Login",
    }
}

/// A tile with the item's kind glyph: quiet, one tone, as Seer's glyphs.
pub(crate) fn glyph_tile(k: &Kit, kind: &str, size: f32, radius: f32) -> El {
    row()
        .key("tile")
        .size(size, size)
        .center()
        .radius(radius)
        .continuous_corners()
        .fill(k.c.layer_02)
        .child(icon(kind_icon(kind), (size * 0.5).round()).color(k.c.icon_base))
}

/// What a row says under its label: the item's detail, else its kind.
pub(crate) fn fact(item: &ItemInfo) -> String {
    item.detail
        .clone()
        .unwrap_or_else(|| kind_name(&item.kind).to_owned())
}

/// The vault: the sidebar and the page, with ⌘K's actions and the ? sheet
/// over it in `layer`.
pub fn view(s: &App, k: &Kit, inset: f32, layer: &mut Vec<El>) -> El {
    let main = if s.settings_open {
        crate::settings::page(s, k)
    } else {
        page::pane(s, k)
    };
    let mut toolbar = Toolbar::new();
    if !s.settings_open {
        toolbar = toolbar.trailing(page::toolbar(s, k));
    }
    layer.extend(crate::palette::view(s, k).map(|card| over(card, 72.0)));
    layer.extend(crate::sheet::view(s, k).map(|card| over(card, 96.0)));
    SplitView::new(main)
        .sidebar(&s.sidebar, |s: &mut App| &mut s.sidebar, sidebar(s, k))
        .toolbar(toolbar)
        .toolbar_in_panel()
        .hide_sidebar_toggle()
        .titlebar_inset(inset)
        .build(k)
}

/// A card over the whole window, `top` from its top; a press beside it
/// closes it, as Esc does.
fn over(card: El, top: f32) -> El {
    col()
        .key("over")
        .pin(Some(0.0), Some(0.0), Some(0.0), Some(0.0))
        .items_center()
        .pt(top)
        .on_press(|s: &mut App| {
            s.close_palette();
            s.nav.sheet = false;
        })
        .child(card.on_press(|_: &mut App| {}))
}

fn sidebar(s: &App, k: &Kit) -> El {
    let vault = s
        .status
        .as_ref()
        .and_then(|st| st.vaults.iter().find(|v| v.default).or(st.vaults.first()))
        .map_or_else(|| "Personal".to_owned(), |v| v.name.clone());
    let count = if s.search.text.trim().is_empty() {
        s.items.len()
    } else {
        s.visible().len()
    };
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
                    text(vault)
                        .font(k.ty.small_medium)
                        .color(k.c.text_muted)
                        .grow(1.0)
                        .truncate(),
                )
                .children(s.loaded.then(|| {
                    text(count.to_string())
                        .key("count")
                        .font(k.ty.small.features("'tnum' 1"))
                        .color(k.c.text_faint)
                })),
        )
        .child(
            col()
                .key("list")
                .w_full()
                .grow(1.0)
                .min_h(0.0)
                .scroll(ScrollSpec {
                    stick_bottom: false,
                })
                .scroll_edge_fade(LIST_EDGE)
                .scroll_margin(LIST_EDGE)
                .child(rows(s, k)),
        )
        .child(foot(s, k))
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

/// The visible items as rows, or why there are none.
pub(crate) fn rows(s: &App, k: &Kit) -> El {
    let visible = s.visible();
    let mut rows = col()
        .key("rows")
        .role("listbox")
        .label("Items")
        .w_full()
        .gap(ROW_GAP)
        .px(ROWS_PAD)
        .py(ROWS_PAD);
    if !s.loaded {
        // The list arrives within a frame or two of unlocking; show nothing rather than a flash.
    } else if s.items.is_empty() {
        rows = rows.child(empty(
            k,
            "empty",
            "No items yet",
            "What you add shows up here and on your other devices.",
        ));
    } else if visible.is_empty() {
        rows = rows.child(empty(
            k,
            "no-match",
            "No matches",
            &format!("Nothing matches “{}”.", s.search.text.trim()),
        ));
    }
    let at = s
        .selected
        .as_deref()
        .and_then(|id| visible.iter().position(|i| i.id == id))
        .filter(|_| !s.settings_open);
    if let Some(at) = at {
        // One highlight for the list, under the rows, on the selection at once.
        rows = rows.child(
            el().key("highlight")
                .pin(Some(ROWS_PAD), Some(ROWS_PAD), Some(ROWS_PAD), None)
                .h(ROW_H)
                .radius(8.0)
                .continuous_corners()
                .fill(k.c.pressed)
                .offset(0.0, at as f32 * (ROW_H + ROW_GAP))
                .offset_motion(Anim::INSTANT),
        );
    }
    for (i, item) in visible.iter().enumerate() {
        rows = rows.child(list_row(k, item, i, at == Some(i)));
    }
    rows
}

fn empty(k: &Kit, key: &str, title: &str, body: &str) -> El {
    col()
        .key(key)
        .w_full()
        .px(10.0)
        .py(24.0)
        .gap(4.0)
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
    let sub = fact(item);
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
            text(sub.clone())
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
    let device = s
        .status
        .as_ref()
        .and_then(|st| st.device.as_ref())
        .and_then(|d| d.name.clone())
        .unwrap_or_else(|| "This device".to_owned());
    let about = match peers {
        0 => device,
        1 => format!("{device} · 1 online"),
        n => format!("{device} · {n} online"),
    };
    let settings = IconButton::new(&SLIDERS)
        .variant(IconButtonVariant::GhostMuted)
        .label("Settings")
        .help("Settings")
        .shortcut("⌘,")
        .on_press(|s: &mut App| {
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
