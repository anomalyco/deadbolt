//! Direction A, "Document": Seer's shape. The list is the sidebar, with the
//! search under the traffic lights, two-line rows led by a kind glyph and the
//! vault's footer of who's here and Settings. The item is a page in the inset
//! card: a tile and a big title, then its fields stacked label over value,
//! with ⇥ moving into them and the field the keys are on saying what its keys
//! do. ⌘, swaps the page for Settings while the sidebar stays.

use deadbolt_client::protocol::ItemInfo;
use rune::{Color, El, TextStyle, col, el, icon, row, spacer, text};
use rune_kit::shell::{SplitView, Toolbar};
use rune_kit::{
    Button, ButtonVariant, ControlSize, IconButton, IconButtonVariant, Keybind, Kit, TextInput,
};

use super::{
    FACT, Look, Shown, Value, code_ring, field_keys, fields, glyph_tile, kind_icon, kind_name,
    value_el,
};
use crate::model::App;

/// The page's column: wide enough for a public key, narrow enough to read.
pub(super) const PAGE_W: f32 = 560.0;
pub(super) const TITLE: TextStyle = TextStyle::new(22.0, 600.0).lh(28.0);

pub fn vault(s: &App, k: &Kit, inset: f32, look: Look) -> El {
    let mut main = if look.settings {
        super::settings::page(s, k, look)
    } else {
        page(s, k, look)
    };
    let mut toolbar = Toolbar::new();
    if !look.settings {
        toolbar = toolbar.trailing(item_actions(s, k));
    }
    if look.actions {
        main = col().key("page-stack").w_full().h_full().child(main).child(
            col()
                .key("palette")
                .absolute(0.0, 0.0)
                .w_full()
                .h_full()
                .pt(64.0)
                .items_center()
                .child(super::actions(s, k, false)),
        );
    }
    SplitView::new(main)
        .sidebar(
            &s.sidebar,
            |s: &mut App| &mut s.sidebar,
            sidebar(s, k, look),
        )
        .toolbar(toolbar)
        .toolbar_in_panel()
        .hide_sidebar_toggle()
        .titlebar_inset(inset)
        .build(k)
}

fn item_actions(s: &App, k: &Kit) -> El {
    row()
        .key("item-actions")
        .gap(4.0)
        .center_y()
        .pr(8.0)
        .child(
            IconButton::new(&crate::edit::view::PLUS)
                .variant(IconButtonVariant::GhostMuted)
                .help("New item")
                .shortcut("⌘N")
                .build(k)
                .key("new"),
        )
        .children(s.selected_item().map(|_| {
            Button::new("Edit")
                .variant(ButtonVariant::GhostMuted)
                .control_size(ControlSize::Regular)
                .help("Edit")
                .shortcut("⌘E")
                .build(k)
                .key("edit")
        }))
}

// -------------------------------------------------------------------------------------------
// The sidebar.

fn sidebar(s: &App, k: &Kit, look: Look) -> El {
    let visible = s.visible();
    let rows = visible
        .iter()
        .enumerate()
        .fold(col().key("rows").w_full().gap(1.0), |c, (i, item)| {
            c.child(list_row(s, k, item, i, look))
        });
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
                .px(14.0)
                .pb(6.0)
                .center_y()
                .child(
                    text("Personal")
                        .font(k.ty.small_medium)
                        .color(k.c.text_muted)
                        .grow(1.0),
                )
                .child(
                    text(visible.len().to_string())
                        .font(k.ty.small)
                        .color(k.c.text_faint),
                ),
        )
        .child(
            col()
                .key("list")
                .w_full()
                .grow(1.0)
                .min_h(0.0)
                .px(6.0)
                .clip_rounded(0.0)
                .child(rows),
        )
        .child(foot(s, k, look))
}

/// The search, quiet until typed in: no ring, ⌘K at its end.
fn search(s: &App, k: &Kit) -> El {
    let mut input = TextInput::new(&s.search)
        .placeholder("Search")
        .width(None)
        .height(30.0)
        .plain()
        .leading_icon(k.glyph.search)
        .leading_icon_size(14.0)
        .on_edit(|s: &mut App| &mut s.search);
    if s.search.text.is_empty() {
        input = input.trailing(Keybind::new(&["⌘", "K"]).build(k));
    }
    el().key("search")
        .w_full()
        .radius(8.0)
        .continuous_corners()
        .fill(if k.dark { k.c.layer_01 } else { k.c.layer_02 })
        .child(input.build(k).key("search-field"))
}

fn list_row(s: &App, k: &Kit, item: &ItemInfo, i: usize, look: Look) -> El {
    let on = s.selected.as_deref() == Some(item.id.as_str()) && !look.settings;
    let title = text(item.label.clone())
        .font(k.ty.ui)
        .color(if on { k.c.text_strong } else { k.c.text_base })
        .truncate()
        .grow(1.0)
        .min_w(0.0);
    let top = row()
        .key("top")
        .w_full()
        .gap(8.0)
        .center_y()
        .child(icon(kind_icon(&item.kind), 16.0).color(if on {
            k.c.icon_base
        } else {
            k.c.icon_muted
        }))
        .child(title)
        // ⌘1–⌘9 jump to the first nine rows.
        .children((i < 9 && on).then(|| {
            text(format!("⌘{}", i + 1))
                .font(k.ty.small)
                .color(k.c.text_faint)
        }));
    let fact = item
        .detail
        .clone()
        .unwrap_or_else(|| kind_name(&item.kind).to_owned());
    col()
        .key(format!("row-{}", item.short))
        .w_full()
        .px(10.0)
        .py(6.0)
        .gap(1.0)
        .radius(8.0)
        .continuous_corners()
        .fill(if on { k.c.layer_02 } else { Color::TRANSPARENT })
        .hover(k.c.hover)
        .child(top)
        .child(
            text(fact)
                .font(FACT)
                .color(k.c.text_faint)
                .truncate()
                .pl(24.0),
        )
}

/// Where the vault lives and who's here, then Settings and Lock.
fn foot(s: &App, k: &Kit, look: Look) -> El {
    let peers = s.status.as_ref().map_or(0, |st| st.peers_online);
    let device = s
        .status
        .as_ref()
        .and_then(|st| st.device.as_ref())
        .and_then(|d| d.name.clone())
        .unwrap_or_default();
    let about = match peers {
        0 => device,
        1 => format!("{device} · 1 device online"),
        n => format!("{device} · {n} devices online"),
    };
    let cog = IconButton::new(&super::SLIDERS)
        .variant(IconButtonVariant::GhostMuted)
        .help("Settings")
        .shortcut("⌘,")
        .build(k)
        .key("settings");
    let cog = if look.settings {
        el().key("cog-on").radius(6.0).fill(k.c.layer_02).child(cog)
    } else {
        cog
    };
    row()
        .key("foot")
        .w_full()
        .h(44.0)
        .pl(14.0)
        .pr(8.0)
        .gap(2.0)
        .center_y()
        .child(
            row()
                .key("presence")
                .gap(7.0)
                .center_y()
                .grow(1.0)
                .min_w(0.0)
                .child(el().size(6.0, 6.0).radius(3.0).fill(if peers > 0 {
                    k.c.success.icon
                } else {
                    k.c.icon_faint
                }))
                .child(
                    text(about)
                        .font(k.ty.small)
                        .color(k.c.text_muted)
                        .truncate(),
                ),
        )
        .child(cog)
        .child(
            IconButton::new(k.glyph.lock)
                .variant(IconButtonVariant::GhostMuted)
                .help("Lock")
                .shortcut("⌘L")
                .build(k)
                .key("lock"),
        )
}

// -------------------------------------------------------------------------------------------
// The item page.

fn page(s: &App, k: &Kit, look: Look) -> El {
    let body = match s.selected_item() {
        Some(item) => item_page(s, k, item, look),
        None => text("Select an item")
            .font(k.ty.text_small)
            .color(k.c.text_faint),
    };
    let mut pane = col()
        .key("page")
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .items_center()
        .px(40.0)
        .pb(24.0)
        .child(col().key("page-col").w_full().max_w(PAGE_W).child(body))
        .child(spacer());
    if look.field.is_none() && !look.actions {
        pane = pane.child(
            row()
                .key("page-keys")
                .w_full()
                .max_w(PAGE_W)
                .gap(16.0)
                .child(super::hint(k, &["⇥"], "Fields"))
                .child(super::hint(k, &["⌘", "K"], "Actions"))
                .child(spacer())
                .child(super::hint(k, &["?"], "Shortcuts")),
        );
    }
    pane
}

fn item_page(s: &App, k: &Kit, item: &ItemInfo, look: Look) -> El {
    let mut sub = kind_name(&item.kind).to_owned();
    if let Some(source) = &item.source {
        sub = format!("{sub} · From {source}");
    }
    let head = row()
        .key("head")
        .w_full()
        .gap(14.0)
        .center_y()
        .pb(28.0)
        .child(glyph_tile(k, &item.kind, 44.0, 11.0))
        .child(
            col()
                .key("titles")
                .gap(2.0)
                .grow(1.0)
                .min_w(0.0)
                .child(
                    text(item.label.clone())
                        .key("title")
                        .font(TITLE)
                        .color(k.c.text_strong)
                        .truncate_fade(),
                )
                .child(text(sub).font(k.ty.text_small).color(k.c.text_muted)),
        );
    let shown = fields(s, item);
    let mut list = col().key("fields").w_full().gap(2.0);
    for (i, f) in shown.iter().enumerate() {
        // Notes stand apart from what you copy.
        let apart = f.field.name == "notes" && i > 0;
        list = list.child(field(s, k, f, look.field == Some(i)).mt(if apart { 18.0 } else { 0.0 }));
    }
    col().key("item").w_full().child(head).child(list)
}

/// A field, label over value. The one the keys are on is filled and says
/// what ↵, Space and O do; the rest show nothing until hovered.
fn field(s: &App, k: &Kit, f: &Shown, on: bool) -> El {
    let wraps = matches!(f.value, Value::Text(_) | Value::Mono(_))
        || matches!(f.value, Value::Secret { shown: true, .. });
    let mut value = row().key("value").w_full().gap(10.0).center_y().child(
        value_el(k, &f.value, k.ty.ui.lh(20.0), wraps)
            .grow(1.0)
            .shrink(),
    );
    if matches!(f.value, Value::Code(_)) {
        value = row()
            .key("value")
            .gap(10.0)
            .center_y()
            .child(value_el(k, &f.value, k.ty.ui.lh(20.0), false))
            .child(code_ring(s, k));
    }
    let words = col()
        .key("words")
        .gap(3.0)
        .grow(1.0)
        .shrink()
        .min_w(0.0)
        .child(
            text(f.label.clone())
                .font(k.ty.small_medium)
                .color(k.c.text_faint),
        )
        .child(value);
    row()
        .key(format!("field-{}", f.field.name))
        .w_full()
        .min_h(54.0)
        .ml(-12.0)
        .mr(-12.0)
        .px(12.0)
        .py(8.0)
        .gap(16.0)
        .radius(10.0)
        .continuous_corners()
        .center_y()
        .fill(if on { k.c.layer_02 } else { Color::TRANSPARENT })
        .hover(k.c.hover)
        .child(words)
        .children(on.then(|| field_keys(k, f)))
}
