//! Direction C, "Floating": the whole app as one window over whatever you're
//! in, as Raycast and 1Password's Quick Access are. A big search, the list
//! and the selected item side by side, and a footer of what ↵ and ⌘K do;
//! ⌘K opens every action for the item. Run with `--size 760x480`.

use deadbolt_client::protocol::ItemInfo;
use rune::{Color, El, TextStyle, col, el, icon, row, spacer, text};
use rune_kit::{Kit, TextInput};

use super::{BOLT, Look, Shown, Value, code_ring, fields, kind_icon, kind_name, value_el};
use crate::model::App;

const LIST_W: f32 = 248.0;
const LABEL_W: f32 = 96.0;

pub fn window(s: &App, k: &Kit, look: Look) -> El {
    let dark = k.dark;
    let mut card = col()
        .key("float")
        .w_full()
        .h_full()
        .radius(14.0)
        .continuous_corners()
        .fill(k.c.bg_base)
        .border(
            0.5,
            if dark {
                k.c.border_base
            } else {
                k.c.border_weak
            },
        )
        .clip_rounded(14.0)
        .child(header(s, k))
        .child(
            row()
                .key("body")
                .w_full()
                .grow(1.0)
                .min_h(0.0)
                .items_stretch()
                .child(list(s, k))
                .child(detail(s, k, look).grow(1.0).min_w(0.0)),
        )
        .child(footer(s, k));
    for shadow in k.shadow_layers(&k.elevation.overlay) {
        card = card.box_shadow(shadow);
    }
    card = card.child(
        el().key("rim")
            .absolute(0.0, 0.0)
            .w_full()
            .h_full()
            .radius(14.0)
            .continuous_corners()
            .border(
                0.5,
                if dark {
                    k.c.border_base
                } else {
                    k.c.border_weak
                },
            ),
    );
    let mut window = col()
        .key("desk")
        .w_full()
        .h_full()
        .padding(20.0)
        .fill(backdrop(k))
        .child(card);
    if look.actions {
        window = window.child(
            el().absolute(0.0, 0.0)
                .w_full()
                .h_full()
                .items_end()
                .justify_end()
                .pr(36.0)
                .pb(68.0)
                .child(super::actions(s, k, true)),
        );
    }
    window
}

/// What shows around the window in a still: the desktop, faintly.
fn backdrop(k: &Kit) -> Color {
    if k.dark {
        rune_theme_opencode::scale("gray", true, 3)
    } else {
        rune_theme_opencode::scale("gray", false, 4)
    }
}

fn header(s: &App, k: &Kit) -> El {
    row()
        .key("header")
        .w_full()
        .h(56.0)
        .px(18.0)
        .gap(12.0)
        .center_y()
        .child(icon(&BOLT, 18.0).color(rune_theme_opencode::brand(k.dark)))
        .child(
            TextInput::new(&s.search)
                .placeholder("Search Deadbolt")
                .width(None)
                .plain()
                .text_style(TextStyle::new(18.0, 400.0).lh(24.0))
                .height(40.0)
                .on_edit(|s: &mut App| &mut s.search)
                .build(k)
                .grow(1.0),
        )
}

fn list(s: &App, k: &Kit) -> El {
    let rows = s
        .visible()
        .into_iter()
        .fold(col().key("rows").w_full().gap(1.0), |c, item| {
            c.child(list_row(s, k, item))
        });
    col()
        .key("list")
        .w(LIST_W)
        .h_full()
        .px(8.0)
        .clip_rounded(0.0)
        .child(rows)
}

fn list_row(s: &App, k: &Kit, item: &ItemInfo) -> El {
    let on = s.selected.as_deref() == Some(item.id.as_str());
    row()
        .key(format!("row-{}", item.short))
        .w_full()
        .h(40.0)
        .px(10.0)
        .gap(10.0)
        .radius(8.0)
        .continuous_corners()
        .center_y()
        .fill(if on { k.c.layer_02 } else { Color::TRANSPARENT })
        .child(icon(kind_icon(&item.kind), 16.0).color(if on {
            k.c.icon_base
        } else {
            k.c.icon_muted
        }))
        .child(
            col()
                .grow(1.0)
                .min_w(0.0)
                .child(
                    text(item.label.clone())
                        .font(k.ty.ui_compact)
                        .color(k.c.text_strong)
                        .truncate(),
                )
                .child(
                    text(
                        item.detail
                            .clone()
                            .unwrap_or_else(|| kind_name(&item.kind).into()),
                    )
                    .font(super::FACT)
                    .color(k.c.text_faint)
                    .truncate(),
                ),
        )
}

fn detail(s: &App, k: &Kit, look: Look) -> El {
    let pane = col()
        .key("detail")
        .h_full()
        .pl(12.0)
        .pr(20.0)
        .pt(6.0)
        .gap(14.0);
    let Some(item) = s.selected_item() else {
        return pane;
    };
    let shown = fields(s, item);
    let rows = shown
        .iter()
        .enumerate()
        .fold(col().key("fields").w_full(), |c, (i, f)| {
            c.child(field(s, k, f, look.field == Some(i)))
        });
    pane.child(
        row()
            .key("head")
            .gap(10.0)
            .center_y()
            .child(super::glyph_tile(k, &item.kind, 28.0, 7.0))
            .child(
                text(item.label.clone())
                    .font(TextStyle::new(15.0, 600.0).lh(20.0))
                    .color(k.c.text_strong)
                    .truncate_fade(),
            ),
    )
    .child(rows)
}

fn field(s: &App, k: &Kit, f: &Shown, on: bool) -> El {
    let mut value = row().gap(8.0).center_y().grow(1.0).min_w(0.0).child(
        value_el(k, &f.value, k.ty.text_small.lh(18.0), false)
            .grow(1.0)
            .shrink(),
    );
    if matches!(f.value, Value::Code(_)) {
        value = row()
            .gap(8.0)
            .center_y()
            .grow(1.0)
            .child(value_el(k, &f.value, k.ty.text_small.lh(18.0), false))
            .child(code_ring(s, k));
    }
    row()
        .key(format!("field-{}", f.field.name))
        .w_full()
        .h(34.0)
        .ml(-8.0)
        .px(8.0)
        .gap(8.0)
        .radius(7.0)
        .center_y()
        .fill(if on { k.c.layer_02 } else { Color::TRANSPARENT })
        .child(
            text(f.label.clone())
                .font(k.ty.text_small)
                .color(k.c.text_faint)
                .w(LABEL_W)
                .truncate(),
        )
        .child(value)
}

fn footer(s: &App, k: &Kit) -> El {
    let does = s.enter_hint().unwrap_or("Copy");
    row()
        .key("footer")
        .w_full()
        .h(40.0)
        .px(16.0)
        .gap(16.0)
        .center_y()
        .fill(k.c.layer_01)
        .child(text("Personal").font(k.ty.small).color(k.c.text_faint))
        .child(spacer())
        .child(super::hint(k, &["↵"], does))
        .child(super::hint(k, &["⌘", "K"], "Actions"))
}
