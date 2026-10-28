//! Direction B, "List first": the list is the window, one line per item and
//! grouped by kind, each led by a monogram in its own colour (standing in for
//! a site's icon). The selected item sits in an inspector at the right, its
//! fields in boxes as 1Password groups them. Search spans the title bar.

use deadbolt_client::protocol::ItemInfo;
use rune::{Color, El, TextStyle, col, el, icon, row, spacer, text};
use rune_kit::{IconButton, IconButtonVariant, Keybind, Kit, TextInput};

use super::{Look, Shown, Value, code_ring, fields, kind_icon, kind_name, monogram, value_el};
use crate::model::App;

const INSPECTOR_W: f32 = 300.0;
const ROW_H: f32 = 32.0;
const USER_W: f32 = 150.0;

pub fn vault(s: &App, k: &Kit, inset: f32, look: Look) -> El {
    col()
        .key("compact")
        .w_full()
        .h_full()
        .child(band(s, k, inset))
        .child(
            row()
                .key("body")
                .w_full()
                .grow(1.0)
                .min_h(0.0)
                .items_stretch()
                .child(list(s, k).grow(1.0).min_w(0.0))
                .child(inspector(s, k, look)),
        )
}

fn band(s: &App, k: &Kit, inset: f32) -> El {
    let mut input = TextInput::new(&s.search)
        .placeholder(crate::view::search_placeholder(s))
        .width(None)
        .plain()
        .leading_icon(k.glyph.search)
        .on_edit(|s: &mut App| &mut s.search);
    if s.search.text.is_empty() {
        input = input.trailing(Keybind::new(&["⌘", "K"]).build(k));
    }
    row()
        .key("band")
        .w_full()
        .h(48.0)
        .pl(inset.max(80.0))
        .pr(10.0)
        .gap(6.0)
        .center_y()
        .window_drag()
        .child(
            el().key("search")
                .w_full()
                .max_w(380.0)
                .radius(8.0)
                .continuous_corners()
                .fill(if k.dark { k.c.layer_01 } else { k.c.layer_02 })
                .child(input.build(k)),
        )
        .child(spacer())
        .child(
            IconButton::new(&crate::edit::view::PLUS)
                .variant(IconButtonVariant::GhostMuted)
                .help("New item")
                .shortcut("⌘N")
                .build(k),
        )
        .child(
            IconButton::new(k.glyph.lock)
                .variant(IconButtonVariant::GhostMuted)
                .help("Lock")
                .shortcut("⌘L")
                .build(k),
        )
}

/// Groups in a fixed order, each its kind's plural and a count.
fn list(s: &App, k: &Kit) -> El {
    const ORDER: [(&str, &str); 6] = [
        ("login", "Logins"),
        ("passkey", "Passkeys"),
        ("card", "Cards"),
        ("identity", "Identities"),
        ("note", "Secure notes"),
        ("ssh", "SSH keys"),
    ];
    let visible = s.visible();
    let mut c = col().key("list").w_full().px(8.0).pt(4.0).pb(8.0);
    for (kind, title) in ORDER {
        let items: Vec<&&ItemInfo> = visible.iter().filter(|i| i.kind == kind).collect();
        if items.is_empty() {
            continue;
        }
        c = c.child(
            row()
                .key(format!("group-{kind}"))
                .w_full()
                .h(28.0)
                .px(10.0)
                .gap(6.0)
                .center_y()
                .mt(8.0)
                .child(text(title).font(k.ty.small_medium).color(k.c.text_muted))
                .child(
                    text(items.len().to_string())
                        .font(k.ty.small)
                        .color(k.c.text_faint),
                ),
        );
        for item in items {
            c = c.child(list_row(s, k, item));
        }
    }
    el().key("list-card")
        .ml(8.0)
        .mb(8.0)
        .radius(10.0)
        .continuous_corners()
        .fill(k.c.bg_base)
        .border(0.5, k.c.border_weak)
        .clip_rounded(10.0)
        .child(c)
}

fn list_row(s: &App, k: &Kit, item: &ItemInfo) -> El {
    let on = s.selected.as_deref() == Some(item.id.as_str());
    row()
        .key(format!("row-{}", item.short))
        .w_full()
        .h(ROW_H)
        .px(10.0)
        .gap(10.0)
        .radius(7.0)
        .continuous_corners()
        .center_y()
        .fill(if on { k.c.layer_02 } else { Color::TRANSPARENT })
        .hover(k.c.hover)
        .child(badge(k, item, 20.0))
        .child(
            text(item.label.clone())
                .font(k.ty.ui)
                .color(k.c.text_strong)
                .truncate()
                .grow(1.0)
                .min_w(0.0),
        )
        .child(
            text(item.detail.clone().unwrap_or_default())
                .font(k.ty.text_small)
                .color(k.c.text_faint)
                .truncate()
                .w(USER_W),
        )
}

/// A site's monogram for what signs in somewhere, the kind's glyph otherwise.
fn badge(k: &Kit, item: &ItemInfo, size: f32) -> El {
    if matches!(item.kind.as_str(), "login" | "passkey") {
        monogram(k, &item.label, size)
    } else {
        super::glyph_tile(k, &item.kind, size, size / 4.0)
    }
}

fn inspector(s: &App, k: &Kit, look: Look) -> El {
    let pane = col()
        .key("inspector")
        .w(INSPECTOR_W)
        .h_full()
        .px(16.0)
        .pb(16.0)
        .gap(16.0);
    let Some(item) = s.selected_item() else {
        return pane.child(
            text("Nothing selected")
                .font(k.ty.text_small)
                .color(k.c.text_faint),
        );
    };
    let head = col()
        .key("head")
        .w_full()
        .gap(10.0)
        .pt(4.0)
        .child(badge(k, item, 40.0))
        .child(
            col()
                .gap(2.0)
                .child(
                    text(item.label.clone())
                        .font(TextStyle::new(17.0, 600.0).lh(22.0))
                        .color(k.c.text_strong)
                        .truncate_fade(),
                )
                .child(
                    row()
                        .gap(5.0)
                        .center_y()
                        .child(icon(kind_icon(&item.kind), 12.0).color(k.c.icon_faint))
                        .child(
                            text(kind_name(&item.kind))
                                .font(k.ty.small)
                                .color(k.c.text_faint),
                        ),
                ),
        );
    let shown = fields(s, item);
    // What you copy in one box, a site in another, notes on their own.
    let (notes, rest): (Vec<_>, Vec<_>) = shown
        .iter()
        .enumerate()
        .partition(|(_, f)| f.field.name == "notes");
    let (site, creds): (Vec<_>, Vec<_>) =
        rest.into_iter().partition(|(_, f)| f.field.name == "url");
    let mut p = pane.child(head);
    for (key, group) in [("creds", creds), ("site", site), ("notes", notes)] {
        if !group.is_empty() {
            p = p.child(boxed(s, k, key, &group, look.field));
        }
    }
    p.child(spacer()).child(
        row()
            .key("keys")
            .w_full()
            .gap(14.0)
            .children(s.enter_hint().map(|does| super::hint(k, &["↵"], does)))
            .child(super::hint(k, &["⌘", "K"], "Actions")),
    )
}

fn boxed(s: &App, k: &Kit, key: &str, group: &[(usize, &Shown)], at: Option<usize>) -> El {
    let mut c = col()
        .key(format!("box-{key}"))
        .w_full()
        .radius(10.0)
        .continuous_corners()
        .border(0.5, k.c.border_base)
        .clip_rounded(10.0);
    for (n, (i, f)) in group.iter().enumerate() {
        if n > 0 {
            c = c.child(el().w_full().h(0.5).fill(k.c.border_weak));
        }
        c = c.child(cell(s, k, f, at == Some(*i)));
    }
    c
}

fn cell(s: &App, k: &Kit, f: &Shown, on: bool) -> El {
    let wraps = !matches!(f.value, Value::Secret { shown: false, .. } | Value::Code(_));
    let mut value = row().gap(8.0).center_y().child(
        value_el(k, &f.value, k.ty.text_small.lh(18.0), wraps)
            .grow(1.0)
            .shrink(),
    );
    if matches!(f.value, Value::Code(_)) {
        value = value.child(code_ring(s, k));
    }
    col()
        .key(format!("cell-{}", f.field.name))
        .w_full()
        .px(12.0)
        .py(8.0)
        .gap(2.0)
        .fill(if on { k.c.layer_02 } else { Color::TRANSPARENT })
        .hover(k.c.hover)
        .child(
            text(f.label.clone())
                .font(super::FACT)
                .color(k.c.text_faint),
        )
        .child(value)
}
