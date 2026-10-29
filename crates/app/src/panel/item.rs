//! The quick panel's item, beside its list: the kind's tile and the label,
//! then one line per field, its name before its value. Secrets stay masked;
//! ⏎ and ⌘K copy from here.

use rune::{El, col, row, text};
use rune_kit::Kit;

use crate::model::{App, group_code, is_secret, title_case};
use crate::view::theme::PANEL_ITEM_TITLE;
use crate::view::{item_fields, masked_secret, tnum};

/// The width of a field's name.
const NAME_W: f32 = 96.0;

pub fn view(s: &App, k: &Kit) -> El {
    let pane = col()
        .key("item")
        .grow(1.0)
        .shrink()
        .min_w(0.0)
        .h_full()
        .pl(16.0)
        .pr(20.0)
        .pt(14.0)
        .gap(14.0);
    let Some(item) = s.selected_item() else {
        return pane;
    };
    let head = row()
        .key("head")
        .gap(10.0)
        .center_y()
        .child(crate::vault::glyph_tile(k, &item.kind, 28.0, 7.0))
        .child(
            text(item.label.clone())
                .key("title")
                .font(PANEL_ITEM_TITLE)
                .color(k.c.text_strong)
                .truncate_fade(),
        );
    let mut fields = col().key("fields").w_full();
    if let Some(full) = s.page() {
        for (field, is_code) in item_fields(full) {
            let value = if is_code {
                let now = s.otp.as_ref().filter(|o| o.item == full.id);
                match (
                    now.and_then(|o| o.code.as_ref()),
                    now.and_then(|o| o.error.as_ref()),
                ) {
                    (Some(code), _) => text(group_code(code))
                        .font(tnum(k.ty.mono))
                        .color(k.c.text_base),
                    (None, Some(err)) => text(format!("No code: {err}"))
                        .font(k.ty.text_small)
                        .color(k.c.danger.fg),
                    (None, None) => text("••• •••").font(tnum(k.ty.mono)).color(k.c.text_base),
                }
            } else if is_secret(&field.kind) {
                masked_secret().font(k.ty.mono).color(k.c.text_base)
            } else {
                text(field.value.lines().next().unwrap_or_default().to_owned())
                    .font(k.ty.text_small)
                    .color(k.c.text_base)
            };
            let name = if is_code {
                "One-time code".to_owned()
            } else {
                title_case(&field.name)
            };
            fields = fields.child(
                row()
                    .key(format!("field-{}", field.name))
                    .w_full()
                    .h(32.0)
                    .gap(8.0)
                    .center_y()
                    .child(
                        text(name)
                            .key("name")
                            .font(k.ty.text_small)
                            .color(k.c.text_faint)
                            .w(NAME_W)
                            .truncate(),
                    )
                    .child(
                        value
                            .key("value")
                            .grow(1.0)
                            .shrink()
                            .min_w(0.0)
                            .truncate_fade(),
                    ),
            );
        }
    }
    pane.child(head).child(fields)
}
