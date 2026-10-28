//! The quick panel's item, beside its list: the kind's tile and the label,
//! then one line per field, its name before its value. Secrets stay masked;
//! ⏎ and ⌘K copy from here.

use deadbolt_client::protocol::code_field;
use rune::{El, TextStyle, col, row, text};
use rune_kit::Kit;

use crate::keys::shown;
use crate::model::{App, group_code, is_secret, title_case};

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
                .font(TextStyle::new(15.0, 600.0).lh(20.0))
                .color(k.c.text_strong)
                .truncate_fade(),
        );
    let mut fields = col().key("fields").w_full();
    if let Some(full) = s.detail.as_ref().filter(|d| d.id == item.id) {
        let code = code_field(&full.fields);
        for (i, field) in full.fields.iter().enumerate() {
            if !shown(&full.kind, &field.name) {
                continue;
            }
            let value = if code == Some(i) {
                let now = s.otp.as_ref().filter(|o| o.item == full.id);
                text(
                    now.and_then(|o| o.code.as_ref())
                        .map_or_else(|| "••• •••".to_owned(), |c| group_code(c)),
                )
                .font(k.ty.mono.features("'tnum' 1"))
            } else if is_secret(&field.kind) {
                text(field.value.trim_end_matches(['\r', '\n']).to_owned())
                    .secure()
                    .revealed(false)
                    .font(k.ty.mono)
            } else {
                text(field.value.lines().next().unwrap_or_default().to_owned())
                    .font(k.ty.text_small)
            };
            let name = if code == Some(i) {
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
                            .color(k.c.text_base)
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
