//! ?: every shortcut, in a card over the page. Esc, ↵ or ? again close it.
//! Settings shows the same columns under its rows.

use rune::{El, col, row, text};
use rune_kit::{Keybind, Kit};

use crate::keys::SHORTCUTS;
use crate::model::App;

/// Two columns of what each key does and its keycaps.
pub fn columns(k: &Kit) -> El {
    let half = SHORTCUTS.len().div_ceil(2);
    let column = |keys: &[(&[&str], &str)]| {
        keys.iter()
            .fold(col().gap(10.0).grow(1.0).w(0.0), |c, (caps, label)| {
                c.child(
                    row()
                        .w_full()
                        .center_y()
                        .child(
                            text((*label).to_owned())
                                .font(k.ty.text_small)
                                .color(k.c.text_muted)
                                .grow(1.0),
                        )
                        .child(Keybind::new(caps).build(k)),
                )
            })
    };
    row()
        .key("shortcuts")
        .w_full()
        .gap(40.0)
        .items_start()
        .child(column(&SHORTCUTS[..half]))
        .child(column(&SHORTCUTS[half..]))
}

pub fn view(s: &App, k: &Kit) -> Option<El> {
    if !s.nav.sheet {
        return None;
    }
    let card = col()
        .key("sheet")
        .role("dialog")
        .label("Keyboard shortcuts")
        .w(500.0)
        .padding(20.0)
        .gap(16.0)
        .radius(12.0)
        .continuous_corners()
        .fill(k.c.surface_raised)
        .border(0.5, k.c.border_weak)
        .child(
            row()
                .key("sheet-head")
                .w_full()
                .center_y()
                .child(
                    text("Keyboard shortcuts")
                        .font(k.ty.ui_medium)
                        .color(k.c.text_strong)
                        .grow(1.0),
                )
                .child(Keybind::new(&["esc"]).build(k)),
        )
        .child(columns(k));
    Some(k.elevate(card, &k.elevation.overlay))
}
