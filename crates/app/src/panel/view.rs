//! The quick panel's card: a search field over the vault's rows beside the
//! selected item, and a footer that says what ⏎ and ⌘K do, then shows the
//! copy as the vault does. ⌘K's actions open over its corner.
//!
//! Motion: it opens at rest on the next frame, like a menu, and only its
//! close fades (`.25/0`). Rows filter as in the vault (rows that stay slide,
//! rows that arrive or leave fade in place). The footer's label rolls what
//! changes, like the vault's copy notice. Screens inside the card (locked,
//! vault, …) swap with the whole-state replacement. Reduced motion keeps only
//! fades (Rune).

use rune::{Cx, El, Icon, Spring, SpringPair, Transition, col, el, icon, row, spacer, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Kit, TextInput};

use super::{CLOSE, MARGIN, Phase};
use crate::model::{App, Screen};
use crate::view::theme::PANEL_HEADER;
use crate::view::{
    copy_line, device_name, extra_copy_hints, hint, instant, passphrase_field, replace,
    search_placeholder, touch_id_button, unlock_error,
};

const HEADER_H: f32 = 56.0;
const FOOTER_H: f32 = 40.0;
/// The list beside the item.
const LIST_W: f32 = 250.0;

pub fn panel(s: &App, cx: &mut Cx<App>) -> El {
    if s.reduced_motion {
        cx.reduced_motion(true);
    }
    let k = rune_theme_opencode::kit(cx.system_dark());
    let mut window = col().key("panel").w_full().h_full().padding(MARGIN);
    let showing = matches!(
        s.panel_phase(),
        Some(Phase::Open | Phase::Copied { .. }) | None
    );
    if showing {
        window = window.child(card(s, k));
    }
    window
}

fn card(s: &App, k: &Kit) -> El {
    let (header, body) = match &s.screen {
        Screen::Vault => (search(s, k), vault(s, k)),
        Screen::Locked => (
            title(k, "locked", k.glyph.lock, "Unlock Deadbolt"),
            locked(s, k),
        ),
        Screen::Onboarding => (
            title(k, "setup", k.glyph.lock, "Set up Deadbolt"),
            message(
                k,
                "setup",
                "This device has no vault yet. Create one, or join one from your other device, in Deadbolt's window.",
                Some(
                    Button::new("Open Deadbolt")
                        .variant(ButtonVariant::Contrast)
                        .control_size(ControlSize::Large)
                        .on_press_tx(|s: &mut App, tx| s.open_main(tx))
                        .build(k),
                ),
            ),
        ),
        Screen::Failed(error) => (
            title(k, "failed", k.glyph.lock, "Can't reach Deadbolt"),
            message(
                k,
                "failed",
                error,
                Some(
                    Button::new("Try again")
                        .variant(ButtonVariant::Neutral)
                        .control_size(ControlSize::Large)
                        .on_press(|s: &mut App| s.retry())
                        .build(k),
                ),
            ),
        ),
        Screen::Connecting => (
            title(k, "connecting", k.glyph.lock, "Deadbolt"),
            message(k, "connecting", "Starting Deadbolt…", None),
        ),
    };
    let close = Spring::new(CLOSE as f32, 0.0);
    let card = k.elevate(
        col()
            .key("card")
            .w_full()
            .h_full()
            .radius(k.radius.lg)
            .fill(k.c.bg_base)
            // Only the close fades (`summon` settles what's inside).
            .transition(Transition::asymmetric(
                Transition::identity(),
                Transition::opacity().springs(SpringPair::new(close, close)),
            )),
        &k.elevation.floating,
    );
    let card = card
        .child(header.transition(replace()))
        .child(rule("rule-top", k))
        .child(
            col()
                .key("body")
                .w_full()
                .grow(1.0)
                .min_h(0.0)
                .child(body.transition(replace())),
        )
        .child(rule("rule-bottom", k))
        .child(footer(s, k));
    match crate::palette::view(s, k) {
        Some(actions) => card.child(
            col()
                .key("over")
                .pin(Some(0.0), Some(0.0), Some(0.0), Some(0.0))
                .items_end()
                .justify_end()
                .pr(16.0)
                .pb(FOOTER_H + 8.0)
                .transition(instant())
                .on_press_tx(|s: &mut App, tx| {
                    tx.instant();
                    s.close_palette();
                })
                .child(actions.on_press(|_: &mut App| {})),
        ),
        None => card,
    }
}

fn rule(key: &str, k: &Kit) -> El {
    el().key(key).h(1.0).w_full().fill(k.c.border_weak)
}

fn header(key: &str) -> El {
    row()
        .key(key)
        .w_full()
        .h(HEADER_H)
        .px(18.0)
        .gap(12.0)
        .center_y()
}

/// A flat field filling the header: a press anywhere on it, the icon too,
/// lands in the field. While the copy's confirmation shows it takes nothing.
fn search(s: &App, k: &Kit) -> El {
    let mut field = TextInput::new(&s.search)
        .plain()
        .placeholder(search_placeholder(s))
        .leading_icon(k.glyph.search)
        .leading_icon_size(18.0)
        .text_style(PANEL_HEADER)
        .height(HEADER_H)
        .width(None)
        .on_key(|s: &mut App, ev, tx| s.panel_search_key(ev, tx))
        .on_change(|s: &mut App, _| s.search_changed());
    if !s.panel_inert() {
        field = field.on_edit(|s: &mut App| &mut s.search);
        if !s.search.text.is_empty() {
            field = field
                .clear_button()
                .on_action(|s: &mut App, _| s.clear_search());
        }
    }
    header("search")
        .px(10.0)
        .child(field.build(k).key("search-field").label("Search items"))
}

/// Icon and text where the search field puts its own (its 6 pt gap).
fn title(k: &Kit, key: &str, glyph: &'static Icon, label: &str) -> El {
    header(key)
        .gap(6.0)
        .child(icon(glyph, 18.0).color(k.c.icon_muted))
        .child(
            text(label.to_owned())
                .font(PANEL_HEADER)
                .color(k.c.text_strong),
        )
}

/// The list beside the selected item.
fn vault(s: &App, k: &Kit) -> El {
    let visible = s.visible_at();
    row()
        .key("split")
        .w_full()
        .h_full()
        .items_stretch()
        .child(crate::vault::item_list(s, k, &visible).w(LIST_W).h_full())
        .child(el().key("rule-side").w(1.0).h_full().fill(k.c.border_weak))
        .child(super::item::view(s, k))
}

fn locked(s: &App, k: &Kit) -> El {
    let about = match (device_name(s), s.touch_id_ready()) {
        (Some(name), true) => format!("Use Touch ID or enter your passphrase to unlock {name}."),
        (None, true) => "Use Touch ID or enter your passphrase to unlock this device.".into(),
        (Some(name), false) => format!("Enter your passphrase to unlock {name}."),
        (None, false) => "Enter your passphrase to unlock this device.".into(),
    };
    col()
        .key("unlock")
        .w_full()
        .px(18.0)
        .py(20.0)
        .gap(12.0)
        .items_start()
        .child(
            text(about)
                .key("about")
                .font(k.ty.text_small)
                .color(k.c.text_muted)
                .wrap()
                .w_full(),
        )
        .child(passphrase_field(s, k))
        .children(unlock_error(s, k))
        .children(touch_id_button(s, k).map(|b| b.mt(4.0)))
}

fn message(k: &Kit, key: &str, body: &str, action: Option<El>) -> El {
    col()
        .key(format!("{key}-body"))
        .w_full()
        .px(18.0)
        .py(20.0)
        .gap(16.0)
        .items_start()
        .child(
            text(body.to_owned())
                .key("message")
                .font(k.ty.text_small)
                .color(k.c.text_muted)
                .wrap()
                .w_full(),
        )
        .children(action.map(|a| a.key("action")))
}

/// What ⏎ does, rolling into the copy's line (as in the vault's copy notice)
/// once it lands or if it failed; a notice replaces it. The other keys sit on
/// the right.
fn footer(s: &App, k: &Kit) -> El {
    let copied = matches!(s.panel_phase(), Some(Phase::Copied { .. }));
    let copy = s
        .copy
        .as_ref()
        .filter(|copy| copied || copy.error.is_some());
    let mut bar = row()
        .key("footer")
        .w_full()
        .h(FOOTER_H)
        .px(14.0)
        .gap(8.0)
        .center_y();
    let enter = enter_does(s);
    if let (None, Some(notice)) = (copy, &s.notice) {
        bar = bar.child(
            row()
                .key(format!("notice:{notice}"))
                .shrink()
                .center_y()
                .transition(replace())
                .child(
                    text(notice.clone())
                        .font(k.ty.text_small)
                        .color(k.c.text_muted)
                        .truncate(),
                ),
        );
    } else if copy.is_some() || !enter.is_empty() {
        bar = bar.child(copy_line(k, "footer-line", copy, enter, false));
    }
    bar = bar.child(spacer()).children(extra_copy_hints(s, k));
    if s.screen == Screen::Vault && s.selected_item().is_some() {
        bar = bar.child(hint(k, "h-actions", &["⌘", "K"], "Actions"));
    }
    bar.child(hint(k, "h-close", &["esc"], "Close"))
}

fn enter_does(s: &App) -> &'static str {
    match &s.screen {
        Screen::Vault => s.enter_hint().unwrap_or_default(),
        Screen::Locked if s.touch_id_ready() && s.passphrase.text.is_empty() => "Touch ID",
        Screen::Locked => "Unlock",
        Screen::Onboarding => "Open Deadbolt",
        Screen::Failed(_) => "Try again",
        Screen::Connecting => "",
    }
}
