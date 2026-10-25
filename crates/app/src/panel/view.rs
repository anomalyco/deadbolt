//! The quick panel's card: a search field over the vault view's rows, and a
//! footer that says what ⏎ does, then shows the copy as the vault does.
//!
//! Motion: it opens at rest on the next frame, like a menu, and only its
//! close fades (`.25/0`). Rows filter as in the vault (rows that stay slide,
//! rows that arrive or leave fade in place). The footer's label rolls what
//! changes, like the vault's copy notice. Screens inside the card (locked,
//! vault, …) swap with the whole-state replacement. Reduced motion keeps only
//! fades (Rune).

use rune::{
    Cx, El, Icon, ScrollSpec, Spring, SpringPair, TextStyle, Transition, col, el, icon, row,
    spacer, text,
};
use rune_kit::{Button, ButtonVariant, ControlSize, Kit};

use deadbolt_client::protocol::ItemInfo;

use super::{CLOSE, MARGIN, Phase};
use crate::model::{App, Screen};
use crate::view::{LIST_EDGE, copy_line, hint, passphrase_field, rows, search_input, unlock_error};

const HEADER_H: f32 = 56.0;
const FOOTER_H: f32 = 40.0;

pub fn panel(s: &App, cx: &mut Cx<App>) -> El {
    if s.reduced_motion {
        cx.reduced_motion(true);
    }
    let k = crate::theme::kit(cx.system_dark());
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
        Screen::Vault => (search(s, k), list(s, k)),
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
    let mut card = col()
        .key("card")
        .w_full()
        .h_full()
        .radius(k.radius.lg)
        .fill(k.c.bg_base)
        // Only the close fades (`summon` settles what's inside).
        .transition(Transition::asymmetric(
            Transition::identity(),
            Transition::opacity().springs(SpringPair::new(
                Spring::new(CLOSE as f32, 0.0),
                Spring::new(CLOSE as f32, 0.0),
            )),
        ));
    for shadow in k.shadow_layers(&k.elevation.floating) {
        card = card.box_shadow(shadow);
    }
    card.child(header.transition(Transition::blur_replace()))
        .child(rule("rule-top", k))
        .child(
            col()
                .key("body")
                .w_full()
                .grow(1.0)
                .min_h(0.0)
                .child(body.transition(Transition::blur_replace())),
        )
        .child(rule("rule-bottom", k))
        .child(footer(s, k))
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

fn search(s: &App, k: &Kit) -> El {
    header("search")
        .child(
            icon(k.glyph.search, 18.0)
                .key("search-icon")
                .color(k.c.icon_muted),
        )
        .child(search_input(
            s,
            k,
            TextStyle::new(17.0, 400.0).lh(24.0),
            |s, ev, tx| s.panel_search_key(ev, tx),
        ))
}

fn title(k: &Kit, key: &str, glyph: &'static Icon, label: &str) -> El {
    header(key)
        .child(icon(glyph, 18.0).color(k.c.icon_muted))
        .child(
            text(label.to_owned())
                .font(TextStyle::new(17.0, 400.0).lh(24.0))
                .color(k.c.text_strong),
        )
}

fn list(s: &App, k: &Kit) -> El {
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
        .child(rows(s, k))
}

fn locked(s: &App, k: &Kit) -> El {
    let device = s
        .status
        .as_ref()
        .and_then(|st| st.device.as_ref())
        .and_then(|d| d.name.clone());
    let about = match device {
        Some(name) => format!("Enter your passphrase to unlock {name}."),
        None => "Enter your passphrase to unlock this device.".into(),
    };
    let mut body = col()
        .key("unlock")
        .w_full()
        .px(18.0)
        .py(20.0)
        .gap(12.0)
        .child(
            text(about)
                .key("about")
                .font(k.ty.text_small)
                .color(k.c.text_muted)
                .wrap()
                .w_full(),
        )
        .child(passphrase_field(s, k));
    if let Some(e) = unlock_error(s, k) {
        body = body.child(e);
    }
    body
}

fn message(k: &Kit, key: &str, body: &str, action: Option<El>) -> El {
    let mut out = col()
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
        );
    if let Some(action) = action {
        out = out.child(action.key("action"));
    }
    out
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
                .transition(Transition::blur_replace())
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
    bar = bar.child(spacer());
    if s.selected_item().is_some_and(has_username) {
        bar =
            bar.child(hint(k, "h-user", &["⇧", "⏎"], "Username").transition(Transition::opacity()));
    }
    bar.child(hint(k, "h-close", &["esc"], "Close"))
}

/// A login's list row carries its username, if it has one; cards have none.
fn has_username(item: &ItemInfo) -> bool {
    item.kind == "login" && item.detail.is_some()
}

fn enter_does(s: &App) -> &'static str {
    match &s.screen {
        Screen::Vault => match s.selected_item().map(|i| i.kind.as_str()) {
            None => "",
            Some("card") => "Copy number",
            Some(_) => "Copy password",
        },
        Screen::Locked => "Unlock",
        Screen::Onboarding => "Open Deadbolt",
        Screen::Failed(_) => "Try again",
        Screen::Connecting => "",
    }
}
