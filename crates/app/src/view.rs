//! Drawing. Every screen reads `App` and returns Rune elements; handlers call
//! into `model.rs`.
//!
//! Motion (docs/app.md has the full table): screens swap with Kit's
//! whole-state replacement (blur σ 1.5, scale .96, fade; exits shorter). A
//! search replaces the list at once, and any new selection (search, arrows,
//! a click) replaces the item's title and fields at once. Nothing animates on
//! first paint, and reduced motion keeps only fades (Rune's runtime does both).

mod notice;
pub(crate) mod theme;

use deadbolt_client::protocol::{FieldInfo, ItemInfo, code_field};
use rune::{Cx, Edge, El, Icon, ScrollSpec, Transition, col, el, icon, row, text};
use rune_kit::shell::Page;
use rune_kit::{
    Button, ButtonVariant, ControlSize, IconButton, IconButtonVariant, Keybind, Kit, RollingText,
    TextInput,
};

use crate::keys::shown;
use crate::model::{App, Copy, Screen, has_code};
use theme::CARD_TITLE;

pub(crate) use notice::banner;
pub use notice::{Notice, Severity};
pub use theme::CHROME;
pub(crate) use theme::{LIST_EDGE, NOTICE_W, instant, replace, rise, tnum};

pub fn app(s: &App, cx: &mut Cx<App>) -> El {
    if s.reduced_motion {
        cx.reduced_motion(true);
    }
    let k = rune_theme_opencode::kit(cx.system_dark());
    let inset = cx.titlebar_inset();
    let reduced = cx.is_reduced_motion();
    let mut layer = Vec::new();
    let screen = match &s.screen {
        Screen::Vault if !s.installing() => crate::vault::view(s, k, inset, reduced, &mut layer),
        Screen::Vault => page(k, inset, crate::install::page(s, k)),
        Screen::Connecting => page(k, inset, connecting(k).into()),
        Screen::Onboarding => page(
            k,
            inset,
            crate::onboarding::view::screen(s, k, cx.system_dark()),
        ),
        Screen::Locked => page(k, inset, unlock(s, k).into()),
        Screen::Failed(message) => page(k, inset, failed(k, message).into()),
    };
    let root = col()
        .key("window")
        .w_full()
        .h_full()
        .fill(k.c.bg_deep)
        .child(screen.grow(1.0).w_full().transition(replace()))
        .children(layer);
    // An export dropped anywhere on the open vault goes straight to its preview.
    if s.accepts_drops() {
        root.on_drop_files(|s: &mut App, files, _| s.drop_files(files))
            .accepts_extensions(crate::import::EXTENSIONS)
            .on_drop_hover(|s: &mut App, over, tx| {
                tx.instant();
                s.drop_hover(over);
            })
            // Anything else is refused on the drop, with why; a drag of it
            // lights nothing, as the drop zone only lights for what it takes.
            .on_drop_rejected(|s: &mut App, files, _| s.drop_rejected(files))
    } else {
        root
    }
}

/// A screen other than the vault: what its page holds, and the button in its
/// title bar (Back or Cancel).
pub struct Paged {
    pub body: El,
    pub back: Option<El>,
}

impl From<El> for Paged {
    fn from(body: El) -> Paged {
        Paged { body, back: None }
    }
}

/// The frame and title bar of the vault's shell, for every other screen.
/// Within it, one screen replaces the next.
fn page(k: &Kit, inset: f32, p: Paged) -> El {
    let mut page = Page::new(p.body.grow(1.0).w_full().transition(replace())).titlebar_inset(inset);
    if let Some(back) = p.back {
        page = page.leading(back.transition(Transition::opacity()));
    }
    el().key("page").w_full().h_full().child(page.build(k))
}

/// A centred column for the screens that aren't the vault.
fn centred(key: &str, k: &Kit, glyph: &'static Icon, title: &str, body: El) -> El {
    col().key(key).center().child(
        col()
            .key("panel")
            .w(320.0)
            .gap(16.0)
            .items_start()
            .child(
                row()
                    .key("mark")
                    .size(36.0, 36.0)
                    .center()
                    .radius(k.radius.lg)
                    .fill(k.c.layer_02)
                    .child(icon(glyph, 20.0).color(k.c.icon_base)),
            )
            .child(
                text(title)
                    .key("title")
                    .font(CARD_TITLE)
                    .color(k.c.text_strong),
            )
            .child(body),
    )
}

fn muted(k: &Kit, key: &str, s: impl Into<String>) -> El {
    text(s.into())
        .key(key)
        .font(k.ty.text_small)
        .color(k.c.text_muted)
        .wrap()
        .w_full()
}

fn connecting(k: &Kit) -> El {
    col().key("connecting").center().child(
        text("Starting Deadbolt…")
            .font(k.ty.text_small)
            .color(k.c.text_faint),
    )
}

fn failed(k: &Kit, message: &str) -> El {
    centred(
        "failed",
        k,
        k.glyph.lock,
        "Can't reach Deadbolt",
        col()
            .key("body")
            .w_full()
            .gap(16.0)
            .child(muted(k, "message", message))
            .child(
                Button::new("Try again")
                    .variant(ButtonVariant::Neutral)
                    .control_size(ControlSize::Large)
                    .on_press(|s: &mut App| s.retry())
                    .build(k),
            ),
    )
}

fn unlock(s: &App, k: &Kit) -> El {
    let vaults = s.status.as_ref().map_or(0, |st| st.vaults.len());
    let about = match (device_name(s), vaults) {
        (Some(name), 0) => format!("Locked · {name}"),
        (Some(name), n) => format!(
            "Locked · {name} · {n} vault{}",
            if n == 1 { "" } else { "s" }
        ),
        (None, _) => "Locked. Enter your passphrase to unlock this device.".into(),
    };
    let mut body = col()
        .key("body")
        .w_full()
        .gap(12.0)
        .child(muted(k, "about", about))
        .child(passphrase_field(s, k))
        .children(unlock_error(s, k));
    let label = if s.unlocking {
        "Unlocking…"
    } else {
        "Unlock"
    };
    let unlock_button = Button::new(label)
        .variant(ButtonVariant::Contrast)
        .control_size(ControlSize::Large)
        .disabled(s.unlocking || s.passphrase.text.is_empty())
        .on_press(|s: &mut App| s.submit_unlock())
        .build(k)
        .key("unlock");
    body = match touch_id_button(s, k) {
        Some(touch_id) => body.child(
            row()
                .key("actions")
                .w_full()
                .gap(8.0)
                .center_y()
                .mt(4.0)
                .motion(k.motion.control)
                .child(unlock_button.grow(1.0))
                .child(touch_id.grow(1.0)),
        ),
        None => body.child(unlock_button.mt(4.0)),
    };
    col().key("unlock").center().child(
        col()
            .key("panel")
            .w(320.0)
            .gap(20.0)
            .items_start()
            .child(crate::onboarding::view::wordmark(k, 28.0))
            .child(body),
    )
}

/// The passphrase field: dots, Enter unlocks, typing clears the last error.
/// In the quick panel, Escape closes the panel rather than blurring the field.
pub(crate) fn passphrase_field(s: &App, k: &Kit) -> El {
    TextInput::new(&s.passphrase)
        .placeholder("Passphrase")
        .large()
        .width(None)
        .invalid(s.unlock_error.is_some())
        .disabled(s.unlocking)
        .on_edit(|s: &mut App| &mut s.passphrase)
        .on_key(|s: &mut App, ev, tx| s.panel_shortcut(ev, tx) || s.panel_escape(ev, tx))
        .on_change(|s: &mut App, _| s.passphrase_changed())
        .on_submit(|s: &mut App, _| s.submit_unlock())
        .build(k)
        .key("passphrase")
}

/// Use Touch ID when a biometric slot is ready on this lock screen.
pub(crate) fn touch_id_button(s: &App, k: &Kit) -> Option<El> {
    s.touch_id_ready().then(|| {
        let label = if s.touch_id_unlocking {
            "Touch ID…"
        } else {
            "Use Touch ID"
        };
        Button::new(label)
            .variant(ButtonVariant::Neutral)
            .control_size(ControlSize::Large)
            .disabled(s.busy_unlocking())
            .on_press(|s: &mut App| s.unlock_touch_id())
            .build(k)
            .key("touch-id")
    })
}

/// Shown when the enrolled Touch ID slot was wiped (expired, fingerprint set
/// changed, or passphrase changed).
pub const TOUCH_ID_RESET: &str = "Touch ID was reset; enter your passphrase.";

/// Shown when Touch ID is enabled in `config.toml` before a biometric slot has
/// ever been enrolled.
pub const TOUCH_ID_FINISH_SETUP: &str = "Enter your passphrase once to finish turning on Touch ID.";

pub(crate) fn unlock_error(s: &App, k: &Kit) -> Option<El> {
    let (key, msg, ink) = if let Some(e) = &s.unlock_error {
        ("error", e.as_str(), k.c.danger.fg)
    } else if s.touch_id_reset() {
        ("touch-id-reset", TOUCH_ID_RESET, k.c.text_muted)
    } else if s.touch_id_enabled() && !s.touch_id_ready() {
        ("touch-id-finish", TOUCH_ID_FINISH_SETUP, k.c.text_muted)
    } else {
        return None;
    };
    Some(
        text(msg.to_owned())
            .key(key)
            .font(k.ty.text_small)
            .color(ink)
            .wrap()
            .w_full()
            .transition(Transition::opacity()),
    )
}

// -------------------------------------------------------------------------------------------
// Shared builders across the vault, quick panel, Settings, edit and import views.

pub(crate) fn device_name(s: &App) -> Option<&str> {
    s.status
        .as_ref()
        .and_then(|st| st.device.as_ref())
        .and_then(|d| d.name.as_deref())
}

pub(crate) fn vault_name<'a>(s: &'a App, fallback: &'a str) -> &'a str {
    s.status
        .as_ref()
        .and_then(|st| st.vaults.iter().find(|v| v.default).or(st.vaults.first()))
        .map_or(fallback, |v| v.name.as_str())
}

pub(crate) fn search_placeholder(s: &App) -> String {
    match s.items.len() {
        1 => "Search 1 item".to_owned(),
        n => format!("Search {n} items"),
    }
}

/// A vertical scroll viewport with edge fade over hidden content.
pub(crate) fn scroll_col(key: &str) -> El {
    col()
        .key(key)
        .scroll(ScrollSpec {
            stick_bottom: false,
        })
        .scroll_edge_fade(LIST_EDGE)
}

/// A floating status pill that rises in and leaves the same way.
pub(crate) fn status_pill(k: &Kit, key: &str, pill: El) -> El {
    let pill = pill
        .key(key)
        .role("status")
        .w(NOTICE_W)
        .self_center()
        .padding(12.0)
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .transition(rise());
    k.elevate(pill, &k.elevation.floating)
}

/// Show/Hide icon button for a secret field.
pub(crate) fn reveal_button(k: &Kit, noun: &str, revealed: bool) -> IconButton {
    let glyph = if revealed {
        k.glyph.eye_off
    } else {
        k.glyph.eye
    };
    IconButton::new(glyph)
        .variant(IconButtonVariant::GhostMuted)
        .label(if revealed {
            format!("Hide {noun}")
        } else {
            format!("Show {noun}")
        })
}

/// Shown fields of `full`, each paired with whether it's the item's active one-time code field.
pub(crate) fn item_fields(full: &ItemInfo) -> impl Iterator<Item = (&FieldInfo, bool)> {
    let code = code_field(&full.fields);
    full.fields
        .iter()
        .enumerate()
        .filter(|(_, f)| shown(&full.kind, &f.name))
        .map(move |(i, f)| (f, code == Some(i)))
}

/// Fixed 12-bullet secure mask without copying any secret value into the tree.
pub(crate) fn masked_secret() -> El {
    text("•").secure()
}

/// A key and what it does, for the hint bars.
pub(crate) fn hint(k: &Kit, key: &str, keys: &[&str], label: &str) -> El {
    row()
        .key(key)
        .gap(6.0)
        .center_y()
        .child(Keybind::new(keys).build(k))
        .child(
            text(label.to_owned())
                .font(k.ty.small)
                .color(k.c.text_muted),
        )
}

/// `⇧⏎ Username` and `⌥⏎ Code` hints for the selected item.
pub(crate) fn extra_copy_hints(s: &App, k: &Kit) -> Vec<El> {
    let mut hints = Vec::new();
    if s.has_username() {
        hints.push(hint(k, "h-user", &["⇧", "⏎"], "Username").transition(Transition::opacity()));
    }
    if has_code(s) {
        hints.push(hint(k, "h-code", &["⌥", "⏎"], "Code").transition(Transition::opacity()));
    }
    hints
}

/// What a copy says, in one label that rolls only the characters that
/// change: what ⏎ does ("Copy password", the panel's footer), then "Copied,
/// clears in 0:30" counting down, then "Clipboard cleared". A failed copy
/// says why on its own line, swapped by replacement; `wrap` lets it wrap (the
/// vault's notice). Shared by that notice and the quick panel's footer; `key`
/// names the line, so each keeps its own roll.
pub(crate) fn copy_line(k: &Kit, key: &str, copy: Option<&Copy>, does: &str, wrap: bool) -> El {
    if let Some(error) = copy.and_then(|c| c.error.as_ref()) {
        let message = text(error.clone())
            .font(k.ty.text_small)
            .color(k.c.danger.fg);
        let line = row().key("failed").transition(replace());
        return if wrap {
            line.w_full().child(message.wrap().w_full())
        } else {
            line.shrink().child(message.truncate())
        };
    }
    let check = |ink| {
        icon(k.glyph.check_small, 16.0)
            .key("check")
            .color(ink)
            .transition(replace())
    };
    let (lead, label, ink) = match copy {
        None => (
            Keybind::new(&["⏎"])
                .build(k)
                .key("enter")
                .transition(replace()),
            does.to_owned(),
            k.c.text_base,
        ),
        Some(copy) if copy.cleared_at.is_some() => (
            check(k.c.icon_muted),
            "Clipboard cleared".to_owned(),
            k.c.text_muted,
        ),
        Some(copy) => {
            let left = copy.shown;
            (
                check(k.c.icon_base),
                format!("Copied, clears in {}:{:02}", left / 60, left % 60),
                k.c.text_base,
            )
        }
    };
    row()
        .key(key)
        .gap(8.0)
        .center_y()
        .transition(replace())
        .child(lead)
        .child(
            RollingText::new(format!("{key}-label"), label)
                .font(tnum(k.ty.small))
                .color(ink)
                .from(Edge::Top)
                .build(k),
        )
}
