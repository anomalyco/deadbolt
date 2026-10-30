//! Drawing first run: the welcome, the two forms, inline notices, and the
//! empty-vault guide; `ceremony` draws progress, the pairing code, and the
//! moment the vault is ready.
//!
//! Motion: steps swap with the app's whole-state replacement, except progress
//! and its result, which share one panel so the bolt can throw. Hints swap in
//! place under their fields. Reduced motion drops the travel and keeps the
//! fades (Rune's runtime).

use rune::{
    Color, Cursor, El, Icon, ScrollSpec, Shadow, TextEdit, TextStyle, Transition, col, el, icon,
    row, text,
};
use rune_kit::{Button, ButtonVariant, ControlSize, IconButton, IconButtonVariant, Kit, TextInput};

use super::{Flow, Step, Strength};
use crate::model::App;
use crate::view::{Paged, banner};

pub(crate) const PANEL_W: f32 = 400.0;

pub static CHEVRON_LEFT: Icon = Icon {
    name: "deadbolt-chevron-left",
    view: 16.0,
    body: r#"<path d="M10 3.5L5.5 8l4.5 4.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#,
};
pub static CHEVRON_RIGHT: Icon = Icon {
    name: "deadbolt-chevron-right",
    view: 16.0,
    body: r#"<path d="M6 3.5L10.5 8 6 12.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#,
};
pub static PLUS: Icon = Icon {
    name: "deadbolt-plus",
    view: 16.0,
    body: r#"<path d="M8 3v10M3 8h10" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#,
};
pub static DEVICES: Icon = Icon {
    name: "deadbolt-devices",
    view: 16.0,
    body: r#"<rect x="1.75" y="3" width="9" height="6.5" rx="1" stroke="currentColor" stroke-width="1.25"/><path d="M4 12.5h4.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/><rect x="11.5" y="5.5" width="3" height="7.5" rx=".75" stroke="currentColor" stroke-width="1.25"/>"#,
};
pub fn screen(s: &App, k: &Kit, dark: bool) -> Paged {
    let o = &s.onboarding;
    match &o.step {
        Step::Welcome => welcome(s, k),
        Step::Create => form(s, k, Flow::Create),
        Step::Join => form(s, k, Flow::Join),
        Step::Working(flow) | Step::Done { flow, .. } => {
            super::ceremony::progress(s, k, dark, *flow)
        }
        Step::Code => super::ceremony::code(s, k),
    }
}

pub(crate) fn muted(k: &Kit, key: &str, s: impl Into<String>) -> El {
    text(s.into())
        .key(key)
        .font(k.ty.text_small)
        .color(k.c.text_muted)
        .wrap()
        .w_full()
}

pub(crate) fn title(k: &Kit, key: &str, s: impl Into<String>) -> El {
    text(s.into())
        .key(key)
        .font(TextStyle::new(17.0, 500.0).lh(22.0))
        .color(k.c.text_strong)
}

/// A step: the panel centred in the page, with an optional button in the
/// title bar. A panel taller than the page scrolls.
pub(crate) fn page(key: &str, bar: Option<El>, panel: El) -> Paged {
    let body = col()
        .key("page-scroll")
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .scroll(ScrollSpec {
            stick_bottom: false,
        })
        .child(col().w_full().grow(1.0).center().py(16.0).child(panel));
    Paged {
        body: col().key(key).w_full().h_full().child(body),
        back: bar,
    }
}

/// A button for the title bar: Back or Cancel.
pub(crate) fn bar(k: &Kit, label: &str, glyph: &'static Icon, press: fn(&mut App)) -> El {
    Button::new(label)
        .variant(ButtonVariant::Ghost)
        .control_size(ControlSize::Large)
        .icon(glyph)
        .on_press(press)
        .build(k)
        .key("back")
}

/// A floating vault notice with a primary action and "Not now" (`install`, `shortcut`).
pub(crate) fn offer_card(
    k: &Kit,
    key: &str,
    head: impl Into<String>,
    (body_key, body): (&str, impl Into<String>),
    (action_key, action_label, on_action): (&str, &str, fn(&mut App)),
    on_dismiss: fn(&mut App),
) -> El {
    let card = crate::view::status_pill(k, key, col().gap(10.0));
    card.child(
        col()
            .key("text")
            .w_full()
            .gap(2.0)
            .child(
                text(head.into())
                    .font(k.ty.ui_medium)
                    .color(k.c.text_strong)
                    .wrap()
                    .w_full(),
            )
            .child(muted(k, body_key, body)),
    )
    .child(
        row()
            .key("actions")
            .gap(8.0)
            .child(
                Button::new(action_label)
                    .variant(ButtonVariant::Neutral)
                    .control_size(ControlSize::Large)
                    .on_press(on_action)
                    .build(k)
                    .key(action_key),
            )
            .child(
                Button::new("Not now")
                    .variant(ButtonVariant::Ghost)
                    .control_size(ControlSize::Large)
                    .on_press(on_dismiss)
                    .build(k)
                    .key("dismiss"),
            ),
    )
}

// -------------------------------------------------------------------------------------------
// Welcome

fn welcome(s: &App, k: &Kit) -> Paged {
    let o = &s.onboarding;
    let about = if o.device_ready {
        "This device is set up but holds no vault yet. Create one, or join yours from another device."
    } else {
        "A password manager with no server. Your devices hold the vault and sync with each other directly."
    };
    let mut panel = col()
        .key("panel")
        .w(PANEL_W)
        .items_start()
        .child(wordmark(k, 40.0))
        .child(muted(k, "about", about).mt(12.0));
    if let Some(n) = &o.notice {
        panel = panel.child(banner(k, n).mt(24.0));
    }
    panel = panel.child(
        col()
            .key("choices")
            .w_full()
            .gap(8.0)
            .mt(28.0)
            .child(choice(
                k,
                "create",
                &PLUS,
                "Create a vault",
                "Start fresh on this device.",
                Flow::Create,
            ))
            .child(choice(
                k,
                "join",
                &DEVICES,
                "Join from another device",
                "Your vault is already on another device.",
                Flow::Join,
            )),
    );
    page("welcome", None, panel)
}

/// The name, set in the theme's sans, tight, for the lock and welcome screens.
pub fn wordmark(k: &Kit, size: f32) -> El {
    text("Deadbolt")
        .key("wordmark")
        .role("heading")
        .label("Deadbolt")
        .font(
            TextStyle::new(size, 600.0)
                .lh((size * 1.15).round())
                .tracking(-size * 0.03),
        )
        .color(k.c.text_strong)
}

fn choice(k: &Kit, key: &str, glyph: &'static Icon, label: &str, sub: &str, flow: Flow) -> El {
    let mut card = row()
        .key(key)
        .role("button")
        .label(label.to_owned())
        .focusable(true)
        .w_full()
        .px(14.0)
        .py(12.0)
        .gap(12.0)
        .center_y()
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .hover(k.c.hover)
        .press(k.c.pressed)
        .cursor(Cursor::Pointer)
        .on_press(move |s: &mut App| s.choose(flow))
        .child(
            row()
                .key("glyph")
                .size(32.0, 32.0)
                .center()
                .radius(k.radius.md)
                .fill(k.c.layer_02)
                .child(icon(glyph, 16.0).color(k.c.icon_base)),
        )
        .child(
            col()
                .key("words")
                .grow(1.0)
                .shrink()
                .gap(2.0)
                .child(
                    text(label.to_owned())
                        .font(k.ty.ui_medium)
                        .color(k.c.text_strong),
                )
                .child(
                    text(sub.to_owned())
                        .font(k.ty.text_small)
                        .color(k.c.text_muted)
                        .wrap()
                        .w_full(),
                ),
        )
        .child(icon(&CHEVRON_RIGHT, 16.0).key("go").color(k.c.icon_muted));
    for s in k.shadow_layers(&k.elevation.raised) {
        card = card.box_shadow(s);
    }
    card
}

// -------------------------------------------------------------------------------------------
// The forms

fn form(s: &App, k: &Kit, flow: Flow) -> Paged {
    let o = &s.onboarding;
    let device = !o.device_ready;
    let (key, heading, about, submit) = match (flow, device) {
        (Flow::Create, true) => (
            "create",
            "Create a vault",
            "Pick a passphrase for this device. There's no reset, so make it one you'll remember.",
            "Create vault",
        ),
        (Flow::Create, false) => (
            "create",
            "Create a vault",
            "This device is set up. Name the new vault.",
            "Create vault",
        ),
        (Flow::Join, true) => (
            "join",
            "Join from another device",
            "This device gets its own passphrase. There's no reset, so make it one you'll remember.",
            "Continue",
        ),
        (Flow::Join, false) => (
            "join",
            "Join from another device",
            "This device is set up. Make a code, then type it on a device that has your vault.",
            "Make a pairing code",
        ),
    };
    let mut panel = col().key("panel").w(PANEL_W).gap(16.0).items_start().child(
        col()
            .key("head")
            .w_full()
            .gap(6.0)
            .child(title(k, "title", heading))
            .child(muted(k, "about", about)),
    );
    if let Some(n) = &o.notice {
        panel = panel.child(banner(k, n));
    }
    let mut names = row().key("names").w_full().gap(12.0).items_start();
    if device {
        names = names.child(device_field(s, k, flow));
    }
    if flow == Flow::Create {
        names = names.child(vault_field(s, k));
    }
    if device || flow == Flow::Create {
        panel = panel.child(names);
    }
    if device {
        panel = panel
            .child(passphrase_field(s, k, flow))
            .child(repeat_field(s, k, flow));
    }
    panel = panel.child(
        Button::new(submit)
            .variant(ButtonVariant::Contrast)
            .control_size(ControlSize::Large)
            .on_press(move |s: &mut App| s.submit_onboarding(flow))
            .build(k)
            .key("submit")
            .mt(4.0),
    );
    page(
        key,
        Some(bar(k, "Back", &CHEVRON_LEFT, |s| s.onboarding_back())),
        panel,
    )
}

/// A labelled field with an optional hint line under it.
fn labelled(k: &Kit, key: &str, label: &str, input: El, hint: Option<El>) -> El {
    let mut field = col()
        .key(key)
        .w_full()
        .grow(1.0)
        .shrink()
        .gap(6.0)
        .child(
            text(label.to_owned())
                .key("label")
                .font(k.ty.text_small_medium)
                .color(k.c.text_muted),
        )
        .child(input);
    if let Some(hint) = hint {
        field = field.child(hint);
    }
    field
}

/// One line under a field. Its key names what it says, so a new message
/// replaces the old in place.
fn hint(k: &Kit, key: &str, ink: Color, words: impl Into<String>) -> El {
    row()
        .key(key.to_owned())
        .w_full()
        .min_h(16.0)
        .gap(6.0)
        .center_y()
        .transition(Transition::opacity())
        .child(
            text(words.into())
                .font(k.ty.text_xsmall)
                .color(ink)
                .wrap()
                .w_full(),
        )
}

fn device_field(s: &App, k: &Kit, flow: Flow) -> El {
    let o = &s.onboarding;
    let problem = o.device_problem().filter(|_| o.attempted);
    let input = TextInput::new(&o.device)
        .placeholder("This device")
        .large()
        .width(None)
        .invalid(problem.is_some())
        .on_edit(|s: &mut App| &mut s.onboarding.device)
        .on_change(|s: &mut App, _| s.onboarding.device_edited = true)
        .on_key(super::key)
        .on_submit(move |s: &mut App, _| s.advance_onboarding(flow))
        .build(k)
        .key("device-input");
    let hint = problem.map(|p| hint(k, "device-problem", k.c.danger.fg, p));
    labelled(k, "device", "This device", input, hint)
}

fn vault_field(s: &App, k: &Kit) -> El {
    let o = &s.onboarding;
    let typed = !o.vault.text.trim().is_empty();
    let problem = o.vault_problem().filter(|_| typed || o.attempted);
    let input = TextInput::new(&o.vault)
        .placeholder("personal")
        .large()
        .width(None)
        .invalid(problem.is_some())
        .on_edit(|s: &mut App| &mut s.onboarding.vault)
        .on_key(super::key)
        .on_submit(|s: &mut App, _| s.advance_onboarding(Flow::Create))
        .build(k)
        .key("vault-input");
    let hint = problem.map(|p| hint(k, "vault-problem", k.c.danger.fg, p));
    labelled(k, "vault", "Vault", input, hint)
}

fn passphrase_field(s: &App, k: &Kit, flow: Flow) -> El {
    let o = &s.onboarding;
    let strength = o.strength();
    let short = strength == Strength::TooShort;
    let input = TextInput::new(&o.passphrase)
        .placeholder("Passphrase")
        .large()
        .width(None)
        .invalid(o.attempted && short)
        .on_edit(|s: &mut App| &mut s.onboarding.passphrase)
        .on_key(super::key)
        .on_submit(move |s: &mut App, _| {
            if s.onboarding.repeat_matches() == Some(true) {
                s.submit_onboarding(flow);
            } else {
                s.onboarding.passphrase.focused = false;
                s.onboarding.repeat.focused = true;
            }
        })
        .build(k)
        .key("passphrase-input");
    labelled(
        k,
        "passphrase",
        "Passphrase",
        input,
        Some(strength_hint(k, &o.passphrase, strength, o.attempted)),
    )
}

/// A three-step meter and a word. The line is always there, so typing never
/// moves the fields below it.
fn strength_hint(k: &Kit, passphrase: &TextEdit, strength: Strength, attempted: bool) -> El {
    let (filled, ink, words) = match strength {
        Strength::TooShort if passphrase.text.is_empty() && !attempted => {
            (0, k.c.text_faint, "At least 8 characters.")
        }
        Strength::TooShort if attempted => (0, k.c.danger.fg, "Too short: at least 8 characters."),
        Strength::TooShort => (0, k.c.text_faint, "Too short: at least 8 characters."),
        Strength::Weak => (1, k.c.danger.fg, "Weak. Add a word or two."),
        Strength::Fair => (2, k.c.text_base, "Fair. One more word makes it strong."),
        Strength::Strong => (3, k.c.text_strong, "Strong."),
    };
    let label_ink = if strength == Strength::Weak {
        k.c.danger.fg
    } else if strength == Strength::TooShort {
        ink
    } else {
        k.c.text_muted
    };
    let meter = row()
        .key("meter")
        .w(72.0)
        .h(3.0)
        .gap(3.0)
        .children((0..3).map(|i| {
            el().key(format!("seg{i}"))
                .grow(1.0)
                .h(3.0)
                .radius(1.5)
                .fill(if i < filled { ink } else { k.c.layer_03 })
        }));
    row()
        .key("strength")
        .w_full()
        .h(16.0)
        .gap(10.0)
        .center_y()
        .child(meter)
        .child(
            text(words)
                .key("words")
                .font(k.ty.text_xsmall)
                .color(label_ink),
        )
}

fn repeat_field(s: &App, k: &Kit, flow: Flow) -> El {
    let o = &s.onboarding;
    let matches = o.repeat_matches();
    let input = TextInput::new(&o.repeat)
        .placeholder("Passphrase again")
        .large()
        .width(None)
        .invalid(matches == Some(false))
        .on_edit(|s: &mut App| &mut s.onboarding.repeat)
        .on_key(super::key)
        .on_submit(move |s: &mut App, _| s.submit_onboarding(flow))
        .build(k)
        .key("repeat-input");
    let line = match matches {
        Some(true) => row()
            .key("matches")
            .w_full()
            .h(16.0)
            .gap(6.0)
            .center_y()
            .transition(Transition::blur_replace())
            .child(icon(k.glyph.check_small, 14.0).color(k.c.icon_base))
            .child(text("Matches").font(k.ty.text_xsmall).color(k.c.text_muted)),
        Some(false) => hint(
            k,
            "mismatch",
            k.c.danger.fg,
            "Doesn't match the passphrase.",
        ),
        None => hint(k, "type-again", k.c.text_faint, "Type it again to be sure."),
    };
    labelled(k, "repeat", "Repeat passphrase", input, Some(line))
}

// -------------------------------------------------------------------------------------------
// The empty vault

const ADD: &str = "deadbolt new login url=github.com username=you";

/// What to do with a vault that has nothing in it yet: import an export
/// here, or add a login in the CLI for now.
pub fn empty_vault(s: &App, k: &Kit) -> El {
    let vault = s
        .status
        .as_ref()
        .and_then(|st| st.vaults.iter().find(|v| v.default).or(st.vaults.first()))
        .map_or("Your vault".to_owned(), |v| v.name.clone());
    col()
        .key("guide")
        .w_full()
        .gap(20.0)
        .transition(Transition::opacity())
        .child(
            text(format!("{vault} is empty"))
                .key("title")
                .font(TextStyle::new(20.0, 500.0).lh(26.0))
                .color(k.c.text_strong),
        )
        .child(crate::import::view::drop_zone(s, k))
        .children(crate::import::view::error(s, k))
        .child(command(
            s,
            k,
            "add",
            "Add a login",
            ADD,
            Some("In a terminal, for now."),
        ))
        .child(
            col()
                .key("devices")
                .w_full()
                .gap(4.0)
                .child(
                    text("Add a device")
                        .key("label")
                        .font(k.ty.text_small_medium)
                        .color(k.c.text_muted),
                )
                .child(muted(
                    k,
                    "how",
                    "Open Deadbolt on it, choose Join from another device, and run the command it shows here.",
                )),
        )
}

fn command(s: &App, k: &Kit, key: &str, label: &str, line: &'static str, note: Option<&str>) -> El {
    let copied =
        s.onboarding.copied_command.as_ref().is_some_and(|(c, at)| {
            *c == line && at.is_none_or(|at| s.clock - at < super::COPIED_FOR)
        });
    let mut block = col()
        .key(key)
        .w_full()
        .gap(6.0)
        .child(
            text(label.to_owned())
                .key("label")
                .font(k.ty.text_small_medium)
                .color(k.c.text_muted),
        )
        .child(
            row()
                .key("line")
                .w_full()
                .min_h(36.0)
                .pl(12.0)
                .pr(4.0)
                .gap(8.0)
                .center_y()
                .radius(k.radius.md)
                .fill(k.c.layer_01)
                .box_shadow(Shadow {
                    spread: 0.5,
                    color: k.c.border_base,
                    ..Shadow::default()
                })
                .child(
                    text(line)
                        .key("text")
                        .font(k.ty.text_small)
                        .color(k.c.text_base)
                        .truncate_fade()
                        .grow(1.0),
                )
                .child(
                    IconButton::new(if copied {
                        k.glyph.check_small
                    } else {
                        k.glyph.copy
                    })
                    .variant(IconButtonVariant::GhostMuted)
                    .label(if copied { "Copied" } else { "Copy" })
                    .on_press_tx(move |s: &mut App, tx| s.copy_command(line, tx))
                    .build(k)
                    .key(if copied { "copied" } else { "copy" })
                    .transition(Transition::blur_replace()),
                ),
        );
    if let Some(note) = note {
        block = block.child(
            text(note.to_owned())
                .key("note")
                .font(k.ty.text_xsmall)
                .color(k.c.text_faint)
                .wrap()
                .w_full(),
        );
    }
    block
}
