//! Drawing first run: the welcome, the two forms, progress, the pairing ticket
//! and code, and the moment the vault is ready.
//!
//! Motion: steps swap with the app's whole-state replacement, except progress
//! and its result, which share one panel so the bolt can throw. The bolt's
//! throw is the one spring with bounce (`THROW`); the strike it lands in
//! flashes hot on contact and cools through red to rest (instant attack,
//! convex decay). Hints swap in place under their fields. Reduced motion
//! drops the travel and keeps the fades (Rune's runtime).

use rune::{
    Color, Cursor, Curve, Cycle, Easing, El, Icon, Shadow, Spring, TextEdit, TextStyle, Transition,
    canvas, col, el, icon, row, text,
};
use rune_kit::{
    Button, ButtonVariant, ControlSize, IconButton, IconButtonVariant, Kit, StateColors, TextInput,
};

use super::worker::Stage;
use super::{Flow, Notice, Severity, Step, Strength};
use crate::model::App;
use crate::theme;

pub(crate) const PANEL_W: f32 = 400.0;
/// The bolt's throw: the one sanctioned flourish (Kit's "playful", .3 / .3).
const THROW: Spring = Spring::new(0.3, 0.3);

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
pub static CAUTION: Icon = Icon {
    name: "deadbolt-caution",
    view: 16.0,
    body: r#"<path d="M8 2.25L14.25 13.25H1.75Z" stroke="currentColor" stroke-width="1.25" stroke-linejoin="round"/><path d="M8 6.5v3" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/><circle cx="8" cy="11.4" r=".8" fill="currentColor"/>"#,
};
pub static INFO: Icon = Icon {
    name: "deadbolt-info",
    view: 16.0,
    body: r#"<circle cx="8" cy="8" r="6.25" stroke="currentColor" stroke-width="1.25"/><path d="M8 7.25v4" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/><circle cx="8" cy="4.9" r=".8" fill="currentColor"/>"#,
};

pub fn screen(s: &App, k: &Kit, dark: bool) -> El {
    let o = &s.onboarding;
    match &o.step {
        Step::Welcome => welcome(s, k),
        Step::Create => form(s, k, Flow::Create),
        Step::Join => form(s, k, Flow::Join),
        Step::Working(flow) => progress(s, k, dark, *flow),
        Step::Done { flow, .. } => progress(s, k, dark, *flow),
        Step::Ticket => ticket(s, k),
        Step::Confirm {
            code,
            vault,
            inviter,
        } => confirm(k, code, vault, inviter),
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

/// A step: the panel centred in the window, with an optional button over
/// the top-left corner, so the panel has the window's whole height.
pub(crate) fn page(key: &str, bar: Option<El>, panel: El) -> El {
    let mut page = col().key(key).w_full().h_full().center().child(panel);
    if let Some(bar) = bar {
        page = page.child(bar);
    }
    page
}

pub(crate) fn bar(k: &Kit, label: &str, glyph: &'static Icon, press: fn(&mut App)) -> El {
    row().key("bar").absolute(12.0, 12.0).child(
        Button::new(label)
            .variant(ButtonVariant::Ghost)
            .control_size(ControlSize::Large)
            .icon(glyph)
            .on_press(press)
            .build(k)
            .key("back"),
    )
}

// -------------------------------------------------------------------------------------------
// Welcome

fn welcome(s: &App, k: &Kit) -> El {
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
        .child(wordmark(k, 64.0))
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

pub fn wordmark(k: &Kit, size: f32) -> El {
    text("DEADBOLT")
        .key("wordmark")
        .role("heading")
        .label("Deadbolt")
        .font(theme::wordmark(size))
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

/// A notice in place, coloured by how serious it is: a dim tint and border,
/// with full colour kept for the icon and title.
pub fn banner(k: &Kit, n: &Notice) -> El {
    let neutral = StateColors {
        bg: k.c.layer_01,
        fg: k.c.text_strong,
        border: k.c.border_base,
        icon: k.c.icon_muted,
    };
    let (tone, glyph) = match n.severity {
        Severity::Neutral => (neutral, &INFO),
        Severity::Caution => (k.c.warning, &CAUTION),
        Severity::Danger => (k.c.danger, k.glyph.circle_x),
    };
    row()
        .key("notice")
        .role("alert")
        .w_full()
        .padding(12.0)
        .gap(10.0)
        .radius(k.radius.md)
        .fill(tone.bg)
        .box_shadow(Shadow {
            spread: 1.0,
            color: tone.border,
            ..Shadow::default()
        })
        .transition(Transition::opacity())
        .child(icon(glyph, 16.0).key("icon").color(tone.icon).mt(2.0))
        .child(
            col()
                .key("words")
                .grow(1.0)
                .shrink()
                .gap(2.0)
                .child(
                    text(n.title.clone())
                        .key("title")
                        .font(k.ty.ui_medium)
                        .color(tone.fg)
                        .wrap()
                        .w_full(),
                )
                .child(muted(k, "body", n.body.clone())),
        )
}

// -------------------------------------------------------------------------------------------
// The forms

fn form(s: &App, k: &Kit, flow: Flow) -> El {
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
            "This device is set up. Make a ticket, then pair from a device that has your vault.",
            "Make a pairing ticket",
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
        names = names.child(device_field(s, k));
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
    let press: fn(&mut App) = match flow {
        Flow::Create => |s| s.submit_create(),
        Flow::Join => |s| s.submit_join(),
    };
    panel = panel.child(
        Button::new(submit)
            .variant(ButtonVariant::Contrast)
            .control_size(ControlSize::Large)
            .on_press(press)
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

fn submit_for(flow: Flow) -> fn(&mut App, &mut rune::Tx) {
    match flow {
        Flow::Create => |s, _| s.submit_create(),
        Flow::Join => |s, _| s.submit_join(),
    }
}

fn device_field(s: &App, k: &Kit) -> El {
    let o = &s.onboarding;
    let problem = o.device_problem().filter(|_| o.attempted);
    let input = TextInput::new(&o.device)
        .placeholder("This device")
        .large()
        .width(None)
        .invalid(problem.is_some())
        .on_edit(|s: &mut App| &mut s.onboarding.device)
        .on_key(|s: &mut App, ev, tx| super::key(s, ev, tx))
        .on_submit(|s: &mut App, _| s.onboarding.passphrase.focused = true)
        .build(k)
        .key("device-input");
    let hint = problem.map(|p| hint(k, "device-problem", k.c.danger.fg, p));
    labelled(k, "device", "This device", input, hint)
}

fn vault_field(s: &App, k: &Kit) -> El {
    let o = &s.onboarding;
    let typed = !o.vault.text.trim().is_empty();
    let problem = o.vault_problem().filter(|_| typed || o.attempted);
    let submit = if o.device_ready {
        submit_for(Flow::Create)
    } else {
        |s: &mut App, _: &mut rune::Tx| s.onboarding.passphrase.focused = true
    };
    let input = TextInput::new(&o.vault)
        .placeholder("personal")
        .large()
        .width(None)
        .invalid(problem.is_some())
        .on_edit(|s: &mut App| &mut s.onboarding.vault)
        .on_key(|s: &mut App, ev, tx| super::key(s, ev, tx))
        .on_submit(submit)
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
        .on_submit(move |s: &mut App, tx| {
            if s.onboarding.repeat_matches() == Some(true) {
                submit_for(flow)(s, tx);
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
        .on_submit(move |s: &mut App, tx| submit_for(flow)(s, tx))
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
// Progress and the moment

fn progress(s: &App, k: &Kit, dark: bool, flow: Flow) -> El {
    let o = &s.onboarding;
    let done = matches!(o.step, Step::Done { .. });
    let vault = o.vault.text.trim();
    let (heading, about) = match (&o.step, flow) {
        (Step::Done { vault, from, .. }, Flow::Join) => (
            format!("Joined {vault}"),
            match from {
                Some(from) => format!("Synced from {from}. Opening it now."),
                None => "Opening it now.".to_owned(),
            },
        ),
        (Step::Done { vault, .. }, Flow::Create) => {
            ("Vault created".to_owned(), format!("Opening {vault} now."))
        }
        (_, Flow::Create) => (
            "Creating your vault".to_owned(),
            "It lives on this device, encrypted with your passphrase.".to_owned(),
        ),
        // Cancelled while the device was being set up: that finishes first.
        (_, Flow::Join) if o.stopping() => (
            "Stopping".to_owned(),
            if o.stage == Some(Stage::Protecting) {
                "This device finishes setting up with the passphrase you chose, then the \
                 join stops."
            } else {
                "Nothing was shared."
            }
            .to_owned(),
        ),
        (_, Flow::Join) => match &o.pairing {
            Some(p) => (
                format!("Joining {}", p.vault),
                format!("Receiving it from {}.", p.inviter),
            ),
            None => (
                "Getting ready to pair".to_owned(),
                "Then you'll see a ticket to use on your other device.".to_owned(),
            ),
        },
    };
    let mut steps = col().key("steps").w_full().gap(10.0);
    let at = o
        .stage
        .and_then(|st| o.plan.iter().position(|p| *p == st))
        .unwrap_or(0);
    for (i, stage) in o.plan.iter().enumerate() {
        let state = if done || i < at {
            Mark::Done
        } else if i == at {
            Mark::Active
        } else {
            Mark::Pending
        };
        steps = steps.child(step_row(k, *stage, state, vault, o.pairing.as_ref()));
    }
    let panel = col()
        .key("panel")
        .w(PANEL_W)
        .gap(24.0)
        .items_start()
        .child(bolt(k, dark, done, o.phase))
        .child(
            col()
                .key("head")
                .w_full()
                .gap(6.0)
                .child(
                    title(k, &format!("title-{heading}"), heading)
                        .transition(Transition::blur_replace()),
                )
                .child(
                    muted(k, &format!("about-{about}"), about)
                        .transition(Transition::blur_replace()),
                ),
        )
        .child(steps);
    let key = match flow {
        Flow::Create => "progress-create",
        Flow::Join => "progress-join",
    };
    // Getting a ticket can wait on a relay; until the codes match, a join can stop.
    let cancel = (flow == Flow::Join && !done && o.pairing.is_none() && !o.stopping())
        .then(|| bar(k, "Cancel", k.glyph.close, |s| s.cancel_join()));
    page(key, cancel, panel)
}

#[derive(Clone, Copy, PartialEq)]
enum Mark {
    Pending,
    Active,
    Done,
}

fn step_row(
    k: &Kit,
    stage: Stage,
    mark: Mark,
    vault: &str,
    pairing: Option<&super::Pairing>,
) -> El {
    let (label, detail) = match stage {
        Stage::Starting => ("Starting Deadbolt".to_owned(), None),
        Stage::Protecting => (
            "Protecting your passphrase".to_owned(),
            Some("Argon2 makes it slow to guess, so this takes a moment."),
        ),
        Stage::CreatingVault => (format!("Creating {vault}"), None),
        Stage::MakingTicket => (
            "Making a pairing ticket".to_owned(),
            Some("Reaching a relay so your other device can find this one."),
        ),
        Stage::Joining => (
            match pairing {
                Some(p) => format!("Receiving {}", p.vault),
                None => "Receiving the vault".to_owned(),
            },
            None,
        ),
    };
    let glyph = match mark {
        Mark::Done => row()
            .key("done")
            .size(16.0, 16.0)
            .center()
            .transition(Transition::blur_replace())
            .child(icon(k.glyph.check_small, 16.0).color(k.c.icon_base)),
        Mark::Active => row()
            .key("active")
            .size(16.0, 16.0)
            .center()
            .transition(Transition::blur_replace())
            .child(
                el().key("dot")
                    .size(6.0, 6.0)
                    .radius(3.0)
                    .fill(k.c.text_strong)
                    .cycle(BREATHE),
            ),
        Mark::Pending => row()
            .key("pending")
            .size(16.0, 16.0)
            .center()
            .transition(Transition::blur_replace())
            .child(el().size(4.0, 4.0).radius(2.0).fill(k.c.text_faint)),
    };
    let ink = match mark {
        Mark::Done => k.c.text_muted,
        Mark::Active => k.c.text_strong,
        Mark::Pending => k.c.text_faint,
    };
    let mut words = col()
        .key("words")
        .grow(1.0)
        .shrink()
        .gap(2.0)
        .child(text(label).key("label").font(k.ty.text_small).color(ink));
    if let (Mark::Active, Some(detail)) = (mark, detail) {
        words = words.child(
            text(detail)
                .key("detail")
                .font(k.ty.text_xsmall)
                .color(k.c.text_faint)
                .wrap()
                .w_full()
                .transition(Transition::opacity()),
        );
    }
    row()
        .key(format!("stage-{stage:?}"))
        .w_full()
        .gap(10.0)
        .items_start()
        .child(glyph.mt(1.0))
        .child(words)
}

/// A slow breath for "working on it". Reduced motion holds it full.
const BREATHE: Cycle = Cycle {
    period: 1.4,
    phase: 0.0,
    stops: &[(0.0, 1.0), (0.5, 0.3), (1.0, 1.0)],
    still: 1.0,
    fps: 30.0,
};

/// Three dots breathing in turn: waiting on someone else.
fn waiting(k: &Kit) -> El {
    const STOPS: &[(f32, f32)] = &[(0.0, 0.25), (0.3, 1.0), (0.6, 0.25), (1.0, 0.25)];
    row()
        .key("dots")
        .gap(4.0)
        .center_y()
        .children((0..3).map(|i| {
            el().key(format!("dot{i}"))
                .size(5.0, 5.0)
                .radius(2.5)
                .fill(k.c.text_muted)
                .cycle(Cycle {
                    period: 1.2,
                    phase: i as f32 * 0.15,
                    stops: STOPS,
                    still: 0.6,
                    fps: 30.0,
                })
        }))
}

/// Geometry of the bolt mark, in points.
mod geo {
    pub const W: f32 = 80.0;
    pub const H: f32 = 52.0;
    pub const BODY: f32 = 52.0;
    pub const BOLT: [f32; 2] = [30.0, 10.0];
    /// The bolt's left edge: drawn back flush inside the body, and thrown
    /// across the gap with its tip in the strike.
    pub const BACK: f32 = 22.0;
    pub const THROWN: f32 = 46.0;
    /// The strike plate the bolt enters.
    pub const STRIKE: [f32; 4] = [70.0, 11.0, 8.0, 30.0];
}

/// The deadbolt: a body and, across a gap, the strike. While work runs the
/// bolt is drawn back inside the body. When the vault is ready it throws
/// across the gap into the strike, which flashes hot on contact and cools
/// through red to rest.
fn bolt(k: &Kit, dark: bool, done: bool, phase: usize) -> El {
    let accent = k.c.text_accent;
    let rest = k.c.layer_03;
    let hot = theme::color(dark, "hot");
    // (strike fill, its colour spring, glow opacity, glow curve) per phase.
    let (strike, spring, glow, curve): (Color, Spring, f32, Curve) = match (done, phase) {
        (false, _) | (true, 0) => (rest, Spring::new(0.3, 0.0), 0.0, Curve::linear(0.1)),
        // Contact: instant attack.
        (true, 1) => (hot, Spring::new(0.06, 0.0), 1.0, Curve::linear(0.05)),
        // Cooling: hot to red quickly; the glow decays fast, then slowly.
        (true, 2) => (
            accent,
            Spring::new(0.3, 0.0),
            0.0,
            Curve::tween(1.1, Easing::cubic(0.0, 0.0, 0.2, 1.0)),
        ),
        // Red to rest.
        (true, _) => (
            rest,
            Spring::new(0.9, 0.0),
            0.0,
            Curve::tween(1.1, Easing::cubic(0.0, 0.0, 0.2, 1.0)),
        ),
    };
    let [sx, sy, sw, sh] = geo::STRIKE;
    let x = if done { geo::THROWN } else { geo::BACK };
    let ring = Shadow {
        spread: 0.5,
        color: k.c.border_base,
        ..Shadow::default()
    };
    el().key("bolt")
        .role("img")
        .label(if done { "Locked" } else { "Unlocked" })
        .size(geo::W, geo::H)
        // Light from the strike, local to it.
        .child(
            el().key("glow")
                .absolute(sx, sy)
                .size(sw, sh)
                .radius(3.0)
                .fill(k.alpha(accent, 0.6))
                .box_shadow(Shadow {
                    blur: 18.0,
                    spread: 3.0,
                    color: k.alpha(accent, 0.8),
                    ..Shadow::default()
                })
                .opacity(glow)
                .opacity_motion(curve),
        )
        // Behind the body, so it slides out of it.
        .child(
            el().key("throw")
                .absolute(x, (geo::H - geo::BOLT[1]) / 2.0)
                .size(geo::BOLT[0], geo::BOLT[1])
                .radius(2.0)
                .fill(k.c.text_strong)
                .motion(THROW),
        )
        .child(
            el().key("body")
                .absolute(0.0, 0.0)
                .size(geo::BODY, geo::BODY)
                .radius(k.radius.lg + 4.0)
                .fill(k.c.layer_02)
                .box_shadow(ring)
                .child(
                    el().key("keyhole")
                        .absolute(22.0, 16.0)
                        .size(8.0, 8.0)
                        .radius(4.0)
                        .fill(k.c.bg_base),
                )
                .child(
                    el().key("slot")
                        .absolute(24.5, 21.0)
                        .size(3.0, 11.0)
                        .radius(1.5)
                        .fill(k.c.bg_base),
                ),
        )
        .child(
            el().key("strike")
                .absolute(sx, sy)
                .size(sw, sh)
                .radius(2.0)
                .fill(strike)
                .box_shadow(ring)
                .motion(spring),
        )
}

// -------------------------------------------------------------------------------------------
// Pairing

fn ticket(s: &App, k: &Kit) -> El {
    let o = &s.onboarding;
    let Some(t) = &o.ticket else {
        return page("ticket", None, col());
    };
    let copied = o.copied.is_some();
    let grouped = t
        .text
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    let mut pair = row().key("pair").gap(36.0).center_y();
    if let Some(qr) = &t.qr {
        // Whole points per module, about 232 points across, with the quiet
        // zone (4 modules) as the tile's padding. Dark on paper in both
        // appearances: scanners want dark modules on light.
        let module = (232.0 / qr.width as f32).floor().clamp(2.0, 6.0);
        let side = module * qr.width as f32;
        pair = pair.child(
            col()
                .key("qr")
                .role("img")
                .label("Pairing ticket as a QR code")
                .padding(module * 4.0)
                .radius(k.radius.lg)
                .fill(theme::color(false, "surface"))
                .box_shadow(Shadow {
                    spread: 0.5,
                    color: k.c.border_base,
                    ..Shadow::default()
                })
                .child(canvas(qr.shape(module, Color::BLACK)).size(side, side)),
        );
    }
    let mut how = col()
        .key("how")
        .w(320.0)
        .shrink()
        .gap(14.0)
        .items_start()
        .child(title(k, "title", "Pair from your other device"))
        .child(muted(
            k,
            "run",
            "On a device that already has your vault, run this command or scan the code.",
        ))
        .child(
            col()
                .key("command")
                .w_full()
                .padding(12.0)
                .gap(4.0)
                .radius(k.radius.md)
                .fill(k.c.layer_01)
                .box_shadow(Shadow {
                    spread: 0.5,
                    color: k.c.border_base,
                    ..Shadow::default()
                })
                .child(
                    text("deadbolt pair")
                        .key("cmd")
                        .font(k.ty.text_small_medium.lh(20.0))
                        .color(k.c.text_strong),
                )
                .child(
                    text(grouped)
                        .key("ticket")
                        .font(k.ty.text_small.lh(20.0))
                        .color(k.c.text_base)
                        .wrap()
                        .w_full(),
                ),
        )
        .child(
            Button::new(if copied { "Copied" } else { "Copy command" })
                .variant(ButtonVariant::Neutral)
                .control_size(ControlSize::Large)
                .icon(if copied {
                    k.glyph.check_small
                } else {
                    k.glyph.copy
                })
                .on_press_tx(|s: &mut App, tx| s.copy_ticket(tx))
                .build(k)
                .key("copy"),
        );
    // A failed copy.
    if let Some(n) = &o.notice {
        how = how.child(banner(k, n));
    }
    how = how.child(
        row()
            .key("waiting")
            .gap(10.0)
            .center_y()
            .mt(4.0)
            .child(waiting(k))
            .child(
                text("Waiting for your other device")
                    .font(k.ty.text_small)
                    .color(k.c.text_muted),
            ),
    );
    page(
        "ticket",
        Some(bar(k, "Cancel", k.glyph.close, |s| s.cancel_join())),
        pair.child(how),
    )
}

fn confirm(k: &Kit, code: &str, vault: &str, inviter: &str) -> El {
    let spaced = if code.len() == 6 {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_owned()
    };
    let panel = col()
        .key("panel")
        .w(PANEL_W)
        .gap(16.0)
        .items_start()
        .child(title(k, "title", "Do the codes match?"))
        .child(muted(
            k,
            "about",
            format!("{inviter} is adding this device to {vault}. Check it shows this code."),
        ))
        .child(
            text(spaced)
                .key("code")
                .role("status")
                .font(TextStyle::new(56.0, 500.0).lh(64.0).tracking(2.0))
                .color(k.c.text_strong)
                .mt(4.0)
                .mb(4.0),
        )
        .child(
            row()
                .key("answers")
                .gap(8.0)
                .child(
                    Button::new("They match")
                        .variant(ButtonVariant::Contrast)
                        .control_size(ControlSize::Large)
                        .on_press(|s: &mut App| s.answer_code(true))
                        .build(k)
                        .key("match"),
                )
                .child(
                    Button::new("They don't match")
                        .variant(ButtonVariant::Neutral)
                        .control_size(ControlSize::Large)
                        .on_press(|s: &mut App| s.answer_code(false))
                        .build(k)
                        .key("mismatch"),
                ),
        )
        .child(muted(
            k,
            "why",
            "Matching codes mean you're talking to your own device, not someone who saw the ticket.",
        ));
    page(
        "confirm",
        Some(bar(k, "Cancel", k.glyph.close, |s| s.cancel_join())),
        panel,
    )
}

// -------------------------------------------------------------------------------------------
// The empty vault

const ADD: &str = "deadbolt new login url=github.com username=you";
const IMPORT: &str = "deadbolt import bitwarden export.json";

/// What to do with a vault that has nothing in it yet. Adding and importing
/// happen in the CLI for now.
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
            col()
                .key("head")
                .w_full()
                .gap(4.0)
                .child(
                    text(format!("{vault} is empty"))
                        .key("title")
                        .font(TextStyle::new(20.0, 500.0).lh(26.0))
                        .color(k.c.text_strong),
                )
                .child(muted(
                    k,
                    "about",
                    "Adding and importing in the app come later. For now, in a terminal:",
                )),
        )
        .child(command(s, k, "add", "Add a login", ADD, None))
        .child(command(
            s,
            k,
            "import",
            "Import from Bitwarden",
            IMPORT,
            Some("Export first: Bitwarden › Tools › Export vault › .json"),
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
    let copied = s
        .onboarding
        .copied_command
        .as_ref()
        .is_some_and(|(c, at)| *c == line && s.clock - at < super::COPIED_FOR);
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
