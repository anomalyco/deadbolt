//! Running first-run ceremonies: honest stage progress, the deadbolt throw
//! moment when a vault is ready, the QR pairing ticket, and code comparison.

use rune::{
    Color, Curve, Cycle, Easing, El, Shadow, Spring, TextStyle, Transition, canvas, col, el, icon,
    row, text,
};
use rune_kit::{Button, ButtonVariant, ControlSize, Kit};

use super::super::worker::Stage;
use super::super::{Flow, Pairing, Step};
use super::{PANEL_W, banner, bar, muted, page, title};
use crate::model::App;
use crate::view::Paged;

/// The bolt's throw: the one sanctioned flourish (Kit's "playful", .3 / .3).
const THROW: Spring = Spring::new(0.3, 0.3);

/// A slow breath for "working on it". Reduced motion holds it full.
const BREATHE: Cycle = Cycle {
    period: 1.4,
    phase: 0.0,
    stops: &[(0.0, 1.0), (0.5, 0.3), (1.0, 1.0)],
    still: 1.0,
    fps: 30.0,
};

pub(super) fn progress(s: &App, k: &Kit, dark: bool, flow: Flow) -> Paged {
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

fn step_row(k: &Kit, stage: Stage, mark: Mark, vault: &str, pairing: Option<&Pairing>) -> El {
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
    // The theme's ember: red, and its pale end for the flash.
    let accent = rune_theme_opencode::brand(dark);
    let rest = k.c.layer_03;
    let hot = rune_theme_opencode::ember(dark, if dark { 12 } else { 7 });
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

pub(super) fn ticket(s: &App, k: &Kit) -> Paged {
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
                .fill(k.c.white)
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

pub(super) fn confirm(k: &Kit, code: &str, vault: &str, inviter: &str) -> Paged {
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
