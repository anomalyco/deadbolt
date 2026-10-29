//! Notices: how serious something is, and the banner that shows it in place.

use rune::El;
use rune::{Icon, Shadow, Transition, col, icon, row, text};
use rune_kit::{Kit, StateColors};

use super::muted;

static CAUTION: Icon = Icon {
    name: "deadbolt-caution",
    view: 16.0,
    body: r#"<path d="M8 2.25L14.25 13.25H1.75Z" stroke="currentColor" stroke-width="1.25" stroke-linejoin="round"/><path d="M8 6.5v3" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/><circle cx="8" cy="11.4" r=".8" fill="currentColor"/>"#,
};
static INFO: Icon = Icon {
    name: "deadbolt-info",
    view: 16.0,
    body: r#"<circle cx="8" cy="8" r="6.25" stroke="currentColor" stroke-width="1.25"/><path d="M8 7.25v4" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/><circle cx="8" cy="4.9" r=".8" fill="currentColor"/>"#,
};

/// How serious a notice is, which sets its colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Nothing went wrong: the person changed their mind, a code ran out.
    Neutral,
    /// Stopped for safety: the codes didn't match.
    Caution,
    /// Something failed.
    Danger,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Notice {
    pub severity: Severity,
    pub title: String,
    pub body: String,
}

impl Notice {
    pub(crate) fn new(
        severity: Severity,
        title: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            title: title.into(),
            body: body.into(),
        }
    }
}

/// A notice in place, coloured by how serious it is: a dim tint and border,
/// with full colour kept for the icon and title.
pub(crate) fn banner(k: &Kit, n: &Notice) -> El {
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
