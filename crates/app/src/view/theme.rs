//! Shared typography, geometry, motion presets and icons across views.

use rune::{Chrome, El, Icon, Spring, SpringPair, TextStyle, Transition, icon, row};
use rune_kit::Kit;

use crate::model::BAR_W;

/// The main window: content under a transparent title bar, with the traffic
/// lights centred in the shell's 48 pt band.
pub const CHROME: Chrome = Chrome {
    full_size_content: true,
    traffic_lights: Some((16.0, 17.0)),
    drag_regions: true,
};

/// How far a list's edges fade over hidden rows, and how far a row brought into view stops from them.
pub(crate) const LIST_EDGE: f32 = 24.0;
/// The item and Settings column: wide enough for a public key, narrow enough to read.
pub(crate) const PAGE_W: f32 = 560.0;
pub(crate) const NOTICE_W: f32 = BAR_W + 24.0;

pub(crate) const TITLE: TextStyle = TextStyle::new(22.0, 600.0).lh(28.0);
pub(crate) const SUBHEADING: TextStyle = TextStyle::new(20.0, 500.0).lh(26.0);
pub(crate) const CARD_TITLE: TextStyle = TextStyle::new(17.0, 500.0).lh(22.0);
pub(crate) const PANEL_HEADER: TextStyle = TextStyle::new(17.0, 400.0).lh(24.0);
pub(crate) const PANEL_ITEM_TITLE: TextStyle = TextStyle::new(15.0, 600.0).lh(20.0);
/// The 11.5/440 second line Seer's rows use.
pub(crate) const FACT: TextStyle = TextStyle::new(11.5, 440.0).lh(14.0);

/// Tabular figures so counts and countdown digits hold one width.
pub(crate) fn tnum(style: TextStyle) -> TextStyle {
    style.features("'tnum' 1")
}

const INSTANT_SPRING: Spring = Spring::new(0.001, 0.0);

/// Enters and leaves at once, with no fade.
pub(crate) fn instant() -> Transition {
    Transition::identity().springs(SpringPair::new(INSTANT_SPRING, INSTANT_SPRING))
}

/// Whole-state replacement (blur σ 1.5, scale .96, fade; `.3/0` in, `.24/0` out).
pub(crate) fn replace() -> Transition {
    Transition::blur_replace()
}

/// Floating status notices: rise 12 pt with a fade, and leave the same way.
pub(crate) fn rise() -> Transition {
    Transition::offset(0.0, 12.0).combined(Transition::opacity())
}

macro_rules! glyph {
    ($vis:vis $ident:ident, $name:literal, $body:literal) => {
        $vis static $ident: Icon = Icon {
            name: $name,
            view: 16.0,
            body: $body,
        };
    };
}

glyph!(
    LOGIN,
    "kind-login",
    r#"<circle cx="5.25" cy="10.75" r="2.75" stroke="currentColor" stroke-width="1.25"/><path d="M7.2 8.8L13 3M10.6 5.4l1.6 1.6M12.1 3.9l1.15 1.15" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
glyph!(
    CARD,
    "kind-card",
    r#"<rect x="2.25" y="3.75" width="11.5" height="8.5" rx="1.75" stroke="currentColor" stroke-width="1.25"/><path d="M2.25 6.75h11.5M4.75 9.75h2.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
glyph!(
    NOTE,
    "kind-note",
    r#"<path d="M4 2.75h5.25l2.75 2.75v7.75H4z" stroke="currentColor" stroke-width="1.25" stroke-linejoin="round"/><path d="M6.25 8.25h3.5M6.25 10.5h2.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
glyph!(
    SSH,
    "kind-ssh",
    r#"<rect x="2.25" y="3" width="11.5" height="10" rx="1.75" stroke="currentColor" stroke-width="1.25"/><path d="M5 6.5l1.75 1.5L5 9.5M8.5 10h2.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    IDENTITY,
    "kind-identity",
    r#"<circle cx="8" cy="5.75" r="2.5" stroke="currentColor" stroke-width="1.25"/><path d="M3.5 13.25c.6-2.3 2.4-3.5 4.5-3.5s3.9 1.2 4.5 3.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
glyph!(
    PASSKEY,
    "kind-passkey",
    r#"<circle cx="6" cy="5.5" r="2.25" stroke="currentColor" stroke-width="1.25"/><path d="M2.5 12.75c.4-2 1.8-3.25 3.5-3.25.8 0 1.5.25 2.1.7" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/><circle cx="11.25" cy="9" r="1.75" stroke="currentColor" stroke-width="1.25"/><path d="M11.25 10.75v2.75M11.25 12.25h1.25" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
glyph!(
    pub(crate) SLIDERS,
    "sliders",
    r#"<path d="M2.75 5h6M11.75 5h1.5M2.75 11h1.5M7.25 11h6" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/><circle cx="10.25" cy="5" r="1.5" stroke="currentColor" stroke-width="1.25"/><circle cx="5.75" cy="11" r="1.5" stroke="currentColor" stroke-width="1.25"/>"#
);
glyph!(
    pub PLUS,
    "deadbolt-plus",
    r#"<path d="M8 3.25v9.5M3.25 8h9.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
glyph!(
    pub TRASH,
    "deadbolt-trash",
    r#"<path d="M2.75 4.25h10.5M6.25 4.25v-1c0-.41.34-.75.75-.75h2c.41 0 .75.34.75.75v1M4.25 4.25l.6 8.1c.04.65.58 1.15 1.23 1.15h3.84c.65 0 1.19-.5 1.23-1.15l.6-8.1" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    pub REGENERATE,
    "deadbolt-regenerate",
    r#"<path d="M12.75 8a4.75 4.75 0 1 1-1.39-3.36" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/><path d="M11.75 2.25v2.5h-2.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    pub IMPORT,
    "deadbolt-import",
    r#"<path d="M8 2.25v7.5M4.75 6.5 8 9.75l3.25-3.25" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><path d="M2.25 10.5v1.75c0 .69.56 1.25 1.25 1.25h9c.69 0 1.25-.56 1.25-1.25V10.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);

pub(crate) fn kind_icon(kind: &str) -> &'static Icon {
    match kind {
        "card" => &CARD,
        "note" => &NOTE,
        "ssh" => &SSH,
        "identity" => &IDENTITY,
        "passkey" => &PASSKEY,
        _ => &LOGIN,
    }
}

/// "Login", "Card", "Secure note", "SSH key"…
pub(crate) fn kind_name(kind: &str) -> &'static str {
    match kind {
        "card" => "Card",
        "note" => "Secure note",
        "ssh" => "SSH key",
        "identity" => "Identity",
        "passkey" => "Passkey",
        _ => "Login",
    }
}

/// A tile with the item's kind glyph: quiet, one tone, as Seer's glyphs.
pub(crate) fn glyph_tile(k: &Kit, kind: &str, size: f32, radius: f32) -> El {
    row()
        .key("tile")
        .size(size, size)
        .center()
        .radius(radius)
        .continuous_corners()
        .fill(k.c.layer_02)
        .child(icon(kind_icon(kind), (size * 0.5).round()).color(k.c.icon_base))
}
