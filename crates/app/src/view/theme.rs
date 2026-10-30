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
    API,
    "kind-api",
    r#"<path d="M6 3c-1.5 0-1.75.75-1.75 1.75v1.5c0 .9-.5 1.5-1.5 1.75.98.25 1.5.85 1.5 1.75v1.5C4.25 12.25 4.5 13 6 13M10 3c1.5 0 1.75.75 1.75 1.75v1.5c0 .9.5 1.5 1.5 1.75-1 .25-1.5.85-1.5 1.75v1.5c0 1-.25 1.75-1.75 1.75" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    DATABASE,
    "kind-database",
    r#"<ellipse cx="8" cy="4.25" rx="4.75" ry="1.75" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><path d="M3.25 4.25v7.5c0 .97 2.13 1.75 4.75 1.75s4.75-.78 4.75-1.75v-7.5M3.25 8c0 .97 2.13 1.75 4.75 1.75S12.75 8.97 12.75 8" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    SERVER,
    "kind-server",
    r#"<rect x="2.75" y="2.75" width="10.5" height="4.5" rx="1.25" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><rect x="2.75" y="8.75" width="10.5" height="4.5" rx="1.25" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><path d="M5.25 5h.01M5.25 11h.01" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    WIFI,
    "kind-wifi",
    r#"<path d="M2.5 6.5a8 8 0 0 1 11 0M4.5 8.75a5 5 0 0 1 7 0M6.5 11a2 2 0 0 1 3 0M8 13.25h.01" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    LICENSE,
    "kind-license",
    r#"<rect x="2.75" y="2.75" width="10.5" height="8" rx="1.25" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><path d="M5.25 5.5h5.5M5.25 8h3M10 10.75v2.5l1-.75 1 .75v-2.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    BANK,
    "kind-bank",
    r#"<path d="M2.75 6.25 8 3l5.25 3.25M3.75 6.75v5M6.25 6.75v5M9.75 6.75v5M12.25 6.75v5M2.75 13h10.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    DOCUMENT,
    "kind-document",
    r#"<path d="M10.75 5.75 6.6 9.9a1.25 1.25 0 0 0 1.77 1.77l4.6-4.6a2.5 2.5 0 0 0-3.54-3.54L4.8 8.18a3.75 3.75 0 0 0 5.3 5.3l3.15-3.15" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    PASSPORT,
    "kind-passport",
    r#"<rect x="3.25" y="2.25" width="9.5" height="11.5" rx="1.25" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><circle cx="8" cy="7" r="2.25" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><path d="M5.75 11h4.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    DRIVER_LICENSE,
    "kind-driver-license",
    r#"<rect x="2.25" y="3.75" width="11.5" height="8.5" rx="1.75" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><circle cx="5.75" cy="7.25" r="1.25" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 10.25c.35-.8 1-1.25 1.75-1.25s1.4.45 1.75 1.25M9.25 6.75h2.5M9.25 9.25h2" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    ID_DOCUMENT,
    "kind-id-document",
    r#"<rect x="2.25" y="3.75" width="11.5" height="8.5" rx="1.75" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><path d="M5.5 6.25 5 9.75M7.5 6.25 7 9.75M4.5 7.25h3.5M4.25 8.75h3.5M9.75 7h1.75M9.75 9h1.75" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    MEMBERSHIP,
    "kind-membership",
    r#"<path d="m8 2.75 1.55 3.15 3.45.5-2.5 2.45.6 3.45L8 10.65 4.9 12.3l.6-3.45L3 6.4l3.45-.5z" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    CRYPTO,
    "kind-crypto",
    r#"<path d="M3 4.75c0-.83.67-1.5 1.5-1.5h7.25v2.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><rect x="3" y="5.75" width="10.25" height="7" rx="1.25" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><path d="M10.5 9.25h.01" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
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
    pub(crate) DOWNLOAD,
    "deadbolt-download",
    r#"<path d="M8 2.25v7.5M4.75 6.5 8 9.75l3.25-3.25" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><path d="M3 13.25h10" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
glyph!(
    pub IMPORT,
    "deadbolt-import",
    r#"<path d="M8 2.25v7.5M4.75 6.5 8 9.75l3.25-3.25" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/><path d="M2.25 10.5v1.75c0 .69.56 1.25 1.25 1.25h9c.69 0 1.25-.56 1.25-1.25V10.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    pub STAR,
    "deadbolt-star",
    r#"<path d="m8 2.35 1.65 3.34 3.69.54-2.67 2.6.63 3.68L8 10.77l-3.3 1.74.63-3.68-2.67-2.6 3.69-.54z" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
glyph!(
    pub STAR_FILL,
    "deadbolt-star-fill",
    r#"<path d="m8 2.35 1.65 3.34 3.69.54-2.67 2.6.63 3.68L8 10.77l-3.3 1.74.63-3.68-2.67-2.6 3.69-.54z" fill="currentColor" stroke="currentColor" stroke-width="1.0" stroke-linejoin="round"/>"#
);

pub(crate) fn kind_icon(kind: &str) -> &'static Icon {
    match kind {
        "card" => &CARD,
        "note" => &NOTE,
        "ssh" => &SSH,
        "identity" => &IDENTITY,
        "passkey" => &PASSKEY,
        "api" => &API,
        "database" => &DATABASE,
        "server" => &SERVER,
        "wifi" => &WIFI,
        "license" => &LICENSE,
        "bank" => &BANK,
        "document" => &DOCUMENT,
        "passport" => &PASSPORT,
        "driver-license" => &DRIVER_LICENSE,
        "id-document" => &ID_DOCUMENT,
        "membership" => &MEMBERSHIP,
        "crypto" => &CRYPTO,
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
        "api" => "API credential",
        "database" => "Database",
        "server" => "Server",
        "wifi" => "Wi-Fi network",
        "license" => "Software license",
        "bank" => "Bank account",
        "document" => "Document",
        "passport" => "Passport",
        "driver-license" => "Driver's license",
        "id-document" => "ID document",
        "membership" => "Membership",
        "crypto" => "Crypto wallet",
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
