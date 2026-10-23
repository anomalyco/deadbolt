//! Deadbolt's look as Rune theme data: the site's black, white and red, IBM
//! Plex Mono for everything but the wordmark, which is Anton, small radii and
//! flat surfaces. `assets/theme.json`
//! holds the colours; rune-kit derives the semantic tokens from three of them
//! and this overrides the few where Deadbolt's look differs.

use std::sync::OnceLock;

use rune::{Color, Family, Shadow, TextStyle, Theme};
use rune_kit::{Elevation, Kit, PaletteFocus, PaletteSeed, Radius, StateColors, Type};

pub const THEME: &str = include_str!("../assets/theme.json");

/// IBM Plex Mono and Anton (both OFL, `assets/fonts/*-LICENSE.txt`), for
/// `AppSpec::fonts`. Anton is the site's subset (Latin), decompressed to TTF.
pub const FONTS: &[&[u8]] = &[
    include_bytes!("../assets/fonts/IBMPlexMono-Regular.ttf"),
    include_bytes!("../assets/fonts/IBMPlexMono-Medium.ttf"),
    include_bytes!("../assets/fonts/Anton-Regular.ttf"),
];

/// `AppSpec::families`: Plex Mono in both slots. Anton is registered through
/// [`FONTS`] and named by [`wordmark`].
pub const FAMILIES: (&str, &str) = ("IBM Plex Mono", "IBM Plex Mono");

/// The wordmark, in Anton, for the lock and onboarding screens only.
pub fn wordmark(size: f32) -> TextStyle {
    TextStyle::new(size, 400.0)
        .family(Family::Named("Anton"))
        .lh(size)
        .tracking(size * 0.01)
}

/// The kit tokens for one appearance.
pub fn kit(dark: bool) -> &'static Kit {
    static DARK: OnceLock<Kit> = OnceLock::new();
    static LIGHT: OnceLock<Kit> = OnceLock::new();
    if dark {
        DARK.get_or_init(|| build(true))
    } else {
        LIGHT.get_or_init(|| build(false))
    }
}

/// A colour from `assets/theme.json` that rune-kit has no token for.
pub fn color(dark: bool, name: &str) -> Color {
    theme(dark).color(name)
}

fn theme(dark: bool) -> &'static Theme {
    static DARK: OnceLock<Theme> = OnceLock::new();
    static LIGHT: OnceLock<Theme> = OnceLock::new();
    let parse = || Theme::from_json(THEME, dark).unwrap_or_else(|e| panic!("{e}"));
    if dark {
        DARK.get_or_init(parse)
    } else {
        LIGHT.get_or_init(parse)
    }
}

fn build(dark: bool) -> Kit {
    let t = theme(dark);
    let c = |n: &str| t.color(n);
    // Focus is ink, as on the site; red is kept for the countdown and danger.
    let mut k = Kit::from_palette_focus(
        PaletteSeed {
            bg: c("bg"),
            fg: c("text"),
            accent: c("accent"),
        },
        PaletteFocus::Ink,
    );
    let p = &mut k.c;
    // The site's surface ramp. Derived layers rise from the background on both
    // appearances, so on paper raised surfaces come out darker (#e1ddd5) where
    // the site's are lighter (#f3f0ea), and the dark steps differ by up to 13
    // levels (the site's surface sits below its raised layer).
    [p.surface_base, p.surface_weak] = [c("surface"); 2];
    [
        p.layer_01,
        p.bg_button_neutral,
        p.surface_raised,
        p.surface_raised_base,
    ] = [c("raised"); 4];
    [p.layer_02, p.surface_raised_hover] = [c("layer"); 2];
    [p.layer_03, p.layer_04] = [c("layer-strong"); 2];
    // Hairlines everywhere: the derived opaque border steps are heavier lines
    // (#393939 on black, #aeaaa3 on paper).
    [p.border_weak, p.std_border, p.border_disabled] = [p.border_base; 3];
    p.border_hover = p.border_strong;
    // The site's faint ink on paper; the derived one is darker (#807c75).
    [p.text_faint, p.icon_faint, p.icon_weaker] = [c("text-faint"); 3];
    // The site's red and amber: derived status roles take rune-kit's own
    // (#ff847d and #dfa11a on black), not the seed's.
    p.danger = StateColors {
        bg: c("danger-bg"),
        fg: c("danger"),
        border: c("danger-border"),
        icon: c("danger"),
    };
    p.warning = StateColors {
        bg: c("warning-bg"),
        fg: c("warning"),
        border: c("warning-border"),
        icon: c("warning"),
    };
    // Flat surfaces: a hairline ring, and a drop only where something floats.
    let ring = Shadow {
        spread: 0.5,
        color: k.c.border_base,
        ..Shadow::default()
    };
    let drop = |y: f32, blur: f32| Shadow {
        y,
        blur,
        color: c("shadow"),
        ..Shadow::default()
    };
    k.elevation = Elevation {
        raised: vec![ring],
        floating: vec![drop(8.0, 24.0), ring],
        overlay: vec![drop(12.0, 32.0), ring],
        button_neutral: vec![ring],
        button_contrast: vec![],
        elements: vec![],
        switch_off: vec![],
        switch_on: vec![],
        md: vec![drop(4.0, 12.0)],
        knob: vec![drop(1.0, 3.0)],
    };
    let mono = |size: f32, weight: f32, line: f32| TextStyle::new(size, weight).lh(line);
    k.ty = Type {
        ui: mono(13.0, 400.0, 20.0),
        ui_medium: mono(13.0, 500.0, 20.0),
        ui_compact: mono(13.0, 400.0, 16.0),
        small: mono(11.0, 400.0, 16.0),
        small_medium: mono(11.0, 500.0, 16.0),
        body: mono(14.0, 400.0, 21.0),
        body_medium: mono(14.0, 500.0, 21.0),
        text_small: mono(12.0, 400.0, 18.0),
        text_small_medium: mono(12.0, 500.0, 18.0),
        text_xsmall: mono(11.0, 400.0, 16.0),
        text_xsmall_medium: mono(11.0, 500.0, 16.0),
        mono: mono(12.0, 400.0, 18.0).mono(),
    };
    let r = |n: &str| t.num(n);
    k.radius = Radius {
        xs: 2.0,
        sm: r("radius-sm"),
        md: r("radius-md"),
        lg: r("radius-lg"),
        xl: r("radius-lg"),
    };
    k
}
