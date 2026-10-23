//! Deadbolt's look as Rune theme data: the site's black, white and red, IBM
//! Plex Mono for everything, small radii and flat surfaces. `assets/theme.json`
//! holds the colours; rune-kit derives the semantic tokens from three of them
//! and this overrides the few where Deadbolt's look differs.

use std::sync::OnceLock;

use rune::{Shadow, TextStyle, Theme};
use rune_kit::{Elevation, Kit, PaletteSeed, Radius, StateColors, Type};

pub const THEME: &str = include_str!("../assets/theme.json");

/// IBM Plex Mono (OFL, `assets/fonts/IBMPlexMono-LICENSE.txt`), for `AppSpec::fonts`.
pub const FONTS: &[&[u8]] = &[
    include_bytes!("../assets/fonts/IBMPlexMono-Regular.ttf"),
    include_bytes!("../assets/fonts/IBMPlexMono-Medium.ttf"),
];

/// `AppSpec::families`: Plex Mono is both, as on the site.
pub const FAMILIES: (&str, &str) = ("IBM Plex Mono", "IBM Plex Mono");

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

fn build(dark: bool) -> Kit {
    let t = Theme::from_json(THEME, dark).unwrap_or_else(|e| panic!("{e}"));
    let c = |n: &str| t.color(n);
    let mut k = Kit::from_palette(PaletteSeed {
        bg: c("bg"),
        fg: c("text"),
        accent: c("accent"),
    });
    let p = &mut k.c;
    // The site's surface ramp: derived layers mix in linear light and read far
    // lighter on black.
    [p.surface_base, p.surface_weak] = [c("surface"); 2];
    [
        p.layer_01,
        p.bg_button_neutral,
        p.surface_raised,
        p.surface_raised_base,
    ] = [c("raised"); 4];
    [p.layer_02, p.surface_raised_hover] = [c("layer"); 2];
    [p.layer_03, p.layer_04] = [c("layer-strong"); 2];
    // Hairlines, not opaque grey.
    [
        p.border_muted,
        p.border_weak,
        p.border_base,
        p.std_border,
        p.border_disabled,
    ] = [c("border"); 5];
    [p.border_strong, p.border_hover] = [c("border-strong"); 2];
    // Focus is ink; red is kept for the countdown and danger.
    [p.border_focus, p.border_active] = [c("focus"); 2];
    [p.text_muted, p.text_weak, p.icon_muted, p.std_icon] = [c("text-muted"); 4];
    [p.text_faint, p.icon_faint, p.icon_weaker] = [c("text-faint"); 3];
    [p.hover, p.surface_hover] = [c("hover"); 2];
    p.pressed = c("pressed");
    p.danger = StateColors {
        bg: c("danger-bg"),
        fg: c("danger"),
        border: c("danger-border"),
        icon: c("danger"),
    };
    // Flat surfaces: a hairline ring, and a drop only where something floats.
    let ring = Shadow {
        spread: 0.5,
        color: c("border"),
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
    k.blend_over = Some(c("bg"));
    k
}
