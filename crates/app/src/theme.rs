//! Deadbolt's look as Rune theme data: the site's black, white and red, IBM
//! Plex Mono for everything, small radii and flat surfaces. `assets/theme.json`
//! holds the colours; this maps them onto rune-kit's semantic tokens.

use std::sync::OnceLock;

use rune::{Shadow, TextStyle, Theme};
use rune_kit::{Elevation, Kit, Radius, StateColors, Type};

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
    let mut k = Kit::neutral(dark);
    let p = &mut k.c;
    p.page = c("bg");
    p.bg_base = c("bg");
    p.bg_deep = c("bg");
    p.layer_01 = c("raised");
    p.layer_02 = c("layer");
    p.layer_03 = c("layer-strong");
    p.layer_04 = c("layer-strong");
    p.bg_button_neutral = c("raised");
    p.bg_contrast = c("contrast-bg");
    p.bg_inverse = c("contrast-bg");
    p.bg_icon_button_contrast = c("contrast-bg");
    p.text_contrast = c("contrast-text");
    p.text_inverse = c("contrast-text");
    p.icon_contrast = c("contrast-text");
    p.icon_inverse = c("contrast-text");
    p.submit_fg = c("contrast-text");
    p.submit_icon = c("contrast-text");
    p.bg_accent = c("accent");
    p.text_accent = c("accent");
    p.icon_accent = c("accent");
    for text in [
        &mut p.text_base,
        &mut p.text_strong,
        &mut p.std_text,
        &mut p.icon_base,
        &mut p.std_icon_strong,
    ] {
        *text = c("text");
    }
    for muted in [
        &mut p.text_muted,
        &mut p.text_weak,
        &mut p.icon_muted,
        &mut p.std_icon,
        &mut p.icon_weaker,
    ] {
        *muted = c("text-muted");
    }
    p.text_faint = c("text-faint");
    p.icon_faint = c("text-faint");
    for border in [
        &mut p.border_muted,
        &mut p.border_base,
        &mut p.border_weak,
        &mut p.std_border,
        &mut p.border_disabled,
    ] {
        *border = c("border");
    }
    p.border_strong = c("border-strong");
    p.border_hover = c("border-strong");
    p.border_focus = c("focus");
    p.border_active = c("focus");
    p.hover = c("hover");
    p.surface_hover = c("hover");
    p.pressed = c("pressed");
    p.surface_base = c("surface");
    p.surface_weak = c("surface");
    p.surface_raised = c("raised");
    p.surface_raised_base = c("raised");
    p.surface_raised_hover = c("layer");
    p.danger = StateColors {
        bg: c("danger-bg"),
        fg: c("danger"),
        border: c("danger-border"),
        icon: c("danger"),
    };
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
