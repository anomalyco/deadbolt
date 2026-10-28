//! Design directions for the vault (t387), drawn from the real `App` behind
//! `--scene dir-*`: A, a Seer-style document page with a Settings page; B, a
//! list-first table with an inspector; C, the whole app as one floating
//! window. Only scenes set `App::look`; a live run never draws these.

mod compact;
mod document;
mod floating;
mod settings;

use deadbolt_client::protocol::{FieldInfo, ItemInfo, code_field};
use rune::{Color, El, Icon, TextStyle, col, el, icon, row, text};
use rune_kit::{Keybind, Kit};

use crate::model::{App, Screen, group_code, is_secret, title_case};

/// Which direction a scene draws, and the keyboard state it shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Look {
    pub take: Take,
    /// ⌘, has the page instead of the item.
    pub settings: bool,
    /// ⇥ moved into the item: the field the keys act on.
    pub field: Option<usize>,
    /// The Settings row the keys act on.
    pub row: Option<usize>,
    /// ⌘K's actions are open.
    pub actions: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Take {
    Document,
    Compact,
    Floating,
}

impl Look {
    pub fn new(take: Take) -> Look {
        Look {
            take,
            settings: false,
            field: None,
            row: None,
            actions: false,
        }
    }
}

/// The vault in the scene's direction, or `None` to draw today's.
pub fn view(s: &App, k: &Kit, inset: f32) -> Option<El> {
    let look = s.look?;
    if s.screen != Screen::Vault {
        return None;
    }
    Some(match look.take {
        Take::Document => document::vault(s, k, inset, look),
        Take::Compact => compact::vault(s, k, inset, look),
        Take::Floating => floating::window(s, k, look),
    })
}

/// Sets a scene's direction.
pub fn set(s: &mut App, look: Look) {
    s.look = Some(look);
}

// -------------------------------------------------------------------------------------------
// Shared pieces.

macro_rules! glyph {
    ($name:literal, $body:literal) => {
        Icon {
            name: $name,
            view: 16.0,
            body: $body,
        }
    };
}

static LOGIN: Icon = glyph!(
    "dir-login",
    r#"<circle cx="5.25" cy="10.75" r="2.75" stroke="currentColor" stroke-width="1.25"/><path d="M7.2 8.8L13 3M10.6 5.4l1.6 1.6M12.1 3.9l1.15 1.15" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
static CARD: Icon = glyph!(
    "dir-card",
    r#"<rect x="2.25" y="3.75" width="11.5" height="8.5" rx="1.75" stroke="currentColor" stroke-width="1.25"/><path d="M2.25 6.75h11.5M4.75 9.75h2.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
static NOTE: Icon = glyph!(
    "dir-note",
    r#"<path d="M4 2.75h5.25l2.75 2.75v7.75H4z" stroke="currentColor" stroke-width="1.25" stroke-linejoin="round"/><path d="M6.25 8.25h3.5M6.25 10.5h2.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
static SSH: Icon = glyph!(
    "dir-ssh",
    r#"<rect x="2.25" y="3" width="11.5" height="10" rx="1.75" stroke="currentColor" stroke-width="1.25"/><path d="M5 6.5l1.75 1.5L5 9.5M8.5 10h2.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#
);
static IDENTITY: Icon = glyph!(
    "dir-identity",
    r#"<circle cx="8" cy="5.75" r="2.5" stroke="currentColor" stroke-width="1.25"/><path d="M3.5 13.25c.6-2.3 2.4-3.5 4.5-3.5s3.9 1.2 4.5 3.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
static PASSKEY: Icon = glyph!(
    "dir-passkey",
    r#"<circle cx="6" cy="5.5" r="2.25" stroke="currentColor" stroke-width="1.25"/><path d="M2.5 12.75c.4-2 1.8-3.25 3.5-3.25.8 0 1.5.25 2.1.7" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/><circle cx="11.25" cy="9" r="1.75" stroke="currentColor" stroke-width="1.25"/><path d="M11.25 10.75v2.75M11.25 12.25h1.25" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
);
pub(crate) static SLIDERS: Icon = glyph!(
    "dir-sliders",
    r#"<path d="M2.75 5h6M11.75 5h1.5M2.75 11h1.5M7.25 11h6" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/><circle cx="10.25" cy="5" r="1.5" stroke="currentColor" stroke-width="1.25"/><circle cx="5.75" cy="11" r="1.5" stroke="currentColor" stroke-width="1.25"/>"#
);
static BOLT: Icon = glyph!(
    "dir-bolt",
    r#"<rect x="3" y="7" width="10" height="6.5" rx="1.5" stroke="currentColor" stroke-width="1.25"/><path d="M5.25 7V5.25a2.75 2.75 0 0 1 5.5 0V7" stroke="currentColor" stroke-width="1.25"/><path d="M8 9.5v1.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#
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

/// The 11.5/440 second line Seer's rows use.
pub(crate) const FACT: TextStyle = TextStyle::new(11.5, 440.0).lh(14.0);

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

/// A monogram in a colour from the item's name, for lists that stand in favicons.
pub(crate) fn monogram(k: &Kit, label: &str, size: f32) -> El {
    const HUES: [&str; 7] = ["cobalt", "mint", "amber", "lilac", "coral", "apple", "yuzu"];
    let hash = label
        .bytes()
        .fold(5381u32, |h, b| h.wrapping_mul(33) ^ u32::from(b));
    let hue = HUES[hash as usize % HUES.len()];
    let (bg, fg) = (
        rune_theme_opencode::scale(hue, k.dark, 4),
        rune_theme_opencode::scale(hue, k.dark, 11),
    );
    let letter = label.chars().find(|c| c.is_alphanumeric()).unwrap_or('•');
    row()
        .key("mono")
        .size(size, size)
        .center()
        .radius((size * 0.28).round())
        .continuous_corners()
        .fill(bg)
        .child(
            text(letter.to_uppercase().to_string())
                .font(TextStyle::new((size * 0.5).round(), 600.0).lh(size))
                .color(fg),
        )
}

/// A keycap and what it does.
pub(crate) fn hint(k: &Kit, keys: &[&str], label: &str) -> El {
    row()
        .gap(6.0)
        .center_y()
        .child(Keybind::new(keys).build(k))
        .child(
            text(label.to_owned())
                .font(k.ty.small)
                .color(k.c.text_muted),
        )
}

/// The selected item's fields as the item page shows them: name, shown value
/// and kind, with a passkey's bookkeeping left out and the code where it goes.
pub(crate) struct Shown<'a> {
    pub field: &'a FieldInfo,
    pub label: String,
    pub value: Value,
}

pub(crate) enum Value {
    Text(String),
    Mono(String),
    /// A secret: twelve dots unless shown.
    Secret {
        value: String,
        shown: bool,
    },
    Code(String),
}

pub(crate) fn fields<'a>(s: &'a App, item: &ItemInfo) -> Vec<Shown<'a>> {
    let Some(full) = s.detail.as_ref().filter(|d| d.id == item.id) else {
        return Vec::new();
    };
    let code = code_field(&full.fields);
    full.fields
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            full.kind != "passkey"
                || matches!(f.name.as_str(), "rp-id" | "username" | "created" | "notes")
        })
        .map(|(i, f)| {
            let value = f.value.trim_end_matches(['\r', '\n']).to_owned();
            let value = if code == Some(i) {
                let digits = s
                    .otp
                    .as_ref()
                    .and_then(|o| o.code.as_ref())
                    .map_or_else(|| "••• •••".to_owned(), |c| group_code(c));
                Value::Code(digits)
            } else if is_secret(&f.kind) {
                Value::Secret {
                    value,
                    shown: s.revealed.iter().any(|r| r == &f.name),
                }
            } else if matches!(f.name.as_str(), "public-key" | "fingerprint") {
                Value::Mono(value)
            } else {
                Value::Text(value)
            };
            let label = if code == Some(i) {
                "One-time code".to_owned()
            } else {
                title_case(&f.name)
            };
            Shown {
                field: f,
                label,
                value,
            }
        })
        .collect()
}

/// A shown field's value, as text in `style` (mono for secrets and keys).
pub(crate) fn value_el(k: &Kit, v: &Value, style: TextStyle, wrap: bool) -> El {
    let mono = TextStyle {
        size: style.size,
        line_height: style.line_height,
        ..k.ty.mono
    };
    let t = match v {
        Value::Text(s) => text(s.clone()).font(style).color(k.c.text_base),
        Value::Mono(s) => text(s.clone()).font(mono).color(k.c.text_base),
        Value::Secret { value, shown } => text(value.clone())
            .secure()
            .revealed(*shown)
            .font(mono)
            .color(k.c.text_base),
        Value::Code(c) => text(c.clone())
            .font(
                TextStyle {
                    size: style.size + 2.0,
                    ..mono
                }
                .features("'tnum' 1"),
            )
            .color(k.c.text_strong),
    };
    if wrap {
        t.wrap_anywhere().min_w(0.0)
    } else {
        t.truncate_fade().min_w(0.0)
    }
}

/// What ↵, Space and O do on a field the keys are on.
pub(crate) fn field_keys(k: &Kit, f: &Shown) -> El {
    let mut r = row().key("keys").gap(12.0).center_y();
    if matches!(f.value, Value::Secret { .. }) {
        let shown = matches!(f.value, Value::Secret { shown: true, .. });
        r = r.child(hint(k, &["Space"], if shown { "Hide" } else { "Show" }));
    }
    if f.field.name == "url" {
        r = r.child(hint(k, &["O"], "Open"));
    }
    r.child(hint(k, &["↵"], "Copy"))
}

/// The countdown beside a code, emptying over its period.
pub(crate) fn code_ring(s: &App, k: &Kit) -> El {
    let left = s
        .otp
        .as_ref()
        .map_or(0.6, |o| ((o.until - s.clock) / 30.0).clamp(0.0, 1.0) as f32);
    let w = 28.0;
    el().key("code-track")
        .w(w)
        .h(3.0)
        .radius(1.5)
        .fill(k.c.layer_03)
        .child(
            el().key("code-bar")
                .w(w * left)
                .h(3.0)
                .radius(1.5)
                .fill(k.c.text_accent),
        )
}

/// The ⌘K actions for the selected item, over whatever has the window.
pub(crate) fn actions(s: &App, k: &Kit, floating: bool) -> El {
    let item = s.selected_item();
    let site = item.map(|i| i.label.clone()).unwrap_or_default();
    let mut list: Vec<(&str, String, &[&str])> = vec![
        ("copy", "Copy password".into(), &["↵"]),
        ("user", "Copy username".into(), &["⇧", "↵"]),
    ];
    if crate::model::has_code(s) {
        list.push(("code", "Copy one-time code".into(), &["⌥", "↵"]));
    }
    list.extend([
        ("show", "Show password".into(), &["Space"][..]),
        ("open", format!("Open {site}"), &["⌘", "O"][..]),
        ("edit", "Edit".into(), &["⌘", "E"][..]),
    ]);
    if floating {
        list.push(("window", "Open in Deadbolt".into(), &["⌘", "↵"]));
    }
    list.push(("delete", "Delete…".into(), &["⌘", "⌫"]));
    let rows = list.into_iter().enumerate().fold(
        col().key("actions-rows").w_full().gap(1.0).px(6.0).pb(6.0),
        |c, (i, (key, label, keys))| {
            let on = i == 0;
            let ink = if key == "delete" {
                k.c.danger.fg
            } else {
                k.c.text_base
            };
            c.child(
                row()
                    .key(format!("action-{key}"))
                    .w_full()
                    .h(32.0)
                    .px(10.0)
                    .radius(6.0)
                    .center_y()
                    .fill(if on { k.c.layer_03 } else { Color::TRANSPARENT })
                    .child(text(label).font(k.ty.ui).color(ink).grow(1.0))
                    .child(Keybind::new(keys).build(k)),
            )
        },
    );
    let mut card = col()
        .key("actions")
        .w(300.0)
        .radius(12.0)
        .continuous_corners()
        .fill(k.c.surface_raised)
        .border(0.5, k.c.border_weak)
        .child(
            row()
                .key("actions-head")
                .w_full()
                .h(38.0)
                .px(16.0)
                .center_y()
                .child(
                    text(item.map_or_else(String::new, |i| i.label.clone()))
                        .font(k.ty.small_medium)
                        .color(k.c.text_muted),
                ),
        )
        .child(rows);
    for shadow in k.shadow_layers(&k.elevation.overlay) {
        card = card.box_shadow(shadow);
    }
    card
}

/// The `dir-*` scenes: today's fixtures, drawn in a direction.
pub(crate) fn scene(s: &mut App, name: &str) {
    let (take, rest) = name.split_once('-').unwrap_or((name, ""));
    match rest {
        "ssh" => crate::kind_scene(s, "ssh"),
        _ => crate::vault(s),
    }
    let mut look = Look::new(match take {
        "a" => Take::Document,
        "b" => Take::Compact,
        _ => Take::Floating,
    });
    match rest {
        "field" => look.field = Some(0),
        "actions" => look.actions = true,
        "settings" => {
            if let Some(st) = &mut s.status {
                st.touch_id_available = true;
                st.touch_id_enabled = true;
            }
            look.settings = true;
            look.row = Some(1);
        }
        _ => {}
    }
    s.search.focused = false;
    set(s, look);
}
