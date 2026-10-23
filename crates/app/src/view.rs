//! Drawing. Every screen reads `App` and returns Rune elements; handlers call
//! into `model.rs`.
//!
//! Motion (docs/app.md has the full table): screens swap with Kit's
//! whole-state replacement (blur 4, scale .96, fade; exits shorter). Filter
//! results reflow on `REFLOW` while rows that stay never blur; rows that leave
//! or arrive fade in place. Keyboard selection and the selected item's fields
//! land at once. Nothing animates on first paint, and reduced motion keeps
//! only fades (Rune's runtime does both).

use deadbolt_client::protocol::{FieldInfo, ItemInfo};
use rune::{
    Cursor, Cx, El, Icon, ScrollSpec, Spring, TextStyle, Transition, col, el, icon, row, spacer,
    text, text_input,
};
use rune_kit::{Button, ButtonSize, ButtonVariant, IconButton, IconButtonVariant, Kit, TextInput};

use crate::model::{App, BAR_W, Screen, is_secret, title_case};

const LIST_W: f32 = 300.0;
const NOTICE_W: f32 = BAR_W + 24.0;

pub static LOCK: Icon = Icon {
    name: "deadbolt-lock",
    view: 16.0,
    body: r#"<rect x="3.5" y="7" width="9" height="6.5" rx="1.5" stroke="currentColor"/><path d="M5.5 7V5.25a2.5 2.5 0 0 1 5 0V7" stroke="currentColor"/>"#,
};
pub static EYE: Icon = Icon {
    name: "deadbolt-eye",
    view: 16.0,
    body: r#"<path d="M1.75 8C3.1 5.4 5.4 4 8 4s4.9 1.4 6.25 4C12.9 10.6 10.6 12 8 12S3.1 10.6 1.75 8Z" stroke="currentColor"/><circle cx="8" cy="8" r="1.75" stroke="currentColor"/>"#,
};
// Key symbols Plex Mono lacks (Rune only falls back to other fonts for CJK).
pub static CMD: Icon = Icon {
    name: "deadbolt-cmd",
    view: 16.0,
    body: r#"<path d="M6 6h4v4H6zM6 6V4.5A1.5 1.5 0 1 0 4.5 6H6M10 6V4.5A1.5 1.5 0 1 1 11.5 6H10M10 10v1.5a1.5 1.5 0 1 0 1.5-1.5H10M6 10v1.5A1.5 1.5 0 1 1 4.5 10H6" stroke="currentColor" stroke-width="1.25"/>"#,
};
pub static SHIFT: Icon = Icon {
    name: "deadbolt-shift",
    view: 16.0,
    body: r#"<path d="M8 2.5l5.5 6h-3V13h-5V8.5h-3z" stroke="currentColor" stroke-width="1.25" stroke-linejoin="round"/>"#,
};
pub static ENTER: Icon = Icon {
    name: "deadbolt-enter",
    view: 16.0,
    body: r#"<path d="M13 3v5.5A1.5 1.5 0 0 1 11.5 10H3.5M6.5 7l-3 3 3 3" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#,
};
pub static EYE_OFF: Icon = Icon {
    name: "deadbolt-eye-off",
    view: 16.0,
    body: r#"<path d="M1.75 8C3.1 5.4 5.4 4 8 4s4.9 1.4 6.25 4C12.9 10.6 10.6 12 8 12S3.1 10.6 1.75 8Z" stroke="currentColor"/><path d="M3 13L13 3" stroke="currentColor"/>"#,
};

fn replace() -> Transition {
    Transition::blur_replace()
}

pub fn app(s: &App, cx: &mut Cx<App>) -> El {
    cx.reduced_motion(s.reduced_motion);
    let k = crate::theme::kit(cx.system_dark());
    let screen = match &s.screen {
        Screen::Connecting => connecting(k),
        Screen::NotSetUp => not_set_up(k),
        Screen::Locked => unlock(s, k),
        Screen::Vault => vault(s, k),
        Screen::Failed(message) => failed(k, message),
    };
    col()
        .key("window")
        .w_full()
        .h_full()
        .fill(k.c.bg_base)
        .child(screen.grow(1.0).w_full().transition(replace()))
}

/// A centred column for the screens that aren't the vault.
fn centred(key: &str, k: &Kit, glyph: &'static Icon, title: &str, body: El) -> El {
    col().key(key).center().child(
        col()
            .key("panel")
            .w(320.0)
            .gap(16.0)
            .items_start()
            .child(
                row()
                    .key("mark")
                    .size(36.0, 36.0)
                    .center()
                    .radius(k.radius.lg)
                    .fill(k.c.layer_02)
                    .child(icon(glyph, 20.0).color(k.c.icon_base)),
            )
            .child(
                text(title)
                    .key("title")
                    .font(TextStyle::new(17.0, 500.0).lh(22.0))
                    .color(k.c.text_strong),
            )
            .child(body),
    )
}

fn muted(k: &Kit, key: &str, s: impl Into<String>) -> El {
    text(s.into())
        .key(key)
        .font(k.ty.text_small)
        .color(k.c.text_muted)
        .wrap()
        .w_full()
}

fn connecting(k: &Kit) -> El {
    col().key("connecting").center().child(
        text("Starting Deadbolt…")
            .font(k.ty.text_small)
            .color(k.c.text_faint),
    )
}

fn not_set_up(k: &Kit) -> El {
    centred(
        "setup",
        k,
        &LOCK,
        "Set up this device",
        col()
            .key("body")
            .w_full()
            .gap(16.0)
            .child(muted(
                k,
                "how",
                "Run deadbolt init in a terminal to create a vault, or deadbolt join to join one from your other device.",
            ))
            .child(Button::new("Check again").variant(ButtonVariant::Neutral).on_press(|s: &mut App| s.retry()).build(k)),
    )
}

fn failed(k: &Kit, message: &str) -> El {
    centred(
        "failed",
        k,
        &LOCK,
        "Can't reach Deadbolt",
        col()
            .key("body")
            .w_full()
            .gap(16.0)
            .child(muted(k, "message", message))
            .child(
                Button::new("Try again")
                    .variant(ButtonVariant::Neutral)
                    .on_press(|s: &mut App| s.retry())
                    .build(k),
            ),
    )
}

fn unlock(s: &App, k: &Kit) -> El {
    let device = s
        .status
        .as_ref()
        .and_then(|st| st.device.as_ref())
        .and_then(|d| d.name.clone());
    let vaults = s.status.as_ref().map_or(0, |st| st.vaults.len());
    let about = match (device, vaults) {
        (Some(name), 0) => name,
        (Some(name), n) => format!("{name} · {n} vault{}", if n == 1 { "" } else { "s" }),
        (None, _) => "Enter your passphrase to unlock this device.".into(),
    };
    let field = TextInput::new(&s.passphrase.mask)
        .placeholder("Passphrase")
        .large()
        .width(None)
        .invalid(s.unlock_error.is_some())
        .disabled(s.unlocking)
        .on_edit(|s: &mut App| &mut s.passphrase.mask)
        .on_key(|s: &mut App, ev, _| s.passphrase.key(ev))
        .on_change(|s: &mut App, _| {
            s.passphrase.reconcile();
            s.unlock_error = None;
        })
        .on_submit(|s: &mut App, _| s.submit_unlock())
        .build(k)
        .key("passphrase");
    let mut body = col()
        .key("body")
        .w_full()
        .gap(12.0)
        .child(muted(k, "about", about))
        .child(field);
    if let Some(e) = &s.unlock_error {
        body = body.child(
            text(e.clone())
                .key("error")
                .font(k.ty.text_small)
                .color(k.c.danger.fg)
                .wrap()
                .w_full()
                .transition(Transition::opacity()),
        );
    }
    let label = if s.unlocking {
        "Unlocking…"
    } else {
        "Unlock"
    };
    body = body.child(
        Button::new(label)
            .variant(ButtonVariant::Contrast)
            .size(ButtonSize::Large)
            .disabled(s.unlocking || s.passphrase.is_empty())
            .on_press(|s: &mut App| s.submit_unlock())
            .build(k)
            .key("unlock")
            .mt(4.0),
    );
    centred("unlock", k, &LOCK, "Deadbolt is locked", body)
}

// -------------------------------------------------------------------------------------------
// The vault: search, list, detail.

fn vault(s: &App, k: &Kit) -> El {
    col()
        .key("vault")
        .child(toolbar(s, k))
        .child(el().key("rule").h(1.0).w_full().fill(k.c.border_weak))
        .child(
            row()
                .key("body")
                .grow(1.0)
                .shrink()
                .w_full()
                .child(list(s, k))
                .child(el().key("split").w(1.0).h_full().fill(k.c.border_weak))
                .child(detail(s, k)),
        )
        .child(el().key("rule2").h(1.0).w_full().fill(k.c.border_weak))
        .child(hints(k))
}

fn toolbar(s: &App, k: &Kit) -> El {
    let count = match s.items.len() {
        1 => "Search 1 item".to_owned(),
        n => format!("Search {n} items"),
    };
    let field = text_input(&s.search, TextStyle::new(15.0, 400.0).lh(20.0))
        .key("search-input")
        .grow(1.0)
        .shrink()
        .color(k.c.text_strong)
        .placeholder(count, k.c.text_faint)
        .caret(k.c.text_strong, k.alpha(k.c.text_accent, 0.3))
        .animate_edit_layout()
        .on_edit(|s: &mut App| &mut s.search)
        .on_input_key(|s: &mut App, ev, tx| s.search_key(ev, tx))
        .on_input_change(|s: &mut App, _| s.keep_selection_visible());
    row()
        .key("toolbar")
        .w_full()
        .h(52.0)
        .px(16.0)
        .gap(10.0)
        .center_y()
        .child(
            icon(k.glyph.search, 16.0)
                .key("search-icon")
                .color(k.c.icon_muted),
        )
        .child(field)
        .child(
            IconButton::new(&LOCK)
                .variant(IconButtonVariant::Ghost)
                .label("Lock")
                .on_press(|s: &mut App| s.lock())
                .build(k)
                .key("lock"),
        )
}

fn list(s: &App, k: &Kit) -> El {
    let visible = s.visible();
    let mut rows = col().key("rows").w_full().gap(2.0).px(8.0).py(8.0);
    if !s.loaded {
        // The list arrives within a frame or two of unlocking; show nothing rather than a flash.
    } else if s.items.is_empty() {
        rows = rows.child(empty(
            k,
            "empty",
            "No items yet",
            "Add one with deadbolt new login.",
        ));
    } else if visible.is_empty() {
        rows = rows.child(empty(
            k,
            "no-match",
            "No matches",
            &format!("Nothing matches “{}”.", s.search.text.trim()),
        ));
    }
    for i in 0..visible.len() {
        rows = rows.child(list_row(s, k, &visible, i));
    }
    col()
        .key("list")
        .w(LIST_W)
        .h_full()
        .scroll(ScrollSpec {
            stick_bottom: false,
        })
        // No soft top/bottom edge: nested clip_fades apply the outer fade
        // widths to each row's own line (Rune bug), which washes the rows out.
        .child(rows)
}

fn empty(k: &Kit, key: &str, title: &str, body: &str) -> El {
    col()
        .key(key)
        .w_full()
        .px(12.0)
        .py(24.0)
        .gap(4.0)
        .transition(Transition::opacity())
        .child(text(title).font(k.ty.ui_medium).color(k.c.text_base))
        .child(
            text(body)
                .font(k.ty.text_small)
                .color(k.c.text_muted)
                .wrap()
                .w_full(),
        )
}

/// Row `i` of the visible items. Rows are built only here, by index, ready for a lazy list.
fn list_row(s: &App, k: &Kit, visible: &[&ItemInfo], i: usize) -> El {
    let item = visible[i];
    let selected = s.selected.as_deref() == Some(item.id.as_str());
    let id = item.id.clone();
    let mut r = col()
        .key(format!("item-{}", item.id))
        .role("option")
        .label(item.label.clone())
        .w_full()
        .px(10.0)
        .py(7.0)
        .gap(1.0)
        .radius(k.radius.md)
        .cursor(Cursor::Pointer)
        // Rows that stay slide to their new place; rows that leave or arrive fade in place.
        .motion(rune::tok::motion::REFLOW)
        .transition(
            Transition::blur(3.0)
                .combined(Transition::scale(0.96))
                .springs(rune::SpringPair::new(
                    rune::tok::motion::SETTLE,
                    rune::tok::motion::SNAP,
                )),
        )
        .on_press(move |s: &mut App| s.select(Some(id.clone())))
        .child(fade_line(
            text(item.label.clone())
                .font(k.ty.ui_medium.lh(20.0))
                .color(k.c.text_strong),
            "label",
        ));
    let sub = match &item.detail {
        Some(d) => format!("{d} · {}", item.kind),
        None => item.kind.clone(),
    };
    r = r.child(fade_line(
        text(sub).font(k.ty.small.lh(16.0)).color(k.c.text_muted),
        "sub",
    ));
    if selected {
        r.fill(k.c.surface_raised_hover)
    } else {
        r.hover(k.c.hover)
    }
}

/// One line of text that fades out at the right edge instead of ending in "…".
fn fade_line(t: El, key: &str) -> El {
    row()
        .key(key)
        .w_full()
        .shrink()
        .clip_fade(0.0, 0.0, 20.0, 0.0)
        .child(t)
}

fn detail(s: &App, k: &Kit) -> El {
    let mut pane = col()
        .key("detail")
        .grow(1.0)
        .shrink()
        .h_full()
        .px(28.0)
        .py(24.0)
        .gap(20.0);
    let Some(item) = s.selected_item() else {
        if s.loaded && !s.items.is_empty() {
            pane = pane.child(
                text("Select an item")
                    .key("none")
                    .font(k.ty.text_small)
                    .color(k.c.text_faint),
            );
        }
        return pane;
    };
    let kind = format!("{} · {}", item.kind, item.short);
    pane = pane.child(
        col()
            .key("head")
            .w_full()
            .gap(4.0)
            .child(fade_line(
                text(item.label.clone())
                    .font(TextStyle::new(20.0, 500.0).lh(26.0))
                    .color(k.c.text_strong),
                "title",
            ))
            .child(
                text(kind)
                    .key("kind")
                    .font(k.ty.text_small)
                    .color(k.c.text_muted),
            ),
    );
    let mut fields = col().key("fields").w_full().gap(2.0);
    if let Some(full) = s.detail.as_ref().filter(|d| d.id == item.id) {
        for field in &full.fields {
            fields = fields.child(field_row(s, &full.id, field, k));
        }
    }
    pane = pane.child(fields).child(spacer());
    if let Some(n) = notice(s, k) {
        pane = pane.child(n);
    }
    if let Some(n) = &s.notice {
        pane = pane.child(
            text(n.clone())
                .key("agent-notice")
                .font(k.ty.text_small)
                .color(k.c.danger.fg)
                .wrap()
                .w_full(),
        );
    }
    pane
}

fn field_row(s: &App, item: &str, field: &FieldInfo, k: &Kit) -> El {
    let secret = is_secret(&field.kind);
    let revealed = s.revealed.iter().any(|f| f == &field.name);
    let value = if secret && !revealed {
        "••••••••••••".to_owned()
    } else {
        field.value.clone()
    };
    let style = if secret {
        k.ty.mono.lh(20.0)
    } else {
        k.ty.text_small.lh(20.0)
    };
    let copied = s
        .copy
        .as_ref()
        .is_some_and(|c| c.item == item && c.field == field.name && c.cleared_at.is_none());
    let name = field.name.clone();
    let mut actions = row().key("actions").gap(2.0).center_y();
    if secret {
        let n = name.clone();
        actions = actions.child(
            IconButton::new(if revealed { &EYE_OFF } else { &EYE })
                .variant(IconButtonVariant::GhostMuted)
                .label(if revealed { "Hide" } else { "Show" })
                .on_press(move |s: &mut App| s.toggle_reveal(&n))
                .build(k)
                .key("reveal"),
        );
    }
    // The copy glyph becomes a check while this field is on the clipboard.
    let glyph = if copied {
        k.glyph.check_small
    } else {
        k.glyph.copy
    };
    let n = name.clone();
    actions = actions.child(
        IconButton::new(glyph)
            .variant(IconButtonVariant::GhostMuted)
            .label(if copied { "Copied" } else { "Copy" })
            .on_press_tx(move |s: &mut App, tx| s.copy_field(&n, tx))
            .build(k)
            .key(if copied { "copied" } else { "copy" })
            .transition(replace()),
    );
    let value = if field.kind == "note" {
        text(value).font(style).color(k.c.text_base).wrap().w_full()
    } else {
        text(value).font(style).color(k.c.text_base)
    };
    row()
        .key(format!("field-{}", field.name))
        .w_full()
        .min_h(40.0)
        .px(10.0)
        .gap(12.0)
        .center_y()
        .radius(k.radius.md)
        .hover(k.c.hover)
        .child(
            text(title_case(&field.name))
                .key("name")
                .w(84.0)
                .font(k.ty.text_small)
                .color(k.c.text_muted),
        )
        .child(
            row()
                .key("value")
                .grow(1.0)
                .shrink()
                .clip_fade(0.0, 0.0, 20.0, 0.0)
                .child(value),
        )
        .child(actions)
}

/// "Password copied · clears in 0:28", with a bar that empties; then
/// "Clipboard cleared" for a moment before it leaves.
fn notice(s: &App, k: &Kit) -> Option<El> {
    let copy = s.copy.as_ref()?;
    let mut pill = col()
        .key("copy-notice")
        .role("status")
        .w(NOTICE_W)
        .self_center()
        .padding(12.0)
        .gap(10.0)
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .transition(Transition::offset(0.0, 12.0).combined(Transition::opacity()));
    pill = rune_kit_shadows(pill, &k.elevation.floating);
    let line = if let Some(error) = &copy.error {
        row().key("failed").w_full().child(
            text(error.clone())
                .font(k.ty.text_small)
                .color(k.c.danger.fg)
                .wrap()
                .w_full(),
        )
    } else if copy.cleared_at.is_some() {
        row()
            .key("cleared")
            .w_full()
            .gap(8.0)
            .center_y()
            .transition(replace())
            .child(icon(k.glyph.check_small, 16.0).color(k.c.icon_muted))
            .child(
                text("Clipboard cleared")
                    .font(k.ty.text_small)
                    .color(k.c.text_muted),
            )
    } else {
        let left = copy.shown;
        row()
            .key("copied")
            .w_full()
            .gap(8.0)
            .center_y()
            .transition(replace())
            .child(icon(k.glyph.check_small, 16.0).color(k.c.icon_base))
            .child(
                text(format!("{} copied", copy.what))
                    .font(k.ty.ui_medium)
                    .color(k.c.text_strong),
            )
            .child(spacer())
            .child(
                text("clears in")
                    .font(k.ty.text_small)
                    .color(k.c.text_muted),
            )
            .child(
                text(format!("{}:{:02}", left / 60, left % 60))
                    .font(k.ty.text_small)
                    .color(k.c.text_base),
            )
    };
    pill = pill.child(line);
    // The bar's width follows a `Live` value the countdown sets, so ticking doesn't rebuild the view.
    pill = pill.child(
        el().key("track")
            .w(BAR_W)
            .h(2.0)
            .radius(1.0)
            .fill(k.c.layer_03)
            .child(
                el().key("bar")
                    .w(BAR_W)
                    .h(2.0)
                    .radius(1.0)
                    .fill(k.c.text_accent)
                    .live_rect(s.bar.smooth(Spring::new(0.12, 0.0))),
            ),
    );
    Some(pill)
}

fn rune_kit_shadows(mut e: El, list: &[rune::Shadow]) -> El {
    for s in list {
        e = e.box_shadow(*s);
    }
    e
}

/// Keycaps like rune-kit's `Keybind`, with ⌘ ⇧ ↵ drawn as icons.
fn keycaps(keys: &[&str], k: &Kit) -> El {
    let font = TextStyle {
        line_height: 11.0,
        ..k.ty.small_medium
    };
    let ink = k.c.text_muted;
    row()
        .role("group")
        .label(keys.join(" "))
        .gap(2.0)
        .center_y()
        .children(keys.iter().enumerate().map(|(i, key)| {
            let glyph = match *key {
                "⌘" => Some(&CMD),
                "⇧" => Some(&SHIFT),
                "↵" => Some(&ENTER),
                _ => None,
            };
            let cap = row()
                .key(format!("key{i}"))
                .min_w(14.0)
                .h(14.0)
                .px(if glyph.is_some() { 2.0 } else { 4.0 })
                .center()
                .radius(2.0)
                .fill(k.c.layer_03);
            match glyph {
                Some(g) => cap.child(icon(g, 10.0).color(ink)),
                None => cap.child(text(key.to_string()).font(font).color(ink)),
            }
        }))
}

fn hints(k: &Kit) -> El {
    let hint = |key: &str, keys: &[&str], label: &str| {
        row()
            .key(key)
            .gap(6.0)
            .center_y()
            .child(keycaps(keys, k))
            .child(
                text(label.to_owned())
                    .font(k.ty.small)
                    .color(k.c.text_muted),
            )
    };
    row()
        .key("hints")
        .w_full()
        .h(32.0)
        .px(16.0)
        .gap(16.0)
        .center_y()
        .child(hint("h-copy", &["↵"], "Copy password"))
        .child(hint("h-user", &["⇧", "↵"], "Copy username"))
        .child(hint("h-move", &["↑", "↓"], "Select"))
        .child(spacer())
        .child(hint("h-lock", &["⌘", "L"], "Lock"))
}
