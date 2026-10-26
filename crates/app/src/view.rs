//! Drawing. Every screen reads `App` and returns Rune elements; handlers call
//! into `model.rs`.
//!
//! Motion (docs/app.md has the full table): screens swap with Kit's
//! whole-state replacement (blur σ 1.5, scale .96, fade; exits shorter). A
//! search replaces the list at once, and any new selection (search, arrows,
//! a click) replaces the item's title and fields at once. Nothing animates on
//! first paint, and reduced motion keeps only fades (Rune's runtime does both).

use deadbolt_client::protocol::{FieldInfo, ItemInfo};
use rune::{
    Chrome, Cursor, Cx, Edge, El, Icon, KeyEvent, ScrollSpec, TextStyle, Transition, Tx, col, el,
    icon, row, spacer, text, text_input,
};
use rune_kit::shell::{SplitView, TOOLBAR_HEIGHT, Toolbar};
use rune_kit::{
    Button, ButtonVariant, ControlSize, IconButton, IconButtonVariant, Keybind, Kit, Placement,
    Popover, RollingText, TextInput,
};

use crate::model::{App, BAR_W, Copy, Screen, is_secret, title_case};

/// The main window: content under a transparent title bar, with the traffic
/// lights centred in the shell's 48 pt band.
pub const CHROME: Chrome = Chrome {
    full_size_content: true,
    traffic_lights: Some((16.0, 17.0)),
    drag_regions: true,
};
/// The search field in the vault's toolbar.
const SEARCH_W: f32 = 260.0;
/// How far a list's edges fade over hidden rows, and how far a row brought into view stops from them.
pub(crate) const LIST_EDGE: f32 = 24.0;
pub(crate) const NOTICE_W: f32 = BAR_W + 24.0;

fn replace() -> Transition {
    Transition::blur_replace()
}

pub fn app(s: &App, cx: &mut Cx<App>) -> El {
    if s.reduced_motion {
        cx.reduced_motion(true);
    }
    let k = rune_theme_opencode::kit(cx.system_dark());
    let inset = cx.titlebar_inset();
    let mut layer = Vec::new();
    let shell = s.screen == Screen::Vault && !s.installing();
    let screen = match &s.screen {
        Screen::Vault if s.installing() => crate::install::page(s, k, inset),
        Screen::Connecting => connecting(k),
        Screen::Onboarding => crate::onboarding::view::screen(s, k, cx.system_dark(), inset),
        Screen::Locked => unlock(s, k),
        Screen::Vault => vault(s, k, inset, &mut layer),
        Screen::Failed(message) => failed(k, message),
    };
    // The vault's shell has its own title bar; every other screen gets an
    // empty band to drag the window by, under what it draws.
    let band = (!shell).then(|| {
        el().key("titlebar")
            .pin(Some(0.0), Some(0.0), Some(0.0), None)
            .h(TOOLBAR_HEIGHT)
            .window_drag()
    });
    let root = col()
        .key("window")
        .w_full()
        .h_full()
        .fill(k.c.bg_base)
        .children(band)
        .child(screen.grow(1.0).w_full().transition(replace()))
        .children(layer);
    // An export dropped anywhere on the open vault goes straight to its preview.
    if s.accepts_drops() {
        root.on_drop_files(|s: &mut App, files, _| s.drop_files(files))
            .accepts_extensions(crate::import::EXTENSIONS)
            .on_drop_hover(|s: &mut App, over, tx| {
                tx.instant();
                s.drop_hover(over);
            })
            // Anything else is refused on the drop, with why; a drag of it
            // lights nothing, as the drop zone only lights for what it takes.
            .on_drop_rejected(|s: &mut App, files, _| s.drop_rejected(files))
    } else {
        root
    }
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

fn failed(k: &Kit, message: &str) -> El {
    centred(
        "failed",
        k,
        k.glyph.lock,
        "Can't reach Deadbolt",
        col()
            .key("body")
            .w_full()
            .gap(16.0)
            .child(muted(k, "message", message))
            .child(
                Button::new("Try again")
                    .variant(ButtonVariant::Neutral)
                    .control_size(ControlSize::Large)
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
        (Some(name), 0) => format!("Locked · {name}"),
        (Some(name), n) => format!(
            "Locked · {name} · {n} vault{}",
            if n == 1 { "" } else { "s" }
        ),
        (None, _) => "Locked. Enter your passphrase to unlock this device.".into(),
    };
    let mut body = col()
        .key("body")
        .w_full()
        .gap(12.0)
        .child(muted(k, "about", about))
        .child(passphrase_field(s, k));
    if let Some(e) = unlock_error(s, k) {
        body = body.child(e);
    }
    let label = if s.unlocking {
        "Unlocking…"
    } else {
        "Unlock"
    };
    body = body.child(
        Button::new(label)
            .variant(ButtonVariant::Contrast)
            .control_size(ControlSize::Large)
            .disabled(s.unlocking || s.passphrase.text.is_empty())
            .on_press(|s: &mut App| s.submit_unlock())
            .build(k)
            .key("unlock")
            .mt(4.0),
    );
    col().key("unlock").center().child(
        col()
            .key("panel")
            .w(320.0)
            .gap(20.0)
            .items_start()
            .child(crate::onboarding::view::wordmark(k, 28.0))
            .child(body),
    )
}

/// The passphrase field: dots, Enter unlocks, typing clears the last error.
/// In the quick panel, Escape closes the panel rather than blurring the field.
pub(crate) fn passphrase_field(s: &App, k: &Kit) -> El {
    TextInput::new(&s.passphrase)
        .placeholder("Passphrase")
        .large()
        .width(None)
        .invalid(s.unlock_error.is_some())
        .disabled(s.unlocking)
        .on_edit(|s: &mut App| &mut s.passphrase)
        .on_key(|s: &mut App, ev, tx| s.panel_shortcut(ev, tx) || s.panel_escape(ev, tx))
        .on_change(|s: &mut App, _| s.passphrase_changed())
        .on_submit(|s: &mut App, _| s.submit_unlock())
        .build(k)
        .key("passphrase")
}

pub(crate) fn unlock_error(s: &App, k: &Kit) -> Option<El> {
    let e = s.unlock_error.as_ref()?;
    Some(
        text(e.clone())
            .key("error")
            .font(k.ty.text_small)
            .color(k.c.danger.fg)
            .wrap()
            .w_full()
            .transition(Transition::opacity()),
    )
}

// -------------------------------------------------------------------------------------------
// The vault: search, list, detail.

/// Rune-kit's shell: the list as the sidebar, search and Lock in the toolbar
/// over the detail pane, and the key hints along the pane's foot.
fn vault(s: &App, k: &Kit, inset: f32, layer: &mut Vec<El>) -> El {
    let main = col()
        .key("vault")
        .w_full()
        .min_h(0.0)
        .child(detail(s, k))
        .child(el().key("rule").h(1.0).w_full().fill(k.c.border_weak))
        .child(hints(s, k, layer));
    let toolbar = Toolbar::new().leading(search(s, k)).trailing(
        IconButton::new(k.glyph.lock)
            .variant(IconButtonVariant::GhostMuted)
            .label("Lock")
            .on_press(|s: &mut App| s.lock())
            .build(k)
            .key("lock"),
    );
    SplitView::new(main)
        .sidebar(&s.sidebar, |s: &mut App| &mut s.sidebar, list(s, k))
        .toolbar(toolbar)
        .titlebar_inset(inset)
        .build(k)
}

/// Keys the search field handles before its editor; true when handled.
pub(crate) type SearchKeys = fn(&mut App, &KeyEvent, &mut Tx) -> bool;

/// The search field: typing filters the list live; `keys` takes ↑↓, Enter and Escape.
pub(crate) fn search_input(s: &App, k: &Kit, style: TextStyle, keys: SearchKeys) -> El {
    text_input(&s.search, style)
        .key("search-input")
        .label("Search items")
        .grow(1.0)
        .shrink()
        .color(k.c.text_strong)
        .placeholder(search_placeholder(s), k.c.text_faint)
        .caret(k.c.text_strong, k.alpha(k.c.text_accent, 0.3))
        .on_edit(|s: &mut App| &mut s.search)
        .on_input_key(keys)
        .on_input_change(|s: &mut App, _| s.search_changed())
}

/// The vault's search field: typing filters the list live; `search_key`
/// takes ↑↓, Enter and Escape.
///
/// Rune-kit's `TextInput` look, built here so the field itself spans the
/// box: a press on the icon or the padding lands in the field, as on its
/// text, rather than on the title bar under it (a window drag) or on a box
/// around it (a blur on the way down). Back to `TextInput` once it routes
/// those presses to its field.
fn search(s: &App, k: &Kit) -> El {
    let c = &k.c;
    let field = text_input(&s.search, k.ty.ui_compact)
        .single_line()
        .key("search-input")
        .label("Search items")
        .w_full()
        .h_full()
        .pl(30.0)
        .pr(8.0)
        .py(6.0)
        .color(c.text_base)
        .placeholder(search_placeholder(s), c.text_faint)
        .caret(c.text_base, k.selection())
        .on_edit(|s: &mut App| &mut s.search)
        .on_input_key(|s: &mut App, ev, tx| s.search_key(ev, tx))
        .on_input_change(|s: &mut App, _| s.search_changed());
    let mut search = el()
        .key("search")
        .w(SEARCH_W)
        .h(28.0)
        .radius(k.radius.md)
        .fill(c.bg_base)
        .gradient(k.light(0.06), k.light(0.02))
        .motion(k.motion.control)
        .child(field)
        .child(
            icon(k.glyph.search, 16.0)
                .key("search-icon")
                .color(c.icon_muted)
                .absolute(8.0, 6.0),
        );
    if s.search.focused {
        search = search.outline(1.0, 0.0, c.border_focus);
    } else {
        for shadow in k.shadow_layers(&k.elevation.button_neutral) {
            search = search.box_shadow(shadow);
        }
        search = search.hover(c.hover);
    }
    search
}

fn search_placeholder(s: &App) -> String {
    match s.items.len() {
        1 => "Search 1 item".to_owned(),
        n => format!("Search {n} items"),
    }
}

fn list(s: &App, k: &Kit) -> El {
    col()
        .key("list")
        .w_full()
        .h_full()
        .scroll(ScrollSpec {
            stick_bottom: false,
        })
        .scroll_edge_fade(LIST_EDGE)
        .scroll_margin(LIST_EDGE)
        .child(rows(s, k))
}

/// The visible items as rows, or why there are none. Shared by the vault and the quick panel.
pub(crate) fn rows(s: &App, k: &Kit) -> El {
    let visible = s.visible();
    let mut rows = col()
        .key("rows")
        .role("listbox")
        .label("Items")
        .w_full()
        .gap(2.0)
        .px(8.0)
        .py(8.0);
    if !s.loaded {
        // The list arrives within a frame or two of unlocking; show nothing rather than a flash.
    } else if s.items.is_empty() {
        rows = rows.child(empty(
            k,
            "empty",
            "No items yet",
            "What you add shows up here and on your other devices.",
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
    rows
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
        .px(8.0)
        .py(6.0)
        .radius(k.radius.md)
        .cursor(Cursor::Pointer)
        // A search replaces the list at once (an edit is instant: no
        // `animate_edit_layout`). Rows an agent change adds or removes fade
        // in place while the rest slide to their new places.
        .motion(rune::tok::motion::REFLOW)
        .transition(
            Transition::blur(3.0)
                .combined(Transition::scale(0.96))
                .springs(rune::SpringPair::new(
                    rune::tok::motion::SETTLE,
                    rune::tok::motion::SNAP,
                )),
        )
        // The click blurs the search; keys stay with it, so ↑↓ and ⏎ go on
        // from the clicked row. The item replaces at once, unless the import
        // view swaps back to it.
        .on_press_tx(move |s: &mut App, tx| {
            if !s.import.showing() {
                tx.instant();
            }
            s.cancel_import();
            s.select(Some(id.clone()));
            s.search.focused = true;
        })
        .child(
            text(item.label.clone())
                .key("label")
                .font(k.ty.ui_medium.lh(18.0))
                .color(k.c.text_base)
                .truncate_fade(),
        );
    let sub = match &item.detail {
        Some(d) => format!("{d} · {}", item.kind),
        None => item.kind.clone(),
    };
    r = r.child(
        text(sub)
            .key("sub")
            .font(k.ty.small.lh(16.0))
            .color(if selected {
                k.c.text_muted
            } else {
                k.c.text_faint
            })
            .truncate_fade(),
    );
    if selected {
        r.fill(k.c.pressed)
    } else {
        r.hover(k.c.hover)
    }
}

fn detail(s: &App, k: &Kit) -> El {
    let mut pane = col()
        .key("detail")
        .w_full()
        .grow(1.0)
        .shrink()
        .min_h(0.0)
        .px(28.0)
        .py(24.0)
        .gap(20.0);
    let offer = s.loaded.then(|| crate::install::offer(s, k)).flatten();
    let shortcut = crate::shortcut::notice(s, k);
    let imported = crate::import::view::imported(s, k);
    let importing = s.loaded && (s.import.showing() || s.drop_hovering() || s.items.is_empty());
    if importing {
        // An empty vault keeps its guide, with the drop zone, until there's a preview.
        let content = if s.items.is_empty() && s.import.preview().is_none() {
            crate::onboarding::view::empty_vault(s, k)
        } else {
            crate::import::view::pane(s, k)
        };
        // A notice under the drop zone can take it past a short window. The
        // viewport clips, so it pads for the rings drawn outside its content,
        // and the pane gives that padding back.
        const RING: f32 = 2.0;
        let foot: Vec<El> = [shortcut, offer, imported, notice(s, k)]
            .into_iter()
            .flatten()
            .collect();
        return pane
            .px(28.0 - RING)
            .py(24.0 - RING)
            .child(
                col()
                    .key("import-scroll")
                    .w_full()
                    .grow(1.0)
                    .shrink()
                    .min_h(0.0)
                    .padding(RING)
                    .scroll(ScrollSpec {
                        stick_bottom: false,
                    })
                    .scroll_edge_fade(LIST_EDGE)
                    .child(content),
            )
            .children(
                (!foot.is_empty())
                    .then(|| col().key("foot").w_full().px(RING).gap(20.0).children(foot)),
            );
    }
    // One element, item or not, so leaving for the import view and coming back
    // swap whole, while a new selection (or none) replaces what's in it at once.
    let item_el = || {
        col()
            .key("item")
            .w_full()
            .gap(20.0)
            .transition(crate::import::view::swap())
    };
    let Some(item) = s.selected_item() else {
        if s.loaded {
            pane = pane.child(
                item_el().child(
                    text("Select an item")
                        .key("none")
                        .font(k.ty.text_small)
                        .color(k.c.text_faint),
                ),
            );
        }
        if offer.is_some() || shortcut.is_some() || imported.is_some() {
            pane = pane
                .child(spacer())
                .children(shortcut)
                .children(offer)
                .children(imported);
        }
        return pane;
    };
    let kind = format!("{} · {}", item.kind, item.short);
    let head = col()
        .key("head")
        .w_full()
        .gap(4.0)
        .child(
            text(item.label.clone())
                .key("title")
                .font(TextStyle::new(20.0, 500.0).lh(26.0))
                .color(k.c.text_strong)
                .truncate_fade(),
        )
        .child(
            text(kind)
                .key("kind")
                .font(k.ty.text_small)
                .color(k.c.text_muted),
        );
    let mut fields = col().key("fields").w_full().gap(2.0);
    if let Some(full) = s.detail.as_ref().filter(|d| d.id == item.id) {
        for field in &full.fields {
            fields = fields.child(field_row(s, &full.id, field, k));
        }
    }
    pane = pane
        .child(item_el().child(head).child(fields))
        .child(spacer())
        .children(shortcut)
        .children(offer)
        .children(imported);
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
    let named = title_case(&name);
    let noun = if named == name.to_uppercase() {
        named.clone()
    } else {
        name.clone()
    };
    let mut actions = row().key("actions").gap(2.0).center_y();
    if secret {
        let n = name.clone();
        let glyph = if revealed {
            k.glyph.eye_off
        } else {
            k.glyph.eye
        };
        actions = actions.child(
            IconButton::new(glyph)
                .variant(IconButtonVariant::GhostMuted)
                .label(if revealed {
                    format!("Hide {noun}")
                } else {
                    format!("Show {noun}")
                })
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
            .label(if copied {
                format!("{named} copied")
            } else {
                format!("Copy {noun}")
            })
            .on_press_tx(move |s: &mut App, tx| s.copy_field(&n, tx))
            .build(k)
            .key(if copied { "copied" } else { "copy" })
            .transition(replace()),
    );
    let value = text(value).key("value").font(style).color(k.c.text_base);
    let value = if field.kind == "note" {
        value.wrap().min_w(0.0)
    } else {
        value.truncate_fade()
    };
    row()
        .key(format!("field-{}", field.name))
        // A field a background refresh adds or removes fades; a new selection
        // replaces them at once (`Tx::instant`).
        .transition(Transition::opacity())
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
        .child(value.grow(1.0).shrink())
        .child(actions)
}

/// "Copied, clears in 0:28", with a bar that empties; then "Clipboard
/// cleared" for a moment before it leaves.
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
    for shadow in k.shadow_layers(&k.elevation.floating) {
        pill = pill.box_shadow(shadow);
    }
    pill = pill.child(copy_line(k, "notice-line", Some(copy), "", true));
    // The bar empties on a linear `Tween`, so the countdown never rebuilds the view for it.
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
                    .live_rect(&copy.bar),
            ),
    );
    Some(pill)
}

/// A key and what it does, for the hint bars.
pub(crate) fn hint(k: &Kit, key: &str, keys: &[&str], label: &str) -> El {
    row()
        .key(key)
        .gap(6.0)
        .center_y()
        .child(Keybind::new(keys).build(k))
        .child(
            text(label.to_owned())
                .font(k.ty.small)
                .color(k.c.text_muted),
        )
}

/// What a copy says, in one label that rolls only the characters that
/// change: what ⏎ does ("Copy password", the panel's footer), then "Copied,
/// clears in 0:30" counting down, then "Clipboard cleared". A failed copy
/// says why on its own line, swapped by replacement; `wrap` lets it wrap (the
/// vault's notice). Shared by that notice and the quick panel's footer; `key`
/// names the line, so each keeps its own roll.
pub(crate) fn copy_line(k: &Kit, key: &str, copy: Option<&Copy>, does: &str, wrap: bool) -> El {
    if let Some(error) = copy.and_then(|c| c.error.as_ref()) {
        let message = text(error.clone())
            .font(k.ty.text_small)
            .color(k.c.danger.fg);
        let line = row().key("failed").transition(replace());
        return if wrap {
            line.w_full().child(message.wrap().w_full())
        } else {
            line.shrink().child(message.truncate())
        };
    }
    let check = |ink| {
        icon(k.glyph.check_small, 16.0)
            .key("check")
            .color(ink)
            .transition(replace())
    };
    let (lead, label, ink) = match copy {
        None => (
            Keybind::new(&["⏎"])
                .build(k)
                .key("enter")
                .transition(replace()),
            does.to_owned(),
            k.c.text_base,
        ),
        Some(copy) if copy.cleared_at.is_some() => (
            check(k.c.icon_muted),
            "Clipboard cleared".to_owned(),
            k.c.text_muted,
        ),
        Some(copy) => {
            let left = copy.shown;
            (
                check(k.c.icon_base),
                format!("Copied, clears in {}:{:02}", left / 60, left % 60),
                k.c.text_base,
            )
        }
    };
    row()
        .key(key)
        .gap(8.0)
        .center_y()
        .transition(replace())
        .child(lead)
        .child(
            // Tabular figures: the countdown's digits keep one width, so the
            // line doesn't shake as it counts.
            RollingText::new(format!("{key}-label"), label)
                .font(k.ty.small.features("'tnum' 1"))
                .color(ink)
                .from(Edge::Top)
                .build(k),
        )
}

fn hints(s: &App, k: &Kit, layer: &mut Vec<El>) -> El {
    row()
        .key("hints")
        .w_full()
        .h(32.0)
        .px(16.0)
        .gap(16.0)
        .center_y()
        // At the narrowest window the key hints give way, never Settings. Lock
        // has its button in the toolbar, so ⌘L needs no hint here.
        .child(
            row()
                .key("h-keys")
                .shrink()
                .pr(16.0)
                .gap(16.0)
                .center_y()
                .clip_fade(0.0, 0.0, 16.0, 0.0)
                .children(key_hints(s, k)),
        )
        .child(spacer())
        .children(crate::panel::window::entry(s, k))
        .child(settings(s, k, layer))
}

/// What ⏎ and the arrows do: the item's copies, or the import view's steps while it shows.
fn key_hints(s: &App, k: &Kit) -> Vec<El> {
    let hint = |key: &str, keys: &[&str], label: &str| hint(k, key, keys, label);
    if !(s.import.showing() || s.drop_hovering()) {
        return vec![
            hint("h-copy", &["⏎"], "Copy password"),
            hint("h-user", &["⇧", "⏎"], "Copy username"),
            hint("h-move", &["↑", "↓"], "Select"),
        ];
    }
    let mut hints = Vec::new();
    match &s.import.phase {
        crate::import::Phase::Preview(p) if p.new_items() > 0 => {
            hints.push(hint("h-import", &["⏎"], "Import"))
        }
        crate::import::Phase::Preview(_) => hints.push(hint("h-done", &["⏎"], "Done")),
        _ => {}
    }
    hints.push(hint("h-cancel", &["esc"], "Cancel"));
    hints
}

/// Settings in the vault's footer: the quick panel's shortcut and the
/// install page. Its popover goes in `layer`.
fn settings(s: &App, k: &Kit, layer: &mut Vec<El>) -> El {
    Popover::new("settings")
        .title("Settings")
        .open(s.settings_open)
        .placement(Placement::TopEnd)
        .trigger(
            Button::new("Settings")
                .variant(ButtonVariant::GhostMuted)
                .control_size(ControlSize::Regular)
                .on_press(|s: &mut App| {
                    if s.settings_open {
                        s.close_settings();
                    } else {
                        s.settings_open = true;
                    }
                })
                .build(k),
        )
        .on_close(|s: &mut App| s.close_settings())
        .child(
            col()
                .key("settings-body")
                .gap(12.0)
                .child(crate::shortcut::setting(s, k))
                .children(crate::install::setting(s, k)),
        )
        .build(k, layer)
}
