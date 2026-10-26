//! Drawing. Every screen reads `App` and returns Rune elements; handlers call
//! into `model.rs`.
//!
//! Motion (docs/app.md has the full table): screens swap with Kit's
//! whole-state replacement (blur σ 1.5, scale .96, fade; exits shorter). A
//! search replaces the list at once, and any new selection (search, arrows,
//! a click) replaces the item's title and fields at once. Nothing animates on
//! first paint, and reduced motion keeps only fades (Rune's runtime does both).

use deadbolt_client::protocol::{FieldInfo, ItemInfo, code_field, noun};
use rune::{
    Chrome, Cx, Edge, El, Icon, ScrollSpec, TextEdit, TextStyle, Transition, col, el, icon, row,
    spacer, text,
};
use rune_kit::shell::{Page, SidebarRow, SplitView, Toolbar};
use rune_kit::{
    Button, ButtonVariant, ControlSize, IconButton, IconButtonVariant, Keybind, Kit, Placement,
    Popover, RollingText, Switch, TextInput,
};

use crate::model::{
    App, BAR_W, CODE_BAR, Copy, Otp, Screen, field_words, group_code, is_secret, title_case,
};

/// The main window: content under a transparent title bar, with the traffic
/// lights centred in the shell's 48 pt band.
pub const CHROME: Chrome = Chrome {
    full_size_content: true,
    traffic_lights: Some((16.0, 17.0)),
    drag_regions: true,
};
/// The search field in the vault's toolbar.
const SEARCH_W: f32 = 260.0;
/// A list row: the item's label over its detail and kind.
const ROW_H: f32 = 46.0;
/// How far a list's edges fade over hidden rows, and how far a row brought into view stops from them.
pub(crate) const LIST_EDGE: f32 = 24.0;
/// An item's field row, one line high, and its value's line.
const FIELD_H: f32 = 40.0;
const VALUE_LINE: f32 = 20.0;
pub(crate) const NOTICE_W: f32 = BAR_W + 24.0;

pub(crate) fn replace() -> Transition {
    Transition::blur_replace()
}

pub fn app(s: &App, cx: &mut Cx<App>) -> El {
    if s.reduced_motion {
        cx.reduced_motion(true);
    }
    let k = rune_theme_opencode::kit(cx.system_dark());
    let inset = cx.titlebar_inset();
    let mut layer = Vec::new();
    let screen = match &s.screen {
        Screen::Vault if !s.installing() => vault(s, k, inset, &mut layer),
        Screen::Vault => page(k, inset, crate::install::page(s, k)),
        Screen::Connecting => page(k, inset, connecting(k).into()),
        Screen::Onboarding => page(
            k,
            inset,
            crate::onboarding::view::screen(s, k, cx.system_dark()),
        ),
        Screen::Locked => page(k, inset, unlock(s, k).into()),
        Screen::Failed(message) => page(k, inset, failed(k, message).into()),
    };
    let root = col()
        .key("window")
        .w_full()
        .h_full()
        .fill(k.c.bg_deep)
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

/// A screen other than the vault: what its page holds, and the button in its
/// title bar (Back or Cancel).
pub struct Paged {
    pub body: El,
    pub back: Option<El>,
}

impl From<El> for Paged {
    fn from(body: El) -> Paged {
        Paged { body, back: None }
    }
}

/// The frame and title bar of the vault's shell, for every other screen.
/// Within it, one screen replaces the next.
fn page(k: &Kit, inset: f32, p: Paged) -> El {
    let mut page = Page::new(p.body.grow(1.0).w_full().transition(replace())).titlebar_inset(inset);
    if let Some(back) = p.back {
        page = page.leading(back.transition(Transition::opacity()));
    }
    el().key("page").w_full().h_full().child(page.build(k))
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
    let unlock_button = Button::new(label)
        .variant(ButtonVariant::Contrast)
        .control_size(ControlSize::Large)
        .disabled(s.unlocking || s.passphrase.text.is_empty())
        .on_press(|s: &mut App| s.submit_unlock())
        .build(k)
        .key("unlock");
    body = if s.touch_id_ready() {
        let touch_label = if s.touch_id_unlocking {
            "Touch ID…"
        } else {
            "Use Touch ID"
        };
        body.child(
            row()
                .key("actions")
                .w_full()
                .gap(8.0)
                .center_y()
                .mt(4.0)
                .motion(k.motion.control)
                .child(unlock_button.grow(1.0))
                .child(
                    Button::new(touch_label)
                        .variant(ButtonVariant::Neutral)
                        .control_size(ControlSize::Large)
                        .disabled(s.busy_unlocking())
                        .on_press(|s: &mut App| s.unlock_touch_id())
                        .build(k)
                        .key("touch-id")
                        .grow(1.0),
                ),
        )
    } else {
        body.child(unlock_button.mt(4.0))
    };
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

/// Shown when the enrolled Touch ID slot was wiped (expired, fingerprint set
/// changed, or passphrase changed).
pub const TOUCH_ID_RESET: &str = "Touch ID was reset; enter your passphrase.";

/// Shown when Touch ID is enabled in `config.toml` before a biometric slot has
/// ever been enrolled.
pub const TOUCH_ID_FINISH_SETUP: &str = "Enter your passphrase once to finish turning on Touch ID.";

pub(crate) fn unlock_error(s: &App, k: &Kit) -> Option<El> {
    if let Some(e) = &s.unlock_error {
        return Some(
            text(e.clone())
                .key("error")
                .font(k.ty.text_small)
                .color(k.c.danger.fg)
                .wrap()
                .w_full()
                .transition(Transition::opacity()),
        );
    }
    if s.touch_id_reset() {
        return Some(
            text(TOUCH_ID_RESET)
                .key("touch-id-reset")
                .font(k.ty.text_small)
                .color(k.c.text_muted)
                .wrap()
                .w_full()
                .transition(Transition::opacity()),
        );
    }
    if s.touch_id_enabled() && !s.touch_id_ready() {
        return Some(
            text(TOUCH_ID_FINISH_SETUP)
                .key("touch-id-finish")
                .font(k.ty.text_small)
                .color(k.c.text_muted)
                .wrap()
                .w_full()
                .transition(Transition::opacity()),
        );
    }
    None
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
    let toolbar = Toolbar::new()
        .leading(search(s, k))
        .trailing(crate::edit::view::toolbar_new(s, k))
        .trailing(
            IconButton::new(k.glyph.lock)
                .variant(IconButtonVariant::GhostMuted)
                .help("Lock")
                .shortcut("⌘L")
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

/// The vault's search field: typing filters the list live; `search_key`
/// takes ↑↓, Enter and Escape. A press anywhere in its box, the icon too,
/// lands in the field.
fn search(s: &App, k: &Kit) -> El {
    TextInput::new(&s.search)
        .placeholder(search_placeholder(s))
        .leading_icon(k.glyph.search)
        .width(Some(SEARCH_W))
        .on_edit(|s: &mut App| &mut s.search)
        .on_key(|s: &mut App, ev, tx| s.search_key(ev, tx))
        .on_change(|s: &mut App, _| s.search_changed())
        .build(k)
        .key("search")
        .label("Search items")
}

pub(crate) fn search_placeholder(s: &App) -> String {
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
    let id = item.id.clone();
    // A secure note has no detail: its body never shows in the list.
    let kind = noun(&item.kind, 1);
    let sub = match &item.detail {
        Some(d) => format!("{d} · {kind}"),
        None => kind.to_owned(),
    };
    SidebarRow::new(item.label.clone())
        .subtitle(sub)
        .height(ROW_H)
        .selected(s.selected.as_deref() == Some(item.id.as_str()))
        // The keys stay with the search: rows take no focus (Tab, Space), and
        // a press selects while the search keeps focus.
        .select_only()
        // The item replaces at once, unless the import view swaps back to it.
        .on_select(move |s: &mut App, tx| {
            if s.panel_inert() {
                return;
            }
            // The item being edited stays as it is, focus and all.
            if s.edit.form.as_ref().and_then(|f| f.id.as_deref()) == Some(id.as_str()) {
                return;
            }
            // A form giving way keeps its exit; otherwise the item replaces at once.
            let was_editing = s.editing();
            if !s.leave_edit() {
                return;
            }
            // Focus somewhere else (nothing, Lock) comes back to the search.
            s.search.focused = true;
            if !s.import.showing() && !was_editing {
                tx.instant();
            }
            s.cancel_import();
            s.select(Some(id.clone()));
        })
        .build(k)
        .key(format!("item-{}", item.id))
        .role("option")
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
    let importing =
        s.loaded && !s.editing() && (s.import.showing() || s.drop_hovering() || s.items.is_empty());
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
    if let Some(form) = &s.edit.form {
        return pane.child(crate::edit::view::form(s, k, form));
    }
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
    let mut kind = format!("{} · {}", noun(&item.kind, 1), item.short);
    if let Some(source) = &item.source {
        kind = format!("{kind} · From {source}");
    }
    let titles = col()
        .key("titles")
        .grow(1.0)
        .shrink()
        .min_w(0.0)
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
    let mut head = col().key("head").w_full().gap(12.0).child(
        row()
            .key("head-row")
            .w_full()
            .gap(12.0)
            .items_start()
            .child(titles)
            .child(crate::edit::view::item_actions(s, k)),
    );
    if let Some(delete) = s.edit.delete.as_ref().filter(|d| d.id == item.id) {
        head = head.child(crate::edit::view::confirm(k, delete));
    }
    let mut fields = col().key("fields").w_full().gap(2.0);
    if let Some(full) = s.detail.as_ref().filter(|d| d.id == item.id) {
        let code = code_field(&full.fields);
        for (i, field) in full.fields.iter().enumerate() {
            fields = fields.child(if code == Some(i) {
                code_row(s, &full.id, field, k)
            } else {
                field_row(s, &full.id, field, k)
            });
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

/// Whether this field of this item is on the clipboard, counting down.
fn is_copied(s: &App, item: &str, field: &str) -> bool {
    s.copy
        .as_ref()
        .is_some_and(|c| c.item == item && c.field == field && c.cleared_at.is_none())
}

/// A field's copy button; its glyph becomes a check while the field is on
/// the clipboard.
/// "one-time code" is "One-time code".
fn capitalized(words: &str) -> String {
    let mut chars = words.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn copy_button(k: &Kit, name: &str, noun: &str, copied: bool) -> El {
    let glyph = if copied {
        k.glyph.check_small
    } else {
        k.glyph.copy
    };
    let n = name.to_owned();
    IconButton::new(glyph)
        .variant(IconButtonVariant::GhostMuted)
        .label(if copied {
            format!("{} copied", capitalized(noun))
        } else {
            format!("Copy {noun}")
        })
        .on_press_tx(move |s: &mut App, tx| s.copy_field(&n, tx))
        .build(k)
        .key(if copied { "copied" } else { "copy" })
        .transition(replace())
}

/// A field row's frame: its name, then the value and the actions.
/// How a field's value sits in its row.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// One line, centred.
    Line,
    /// A value that may wrap or span lines (a public key, a URL, a note):
    /// its name and buttons stay level with the first line, so a value
    /// shown or hidden doesn't move them.
    Wraps,
}

fn field_frame(k: &Kit, name: &str, label: String, value: El, actions: El, frame: Frame) -> El {
    let label = text(label)
        .key("name")
        .w(104.0)
        .font(k.ty.text_small)
        .color(k.c.text_muted);
    let (row, label, value, actions) = match frame {
        Frame::Line => (row().center_y(), label, value, actions),
        // Laid out as `Line` while it fits on one line.
        Frame::Wraps => (
            row().items_start(),
            label.mt((FIELD_H - k.ty.text_small.line_px()) / 2.0),
            value.py((FIELD_H - VALUE_LINE) / 2.0),
            actions.h(FIELD_H),
        ),
    };
    row.key(format!("field-{name}"))
        // A field a background refresh adds or removes fades; a new selection
        // replaces them at once (`Tx::instant`).
        .transition(Transition::opacity())
        .w_full()
        .min_h(FIELD_H)
        .px(10.0)
        .gap(12.0)
        .radius(k.radius.md)
        .hover(k.c.hover)
        .child(label)
        .child(value.grow(1.0).shrink())
        .child(actions)
}

/// The one-time code: the agent's current code in 3+3 groups, rolling to
/// the next as its period ends, beside a bar that empties over the period.
/// Each period's bar wipes in from the left. Copy copies the current code.
fn code_row(s: &App, item: &str, field: &FieldInfo, k: &Kit) -> El {
    let otp = s.otp.as_ref().filter(|o| o.item == item);
    let style = k.ty.mono.lh(20.0).features("'tnum' 1");
    let value = match (otp.and_then(|o| o.code.as_ref()), otp) {
        (Some(code), Some(otp)) => {
            let [w, h] = CODE_BAR;
            let bar = el()
                .key(format!("code-bar-{}", otp.turns))
                .w(w)
                .h(h)
                .radius(h / 2.0)
                .fill(k.c.text_accent)
                .live_rect(&otp.bar)
                .transition(Transition::reveal(Edge::Leading));
            row()
                .key("value")
                .gap(12.0)
                .center_y()
                .child(
                    RollingText::new(format!("code-{item}"), group_code(code))
                        .font(style)
                        .color(k.c.text_base)
                        .from(Edge::Bottom)
                        .build(k),
                )
                .child(
                    el().key("code-track")
                        .w(w)
                        .h(h)
                        .radius(h / 2.0)
                        .fill(k.c.layer_03)
                        .child(bar),
                )
        }
        (
            None,
            Some(Otp {
                error: Some(error), ..
            }),
        ) => row().key("value").child(
            text(format!("No code: {error}"))
                .key("code-error")
                .font(k.ty.text_small.lh(20.0))
                .color(k.c.danger.fg)
                .truncate_fade(),
        ),
        _ => row().key("value").child(
            text("••• •••")
                .key("code-waiting")
                .font(style)
                .color(k.c.text_faint),
        ),
    };
    let copyable = otp.is_some_and(|o| o.error.is_none());
    let actions = row()
        .key("actions")
        .gap(2.0)
        .center_y()
        .children(copyable.then(|| {
            copy_button(
                k,
                &field.name,
                "one-time code",
                is_copied(s, item, &field.name),
            )
        }));
    field_frame(
        k,
        &field.name,
        "One-time code".into(),
        value,
        actions,
        Frame::Line,
    )
}

fn field_row(s: &App, item: &str, field: &FieldInfo, k: &Kit) -> El {
    let secret = is_secret(&field.kind);
    // The agent leaves one-time password secrets out (only the code field
    // gives a code), so there's nothing here to show or copy.
    let held = field.kind != "otp";
    let revealed = held && s.revealed.iter().any(|f| f == &field.name);
    let masked = secret && !revealed;
    // A key file's final line break would draw an empty last line; Copy
    // still copies it.
    let value = if masked {
        "••••••••••••".to_owned()
    } else {
        field.value.trim_end_matches(['\r', '\n']).to_owned()
    };
    // Secrets and key material read in mono, where 0/O and l/1 differ.
    let style = if secret || matches!(field.name.as_str(), "public-key" | "fingerprint") {
        k.ty.mono.lh(VALUE_LINE)
    } else {
        k.ty.text_small.lh(VALUE_LINE)
    };
    let name = field.name.clone();
    let named = title_case(&name);
    let noun = field_words(&name);
    let mut actions = row().key("actions").gap(2.0).center_y();
    if secret && held {
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
    if held {
        actions = actions.child(copy_button(k, &name, &noun, is_copied(s, item, &name)));
    }
    // Shown values wrap: notes, an address, a secure note's body or a
    // private key over their lines, and a long public key, URL or base64
    // run inside itself rather than being cut off. A masked value is one line.
    let value = if masked {
        text(value).truncate_fade()
    } else if secret {
        // A shown secret is drawn through Rune's secure path, never as
        // text: kept out of the element tree, `Debug` and the shared layout
        // cache, zeroized, and masked again as it leaves (a lock's fade).
        // Read-only: it takes no presses, focus or keys.
        let mut edit = TextEdit::new(value);
        edit.set_secure(true);
        edit.set_revealed(true);
        rune::text_input(&edit, style)
            .wrap_anywhere()
            .min_w(0.0)
            .inert()
    } else {
        text(value).wrap_anywhere().min_w(0.0)
    };
    let value = value.key("value").font(style).color(k.c.text_base);
    field_frame(k, &name, named, value, actions, Frame::Wraps)
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
    if let Some(form) = &s.edit.form {
        let mut hints = vec![hint("h-save", &["⌘", "S"], "Save")];
        if form.is_new() {
            hints.push(hint("h-cancel", &["esc"], "Cancel"));
        } else {
            hints.push(hint("h-cancel", &["esc"], "Cancel editing"));
        }
        return hints;
    }
    if s.edit.delete.is_some() {
        return vec![
            hint("h-delete", &["⏎"], "Delete"),
            hint("h-cancel", &["esc"], "Cancel"),
        ];
    }
    if !(s.import.showing() || s.drop_hovering()) {
        let mut hints: Vec<El> = s
            .enter_hint()
            .map(|label| hint("h-copy", &["⏎"], label))
            .into_iter()
            .collect();
        if s.has_username() {
            hints.push(hint("h-user", &["⇧", "⏎"], "Copy username"));
        }
        if crate::model::has_code(s) {
            hints.push(hint("h-code", &["⌥", "⏎"], "Copy code").transition(replace()));
        }
        // Four don't fit: ⌥⏎ takes ↑↓'s place.
        if hints.len() < 3 {
            hints.push(hint("h-move", &["↑", "↓"], "Select").transition(replace()));
        }
        return hints;
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
                .children(touch_id_setting(s, k))
                .child(crate::shortcut::setting(s, k))
                .child(crate::mirror::setting(s, k))
                .children(crate::install::setting(s, k)),
        )
        .build(k, layer)
}

fn touch_id_setting(s: &App, k: &Kit) -> Option<El> {
    if !s.touch_id_available() {
        return None;
    }
    let mut section = col().key("touch-id-setting").w(240.0).gap(6.0).child(
        row()
            .key("touch-id-row")
            .w_full()
            .center_y()
            .child(
                text("Unlock with Touch ID")
                    .key("touch-id-label")
                    .font(k.ty.text_small)
                    .color(k.c.text_base)
                    .grow(1.0),
            )
            .child(
                Switch::new(s.touch_id_enabled())
                    .label("Unlock with Touch ID")
                    .hide_label()
                    .disabled(s.touch_id_busy)
                    .on_toggle(|s: &mut App| s.toggle_touch_id())
                    .build(k)
                    .key("touch-id-switch"),
            ),
    );
    if let Some(error) = &s.touch_id_error {
        section = section.child(
            text(error.clone())
                .key("touch-id-error")
                .font(k.ty.small_medium)
                .color(k.c.danger.fg)
                .wrap()
                .w_full()
                .transition(Transition::opacity()),
        );
    }
    Some(section)
}
