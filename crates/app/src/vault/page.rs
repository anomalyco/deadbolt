//! The item's page, in the inset card: its kind's tile and a big title, then
//! its fields stacked label over value. ⇥ moves the keys into the fields
//! (`keys`), and the one they're on fills; the foot says what the keys do.
//! The import view, the form and the notices take the same place.

use deadbolt_client::protocol::{FieldInfo, ItemInfo, code_field};
use rune::{Anim, Color, Edge, El, ScrollSpec, TextStyle, Transition, col, el, row, spacer, text};
use rune_kit::{IconButton, IconButtonVariant, Keybind, Kit, RollingText};

use crate::keys::shown;
use crate::model::{App, BAR_W, CODE_BAR, Otp, field_words, group_code, is_secret, title_case};
use crate::view::{LIST_EDGE, NOTICE_W, copy_line, hint, replace};

/// The page's column: wide enough for a public key, narrow enough to read.
pub(crate) const PAGE_W: f32 = 560.0;
pub(crate) const TITLE: TextStyle = TextStyle::new(22.0, 600.0).lh(28.0);
/// A field: its label over one line of value.
const FIELD_H: f32 = 56.0;
const VALUE_LINE: f32 = 20.0;
/// How far a field's fill reaches past the column, so its words line up with the title.
const BLEED: f32 = 12.0;
/// Room at a field's end for each of its buttons.
const BUTTON_W: f32 = 30.0;

/// The page and its foot of key hints.
pub fn pane(s: &App, k: &Kit) -> El {
    col()
        .key("vault")
        .w_full()
        .min_h(0.0)
        .child(detail(s, k))
        .child(foot(s, k))
}

/// The toolbar over the page: Delete and Edit for the item, and New.
pub fn toolbar(s: &App, k: &Kit) -> El {
    let item = s.selected_item().is_some()
        && s.edit.form.is_none()
        && !s.import.showing()
        && !s.drop_hovering()
        && !s.items.is_empty();
    row()
        .key("tools")
        .gap(4.0)
        .center_y()
        .pr(4.0)
        .children(item.then(|| crate::edit::view::item_actions(s, k)))
        .child(crate::edit::view::toolbar_new(s, k))
}

fn detail(s: &App, k: &Kit) -> El {
    let pane = col()
        .key("detail")
        .w_full()
        .grow(1.0)
        .shrink()
        .min_h(0.0)
        .items_center()
        .px(40.0 - BLEED)
        .pt(4.0)
        .pb(20.0)
        .gap(20.0);
    let offer = s.loaded.then(|| crate::install::offer(s, k)).flatten();
    let shortcut = crate::shortcut::notice(s, k);
    let imported = crate::import::view::imported(s, k);
    let notices: Vec<El> = [shortcut, offer, imported, notice(s, k), agent_notice(s, k)]
        .into_iter()
        .flatten()
        .collect();
    let importing =
        s.loaded && !s.editing() && (s.import.showing() || s.drop_hovering() || s.items.is_empty());
    let body = if importing {
        // An empty vault keeps its guide, with the drop zone, until there's a preview.
        if s.items.is_empty() && s.import.preview().is_none() {
            crate::onboarding::view::empty_vault(s, k)
        } else {
            crate::import::view::pane(s, k)
        }
    } else if let Some(form) = &s.edit.form {
        crate::edit::view::form(s, k, form)
    } else {
        // One element, item or not, so leaving for the import view and coming
        // back swap whole, while a new selection (or none) replaces what's in
        // it at once.
        let item = col()
            .key("item")
            .w_full()
            .transition(crate::import::view::swap());
        match s.selected_item() {
            Some(item_info) => item.children(page(s, k, item_info)),
            None if s.loaded => item.child(
                text("Select an item")
                    .key("none")
                    .font(k.ty.text_small)
                    .color(k.c.text_faint)
                    .px(BLEED),
            ),
            None => item,
        }
    };
    // The form scrolls its own fields; the rest scroll here. The viewport
    // clips, so it pads for the fills and rings drawn past the column.
    let content = col().key("page-col").w_full().max_w(PAGE_W + 2.0 * BLEED);
    let content = if s.edit.form.is_some() && !importing {
        content.grow(1.0).shrink().min_h(0.0).px(BLEED).child(body)
    } else {
        content.grow(1.0).shrink().min_h(0.0).child(
            col()
                .key(if importing {
                    "import-scroll"
                } else {
                    "page-scroll"
                })
                .w_full()
                .grow(1.0)
                .shrink()
                .min_h(0.0)
                .px(BLEED)
                .pt(2.0)
                .scroll(ScrollSpec {
                    stick_bottom: false,
                })
                .scroll_edge_fade(LIST_EDGE)
                .child(body),
        )
    };
    pane.child(content).children((!notices.is_empty()).then(|| {
        col()
            .key("foot-notices")
            .w_full()
            .gap(20.0)
            .children(notices)
    }))
}

/// The head, a delete waiting for its answer, and the fields.
fn page(s: &App, k: &Kit, item: &ItemInfo) -> Vec<El> {
    let mut sub = crate::vault::kind_name(&item.kind).to_owned();
    if let Some(source) = &item.source {
        sub = format!("{sub} · From {source}");
    }
    let head = row()
        .key("head")
        .w_full()
        .gap(14.0)
        .center_y()
        .pb(24.0)
        .child(crate::vault::glyph_tile(k, &item.kind, 44.0, 11.0))
        .child(
            col()
                .key("titles")
                .gap(2.0)
                .grow(1.0)
                .shrink()
                .min_w(0.0)
                .child(
                    text(item.label.clone())
                        .key("title")
                        .font(TITLE)
                        .color(k.c.text_strong)
                        .truncate_fade(),
                )
                .child(
                    text(sub)
                        .key("kind")
                        .font(k.ty.text_small)
                        .color(k.c.text_muted),
                ),
        );
    let mut out = vec![head];
    if let Some(delete) = s.edit.delete.as_ref().filter(|d| d.id == item.id) {
        out.push(crate::edit::view::confirm(k, delete).mb(20.0));
    }
    let mut fields = col().key("fields").w_full().gap(2.0);
    if let Some(full) = s.detail.as_ref().filter(|d| d.id == item.id) {
        let code = code_field(&full.fields);
        let mut at = 0;
        for (i, field) in full.fields.iter().enumerate() {
            if !shown(&full.kind, &field.name) {
                continue;
            }
            let on = s.nav.field == Some(at);
            at += 1;
            let el = if code == Some(i) {
                code_row(s, &full.id, field, k, on)
            } else {
                field_row(s, &full.id, &full.kind, field, k, on)
            };
            // Notes stand apart from what you copy.
            fields = fields.child(if field.name == "notes" && at > 1 {
                el.mt(16.0)
            } else {
                el
            });
        }
    }
    out.push(fields);
    out
}

/// Whether this field of this item is on the clipboard, counting down.
fn is_copied(s: &App, item: &str, field: &str) -> bool {
    s.copy
        .as_ref()
        .is_some_and(|c| c.item == item && c.field == field && c.cleared_at.is_none())
}

/// "one-time code" is "One-time code".
fn capitalized(words: &str) -> String {
    let mut chars = words.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// A field's copy button; its glyph becomes a check while the field is on
/// the clipboard.
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

/// A field: its label over its value, with its buttons at the end, level
/// with the first line, so a value shown or hidden over more lines moves
/// neither. The one the keys are on fills.
fn field_frame(
    k: &Kit,
    name: &str,
    label: String,
    value: El,
    actions: (El, usize),
    on: bool,
) -> El {
    let (actions, buttons) = actions;
    let buttons = buttons as f32;
    col()
        .key(format!("field-{name}"))
        // A field a background refresh adds or removes fades; a new selection
        // replaces them at once (`Tx::instant`).
        .transition(Transition::opacity())
        .w_full()
        .min_h(FIELD_H)
        .ml(-BLEED)
        .mr(-BLEED)
        .px(BLEED)
        .py(8.0)
        .gap(3.0)
        .radius(10.0)
        .continuous_corners()
        .fill(if on { k.c.layer_02 } else { Color::TRANSPARENT })
        .hover(k.c.hover)
        .hover_motion(Anim::INSTANT, Anim::INSTANT)
        .child(
            text(label)
                .key("name")
                .font(k.ty.small_medium)
                .color(k.c.text_faint),
        )
        .child(value.w_full().pr(buttons * BUTTON_W))
        .child(
            actions
                .pin(None, Some(0.0), Some(BLEED - 6.0), None)
                .h(FIELD_H),
        )
}

/// The one-time code: the agent's current code in 3+3 groups, rolling to
/// the next as its period ends, beside a bar that empties over the period.
/// Each period's bar wipes in from the left. Copy copies the current code.
fn code_row(s: &App, item: &str, field: &FieldInfo, k: &Kit, on: bool) -> El {
    let otp = s.otp.as_ref().filter(|o| o.item == item);
    let style = k.ty.mono.lh(VALUE_LINE).features("'tnum' 1");
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
                        .font(TextStyle {
                            size: 15.0,
                            ..style
                        })
                        .color(k.c.text_strong)
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
                .font(k.ty.text_small.lh(VALUE_LINE))
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
    let buttons = usize::from(copyable);
    field_frame(
        k,
        &field.name,
        "One-time code".into(),
        value,
        (actions, buttons),
        on,
    )
}

fn field_row(s: &App, item: &str, kind: &str, field: &FieldInfo, k: &Kit, on: bool) -> El {
    let secret = is_secret(&field.kind);
    // The agent leaves one-time password secrets out (only the code field
    // gives a code), so there's nothing here to show or copy.
    let held = field.kind != "otp";
    let revealed = held && s.revealed.iter().any(|f| f == &field.name);
    // A key file's final line break would draw an empty last line; Copy
    // still copies it.
    let value = field.value.trim_end_matches(['\r', '\n']).to_owned();
    // Secrets and key material read in mono, where 0/O and l/1 differ.
    let style = if secret || matches!(field.name.as_str(), "public-key" | "fingerprint") {
        k.ty.mono.lh(VALUE_LINE)
    } else {
        k.ty.ui.lh(VALUE_LINE)
    };
    let name = field.name.clone();
    let named = title_case(&name);
    let noun = field_words(&name);
    let mut actions = row().key("actions").gap(2.0).center_y();
    let mut buttons = 0;
    if secret && held {
        buttons += 1;
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
    // A passkey's date is for reading; nothing pastes it anywhere.
    if held && !(kind == "passkey" && name == "created") {
        buttons += 1;
        actions = actions.child(copy_button(k, &name, &noun, is_copied(s, item, &name)));
    }
    // Shown values wrap: notes, an address, a secure note's body or a
    // private key over their lines, and a long public key, URL or base64
    // run inside itself rather than being cut off. A masked value is one line.
    let value = if secret && (!held || value.is_empty()) {
        // Nothing held to show (an otp secret the agent left out): just the mask.
        text("••••••••••••").truncate_fade()
    } else if secret {
        // A secret, hidden or shown, is a secure label: twelve dots
        // whatever its length until Show, never selectable or copyable,
        // kept out of the element tree, `Debug` and the shared caches,
        // zeroized, and masked again as it leaves (a lock's fade).
        text(value)
            .secure()
            .revealed(revealed)
            .wrap_anywhere()
            .min_w(0.0)
    } else {
        text(value).wrap_anywhere().min_w(0.0)
    };
    let value = value.key("value").font(style).color(k.c.text_base);
    field_frame(k, &name, named, value, (actions, buttons), on)
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

fn agent_notice(s: &App, k: &Kit) -> Option<El> {
    let n = s.notice.as_ref().filter(|_| s.selected_item().is_some())?;
    Some(
        text(n.clone())
            .key("agent-notice")
            .font(k.ty.text_small)
            .color(k.c.danger.fg)
            .wrap()
            .w_full()
            .max_w(PAGE_W),
    )
}

/// The page's foot: what the keys do now on the left, the way to the rest
/// on the right.
fn foot(s: &App, k: &Kit) -> El {
    let rest = s.edit.form.is_none()
        && s.edit.delete.is_none()
        && !s.import.showing()
        && !s.drop_hovering();
    row()
        .key("hints")
        .w_full()
        .h(36.0)
        .px(20.0)
        .gap(16.0)
        .center_y()
        .child(
            row()
                .key("h-keys")
                .shrink()
                .min_w(0.0)
                .pr(16.0)
                .gap(16.0)
                .center_y()
                .clip_fade(0.0, 0.0, 16.0, 0.0)
                .children(key_hints(s, k)),
        )
        .child(spacer())
        .children(rest.then(|| hint(k, "h-actions", &["⌘", "K"], "Actions")))
        .children(rest.then(|| {
            row()
                .key("h-help")
                .label("Shortcuts")
                .child(Keybind::new(&["?"]).build(k))
        }))
}

/// What ⏎ and the arrows do: the item's copies, the field's keys once ⇥
/// moved into it, or the form's and the import view's steps while they show.
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
        if let Some(f) = s.focused_field() {
            let mut hints = vec![hint("h-field-copy", &["⏎"], "Copy")];
            if is_secret(&f.kind) && f.kind != "otp" {
                let label = if s.revealed.iter().any(|r| r == &f.name) {
                    "Hide"
                } else {
                    "Show"
                };
                hints.push(hint("h-space", &["Space"], label));
            }
            hints.push(hint("h-back", &["⇥"], "Back"));
            return hints;
        }
        let mut hints: Vec<El> = s
            .enter_hint()
            .map(|label| hint("h-copy", &["⏎"], label))
            .into_iter()
            .collect();
        if s.has_username() {
            hints.push(hint("h-user", &["⇧", "⏎"], "Username"));
        }
        if crate::model::has_code(s) {
            hints.push(hint("h-code", &["⌥", "⏎"], "Code").transition(replace()));
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
