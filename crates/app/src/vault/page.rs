//! The item's page, in the inset card: its kind's tile and a big title, then
//! its fields stacked label over value. ⇥ moves the keys into the fields
//! (`keys`), and the one they're on fills; the foot says what the keys do.
//! The import view, the form and the notices take the same place.

use deadbolt_client::protocol::{FieldInfo, ItemInfo};
use rune::{Anim, Color, Edge, El, TextStyle, Transition, col, el, row, spacer, text};
use rune_kit::{IconButton, IconButtonVariant, Keybind, Kit, RollingText};

use crate::model::{App, BAR_W, CODE_BAR, Otp, field_words, group_code, is_secret, title_case};
use crate::view::theme::{PAGE_W, TITLE};
use crate::view::{
    copy_line, extra_copy_hints, hint, item_fields, masked_secret, replace, reveal_button,
    scroll_col, status_pill, tnum,
};

/// A field: its label over one line of value.
const FIELD_H: f32 = 56.0;
const VALUE_LINE: f32 = 20.0;
/// How far a field's fill reaches past the column, so its words line up with the title.
const BLEED: f32 = 12.0;
/// Room at a field's end for each of its buttons.
const BUTTON_W: f32 = 30.0;

/// The page and its foot of key hints.
pub fn pane(s: &App, k: &Kit, layer: &mut Vec<El>) -> El {
    col()
        .key("vault")
        .w_full()
        .min_h(0.0)
        .child(detail(s, k, layer))
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

fn detail(s: &App, k: &Kit, layer: &mut Vec<El>) -> El {
    let offer = s.loaded.then(|| crate::install::offer(s, k)).flatten();
    let notices = [
        crate::shortcut::notice(s, k),
        offer,
        crate::import::view::imported(s, k),
        notice(s, k),
        agent_notice(s, k),
    ]
    .into_iter()
    .flatten();
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
        crate::edit::view::form(s, k, form, layer)
    } else {
        // One element, item or not, so leaving for the import view and coming
        // back swap whole, while a new selection (or none) replaces what's in
        // it at once.
        let item = col().key("item").w_full().transition(replace());
        match s.page_view() {
            Some((head, full)) => item.children(page(s, k, head, full)),
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
    let content = col()
        .key("page-col")
        .w_full()
        .max_w(PAGE_W + 2.0 * BLEED)
        .grow(1.0)
        .shrink()
        .min_h(0.0);
    let content = if s.edit.form.is_some() && !importing {
        content.px(BLEED).child(body)
    } else {
        let scroll = scroll_col(if importing {
            "import-scroll"
        } else {
            "page-scroll"
        });
        content.child(
            scroll
                .w_full()
                .grow(1.0)
                .shrink()
                .min_h(0.0)
                .px(BLEED)
                .pt(2.0)
                .child(body),
        )
    };
    col()
        .key("detail")
        .w_full()
        .grow(1.0)
        .shrink()
        .min_h(0.0)
        .items_center()
        .px(40.0 - BLEED)
        .pt(4.0)
        .pb(20.0)
        .gap(20.0)
        .child(content)
        .children(notices)
}

/// The head, a delete waiting for its answer, and the fields, if they're here.
fn page(s: &App, k: &Kit, item: &ItemInfo, full: Option<&ItemInfo>) -> Vec<El> {
    let mut sub = crate::vault::kind_name(&item.kind).to_owned();
    if let Some(source) = &item.source {
        sub = format!("{sub} · From {source}");
    }
    let tags_source = full.map_or(&item.tags, |f| &f.tags);
    let mut titles = col()
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
        );
    if !tags_source.is_empty() {
        let mut chips = row().key("tags").w_full().flex_wrap().gap(6.0).mt(6.0);
        for tag in tags_source {
            let chosen = tag.clone();
            chips = chips.child(
                row()
                    .key(format!("tag-{tag}"))
                    .role("button")
                    .label(format!("Filter by #{tag}"))
                    .h(22.0)
                    .px(8.0)
                    .center_y()
                    .radius(6.0)
                    .continuous_corners()
                    .fill(k.c.layer_02)
                    .hover(k.c.hover)
                    .hover_motion(Anim::INSTANT, Anim::INSTANT)
                    .on_press_tx(move |s: &mut App, tx| s.filter_by_tag(&chosen, tx))
                    .child(
                        text(format!("#{tag}"))
                            .font(k.ty.small)
                            .color(k.c.text_muted),
                    ),
            );
        }
        titles = titles.child(chips);
    }
    let head = row()
        .key("head")
        .w_full()
        .gap(14.0)
        .items_start()
        .pb(24.0)
        .child(crate::vault::glyph_tile(k, &item.kind, 44.0, 11.0).mt(2.0))
        .child(titles);
    let mut out = vec![head];
    if let Some(delete) = s.edit.delete.as_ref().filter(|d| d.id == item.id) {
        out.push(crate::edit::view::confirm(k, delete).mb(20.0));
    }
    let mut fields = col().key("fields").w_full().gap(2.0);
    if let Some(full) = full {
        for (at, (field, is_code)) in item_fields(full).enumerate() {
            let on = s.nav.field == Some(at);
            let el = if is_code {
                code_row(s, &full.id, field, k, on)
            } else {
                field_row(s, &full.id, &full.kind, field, k, on)
            };
            // Notes stand apart from what you copy.
            fields = fields.child(if field.name == "notes" && at > 0 {
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

/// A field's copy button; its glyph becomes a check while the field is on
/// the clipboard.
fn copy_button(k: &Kit, item: &str, name: &str, title: &str, noun: &str, copied: bool) -> El {
    let glyph = if copied {
        k.glyph.check_small
    } else {
        k.glyph.copy
    };
    let (id, n) = (item.to_owned(), name.to_owned());
    IconButton::new(glyph)
        .variant(IconButtonVariant::GhostMuted)
        .label(if copied {
            format!("{title} copied")
        } else {
            format!("Copy {noun}")
        })
        .on_press_tx(move |s: &mut App, tx| {
            // A page held over a new selection (`App::page_view`) acts on nothing.
            if s.selected.as_deref() == Some(id.as_str()) {
                s.copy_field(&n, tx);
            }
        })
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
        .child(value.w_full().pr(buttons as f32 * BUTTON_W))
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
    let style = tnum(k.ty.mono.lh(VALUE_LINE));
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
                item,
                &field.name,
                "One-time code",
                "one-time code",
                is_copied(s, item, &field.name),
            )
        }));
    field_frame(
        k,
        &field.name,
        "One-time code".into(),
        value,
        (actions, usize::from(copyable)),
        on,
    )
}

/// A file: its name, and Save… (a dialog, then the agent sends its
/// contents to write there).
fn file_row(item: &str, field: &FieldInfo, k: &Kit, on: bool) -> El {
    let name = &field.name;
    let (id, n) = (item.to_owned(), name.clone());
    let save = IconButton::new(&crate::view::theme::DOWNLOAD)
        .variant(IconButtonVariant::GhostMuted)
        .label(format!("Save {}…", field_words(name)))
        .help("Save…")
        .on_press_tx(move |s: &mut App, tx| {
            if s.selected.as_deref() == Some(id.as_str()) {
                s.save_file(&n, tx);
            }
        })
        .build(k)
        .key("save");
    let value = text(deadbolt_client::file::name(&field.value).to_owned())
        .wrap_anywhere()
        .min_w(0.0)
        .key("value")
        .font(k.ty.ui.lh(VALUE_LINE))
        .color(k.c.text_base);
    let actions = row().key("actions").gap(2.0).center_y().child(save);
    field_frame(k, name, title_case(name), value, (actions, 1), on)
}

fn field_row(s: &App, item: &str, kind: &str, field: &FieldInfo, k: &Kit, on: bool) -> El {
    if field.kind == "file" {
        return file_row(item, field, k, on);
    }
    let secret = is_secret(&field.kind);
    // The agent leaves one-time password secrets out (only the code field
    // gives a code), so there's nothing here to show or copy.
    let held = field.kind != "otp";
    let revealed = held && s.revealed.iter().any(|f| f == &field.name);
    // A key file's final line break would draw an empty last line; Copy
    // still copies it.
    let raw = field.value.trim_end_matches(['\r', '\n']);
    // Secrets and key material read in mono, where 0/O and l/1 differ.
    let style = if secret || matches!(field.name.as_str(), "public-key" | "fingerprint") {
        k.ty.mono.lh(VALUE_LINE)
    } else {
        k.ty.ui.lh(VALUE_LINE)
    };
    let name = &field.name;
    let named = title_case(name);
    let noun = field_words(name);
    let mut actions = row().key("actions").gap(2.0).center_y();
    let mut buttons = 0;
    if secret && held {
        buttons += 1;
        let (id, n) = (item.to_owned(), name.clone());
        actions = actions.child(
            reveal_button(k, &noun, revealed)
                .on_press(move |s: &mut App| {
                    if s.selected.as_deref() == Some(id.as_str()) {
                        s.toggle_reveal(&n);
                    }
                })
                .build(k)
                .key("reveal"),
        );
    }
    // A passkey's date is for reading; nothing pastes it anywhere.
    if held && !(kind == "passkey" && name == "created") {
        buttons += 1;
        actions = actions.child(copy_button(
            k,
            item,
            name,
            &named,
            &noun,
            is_copied(s, item, name),
        ));
    }
    // Shown values wrap: notes, an address, a secure note's body or a
    // private key over their lines, and a long public key, URL or base64
    // run inside itself rather than being cut off. A masked value is one
    // fixed 12-dot secure label, never copying the secret while hidden.
    let value = if secret && !(revealed && !raw.is_empty()) {
        masked_secret().min_w(0.0)
    } else if secret {
        text(raw.to_owned())
            .secure()
            .revealed(true)
            .wrap_anywhere()
            .min_w(0.0)
    } else {
        text(raw.to_owned()).wrap_anywhere().min_w(0.0)
    };
    let value = value.key("value").font(style).color(k.c.text_base);
    field_frame(k, name, named, value, (actions, buttons), on)
}

/// "Copied, clears in 0:28", with a bar that empties; then "Clipboard
/// cleared" for a moment before it leaves.
fn notice(s: &App, k: &Kit) -> Option<El> {
    let copy = s.copy.as_ref()?;
    let pill = col()
        .gap(10.0)
        .child(copy_line(k, "notice-line", Some(copy), "", true))
        // The bar empties on a linear `Tween`, so the countdown never rebuilds the view for it.
        .child(
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
    Some(status_pill(k, "copy-notice", pill))
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
            .max_w(PAGE_W)
            .transition(Transition::opacity()),
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
    let h = |key: &str, keys: &[&str], label: &str| hint(k, key, keys, label);
    if let Some(form) = &s.edit.form {
        let cancel = if form.is_new() {
            "Cancel"
        } else {
            "Cancel editing"
        };
        return vec![
            h("h-save", &["⌘", "S"], "Save"),
            h("h-cancel", &["esc"], cancel),
        ];
    }
    if s.edit.delete.is_some() {
        return vec![
            h("h-delete", &["⏎"], "Delete"),
            h("h-cancel", &["esc"], "Cancel"),
        ];
    }
    if !(s.import.showing() || s.drop_hovering()) {
        if let Some(f) = s.focused_field() {
            let copy = if f.kind == "file" { "Save…" } else { "Copy" };
            let mut hints = vec![h("h-field-copy", &["⏎"], copy)];
            if is_secret(&f.kind) && f.kind != "otp" {
                let label = if s.revealed.iter().any(|r| r == &f.name) {
                    "Hide"
                } else {
                    "Show"
                };
                hints.push(h("h-space", &["Space"], label));
            }
            hints.push(h("h-back", &["⇥"], "Back"));
            return hints;
        }
        let mut hints: Vec<El> = s
            .enter_hint()
            .map(|label| h("h-copy", &["⏎"], label))
            .into_iter()
            .collect();
        hints.extend(extra_copy_hints(s, k));
        return hints;
    }
    let mut hints = Vec::new();
    match &s.import.phase {
        crate::import::Phase::Preview(p) if p.new_items() > 0 => {
            hints.push(h("h-import", &["⏎"], "Import"))
        }
        crate::import::Phase::Preview(_) => hints.push(h("h-done", &["⏎"], "Done")),
        _ => {}
    }
    hints.push(h("h-cancel", &["esc"], "Cancel"));
    hints
}
