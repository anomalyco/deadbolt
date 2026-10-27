//! Drawing the form and the delete confirm.
//!
//! Motion: the form and the item swap whole, with the import view's
//! replacement (.3 in, .25 out). The delete button grows into its confirm, a
//! dim red surface, on one spring (.3, no bounce) and shrinks back into it on
//! cancel; with Reduce Motion they fade in place (.2). A generated password
//! replaces the last one with the app's blur replacement. Problems, the
//! conflict notice and the nudge fade in where they show.

use rune::{El, Icon, Shadow, Spring, SpringPair, Transition, col, el, row, spacer, text};
use rune_kit::{
    Button, ButtonVariant, ControlSize, IconButton, IconButtonVariant, Kit, SegmentedControl,
    State, Switch, TextArea, TextInput,
};

use super::{Conflict, Delete, Field, Form, Input, KINDS, LENGTHS};
use crate::import::view::swap;
use crate::model::{App, title_case};
use crate::onboarding::{Notice, Severity};

pub static PLUS: Icon = Icon {
    name: "deadbolt-plus",
    view: 16.0,
    body: r#"<path d="M8 3.25v9.5M3.25 8h9.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/>"#,
};

pub static TRASH: Icon = Icon {
    name: "deadbolt-trash",
    view: 16.0,
    body: r#"<path d="M2.75 4.25h10.5M6.25 4.25v-1c0-.41.34-.75.75-.75h2c.41 0 .75.34.75.75v1M4.25 4.25l.6 8.1c.04.65.58 1.15 1.23 1.15h3.84c.65 0 1.19-.5 1.23-1.15l.6-8.1" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

pub static REGENERATE: Icon = Icon {
    name: "deadbolt-regenerate",
    view: 16.0,
    body: r#"<path d="M12.75 8a4.75 4.75 0 1 1-1.39-3.36" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"/><path d="M11.75 2.25v2.5h-2.5" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

/// The field names' column, as the item's.
const LABEL_W: f32 = 84.0;
/// A shown secret's text area grows to this, then scrolls inside.
const SECRET_LINES: usize = 12;
const SECRET_MAX_H: f32 = 200.0;
const LABEL_GAP: f32 = 12.0;
/// The delete button's growth into its confirm, and back.
const GROW: Spring = Spring::new(0.3, 0.0);
/// The confirm's fade where nothing grows (Reduce Motion).
const FADE: Spring = Spring::new(0.2, 0.0);

fn fade() -> Transition {
    Transition::opacity()
}

/// The detail pane while a form is open.
pub fn form(s: &App, k: &Kit, f: &Form) -> El {
    let mut fields = col().key("fields").w_full().gap(8.0);
    for i in 0..f.fields.len() {
        fields = fields.child(field(s, k, f, i));
    }
    let form = col()
        .key("form")
        .w_full()
        .grow(1.0)
        .shrink()
        .min_h(0.0)
        .gap(16.0)
        .transition(swap());
    form.child(head(k, f))
        .children(conflict(k, f))
        .child(
            col()
                .key("form-scroll")
                .w_full()
                .grow(1.0)
                .shrink()
                .min_h(0.0)
                // Room for the focus rings the viewport would clip.
                .padding(3.0)
                .scroll(rune::ScrollSpec {
                    stick_bottom: false,
                })
                .scroll_edge_fade(crate::view::LIST_EDGE)
                .child(fields),
        )
        .child(foot(k, f))
}

/// The name, and the type: a picker for a new item.
fn head(k: &Kit, f: &Form) -> El {
    let name = TextInput::new(&f.name)
        .placeholder(if f.is_new() {
            "Name"
        } else {
            "Name (from its fields)"
        })
        .large()
        .width(None)
        .invalid(f.problem_for("name").is_some())
        .on_edit(|s: &mut App| s.name_mut())
        .on_key(|s: &mut App, ev, _| s.form_key(ev, Field::Line))
        .on_change(|s: &mut App, _| s.form_changed())
        .on_submit(|s: &mut App, _| s.save())
        .build(k)
        .key("name")
        .label("Name");
    let mut head = col().key("head").w_full().gap(8.0);
    if f.is_new() {
        let labels: Vec<String> = KINDS
            .iter()
            .map(|kind| title_case(deadbolt_client::protocol::noun(kind, 1)))
            .collect();
        let at = KINDS.iter().position(|kind| *kind == f.kind);
        let kinds = SegmentedControl::new(&labels, at)
            .fit()
            .on_pick(|s: &mut App, i, _| {
                if let Some(kind) = KINDS.get(i) {
                    s.pick_kind(kind);
                }
            });
        head = head.child(
            row()
                .key("kinds")
                .child(disable(kinds, labels.len(), f.saving).build(k)),
        );
    }
    head = head.child(name);
    if let Some(p) = f.problem_for("name") {
        head = head.child(problem(k, "name-problem", p));
    }
    head
}

/// Another device changed or deleted the item while it was open here.
fn conflict(k: &Kit, f: &Form) -> Option<El> {
    let conflict = f.conflict?;
    let notice = match conflict {
        Conflict::Changed => Notice {
            severity: Severity::Caution,
            title: "Changed on another device".into(),
            body: "Saving keeps what you changed here and their changes to the other fields."
                .into(),
        },
        Conflict::Deleted => Notice {
            severity: Severity::Caution,
            title: "Deleted on another device".into(),
            body: "Saving adds it back.".into(),
        },
    };
    let mut block = col()
        .key("conflict")
        .w_full()
        .gap(8.0)
        .transition(fade())
        .child(crate::onboarding::view::banner(k, &notice));
    if conflict == Conflict::Changed {
        block = block.child(
            row().key("theirs").child(
                Button::new("Show theirs")
                    .variant(ButtonVariant::GhostMuted)
                    .control_size(ControlSize::Small)
                    .disabled(f.saving)
                    .on_press(|s: &mut App| s.reload_edit())
                    .build(k),
            ),
        );
    }
    Some(block)
}

fn placeholder(input: &Input) -> &'static str {
    if input.held {
        return "Kept · type to replace";
    }
    if input.keeps() {
        return "Kept · type or paste to replace";
    }
    match input.name.as_str() {
        "url" => "example.com",
        "expiry" => "MM/YY",
        "number" => "Card number",
        "cvv" => "3 or 4 digits",
        "otp" => "otpauth:// link or secret",
        "email" => "name@example.com",
        "birthday" => "YYYY-MM-DD",
        "public-key" => "ssh-ed25519 AAAA…",
        "fingerprint" => "SHA256:…",
        _ if input.required => "Required",
        _ => "",
    }
}

fn field(s: &App, k: &Kit, f: &Form, i: usize) -> El {
    let input = &f.fields[i];
    let named = title_case(&input.name);
    let problem_text = f.problem_for(&input.name);
    let invalid = problem_text.is_some();
    let generates = f.generates() == Some(i);
    let control = if input.lines && input.secret() {
        // A secret over several lines: hidden, one fixed row of dots, or
        // empty for a value kept (`Input::kept`); shown, the whole value,
        // wrapping and editable anywhere. Still secure either way.
        let shown = input.edit.is_revealed();
        row()
            .key("secret-lines")
            .w_full()
            .gap(4.0)
            .items_start()
            .child(
                el().grow(1.0).shrink().min_w(0.0).child(
                    TextArea::new(&input.edit)
                        .secure()
                        .revealed(shown)
                        .wrap_anywhere()
                        .width(None)
                        .auto_grow(1, SECRET_LINES)
                        .max_height(SECRET_MAX_H)
                        .placeholder(placeholder(input))
                        .invalid(invalid)
                        .on_edit(move |s: &mut App| s.input_mut(i))
                        .on_key(move |s: &mut App, ev, tx| {
                            s.form_key(ev, Field::SecretLines) || s.copy_secret_input(i, ev, tx)
                        })
                        .on_change(|s: &mut App, _| s.form_changed())
                        .on_submit(|s: &mut App, _| s.save())
                        .build(k)
                        .label(named.clone()),
                ),
            )
            .child(secret_actions(k, input, i, false, f.saving).mt(6.0))
    } else if input.lines || input.wraps() {
        let area = TextArea::new(&input.edit)
            .wrap_anywhere()
            .width(None)
            .placeholder(placeholder(input))
            .invalid(invalid)
            .on_edit(move |s: &mut App| s.input_mut(i));
        let area = if input.lines {
            // Rune submits a plain ⏎ in a text area; here it breaks the line.
            area.auto_grow(2, 6)
                .on_key(|s: &mut App, ev, _| s.form_key(ev, Field::Lines))
                .on_change(|s: &mut App, _| s.form_changed())
                .on_submit(move |s: &mut App, _| s.break_line(i))
        } else {
            area.auto_grow(1, 4)
                .on_key(|s: &mut App, ev, _| s.form_key(ev, Field::Wrapped))
                .on_change(move |s: &mut App, _| s.wrapped_changed(i))
        };
        area.build(k).label(named.clone())
    } else {
        let mut t = TextInput::new(&input.edit)
            .width(None)
            .placeholder(placeholder(input))
            .invalid(invalid)
            .on_edit(move |s: &mut App| s.input_mut(i))
            .on_change(|s: &mut App, _| s.form_changed())
            .on_submit(|s: &mut App, _| s.save());
        if input.secret() {
            t = t
                .on_key(move |s: &mut App, ev, tx| {
                    s.form_key(ev, Field::Line) || s.copy_secret_input(i, ev, tx)
                })
                .text_style(k.ty.mono)
                .trailing(secret_actions(k, input, i, generates, f.saving));
        } else {
            t = t.on_key(|s: &mut App, ev, _| s.form_key(ev, Field::Line));
        }
        let built = t.build(k).label(named.clone());
        if generates {
            // Each generated password replaces the last, rather than popping in.
            el().key(format!("value-{}", f.generated))
                .w_full()
                .transition(crate::view::replace())
                .child(built)
        } else {
            built
        }
    };
    let mut value = col()
        .key("value")
        .grow(1.0)
        .shrink()
        .min_w(0.0)
        .gap(6.0)
        .child(control);
    // An edit keeps its password until asked for a new one; then the controls show.
    if generates && (f.is_new() || f.generated > 0) {
        value = value.child(generator(s, k, f.saving));
    }
    if let Some(p) = problem_text {
        value = value.child(problem(k, "problem", p));
    }
    row()
        .key(format!("field-{}", input.name))
        .w_full()
        .gap(LABEL_GAP)
        .items_start()
        .child(
            text(named)
                .key("name")
                .w(LABEL_W)
                // Level with the first line of the control's text.
                .mt(7.0)
                .font(k.ty.text_small)
                .color(k.c.text_muted),
        )
        .child(value)
}

/// Show or hide, and for the generated password, a new one. A value the
/// agent keeps back has nothing to show until a new one is typed.
fn secret_actions(k: &Kit, input: &Input, i: usize, generates: bool, saving: bool) -> El {
    let shown = input.edit.is_revealed();
    let noun = title_case(&input.name);
    let mut actions = row().key("actions").gap(2.0).pr(2.0).center_y();
    if generates {
        actions = actions.child(
            IconButton::new(&REGENERATE)
                .variant(IconButtonVariant::GhostMuted)
                .control_size(ControlSize::Small)
                .label("Generate a new password")
                .help("Generate a new password")
                .disabled(saving)
                .on_press(|s: &mut App| s.generate())
                .build(k)
                .key("regenerate"),
        );
    }
    if input.held && input.edit.text.is_empty() {
        return actions;
    }
    actions.child(
        IconButton::new(if shown { k.glyph.eye_off } else { k.glyph.eye })
            .variant(IconButtonVariant::GhostMuted)
            .control_size(ControlSize::Small)
            .label(if shown {
                format!("Hide {noun}")
            } else {
                format!("Show {noun}")
            })
            .disabled(saving)
            .on_press(move |s: &mut App| s.toggle_shown(i))
            .build(k)
            .key("reveal"),
    )
}

/// The generator's length and symbols; changing either generates again.
/// Neither changes while the form saves.
fn generator(s: &App, k: &Kit, saving: bool) -> El {
    let labels: Vec<String> = LENGTHS.iter().map(usize::to_string).collect();
    let at = LENGTHS.iter().position(|l| *l == s.edit.length);
    row()
        .key("generator")
        .w_full()
        .gap(12.0)
        .center_y()
        .child(
            text("Length")
                .key("length-label")
                .font(k.ty.text_small)
                .color(k.c.text_muted),
        )
        .child(
            disable(
                SegmentedControl::new(&labels, at)
                    .fit()
                    .on_pick(|s: &mut App, i, _| {
                        if let Some(length) = LENGTHS.get(i) {
                            s.set_length(*length);
                        }
                    }),
                labels.len(),
                saving,
            )
            .build(k)
            .key("length")
            .label("Password length"),
        )
        .child(spacer())
        .child(
            Switch::new(s.edit.symbols)
                .label("Symbols")
                .disabled(saving)
                .on_toggle(|s: &mut App| s.toggle_symbols())
                .build(k)
                .key("symbols"),
        )
}

/// Every segment disabled, which also drops their presses (Rune's
/// `SegmentedControl` has no `disabled` of its own).
fn disable(mut control: SegmentedControl, segments: usize, disabled: bool) -> SegmentedControl {
    if disabled {
        for i in 0..segments {
            control = control.segment_state(i, State::Disabled);
        }
    }
    control
}

fn problem(k: &Kit, key: &str, message: &str) -> El {
    text(message.to_owned())
        .key(key)
        .role("alert")
        .font(k.ty.text_small)
        .color(k.c.danger.fg)
        .wrap()
        .w_full()
        .transition(fade())
}

/// Cancel and Save, after a problem that names no field or the nudge.
fn foot(k: &Kit, f: &Form) -> El {
    let say = match &f.problem {
        Some(p) if p.field.is_none() => Some(problem(k, "form-problem", &p.message)),
        _ if f.nudge => Some(
            text("Save or cancel your changes first.")
                .key("nudge")
                .role("status")
                .font(k.ty.text_small)
                .color(k.c.text_muted)
                .wrap()
                .w_full()
                .transition(fade()),
        ),
        _ => None,
    };
    row()
        .key("foot")
        .w_full()
        .gap(8.0)
        .center_y()
        .child(row().key("say").grow(1.0).shrink().min_w(0.0).children(say))
        .child(
            Button::new("Cancel")
                .variant(ButtonVariant::GhostMuted)
                .control_size(ControlSize::Regular)
                .disabled(f.saving)
                .on_press(|s: &mut App| s.cancel_edit())
                .build(k)
                .key("cancel"),
        )
        .child(
            Button::new(if f.saving { "Saving…" } else { "Save" })
                .rolling("save-label")
                .variant(ButtonVariant::Contrast)
                .control_size(ControlSize::Regular)
                .disabled(f.saving)
                .help("Save")
                .shortcut("⌘S")
                .on_press(|s: &mut App| s.save())
                .build(k)
                .key("save"),
        )
}

/// Edit and Delete beside the item's title. While its confirm shows, the
/// delete button is the confirm.
pub fn item_actions(s: &App, k: &Kit) -> El {
    let ready = s.detail.is_some();
    let mut actions = row().key("item-actions").gap(4.0).center_y();
    if s.edit.delete.is_none() {
        actions = actions.child(
            IconButton::new(&TRASH)
                .variant(IconButtonVariant::GhostMuted)
                .label("Delete")
                .help("Delete")
                .shortcut("⌘⌫")
                .on_press(|s: &mut App| s.ask_delete())
                .build(k)
                .key("delete")
                .matched("delete")
                .motion(GROW),
        );
    }
    actions.child(
        Button::new("Edit")
            .variant(ButtonVariant::Neutral)
            .control_size(ControlSize::Regular)
            .disabled(!ready)
            .help("Edit")
            .shortcut("⌘E")
            .on_press(|s: &mut App| s.edit_selected())
            .build(k)
            .key("edit"),
    )
}

/// "Delete “GitHub”?" in place, on a dim red surface, grown from the delete button.
pub fn confirm(k: &Kit, d: &Delete) -> El {
    let red = k.c.danger.fg;
    let mut body = col()
        .key("words")
        .w_full()
        .gap(2.0)
        .child(
            text(format!("Delete “{}”?", d.label))
                .key("title")
                .font(k.ty.ui_medium)
                .color(k.c.text_strong)
                .truncate_fade(),
        )
        .child(
            text("It's deleted on all your devices.")
                .key("body")
                .font(k.ty.text_small)
                .color(k.c.text_muted)
                .wrap()
                .w_full(),
        );
    if let Some(e) = &d.error {
        body = body.child(problem(k, "problem", e));
    }
    col()
        .key("delete-confirm")
        .role("alertdialog")
        .label(format!("Delete {}?", d.label))
        .matched("delete")
        .motion(GROW)
        .transition(Transition::opacity().springs(SpringPair::new(FADE, FADE)))
        .w_full()
        .padding(12.0)
        .gap(12.0)
        .radius(k.radius.md)
        .fill(k.alpha(red, 0.10))
        .box_shadow(Shadow {
            spread: 1.0,
            color: k.alpha(red, 0.30),
            ..Shadow::default()
        })
        .child(body)
        .child(
            row()
                .key("buttons")
                .w_full()
                .gap(8.0)
                .child(spacer())
                .child(
                    Button::new("Cancel")
                        .variant(ButtonVariant::GhostMuted)
                        .disabled(d.busy)
                        .on_press(|s: &mut App| s.cancel_delete())
                        .build(k)
                        .key("cancel"),
                )
                .child(
                    Button::new(if d.busy { "Deleting…" } else { "Delete" })
                        .rolling("delete-label")
                        .variant(ButtonVariant::Danger)
                        .disabled(d.busy)
                        .on_press(|s: &mut App| s.delete_now())
                        .build(k)
                        .key("delete-now"),
                ),
        )
}

/// The toolbar's New button.
pub fn toolbar_new(s: &App, k: &Kit) -> El {
    IconButton::new(&PLUS)
        .variant(IconButtonVariant::GhostMuted)
        .label("New item")
        .help("New item")
        .shortcut("⌘N")
        .disabled(!s.loaded || s.editing())
        .on_press(|s: &mut App| s.new_item())
        .build(k)
        .key("new")
}
