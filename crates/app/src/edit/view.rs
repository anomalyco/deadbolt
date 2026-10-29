//! Drawing the form and the delete confirm.
//!
//! Motion: the form and the item swap whole, with the app's whole-state
//! replacement. The delete button grows into its confirm, a dim red surface,
//! on one spring (.3, no bounce) and shrinks back into it on cancel; with
//! Reduce Motion they fade in place (.2). A generated password replaces the
//! last one with the app's blur replacement. Problems, the conflict notice and
//! the nudge fade in where they show.

use rune::{El, Shadow, Spring, SpringPair, Transition, col, el, icon, row, spacer, text};
use rune_kit::{
    Button, ButtonVariant, ControlSize, IconButton, IconButtonVariant, Kit, Placement, Popover,
    SegmentedControl, State, Switch, TextArea, TextInput,
};

use super::{Conflict, Delete, Field, Form, Input, LENGTHS, editable, type_matches};
use crate::model::{App, title_case};
use crate::view::theme::{PLUS, REGENERATE, TRASH, kind_icon, kind_name};
use crate::view::{Notice, Severity};
use crate::view::{replace, reveal_button, scroll_col};

/// A shown secret's text area grows to this, then scrolls inside.
const SECRET_LINES: usize = 12;
const SECRET_MAX_H: f32 = 200.0;
/// Around the form's fields, for a focused one's edge.
const FIELD_PAD: f32 = 3.0;
/// The delete button's growth into its confirm, and back.
const GROW: Spring = Spring::new(0.3, 0.0);
/// The confirm's fade where nothing grows (Reduce Motion).
const FADE: Spring = Spring::new(0.2, 0.0);

/// The detail pane while a form is open.
pub fn form(s: &App, k: &Kit, f: &Form, layer: &mut Vec<El>) -> El {
    let mut fields = col().key("fields").w_full().gap(14.0);
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
        .transition(replace());
    // The head and the foot line up with the scroll's padded fields.
    form.child(head(s, k, f, layer).px(FIELD_PAD))
        .children(conflict(k, f))
        .children(mirrored(k, f))
        .child(
            scroll_col("form-scroll")
                .w_full()
                .grow(1.0)
                .shrink()
                .min_h(0.0)
                // Room for a focused field's edge the viewport would clip.
                .padding(FIELD_PAD)
                .child(fields),
        )
        .child(foot(k, f).px(FIELD_PAD))
}

/// The name, and the type: a picker for a new item.
fn head(s: &App, k: &Kit, f: &Form, layer: &mut Vec<El>) -> El {
    let invalid = f.problem_for("name").is_some();
    let name = TextInput::new(&f.name)
        .placeholder(if f.is_new() {
            "Name"
        } else {
            "Name (from its fields)"
        })
        .large()
        .width(None)
        .invalid(invalid)
        .on_edit(|s: &mut App| s.name_mut())
        .on_key(|s: &mut App, ev, _| s.form_key(ev, Field::Line))
        .on_change(|s: &mut App, _| s.form_changed())
        .on_submit(|s: &mut App, _| s.save());
    let name = quiet(k, name.build(k), &f.name, invalid)
        .key("name")
        .label("Name");
    let mut head = col().key("head").w_full().gap(8.0);
    if f.is_new() {
        // Spaced from the name as the fields are from each other.
        head = head.child(type_row(s, k, f, layer).mb(6.0));
    }
    head.child(name)
        .children(f.problem_for("name").map(|p| problem(k, "name-problem", p)))
}

/// The New Item form's type: one row with the type's icon, name and a
/// chevron. A press, ⌘T, Space or ⏎ opens the list of types under it, with
/// a filter field on top (`types`). Built from Rune's `Popover` and
/// `TextInput`: rune-kit's `Combobox` has no icons on its trigger or its
/// options, no keywords to match beside the label, and no way to open it
/// with the filter focused from the app.
fn type_row(s: &App, k: &Kit, f: &Form, layer: &mut Vec<El>) -> El {
    let open = s.types_open();
    let name = kind_name(&f.kind);
    let chevron = if open {
        k.glyph.chevron_up
    } else {
        k.glyph.chevron_down
    };
    let trigger = Button::new(name)
        .icon(kind_icon(&f.kind))
        .label_with(move |font, ink| {
            row()
                .gap(4.0)
                .center_y()
                .child(text(name).font(font).color(ink))
                .child(icon(chevron, 14.0).key("chevron").color(ink))
        })
        .variant(ButtonVariant::Neutral)
        .control_size(ControlSize::Regular)
        .expanded(open)
        .disabled(f.saving)
        .help("Change the type")
        .shortcut("⌘T")
        .on_press(|s: &mut App| s.toggle_types())
        .build(k)
        .key("type")
        .label(format!("Type: {name}"))
        .on_key(|s: &mut App, ev, _| {
            let plain = ev.mods == rune::Mods::default();
            if plain && ev.key == rune::Key::Enter && !s.types_open() {
                s.open_types();
                return true;
            }
            false
        });
    let popover = Popover::new("types")
        .trigger(trigger)
        .placement(Placement::BottomStart)
        .open(open && !f.saving)
        .on_close(|s: &mut App| s.close_types());
    let popover = if open && !f.saving {
        popover.child(type_list(s, k, f))
    } else {
        popover
    };
    row().key("type-row").child(popover.build(k, layer))
}

/// The list under the type row: the filter, then each matching type with
/// its icon and full name, the keys' one lit, the current one checked.
fn type_list(s: &App, k: &Kit, f: &Form) -> El {
    let types = &s.edit.types;
    let filter = TextInput::new(&types.filter)
        .width(None)
        .placeholder("Filter types")
        .on_edit(|s: &mut App| &mut s.edit.types.filter)
        .on_change(|s: &mut App, _| s.types_filtered())
        .on_key(|s: &mut App, ev, tx| s.types_key(ev, tx));
    let filter = quiet(k, filter.build(k), &types.filter, false)
        .key("type-filter")
        .label("Filter types");
    let found = type_matches(&types.filter.text);
    let active = types.active.min(found.len().saturating_sub(1));
    let mut rows = col().key("type-rows").role("listbox").w_full().gap(1.0);
    for (i, kind) in found.iter().copied().enumerate() {
        let lit = i == active;
        let check = icon(k.glyph.check_small, 14.0)
            .color(k.c.icon_base)
            .opacity(if kind == f.kind { 1.0 } else { 0.0 });
        rows = rows.child(
            row()
                .key(format!("type-{kind}"))
                .role("option")
                .label(kind_name(kind))
                .w_full()
                .h(30.0)
                .px(8.0)
                .gap(10.0)
                .center_y()
                .radius(k.radius.sm)
                .fill(if lit {
                    k.c.hover
                } else {
                    rune::Color::TRANSPARENT
                })
                .child(icon(kind_icon(kind), 16.0).color(k.c.icon_base))
                .child(
                    text(kind_name(kind))
                        .font(k.ty.ui)
                        .color(k.c.text_base)
                        .grow(1.0)
                        .shrink()
                        .truncate(),
                )
                .child(check)
                .on_hover(move |s: &mut App| s.hover_type(i))
                .on_press(move |s: &mut App| s.choose_type(kind)),
        );
    }
    if found.is_empty() {
        rows = rows.child(
            row()
                .key("type-none")
                .h(30.0)
                .px(8.0)
                .center_y()
                .child(text("No type matches").font(k.ty.ui).color(k.c.text_faint)),
        );
    }
    col()
        .key("type-list")
        .w(TYPE_LIST_W)
        .gap(8.0)
        .child(filter)
        .child(
            scroll_col("type-scroll")
                .w_full()
                .max_h(TYPE_LIST_H)
                .preserve_focus_on_press(true)
                .child(rows),
        )
}

/// The type list's width, and the height it scrolls past: nine rows and
/// half of the next, so the list says there's more.
const TYPE_LIST_W: f32 = 248.0;
const TYPE_LIST_H: f32 = 9.5 * 31.0;

/// A file field: the file's name (or none yet), Choose File… and, unless
/// it's required, Remove.
fn file_control(k: &Kit, input: &Input, i: usize, invalid: bool, saving: bool) -> El {
    let name = input.value().map(deadbolt_client::file::name);
    let shown = text(name.unwrap_or("No file chosen").to_owned())
        .key("file-name")
        .font(k.ty.ui)
        .color(if name.is_some() {
            k.c.text_base
        } else {
            k.c.text_faint
        })
        .truncate_fade()
        .grow(1.0)
        .shrink()
        .min_w(0.0);
    let mut control = row()
        .key("file")
        .w_full()
        .gap(8.0)
        .center_y()
        .padding(8.0)
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .child(shown)
        .child(
            Button::new(if name.is_some() {
                "Choose Another…"
            } else {
                "Choose File…"
            })
            .variant(ButtonVariant::Neutral)
            .control_size(ControlSize::Small)
            .disabled(saving)
            .on_press_tx(move |s: &mut App, tx| s.choose_field_file(i, tx))
            .build(k)
            .key("choose"),
        );
    if name.is_some() && !input.required {
        control = control.child(
            Button::new("Remove")
                .variant(ButtonVariant::GhostMuted)
                .control_size(ControlSize::Small)
                .disabled(saving)
                .on_press(move |s: &mut App| s.remove_file(i))
                .build(k)
                .key("remove"),
        );
    }
    if invalid {
        control = control.outline(1.0, 0.0, k.c.danger.fg);
    }
    control
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
        .transition(Transition::opacity())
        .child(crate::view::banner(k, &notice));
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

/// Editing a mirrored item: allowed, but its source wins the next sync.
fn mirrored(k: &Kit, f: &Form) -> Option<El> {
    let source = f.source().filter(|_| f.conflict.is_none())?;
    let notice = Notice {
        severity: Severity::Caution,
        title: format!("From {source}"),
        body: format!(
            "The next sync from {source} puts back its version. \
             To keep a change, make it in {source}."
        ),
    };
    Some(
        col()
            .key("mirrored")
            .w_full()
            .transition(Transition::opacity())
            .child(crate::view::banner(k, &notice)),
    )
}

fn placeholder(kind: &str, input: &Input) -> &'static str {
    if input.held {
        return "Kept · type to replace";
    }
    if input.keeps() {
        return "Kept · type or paste to replace";
    }
    match input.name.as_str() {
        "url" => "example.com",
        "expiry" => "MM/YY",
        "number" if kind == "card" => "Card number",
        "cvv" => "3 or 4 digits",
        "otp" => "otpauth:// link or secret",
        "email" => "name@example.com",
        "birthday" => "YYYY-MM-DD",
        "phone" => "+1 555 010 0100",
        "country" if kind == "identity" => "US, GB, DE…",
        "public-key" => "ssh-ed25519 AAAA…",
        "fingerprint" => "SHA256:…",
        "credential" => "Token or key",
        "port" => "5432",
        "expires" | "issued" | "purchased" if input.kind == "date" => "YYYY-MM-DD",
        "expires" | "member-since" if input.kind == "month" => "MM/YY",
        "admin-console" => "example.com/admin",
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
    let control = if input.file() {
        file_control(k, input, i, invalid, f.saving).label(named.clone())
    } else if input.lines && input.secret() {
        // A secret over several lines: hidden, one fixed row of dots, or
        // empty for a value kept (`Input::kept`); shown, the whole value,
        // wrapping and editable anywhere. Still secure either way.
        row()
            .key("secret-lines")
            .w_full()
            .gap(4.0)
            .items_start()
            .child(
                el().grow(1.0).shrink().min_w(0.0).child(
                    quiet(
                        k,
                        TextArea::new(&input.edit)
                            .secure()
                            .revealed(input.edit.is_revealed())
                            .wrap_anywhere()
                            .width(None)
                            .auto_grow(1, SECRET_LINES)
                            .max_height(SECRET_MAX_H)
                            .placeholder(placeholder(&f.kind, input))
                            .invalid(invalid)
                            .on_edit(move |s: &mut App| s.input_mut(i))
                            .on_key(move |s: &mut App, ev, tx| {
                                s.form_key(ev, Field::SecretLines) || s.copy_secret_input(i, ev, tx)
                            })
                            .on_change(|s: &mut App, _| s.form_changed())
                            .on_submit(|s: &mut App, _| s.save())
                            .build(k),
                        &input.edit,
                        invalid,
                    )
                    .label(named.clone()),
                ),
            )
            .child(secret_actions(k, input, i, false, f.saving).mt(6.0))
    } else if input.lines || input.wraps() {
        let area = TextArea::new(&input.edit)
            .wrap_anywhere()
            .width(None)
            .placeholder(placeholder(&f.kind, input))
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
        quiet(k, area.build(k), &input.edit, invalid).label(named.clone())
    } else {
        let mut t = TextInput::new(&input.edit)
            .width(None)
            .placeholder(placeholder(&f.kind, input))
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
        let built = quiet(k, t.build(k), &input.edit, invalid).label(named.clone());
        if generates {
            // Each generated password replaces the last, rather than popping in.
            el().key(format!("value-{}", f.generated))
                .w_full()
                .transition(replace())
                .child(built)
        } else {
            built
        }
    };
    let mut value = col()
        .key("value")
        .w_full()
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
    // Its name over it, as the item's page has them.
    col()
        .key(format!("field-{}", input.name))
        .w_full()
        .gap(6.0)
        .child(
            text(named)
                .key("name")
                .font(k.ty.small_medium)
                .color(k.c.text_faint),
        )
        .child(value)
}

/// A focused field keeps a neutral edge instead of the kit's blue ring;
/// the caret says where typing goes.
fn quiet(k: &Kit, field: El, edit: &rune::TextEdit, invalid: bool) -> El {
    if edit.focused && !invalid {
        field.outline(1.0, 0.0, k.c.border_strong)
    } else {
        field
    }
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
        reveal_button(k, &noun, shown)
            .control_size(ControlSize::Small)
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
        .transition(Transition::opacity())
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
                .transition(Transition::opacity()),
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

/// Edit and Delete beside the item's title (a passkey has only Delete).
/// While its confirm shows, the delete button is the confirm.
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
    if !s.selected_item().is_some_and(|i| editable(&i.kind)) {
        return actions;
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
    let body = col()
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
        )
        .children(d.error.as_deref().map(|e| problem(k, "problem", e)));
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
