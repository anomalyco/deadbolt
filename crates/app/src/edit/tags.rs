//! Editing an item's tags and favorite state inside the form (`edit`).
//!
//! Current tags show as compact `#tag` chips with an `×` button (`⌫` in an
//! empty input removes the last chip). Typing in the `Tags` input offers
//! matching existing tags and parent prefixes in a quiet `Popover`; `,`, `⇥`
//! or `⏎` adds what's typed without submitting the form, while `⏎` on an empty
//! `Tags` input saves the form as usual.

use deadbolt_core::tag::{MAX_TAGS, fold_tag, normalize_tag, tag_counts};
use rune::{Anim, Color, El, Key, KeyEvent, TextEdit, Tx, col, icon, row, text};
use rune_kit::{Kit, Placement, Popover, TextInput};

use super::{Field, Form, Problem};
use crate::model::App;
use crate::view::scroll_col;

const SUGGEST_W: f32 = 248.0;
const SUGGEST_H: f32 = 6.5 * 31.0;

/// Up to 8 existing tags or parent prefixes matching what's typed in
/// `f.tag_input`, excluding tags already on the form.
pub fn suggestions(s: &App, f: &Form) -> Vec<String> {
    let raw = f.tag_input.text.trim().trim_start_matches('#');
    let needle = fold_tag(raw);
    if needle.is_empty() {
        return Vec::new();
    }
    let held = |candidate: &str| {
        let cf = fold_tag(candidate);
        f.tags.iter().any(|t| fold_tag(t) == cf)
    };
    let mut ranked: Vec<(u8, String)> =
        tag_counts(s.items.iter().map(|i| i.tags.iter().map(String::as_str)))
            .into_iter()
            .filter_map(|(tag, _)| {
                if held(&tag) {
                    return None;
                }
                let tf = fold_tag(&tag);
                let rank = if tf.starts_with(&needle) {
                    0
                } else if tf.contains(&needle) {
                    1
                } else {
                    return None;
                };
                Some((rank, tag))
            })
            .collect();
    ranked.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| fold_tag(&a.1).cmp(&fold_tag(&b.1)))
    });
    ranked.into_iter().take(8).map(|(_, t)| t).collect()
}

/// Inserts `raw` into `tags` after normalizing and deduplicating
/// case-insensitively (updating display case if already present).
pub(super) fn push_clean_tag(tags: &mut Vec<String>, raw: &str) -> Result<bool, Problem> {
    let Some(clean) = normalize_tag(raw) else {
        return Err(Problem {
            field: Some("tags".into()),
            message: "A tag is 1 to 128 characters, with non-empty / parts.".into(),
        });
    };
    let folded = fold_tag(&clean);
    if let Some(existing) = tags.iter_mut().find(|t| fold_tag(t) == folded) {
        let changed = *existing != clean;
        *existing = clean;
        tags.sort_by_key(|t| (fold_tag(t), t.clone()));
        return Ok(changed);
    }
    if tags.len() >= MAX_TAGS {
        return Err(Problem {
            field: Some("tags".into()),
            message: format!("An item can have at most {MAX_TAGS} tags."),
        });
    }
    tags.push(clean);
    tags.sort_by_key(|t| (fold_tag(t), t.clone()));
    Ok(true)
}

impl App {
    pub fn toggle_form_favorite(&mut self) {
        if let Some(form) = self.edit.form.as_mut().filter(|f| !f.saving) {
            form.favorite = !form.favorite;
            self.form_changed();
        }
    }

    pub fn tag_input_mut(&mut self) -> &mut TextEdit {
        let super::Edit { form, scratch, .. } = &mut self.edit;
        match form.as_mut().filter(|f| !f.saving) {
            Some(f) => &mut f.tag_input,
            None => {
                scratch.clear();
                scratch
            }
        }
    }

    /// Commits comma-separated segments as they're typed or pasted.
    pub fn tag_input_changed(&mut self) {
        let Some(form) = self.edit.form.as_mut().filter(|f| !f.saving) else {
            return;
        };
        form.tag_active = None;
        form.problem = None;
        form.nudge = false;
        if !form.tag_input.text.contains(',') {
            return;
        }
        let text = form.tag_input.text.clone();
        let parts: Vec<&str> = text.split(',').collect();
        let (&tail, completed) = parts.split_last().unwrap_or((&"", &[]));
        for part in completed {
            if !part.trim().trim_start_matches('#').is_empty()
                && let Err(problem) = push_clean_tag(&mut form.tags, part)
            {
                form.problem = Some(problem);
                return;
            }
        }
        let rest = tail.trim_start().to_owned();
        let end = rest.len();
        form.tag_input.replace_text(rest);
        form.tag_input.set_selection(end, end);
    }

    /// Commits whatever is currently in `form.tag_input` (or the highlighted
    /// suggestion if chosen with `↑↓`).
    pub fn commit_tag_input(&mut self) -> bool {
        let found = match self.edit.form.as_ref() {
            Some(f) if !f.saving => suggestions(self, f),
            _ => return false,
        };
        let Some(form) = self.edit.form.as_mut().filter(|f| !f.saving) else {
            return false;
        };
        let chosen = form
            .tag_active
            .and_then(|at| found.get(at).cloned())
            .unwrap_or_else(|| form.tag_input.text.clone());
        if chosen.trim().trim_start_matches('#').is_empty() {
            return false;
        }
        match push_clean_tag(&mut form.tags, &chosen) {
            Ok(_) => {
                form.tag_input.clear();
                form.tag_active = None;
                form.problem = None;
                form.nudge = false;
                true
            }
            Err(problem) => {
                form.problem = Some(problem);
                true
            }
        }
    }

    pub fn choose_tag_suggestion(&mut self, tag: &str) {
        let Some(form) = self.edit.form.as_mut().filter(|f| !f.saving) else {
            return;
        };
        match push_clean_tag(&mut form.tags, tag) {
            Ok(_) => {
                form.tag_input.clear();
                form.tag_input.focused = true;
                form.tag_active = None;
                form.problem = None;
                form.nudge = false;
            }
            Err(problem) => form.problem = Some(problem),
        }
    }

    pub fn remove_form_tag(&mut self, at: usize) {
        if let Some(form) = self.edit.form.as_mut().filter(|f| !f.saving)
            && at < form.tags.len()
        {
            form.tags.remove(at);
            form.problem = None;
            form.nudge = false;
        }
    }

    pub fn tag_key(&mut self, ev: &KeyEvent, _tx: &mut Tx) -> bool {
        let plain = ev.mods == rune::Mods::default();
        let has_text = self
            .edit
            .form
            .as_ref()
            .is_some_and(|f| !f.tag_input.text.trim().is_empty());
        if plain && ev.key == Key::Backspace {
            let empty = self
                .edit
                .form
                .as_ref()
                .is_some_and(|f| f.tag_input.text.is_empty() && !f.tags.is_empty());
            if empty {
                if let Some(last) = self.edit.form.as_ref().map(|f| f.tags.len() - 1) {
                    self.remove_form_tag(last);
                }
                return true;
            }
        }
        if has_text {
            let found = self
                .edit
                .form
                .as_ref()
                .map(|f| suggestions(self, f))
                .unwrap_or_default();
            if plain && matches!(ev.key, Key::Down | Key::Up) && !found.is_empty() {
                if let Some(form) = self.edit.form.as_mut() {
                    let len = found.len();
                    form.tag_active = Some(match (ev.key == Key::Down, form.tag_active) {
                        (true, None) => 0,
                        (false, None) => len - 1,
                        (true, Some(i)) => (i + 1) % len,
                        (false, Some(i)) => (i + len - 1) % len,
                    });
                }
                return true;
            }
            if plain && matches!(ev.key, Key::Enter | Key::Tab) {
                return self.commit_tag_input();
            }
            if plain
                && ev.key == Key::Escape
                && !found.is_empty()
                && let Some(form) = self.edit.form.as_mut()
                && form.tag_active.take().is_some()
            {
                return true;
            }
        }
        self.form_key(ev, Field::Line)
    }
}

pub fn field(s: &App, k: &Kit, f: &Form, layer: &mut Vec<El>) -> El {
    let problem_text = f.problem_for("tags");
    let invalid = problem_text.is_some();
    let found = suggestions(s, f);
    let open = f.tag_input.focused && !f.saving && !found.is_empty();

    let mut chips = row().key("tag-chips").w_full().flex_wrap().gap(6.0);
    for (i, tag) in f.tags.iter().enumerate() {
        let saving = f.saving;
        chips = chips.child(
            row()
                .key(format!("form-tag-{tag}"))
                .h(24.0)
                .pl(8.0)
                .pr(4.0)
                .gap(4.0)
                .center_y()
                .radius(6.0)
                .continuous_corners()
                .fill(k.c.layer_02)
                .child(
                    text(format!("#{tag}"))
                        .font(k.ty.small)
                        .color(k.c.text_base),
                )
                .child(
                    row()
                        .key(format!("remove-tag-{tag}"))
                        .role("button")
                        .label(format!("Remove tag {tag}"))
                        .size(18.0, 18.0)
                        .radius(4.0)
                        .center()
                        .hover(k.c.hover)
                        .hover_motion(Anim::INSTANT, Anim::INSTANT)
                        .on_press(move |s: &mut App| {
                            if !saving {
                                s.remove_form_tag(i);
                            }
                        })
                        .child(icon(k.glyph.close, 11.0).color(k.c.icon_muted)),
                ),
        );
    }

    let input = TextInput::new(&f.tag_input)
        .width(None)
        .placeholder("Add tag (work/aws)")
        .invalid(invalid)
        .disabled(f.saving)
        .on_edit(|s: &mut App| s.tag_input_mut())
        .on_change(|s: &mut App, _| s.tag_input_changed())
        .on_key(|s: &mut App, ev, tx| s.tag_key(ev, tx))
        .on_submit(|s: &mut App, _| {
            if !s.commit_tag_input() {
                s.save();
            }
        });
    let input = super::view::quiet(k, input.build(k), &f.tag_input, invalid)
        .key("tags-input")
        .label("Tags");

    let control = if open {
        let mut list = col()
            .key("tag-suggest-rows")
            .role("listbox")
            .w_full()
            .gap(1.0);
        for (i, tag) in found.iter().enumerate() {
            let lit = f.tag_active == Some(i);
            let chosen = tag.clone();
            list = list.child(
                row()
                    .key(format!("suggest-tag-{tag}"))
                    .role("option")
                    .label(format!("#{tag}"))
                    .w_full()
                    .h(30.0)
                    .px(8.0)
                    .center_y()
                    .radius(k.radius.sm)
                    .fill(if lit { k.c.hover } else { Color::TRANSPARENT })
                    .on_hover(move |s: &mut App| {
                        if let Some(form) = s.edit.form.as_mut() {
                            form.tag_active = Some(i);
                        }
                    })
                    .on_press(move |s: &mut App| s.choose_tag_suggestion(&chosen))
                    .child(
                        text(format!("#{tag}"))
                            .font(k.ty.ui)
                            .color(k.c.text_base)
                            .truncate(),
                    ),
            );
        }
        Popover::new("tag-suggestions")
            .trigger(input)
            .placement(Placement::BottomStart)
            .open(true)
            .on_close(|s: &mut App| {
                if let Some(form) = s.edit.form.as_mut() {
                    form.tag_active = None;
                }
            })
            .child(
                scroll_col("tag-suggest-scroll")
                    .w(SUGGEST_W)
                    .max_h(SUGGEST_H)
                    .preserve_focus_on_press(true)
                    .child(list),
            )
            .build(k, layer)
    } else {
        input
    };

    let mut value = col().key("tags-value").w_full().gap(8.0);
    if !f.tags.is_empty() {
        value = value.child(chips);
    }
    value = value.child(control);
    if let Some(p) = problem_text {
        value = value.child(super::view::problem(k, "tags-problem", p));
    }

    col()
        .key("field-tags")
        .w_full()
        .gap(6.0)
        .child(
            text("Tags")
                .key("name")
                .font(k.ty.small_medium)
                .color(k.c.text_faint),
        )
        .child(value)
}
