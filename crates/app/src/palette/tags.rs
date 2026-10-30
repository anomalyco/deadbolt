//! `Filter by tag…` inside `⌘K`: narrows the vault's tags and parent prefixes
//! with item counts, then writes `#<tag> ` into the search.

use deadbolt_core::tag::{fold_tag, tag_counts};
use rune::{Color, El, Key, KeyEvent, Tx, col, row, text};
use rune_kit::{Keybind, Kit, TextInput};

use crate::keys::{chord, plain};
use crate::model::App;
use crate::view::{scroll_col, tnum};

/// Tags and parent prefixes in the vault matching `s.tag_filter`, with counts.
pub fn matching_tags(s: &App) -> Vec<(String, usize)> {
    let needle = fold_tag(s.tag_filter.text.trim().trim_start_matches('#'));
    tag_counts(s.items.iter().map(|i| i.tags.iter().map(String::as_str)))
        .into_iter()
        .filter(|(tag, _)| needle.is_empty() || fold_tag(tag).contains(&needle))
        .collect()
}

impl App {
    pub fn open_tag_palette(&mut self) {
        self.nav.palette.get_or_insert(0);
        self.nav.palette_tags = true;
        self.nav.tag_row = 0;
        self.nav.sheet = false;
        self.tag_filter.clear();
        self.tag_filter.focused = true;
        self.search.focused = false;
    }

    pub fn palette_tags_filtered(&mut self) {
        self.nav.tag_row = 0;
    }

    /// Keys in `⌘K`'s tag picker (`true` when handled, `false` to let the
    /// filter input edit text).
    pub(crate) fn palette_tags_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        if chord(ev, 'k') {
            self.close_palette();
            self.search.focused = true;
            return true;
        }
        if chord(ev, 'l') {
            self.close_palette();
            self.lock();
            return true;
        }
        if ev.key == Key::Escape {
            self.nav.palette_tags = false;
            self.tag_filter.clear();
            self.tag_filter.focused = false;
            self.search.focused = true;
            return true;
        }
        let found = matching_tags(self);
        let last = found.len().saturating_sub(1);
        let at = self.nav.tag_row.min(last);
        match ev.key {
            Key::Up | Key::Down if plain(ev) && !found.is_empty() => {
                let by = if ev.key == Key::Down { 1 } else { -1 };
                let next = (at as isize + by).clamp(0, last as isize) as usize;
                self.nav.tag_row = next;
                tx.scroll_into_view(format!("palette-tag-{}", found[next].0));
                true
            }
            Key::Up | Key::Down if plain(ev) => true,
            Key::Enter if plain(ev) => {
                if let Some((tag, _)) = found.get(at) {
                    let tag = tag.clone();
                    self.close_palette();
                    self.filter_by_tag(&tag, tx);
                }
                true
            }
            _ => false,
        }
    }
}

pub fn view(s: &App, k: &Kit) -> El {
    let found = matching_tags(s);
    let active = s.nav.tag_row.min(found.len().saturating_sub(1));
    let filter = TextInput::new(&s.tag_filter)
        .plain()
        .placeholder("Filter tags")
        .leading_icon(k.glyph.search)
        .leading_icon_size(14.0)
        .width(None)
        .on_edit(|s: &mut App| &mut s.tag_filter)
        .on_change(|s: &mut App, _| s.palette_tags_filtered())
        .on_key(|s: &mut App, ev, tx| s.palette_tags_key(ev, tx))
        .build(k)
        .key("palette-tag-filter")
        .label("Filter tags");

    let mut rows = col()
        .key("palette-tag-rows")
        .role("listbox")
        .label("Tags")
        .w_full()
        .gap(1.0)
        .px(6.0)
        .pb(6.0);
    for (i, (tag, count)) in found.iter().enumerate() {
        let chosen = tag.clone();
        rows = rows.child(
            row()
                .key(format!("palette-tag-{tag}"))
                .role("option")
                .label(format!("#{tag}, {count}"))
                .w_full()
                .h(30.0)
                .px(10.0)
                .gap(8.0)
                .radius(6.0)
                .continuous_corners()
                .center_y()
                .fill(if i == active {
                    k.c.layer_03
                } else {
                    Color::TRANSPARENT
                })
                .on_hover(move |s: &mut App| s.nav.tag_row = i)
                .on_press_tx(move |s: &mut App, tx| {
                    s.close_palette();
                    s.filter_by_tag(&chosen, tx);
                })
                .child(
                    text(format!("#{tag}"))
                        .font(k.ty.ui)
                        .color(k.c.text_base)
                        .grow(1.0)
                        .shrink()
                        .min_w(0.0)
                        .truncate(),
                )
                .child(
                    text(count.to_string())
                        .font(tnum(k.ty.small))
                        .color(k.c.text_faint),
                ),
        );
    }
    if found.is_empty() {
        rows = rows.child(
            row()
                .key("palette-tag-none")
                .w_full()
                .h(30.0)
                .px(10.0)
                .center_y()
                .child(text("No matching tags").font(k.ty.ui).color(k.c.text_faint)),
        );
    }

    let card = col()
        .key("actions")
        .role("dialog")
        .label("Filter by tag")
        .w(300.0)
        .radius(12.0)
        .continuous_corners()
        .fill(k.c.surface_raised)
        .border(0.5, k.c.border_weak)
        .child(
            row()
                .key("palette-tag-head")
                .w_full()
                .h(38.0)
                .pl(10.0)
                .pr(12.0)
                .gap(8.0)
                .center_y()
                .child(filter.grow(1.0))
                .child(Keybind::new(&["esc"]).build(k)),
        )
        .child(
            scroll_col("palette-tag-scroll")
                .w_full()
                .max_h(256.0)
                .preserve_focus_on_press(true)
                .child(rows),
        );
    k.elevate(card, &k.elevation.overlay)
}
