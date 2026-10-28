//! ⌘K: what you can do with the selected item, then everywhere, over the
//! page. ↑↓ move, ↵ runs, Esc or ⌘K again closes. The quick panel's has only
//! what it can do: copy, open and go to Deadbolt.

use rune::{Color, El, Key, KeyEvent, Tx, col, el, row, text};
use rune_kit::{Keybind, Kit};

use crate::model::{App, copy_label, has_code, is_secret};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Copy,
    Username,
    Code,
    Show,
    Open,
    Edit,
    Delete,
    New,
    Import,
    Settings,
    Lock,
    /// The quick panel's way to the main window.
    Window,
}

impl Action {
    pub fn key(self) -> &'static str {
        match self {
            Action::Copy => "copy",
            Action::Username => "username",
            Action::Code => "code",
            Action::Show => "show",
            Action::Open => "open",
            Action::Edit => "edit",
            Action::Delete => "delete",
            Action::New => "new",
            Action::Import => "import",
            Action::Settings => "settings",
            Action::Lock => "lock",
            Action::Window => "window",
        }
    }

    fn keys(self) -> &'static [&'static str] {
        match self {
            Action::Copy => &["↵"],
            Action::Username => &["⇧", "↵"],
            Action::Code => &["⌥", "↵"],
            Action::Show => &[],
            Action::Open => &["O"],
            Action::Edit => &["⌘", "E"],
            Action::Delete => &["⌘", "⌫"],
            Action::New => &["⌘", "N"],
            Action::Import => &["⇧", "⌘", "I"],
            Action::Settings => &["⌘", ","],
            Action::Lock => &["⌘", "L"],
            Action::Window => &[],
        }
    }
}

/// The selected item's first secret, which Show shows.
fn secret(s: &App) -> Option<(String, bool)> {
    let f = s
        .shown_fields()
        .into_iter()
        .find(|f| is_secret(&f.kind) && f.kind != "otp" && !f.value.is_empty())?;
    let shown = s.revealed.iter().any(|r| r == &f.name);
    Some((f.name.clone(), shown))
}

/// What ⌘K offers now, in order: the item's, then the window's.
pub fn actions(s: &App) -> Vec<Action> {
    let mut list = Vec::new();
    let item = s.selected_item();
    if item.is_some() {
        if s.enter_hint().is_some() {
            list.push(Action::Copy);
        }
        if s.has_username() {
            list.push(Action::Username);
        }
        if has_code(s) {
            list.push(Action::Code);
        }
        if s.panel.is_none() && secret(s).is_some() {
            list.push(Action::Show);
        }
        if s.site().is_some() {
            list.push(Action::Open);
        }
    }
    if s.panel.is_some() {
        list.push(Action::Window);
        return list;
    }
    if item.is_some_and(|i| crate::edit::editable(&i.kind)) && s.detail.is_some() {
        list.push(Action::Edit);
    }
    list.extend([Action::New, Action::Import, Action::Settings, Action::Lock]);
    if item.is_some() {
        list.push(Action::Delete);
    }
    list
}

/// What a row says.
pub fn label(s: &App, a: Action) -> String {
    match a {
        Action::Copy => s
            .selected_item()
            .map_or("Copy", |i| copy_label(&i.kind))
            .to_owned(),
        Action::Username => "Copy username".into(),
        Action::Code => "Copy one-time code".into(),
        Action::Show => match secret(s) {
            Some((name, shown)) => {
                let noun = crate::model::field_words(&name);
                format!("{} {noun}", if shown { "Hide" } else { "Show" })
            }
            None => "Show".into(),
        },
        Action::Open => match s.site() {
            Some(url) => {
                let host = url.split("://").nth(1).unwrap_or(&url);
                format!("Open {}", host.trim_end_matches('/'))
            }
            None => "Open website".into(),
        },
        Action::Edit => "Edit".into(),
        Action::Delete => "Delete…".into(),
        Action::New => "New item".into(),
        Action::Import => "Import passwords…".into(),
        Action::Settings => "Settings".into(),
        Action::Lock => "Lock".into(),
        Action::Window => "Open Deadbolt".into(),
    }
}

impl App {
    pub fn open_palette(&mut self) {
        if actions(self).is_empty() {
            return;
        }
        self.nav.palette = Some(0);
        self.nav.sheet = false;
    }

    pub fn close_palette(&mut self) {
        self.nav.palette = None;
    }

    /// Keys while ⌘K's actions are open; they take every key.
    pub(crate) fn palette_key(&mut self, ev: &KeyEvent, tx: &mut Tx) {
        let list = actions(self);
        let at = self
            .nav
            .palette
            .unwrap_or(0)
            .min(list.len().saturating_sub(1));
        let plain = !ev.mods.cmd && !ev.mods.shift && !ev.mods.alt && !ev.mods.ctrl;
        match &ev.key {
            Key::Escape => self.close_palette(),
            _ if ev.is_command('k') => self.close_palette(),
            Key::Up => self.nav.palette = Some(at.saturating_sub(1)),
            Key::Down => self.nav.palette = Some((at + 1).min(list.len().saturating_sub(1))),
            Key::Text(t) if plain && t == "k" => self.nav.palette = Some(at.saturating_sub(1)),
            Key::Text(t) if plain && t == "j" => {
                self.nav.palette = Some((at + 1).min(list.len().saturating_sub(1)));
            }
            Key::Enter if plain => {
                if let Some(a) = list.get(at) {
                    self.run(*a, tx);
                }
            }
            _ => {}
        }
    }

    /// Runs an action and closes the palette.
    pub fn run(&mut self, a: Action, tx: &mut Tx) {
        self.close_palette();
        match a {
            Action::Copy => self.copy_selected(self.primary_field(), tx),
            Action::Username => self.copy_selected("username", tx),
            Action::Code => self.copy_selected("otp", tx),
            Action::Show => {
                if let Some((name, _)) = secret(self) {
                    self.toggle_reveal(&name);
                }
            }
            Action::Open => self.open_site(tx),
            Action::Edit => self.edit_selected(),
            Action::Delete => self.ask_delete(),
            Action::New => self.new_item(),
            Action::Import => self.show_import(),
            Action::Settings => self.open_settings(),
            Action::Lock => self.lock(),
            Action::Window => self.open_main(tx),
        }
    }
}

/// The card, over whatever has the window.
pub fn view(s: &App, k: &Kit) -> Option<El> {
    let at = s.nav.palette?;
    let list = actions(s);
    let item = s.selected_item().map(|i| i.label.clone());
    let mut rows = col().key("actions-rows").w_full().gap(1.0).px(6.0).pb(6.0);
    for (i, a) in list.iter().enumerate() {
        // The window's actions stand apart from the item's.
        let apart = i > 0 && *a == Action::New;
        if apart {
            rows = rows.child(
                el().key("actions-rule")
                    .w_full()
                    .h(0.5)
                    .my(4.0)
                    .fill(k.c.border_weak),
            );
        }
        let ink = if *a == Action::Delete {
            k.c.danger.fg
        } else {
            k.c.text_base
        };
        let action = *a;
        rows = rows.child(
            row()
                .key(format!("action-{}", a.key()))
                .role("menuitem")
                .label(label(s, *a))
                .w_full()
                .h(32.0)
                .px(10.0)
                .radius(6.0)
                .continuous_corners()
                .center_y()
                .fill(if i == at {
                    k.c.layer_03
                } else {
                    Color::TRANSPARENT
                })
                .on_press_tx(move |s: &mut App, tx| s.run(action, tx))
                .child(
                    text(label(s, *a))
                        .font(k.ty.ui)
                        .color(ink)
                        .grow(1.0)
                        .truncate(),
                )
                .children((!a.keys().is_empty()).then(|| Keybind::new(a.keys()).build(k))),
        );
    }
    let mut card = col()
        .key("actions")
        .role("menu")
        .label("Actions")
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
                    text(item.unwrap_or_else(|| "Deadbolt".into()))
                        .font(k.ty.small_medium)
                        .color(k.c.text_muted)
                        .truncate(),
                ),
        )
        .child(rows);
    for shadow in k.shadow_layers(&k.elevation.overlay) {
        card = card.box_shadow(shadow);
    }
    Some(card)
}
