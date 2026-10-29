//! ⌘, Settings: a page in the item's place, as Seer's, while the sidebar
//! stays. Rows are a label over a faint line with the control at the end,
//! grouped with room between groups; ↑↓ or J K move between rows, ↵ or Space
//! change one (←→ step the clear-after time), Esc leaves. Under them, every
//! shortcut.

use rune::{Color, El, Key, KeyEvent, Transition, Tx, col, el, row, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Kit, Switch};

use crate::model::App;
use crate::vault::FACT;
use crate::vault::page::{PAGE_W, TITLE};

/// How long a copied secret may stay on the clipboard, in seconds.
const CLEAR_STEPS: [f64; 6] = [10.0, 20.0, 30.0, 60.0, 90.0, 120.0];

/// A row the keys can be on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Row {
    TouchId,
    Clear,
    Shortcut,
    Command,
    Sync,
    Agents,
    Activity,
}

/// The rows the page shows, in order.
pub fn rows(s: &App) -> Vec<Row> {
    let mut rows = Vec::new();
    if s.touch_id_available() {
        rows.push(Row::TouchId);
    }
    rows.push(Row::Clear);
    rows.push(Row::Shortcut);
    if s.installer.is_some() {
        rows.push(Row::Command);
    }
    rows.push(Row::Sync);
    rows.push(Row::Agents);
    rows.push(Row::Activity);
    rows
}

impl App {
    /// The keys while Settings shows (`overlay_key`): they never reach the
    /// vault behind it.
    pub(crate) fn settings_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        // Recording: a focused recorder took the keys already; otherwise ↵
        // started it, and the keys record here.
        if self.hotkey.recorder.is_recording() {
            self.record_key(ev, tx);
            return true;
        }
        let rows = rows(self);
        let at = self.nav.row.min(rows.len().saturating_sub(1));
        let plain = !ev.mods.cmd && !ev.mods.shift && !ev.mods.alt && !ev.mods.ctrl;
        let letter = |c: &str| plain && matches!(&ev.key, Key::Text(t) if t == c);
        match &ev.key {
            Key::Escape => {
                self.close_settings();
                self.search.focused = true;
            }
            Key::Up => self.nav.row = at.saturating_sub(1),
            Key::Down => self.nav.row = (at + 1).min(rows.len().saturating_sub(1)),
            _ if letter("k") => self.nav.row = at.saturating_sub(1),
            _ if letter("j") => self.nav.row = (at + 1).min(rows.len().saturating_sub(1)),
            Key::Left if rows.get(at) == Some(&Row::Clear) => self.step_clear_after(-1),
            Key::Right if rows.get(at) == Some(&Row::Clear) => self.step_clear_after(1),
            Key::Enter if plain => self.act(rows.get(at).copied(), tx),
            _ if letter(" ") => self.act(rows.get(at).copied(), tx),
            Key::Tab => return false,
            _ => {}
        }
        true
    }

    /// ↵ or Space on a row.
    fn act(&mut self, row: Option<Row>, _: &mut Tx) {
        match row {
            Some(Row::TouchId) if !self.touch_id_busy => self.toggle_touch_id(),
            Some(Row::Clear) => self.step_clear_after(1),
            Some(Row::Shortcut) => {
                self.hotkey.refused = None;
                self.hotkey.recorder.begin();
            }
            Some(Row::Command) => {
                self.close_settings();
                self.show_installer();
            }
            Some(Row::Sync) => self.sync_one_password(),
            Some(Row::Agents) => self.toggle_agents(),
            Some(Row::Activity) => self.toggle_activity(),
            _ => {}
        }
    }

    /// The next or last clear-after time, round from the ends.
    pub fn step_clear_after(&mut self, by: isize) {
        let n = CLEAR_STEPS.len() as isize;
        let at = CLEAR_STEPS
            .iter()
            .position(|s| *s >= self.clear_after)
            .unwrap_or(CLEAR_STEPS.len() - 1) as isize;
        self.clear_after = CLEAR_STEPS[(at + by).rem_euclid(n) as usize];
    }
}

pub fn page(s: &App, k: &Kit) -> El {
    let rows = rows(s);
    let on = |r: Row| rows.get(s.nav.row) == Some(&r);
    let mut security = Vec::new();
    if s.touch_id_available() {
        let about = match &s.touch_id_error {
            Some(error) => problem(k, "touch-id-error", error),
            None => about(
                k,
                "Use your fingerprint instead of the passphrase on this Mac",
            ),
        };
        let switch = Switch::new(s.touch_id_enabled())
            .label("Unlock with Touch ID")
            .hide_label()
            .disabled(s.touch_id_busy)
            .on_toggle(|s: &mut App| s.toggle_touch_id())
            .build(k)
            .key("touch-id-switch");
        security.push(setting(
            k,
            "touch-id",
            on(Row::TouchId),
            "Unlock with Touch ID",
            about,
            switch,
        ));
    }
    security.push(setting(
        k,
        "clear",
        on(Row::Clear),
        "Clear copied secrets",
        about(k, "How long a copied password stays on the clipboard"),
        stepper(k, &clear_after(s.clear_after), on(Row::Clear)),
    ));
    let (problems, recorder) = crate::shortcut::setting(s, k);
    let shortcut_about = if problems.is_empty() {
        about(k, "Search and copy from any app")
    } else {
        col().key("problems").w_full().gap(2.0).children(problems)
    };
    let mut getting = vec![setting(
        k,
        "shortcut",
        on(Row::Shortcut),
        "Quick panel",
        shortcut_about,
        recorder,
    )];
    if let Some(button) = crate::install::setting(s, k) {
        let installed = s
            .installer
            .as_ref()
            .is_some_and(crate::install::Installer::installed);
        getting.push(setting(
            k,
            "command",
            on(Row::Command),
            "deadbolt command",
            about(
                k,
                if installed {
                    "Installed: use your vault from Terminal and scripts"
                } else {
                    "Use your vault from Terminal and scripts"
                },
            ),
            button,
        ));
    }
    let (synced, sync) = crate::mirror::setting(s, k);
    let sync = setting(
        k,
        "op-sync",
        on(Row::Sync),
        "Sync from 1Password",
        synced,
        sync,
    );
    let (show_agents, agent_list) = crate::agents::setting(s, k);
    let mut agents = vec![setting(
        k,
        "agents-row",
        on(Row::Agents),
        "Agent sign-ins",
        about(
            k,
            "Apps that sign AI agents in to sites you allowed, without asking",
        ),
        show_agents,
    )];
    agents.extend(agent_list);
    let (show, entries) = crate::activity::setting(s, k);
    let mut activity = vec![setting(
        k,
        "activity-row",
        on(Row::Activity),
        "Recent activity",
        about(k, "What apps and commands asked the agent for"),
        show,
    )];
    activity.extend(entries);
    let body = col()
        .key("settings-col")
        .w_full()
        .max_w(PAGE_W)
        .child(
            text("Settings")
                .key("title")
                .font(TITLE)
                .color(k.c.text_strong)
                .pb(20.0),
        )
        .child(group(k, "Security", security))
        .child(group(k, "Getting to it", getting))
        .child(group(k, "Devices", vec![devices(s, k)]))
        .child(group(k, "1Password", vec![sync]))
        .child(group(k, "Agents", agents))
        .child(group(k, "Activity", activity))
        .child(el().key("kb-rule").w_full().h(0.5).fill(k.c.border_weak))
        .child(
            col()
                .key("keyboard")
                .w_full()
                .pt(24.0)
                .gap(14.0)
                .child(
                    text("Keyboard")
                        .font(k.ty.small_medium)
                        .color(k.c.text_faint),
                )
                .child(crate::sheet::columns(k)),
        );
    col()
        .key("settings")
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .scroll(rune::ScrollSpec {
            stick_bottom: false,
        })
        .scroll_edge_fade(crate::view::LIST_EDGE)
        .child(
            col()
                .key("settings-page")
                .w_full()
                .items_center()
                .px(40.0)
                .pt(4.0)
                .pb(32.0)
                .child(body),
        )
}

fn group(k: &Kit, title: &str, rows: Vec<El>) -> El {
    col()
        .key(format!("group-{}", title.to_lowercase().replace(' ', "-")))
        .w_full()
        .pb(24.0)
        .child(
            text(title.to_owned())
                .font(k.ty.small_medium)
                .color(k.c.text_faint)
                .pb(4.0),
        )
        .children(rows)
}

fn about(k: &Kit, words: &str) -> El {
    text(words.to_owned())
        .key("about")
        .font(FACT.lh(16.0))
        .color(k.c.text_faint)
        .wrap()
        .w_full()
}

fn problem(k: &Kit, key: &str, words: &str) -> El {
    text(words.to_owned())
        .key(key)
        .font(k.ty.small_medium)
        .color(k.c.danger.fg)
        .wrap()
        .w_full()
        .transition(Transition::opacity())
}

/// A row: its label over what it does, the control at its end. The row the
/// keys are on fills.
fn setting(k: &Kit, key: &str, on: bool, label: &str, about: El, control: El) -> El {
    row()
        .key(format!("set-{key}"))
        .w_full()
        .min_h(56.0)
        .ml(-14.0)
        .mr(-14.0)
        .px(14.0)
        .py(10.0)
        .gap(16.0)
        .radius(10.0)
        .continuous_corners()
        .center_y()
        .fill(if on { k.c.layer_02 } else { Color::TRANSPARENT })
        .child(
            col()
                .key("words")
                .gap(2.0)
                .grow(1.0)
                .shrink()
                .min_w(0.0)
                .child(
                    text(label.to_owned())
                        .key("label")
                        .font(k.ty.ui_medium)
                        .color(k.c.text_strong),
                )
                .child(about),
        )
        .child(control)
}

/// This device and how many others share the vault.
fn devices(s: &App, k: &Kit) -> El {
    let device = s
        .status
        .as_ref()
        .and_then(|st| st.device.as_ref())
        .and_then(|d| d.name.clone())
        .unwrap_or_else(|| "This device".to_owned());
    let peers = s.status.as_ref().map_or(0, |st| st.peers);
    let online = s.status.as_ref().map_or(0, |st| st.peers_online);
    let shares = match peers {
        0 => "No other devices yet. Add one with deadbolt invite.".to_owned(),
        1 => format!("Shares with 1 other device, {online} online"),
        n => format!("Shares with {n} other devices, {online} online"),
    };
    setting(k, "devices", false, &device, about(k, &shares), el())
}

/// A value ←→ steps through, its arrows showing while the keys are on it.
fn stepper(k: &Kit, value: &str, on: bool) -> El {
    let arrow = |key: &str, glyph: &str, by: isize| {
        text(glyph.to_owned())
            .key(key)
            .font(k.ty.small)
            .color(if on {
                k.c.text_muted
            } else {
                Color::TRANSPARENT
            })
            .on_press(move |s: &mut App| s.step_clear_after(by))
    };
    row()
        .key("stepper")
        .gap(10.0)
        .center_y()
        .child(arrow("less", "←", -1))
        .child(
            text(value.to_owned())
                .key("clear-after")
                .font(k.ty.ui_medium.features("'tnum' 1"))
                .color(k.c.text_base)
                .on_press(|s: &mut App| s.step_clear_after(1)),
        )
        .child(arrow("more", "→", 1))
}

fn clear_after(secs: f64) -> String {
    match secs as u64 {
        s if s < 60 => format!("{s} s"),
        s if s % 60 == 0 => format!("{} min", s / 60),
        s => format!("{}:{:02}", s / 60, s % 60),
    }
}

/// A button for a row.
pub(crate) fn button(label: &str) -> Button {
    Button::new(label)
        .variant(ButtonVariant::Neutral)
        .control_size(ControlSize::Regular)
}
