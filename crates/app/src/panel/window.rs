//! How the quick panel is reached (`--panel`, the main window's hint,
//! ⇧⌘Space), how its window opens, closes and is placed, and when a process
//! with only the panel leaves.
//! Each piece stands in for a Rune API. Focus loss, non-activating panels and
//! placement are on our pin but not adopted yet; the next PR switches to them.
//! Global shortcuts and menus aren't in Rune yet. docs/app.md ("Quick panel
//! stand-ins") says which API replaces which, so switching over changes this
//! file and little else.

use rune::{AppHandle, Cursor, Display, El, Key, KeyEvent, Tx, WindowOptions};
use rune_kit::Kit;

use super::{Phase, SIZE};
use crate::model::App;

/// ⇧⌘Space. macOS already uses ⌘Space (Spotlight) and ⌥⌘Space (the Finder
/// search window); ⇧⌘Space is free there, and it's 1Password's Quick Access
/// default, so people switching keep the habit. Only inside Deadbolt for
/// now: Rune has no global shortcuts yet.
pub const SHORTCUT: [&str; 3] = ["⇧", "⌘", "Space"];

/// Seconds without a key before the panel closes itself. Focus loss isn't
/// adopted yet (the next PR switches to `El::on_window_focus`), so a panel
/// left behind after clicking away goes this way.
pub const IDLE: f64 = 30.0;

/// How far down the screen the window's top sits, as a fraction of its height.
const FROM_TOP: f64 = 0.18;

/// `deadbolt-app --panel` starts with the panel instead of the main window.
pub const FLAG: &str = "--panel";

/// ⇧⌘Space (Ctrl+Shift+Space off macOS).
pub fn is_shortcut(ev: &KeyEvent) -> bool {
    ev.key == Key::Text(" ".into()) && ev.mods.cmd && ev.mods.shift && !ev.mods.alt
}

/// Both windows, so each can reach the other (`App::windows`, None headless
/// and in tests): the main window summons the panel, the panel hides itself
/// and opens the main window for onboarding, and closing the main window
/// quits through the panel so its copy is cleared too.
#[derive(Clone)]
pub struct Windows {
    main: AppHandle<App>,
    panel: AppHandle<App>,
    displays: Vec<Display>,
}

impl Windows {
    pub fn new(main: AppHandle<App>, panel: AppHandle<App>, displays: &[Display]) -> Windows {
        Windows {
            main,
            panel,
            displays: displays.to_vec(),
        }
    }

    /// Brings the panel up fresh (see `App::summon`), placed and in front.
    pub fn summon_panel(&self) {
        self.panel.update(|s, tx| s.summon(tx));
        if let Some(at) = position(&self.displays) {
            self.panel.set_position(at);
        }
        self.panel.open();
    }

    /// For `--panel`: the main window waits to be opened, and the panel comes up.
    pub fn start_with_panel(&self, main: rune::App<App>) -> rune::App<App> {
        self.summon_panel();
        main.windowless()
    }

    /// The close fade has finished.
    pub fn hide_panel(&self) {
        self.panel.hide();
    }

    pub fn open_main(&self) {
        self.main.open();
    }

    /// Nothing but the panel could be on screen, and nothing can summon it
    /// back: the main window isn't open (`--panel`) and there's no global
    /// shortcut yet.
    fn stranded(&self) -> bool {
        !self.main.is_visible()
    }

    /// Quits from the main window through the panel, so the panel clears its copy first.
    pub fn quit(&self) {
        self.panel.update(|panel, tx| {
            panel.close(tx);
            tx.quit();
        });
    }
}

/// A hidden panel with the main window closed can't be brought back (no
/// global shortcut, no launcher), so rather than idle forever the process
/// leaves: once the panel's copy has been cleared on time, so copy then paste
/// still works, or at once without one. True when it quits. Global shortcuts
/// replace this (docs/app.md, Stand-ins).
pub(crate) fn leave_if_stranded(s: &mut App, tx: &mut Tx) -> bool {
    // Before its first open the panel is only waiting (the main window may not be up yet).
    let opened = s.panel.as_ref().is_some_and(|p| p.opens > 0);
    let stranded = opened && s.windows.as_ref().is_some_and(Windows::stranded);
    if !stranded || s.panel_phase() != Some(Phase::Hidden) || s.copy_pending() {
        return false;
    }
    s.close(tx);
    tx.quit();
    true
}

/// Borderless and transparent, near the top of the primary display. Not
/// always on top: until focus loss is adopted (the next PR switches to
/// `El::on_window_focus` and `launcher_panel`), clicking another app at least
/// sends the panel behind it.
pub fn options(displays: &[Display]) -> WindowOptions {
    WindowOptions {
        transparent: true,
        borderless: true,
        resizable: false,
        min_size: Some((0.0, 0.0)),
        max_size: Some(SIZE),
        position: position(displays),
        ..Default::default()
    }
}

/// Centred on the primary display, near its top, in physical pixels. Not the
/// display under the pointer: not adopted yet; the next PR switches to
/// `AppHandle::place`.
pub fn position(displays: &[Display]) -> Option<(i32, i32)> {
    let d = displays
        .iter()
        .find(|d| d.primary)
        .or_else(|| displays.first())?;
    let width = f64::from(SIZE.0) * d.scale;
    let x = f64::from(d.position.0) + (f64::from(d.size.0) - width) / 2.0;
    let y = f64::from(d.position.1) + f64::from(d.size.1) * FROM_TOP;
    Some((x.round() as i32, y.round() as i32))
}

/// The main window's way in, in its hint bar: the shortcut, and a click opens
/// the panel. Stands in for an "Open Quick Panel" menu item.
pub fn entry(k: &Kit) -> El {
    crate::view::hint(k, "h-panel", &SHORTCUT, "Quick panel")
        .cursor(Cursor::Pointer)
        .on_press(|s: &mut App| s.open_panel())
}
