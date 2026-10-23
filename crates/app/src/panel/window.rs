//! How the quick panel is reached (`--panel`, the main window's hint,
//! ⇧⌘Space), how its window opens, closes and is placed, and when a process
//! with only the panel leaves.
//! The window is Rune's launcher panel: it takes keys without activating
//! Deadbolt, opens under the pointer, and clicking away dismisses it. Global
//! shortcuts and menus aren't in Rune yet, so the shortcut, the hint and the
//! stranded rule stand in for them; docs/app.md ("Quick panel stand-ins") says
//! which API replaces which.

use std::sync::Arc;

use rune::{
    Align, AppHandle, ConfiguredWindowOptions, Cursor, DisplayTarget, El, Key, KeyEvent,
    OverlayPlacement, ScreenEdge, Tx, Waker, WindowOptions,
};
use rune_kit::Kit;

use super::Phase;
use crate::model::App;

/// ⇧⌘Space. macOS already uses ⌘Space (Spotlight) and ⌥⌘Space (the Finder
/// search window); ⇧⌘Space is free there, and it's 1Password's Quick Access
/// default, so people switching keep the habit. Only inside Deadbolt for
/// now: Rune has no global shortcuts yet.
pub const SHORTCUT: [&str; 3] = ["⇧", "⌘", "Space"];

/// Where the panel opens: centred near the top of the display under the
/// pointer, the window's top this many points down. Rune falls back to the
/// primary display if that one has gone.
pub const PLACE: (DisplayTarget, OverlayPlacement) = (
    DisplayTarget::UnderPointer,
    OverlayPlacement::Edge {
        edge: ScreenEdge::Top,
        margin: 160.0,
        align: Align::Center,
        inset: 0.0,
    },
);

/// `deadbolt-app --panel` starts with the panel instead of the main window.
pub const FLAG: &str = "--panel";

/// ⇧⌘Space (Ctrl+Shift+Space off macOS).
pub fn is_shortcut(ev: &KeyEvent) -> bool {
    ev.key == Key::Text(" ".into()) && ev.mods.cmd && ev.mods.shift && !ev.mods.alt
}

/// Borderless, transparent and non-activating: it takes keys while the app
/// you were in stays frontmost, and gets them back when it hides.
pub fn options() -> ConfiguredWindowOptions {
    WindowOptions::launcher_panel()
}

/// Both windows, so each can reach the other (`App::windows`, None headless
/// and in tests): the main window summons the panel, the panel hides itself
/// and opens the main window for onboarding, and closing the main window
/// quits through the panel so its copy is cleared too.
#[derive(Clone)]
pub struct Windows {
    main: AppHandle<App>,
    panel: AppHandle<App>,
}

impl Windows {
    pub fn new(main: AppHandle<App>, panel: AppHandle<App>) -> Windows {
        Windows { main, panel }
    }

    /// Brings the panel up fresh (see `App::summon`), placed under the pointer and in front.
    pub fn summon_panel(&self) {
        self.panel.update(|s, tx| s.summon(tx));
        let (display, placement) = PLACE;
        self.panel.place(display, placement);
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

    /// Wakes the panel through an empty update. A launcher redraws, and so
    /// polls, only for updates: a plain wake would leave the agent's answers
    /// (a lock, the list) waiting until the next key. Drop this for the
    /// runtime's waker once Rune redraws a launcher on wake (docs/app.md, Rune gaps).
    pub fn panel_waker(&self) -> Waker {
        let panel = self.panel.clone();
        Arc::new(move || panel.update(|_, _| {}))
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
/// global shortcut yet), so rather than idle forever the process leaves: once
/// the panel's copy has been cleared on time, so copy then paste still works,
/// or at once without one. True when it quits. Global shortcuts replace this
/// (docs/app.md, Stand-ins).
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

/// The main window's way in, in its hint bar: the shortcut, and a click opens
/// the panel. Stands in for an "Open Quick Panel" menu item.
pub fn entry(k: &Kit) -> El {
    crate::view::hint(k, "h-panel", &SHORTCUT, "Quick panel")
        .cursor(Cursor::Pointer)
        .on_press(|s: &mut App| s.open_panel())
}
