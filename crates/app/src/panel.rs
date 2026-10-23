//! The quick panel: a small window for finding an item and copying it.
//! Type to filter, ⏎ copies the password (⇧⏎ the username), and it goes
//! away. It's a second window with its own `App` (its own agent connection;
//! the process's one clipboard), drawn from the vault view's search, rows and
//! copy.
//! `window` holds how it opens, closes and is placed. See docs/app.md.

pub mod view;
pub mod window;

use std::time::Duration;

use rune::{AppSpec, Key, KeyEvent, Tx, Waker};

use crate::agent::{Agent, Job};
use crate::model::{App, Screen};

/// The window: the card plus room for its shadow.
pub const SIZE: (f32, f32) = (680.0, 440.0);
/// Where the card sits in the window.
pub const MARGIN: f32 = 20.0;
/// How long the copy's line shows before the panel goes.
pub const CONFIRM: f64 = 1.1;
/// The close fade, and when the window hides after it starts.
pub const CLOSE: f64 = 0.25;
const HIDE_AFTER: f64 = 0.3;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Phase {
    /// Up and taking keys.
    Open,
    /// A copy landed: the confirmation shows until `until`, then it closes.
    Copied { until: Option<f64> },
    /// The card is fading; the window hides at `until`.
    Closing { until: Option<f64> },
    /// Hidden until the shortcut brings it back.
    Hidden,
}

/// The panel's part of its `App`; `App::panel` is `None` in the main window.
pub struct Panel {
    pub phase: Phase,
    /// Counts summons.
    pub opens: u32,
}

pub fn spec() -> AppSpec<App> {
    AppSpec {
        title: "Deadbolt",
        size: SIZE,
        min_size: Some((0.0, 0.0)),
        init: || App::panel(Agent::offline()),
        view: view::panel,
        scenes: crate::PANEL_SCENES,
        fonts: crate::theme::FONTS,
        families: crate::theme::FAMILIES,
        setup: Some(setup),
        poll: Some(|s, now, tx| s.poll(now, tx)),
        on_key: Some(|s: &mut App, ev: &KeyEvent, tx: &mut Tx| s.panel_key(ev, tx)),
    }
}

/// The panel follows the agent through its watch stream and only asks it to
/// start when summoned, so it never races the main window to start one.
fn setup(s: &mut App, waker: Waker) {
    s.agent.set_waker(waker);
}

impl App {
    /// An `App` for the panel window.
    pub fn panel(agent: Agent) -> App {
        let mut app = App::new(agent);
        app.panel = Some(Panel {
            phase: Phase::Open,
            opens: 0,
        });
        app
    }

    pub fn panel_phase(&self) -> Option<Phase> {
        self.panel.as_ref().map(|p| p.phase)
    }

    /// Closing or hidden: the panel reads nothing from the vault until it's
    /// summoned, and drops what arrives.
    pub(crate) fn panel_away(&self) -> bool {
        matches!(
            self.panel_phase(),
            Some(Phase::Closing { .. } | Phase::Hidden)
        )
    }

    /// Summoned: open fresh and at rest, with no animation: check on the
    /// agent and fetch the list again (empty search, the first item selected).
    pub fn summon(&mut self, tx: &mut Tx) {
        let Some(panel) = &mut self.panel else { return };
        panel.phase = Phase::Open;
        panel.opens += 1;
        // The card's own transition has no entrance, but its contents and a card
        // revived mid-close would still animate in.
        tx.settle();
        // A failed copy shows until the next open; a good one keeps counting down.
        if self.copy.as_ref().is_some_and(|c| c.error.is_some()) {
            self.copy = None;
        }
        self.forget_items();
        self.search.focused = self.screen == Screen::Vault;
        if !self.unlocking {
            self.passphrase.clear();
            self.unlock_error = None;
        }
        self.passphrase.focused = self.screen == Screen::Locked;
        self.agent.send(Job::Connect);
        if self.screen == Screen::Vault {
            self.list();
        }
    }

    /// Escape, clicking away, the confirmation ending, or handing over to the
    /// main window: the card fades, then the window hides. A part-typed passphrase goes as
    /// the card starts leaving.
    pub fn dismiss(&mut self, tx: &mut Tx) {
        let Some(panel) = &mut self.panel else { return };
        if matches!(panel.phase, Phase::Closing { .. } | Phase::Hidden) {
            return;
        }
        panel.phase = Phase::Closing { until: None };
        self.passphrase.clear();
        tx.wake_after(Duration::ZERO);
    }

    /// A copy landed: show the confirmation, then close.
    pub(crate) fn panel_copied(&mut self, tx: &mut Tx) {
        let Some(panel) = &mut self.panel else { return };
        if panel.phase == Phase::Open {
            panel.phase = Phase::Copied { until: None };
            tx.wake_after(Duration::ZERO);
        }
    }

    /// The copy's write failed after all: stay open and show why, rather
    /// than close on the confirmation.
    pub(crate) fn panel_copy_failed(&mut self) {
        if let Some(panel) = &mut self.panel
            && matches!(panel.phase, Phase::Copied { .. })
        {
            panel.phase = Phase::Open;
        }
    }

    /// Moves the panel along its phases. True when anything changed.
    ///
    /// A phase's deadline is set here, from the frame's clock: an event can
    /// arrive before the frame moves `self.clock` on from an idle stretch.
    pub(crate) fn poll_panel(&mut self, now: f64, tx: &mut Tx) -> bool {
        let Some(panel) = &mut self.panel else {
            return false;
        };
        match &mut panel.phase {
            Phase::Copied {
                until: until @ None,
            } => {
                *until = Some(now + CONFIRM);
                tx.wake_after(Duration::from_secs_f64(CONFIRM));
                return false;
            }
            Phase::Closing {
                until: until @ None,
            } => {
                *until = Some(now + HIDE_AFTER);
                tx.wake_after(Duration::from_secs_f64(HIDE_AFTER));
                return false;
            }
            Phase::Copied { until: Some(until) } if now >= *until - 1e-3 => {
                self.dismiss(tx);
                if let Some(panel) = &mut self.panel {
                    panel.phase = Phase::Closing {
                        until: Some(now + HIDE_AFTER),
                    };
                }
                tx.wake_after(Duration::from_secs_f64(HIDE_AFTER));
            }
            Phase::Closing { until: Some(until) } if now >= *until - 1e-3 => self.hide_panel(tx),
            _ => return false,
        }
        true
    }

    /// From the main window: bring the panel up.
    pub fn open_panel(&self) {
        if let (None, Some(windows)) = (&self.panel, &self.windows) {
            windows.summon_panel();
        }
    }

    /// Summoned (`App::summon`), then placed under the pointer and in front.
    pub fn show_panel(&mut self, tx: &mut Tx) {
        self.summon(tx);
        if let Some(windows) = &self.windows {
            windows.present_panel();
        }
    }

    /// The global shortcut, registered on the panel's `App`: up if it's away,
    /// away if it's up.
    pub fn toggle_panel(&mut self, tx: &mut Tx) {
        match self.panel_phase() {
            Some(Phase::Open | Phase::Copied { .. }) => self.dismiss(tx),
            Some(_) => self.show_panel(tx),
            None => self.open_panel(),
        }
    }

    /// ⇧⌘Space inside Deadbolt while it isn't registered globally
    /// (`App::shortcut_fallback`): the main window brings the panel up; the
    /// panel closes.
    pub(crate) fn panel_shortcut(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        if !self.shortcut_fallback || !window::is_shortcut(ev) {
            return false;
        }
        match self.panel {
            Some(_) => self.dismiss(tx),
            None => self.open_panel(),
        }
        true
    }

    /// The card has faded: hide the window and forget everything read and
    /// typed, so nothing outlives the card: what's waiting is applied now, and
    /// anything later is from an older generation and dropped. A copy keeps counting
    /// down and is cleared on time.
    fn hide_panel(&mut self, tx: &mut Tx) {
        let Some(panel) = &mut self.panel else { return };
        panel.phase = Phase::Hidden;
        if let Some(windows) = &self.windows {
            windows.hide_panel();
        }
        for done in self.agent.drain() {
            self.apply(done, tx);
        }
        self.forget_items();
        if !self.unlocking {
            self.unlock_error = None;
        }
    }

    /// The panel's window lost focus (another app or window was clicked):
    /// it goes as Escape sends it.
    pub fn panel_focus(&mut self, focused: bool, tx: &mut Tx) {
        if !focused {
            self.dismiss(tx);
        }
    }

    /// The panel's window was closed (by the system; it has no close button):
    /// the main window's cleanup. The shortcut brings it back.
    pub fn panel_closed(&mut self, tx: &mut Tx) {
        self.close(tx);
        if let Some(panel) = &mut self.panel {
            panel.phase = Phase::Hidden;
        }
    }

    /// The device isn't set up: onboarding lives in the main window.
    pub fn open_main(&mut self, tx: &mut Tx) {
        if let Some(windows) = &self.windows {
            windows.open_main();
        }
        self.dismiss(tx);
    }

    /// Keys in the panel's search field: Escape closes; while the
    /// confirmation shows, nothing else does anything.
    pub fn panel_search_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        if self.panel_shortcut(ev, tx) || self.panel_escape(ev, tx) {
            return true;
        }
        if self.panel_phase() != Some(Phase::Open) {
            return true;
        }
        self.search_key(ev, tx)
    }

    /// Escape in one of the panel's fields closes the panel, before the field
    /// would take it to blur.
    pub(crate) fn panel_escape(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        if self.panel.is_none() || ev.key != Key::Escape {
            return false;
        }
        self.dismiss(tx);
        true
    }

    /// Keys no field took.
    pub fn panel_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        if self.panel_shortcut(ev, tx) {
            return true;
        }
        match ev.key {
            Key::Escape => self.dismiss(tx),
            Key::Enter if self.screen == Screen::Onboarding => self.open_main(tx),
            Key::Enter if matches!(self.screen, Screen::Failed(_)) => self.retry(),
            Key::Command('l')
                if self.screen == Screen::Vault && self.panel_phase() == Some(Phase::Open) =>
            {
                self.lock()
            }
            _ => return false,
        }
        true
    }
}

impl App {
    /// The main window closed: wipe it and quit, through the panel when
    /// there is one, so the panel clears its own copy first. macOS Quit (the
    /// menu, ⌘Q, the Dock, logout) runs this too, as the app is already
    /// ending: the panel's queued quit never runs, and its own `on_close`
    /// wipes it instead.
    pub fn quit(&mut self, tx: &mut Tx) {
        self.close(tx);
        match &self.windows {
            Some(windows) => windows.quit(),
            None => tx.quit(),
        }
    }
}
