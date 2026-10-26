//! How the quick panel is reached (its global shortcut, the menus' "Open
//! Quick Panel", `--panel`, the main window's hint off macOS) and how its
//! window opens, closes and is placed.
//! The window is Rune's launcher panel: it takes keys without activating
//! Deadbolt, opens under the pointer, and clicking away dismisses it. The
//! shortcut itself is `crate::shortcut`.

use rune::{
    Align, AppHandle, ConfiguredWindowOptions, Cursor, DisplayTarget, El, Key, KeyEvent, MenuError,
    MenuItem, OverlayPlacement, ScreenEdge, Shortcut, WindowOptions,
};
use rune_kit::Kit;

use crate::model::App;

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

/// The default shortcut pressed inside Deadbolt: ⇧⌘Space (Ctrl+Shift+Space
/// off macOS). Only while it isn't registered globally (`App::shortcut_fallback`).
pub fn is_shortcut(ev: &KeyEvent) -> bool {
    ev.key == Key::Text(" ".into()) && ev.mods.cmd && ev.mods.shift && !ev.mods.alt
}

/// Borderless, transparent and non-activating: it takes keys while the app
/// you were in stays frontmost, and gets them back when it hides.
pub fn options() -> ConfiguredWindowOptions {
    WindowOptions::launcher_panel()
}

/// Both windows, so each can reach the other (`App::windows`; in the main
/// window None headless and in tests): the main window summons the panel and
/// changes its shortcut, the panel places and hides itself and opens the main
/// window for onboarding, and closing the main window quits through the panel
/// so its copy is cleared too.
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
        self.present_panel();
    }

    /// Places the panel under the pointer and puts it in front.
    pub fn present_panel(&self) {
        let (display, placement) = PLACE;
        self.panel.place(display, placement);
        self.panel.open();
    }

    /// Gives key focus back to the open panel after the system Touch ID sheet closes.
    pub fn focus_panel(&self) {
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

    /// Opens the main window, with the Dock icon a `--panel` start went without.
    pub fn open_main(&self) {
        self.main.set_dock_icon(true);
        self.main.open();
    }

    /// Tells the panel whether ⇧⌘Space inside it still closes it.
    pub fn shortcut_fallback(&self, on: bool) {
        self.panel.update(move |s, _| s.shortcut_fallback = on);
    }

    /// Shows `shortcut` beside the menus' "Open Quick Panel".
    pub fn set_menu(&self, shortcut: Option<&Shortcut>) {
        match self.panel.set_menu(menu(shortcut)) {
            Ok(()) | Err(MenuError::Unsupported | MenuError::NotRunning) => {}
            Err(e) => eprintln!("Couldn't update the menu: {e}"),
        }
    }

    /// "Import Passwords…": the main window, in front, with its import view.
    pub fn show_import(&self) {
        self.main.update(|s, _| s.show_import());
        self.open_main();
    }

    /// "New Item": the main window, in front, with a form for a new login.
    pub fn new_item(&self) {
        self.main.update(|s, _| s.from_menu(App::new_item));
    }

    /// "Edit Item": the main window, in front, editing the selected item.
    pub fn edit_item(&self) {
        self.main.update(|s, _| s.from_menu(App::edit_selected));
    }

    /// "Delete Item…": the main window, in front, asking to delete the selected item.
    pub fn delete_item(&self) {
        self.main.update(|s, _| s.from_menu(App::ask_delete));
    }

    /// Quits from the main window through the panel, so the panel clears its copy first.
    pub fn quit(&self) {
        self.panel.update(|panel, tx| {
            panel.close(tx);
            tx.quit();
        });
    }
}

/// The menus' item, in the app menu and the Dock menu.
pub const OPEN: &str = "Open Quick Panel";

/// The panel's `App` owns the menus, so headless `--window panel` scripts
/// reach them (`{"menu": "Open Quick Panel"}`). Native menus are macOS's;
/// elsewhere the hint bar's `entry` is the way in, and the main window takes
/// ⇧⌘I itself (`App::import_key`).
pub fn menu(shortcut: Option<&Shortcut>) -> Vec<MenuItem<App>> {
    let mut item = MenuItem::new(OPEN, |s: &mut App, tx| s.show_panel(tx));
    if let Some(shortcut) = shortcut {
        item = item.key_equivalent(shortcut.clone());
    }
    let dock = MenuItem::new(OPEN, |s: &mut App, tx| s.show_panel(tx))
        .id("dock-quick")
        .dock();
    let import = MenuItem::new(crate::import::MENU, |s: &mut App, _| {
        if let Some(windows) = &s.windows {
            windows.show_import();
        }
    })
    .menu("File")
    .key_equivalent(import_shortcut());
    let new = MenuItem::new(crate::edit::NEW, |s: &mut App, _| {
        windows(s, Windows::new_item)
    })
    .menu("File")
    .key_equivalent(edit_shortcut('n'));
    let edit = MenuItem::new(crate::edit::EDIT, |s: &mut App, _| {
        windows(s, Windows::edit_item)
    })
    .menu("File")
    .key_equivalent(edit_shortcut('e'));
    // No ⌘⌫ here: a menu's key equivalent comes before the window, and ⌘⌫ in a
    // text field deletes to the line's start. The window takes it (`App::edit_key`).
    let delete = MenuItem::new(crate::edit::DELETE, |s: &mut App, _| {
        windows(s, Windows::delete_item)
    })
    .menu("File");
    vec![item, dock, new, edit, delete, import]
}

/// An item menu's action, on the windows. Nothing while the quick panel is
/// up: its keys are its own.
fn windows(s: &App, f: fn(&Windows)) {
    if s.panel_phase()
        .is_some_and(|p| p != crate::panel::Phase::Hidden)
    {
        return;
    }
    if let Some(windows) = &s.windows {
        f(windows);
    }
}

/// ⌘N and ⌘E, "New Item" and "Edit Item".
#[expect(clippy::expect_used, reason = "constants")]
fn edit_shortcut(key: char) -> Shortcut {
    format!("super+{key}").parse().expect("parses")
}

/// ⇧⌘I, "Import Passwords…".
#[expect(clippy::expect_used, reason = "a constant")]
pub fn import_shortcut() -> Shortcut {
    "shift+super+i".parse().expect("parses")
}

/// The main window's way in off macOS, where there are no native menus: the
/// hint bar shows the shortcut, and a click opens the panel.
pub fn entry(s: &App, k: &Kit) -> Option<El> {
    if cfg!(target_os = "macos") {
        return None;
    }
    let keys = s
        .hotkey
        .shortcut
        .as_ref()
        .map(rune::Shortcut::keycaps)
        .unwrap_or_default();
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    let hint = crate::view::hint(k, "h-panel", &keys, "Quick panel")
        .cursor(Cursor::Pointer)
        .label("Open quick panel")
        .on_press(|s: &mut App| s.open_panel());
    Some(hint)
}
