//! The quick panel's global shortcut: ⇧⌘Space unless it's changed in
//! Settings. It registers on the panel's `App`, so pressing it toggles the
//! panel directly (`App::toggle_panel`); the main window owns the choice, the
//! recorder in Settings and the notice when the shortcut couldn't be
//! registered. The choice is kept in `app-shortcut`, beside the agent's config.

use std::fs;
use std::path::{Path, PathBuf};

use rune::{AppHandle, El, Shortcut, ShortcutError, Transition, Tx, col, row, text};
use rune_kit::{Button, ButtonSize, ButtonVariant, Kit, ShortcutRecorder, ShortcutRecorderState};

use crate::model::{App, Screen};

/// macOS already uses ⌘Space (Spotlight) and ⌥⌘Space (the Finder search
/// window); ⇧⌘Space is free there, and it's 1Password's Quick Access
/// default, so people switching keep the habit. Elsewhere the Super key's
/// chords belong to the desktop, so it's Ctrl+Shift+Space.
pub const DEFAULT: &str = if cfg!(target_os = "macos") {
    "shift+super+space"
} else {
    "ctrl+shift+space"
};

#[expect(clippy::expect_used, reason = "a constant, checked by the tests")]
pub fn default() -> Shortcut {
    DEFAULT.parse().expect("the default shortcut parses")
}

/// A registered shortcut; dropping it unregisters.
pub struct Registration(Option<Box<dyn FnOnce() + Send>>);

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            release();
        }
    }
}

/// Registers `shortcut` on the panel's `App`: pressing it anywhere toggles the panel.
pub fn register(
    panel: &AppHandle<App>,
    shortcut: &Shortcut,
) -> Result<Registration, ShortcutError> {
    let id = panel.register_shortcut(shortcut.clone(), |s, tx| s.toggle_panel(tx))?;
    let panel = panel.clone();
    Ok(Registration(Some(Box::new(move || {
        // At exit the panel's App has already stopped, taking its shortcuts with it.
        if let Err(e) = panel.unregister_shortcut(id)
            && e != ShortcutError::NotRunning
        {
            eprintln!("Couldn't release the quick panel shortcut: {e}");
        }
    }))))
}

/// Where a changed shortcut registers.
enum Target {
    /// The panel's `App`, when the app runs both windows.
    Panel(AppHandle<App>),
    /// Tests and tooling runs: every chord registers except `taken`, as if
    /// another app held them, named `owner` when the desktop would say.
    Virtual {
        taken: Vec<Shortcut>,
        owner: Option<String>,
    },
}

/// The main window's part: the chosen shortcut and whether it's registered.
pub struct Hotkey {
    /// None once cleared in Settings.
    pub shortcut: Option<Shortcut>,
    registration: Option<Registration>,
    /// Why `shortcut` isn't registered, for the vault's notice.
    pub error: Option<ShortcutError>,
    /// The notice was put off until the next launch.
    pub dismissed: bool,
    /// Holds the registered shortcut, so recording a chord that failed to
    /// register proposes it again (`start` leaves it empty on a failure).
    pub recorder: ShortcutRecorderState,
    /// Why "Reset" couldn't take the default back.
    pub reset_error: Option<ShortcutError>,
    /// Who holds the chords that were taken when they tried to register, when
    /// the desktop says (Spotlight, another Rune app, "macOS").
    holders: Vec<(Shortcut, String)>,
    target: Target,
    file: Option<PathBuf>,
}

impl Default for Hotkey {
    fn default() -> Self {
        Hotkey::new(Some(default()), Vec::new())
    }
}

impl Hotkey {
    /// For tests and tooling runs: `shortcut` chosen, not registered yet, and
    /// `taken` held by another app.
    pub fn new(shortcut: Option<Shortcut>, taken: Vec<Shortcut>) -> Hotkey {
        Hotkey {
            recorder: ShortcutRecorderState::new(shortcut.clone()),
            shortcut,
            registration: None,
            error: None,
            dismissed: false,
            reset_error: None,
            holders: Vec::new(),
            target: Target::Virtual { taken, owner: None },
            file: None,
        }
    }

    /// The running app's: `shortcut` as `load` read it from `file`, changes
    /// saved back there, registering on `panel`.
    pub fn live(panel: AppHandle<App>, file: PathBuf, shortcut: Option<Shortcut>) -> Hotkey {
        Hotkey {
            target: Target::Panel(panel),
            ..Hotkey::new(shortcut, Vec::new()).saving_to(file)
        }
    }

    /// Saves changes in `file` (`load` reads it back).
    pub fn saving_to(self, file: PathBuf) -> Hotkey {
        Hotkey {
            file: Some(file),
            ..self
        }
    }

    /// For tests and tooling runs: the taken chords are `owner`'s, as when
    /// macOS names a system shortcut.
    pub fn taken_by(mut self, name: &str) -> Hotkey {
        if let Target::Virtual { owner, .. } = &mut self.target {
            *owner = Some(name.to_owned());
        }
        self
    }

    /// Tests: what other apps hold now, as when one lets go.
    pub fn set_taken(&mut self, now: Vec<Shortcut>) {
        if let Target::Virtual { taken, .. } = &mut self.target {
            *taken = now;
        }
    }

    pub fn registered(&self) -> bool {
        self.registration.is_some()
    }

    /// Who holds `shortcut`, if it was taken when it last tried to register
    /// and the desktop said.
    pub fn holder(&self, shortcut: &Shortcut) -> Option<&str> {
        holder(&self.holders, Some(shortcut))
    }

    fn register(&mut self, shortcut: &Shortcut) -> Result<Registration, ShortcutError> {
        let result = match &self.target {
            Target::Panel(panel) => register(panel, shortcut),
            Target::Virtual { taken, .. } if taken.contains(shortcut) => {
                Err(ShortcutError::Conflict)
            }
            Target::Virtual { .. } => Ok(Registration(None)),
        };
        self.holders.retain(|(held, _)| held != shortcut);
        if let Err(ShortcutError::Conflict) = result
            && let Some(owner) = self.owner(shortcut)
        {
            self.holders.push((shortcut.clone(), owner));
        }
        result
    }

    fn owner(&self, shortcut: &Shortcut) -> Option<String> {
        match &self.target {
            Target::Panel(panel) => panel.shortcut_owner(shortcut),
            Target::Virtual { owner, .. } => owner.clone(),
        }
    }

    /// Registers the chosen shortcut at launch; a failure is kept for the
    /// notice. Settings' "Try again" runs it again.
    pub fn start(&mut self) {
        let Some(shortcut) = self.shortcut.clone() else {
            return;
        };
        match self.register(&shortcut) {
            Ok(registration) => {
                self.registration = Some(registration);
                self.error = None;
                self.recorder = ShortcutRecorderState::new(Some(shortcut));
            }
            Err(error) => {
                self.error = Some(error);
                // Rune gap (retrying an unchanged chord): the recorder ignores
                // a chord equal to its own, so it holds nothing while ours is
                // unregistered, and recording that chord again tries again.
                // Waits on the recorder's opt-in to propose an unchanged chord;
                // then keep it on `shortcut`.
                self.recorder = ShortcutRecorderState::new(None);
            }
        }
    }

    /// The recorder's proposal (None clears it). The new shortcut registers
    /// before the old one lets go, so a failure keeps the old one working. A
    /// chord without ⌘, ⌃ or ⌥ is refused (F1–F20 alone are fine): it would
    /// take that key from typing everywhere.
    pub fn change(&mut self, next: Option<&Shortcut>) -> Result<(), ShortcutError> {
        let registration = next
            .map(|next| match allowed(next) {
                false => Err(ShortcutError::InvalidAccelerator(next.to_string())),
                true => self.register(next),
            })
            .transpose()?;
        self.registration = registration;
        self.shortcut = next.cloned();
        self.error = None;
        self.reset_error = None;
        self.save();
        Ok(())
    }

    /// Settings' "Reset to ⇧⌘Space".
    pub fn reset(&mut self) {
        let default = default();
        match self.change(Some(&default)) {
            Ok(()) => self.recorder = ShortcutRecorderState::new(Some(default)),
            Err(error) => self.reset_error = Some(error),
        }
    }

    /// The recorder, for `ShortcutRecorder`. Recording puts away Reset's error.
    pub fn recorder(&mut self) -> &mut ShortcutRecorderState {
        if self.recorder.is_recording() {
            self.reset_error = None;
        }
        &mut self.recorder
    }

    /// Saves the choice; the default saves as no file, so it follows the
    /// default. Written beside the file and renamed over it, so a crash never
    /// leaves half a line.
    fn save(&self) {
        let Some(file) = &self.file else { return };
        let result = match &self.shortcut {
            Some(s) if *s == default() => match fs::remove_file(file) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                result => result,
            },
            chosen => {
                let line = chosen.as_ref().map(Shortcut::to_string).unwrap_or_default();
                let fresh = file.with_file_name(format!(".app-shortcut-{}", std::process::id()));
                file.parent()
                    .map_or(Ok(()), fs::create_dir_all)
                    .and_then(|()| fs::write(&fresh, format!("{line}\n")))
                    .and_then(|()| fs::rename(&fresh, file))
                    .inspect_err(|_| {
                        fs::remove_file(&fresh).ok();
                    })
            }
        };
        if let Err(e) = result {
            eprintln!("Couldn't save the quick panel shortcut: {e}");
        }
    }
}

/// Holds ⌘, ⌃ or ⌥ (Ctrl or Alt off macOS), or is F1–F20, which type nothing.
/// Shift alone doesn't count.
// Rune gap (unmodified chords): Rune's rule, applied here because the recorder
// and `register_shortcut` still take bare keys. Waits on both refusing them by
// default; then delete this and its uses in `change`, `load` and `refusal`.
pub fn allowed(shortcut: &Shortcut) -> bool {
    use rune::PhysicalKeyCode::*;
    let m = shortcut.modifiers();
    m.cmd
        || m.ctrl
        || m.alt
        || matches!(
            shortcut.physical_key(),
            F1 | F2
                | F3
                | F4
                | F5
                | F6
                | F7
                | F8
                | F9
                | F10
                | F11
                | F12
                | F13
                | F14
                | F15
                | F16
                | F17
                | F18
                | F19
                | F20
        )
}

/// The saved choice: the default without a file, None if it was cleared.
pub fn load(file: &Path) -> Option<Shortcut> {
    let Ok(saved) = fs::read_to_string(file) else {
        return Some(default());
    };
    let saved = saved.trim();
    if saved.is_empty() {
        return None;
    }
    match saved.parse() {
        Ok(shortcut) if allowed(&shortcut) => Some(shortcut),
        Ok(_) => {
            eprintln!("Ignoring the saved quick panel shortcut: {saved} has no modifier");
            Some(default())
        }
        Err(e) => {
            eprintln!("Ignoring the saved quick panel shortcut: {e}");
            Some(default())
        }
    }
}

fn holder<'a>(holders: &'a [(Shortcut, String)], chord: Option<&Shortcut>) -> Option<&'a str> {
    holders
        .iter()
        .find(|(held, _)| Some(held) == chord)
        .map(|(_, owner)| owner.as_str())
}

/// Why a chord wasn't taken, under the recorder: `holders` name who has it.
fn refusal(
    error: &ShortcutError,
    chord: Option<&Shortcut>,
    holders: &[(Shortcut, String)],
) -> String {
    match (error, chord) {
        (ShortcutError::Conflict, Some(chord)) => match holder(holders, Some(chord)) {
            Some(owner) => format!("{} is in use by {owner}.", name(chord)),
            None => format!("{} is in use by another app.", name(chord)),
        },
        (ShortcutError::Conflict, None) => "That shortcut is in use by another app.".to_owned(),
        (ShortcutError::InvalidAccelerator(_), Some(chord)) if !allowed(chord) => {
            if cfg!(target_os = "macos") {
                "Add ⌘, ⌃ or ⌥.".to_owned()
            } else {
                "Add Ctrl or Alt.".to_owned()
            }
        }
        (ShortcutError::InvalidAccelerator(_), _) => "That key can't be a shortcut.".to_owned(),
        (ShortcutError::Unsupported, _) => {
            "This desktop doesn't support global shortcuts.".to_owned()
        }
        (ShortcutError::PermissionDenied, _) => "Permission to use it was declined.".to_owned(),
        (other, _) => format!("It couldn't be registered: {other}."),
    }
}

/// "⇧⌘Space".
pub fn name(shortcut: &Shortcut) -> String {
    shortcut.keycaps().concat()
}

impl App {
    /// Registers the shortcut once the app is running. Without one that
    /// works, a `--panel` start opens the main window too, since nothing else
    /// could bring the panel back once it hides.
    pub fn start_shortcut(&mut self, panel_first: bool) {
        self.hotkey.start();
        self.shortcut_changed();
        if let Some(windows) = &self.windows
            && panel_first
            && !self.hotkey.registered()
        {
            windows.open_main();
        }
    }

    /// The recorder's `on_change`.
    pub fn change_shortcut(&mut self, next: Option<&Shortcut>) -> Result<(), ShortcutError> {
        self.hotkey.change(next)?;
        self.shortcut_changed();
        Ok(())
    }

    pub fn reset_shortcut(&mut self) {
        self.hotkey.reset();
        self.shortcut_changed();
    }

    /// Settings' "Try again", while the chosen shortcut isn't registered.
    pub fn retry_shortcut(&mut self) {
        self.hotkey.start();
        self.shortcut_changed();
    }

    /// While the default shortcut couldn't be registered, it still works
    /// inside Deadbolt (`panel::window::is_shortcut`). The menus show the
    /// chosen one.
    fn shortcut_changed(&mut self) {
        let h = &self.hotkey;
        let fallback = !h.registered() && h.shortcut.as_ref() == Some(&default());
        self.shortcut_fallback = fallback;
        if let Some(windows) = &self.windows {
            windows.shortcut_fallback(fallback);
            windows.set_menu(h.shortcut.as_ref());
        }
    }

    /// The notice's "Choose another…": Settings, with the recorder.
    fn choose_shortcut(&mut self) {
        self.settings_open = true;
    }
}

/// The vault's notice while the chosen shortcut isn't registered.
pub fn notice(s: &App, k: &Kit) -> Option<El> {
    let h = &s.hotkey;
    let error = h
        .error
        .as_ref()
        .filter(|_| !h.dismissed && s.screen == Screen::Vault)?;
    let shortcut = h.shortcut.as_ref()?;
    let why = match error {
        ShortcutError::Conflict => format!(
            "{} is using it, so the quick panel can't open from anywhere.",
            h.holder(shortcut).unwrap_or("Another app")
        ),
        ShortcutError::Unsupported => "This desktop doesn't support global shortcuts.".to_owned(),
        ShortcutError::PermissionDenied => "Permission to use it was declined.".to_owned(),
        other => format!("It couldn't be registered: {other}."),
    };
    let mut card = col()
        .key("shortcut-notice")
        .role("status")
        .w(crate::view::NOTICE_W)
        .self_center()
        .padding(12.0)
        .gap(10.0)
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .transition(Transition::offset(0.0, 12.0).combined(Transition::opacity()));
    for shadow in k.shadow_layers(&k.elevation.floating) {
        card = card.box_shadow(shadow);
    }
    Some(
        card.child(
            col()
                .key("text")
                .w_full()
                .gap(2.0)
                .child(
                    text(format!("{} isn't available", name(shortcut)))
                        .font(k.ty.ui_medium)
                        .color(k.c.text_strong)
                        .wrap()
                        .w_full(),
                )
                .child(
                    text(why)
                        .key("why")
                        .font(k.ty.text_small)
                        .color(k.c.text_muted)
                        .wrap()
                        .w_full(),
                ),
        )
        .child(
            row()
                .key("actions")
                .gap(8.0)
                .child(
                    Button::new("Choose another…")
                        .variant(ButtonVariant::Neutral)
                        .on_press(|s: &mut App| s.choose_shortcut())
                        .build(k)
                        .key("choose"),
                )
                .child(
                    Button::new("Not now")
                        .variant(ButtonVariant::Ghost)
                        .on_press(|s: &mut App| s.hotkey.dismissed = true)
                        .build(k)
                        .key("dismiss"),
                ),
        ),
    )
}

/// Settings' shortcut: the recorder, which keeps showing a refused chord with
/// why under it (`refusal`) and keeps the old shortcut, a way to try an unregistered one again, and a way
/// back to the default.
pub fn setting(s: &App, k: &Kit) -> El {
    let h = &s.hotkey;
    let default = default();
    let recording = h.recorder.is_recording();
    let holders = h.holders.clone();
    let mut section = col()
        .key("shortcut")
        .w_full()
        .gap(6.0)
        .child(
            text("Quick panel shortcut")
                .key("shortcut-label")
                .font(k.ty.text_small)
                .color(k.c.text_muted),
        )
        .child(
            ShortcutRecorder::new("recorder", &h.recorder, |s: &mut App| s.hotkey.recorder())
                .on_change(|s: &mut App, next, _: &mut Tx| s.change_shortcut(next))
                .error_message(move |error, chord| refusal(error, chord, &holders))
                .width(240.0)
                .build(k),
        );
    let line = |message: String, key: &str| {
        text(message)
            .key(key)
            .font(k.ty.small_medium)
            .color(k.c.danger.fg)
            .wrap()
            .w_full()
    };
    if let Some(error) = h.error.as_ref().filter(|_| !recording && !h.registered()) {
        let message = refusal(error, h.shortcut.as_ref(), &h.holders);
        section = section.child(line(message, "shortcut-error"));
    }
    if let Some(error) = h.reset_error.as_ref().filter(|_| !recording) {
        let message = refusal(error, Some(&default), &h.holders);
        section = section.child(line(message, "reset-error"));
    }
    let action = |label: String, key: &str, press: fn(&mut App)| {
        Button::new(label)
            .variant(ButtonVariant::Ghost)
            .size(ButtonSize::Small)
            .on_press(press)
            .build(k)
            .key(key)
            .transition(Transition::opacity())
    };
    if h.shortcut.is_some() && !h.registered() && !recording {
        section = section.child(action("Try again".into(), "retry", App::retry_shortcut));
    }
    if h.shortcut.as_ref() != Some(&default) && !recording {
        let label = format!("Reset to {}", name(&default));
        section = section.child(action(label, "reset", App::reset_shortcut));
    }
    section
}
