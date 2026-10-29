//! The command offer, headless and offline: it appears only in the vault,
//! Settings and the install page take keys before the vault behind them,
//! and copying a command confirms in place.

use deadbolt_app::install::{Copied, Installer};
use deadbolt_app::model::{App, Screen};
use rune::{Env, Key, KeyEvent, Mods, Runtime};

const FRAME: f64 = 1.0 / 60.0;
const OFFER: &str = "Use Deadbolt from your terminal";

fn runtime(scene: &str) -> Runtime<App> {
    let app = rune::tooling::initial_state(&deadbolt_app::spec(), Some(scene));
    let mut rt = Runtime::new(
        app,
        deadbolt_app::view::app,
        (820.0, 540.0),
        Env {
            system_dark: true,
            scale: 1.0,
        },
    );
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
    rt
}

fn settle(rt: &mut Runtime<App>, seconds: f64) {
    for _ in 0..(seconds / FRAME).round() as usize {
        rt.frame(FRAME);
    }
}

fn shows(rt: &Runtime<App>, s: &str) -> bool {
    rt.elements()
        .iter()
        .any(|e| e.text.as_deref().is_some_and(|t| t.contains(s)) && e.opacity > 0.99)
}

fn press(rt: &mut Runtime<App>, key: &str) {
    let (x, y) = rt.find(key).unwrap_or_else(|| panic!("{key} is on screen"));
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    settle(rt, 0.5);
}

fn key(key: Key) -> KeyEvent {
    KeyEvent {
        key,
        mods: Mods::default(),
    }
}

fn installer(rt: &Runtime<App>) -> &Installer {
    rt.state.installer.as_ref().unwrap()
}

/// Keys the vault's search field would act on: move, copy, type.
fn vault_keys(rt: &mut Runtime<App>) {
    for k in [Key::Down, Key::Up, Key::Enter, Key::Text("g".into())] {
        rt.key(key(k));
        rt.frame(FRAME);
    }
}

#[test]
fn the_offer_and_settings_live_in_the_vault_only() {
    for scene in [
        "connecting",
        "welcome",
        "create-typing",
        "ticket",
        "code",
        "creating",
        "locked",
        "failed",
    ] {
        let mut rt = runtime(scene);
        rt.update(|s, _| {
            let mut i = Installer::fixture();
            // Even an install page or Settings left open never covers these.
            i.open = true;
            s.installer = Some(i);
            s.settings_open = true;
        });
        settle(&mut rt, 0.6);
        assert!(!shows(&rt, OFFER), "{scene} shows the offer");
        assert!(!shows(&rt, "Install the deadbolt command"), "{scene}");
        assert!(
            rt.find("settings-trigger").is_none(),
            "{scene} has Settings"
        );
        assert!(
            !installer(&rt).open && !rt.state.settings_open,
            "{scene} closed them"
        );
    }
    let mut rt = runtime("command-offer");
    settle(&mut rt, 0.6);
    assert!(shows(&rt, OFFER));
    assert!(rt.find("settings-trigger").is_some());
}

#[test]
fn lock_and_settings_stay_in_the_narrowest_window() {
    let mut rt = runtime("command-offer");
    rt.set_viewport((640.0, 540.0), 1.0);
    settle(&mut rt, 0.5);
    let elements = rt.elements();
    // Off macOS the hint bar also opens the quick panel (macOS has its menus).
    let panel = (!cfg!(target_os = "macos")).then_some("Quick panel");
    for label in panel.into_iter().chain(["Lock", "Settings"]) {
        let e = elements
            .iter()
            .rfind(|e| e.text.as_deref() == Some(label) || e.label.as_deref() == Some(label))
            .unwrap_or_else(|| panic!("no {label:?}"));
        assert!(
            e.rect[0] + e.rect[2] <= 640.0,
            "{label:?} runs past the window: {:?}",
            e.rect
        );
    }
}

#[test]
fn the_offer_opens_the_page_or_goes_away_for_good() {
    let mut rt = runtime("command-offer");
    settle(&mut rt, 0.6);
    press(&mut rt, "open");
    assert!(rt.state.installing());
    assert!(shows(&rt, "Install the deadbolt command"));
    // Back to the vault; having seen the page answers the offer.
    press(&mut rt, "back");
    assert!(!rt.state.installing());
    assert!(!shows(&rt, OFFER));

    let mut rt = runtime("command-offer");
    settle(&mut rt, 0.6);
    press(&mut rt, "dismiss");
    assert!(installer(&rt).offered);
    assert!(!shows(&rt, OFFER));
}

#[test]
fn settings_takes_keys_before_the_focused_search() {
    let mut rt = runtime("command-offer");
    settle(&mut rt, 0.6);
    let selected = rt.state.selected.clone();
    // Open it without moving focus: the search field would get keys first.
    rt.update(|s, _| s.settings_open = true);
    settle(&mut rt, 0.5);
    assert!(shows(&rt, "deadbolt command") && shows(&rt, "Install…"));
    assert!(
        rt.state.search.focused,
        "search keeps focus beside Settings"
    );

    vault_keys(&mut rt);
    assert_eq!(rt.state.selected, selected, "↑/↓ didn't move the selection");
    assert!(rt.state.copy.is_none(), "Enter didn't copy");
    assert_eq!(rt.state.search.text, "", "typing didn't search");

    rt.key(key(Key::Escape));
    settle(&mut rt, 0.3);
    assert!(!rt.state.settings_open, "Escape closed Settings");
    assert_eq!(rt.state.screen, Screen::Vault);

    // Closing hands focus back to the trigger. Back in the search field, the
    // same keys reach it again.
    rt.update(|s, _| s.search.focused = true);
    settle(&mut rt, 0.1);
    rt.key(key(Key::Down));
    rt.frame(FRAME);
    assert_ne!(rt.state.selected, selected);

    // Settings opens the install page, which also keeps keys from the vault.
    press(&mut rt, "settings-trigger");
    press(&mut rt, "install");
    assert!(rt.state.installing());
    let selected = rt.state.selected.clone();
    vault_keys(&mut rt);
    assert_eq!(rt.state.selected, selected);
    assert!(rt.state.copy.is_none());
    assert_eq!(rt.state.search.text, "");
    rt.key(key(Key::Escape));
    settle(&mut rt, 0.6);
    assert!(!rt.state.installing(), "Escape left the page");
    assert!(shows(&rt, "github.com"));
}

#[test]
fn the_page_is_centred_and_installs_in_place() {
    let mut rt = runtime("install-command");
    settle(&mut rt, 0.6);
    let (panel, _) = rt.presented("panel").unwrap();
    let middle = panel[1] + panel[3] / 2.0;
    // In the page under the 48 pt title bar, framed 8 pt from the bottom: (48 + 532) / 2.
    assert!((middle - 290.0).abs() < 2.0, "panel centred at {middle}");
    press(&mut rt, "action");
    assert!(installer(&rt).installed());
    assert!(shows(&rt, "Command installed"));
    assert!(shows(&rt, "To undo: rm"));
}

#[test]
fn copying_a_command_confirms_in_place() {
    let mut rt = runtime("install-command");
    rt.update(|s, _| {
        let i = s.installer.as_mut().unwrap();
        let scan = i.scan.as_mut().unwrap();
        scan.manual = true;
        scan.on_path = false;
    });
    settle(&mut rt, 0.6);
    assert!(shows(&rt, "sudo ln -s"));
    assert!(shows(&rt, "Copy command") && shows(&rt, "Copy PATH command"));
    rt.update(|s, tx| {
        let now = s.clock;
        s.installer.as_mut().unwrap().copy(Copied::Path, now, tx);
    });
    settle(&mut rt, 0.6);
    assert!(shows(&rt, "Copied"));
    assert!(shows(&rt, "Copy command"), "only the PATH command confirms");
    assert!(!shows(&rt, "Copy PATH command"));
    settle(&mut rt, 1.4);
    assert!(shows(&rt, "Copy PATH command"));
    assert!(!shows(&rt, "Copied"));
}

/// At the smallest window the manual path (two commands to copy) and an
/// error keep clear of the title bar band and Back.
#[test]
fn the_manual_path_stays_under_the_title_bar() {
    let mut rt = runtime("install-command");
    rt.update(|s, _| {
        let i = s.installer.as_mut().unwrap();
        i.error = Some("Couldn't link /Users/dax/.local/bin/deadbolt: permission denied.".into());
        let scan = i.scan.as_mut().unwrap();
        scan.manual = true;
        scan.on_path = false;
    });
    rt.set_viewport((640.0, 420.0), 1.0);
    settle(&mut rt, 0.6);
    let back = rt.presented("back").unwrap().0;
    let panel = rt.presented("panel").unwrap().0;
    assert!(
        panel[1] >= 48.0 && panel[1] >= back[1] + back[3],
        "the panel starts under the band: {panel:?}, Back {back:?}"
    );
    assert!(
        panel[1] + panel[3] <= 420.0,
        "and ends in the window: {panel:?}"
    );
}
