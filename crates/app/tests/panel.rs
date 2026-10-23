//! The quick panel, headless and offline: each state renders inside the card,
//! it opens fresh and at rest, Escape and a copy both close it, its motion
//! (rows filtering, the footer's copy line, the close fading) never pops, it
//! shares one clipboard with the main window, and a process with only the
//! panel leaves once nothing can bring it back.

#![cfg(test)]

use std::sync::{Arc, Mutex};

use deadbolt_app::agent::Done;
use deadbolt_app::clipboard::Clipboard;
use deadbolt_app::model::App;
use deadbolt_app::panel::window::Windows;
use deadbolt_app::panel::{self, Phase};
use deadbolt_client::protocol::ItemInfo;
use rune::{Env, Key, KeyEvent, Mods, Runtime, Shell};

const FRAME: f64 = 1.0 / 60.0;
/// The footer once github.com's password is copied, as the vault's notice says it.
const COPIED: &str = "Copied, clears in 0:30";
/// Every login's password in the scenes.
const PASSWORD: &str = "correct-horse-battery-staple";

fn runtime(scene: &str, dark: bool) -> Runtime<App> {
    let app = rune::tooling::initial_state(&panel::spec(), Some(scene));
    let mut rt = Runtime::new(
        app,
        panel::view::panel,
        panel::SIZE,
        Env {
            system_dark: dark,
            scale: 1.0,
        },
    );
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.on_key = Some(|s, ev, tx| s.panel_key(ev, tx));
    rt.frame(0.0);
    rt
}

/// The main window, on the vault scene with an item's values showing.
fn main_window() -> Runtime<App> {
    let app = rune::tooling::initial_state(&deadbolt_app::spec(), Some("vault"));
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
    rt.frame(0.0);
    rt
}

type Board = Arc<Mutex<Option<String>>>;

/// One clipboard for both windows, as `run` gives them.
fn share_clipboard(windows: [&mut Runtime<App>; 2]) -> Board {
    let (clipboard, board) = Clipboard::memory();
    for rt in windows {
        rt.state.clipboard = clipboard.clone();
    }
    board
}

fn board(board: &Board) -> Option<String> {
    board.lock().unwrap().clone()
}

/// Both windows on the same clock, `seconds` on.
fn both(a: &mut Runtime<App>, b: &mut Runtime<App>, seconds: f64) {
    a.frame(seconds);
    b.frame(seconds);
}

/// The panel as `--panel` starts it: opened, and the main window never was.
fn alone(rt: &mut Runtime<App>) {
    let main = rune::App::new(deadbolt_app::spec());
    let quick = rune::App::new(panel::spec());
    rt.state.windows = Some(Windows::new(main.handle(), quick.handle(), &[]));
    rt.state.panel.as_mut().unwrap().opens = 1;
}

/// The agent's answer to the list a summon asks for (the tests' agent is offline).
fn answer_list(rt: &mut Runtime<App>, items: &[ItemInfo]) {
    let items = items.to_vec();
    rt.update(move |s, tx| {
        let generation = s.generation();
        s.apply(
            Done::Items {
                generation,
                result: Ok(items),
            },
            tx,
        );
    });
}

fn shortcut() -> KeyEvent {
    KeyEvent {
        key: Key::Text(" ".into()),
        mods: Mods {
            cmd: true,
            shift: true,
            ..Mods::default()
        },
    }
}

fn frames(rt: &mut Runtime<App>, n: usize) {
    for _ in 0..n {
        rt.frame(FRAME);
    }
}

fn key(key: Key) -> KeyEvent {
    KeyEvent {
        key,
        mods: Mods::default(),
    }
}

/// (rect, opacity, visible rect) of the innermost element keyed `key`.
fn find(rt: &Runtime<App>, key: &str) -> Option<([f32; 4], f32)> {
    rt.elements()
        .into_iter()
        .rfind(|e| e.key.as_deref() == Some(key))
        .map(|e| (e.rect, e.opacity))
}

fn shows(rt: &Runtime<App>, s: &str) -> bool {
    rt.elements()
        .iter()
        .any(|e| (e.text.as_deref() == Some(s) || e.label.as_deref() == Some(s)) && e.opacity > 0.0)
}

/// The footer's line once it's fully in: what ⏎ does or the copy (the
/// rolling label's text), a failed copy, or a notice.
fn footer(rt: &Runtime<App>) -> String {
    let elements = rt.elements();
    let Some(line) = elements.iter().rposition(|e| {
        e.key
            .as_deref()
            .is_some_and(|k| matches!(k, "footer-line" | "failed") || k.starts_with("notice:"))
            && e.opacity >= 0.99
    }) else {
        return String::new();
    };
    elements
        .iter()
        .filter(|e| e.parent == Some(line))
        .find_map(|e| match e.key.as_deref() {
            Some("footer-line-label") => e.label.clone(),
            _ => e.text.clone(),
        })
        .unwrap_or_default()
}

/// A rolling label's glyphs: (text, rect, opacity).
fn glyphs(rt: &Runtime<App>, label: &str) -> Vec<(String, [f32; 4], f32)> {
    let prefix = format!("{label}.");
    rt.elements()
        .into_iter()
        .filter(|e| e.key.as_deref().is_some_and(|k| k.starts_with(&prefix)))
        .filter_map(|e| Some((e.text?, e.rect, e.opacity)))
        .collect()
}

/// The glyphs of a rolling label that are at rest, in order.
fn steady(rt: &Runtime<App>, label: &str) -> String {
    let y = find(rt, label).expect("the label").0[1];
    glyphs(rt, label)
        .iter()
        .filter(|g| g.2 >= 0.99 && (g.1[1] - y).abs() < 0.01)
        .map(|g| g.0.as_str())
        .collect()
}

fn phase(rt: &Runtime<App>) -> Phase {
    rt.state.panel_phase().unwrap()
}

#[test]
fn every_state_renders_inside_the_card() {
    let states: &[(&str, &[&str])] = &[
        ("connecting", &["Starting Deadbolt…"]),
        ("empty", &["Cloudflare", "github.com"]),
        ("filtering", &["github.com", "gitlab.com"]),
        ("no-match", &["No matches"]),
        ("empty-vault", &["No items yet"]),
        ("locked", &["Unlock Deadbolt"]),
        (
            "locked-error",
            &["That passphrase didn't unlock this device."],
        ),
        ("not-set-up", &["Set up Deadbolt", "Open Deadbolt"]),
        ("failed", &["Can't reach Deadbolt", "Try again"]),
    ];
    for dark in [true, false] {
        for (scene, texts) in states {
            let mut rt = runtime(scene, dark);
            frames(&mut rt, 30);
            for text in *texts {
                assert!(shows(&rt, text), "{scene}: no {text:?}");
            }
            let enter = match *scene {
                "empty" | "filtering" => "Copy password",
                "locked" | "locked-error" => "Unlock",
                "not-set-up" => "Open Deadbolt",
                "failed" => "Try again",
                _ => "",
            };
            assert_eq!(footer(&rt), enter, "{scene}: what ⏎ does");
            let elements = rt.elements();
            let rect = find(&rt, "card").expect("the card").0;
            let rule = find(&rt, "rule-bottom").expect("the footer rule").0;
            assert!(
                (rect[1] + rect[3] - (panel::SIZE.1 - panel::MARGIN)).abs() < 0.5,
                "{scene}: the card fills the window less its margin ({rect:?})"
            );
            for e in &elements {
                let bottom = e.visible[1] + e.visible[3];
                if e.text.is_some() && e.visible[3] > 0.0 && e.rect[1] < rule[1] {
                    assert!(
                        bottom <= rule[1] + 0.5,
                        "{scene}: {:?} spills past the body ({bottom} > {})",
                        e.text,
                        rule[1]
                    );
                }
            }
        }
    }
    let rt = runtime("filtering", true);
    assert!(!shows(&rt, "fly.io"), "filtering hides what doesn't match");
}

#[test]
fn the_copied_state_shows_the_countdown() {
    let mut rt = runtime("copied", true);
    frames(&mut rt, 36);
    assert_eq!(footer(&rt), COPIED);
    assert!(matches!(phase(&rt), Phase::Copied { .. }));
}

#[test]
fn it_opens_fresh_and_at_rest() {
    let mut rt = runtime("filtering", true);
    rt.key(key(Key::Down));
    frames(&mut rt, 2);
    let items = rt.state.items.clone();
    rt.update(|s, tx| s.dismiss(tx));
    frames(&mut rt, 30);
    assert_eq!(phase(&rt), Phase::Hidden);
    assert_eq!(rt.state.selected, None, "hiding forgets the selection");
    assert!(rt.state.items.is_empty(), "and the list");

    rt.update(|s, tx| s.summon(tx));
    rt.frame(FRAME);
    answer_list(&mut rt, &items);
    rt.frame(FRAME);
    assert_eq!(phase(&rt), Phase::Open);
    assert_eq!(rt.state.search.text, "");
    assert!(rt.state.search.focused);
    let first = rt.state.visible().first().map(|i| i.id.clone());
    assert_eq!(rt.state.selected, first, "the first item is selected");
    let elements = rt.elements();
    assert_eq!(find(&rt, "card").unwrap().1, 1.0, "no fade in");
    let moving: Vec<_> = elements
        .iter()
        .filter(|e| e.moving || (e.opacity > 0.0 && e.opacity < 1.0 && e.text.is_some()))
        .map(|e| e.key.clone())
        .collect();
    assert!(moving.is_empty(), "nothing animates on open: {moving:?}");
}

#[test]
fn it_has_no_settings_or_install_offer_and_keeps_its_keys() {
    let mut rt = runtime("empty", true);
    let mut installer = deadbolt_app::install::Installer::fixture();
    installer.show();
    installer.settings_open = true;
    rt.update(|s, _| s.installer = Some(installer));
    frames(&mut rt, 10);
    for text in ["Settings", "Install the deadbolt command", "Install…"] {
        assert!(!shows(&rt, text), "the panel shows {text:?}");
    }

    let first = rt.state.selected.clone();
    rt.key(key(Key::Down));
    rt.frame(FRAME);
    assert_ne!(rt.state.selected, first, "↓ moves the selection");
    rt.key(key(Key::Escape));
    rt.frame(FRAME);
    assert!(matches!(phase(&rt), Phase::Closing { .. }), "Escape closes");
    let i = rt.state.installer.as_ref().unwrap();
    assert!(i.open && i.settings_open, "no popover took the keys");
}

#[test]
fn escape_fades_the_card_then_hides() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 10);
    rt.key(key(Key::Escape));
    rt.frame(FRAME);
    assert!(matches!(phase(&rt), Phase::Closing { .. }));
    frames(&mut rt, 5);
    let fade = find(&rt, "card").expect("still fading").1;
    assert!(fade > 0.0 && fade < 1.0, "the card fades ({fade})");
    frames(&mut rt, 20);
    assert_eq!(phase(&rt), Phase::Hidden);
    let gone = find(&rt, "card").map_or(0.0, |c| c.1);
    assert!(gone < 0.01, "faded out by the time it hides ({gone})");
}

/// Summoned again while the close still fades: the card comes back at rest,
/// not fading back in from where its close had got to.
#[test]
fn a_summon_during_the_close_lands_at_rest() {
    let mut rt = runtime("empty", true);
    let items = rt.state.items.clone();
    frames(&mut rt, 10);
    rt.key(key(Key::Escape));
    frames(&mut rt, 6);
    let fade = find(&rt, "card").expect("still fading").1;
    assert!(fade > 0.0 && fade < 1.0, "mid-close ({fade})");

    rt.update(|s, tx| s.summon(tx));
    rt.frame(FRAME);
    answer_list(&mut rt, &items);
    rt.frame(FRAME);
    assert_eq!(phase(&rt), Phase::Open);
    assert_eq!(find(&rt, "card").unwrap().1, 1.0, "no fade back in");
}

#[test]
fn the_shortcut_closes_it() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 10);
    rt.key(shortcut());
    rt.frame(FRAME);
    assert!(matches!(phase(&rt), Phase::Closing { .. }));
    assert_eq!(rt.state.search.text, "", "the space isn't typed");
}

#[test]
fn escape_on_the_locked_panel_closes_it_and_forgets_the_passphrase() {
    let mut rt = runtime("locked", true);
    frames(&mut rt, 2);
    for c in "hunt".chars() {
        rt.key(key(Key::Text(c.into())));
    }
    rt.frame(FRAME);
    assert_eq!(rt.state.passphrase.text, "hunt");
    rt.key(key(Key::Escape));
    rt.frame(FRAME);
    assert!(
        matches!(phase(&rt), Phase::Closing { .. }),
        "Escape closes, not just blurs the field"
    );
    frames(&mut rt, 30);
    assert_eq!(phase(&rt), Phase::Hidden);
    assert!(rt.state.passphrase.text.is_empty(), "hiding forgets it");
}

/// Both unlock fields: ⌘V pastes (on one line), but nothing copies, cuts or
/// undoes the passphrase out, a ⌃ chord types nothing, and closing leaves an
/// empty secure field.
#[test]
fn the_passphrase_stays_in_its_field() {
    let main = || {
        let app = rune::tooling::initial_state(&deadbolt_app::spec(), Some("locked"));
        let mut rt = Runtime::new(
            app,
            deadbolt_app::view::app,
            (820.0, 540.0),
            Env {
                system_dark: true,
                scale: 1.0,
            },
        );
        rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
        rt
    };
    let with = |key, mods| KeyEvent { key, mods };
    let cmd = Mods {
        cmd: true,
        ..Mods::default()
    };
    let ctrl = Mods {
        ctrl: true,
        ..Mods::default()
    };
    for mut rt in [runtime("locked", true), main()] {
        frames(&mut rt, 2);
        assert!(rt.has_secure_focus());
        for c in "hunter".chars() {
            rt.key(key(Key::Text(c.into())));
        }
        rt.paste("2\t2\r\n");
        rt.frame(FRAME);
        assert_eq!(rt.state.passphrase.text, "hunter22");
        for c in ['a', 'c', 'x', 'z'] {
            rt.key(with(Key::Command(c), cmd));
        }
        rt.key(with(Key::Text("k".into()), ctrl));
        rt.frame(FRAME);
        assert_eq!(rt.state.passphrase.text, "hunter22");
        assert!(rt.copy_request.is_none(), "nothing reaches the clipboard");
        assert!(
            !rt.elements()
                .iter()
                .any(|e| e.text.as_deref().is_some_and(|t| t.contains("hunter"))),
            "the passphrase never shows"
        );
        rt.update(|s, tx| s.close(tx));
        assert!(rt.state.passphrase.text.is_empty());
        assert!(rt.state.passphrase.is_secure());
    }
}

#[test]
fn the_username_hint_shows_only_for_logins_with_one() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 10);
    assert!(shows(&rt, "Username"));
    let card = rt
        .state
        .visible()
        .iter()
        .position(|i| i.kind == "card")
        .unwrap();
    for _ in 0..card {
        rt.key(key(Key::Down));
        rt.frame(FRAME);
    }
    frames(&mut rt, 30);
    assert_eq!(footer(&rt), "Copy number");
    assert!(
        find(&rt, "h-user").is_none_or(|(_, o)| o < 0.01),
        "a card has no username: the hint fades out"
    );
    // ⇧⏎ anyway says so, in the footer.
    rt.update(|s, tx| {
        s.detail = s.selected_item().cloned();
        s.copy_field("username", tx);
    });
    frames(&mut rt, 30);
    assert_eq!(footer(&rt), "Visa •••• 4242 has no username");
}

#[test]
fn it_closes_itself_when_left_alone() {
    let idle = panel::window::IDLE;
    let mut rt = runtime("empty", true);
    rt.frame(idle - 10.0);
    rt.key(key(Key::Down));
    rt.frame(FRAME);
    rt.frame(idle - 5.0);
    assert_eq!(phase(&rt), Phase::Open, "a key keeps it up");
    rt.frame(5.1);
    assert!(matches!(phase(&rt), Phase::Closing { .. }));
}

#[test]
fn a_copy_confirms_then_closes_and_reopens_clean() {
    let mut rt = runtime("empty", true);
    let items = rt.state.items.clone();
    frames(&mut rt, 10);
    assert_eq!(footer(&rt), "Copy password");
    rt.key(key(Key::Enter));
    rt.frame(FRAME);
    assert!(matches!(phase(&rt), Phase::Copied { .. }));
    assert!(rt.state.copy.as_ref().is_some_and(|c| c.error.is_none()));
    let line = find(&rt, "footer-line").expect("the same line");
    assert!(line.1 >= 0.99, "the line stays; its label rolls");
    assert_eq!(
        steady(&rt, "footer-line-label"),
        "Cop",
        "only \"Cop\" stays put"
    );
    frames(&mut rt, 36);
    assert_eq!(footer(&rt), COPIED);
    frames(&mut rt, 40);
    assert!(
        matches!(phase(&rt), Phase::Closing { .. } | Phase::Hidden),
        "it closes after the confirmation"
    );
    frames(&mut rt, 30);
    assert_eq!(phase(&rt), Phase::Hidden);
    assert!(rt.state.copy.is_some(), "the copy keeps counting down");
    assert!(rt.state.items.is_empty() && rt.state.detail.is_none());

    rt.update(|s, tx| s.summon(tx));
    rt.frame(FRAME);
    answer_list(&mut rt, &items);
    rt.frame(FRAME);
    assert_eq!(footer(&rt), "Copy password");
}

#[test]
fn rows_that_stay_slide_when_filtering() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 10);
    let github = rt
        .state
        .items
        .iter()
        .find(|i| i.label == "github.com")
        .unwrap()
        .id
        .clone();
    let row = format!("item-{github}");
    let from = find(&rt, &row).unwrap().0[1];
    for c in "git".chars() {
        rt.key(key(Key::Text(c.into())));
    }
    rt.frame(FRAME);
    let y = find(&rt, &row).unwrap().0[1];
    frames(&mut rt, 60);
    let to = find(&rt, &row).unwrap().0[1];
    assert!(to < from - 40.0, "github.com moves up ({from} -> {to})");
    assert!(
        to < y && y < from,
        "it slides, not jumps ({from} -> {y} -> {to})"
    );
    assert!(!shows(&rt, "fly.io"));
}

/// From `--reduced-motion` or the system's setting.
#[test]
fn reduced_motion_fades_the_label_in_place() {
    for system in [false, true] {
        let mut rt = runtime("empty", true);
        if system {
            rt.set_system_reduced_motion(true);
        } else {
            rt.update(|s, _| s.reduced_motion = true);
        }
        label_fades_in_place(&mut rt);
    }
}

fn label_fades_in_place(rt: &mut Runtime<App>) {
    frames(rt, 10);
    let line = find(rt, "footer-line").unwrap().0;
    let middle = line[1] + line[3] / 2.0;
    rt.key(key(Key::Enter));
    rt.frame(FRAME);
    let rolling = glyphs(rt, "footer-line-label");
    assert!(
        rolling.iter().any(|g| g.2 > 0.0 && g.2 < 1.0),
        "the label crossfades"
    );
    for (glyph, rect, ..) in &rolling {
        assert!(
            (rect[1] + rect[3] / 2.0 - middle).abs() < 0.5,
            "{glyph:?} stays on the line ({rect:?} vs {line:?})"
        );
    }
    frames(rt, 30);
    assert_eq!(footer(rt), COPIED);
}

/// The vault's countdown: the bar empties on the render clock, and the app
/// wakes once a second for the label, which rolls only the digits that change.
#[test]
fn the_countdown_wakes_once_a_second_and_rolls_its_digits() {
    let mut rt = main_window();
    rt.update(|s, tx| s.copy_field("password", tx));
    rt.frame(FRAME);
    let bar = |rt: &Runtime<App>| find(rt, "bar").expect("the bar").0[2];
    let full = bar(&rt);
    let next = rt.wake_deadline().unwrap() - rt.state.clock;
    assert!(
        next > 0.9 && next < 1.01,
        "the next look is at 0:29 ({next} s)"
    );
    rt.frame(0.5);
    assert!(bar(&rt) < full - 2.0, "the bar empties between wakes");
    assert!(shows(&rt, COPIED));

    while !shows(&rt, "Copied, clears in 0:29") {
        assert!(rt.state.clock < 1.1, "0:29 by a second in");
        rt.frame(FRAME);
    }
    assert_eq!(
        steady(&rt, "notice-line-label"),
        "Copied, clears in 0:",
        "only the digits roll"
    );
}

/// Once hidden, the panel's countdown wakes only at its end, not each second
/// (past the one look that was already due when it hid).
#[test]
fn a_hidden_panel_wakes_once_for_its_countdown() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 2);
    rt.key(key(Key::Enter));
    frames(&mut rt, 120);
    assert_eq!(phase(&rt), Phase::Hidden);
    assert!(rt.state.copy_pending());
    rt.frame(1.0);
    let next = rt.wake_deadline().unwrap() - rt.state.clock;
    assert!(
        next > 25.0,
        "nothing wakes it until about the clear ({next} s)"
    );
}

/// Scenario A: the panel copies, hides with its countdown running, and the
/// main window copies the same value later. The panel's countdown mustn't
/// clear the main window's copy early.
#[test]
fn a_replaced_copy_never_clears_the_newer_one() {
    let mut quick = runtime("empty", true);
    let mut main = main_window();
    let clip = share_clipboard([&mut quick, &mut main]);
    quick.key(key(Key::Enter));
    both(&mut quick, &mut main, FRAME);
    assert_eq!(board(&clip).as_deref(), Some(PASSWORD));

    both(&mut quick, &mut main, 15.0);
    assert_eq!(phase(&quick), Phase::Hidden);
    main.update(|s, tx| s.copy_field("password", tx));
    both(&mut quick, &mut main, FRAME);

    both(&mut quick, &mut main, 16.0);
    assert_eq!(
        board(&clip).as_deref(),
        Some(PASSWORD),
        "the panel's 30 s were up, but the copy is main's now"
    );
    assert!(quick.state.copy.is_none(), "its countdown ended quietly");
    let left = main
        .state
        .copy
        .as_ref()
        .unwrap()
        .remaining(main.state.clock);
    assert!((left - 14.0).abs() < 0.1, "main still counts ({left})");

    both(&mut quick, &mut main, 14.5);
    assert_eq!(board(&clip), None, "main's copy clears on its own time");
    assert!(main.state.copy.as_ref().unwrap().cleared_at.is_some());
}

/// Scenario B: main copies A, then the panel copies B. Main's notice leaves
/// quietly, never saying "Clipboard cleared" while B is on the clipboard.
#[test]
fn a_superseded_copy_leaves_quietly() {
    let mut quick = runtime("empty", true);
    let mut main = main_window();
    let clip = share_clipboard([&mut quick, &mut main]);
    main.update(|s, tx| s.copy_field("password", tx));
    both(&mut quick, &mut main, FRAME);
    assert!(main.state.copy.is_some());

    quick.key(KeyEvent {
        key: Key::Enter,
        mods: Mods {
            shift: true,
            ..Mods::default()
        },
    });
    both(&mut quick, &mut main, FRAME);
    let username = board(&clip).unwrap();
    assert_ne!(username, PASSWORD);
    both(&mut quick, &mut main, 0.2);
    assert!(main.state.copy.is_none(), "main's countdown ends at once");

    for _ in 0..35 {
        both(&mut quick, &mut main, 1.0);
        assert!(!shows(&main, "Clipboard cleared"));
        assert!(main.state.copy.is_none());
    }
    assert_eq!(board(&clip), None, "the panel cleared its copy on time");
}

/// Scenario C: the panel copies and hides, then the main window locks. The
/// lock clears the panel's copy, and the panel's countdown ends quietly.
#[test]
fn a_lock_in_the_other_window_clears_the_copy() {
    let mut quick = runtime("empty", true);
    let mut main = main_window();
    let clip = share_clipboard([&mut quick, &mut main]);
    quick.key(key(Key::Enter));
    both(&mut quick, &mut main, FRAME);
    assert_eq!(board(&clip).as_deref(), Some(PASSWORD));
    both(&mut quick, &mut main, 5.0);

    main.update(|s, tx| s.apply(Done::Locked(Ok(())), tx));
    assert_eq!(board(&clip), None, "the lock clears it at once");
    for _ in 0..30 {
        both(&mut quick, &mut main, 1.0);
        assert!(!shows(&quick, "Clipboard cleared"));
    }
    assert!(quick.state.copy.is_none(), "its countdown ended quietly");
}

#[test]
fn alone_it_leaves_once_hidden() {
    let mut rt = runtime("empty", true);
    alone(&mut rt);
    frames(&mut rt, 2);
    rt.key(key(Key::Escape));
    frames(&mut rt, 30);
    assert_eq!(phase(&rt), Phase::Hidden);
    assert_eq!(rt.shell_request, Some(Shell::Quit));
}

#[test]
fn alone_it_leaves_after_clearing_its_copy() {
    let mut rt = runtime("empty", true);
    let clip = share_clipboard([&mut rt, &mut runtime("empty", true)]);
    alone(&mut rt);
    frames(&mut rt, 2);
    rt.key(key(Key::Enter));
    frames(&mut rt, 120);
    assert_eq!(phase(&rt), Phase::Hidden);
    assert_eq!(rt.shell_request, None, "copy, then paste: it waits");
    assert_eq!(board(&clip).as_deref(), Some(PASSWORD));
    rt.frame(26.0);
    assert_eq!(rt.shell_request, None);
    assert_eq!(board(&clip).as_deref(), Some(PASSWORD));
    rt.frame(2.5);
    assert_eq!(board(&clip), None, "cleared on time");
    assert_eq!(rt.shell_request, Some(Shell::Quit), "then it leaves");
}

#[test]
fn with_the_main_window_around_it_stays() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 2);
    rt.key(key(Key::Escape));
    frames(&mut rt, 30);
    assert_eq!(phase(&rt), Phase::Hidden);
    assert_eq!(rt.shell_request, None);
}

#[test]
fn closing_its_window_cleans_up_like_the_main_one() {
    let mut rt = runtime("locked", true);
    let clip = share_clipboard([&mut rt, &mut runtime("empty", true)]);
    rt.update(|s, _| s.passphrase.insert("x"));
    rt.state.clipboard.copy(PASSWORD).unwrap();
    rt.update(|s, tx| s.panel_closed(tx));
    assert!(rt.state.passphrase.text.is_empty());
    assert_eq!(board(&clip), None, "the clipboard is cleared");
    assert_eq!(rt.shell_request, None, "the main window is still around");

    let mut rt = runtime("copied", true);
    let clip = share_clipboard([&mut rt, &mut runtime("empty", true)]);
    rt.update(|s, tx| s.copy_field("password", tx));
    alone(&mut rt);
    rt.update(|s, tx| s.panel_closed(tx));
    assert!(rt.state.detail.is_none() && rt.state.items.is_empty());
    assert_eq!(board(&clip), None);
    assert_eq!(rt.shell_request, Some(Shell::Quit), "alone, it leaves");
}
