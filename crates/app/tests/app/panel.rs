//! The quick panel, headless and offline: each state renders inside the card,
//! it opens fresh and at rest, Escape and a copy both close it, its motion
//! (rows filtering, the footer's copy line, the close fading) never pops, it
//! shares one clipboard with the main window, and its global shortcut brings
//! it up from anywhere.

use deadbolt_app::agent::{Agent, Done, Job, Values};
use deadbolt_app::model::{App, Screen};
use deadbolt_app::panel::window::Windows;
use deadbolt_app::panel::{self, Phase};
use deadbolt_client::protocol::{Change, ItemInfo};
use rune::clipboard::MemoryClipboard;
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

fn main_scene(scene: &str) -> Runtime<App> {
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
    rt.frame(0.0);
    rt
}

/// The main window, on the vault scene with an item's values showing.
fn main_window() -> Runtime<App> {
    main_scene("vault")
}

/// One clipboard for both windows, as Rune gives every window in a process.
fn share_clipboard(windows: [&mut Runtime<App>; 2]) -> MemoryClipboard {
    let clipboard = rune::clipboard::memory();
    for rt in windows {
        rt.use_clipboard(&clipboard);
    }
    clipboard
}

fn board(clipboard: &MemoryClipboard) -> Option<String> {
    clipboard.text().map(|t| t.as_str().to_owned())
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
    rt.state.windows = Some(Windows::new(main.handle(), quick.handle()));
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
        .any(|e| e.text.as_deref() == Some(s) && e.opacity > 0.0)
}

/// The footer's line once it's fully in: what ⏎ does or the copy, a failed
/// copy, or a notice.
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
        .find_map(|e| e.text.clone())
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

/// The glyphs of a rolling label that are at rest, in order: opaque, and
/// centred on its line (the label's rect also holds the roll's fade).
fn steady(rt: &Runtime<App>, label: &str) -> String {
    let rect = find(rt, label).expect("the label").0;
    let middle = rect[1] + rect[3] / 2.0;
    glyphs(rt, label)
        .iter()
        .filter(|g| g.2 >= 0.99 && (g.1[1] + g.1[3] / 2.0 - middle).abs() < 0.01)
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
    rt.update(|s, _| {
        s.installer = Some(installer);
        s.settings_open = true;
    });
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
    assert!(i.open && rt.state.settings_open, "no popover took the keys");
}

#[test]
fn escape_fades_the_card_then_hides() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 10);
    rt.key(key(Key::Escape));
    rt.frame(FRAME);
    fades_then_hides(&mut rt, "Escape");
}

/// A window draws no frames while nothing moves, so the app's clock stands
/// still until an event's frame; the time passes with no poll.
fn idle(rt: &mut Runtime<App>) {
    let poll = rt.poll.take();
    rt.frame(5.0);
    rt.poll = poll;
}

fn fades_then_hides(rt: &mut Runtime<App>, how: &str) {
    assert!(matches!(phase(rt), Phase::Closing { .. }), "{how} closes");
    frames(rt, 5);
    let fade = find(rt, "card").expect("still fading").1;
    assert!(fade > 0.0 && fade < 1.0, "{how}: the card fades ({fade})");
    frames(rt, 20);
    assert_eq!(phase(rt), Phase::Hidden, "{how}");
    let gone = find(rt, "card").map_or(0.0, |c| c.1);
    assert!(
        gone < 0.01,
        "{how}: faded out by the time it hides ({gone})"
    );
}

#[test]
fn after_a_pause_escape_and_clicking_away_still_fade() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 10);
    idle(&mut rt);
    rt.key(key(Key::Escape));
    rt.frame(FRAME);
    fades_then_hides(&mut rt, "Escape");

    let mut rt = runtime("empty", true);
    frames(&mut rt, 10);
    idle(&mut rt);
    rt.update(|s, tx| s.panel_focus(false, tx));
    rt.frame(FRAME);
    fades_then_hides(&mut rt, "clicking away");
}

#[test]
fn after_a_pause_a_copy_still_confirms() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 10);
    idle(&mut rt);
    rt.key(key(Key::Enter));
    rt.frame(FRAME);
    assert!(matches!(phase(&rt), Phase::Copied { .. }));
    frames(&mut rt, 50);
    assert!(
        matches!(phase(&rt), Phase::Copied { .. }),
        "the confirmation shows its full time"
    );
    frames(&mut rt, 30);
    assert!(matches!(phase(&rt), Phase::Closing { .. } | Phase::Hidden));
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
    assert!(
        rt.state.passphrase.text.is_empty(),
        "forgotten as the card starts leaving"
    );
    assert!(rt.state.passphrase.is_secure());
    frames(&mut rt, 30);
    assert_eq!(phase(&rt), Phase::Hidden);
}

/// The locked panel's passphrase field hands ⇧⌘Space to the panel, which
/// closes and forgets what was typed.
#[test]
fn the_shortcut_closes_the_locked_panel_from_its_field() {
    let mut rt = runtime("locked", true);
    frames(&mut rt, 2);
    assert!(rt.has_secure_focus());
    for c in "hunt".chars() {
        rt.key(key(Key::Text(c.into())));
    }
    rt.key(shortcut());
    rt.frame(FRAME);
    assert!(matches!(phase(&rt), Phase::Closing { .. }));
    assert!(rt.state.passphrase.text.is_empty());
    assert!(rt.state.passphrase.is_secure());
}

/// Both unlock fields: a paste (what ⌘V does) lands on one line, but nothing
/// copies, cuts or undoes the passphrase out, ⌃ and ⇧⌘ chords type nothing,
/// and closing leaves an empty secure field.
#[test]
fn the_passphrase_stays_in_its_field() {
    let with = |key, mods| KeyEvent { key, mods };
    let cmd = Mods {
        cmd: true,
        ..Mods::default()
    };
    let ctrl = Mods {
        ctrl: true,
        ..Mods::default()
    };
    for mut rt in [runtime("locked", true), main_scene("locked")] {
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
        rt.key(with(Key::Text("j".into()), ctrl));
        rt.frame(FRAME);
        assert_eq!(rt.state.passphrase.text, "hunter22");
        if rt.state.panel.is_none() {
            rt.key(shortcut());
            rt.frame(FRAME);
        }
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

/// Clicking away goes as Escape does: the card fades, the window hides, and
/// what was read and typed is forgotten.
#[test]
fn clicking_away_closes_it_and_forgets() {
    for scene in ["filtering", "locked"] {
        let mut rt = runtime(scene, true);
        rt.key(key(Key::Down));
        rt.key(key(Key::Text("h".into())));
        frames(&mut rt, 2);
        rt.update(|s, tx| s.panel_focus(true, tx));
        rt.frame(FRAME);
        assert_eq!(
            phase(&rt),
            Phase::Open,
            "{scene}: gaining focus does nothing"
        );

        rt.update(|s, tx| s.panel_focus(false, tx));
        rt.frame(FRAME);
        assert!(matches!(phase(&rt), Phase::Closing { .. }), "{scene}");
        assert!(rt.state.passphrase.text.is_empty(), "{scene}");
        frames(&mut rt, 30);
        assert_eq!(phase(&rt), Phase::Hidden, "{scene}");
        assert!(
            rt.state.items.is_empty() && rt.state.selected.is_none(),
            "{scene}"
        );
        assert!(rt.state.detail.is_none(), "{scene}");
        let gone = find(&rt, "card").map_or(0.0, |c| c.1);
        assert!(gone < 0.01, "{scene}: faded out ({gone})");
    }
}

/// Losing focus to its own copy's close, or once hidden, changes nothing.
#[test]
fn focus_loss_while_closing_keeps_the_copy() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 2);
    rt.key(key(Key::Enter));
    rt.frame(FRAME);
    rt.update(|s, tx| s.panel_focus(false, tx));
    rt.frame(FRAME);
    assert!(matches!(phase(&rt), Phase::Closing { .. }));
    assert!(rt.state.copy_pending(), "the copy still counts down");
    frames(&mut rt, 30);
    rt.update(|s, tx| s.panel_focus(false, tx));
    rt.frame(FRAME);
    assert_eq!(phase(&rt), Phase::Hidden);
}

/// The placement request itself; place.rs checks where it lands.
#[test]
fn it_opens_under_the_pointer_near_the_top() {
    use rune::{Align, DisplayTarget, OverlayPlacement, ScreenEdge};
    let (display, placement) = panel::window::PLACE;
    assert_eq!(display, DisplayTarget::UnderPointer);
    let OverlayPlacement::Edge {
        edge,
        align,
        margin,
        inset,
    } = placement
    else {
        panic!("placed against an edge: {placement:?}");
    };
    assert_eq!((edge, align), (ScreenEdge::Top, Align::Center));
    assert!(margin > 0.0 && margin < 300.0);
    assert_eq!(inset, 0.0, "centred, not nudged");
    // The shortest screen it should fit whole: a 13-inch laptop's default, 900 pt tall.
    assert!(margin + panel::SIZE.1 <= 900.0);
}

#[test]
fn a_copy_confirms_then_closes_and_reopens_clean() {
    let mut rt = runtime("empty", true);
    let items = rt.state.items.clone();
    frames(&mut rt, 10);
    assert_eq!(footer(&rt), "Copy password");
    let hints =
        |rt: &Runtime<App>| ["h-user", "h-close"].map(|key| find(rt, key).map(|(rect, _)| rect));
    let resting = hints(&rt);
    assert!(resting[1].is_some(), "esc Close shows");
    rt.key(key(Key::Enter));
    rt.frame(FRAME);
    assert!(matches!(phase(&rt), Phase::Copied { .. }));
    assert_eq!(hints(&rt), resting, "the hints hold still");
    assert!(rt.state.copy.as_ref().is_some_and(|c| c.error.is_none()));
    let line = find(&rt, "footer-line").expect("the same line");
    assert!(line.1 >= 0.99, "the line stays; its label rolls");
    assert_eq!(
        steady(&rt, "footer-line-label"),
        "Cop",
        "only \"Cop\" stays put"
    );
    for _ in 0..36 {
        rt.frame(FRAME);
        assert_eq!(hints(&rt), resting, "the hints hold still");
    }
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

/// While the copy's confirmation shows, a click on another row picks
/// nothing: the selection, its values and the copy stay, and it still closes.
#[test]
fn a_row_click_during_the_confirmation_does_nothing() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 10);
    let selected = rt.state.selected.clone();
    rt.key(key(Key::Enter));
    rt.frame(FRAME);
    assert!(matches!(phase(&rt), Phase::Copied { .. }));
    let other = rt
        .state
        .visible()
        .iter()
        .map(|i| i.id.clone())
        .find(|i| Some(i) != selected.as_ref())
        .unwrap();
    let (x, y) = rt.find(&format!("item-{other}")).unwrap();
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    frames(&mut rt, 2);
    assert_eq!(rt.state.selected, selected, "the click selected a row");
    assert!(rt.state.detail.is_some(), "the values stay");
    assert!(rt.state.copy_pending(), "the copy stays");
    frames(&mut rt, 34);
    assert_eq!(footer(&rt), COPIED);
    frames(&mut rt, 40);
    assert!(matches!(phase(&rt), Phase::Closing { .. } | Phase::Hidden));
}

/// While the copy's confirmation shows, the search takes nothing: a paste
/// (the just-copied password, say), even after a click on the field, leaves
/// it empty and the selection where it was, and Escape still closes.
#[test]
fn a_paste_during_the_confirmation_does_nothing() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 10);
    let selected = rt.state.selected.clone();
    rt.key(key(Key::Enter));
    rt.frame(FRAME);
    assert!(matches!(phase(&rt), Phase::Copied { .. }));
    assert!(!rt.state.search.focused, "the search let go");
    rt.paste(PASSWORD);
    frames(&mut rt, 2);
    let (x, y) = rt.find("search-field").unwrap();
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    rt.paste(PASSWORD);
    frames(&mut rt, 2);
    assert_eq!(rt.state.search.text, "");
    assert!(!rt.state.search.focused);
    assert_eq!(rt.state.selected, selected);
    rt.key(key(Key::Escape));
    frames(&mut rt, 2);
    assert!(matches!(phase(&rt), Phase::Closing { .. } | Phase::Hidden));
}

/// While the copy's confirmation shows, the list holds still: changes and
/// replies are dropped and nothing is fetched, and the next summon fetches
/// the list again with the search focused.
#[test]
fn the_list_holds_still_during_the_confirmation() {
    let mut rt = runtime("empty", true);
    let (agent, jobs, replies) = Agent::scripted();
    rt.state.agent = agent;
    frames(&mut rt, 10);
    let items = rt.state.items.clone();
    let selected = rt.state.selected.clone();
    let vault = rt.state.status.clone().unwrap().vaults[0].id.clone();
    rt.key(key(Key::Enter));
    rt.frame(FRAME);
    assert!(matches!(phase(&rt), Phase::Copied { .. }));
    jobs.try_iter().count();

    let mut moved = items.clone();
    moved.retain(|i| Some(&i.id) != selected.as_ref());
    for done in [
        Done::Changed(Change::Items { vault }),
        Done::Changed(Change::Resync),
        Done::Items {
            generation: rt.state.generation(),
            result: Ok(moved),
        },
    ] {
        replies.send(done).unwrap();
    }
    frames(&mut rt, 2);
    assert!(
        !jobs.try_iter().any(|j| matches!(j, Job::List { .. })),
        "nothing fetched"
    );
    let ids = |items: &[ItemInfo]| items.iter().map(|i| i.id.clone()).collect::<Vec<_>>();
    assert_eq!(ids(&rt.state.items), ids(&items));
    assert_eq!(rt.state.selected, selected);

    frames(&mut rt, 120);
    assert_eq!(phase(&rt), Phase::Hidden);
    rt.update(|s, tx| s.summon(tx));
    frames(&mut rt, 2);
    assert!(jobs.try_iter().any(|j| matches!(j, Job::List { .. })));
    assert!(rt.state.search.focused);
}

/// A copy whose write fails says why in the footer, and the panel stays
/// open rather than closing on a confirmation.
#[test]
fn a_failed_copy_stays_open_and_says_why() {
    let mut rt = runtime("empty", true);
    let clip = share_clipboard([&mut rt, &mut runtime("empty", true)]);
    clip.fail_writes(Some("no pasteboard"));
    frames(&mut rt, 10);
    rt.key(key(Key::Enter));
    frames(&mut rt, 30);
    assert!(shows(&rt, "Couldn't copy: no pasteboard"));
    assert!(!rt.state.copy_pending());
    assert!(rt.state.search.focused, "the search is back");
    assert_eq!(board(&clip), None);
    frames(&mut rt, 90);
    assert_eq!(phase(&rt), Phase::Open, "no confirmation to close on");
}

/// Typing replaces the list in the frame it happens, as in the vault.
#[test]
fn a_search_replaces_the_list_at_once() {
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
    assert!(!shows(&rt, "fly.io"), "gone at once");
    frames(&mut rt, 60);
    let to = find(&rt, &row).unwrap().0[1];
    assert!(to < from - 40.0, "github.com moves up ({from} -> {to})");
    assert_eq!(y, to, "it's there at once ({from} -> {y} -> {to})");
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

/// Hidden, the panel still clears its copy on time.
#[test]
fn a_hidden_panel_clears_its_copy_on_time() {
    let mut rt = runtime("empty", true);
    let clip = share_clipboard([&mut rt, &mut runtime("empty", true)]);
    frames(&mut rt, 2);
    rt.key(key(Key::Enter));
    frames(&mut rt, 120);
    assert_eq!(phase(&rt), Phase::Hidden);
    assert_eq!(board(&clip).as_deref(), Some(PASSWORD));
    let clears = rt.state.copy.as_ref().unwrap().remaining(rt.state.clock);
    rt.frame(clears - 0.1);
    assert_eq!(board(&clip).as_deref(), Some(PASSWORD), "not early");
    rt.frame(0.2);
    assert_eq!(board(&clip), None, "cleared on time");
}

/// A lock that reaches the hidden panel clears its copy and leaves nothing
/// to show when it next opens.
#[test]
fn a_lock_while_hidden_leaves_nothing_behind() {
    let mut rt = runtime("empty", true);
    let clip = share_clipboard([&mut rt, &mut runtime("empty", true)]);
    frames(&mut rt, 2);
    rt.key(key(Key::Enter));
    frames(&mut rt, 120);
    assert_eq!(phase(&rt), Phase::Hidden);

    rt.update(|s, tx| s.apply(Done::Locked(Ok(())), tx));
    rt.frame(FRAME);
    assert_eq!(board(&clip), None, "the lock clears the copy");
    assert!(rt.state.copy.is_none());
    assert!(rt.state.items.is_empty() && rt.state.detail.is_none());
    rt.update(|s, tx| s.summon(tx));
    frames(&mut rt, 2);
    assert!(shows(&rt, "Unlock Deadbolt"), "it opens locked");
    assert!(!shows(&rt, "github.com"));
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

    both(&mut quick, &mut main, FRAME);
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

/// Rune's own timer runs on the wall clock and can clear a moment before the
/// countdown ends: that's still the clear on time, and the notice says so.
#[test]
fn runes_clear_just_before_the_end_still_says_cleared() {
    let mut main = main_window();
    let clip = share_clipboard([&mut runtime("empty", true), &mut main]);
    main.update(|s, tx| s.copy_field("password", tx));
    main.frame(FRAME);
    assert_eq!(board(&clip).as_deref(), Some(PASSWORD));
    main.frame(29.8);
    main.state
        .copy
        .as_ref()
        .unwrap()
        .copied
        .as_ref()
        .unwrap()
        .clear_now();
    main.frame(FRAME);
    let copy = main.state.copy.as_ref().expect("the notice stays");
    assert!(
        copy.cleared_at.is_some(),
        "it says the clipboard was cleared"
    );
    frames(&mut main, 30);
    assert!(shows(&main, "Clipboard cleared"));
}

/// Started with `--panel` and the main window never opened, the hidden panel
/// waits for its global shortcut: it clears its copy on time and keeps running.
#[test]
fn alone_it_waits_for_the_shortcut() {
    let mut rt = runtime("empty", true);
    let clip = share_clipboard([&mut rt, &mut runtime("empty", true)]);
    alone(&mut rt);
    frames(&mut rt, 2);
    rt.key(key(Key::Enter));
    frames(&mut rt, 120);
    assert_eq!(phase(&rt), Phase::Hidden);
    assert_eq!(board(&clip).as_deref(), Some(PASSWORD));
    rt.frame(28.5);
    assert_eq!(board(&clip), None, "cleared on time");
    rt.frame(60.0);
    assert_eq!(rt.shell_request, None, "it stays for the shortcut");

    rt.update(|s, tx| s.toggle_panel(tx));
    rt.frame(FRAME);
    assert_eq!(phase(&rt), Phase::Open, "the shortcut brings it back");
    rt.update(|s, tx| s.toggle_panel(tx));
    rt.frame(FRAME);
    assert!(
        matches!(phase(&rt), Phase::Closing { .. }),
        "and sends it away"
    );
}

/// ⌘Q is the app menu's (on macOS; off it, closing the window quits), so
/// neither window takes it as a key. Closing the main window quits and
/// clears the copy.
#[test]
fn closing_the_main_window_quits_and_clears_the_copy() {
    let cmd_q = KeyEvent {
        key: Key::Command('q'),
        mods: Mods {
            cmd: true,
            ..Mods::default()
        },
    };
    let mut main = main_window();
    let clip = share_clipboard([&mut main, &mut runtime("empty", true)]);
    main.update(|s, tx| s.copy_field("password", tx));
    main.frame(FRAME);
    main.key(cmd_q.clone());
    main.frame(FRAME);
    assert_eq!(main.shell_request, None, "⌘Q is the menu's");
    assert_eq!(board(&clip).as_deref(), Some(PASSWORD));
    main.update(|s, tx| s.quit(tx));
    main.frame(FRAME);
    assert_eq!(main.shell_request, Some(Shell::Quit));
    assert_eq!(board(&clip), None, "quitting clears the copy");

    let mut quick = runtime("empty", true);
    quick.key(cmd_q);
    quick.frame(FRAME);
    assert_eq!(quick.shell_request, None);
    assert_eq!(phase(&quick), Phase::Open);
}

/// The menu's Quit, ⌘Q, the Dock and logout run each shown window's
/// `on_close` once and then exit, without draining queued updates (headless
/// runs have no OS quit, so this runs the hooks in Rune's order). The main
/// window's clears the copy; the panel's quit, queued behind it, never runs,
/// and the panel's own hook finds nothing of ours left to clear.
#[test]
fn quitting_from_the_menu_clears_the_copy_once() {
    let mut main = main_window();
    let mut quick = runtime("empty", true);
    let clip = share_clipboard([&mut main, &mut quick]);
    main.update(|s, tx| s.copy_field("password", tx));
    main.frame(FRAME);
    assert_eq!(board(&clip).as_deref(), Some(PASSWORD));
    main.update(|s, tx| s.quit(tx));
    assert_eq!(board(&clip), None, "the main window's hook clears it");
    clip.set_text("copied elsewhere");
    quick.update(|s, tx| s.panel_closed(tx));
    assert_eq!(
        board(&clip).as_deref(),
        Some("copied elsewhere"),
        "the panel's doesn't clear again"
    );
    assert_eq!(quick.shell_request, None, "nor quit again");
}

#[test]
fn closing_its_window_cleans_up_like_the_main_one() {
    let mut rt = runtime("locked", true);
    let clip = share_clipboard([&mut rt, &mut runtime("empty", true)]);
    rt.update(|s, _| s.passphrase.insert("x"));
    rt.update(|_, tx| {
        tx.copy_secret(PASSWORD, std::time::Duration::from_secs(30));
    });
    assert_eq!(board(&clip).as_deref(), Some(PASSWORD));
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
    assert_eq!(rt.shell_request, None, "alone, the shortcut brings it back");
}

/// Hidden, the panel follows a lock but reads nothing: changes that would
/// refetch the list, and replies that arrive anyway, leave it holding nothing.
#[test]
fn a_hidden_panel_fetches_and_holds_nothing() {
    let mut rt = runtime("empty", true);
    let (agent, jobs, replies) = Agent::scripted();
    rt.state.agent = agent;
    let items = rt.state.items.clone();
    let item = rt.state.detail.clone().expect("an item's values show");
    let status = rt.state.status.clone().expect("a status");
    frames(&mut rt, 2);
    rt.key(key(Key::Escape));
    frames(&mut rt, 30);
    assert_eq!(phase(&rt), Phase::Hidden);
    assert_eq!(jobs.try_iter().count(), 0);

    let vault = status.vaults[0].id.clone();
    let (generation, seq) = (rt.state.generation(), rt.state.seq());
    for done in [
        Done::Changed(Change::Watching),
        Done::Changed(Change::Resync),
        Done::Changed(Change::Unlocked),
        Done::Changed(Change::Items { vault }),
        Done::Changed(Change::Vaults),
        Done::Status(Some(status.clone())),
        Done::Items {
            generation,
            result: Ok(items),
        },
        Done::Item {
            seq,
            result: Ok(Values::new(item)),
        },
    ] {
        replies.send(done).unwrap();
    }
    frames(&mut rt, 2);
    let sent: Vec<_> = jobs.try_iter().collect();
    assert!(
        !sent
            .iter()
            .any(|job| matches!(job, Job::List { .. } | Job::Get { .. })),
        "nothing fetched"
    );
    assert!(
        rt.state.items.is_empty() && rt.state.detail.is_none(),
        "nothing held"
    );

    replies.send(Done::Changed(Change::Locked)).unwrap();
    frames(&mut rt, 2);
    assert_eq!(rt.state.screen, Screen::Locked, "a lock still reaches it");
}

/// ⌘L locks from the open panel (when no field took it), but not once it's
/// confirming a copy or closing.
#[test]
fn command_l_locks_only_while_open() {
    let command_l = KeyEvent {
        key: Key::Command('l'),
        mods: Mods {
            cmd: true,
            ..Mods::default()
        },
    };
    let mut rt = runtime("empty", true);
    let (agent, jobs, _replies) = Agent::scripted();
    rt.state.agent = agent;
    frames(&mut rt, 2);
    for phase in [
        Phase::Copied { until: None },
        Phase::Closing { until: None },
        Phase::Open,
    ] {
        let ev = command_l.clone();
        rt.update(move |s, tx| {
            s.panel.as_mut().unwrap().phase = phase;
            s.panel_key(&ev, tx);
        });
        let locked = jobs.try_iter().any(|job| matches!(job, Job::Lock));
        assert_eq!(locked, phase == Phase::Open, "{phase:?}");
    }
}

/// Forty logins: more than either window's list shows.
fn many_items() -> Vec<ItemInfo> {
    (0..40)
        .map(|i| ItemInfo {
            id: format!("{i:064x}"),
            short: format!("{i:04x}"),
            kind: "login".into(),
            label: format!("site-{i:02}.com"),
            detail: Some("dax".into()),
            fields: Vec::new(),
            source: None,
            deleted_at: None,
        })
        .collect()
}

/// Scrolling the list under a held press on a row cancels the press, in
/// both windows: the release selects nothing and the search keeps focus.
#[test]
fn scrolling_under_a_pressed_row_cancels_it() {
    let items = many_items();
    for (name, mut rt) in [("panel", runtime("empty", true)), ("main", main_window())] {
        answer_list(&mut rt, &items);
        rt.update(|s, _| s.selected = s.visible().first().map(|i| i.id.clone()));
        frames(&mut rt, 10);
        let selected = rt.state.selected.clone();
        let (x, y) = rt.find(&format!("item-{}", items[2].id)).unwrap();
        rt.pointer_move(x, y);
        rt.pointer_down(x, y);
        frames(&mut rt, 2);
        rt.wheel(x, y, -120.0);
        frames(&mut rt, 2);
        rt.pointer_up(x, y);
        frames(&mut rt, 2);
        assert_eq!(rt.state.selected, selected, "{name}: the release selected");
        assert!(rt.state.search.focused, "{name}: the search keeps focus");
    }
}

/// Rows that ↑ and ↓ bring into view stop clear of the list's faded edges, in
/// both windows, while the list's own ends still sit flush.
#[test]
fn a_selected_row_stops_clear_of_the_lists_fade() {
    const EDGE: f32 = 24.0;
    let items = many_items();
    for (name, mut rt) in [("panel", runtime("empty", true)), ("main", main_window())] {
        answer_list(&mut rt, &items);
        rt.update(|s, _| s.selected = s.visible().first().map(|i| i.id.clone()));
        frames(&mut rt, 10);
        let list = find(&rt, "list").expect("the list").0;
        let row = |rt: &Runtime<App>| {
            let id = rt.state.selected.clone().unwrap();
            find(rt, &format!("item-{id}")).expect("the selected row").0
        };
        let first = row(&rt);
        assert!(
            first[1] - list[1] < EDGE,
            "{name}: the top row sits flush, not pushed down"
        );

        for _ in 0..25 {
            rt.key(key(Key::Down));
            rt.frame(FRAME);
        }
        frames(&mut rt, 60);
        let r = row(&rt);
        let gap = list[1] + list[3] - (r[1] + r[3]);
        assert!(
            (gap - EDGE).abs() < 0.5,
            "{name}: ↓ stops {gap} above the bottom"
        );

        for _ in 0..10 {
            rt.key(key(Key::Up));
            rt.frame(FRAME);
        }
        frames(&mut rt, 60);
        let r = row(&rt);
        let gap = r[1] - list[1];
        assert!(
            (gap - EDGE).abs() < 0.5,
            "{name}: ↑ stops {gap} below the top"
        );
    }
}

/// At rest the footer's rolling label sets like the same words as one text:
/// its glyphs span the plain text's width to within half a device pixel.
#[test]
fn the_rolled_label_is_as_wide_as_plain_text() {
    fn plain(_: &(), _: &mut rune::Cx<()>) -> rune::El {
        rune::row().child(rune::text("Copy password").font(rune_theme_opencode::kit(true).ty.small))
    }
    let env = Env {
        system_dark: true,
        scale: 2.0,
    };
    let mut words = Runtime::new((), plain, (400.0, 100.0), env);
    words.frame(0.0);
    let width = words
        .elements()
        .iter()
        .find_map(|e| e.text.as_ref().map(|_| e.rect[2]));
    let width = width.expect("the plain text");

    let app = rune::tooling::initial_state(&panel::spec(), Some("empty"));
    let mut rt = Runtime::new(app, panel::view::panel, panel::SIZE, env);
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.frame(0.0);
    frames(&mut rt, 30);
    assert_eq!(steady(&rt, "footer-line-label"), "Copy password");
    let glyphs = glyphs(&rt, "footer-line-label");
    let left = glyphs.iter().map(|g| g.1[0]).fold(f32::MAX, f32::min);
    let right = glyphs
        .iter()
        .map(|g| g.1[0] + g.1[2])
        .fold(f32::MIN, f32::max);
    assert!(
        (right - left - width).abs() <= 0.25,
        "rolled {} vs plain {width}",
        right - left
    );
}

/// A press on the search icon focuses the field, and on a focused field
/// never blurs it, even when the pointer leaves before the release.
#[test]
fn a_press_on_the_search_icon_lands_in_the_field() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 2);
    let r = find(&rt, "leading").unwrap().0;
    let (x, y) = (r[0] + r[2] / 2.0, r[1] + r[3] / 2.0);
    rt.update(|_, tx| tx.blur());
    frames(&mut rt, 2);
    assert!(!rt.state.search.focused);
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    frames(&mut rt, 2);
    assert!(rt.state.search.focused, "the press focuses the field");

    rt.pointer_down(x, y);
    rt.frame(FRAME);
    assert!(rt.state.search.focused, "kept on the way down");
    rt.pointer_move(x + 200.0, y + 120.0);
    rt.frame(FRAME);
    rt.pointer_up(x + 200.0, y + 120.0);
    frames(&mut rt, 2);
    assert!(rt.state.search.focused, "kept after a release outside");
}

/// The row that has focus, if any.
fn focused_row(rt: &Runtime<App>) -> Option<String> {
    rt.elements()
        .into_iter()
        .find(|e| e.focused && e.key.as_deref().is_some_and(|k| k.starts_with("item-")))
        .and_then(|e| e.key)
}

/// Rows never take the search's focus: Tab passes them by, and after a
/// press released off an unselected row, typing (Space too) still goes to
/// the search and ↑↓ still move the selection.
#[test]
fn rows_never_take_the_search_focus() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 2);
    assert!(rt.state.search.focused);
    let selected = rt.state.selected.clone();
    for _ in 0..6 {
        rt.key(key(Key::Tab));
        rt.frame(FRAME);
        assert_eq!(focused_row(&rt), None, "Tab");
    }
    assert!(rt.state.search.focused, "Tab leaves the search focused");

    let row = rt
        .state
        .visible()
        .iter()
        .map(|i| i.id.clone())
        .find(|i| Some(i) != selected.as_ref())
        .unwrap();
    let (r, _) = find(&rt, &format!("item-{row}")).unwrap();
    let (x, y) = (r[0] + r[2] / 2.0, r[1] + r[3] / 2.0);
    let (fr, _) = find(&rt, "footer").unwrap();
    let (ux, uy) = (fr[0] + fr[2] / 2.0, fr[1] + fr[3] / 2.0);
    rt.pointer_move(x, y);
    rt.pointer_down(x, y);
    rt.frame(FRAME);
    rt.pointer_move(ux, uy);
    rt.frame(FRAME);
    rt.pointer_up(ux, uy);
    frames(&mut rt, 6);
    assert_eq!(focused_row(&rt), None, "a press released off a row");
    assert!(rt.state.search.focused, "the search keeps focus");
    assert_eq!(rt.state.selected, selected, "nothing was selected");

    rt.key(key(Key::Text(" ".into())));
    rt.key(key(Key::Text("g".into())));
    rt.frame(FRAME);
    assert_eq!(
        rt.state.search.text, " g",
        "Space and g typed into the search"
    );
}

/// A pasted or typed newline never lands in either window's search: it's
/// one line.
#[test]
fn the_search_is_one_line() {
    for mut rt in [runtime("empty", true), main_window()] {
        frames(&mut rt, 2);
        assert!(rt.state.search.focused);
        rt.paste("git\nhub\r\n");
        rt.frame(FRAME);
        rt.key(key(Key::Text("\n".into())));
        rt.frame(FRAME);
        let text = rt.state.search.text.clone();
        assert!(!text.contains(['\n', '\r']), "{text:?}");
    }
}

/// The search's clear button shows once something's typed, and empties it
/// without losing focus or the list.
#[test]
fn the_clear_button_empties_the_search() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 2);
    let clear = |rt: &Runtime<App>| {
        rt.elements()
            .into_iter()
            .find(|e| !e.exiting && e.role == "button" && e.label.as_deref() == Some("Clear"))
    };
    assert!(clear(&rt).is_none(), "nothing to clear");
    for c in "git".chars() {
        rt.key(key(Key::Text(c.into())));
    }
    frames(&mut rt, 2);
    assert_eq!(rt.state.search.text, "git");
    let r = clear(&rt).expect("a clear button").rect;
    let (x, y) = (r[0] + r[2] / 2.0, r[1] + r[3] / 2.0);
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    frames(&mut rt, 2);
    assert_eq!(rt.state.search.text, "");
    assert!(rt.state.search.focused);
    assert!(clear(&rt).is_none());
}

#[test]
fn panel_keys_work_when_the_search_loses_focus_and_palette_opens_at_once() {
    let mut rt = runtime("empty", true);
    frames(&mut rt, 4);
    let first = rt.state.selected.clone();

    // Clicking non-focusable chrome inside the panel blurs the search field.
    rt.update(|_, tx| tx.blur());
    frames(&mut rt, 2);
    assert!(!rt.state.search.focused);

    // ⌘K opens the actions menu at once, and Esc closes the menu before the panel.
    rt.key(KeyEvent {
        key: Key::Command('k'),
        mods: Mods {
            cmd: true,
            ..Mods::default()
        },
    });
    rt.frame(FRAME);
    assert_eq!(find(&rt, "actions").map(|(_, o)| o), Some(1.0));
    rt.key(key(Key::Down));
    rt.frame(FRAME);
    assert_eq!(rt.state.nav.palette, Some(1));
    rt.key(key(Key::Escape));
    rt.frame(FRAME);
    assert_eq!(find(&rt, "actions"), None);
    assert_eq!(
        phase(&rt),
        Phase::Open,
        "Esc closed the menu, not the panel"
    );

    // ↓ still moves the selection, and typing returns focus to the search.
    rt.key(key(Key::Down));
    rt.frame(FRAME);
    assert_ne!(rt.state.selected, first);
    rt.key(key(Key::Text("g".into())));
    rt.frame(FRAME);
    assert!(rt.state.search.focused);
    assert_eq!(rt.state.search.text, "g");
}

#[test]
fn panel_item_masks_empty_secrets_shows_code_errors_and_uses_cached_pages() {
    use deadbolt_client::protocol::FieldInfo;

    let mut rt = runtime("empty", true);
    frames(&mut rt, 2);
    let first_id = rt.state.selected.clone().unwrap();
    let item = rt.state.detail.clone().unwrap();

    // Cache the first item, add a backup otp with an empty value, and surface a code error.
    rt.update(move |s, tx| {
        s.cache.insert(&item, None, s.clock);
        if let Some(d) = &mut s.detail {
            d.fields.push(FieldInfo {
                name: "backup-otp".into(),
                kind: "otp".into(),
                value: String::new(),
            });
        }
        let seq = s.seq();
        s.apply(
            Done::Code {
                seq,
                result: Err(deadbolt_app::agent::Failure {
                    code: None,
                    message: "invalid secret".into(),
                }),
            },
            tx,
        );
    });
    rt.frame(FRAME);
    assert!(shows(&rt, "No code: invalid secret"));
    let backup = rt
        .elements()
        .into_iter()
        .find(|e| e.path.ends_with("field-backup-otp/value"))
        .expect("backup otp value");
    assert!(rt.element_is_secure(&backup.path));
    assert!(
        backup.rect[2] > 20.0,
        "empty secret still draws the 12-dot mask"
    );

    // Stepping away and back shows the cached page immediately while detail is still in flight.
    rt.key(key(Key::Down));
    rt.frame(FRAME);
    rt.key(key(Key::Up));
    rt.frame(FRAME);
    assert_eq!(rt.state.selected.as_deref(), Some(first_id.as_str()));
    assert!(rt.state.detail.is_none());
    assert!(
        find(&rt, "field-username").is_some(),
        "cached page renders at once"
    );
}
