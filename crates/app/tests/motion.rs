//! Motion on the app's own screens, headless and offline: nothing that
//! appears or leaves pops, and what stays moves.

#![cfg(test)]

use deadbolt_app::model::App;
use rune::{Env, Runtime};

const FRAME: f64 = 1.0 / 60.0;

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
    for _ in 0..60 {
        rt.frame(FRAME);
    }
    rt
}

/// (y, opacity) of the innermost element keyed `key`, if it's on screen.
fn at(rt: &Runtime<App>, key: &str) -> Option<(f32, f32)> {
    rt.elements()
        .into_iter()
        .rfind(|e| e.key.as_deref() == Some(key))
        .map(|e| (e.rect[1], e.opacity))
}

#[test]
fn an_unlock_error_fades_in_and_the_button_moves_down() {
    let mut rt = runtime("locked");
    let (from, _) = at(&rt, "unlock").unwrap();
    rt.update(|s, _| s.unlock_error = Some("That passphrase didn't unlock this device.".into()));
    rt.frame(FRAME);
    let (y, _) = at(&rt, "unlock").unwrap();
    let (_, fade) = at(&rt, "error").unwrap();
    assert!(fade < 0.5, "the error fades in (opacity {fade})");
    for _ in 0..60 {
        rt.frame(FRAME);
    }
    let (to, _) = at(&rt, "unlock").unwrap();
    assert!(to > from + 4.0, "the button makes room ({from} -> {to})");
    assert!(
        from < y && y < to,
        "the button moves, not jumps ({from} -> {y} -> {to})"
    );
    assert_eq!(at(&rt, "error").unwrap().1, 1.0);
}

#[test]
fn the_agent_notice_fades_in_and_out() {
    let mut rt = runtime("vault");
    rt.update(|s, _| s.notice = Some("The agent refused.".into()));
    rt.frame(FRAME);
    let (_, fade) = at(&rt, "agent-notice").unwrap();
    assert!(fade < 0.5, "fades in (opacity {fade})");
    for _ in 0..60 {
        rt.frame(FRAME);
    }
    assert_eq!(at(&rt, "agent-notice").unwrap().1, 1.0);
    rt.update(|s, _| s.notice = None);
    rt.frame(FRAME);
    let (_, fade) = at(&rt, "agent-notice").expect("still leaving");
    assert!(fade > 0.0 && fade < 1.0, "fades out (opacity {fade})");
    for _ in 0..60 {
        rt.frame(FRAME);
    }
    assert_eq!(at(&rt, "agent-notice"), None);
}
