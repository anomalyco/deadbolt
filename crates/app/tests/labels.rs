//! What the main controls say to assistive tech, headless and offline.

#![cfg(test)]

use deadbolt_app::model::App;
use deadbolt_app::panel;
use rune::{Env, Runtime};

fn runtime(spec: &rune::AppSpec<App>, size: (f32, f32), scene: &str) -> Runtime<App> {
    let app = rune::tooling::initial_state(spec, Some(scene));
    let mut rt = Runtime::new(
        app,
        spec.view,
        size,
        Env {
            system_dark: true,
            scale: 1.0,
        },
    );
    rt.frame(1.0 / 60.0);
    rt
}

/// (role, label) of every element with a label.
fn labels(rt: &Runtime<App>) -> Vec<(&'static str, String)> {
    rt.elements()
        .into_iter()
        .filter_map(|e| Some((e.role, e.label?)))
        .collect()
}

fn has(rt: &Runtime<App>, role: &str, label: &str) -> bool {
    labels(rt).iter().any(|(r, l)| *r == role && l == label)
}

#[test]
fn the_vault_names_its_controls() {
    let rt = runtime(&deadbolt_app::spec(), (820.0, 540.0), "copied");
    for (role, label) in [
        ("textbox", "Search items"),
        ("listbox", "Items"),
        ("option", "github.com"),
        ("button", "Show password"),
        ("button", "Password copied"),
        ("button", "Copy username"),
        ("button", "Copy URL"),
        ("button", "Lock"),
    ] {
        assert!(
            has(&rt, role, label),
            "no {role} {label:?} in {:?}",
            labels(&rt)
        );
    }
    // macOS has "Open Quick Panel" in its menus instead.
    assert_eq!(
        has(&rt, "button", "Open quick panel"),
        !cfg!(target_os = "macos")
    );
}

#[test]
fn the_quick_panel_names_its_controls() {
    let rt = runtime(&panel::spec(), panel::SIZE, "empty");
    assert!(has(&rt, "textbox", "Search items"), "{:?}", labels(&rt));
    assert!(has(&rt, "listbox", "Items"), "{:?}", labels(&rt));
}
