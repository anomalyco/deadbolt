//! The vault's keys, headless and offline: ↑↓, ⏎ and ⇧⏎ work wherever focus
//! is, a clicked row hands focus back to the search, ⌘F and ⌘K go to the
//! search, and esc clears it.

#![cfg(test)]

use deadbolt_app::model::App;
use rune::{Env, Key, KeyEvent, Mods, Runtime};

const FRAME: f64 = 1.0 / 60.0;

fn scene(name: &str) -> Runtime<App> {
    let app = rune::tooling::initial_state(&deadbolt_app::spec(), Some(name));
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
    settle(&mut rt, 1.0);
    rt
}

fn settle(rt: &mut Runtime<App>, seconds: f64) {
    for _ in 0..(seconds / FRAME).round() as usize {
        rt.frame(FRAME);
    }
}

fn press(rt: &mut Runtime<App>, key: Key, mods: Mods) {
    rt.key(KeyEvent { key, mods });
    rt.frame(FRAME);
}

fn tap(rt: &mut Runtime<App>, key: Key) {
    press(rt, key, Mods::default());
}

fn command(rt: &mut Runtime<App>, c: char) {
    let mods = Mods {
        cmd: true,
        ..Mods::default()
    };
    press(rt, Key::Command(c), mods);
}

/// Nothing focused, as after a click on empty space.
fn blur(rt: &mut Runtime<App>) {
    rt.update(|_, tx| tx.blur());
    settle(rt, 0.1);
    assert!(!rt.state.search.focused);
}

fn click(rt: &mut Runtime<App>, key: &str) {
    let (x, y) = rt.find(key).unwrap_or_else(|| panic!("{key} is on screen"));
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    settle(rt, 0.1);
}

fn ids(rt: &Runtime<App>) -> Vec<String> {
    rt.state.visible().iter().map(|i| i.id.clone()).collect()
}

fn copied(rt: &Runtime<App>) -> Option<&str> {
    rt.state.copy.as_ref().map(|c| c.field.as_str())
}

#[test]
fn a_clicked_row_keeps_the_keys_in_the_search() {
    let mut rt = scene("vault");
    let ids = ids(&rt);
    assert!(rt.state.search.focused);

    click(&mut rt, &format!("item-{}", ids[1]));
    assert_eq!(rt.state.selected.as_deref(), Some(ids[1].as_str()));
    assert!(rt.state.search.focused, "focus went back to the search");

    tap(&mut rt, Key::Down);
    assert_eq!(rt.state.selected.as_deref(), Some(ids[2].as_str()));
    tap(&mut rt, Key::Up);
    tap(&mut rt, Key::Up);
    assert_eq!(rt.state.selected.as_deref(), Some(ids[0].as_str()));

    // Typing still searches.
    tap(&mut rt, Key::Text("g".into()));
    assert_eq!(rt.state.search.text, "g");
}

#[test]
fn vault_keys_work_with_nothing_focused() {
    let mut rt = scene("vault");
    let ids = ids(&rt);
    let at = |rt: &Runtime<App>| {
        let id = rt.state.selected.clone().unwrap();
        ids.iter().position(|i| *i == id).unwrap()
    };
    blur(&mut rt);
    // The scene holds the selected item's values; moving would wait on the agent.
    press(
        &mut rt,
        Key::Enter,
        Mods {
            shift: true,
            ..Mods::default()
        },
    );
    assert_eq!(copied(&rt), Some("username"));
    tap(&mut rt, Key::Enter);
    assert_eq!(copied(&rt), Some("password"));

    let from = at(&rt);
    tap(&mut rt, Key::Down);
    assert_eq!(at(&rt), from + 1);
    tap(&mut rt, Key::Up);
    assert_eq!(at(&rt), from);
    assert!(!rt.state.search.focused, "nothing took focus");
}

#[test]
fn command_f_and_k_focus_the_search_with_its_text_selected() {
    for c in ['f', 'k'] {
        let mut rt = scene("search");
        let query = rt.state.search.text.clone();
        assert!(!query.is_empty(), "the scene has a query");
        blur(&mut rt);

        command(&mut rt, c);
        settle(&mut rt, 0.1);
        let search = &rt.state.search;
        assert!(search.focused, "⌘{c} focused the search");
        assert_eq!(search.selected(), query, "⌘{c} selected the query");

        // Typing replaces it.
        tap(&mut rt, Key::Text("h".into()));
        assert_eq!(rt.state.search.text, "h");
    }
}

#[test]
fn escape_clears_a_search_wherever_focus_is() {
    for focused in [true, false] {
        let mut rt = scene("search");
        let all = rt.state.items.len();
        assert!(rt.state.visible().len() < all, "the scene filters");
        if !focused {
            blur(&mut rt);
        }
        tap(&mut rt, Key::Escape);
        assert_eq!(rt.state.search.text, "", "focused {focused}");
        assert_eq!(rt.state.visible().len(), all);
    }
}

/// With nothing focused too, the import view keeps ⏎ and ⇧⏎ from the item
/// hidden under it.
#[test]
fn the_import_view_keeps_keys_from_the_item_with_nothing_focused() {
    let mut rt = scene("import");
    assert!(rt.state.import.showing());
    blur(&mut rt);
    for shift in [false, true] {
        press(
            &mut rt,
            Key::Enter,
            Mods {
                shift,
                ..Mods::default()
            },
        );
        assert_eq!(copied(&rt), None, "copied with shift {shift}");
        assert!(rt.state.import.showing());
    }
    command(&mut rt, 'f');
    assert!(rt.state.search.focused);
    tap(&mut rt, Key::Enter);
    assert_eq!(copied(&rt), None, "nor once the search has focus");
}

/// The whole search control takes a press, not just its text line: the
/// icon and the padding inside its border focus it and never drag the window.
#[test]
fn a_press_anywhere_on_the_search_focuses_it() {
    let mut rt = scene("vault");
    let r = rt
        .elements()
        .into_iter()
        .find(|e| e.key.as_deref() == Some("search-input"))
        .unwrap()
        .rect;
    let (mid, right) = (r[1] + r[3] / 2.0, r[0] + r[2]);
    let points = [
        ("the icon", r[0] + 16.0, mid),
        ("the top padding", r[0] + r[2] / 2.0, r[1] + 2.0),
        ("the trailing padding", right - 3.0, mid),
    ];
    for (what, x, y) in points {
        blur(&mut rt);
        rt.pointer_move(x, y);
        rt.pointer_down(x, y);
        assert_eq!(rt.take_titlebar_action(), None, "{what} drags the window");
        rt.pointer_up(x, y);
        settle(&mut rt, 0.1);
        assert!(rt.state.search.focused, "{what} focuses the search");
    }
}

/// With the list hidden (⇧⌘B), ↑↓ and a search edit open it again, so the
/// selection never moves out of sight.
#[test]
fn a_hidden_list_opens_when_the_selection_moves() {
    let toggle = Mods {
        cmd: true,
        shift: true,
        ..Mods::default()
    };
    let mut rt = scene("vault");
    for step in [Key::Down, Key::Text("g".into()), Key::Escape] {
        if step == Key::Escape {
            tap(&mut rt, Key::Text("i".into()));
        }
        press(&mut rt, Key::Command('b'), toggle);
        assert!(!rt.state.sidebar.is_open(), "⇧⌘B hides the list");
        // Rune hands focus to the sidebar button as the list hides.
        command(&mut rt, 'f');
        tap(&mut rt, step.clone());
        assert!(rt.state.sidebar.is_open(), "{step:?} opens it");
    }
}

/// Typing in the search with the import view showing closes it, so the list
/// it filters and the item it picks show.
#[test]
fn a_search_edit_closes_the_import_view() {
    let mut rt = scene("import");
    assert!(rt.state.import.showing());
    tap(&mut rt, Key::Text("f".into()));
    assert!(!rt.state.import.showing(), "the import view closed");
    let selected = rt.state.selected.clone().unwrap();
    assert!(
        rt.state.visible().iter().any(|i| i.id == selected),
        "the selection is a match"
    );
    settle(&mut rt, 0.6);
    assert!(rt.find("title").is_some(), "the item shows");
}
