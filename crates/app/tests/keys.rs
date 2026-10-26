//! The vault's keys, headless and offline: ↑↓, ⏎ and ⇧⏎ work wherever focus
//! is, a clicked row hands focus back to the search, ⌘F and ⌘K go to the
//! search, and esc clears it.

#![cfg(test)]

use deadbolt_app::import::Phase;
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
        .find(|e| e.key.as_deref() == Some("search"))
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
/// selection never moves out of sight. Hiding it leaves focus in the search,
/// so typing goes on straight after.
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
        assert!(rt.state.search.focused, "⇧⌘B keeps the search focused");
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

/// The search box's rect.
fn search_box(rt: &Runtime<App>) -> [f32; 4] {
    rt.elements()
        .into_iter()
        .find(|e| e.key.as_deref() == Some("search"))
        .unwrap()
        .rect
}

/// A press on the icon of a focused search keeps the focus all the way,
/// with frames between down and up, and when the pointer leaves before
/// it's released.
#[test]
fn a_press_on_the_focused_search_never_blurs_it() {
    let mut rt = scene("vault");
    let r = search_box(&rt);
    let (x, y) = (r[0] + 16.0, r[1] + r[3] / 2.0);
    let held = |rt: &Runtime<App>, what: &str| {
        assert!(rt.state.search.focused, "focused {what}");
    };
    for leave in [false, true] {
        assert!(rt.state.search.focused);
        rt.pointer_move(x, y);
        rt.pointer_down(x, y);
        assert_eq!(rt.take_titlebar_action(), None, "no window drag");
        rt.frame(FRAME);
        held(&rt, "after the press");
        let (ux, uy) = if leave {
            (r[0] + r[2] + 120.0, y + 60.0)
        } else {
            (x, y)
        };
        rt.pointer_move(ux, uy);
        rt.frame(FRAME);
        held(&rt, "while held");
        rt.pointer_up(ux, uy);
        settle(&mut rt, 0.1);
        held(&rt, &format!("after the release (left {leave})"));
    }
}

/// From the import view too, ↑↓ and a search edit open a hidden list, and a
/// search edit during an import that can't be cancelled opens it while
/// leaving the import view up.
#[test]
fn the_import_view_opens_a_hidden_list() {
    let toggle = Mods {
        cmd: true,
        shift: true,
        ..Mods::default()
    };
    let mut rt = scene("import-nothing-new");
    press(&mut rt, Key::Command('b'), toggle);
    assert!(!rt.state.sidebar.is_open());
    tap(&mut rt, Key::Down);
    assert!(
        !rt.state.import.showing() && rt.state.sidebar.is_open(),
        "↓"
    );

    let mut rt = scene("import-nothing-new");
    rt.update(|s, _| {
        let preview = s.import.preview().unwrap().0.clone();
        s.import.phase = Phase::Importing(preview);
    });
    press(&mut rt, Key::Command('b'), toggle);
    tap(&mut rt, Key::Text("f".into()));
    assert!(rt.state.import.showing(), "the import runs on");
    assert!(rt.state.sidebar.is_open(), "a search edit");
}

/// A search typed while an import runs leaves the item it hides alone, and
/// picks a match once the view it ends on (here "nothing new") goes.
#[test]
fn a_search_during_an_import_is_honoured_once_it_goes() {
    let mut rt = scene("import-nothing-new");
    let preview = rt.state.import.preview().unwrap().0.clone();
    rt.update(|s, _| s.import.phase = Phase::Importing(preview.clone()));
    let github = rt.state.selected.clone();
    command(&mut rt, 'f');
    for c in "fly".chars() {
        tap(&mut rt, Key::Text(c.into()));
    }
    assert_eq!(rt.state.search.text, "fly");
    assert_eq!(rt.state.selected, github, "the hidden item stays");

    rt.update(|s, _| s.import.phase = Phase::Preview(preview));
    tap(&mut rt, Key::Escape);
    assert!(!rt.state.import.showing());
    assert_eq!(rt.state.selected_item().unwrap().label, "fly.io");
}

/// The row that has focus, if any.
fn focused_row(rt: &Runtime<App>) -> Option<String> {
    rt.elements()
        .into_iter()
        .find(|e| e.focused && e.key.as_deref().is_some_and(|k| k.starts_with("item-")))
        .and_then(|e| e.key)
}

/// Rows never take focus, so the keys stay with the search and the
/// selection: Tab passes them by, a press released off an unselected row
/// leaves the search focused, and Space with nothing focused selects
/// nothing, nor closes the import view.
#[test]
fn rows_never_take_focus() {
    for name in ["vault", "import"] {
        let mut rt = scene(name);
        let selected = rt.state.selected.clone();
        let importing = rt.state.import.showing();
        for _ in 0..12 {
            tap(&mut rt, Key::Tab);
            assert_eq!(focused_row(&rt), None, "Tab ({name})");
        }

        blur(&mut rt);
        let row = ids(&rt)
            .into_iter()
            .find(|i| Some(i) != selected.as_ref())
            .unwrap();
        let (x, y) = rt.find(&format!("item-{row}")).unwrap();
        rt.pointer_move(x, y);
        rt.pointer_down(x, y);
        rt.frame(FRAME);
        rt.pointer_move(x + 400.0, y);
        rt.frame(FRAME);
        rt.pointer_up(x + 400.0, y);
        settle(&mut rt, 0.1);
        assert_eq!(
            focused_row(&rt),
            None,
            "a press released off a row ({name})"
        );
        assert!(
            rt.state.search.focused,
            "the search has focus back ({name})"
        );
        assert_eq!(rt.state.selected, selected, "the press selected ({name})");
        assert_eq!(
            rt.state.import.showing(),
            importing,
            "the press closed the import view"
        );

        blur(&mut rt);
        tap(&mut rt, Key::Text(" ".into()));
        settle(&mut rt, 0.1);
        assert_eq!(rt.state.selected, selected, "Space selected a row ({name})");
        assert_eq!(
            rt.state.import.showing(),
            importing,
            "Space closed the import view"
        );
    }
}
