//! Motion on the app's own screens, headless and offline: nothing that
//! appears or leaves pops, and what stays moves.

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

#[test]
fn an_item_synced_in_fades_into_the_list_and_the_selection_stays() {
    use deadbolt_app::agent::Done;
    let mut rt = runtime("vault");
    let selected = rt.state.selected.clone();
    let mut items = rt.state.items.clone();
    let mut synced = items[0].clone();
    synced.id = "b7d1e2".repeat(10) + "0000";
    synced.label = "Bitwarden".into();
    items.push(synced.clone());
    items.sort_by_key(|i| i.label.to_lowercase());
    let generation = rt.state.generation();
    rt.update(|s, tx| {
        let result = Ok(items);
        s.apply(Done::Items { generation, result }, tx)
    });
    rt.frame(FRAME);
    let key = format!("item-{}", synced.id);
    let (_, fade) = at(&rt, &key).expect("the synced row is in the list");
    assert!(fade < 0.5, "the synced row fades in (opacity {fade})");
    let sel_key = format!("item-{}", selected.as_deref().unwrap());
    let (row_y, _) = at(&rt, &sel_key).unwrap();
    let (lit_y, _) = at(&rt, "highlight").unwrap();
    assert!(
        (row_y - lit_y).abs() < 0.5,
        "the highlight rides its row during sync ({lit_y} vs {row_y})"
    );
    for _ in 0..60 {
        rt.frame(FRAME);
    }
    assert_eq!(at(&rt, &key).unwrap().1, 1.0);
    assert_eq!(rt.state.selected, selected, "the selection stays");
}

#[test]
fn the_agent_locking_swaps_to_the_lock_screen_softly() {
    use deadbolt_app::agent::Done;
    use deadbolt_client::protocol::Change;
    let mut rt = runtime("vault");
    rt.update(|s, tx| s.apply(Done::Changed(Change::Locked), tx));
    rt.frame(FRAME);
    let (_, leaving) = at(&rt, "vault").expect("the vault is still leaving");
    assert!(
        leaving > 0.0 && leaving < 1.0,
        "the vault fades out ({leaving})"
    );
    assert!(rt.state.items.is_empty() && rt.state.detail.is_none());
    for _ in 0..60 {
        rt.frame(FRAME);
    }
    assert_eq!(at(&rt, "vault"), None);
    assert_eq!(at(&rt, "passphrase").map(|(_, o)| o), Some(1.0));
}

fn tap(rt: &mut Runtime<App>, key: rune::Key) {
    rt.key(rune::KeyEvent {
        key,
        mods: rune::Mods::default(),
    });
    rt.frame(FRAME);
}

fn row_keys(rt: &Runtime<App>) -> Vec<String> {
    rt.state
        .visible()
        .iter()
        .map(|i| format!("item-{}", i.id))
        .collect()
}

/// Typing and esc replace the list in the frame they happen: no row fades
/// or slides, a selection the search filters out takes its fields with it,
/// and the item pane never swaps out for "No matches".
#[test]
fn a_search_replaces_the_list_at_once() {
    let mut rt = runtime("vault");
    rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
    let all = row_keys(&rt);
    let shown = |rt: &Runtime<App>, key: &str| at(rt, key).map(|(_, o)| o);

    for c in "git".chars() {
        tap(&mut rt, rune::Key::Text(c.into()));
    }
    let kept = row_keys(&rt);
    assert!(!kept.is_empty() && kept.len() < all.len());
    for key in &all {
        let want = kept.contains(key).then_some(1.0);
        assert_eq!(shown(&rt, key), want, "{key} after typing");
    }
    let github = rt.state.selected.clone();
    assert_eq!(shown(&rt, "field-password"), Some(1.0), "github.com stays");

    tap(&mut rt, rune::Key::Text("l".into()));
    assert_ne!(rt.state.selected, github, "gitlab.com is selected");
    assert_eq!(shown(&rt, "field-password"), None, "github.com's fields go");

    for c in "zzz".chars() {
        tap(&mut rt, rune::Key::Text(c.into()));
    }
    assert_eq!(shown(&rt, "no-match"), Some(1.0));
    assert!(all.iter().all(|key| shown(&rt, key).is_none()));
    assert_eq!(shown(&rt, "item"), Some(1.0), "the pane stays put");

    tap(&mut rt, rune::Key::Escape);
    assert_eq!(rt.state.search.text, "");
    assert_eq!(shown(&rt, "no-match"), None);
    for key in &all {
        assert_eq!(shown(&rt, key), Some(1.0), "{key} after esc");
    }
}

/// The selected item's values, as the agent's reply brings them.
fn deliver(rt: &mut Runtime<App>) {
    use deadbolt_app::agent::{Done, Values};
    use deadbolt_client::protocol::FieldInfo;
    let mut item = rt.state.selected_item().unwrap().clone();
    item.fields = vec![FieldInfo {
        name: "password".into(),
        kind: "secret".into(),
        value: "hunter22".into(),
    }];
    let seq = rt.state.seq();
    rt.update(|s, tx| {
        let result = Ok(Values::new(item));
        s.apply(Done::Item { seq, result }, tx)
    });
    rt.frame(FRAME);
}

/// A new selection, by ↑↓ or a click, drops the old item's fields in the
/// same frame, and its title replaces in place.
#[test]
fn a_new_selection_replaces_the_item_at_once() {
    let mut rt = runtime("vault");
    // The app's clock, which ends a held page.
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.frame(FRAME);
    let rows = row_keys(&rt);
    let title = |rt: &Runtime<App>| {
        let e = rt
            .elements()
            .into_iter()
            .rfind(|e| e.key.as_deref() == Some("title"))
            .unwrap();
        (e.text.unwrap(), e.opacity)
    };
    let label = |rt: &Runtime<App>| rt.state.selected_item().unwrap().label.clone();
    let before = label(&rt);
    assert_eq!(at(&rt, "field-password").map(|(_, o)| o), Some(1.0));

    tap(&mut rt, rune::Key::Down);
    assert_ne!(label(&rt), before);
    assert_eq!(at(&rt, "field-password"), None, "no field lingers after ↓");
    assert_eq!(title(&rt), (label(&rt), 1.0));

    deliver(&mut rt);
    assert_eq!(at(&rt, "field-password").map(|(_, o)| o), Some(1.0));

    // A click to a row with no page ready keeps the page before whole (its
    // title and fields, never a mix), then shows the title alone.
    let shown = label(&rt);
    let (x, y) = rt.find(&rows[0]).unwrap();
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    rt.frame(FRAME);
    assert_eq!(rt.state.selected.as_deref(), rows[0].strip_prefix("item-"));
    assert_eq!(title(&rt), (shown, 1.0), "the page before, held");
    assert_eq!(at(&rt, "field-password").map(|(_, o)| o), Some(1.0));
    for _ in 0..(deadbolt_app::model::HOLD / FRAME).ceil() as usize + 1 {
        rt.frame(FRAME);
    }
    assert_eq!(
        at(&rt, "field-password"),
        None,
        "no field lingers once the hold ends"
    );
    assert_eq!(title(&rt), (label(&rt), 1.0), "the click's title");
}

#[test]
fn overlays_and_settings_appear_and_leave_at_once() {
    let mut rt = runtime("vault");
    rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
    let cmd = |c| rune::KeyEvent {
        key: rune::Key::Command(c),
        mods: rune::Mods {
            cmd: true,
            ..rune::Mods::default()
        },
    };

    // ⌘K menu appears and leaves without a fade.
    rt.key(cmd('k'));
    rt.frame(FRAME);
    assert_eq!(at(&rt, "palette-over").map(|(_, o)| o), Some(1.0));
    tap(&mut rt, rune::Key::Escape);
    assert_eq!(at(&rt, "palette-over"), None);

    // ? shortcut sheet appears and leaves without a fade.
    rt.update(|_, tx| tx.blur());
    rt.frame(FRAME);
    tap(&mut rt, rune::Key::Text("?".into()));
    assert_eq!(at(&rt, "sheet").map(|(_, o)| o), Some(1.0));
    tap(&mut rt, rune::Key::Escape);
    assert_eq!(at(&rt, "sheet"), None);

    // ⌘, Settings swaps with the vault page without crossfading.
    rt.key(cmd(','));
    rt.frame(FRAME);
    assert_eq!(at(&rt, "settings").map(|(_, o)| o), Some(1.0));
    assert_eq!(at(&rt, "vault"), None);
    tap(&mut rt, rune::Key::Escape);
    assert_eq!(at(&rt, "settings"), None);
    assert_eq!(at(&rt, "vault").map(|(_, o)| o), Some(1.0));
}

#[test]
fn the_copy_notice_slides_out_when_it_leaves() {
    let mut rt = runtime("copied");
    let (rest_y, opacity) = at(&rt, "copy-notice").expect("copy notice shown");
    assert_eq!(opacity, 1.0);

    rt.update(|s, _| s.copy = None);
    rt.frame(FRAME);
    let (exit_y, exit_opacity) = at(&rt, "copy-notice").expect("copy notice exiting");
    assert!(
        exit_opacity > 0.0 && exit_opacity < 1.0,
        "fades out ({exit_opacity})"
    );
    assert!(
        exit_y > rest_y,
        "slides down 12 pt on exit instead of freezing ({rest_y} -> {exit_y})"
    );
}

#[test]
fn settings_keys_scroll_offscreen_rows_into_view() {
    let mut rt = runtime("settings");
    rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
    rt.set_viewport((640.0, 420.0), 1.0);
    for _ in 0..10 {
        rt.frame(FRAME);
    }
    let viewport = rt
        .elements()
        .into_iter()
        .find(|e| e.key.as_deref() == Some("settings"))
        .unwrap()
        .rect;
    for _ in 0..10 {
        tap(&mut rt, rune::Key::Text("j".into()));
    }
    for _ in 0..60 {
        rt.frame(FRAME);
    }
    let row = rt
        .elements()
        .into_iter()
        .find(|e| e.key.as_deref() == Some("set-activity-row"))
        .unwrap()
        .rect;
    assert!(
        row[1] + row[3] <= viewport[1] + viewport[3] - 20.0,
        "activity row scrolled clear of the bottom edge ({row:?} in {viewport:?})"
    );
}
