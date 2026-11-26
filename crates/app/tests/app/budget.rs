//! Allocation budgets for the hot paths: filtering a long list as the
//! search changes, and the frames that draw it. Each thread's allocations
//! are counted (`procwatch::alloc::Counting` is this binary's allocator),
//! so the counts are exact and tests running alongside don't move them. A
//! ceiling that fails means the path started allocating more: find what,
//! rather than raising it.

use deadbolt_app::MANY;
use deadbolt_app::model::App;
use procwatch::alloc::thread_allocations;
use rune::{Env, Key, KeyEvent, Mods, Runtime};

const FRAME: f64 = 1.0 / 60.0;

fn scene() -> Runtime<App> {
    let app = rune::tooling::initial_state(&deadbolt_app::spec(), Some("vault-243"));
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
    settle(&mut rt);
    rt
}

fn settle(rt: &mut Runtime<App>) {
    for _ in 0..60 {
        rt.frame(FRAME);
    }
}

/// The allocations `f` makes on this thread.
fn counted<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let before = thread_allocations();
    let out = f();
    (out, thread_allocations() - before)
}

#[test]
fn the_counting_allocator_is_installed() {
    let (_, n) = counted(|| std::hint::black_box(vec![0u8; 64]));
    assert_eq!(n, 1, "the test binary counts allocations");
}

/// Filtering all 243 items allocates for the query and the result, never
/// once per item: a per-item allocation would put each query over 243.
#[test]
fn filtering_a_long_list_allocates_per_query_not_per_item() {
    // At most 8 today; a per-item allocation would be 243 or more.
    const CEILING: u64 = 16;
    let mut rt = scene();
    assert_eq!(rt.state.items.len(), MANY);
    for (query, rows) in [
        ("", MANY),
        ("acme", 27),
        ("acme user1", 11),
        ("#work", 0),
        ("is:favorite", 0),
        ("zzz", 0),
    ] {
        rt.state.search = rune::TextEdit::new(query);
        let (visible, n) = counted(|| rt.state.visible_at());
        assert_eq!(visible.len(), rows, "{query:?} matches");
        assert!(n <= CEILING, "{query:?}: {n} allocations, over {CEILING}");
    }
}

/// A frame with nothing new to show allocates next to nothing, and the
/// frame a keystroke filters and redraws the list in stays bounded by the
/// rows on screen, not the 243 in the vault.
#[test]
fn a_frame_over_a_long_list_stays_within_its_budget() {
    const IDLE: u64 = 16;
    // About 1,800 today, for the rows in the scroll window.
    const KEYSTROKE: u64 = 2_400;
    let mut rt = scene();
    let (_, idle) = counted(|| rt.frame(FRAME));
    assert!(
        idle <= IDLE,
        "an idle frame: {idle} allocations, over {IDLE}"
    );

    let (_, key) = counted(|| {
        rt.key(KeyEvent {
            key: Key::Text("a".into()),
            mods: Mods::default(),
        });
        rt.frame(FRAME);
    });
    assert_eq!(rt.state.search.text, "a");
    assert!(
        key <= KEYSTROKE,
        "a keystroke's frame: {key} allocations, over {KEYSTROKE}"
    );

    settle(&mut rt);
    let (_, idle) = counted(|| rt.frame(FRAME));
    assert!(
        idle <= IDLE,
        "an idle frame in a search: {idle} allocations, over {IDLE}"
    );
}
