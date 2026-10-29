//! Holding an arrow down a long list: every frame shows a whole page, the
//! highlight is on the selection on the frame it's made, and the requests
//! waiting on the agent stay few. The `vault-243` scene's agent answers on
//! the app's clock, `LOOPBACK_COST` a request.

use std::collections::VecDeque;

use deadbolt_app::MANY;
use deadbolt_app::agent::{Done, Job, next_jobs};
use deadbolt_app::model::{App, is_secret};
use deadbolt_client::protocol::Change;
use rune::{Env, Key, KeyEvent, Mods, Runtime};

const FRAME: f64 = 1.0 / 60.0;
/// macOS's fastest key repeat, about 30 ms: one ↓ every other frame.
const REPEAT: usize = 2;

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
    settle(&mut rt, 0.5);
    rt
}

fn settle(rt: &mut Runtime<App>, seconds: f64) {
    for _ in 0..(seconds / FRAME).round() as usize {
        rt.frame(FRAME);
    }
}

fn key(rt: &mut Runtime<App>, key: Key) {
    rt.key(KeyEvent {
        key,
        mods: Mods::default(),
    });
}

/// The innermost element keyed `key`'s top, if it's drawn.
fn top(rt: &Runtime<App>, key: &str) -> Option<f32> {
    rt.elements()
        .into_iter()
        .rfind(|e| e.key.as_deref() == Some(key))
        .map(|e| e.rect[1])
}

#[test]
fn holding_down_shows_a_whole_page_every_frame() {
    let mut rt = scene();
    assert_eq!(rt.state.visible().len(), MANY);
    assert!(rt.state.detail.is_some(), "the first item's values are in");
    // Steps that showed the page before for a frame: only the first, whose
    // row wasn't read ahead (the scene's selection reads none).
    let mut missed = Vec::new();
    for step in 0..MANY - 1 {
        key(&mut rt, Key::Down);
        for _ in 0..REPEAT {
            rt.frame(FRAME);
            let selected = rt.state.selected.clone().unwrap();
            let (head, full) = rt.state.page_view().unwrap();
            assert!(full.is_some(), "step {step}: the page has its fields");
            if head.id != selected {
                missed.push(step);
            }
            // The highlight is on the selected row, not on its way there.
            let row = top(&rt, &format!("item-{selected}")).unwrap();
            let lit = top(&rt, "highlight").unwrap();
            assert!((row - lit).abs() < 0.5, "step {step}: {lit} is on {row}");
        }
        let (waiting, _) = rt.state.agent.backlog().unwrap();
        assert!(waiting <= 8, "step {step}: {waiting} requests wait");
    }
    let (_, most) = rt.state.agent.backlog().unwrap();
    assert!(most <= 8, "at most {most} requests ever waited");
    assert!(
        missed.iter().all(|&step| step < 2),
        "the page before showed at steps {missed:?}"
    );
    settle(&mut rt, 0.5);
    let last = rt.state.visible().last().unwrap().id.clone();
    assert_eq!(rt.state.selected.as_deref(), Some(last.as_str()));
    let detail = rt
        .state
        .detail
        .as_ref()
        .expect("the last item's values land");
    assert_eq!(detail.id, last);
}

#[test]
fn the_cache_keeps_no_secret_and_goes_with_the_vault() {
    let mut rt = scene();
    for _ in 0..10 {
        key(&mut rt, Key::Down);
        settle(&mut rt, 0.1);
    }
    let cache = &rt.state.cache;
    assert!(cache.len() > 10, "{} pages kept", cache.len());
    for item in rt.state.visible().iter().take(14) {
        let Some(page) = cache.get(&item.id) else {
            continue;
        };
        for field in page.fields.iter().filter(|f| is_secret(&f.kind)) {
            assert!(
                field.value.is_empty(),
                "{}'s {} is kept",
                item.label,
                field.name
            );
        }
        assert!(page.fields.iter().any(|f| f.name == "username"));
    }
    // A change elsewhere forgets every page.
    rt.update(|s, tx| s.apply(Done::Changed(Change::Resync), tx));
    assert!(rt.state.cache.is_empty());
    settle(&mut rt, 0.3);
    key(&mut rt, Key::Down);
    settle(&mut rt, 0.3);
    assert!(!rt.state.cache.is_empty());
    rt.update(|s, tx| s.apply(Done::Changed(Change::Locked), tx));
    assert!(rt.state.cache.is_empty() && rt.state.detail.is_none());
}

#[test]
fn a_copy_on_a_cached_page_copies_its_own_values() {
    let mut rt = scene();
    // A move reads the next rows ahead; selecting one shows its page at once.
    key(&mut rt, Key::Down);
    settle(&mut rt, 0.3);
    let next = rt.state.visible()[2].id.clone();
    assert!(rt.state.cache.contains(&next));
    key(&mut rt, Key::Down);
    rt.frame(FRAME);
    assert!(
        rt.state.detail.is_none(),
        "its values are still on their way"
    );
    key(&mut rt, Key::Enter);
    rt.frame(FRAME);
    assert!(rt.state.copy.is_none());
    settle(&mut rt, 0.2);
    let copy = rt
        .state
        .copy
        .as_ref()
        .expect("the copy waits for the values");
    assert_eq!(
        (copy.item.as_str(), copy.field.as_str()),
        (next.as_str(), "password")
    );
}

fn get(seq: u64, cached: bool) -> Job {
    Job::Get {
        id: seq.to_string(),
        seq,
        cached,
    }
}

fn peek(id: &str, batch: u64) -> Job {
    Job::Peek {
        id: id.into(),
        epoch: 0,
        batch,
    }
}

fn name(job: &Job) -> String {
    match job {
        Job::Get { seq, cached, .. } => {
            format!("get {seq}{}", if *cached { " cached" } else { "" })
        }
        Job::Peek { id, .. } => format!("peek {id}"),
        Job::List { .. } => "list".into(),
        _ => "other".into(),
    }
}

fn order(jobs: Vec<Job>) -> Vec<String> {
    let mut queue: VecDeque<Job> = jobs.into();
    let mut out = Vec::new();
    loop {
        let round = next_jobs(&mut queue);
        if round.is_empty() {
            return out;
        }
        out.push(round.iter().map(name).collect::<Vec<_>>().join(" + "));
    }
}

#[test]
fn the_worker_runs_the_newest_get_and_reads_ahead_last() {
    // Only the newest selection's values; a page that shows waits for the reads ahead.
    let jobs = vec![
        get(1, false),
        peek("a", 1),
        get(2, true),
        peek("b", 2),
        peek("c", 2),
        Job::List { generation: 0 },
    ];
    assert_eq!(order(jobs), ["list", "peek b + peek c + get 2 cached"]);
    // A page with nothing to show goes first; reads run a few at once.
    let jobs = vec![peek("a", 1), get(3, false)];
    assert_eq!(order(jobs), ["get 3 + peek a"]);
    // A copy hurries a cached one.
    let jobs = vec![get(4, true), peek("a", 1), get(4, false)];
    assert_eq!(order(jobs), ["get 4 + peek a"]);
    // Anything else runs alone, in turn.
    let jobs = vec![
        peek("a", 1),
        peek("b", 1),
        Job::List { generation: 0 },
        get(5, false),
    ];
    assert_eq!(order(jobs), ["list", "get 5 + peek a + peek b"]);
}
