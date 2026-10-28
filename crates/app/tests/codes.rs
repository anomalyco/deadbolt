//! One-time codes: the agent computes each, the detail shows it with a
//! countdown, the app asks for the next once per period and never holds the
//! secret, ⌥⏎ copies it, and locking drops it. Headless, against the scenes'
//! fixed code (RFC 6238's secret, 18 s of 30 left) or a real agent.

#![cfg(test)]

mod support;

use deadbolt_app::agent::{Agent, Done, Job, Values};
use deadbolt_app::model::{App, CODE_SLACK, Screen};
use deadbolt_app::panel::{self, Phase};
use deadbolt_client::protocol::{Change, Code, FieldInfo};
use rune::clipboard::MemoryClipboard;
use rune::{Env, Key, KeyEvent, Mods, Runtime};
use std::sync::mpsc::{Receiver, Sender};

use support::{Device, until};

const FRAME: f64 = 1.0 / 60.0;
/// github.com's id (its start), the vault scene's selection.
const GITHUB: &str = "3f9a1c";
/// Every login's password in the scenes.
const PASSWORD: &str = "correct-horse-battery-staple";

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
    rt.frame(0.0);
    rt
}

/// The quick panel's scene `name`.
fn panel_scene(name: &str) -> Runtime<App> {
    let app = rune::tooling::initial_state(&panel::spec(), Some(name));
    let mut rt = Runtime::new(
        app,
        panel::view::panel,
        panel::SIZE,
        Env {
            system_dark: true,
            scale: 1.0,
        },
    );
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.on_key = Some(|s, ev, tx| s.panel_key(ev, tx));
    rt.frame(0.0);
    rt
}

/// The vault scene with an agent the test answers for.
fn scripted() -> (Runtime<App>, Receiver<Job>, Sender<Done>, MemoryClipboard) {
    script(scene("vault"))
}

/// `rt` with an agent the test answers for, and a clipboard.
fn script(mut rt: Runtime<App>) -> (Runtime<App>, Receiver<Job>, Sender<Done>, MemoryClipboard) {
    let (agent, jobs, replies) = Agent::scripted();
    rt.state.agent = agent;
    let board = rune::clipboard::memory();
    rt.use_clipboard(&board);
    rt.frame(FRAME);
    (rt, jobs, replies, board)
}

/// Runs `seconds` of frames, a quarter second at a time.
fn run(rt: &mut Runtime<App>, seconds: f64) {
    for _ in 0..(seconds / 0.25).round() as usize {
        rt.frame(0.25);
    }
}

/// The code jobs sent since the last call.
fn code_jobs(jobs: &Receiver<Job>) -> Vec<String> {
    jobs.try_iter()
        .filter_map(|j| match j {
            Job::Code { id, .. } => Some(id[..GITHUB.len()].to_owned()),
            _ => None,
        })
        .collect()
}

fn code(digits: &str, valid_until: u64, remaining_ms: u64) -> Code {
    Code {
        code: digits.to_owned().into(),
        period: 30,
        valid_until,
        remaining_ms,
    }
}

/// Text on screen, including what a `RollingText` shows (its label).
fn shows(rt: &Runtime<App>, s: &str) -> bool {
    rt.elements().iter().filter(|e| !e.exiting).any(|e| {
        e.text.as_deref() == Some(s) || (e.role == "text" && e.label.as_deref() == Some(s))
    })
}

fn labelled(rt: &Runtime<App>, label: &str) -> bool {
    rt.elements()
        .iter()
        .any(|e| !e.exiting && e.label.as_deref() == Some(label))
}

fn bar_width(rt: &Runtime<App>) -> f32 {
    rt.elements()
        .iter()
        .rfind(|e| !e.exiting && e.key.as_deref().is_some_and(|k| k.starts_with("code-bar-")))
        .map(|e| e.rect[2])
        .expect("the countdown bar")
}

fn option_enter(rt: &mut Runtime<App>) {
    rt.key(KeyEvent {
        key: Key::Enter,
        mods: Mods {
            alt: true,
            ..Mods::default()
        },
    });
    rt.frame(FRAME);
}

fn enter(rt: &mut Runtime<App>) {
    rt.key(KeyEvent {
        key: Key::Enter,
        mods: Mods::default(),
    });
    rt.frame(FRAME);
}

/// The shown code's period is over, and the next not asked for yet.
fn expire(rt: &mut Runtime<App>) {
    rt.update(|s, _| {
        let now = s.clock;
        s.otp.as_mut().unwrap().until = now - 1.0;
    });
}

/// When the next code is due, on the runtime's clock.
fn due(rt: &Runtime<App>) -> f64 {
    rt.state.otp.as_ref().unwrap().until + CODE_SLACK
}

fn field(name: &str, kind: &str, value: &str) -> FieldInfo {
    FieldInfo {
        name: name.into(),
        kind: kind.into(),
        value: value.into(),
    }
}

fn text(board: &MemoryClipboard) -> Option<String> {
    board.text().map(|t| t.as_str().to_owned())
}

#[test]
fn the_code_shows_grouped_with_copy_and_no_show() {
    let mut rt = scene("vault");
    run(&mut rt, 1.0);
    assert!(shows(&rt, "One-time code"));
    assert!(shows(&rt, "279 037"), "grouped 3+3");
    assert!(labelled(&rt, "Copy one-time code"));
    assert!(!labelled(&rt, "Show otp") && !labelled(&rt, "Show one-time code"));
    assert!(rt.find("h-code").is_some(), "⌥⏎'s hint");
    let otp = rt.state.otp.as_ref().unwrap();
    assert!(otp.item.starts_with(GITHUB));
    let detail = rt.state.detail.as_ref().unwrap();
    let field = detail.fields.iter().find(|f| f.name == "otp").unwrap();
    assert!(field.value.is_empty(), "the app holds no secret");
}

#[test]
fn the_countdown_empties_over_the_period() {
    let mut rt = scene("vault");
    rt.frame(FRAME);
    let start = bar_width(&rt);
    run(&mut rt, 9.0);
    let half = bar_width(&rt);
    assert!(
        (half - start / 2.0).abs() < 1.5,
        "9 s of 18 left halves it: {start} → {half}"
    );
}

#[test]
fn the_next_code_is_asked_for_once_per_period_and_rolls_in() {
    let (mut rt, jobs, replies, _) = scripted();
    let wake = rt.wake_deadline().expect("a wake for the next code");
    assert!((wake - due(&rt)).abs() < 1e-6, "{wake} vs {}", due(&rt));
    run(&mut rt, 17.5);
    assert!(
        code_jobs(&jobs).is_empty(),
        "nothing asked while the code is valid"
    );
    run(&mut rt, 1.0);
    assert_eq!(code_jobs(&jobs), [GITHUB], "one ask at the boundary");
    run(&mut rt, 2.0);
    assert!(code_jobs(&jobs).is_empty(), "no more while it's on its way");

    let seq = rt.state.seq();
    replies
        .send(Done::Code {
            seq,
            result: Ok(code("123456", 2_000_000_040, 29_000)),
        })
        .unwrap();
    run(&mut rt, 1.0);
    assert!(shows(&rt, "123 456"));
    assert_eq!(rt.state.otp.as_ref().unwrap().turns, 2, "a new period");
    assert_eq!(rt.wake_deadline(), Some(due(&rt)), "and a wake for its end");

    run(&mut rt, 27.5);
    assert!(code_jobs(&jobs).is_empty());
    run(&mut rt, 1.0);
    assert_eq!(code_jobs(&jobs), [GITHUB]);

    // A reply tagged for another request is dropped.
    replies
        .send(Done::Code {
            seq: seq + 1,
            result: Ok(code("999999", 2_000_000_070, 30_000)),
        })
        .unwrap();
    run(&mut rt, 1.0);
    assert!(!shows(&rt, "999 999"));
}

#[test]
fn option_enter_copies_the_code_or_the_next_one() {
    let (mut rt, jobs, replies, board) = scripted();
    option_enter(&mut rt);
    assert_eq!(text(&board).as_deref(), Some("279037"));
    assert!(labelled(&rt, "One-time code copied"));

    // Past the period, with the next not here yet: copied as it lands.
    run(&mut rt, 30.0);
    jobs.try_iter().count();
    board.set_text("mine");
    option_enter(&mut rt);
    assert_eq!(text(&board).as_deref(), Some("mine"));
    replies
        .send(Done::Code {
            seq: rt.state.seq(),
            result: Ok(code("654321", 2_000_000_040, 0)),
        })
        .unwrap();
    rt.frame(FRAME);
    assert_eq!(
        text(&board).as_deref(),
        Some("654321"),
        "the code asked for, however little time it has left"
    );
}

/// A code that arrives at its period's very end isn't asked for again
/// until `CODE_SLACK` after it.
#[test]
fn a_code_with_no_time_left_is_not_asked_for_again_at_once() {
    let (mut rt, jobs, replies, _) = scripted();
    run(&mut rt, 18.25);
    assert_eq!(code_jobs(&jobs), [GITHUB]);
    replies
        .send(Done::Code {
            seq: rt.state.seq(),
            result: Ok(code("123456", 2_000_000_040, 0)),
        })
        .unwrap();
    for _ in 0..2 {
        rt.frame(FRAME);
    }
    assert!(code_jobs(&jobs).is_empty(), "not again within the slack");
    run(&mut rt, 0.25);
    assert_eq!(code_jobs(&jobs), [GITHUB]);
}

/// ⌥⏎ past the period, then ⏎: the password stays copied when the code
/// lands.
#[test]
fn another_copy_replaces_a_code_on_its_way() {
    let (mut rt, jobs, replies, board) = scripted();
    expire(&mut rt);
    option_enter(&mut rt);
    assert_eq!(code_jobs(&jobs), [GITHUB]);
    enter(&mut rt);
    assert_eq!(text(&board).as_deref(), Some(PASSWORD));
    replies
        .send(Done::Code {
            seq: rt.state.seq(),
            result: Ok(code("654321", 2_000_000_040, 20_000)),
        })
        .unwrap();
    run(&mut rt, 0.5);
    assert_eq!(text(&board).as_deref(), Some(PASSWORD));
    assert!(shows(&rt, "654 321"), "the code still shows");
}

/// The same in the quick panel, whose confirmation also drops what lands
/// while it shows.
#[test]
fn a_late_code_in_the_panel_leaves_its_copy_alone() {
    let (mut rt, jobs, replies, board) = script(panel_scene("filtering"));
    expire(&mut rt);
    option_enter(&mut rt);
    assert_eq!(code_jobs(&jobs), [GITHUB]);
    assert_eq!(text(&board), None);
    enter(&mut rt);
    assert_eq!(text(&board).as_deref(), Some(PASSWORD));
    assert!(matches!(rt.state.panel_phase(), Some(Phase::Copied { .. })));
    replies
        .send(Done::Code {
            seq: rt.state.seq(),
            result: Ok(code("654321", 2_000_000_040, 20_000)),
        })
        .unwrap();
    rt.frame(FRAME);
    assert_eq!(text(&board).as_deref(), Some(PASSWORD));
    let otp = rt.state.otp.as_ref().unwrap();
    assert_eq!(otp.code.as_deref().map(String::as_str), Some("279037"));
    assert!(code_jobs(&jobs).is_empty());
}

/// Should an otp secret come, it's wiped on arrival; a second otp field
/// has nothing to show or copy.
#[test]
fn otp_secrets_never_stay_in_the_app() {
    let (mut rt, _jobs, replies, _) = scripted();
    let mut item = rt.state.selected_item().cloned().unwrap();
    item.fields = vec![
        field("password", "secret", PASSWORD),
        field("otp", "otp", "JBSWY3DPEHPK3PXP"),
        field("backup", "otp", "KRSXG5CTMVRXEZLU"),
    ];
    replies
        .send(Done::Item {
            seq: rt.state.seq(),
            result: Ok(Values::with_code(
                item,
                Ok(code("123456", 2_000_000_040, 20_000)),
            )),
        })
        .unwrap();
    run(&mut rt, 0.5);
    let detail = rt.state.detail.as_ref().unwrap();
    let values: Vec<_> = detail.fields.iter().map(|f| f.value.as_str()).collect();
    assert_eq!(values, [PASSWORD, "", ""]);
    assert!(shows(&rt, "123 456"));
    assert!(labelled(&rt, "Copy password"));
    assert!(!labelled(&rt, "Copy backup") && !labelled(&rt, "Show backup"));
}

#[test]
fn locking_drops_the_code() {
    let (mut rt, _jobs, replies, _) = scripted();
    run(&mut rt, 1.0);
    replies.send(Done::Changed(Change::Locked)).unwrap();
    run(&mut rt, 1.0);
    assert_eq!(rt.state.screen, Screen::Locked);
    assert!(rt.state.otp.is_none());
    assert!(!shows(&rt, "279 037"));
}

#[test]
fn an_item_without_an_otp_has_no_code() {
    let (mut rt, jobs, replies, _) = scripted();
    rt.key(KeyEvent {
        key: Key::Down,
        mods: Mods::default(),
    });
    rt.frame(FRAME);
    let seq = jobs
        .try_iter()
        .find_map(|j| match j {
            Job::Get { seq, .. } => Some(seq),
            _ => None,
        })
        .expect("the item's values asked for");
    let mut item = rt.state.selected_item().cloned().unwrap();
    assert!(!item.id.starts_with(GITHUB));
    item.fields = vec![field("password", "secret", PASSWORD)];
    replies
        .send(Done::Item {
            seq,
            result: Ok(Values::new(item)),
        })
        .unwrap();
    run(&mut rt, 1.0);
    assert!(
        rt.state
            .detail
            .as_ref()
            .is_some_and(|d| d.fields.len() == 1)
    );
    assert!(labelled(&rt, "Copy password"));
    assert!(rt.state.otp.is_none());
    assert!(!shows(&rt, "One-time code") && rt.find("h-code").is_none());
    assert!(shows(&rt, "Actions"));
}

/// Against a real agent: the item's reply carries the code, not the secret.
#[test]
fn the_agent_computes_the_code() {
    let device = Device::new();
    device.run(&["init"]);
    device.run(&[
        "new",
        "login",
        "url=github.com",
        "password=pw",
        "otp=otpauth://totp/GitHub:dax?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
    ]);
    let agent = Agent::spawn(device.paths(), device.launch());
    let mut rt = Runtime::new(
        App::new(agent),
        deadbolt_app::view::app,
        (820.0, 540.0),
        Env {
            system_dark: true,
            scale: 1.0,
        },
    );
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
    rt.state.agent.send(Job::Connect);
    until(&mut rt, "github.com's code", |s| {
        s.otp.as_ref().is_some_and(|o| o.code.is_some())
    });
    let otp = rt.state.otp.as_ref().unwrap();
    let code = otp.code.as_ref().unwrap();
    assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()));
    assert!(otp.until > rt.state.clock && otp.until <= rt.state.clock + 30.0);
    let detail = rt.state.detail.as_ref().unwrap();
    let field = detail.fields.iter().find(|f| f.name == "otp").unwrap();
    assert!(field.value.is_empty(), "the agent left the secret out");
}
