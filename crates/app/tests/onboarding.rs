//! First run, headless and offline: every onboarding state renders in both
//! appearances, the forms confirm in place, and the moment the vault is ready
//! moves the way docs/app.md says.

#![cfg(test)]

use deadbolt_app::agent::{Done, Failure};
use deadbolt_app::model::{App, Screen};
use deadbolt_app::onboarding::worker::{Progress, Stage, Worker};
use deadbolt_app::onboarding::{Flow, Severity, Step, moment};
use rune::clipboard::MemoryClipboard;
use rune::{Env, Key, KeyEvent, Mods, Runtime};

const FRAME: f64 = 1.0 / 60.0;

fn runtime(scene: &str, dark: bool) -> Runtime<App> {
    let app = rune::tooling::initial_state(&deadbolt_app::spec(), Some(scene));
    let mut rt = Runtime::new(
        app,
        deadbolt_app::view::app,
        (820.0, 540.0),
        Env {
            system_dark: dark,
            scale: 1.0,
        },
    );
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
    rt
}

fn settle(rt: &mut Runtime<App>, seconds: f64) {
    for _ in 0..(seconds / FRAME).round() as usize {
        rt.frame(FRAME);
    }
}

fn shows(rt: &Runtime<App>, s: &str) -> bool {
    rt.elements()
        .iter()
        .any(|e| e.text.as_deref().is_some_and(|t| t.contains(s)) && e.opacity > 0.99)
}

/// The innermost element keyed `key`.
fn find(rt: &Runtime<App>, key: &str) -> Option<rune::runtime::ElementInfo> {
    rt.elements()
        .into_iter()
        .rfind(|e| e.key.as_deref() == Some(key))
}

fn key(key: Key) -> KeyEvent {
    KeyEvent {
        key,
        mods: Mods::default(),
    }
}

/// Types `text` into the focused field and lets hints fade in.
fn type_text(rt: &mut Runtime<App>, text: &str) {
    for c in text.chars() {
        rt.key(key(Key::Text(c.into())));
    }
    settle(rt, 0.4);
}

#[test]
fn every_state_renders_in_both_appearances() {
    let states: &[(&str, &[&str])] = &[
        (
            "welcome",
            &["Deadbolt", "Create a vault", "Join from another device"],
        ),
        ("welcome-set-up", &["holds no vault yet"]),
        (
            "create",
            &["Create a vault", "This device", "At least 8 characters."],
        ),
        ("create-typing", &["Fair.", "Doesn't match the passphrase."]),
        ("create-ready", &["Strong.", "Matches"]),
        ("create-invalid", &["Too short", "Use a-z, 0-9"]),
        ("create-failed", &["Couldn't create the vault"]),
        (
            "creating",
            &["Creating your vault", "Protecting your passphrase"],
        ),
        ("join", &["Join from another device", "Continue"]),
        (
            "ticket",
            &["Pair from your other device", "deadbolt pair", "DBPA"],
        ),
        ("code", &["Do the codes match?", "482 913", "They match"]),
        ("joining", &["Joining personal", "Receiving personal"]),
        ("join-declined", &["Stopped: the codes didn't match"]),
        ("join-cancelled", &["Join cancelled"]),
        ("join-failed", &["Couldn't join"]),
        (
            "empty",
            &["personal is empty", "Drop an export here", "Choose File…"],
        ),
        (
            "import-preview",
            &[
                "Import from 1Password",
                "214 new logins · 3 cards · 12 secure notes · 2 SSH keys · 1 identity",
            ],
        ),
        (
            "import-nothing-new",
            &["Everything in this export is already in personal", "Done"],
        ),
        (
            "import-error",
            &["Passwords.json isn't an export Deadbolt can read"],
        ),
        ("locked", &["Deadbolt", "Locked"]),
    ];
    for dark in [true, false] {
        for (scene, texts) in states {
            let mut rt = runtime(scene, dark);
            settle(&mut rt, 0.1);
            for t in *texts {
                assert!(shows(&rt, t), "{scene} (dark {dark}) shows {t:?}");
            }
        }
    }
}

#[test]
fn the_ticket_is_a_qr_code_and_the_copy_is_the_whole_command() {
    let mut rt = runtime("ticket", true);
    settle(&mut rt, 0.1);
    let qr = find(&rt, "qr").expect("a QR tile");
    assert!(qr.rect[2] >= 220.0, "big enough to scan across a desk");
    rt.update(|s, tx| s.copy_ticket(tx));
    rt.frame(FRAME);
    assert!(shows(&rt, "Copied"));
}

#[test]
fn the_create_form_confirms_in_place() {
    let mut rt = runtime("create", true);
    settle(&mut rt, 0.1);
    // Focus starts in the passphrase.
    type_text(&mut rt, "hunter22");
    assert!(shows(&rt, "Weak."));
    type_text(&mut rt, " correct horse");
    assert!(shows(&rt, "Strong."));
    assert!(
        !rt.elements()
            .iter()
            .any(|e| e.text.as_deref().is_some_and(|t| t.contains("hunter"))),
        "the passphrase never shows"
    );
    // Enter moves on to the repeat, which stays quiet while it's a prefix.
    rt.key(key(Key::Enter));
    rt.frame(FRAME);
    type_text(&mut rt, "hunter");
    assert!(shows(&rt, "Type it again"));
    type_text(&mut rt, "X");
    assert!(shows(&rt, "Doesn't match"));
    rt.key(key(Key::Backspace));
    type_text(&mut rt, "22 correct horse");
    assert_eq!(rt.state.onboarding.repeat.text, "hunter22 correct horse");
    assert!(shows(&rt, "Matches"));

    // A bad vault name stops the submit and says why, in place.
    rt.update(|s, _| s.onboarding.vault = rune::TextEdit::new("My Vault"));
    rt.update(|s, _| s.submit_create());
    settle(&mut rt, 0.4);
    assert_eq!(rt.state.onboarding.step, Step::Create);
    assert!(shows(&rt, "Use a-z, 0-9"));
    assert!(
        rt.state.onboarding.vault.focused,
        "focus goes to the problem"
    );

    // Escape goes back and forgets the passphrase.
    rt.key(key(Key::Escape));
    rt.frame(FRAME);
    assert_eq!(rt.state.onboarding.step, Step::Welcome);
    assert!(rt.state.onboarding.passphrase.text.is_empty());
}

/// ⇧⌘Space in a field opens the quick panel; it never types a space, not
/// into a plain field and not, unseen, into a passphrase.
#[test]
fn the_panel_shortcut_types_nothing() {
    let shortcut = KeyEvent {
        key: Key::Text(" ".into()),
        mods: Mods {
            cmd: true,
            shift: true,
            ..Mods::default()
        },
    };
    let mut rt = runtime("create", true);
    settle(&mut rt, 0.1);
    type_text(&mut rt, "hunter22");
    rt.key(shortcut.clone());
    rt.frame(FRAME);
    assert_eq!(rt.state.onboarding.passphrase.text, "hunter22");

    rt.update(|s, _| {
        s.onboarding.passphrase.focused = false;
        s.onboarding.vault.focused = true;
    });
    rt.frame(FRAME);
    let before = rt.state.onboarding.vault.text.clone();
    rt.key(shortcut);
    rt.frame(FRAME);
    assert_eq!(rt.state.onboarding.vault.text, before);
}

#[test]
fn the_moment_throws_the_bolt_lights_the_strike_and_lets_it_cool() {
    // "creating" reports the vault created at 1.2 s.
    let created = 1.2;
    let mut rt = runtime("creating", true);
    let mut t = 0.0;
    let mut bolt = Vec::new();
    let mut glow = Vec::new();
    while t < created + moment::OPEN + 0.5 {
        rt.frame(FRAME);
        t += FRAME;
        if let (Some(b), Some(g)) = (find(&rt, "throw"), find(&rt, "glow")) {
            bolt.push((t, b.rect[0]));
            glow.push((t, g.opacity));
        }
    }
    let x = |at: f64| {
        bolt.iter()
            .find(|(t, _)| *t >= at)
            .map(|(_, x)| *x)
            .unwrap()
    };
    let (back, thrown) = (x(created - 0.1), x(created + 1.0));
    assert!(thrown > back + 20.0, "the bolt throws ({back} -> {thrown})");
    // It travels: a frame in, it's on its way, not there.
    let early = x(created + 2.0 * FRAME);
    assert!(back < early && early < thrown, "travels ({early})");
    // The one flourish: it seats past its rest by under a point, then settles.
    let peak = bolt
        .iter()
        .filter(|(t, _)| *t < created + moment::OPEN)
        .map(|(_, x)| *x)
        .fold(f32::MIN, f32::max);
    assert!(
        peak > thrown + 0.2 && peak - thrown < 1.5,
        "overshoot {}",
        peak - thrown
    );

    // The glow is dark until contact, lights, then cools without a cut.
    let lit = glow.iter().map(|(_, o)| *o).fold(0.0, f32::max);
    assert!(lit > 0.9, "the strike lights ({lit})");
    let before: f32 = glow
        .iter()
        .filter(|(t, _)| *t < created + moment::CONTACT - FRAME)
        .map(|(_, o)| *o)
        .fold(0.0, f32::max);
    assert!(before < 0.01, "no light before contact ({before})");
    let after: Vec<f32> = glow
        .iter()
        .filter(|(t, _)| *t > created + moment::COOL + 2.0 * FRAME)
        .map(|(_, o)| *o)
        .collect();
    for w in after.windows(2) {
        assert!(w[1] <= w[0] + 1e-4, "cooling never brightens");
        assert!(
            w[0] - w[1] < 0.12,
            "cooling never cuts ({} -> {})",
            w[0],
            w[1]
        );
    }

    // Then the vault opens.
    assert_eq!(rt.state.screen, Screen::Vault);
}

#[test]
fn joining_lands_in_the_vault() {
    let mut rt = runtime("joining", false);
    settle(&mut rt, 1.1);
    assert!(matches!(
        &rt.state.onboarding.step,
        Step::Done { flow: Flow::Join, from: Some(from), .. } if from == "studio"
    ));
    assert!(shows(&rt, "Synced from studio"));
    settle(&mut rt, moment::OPEN - 0.4);
    assert_eq!(rt.state.screen, Screen::Vault);
}

/// The agent locking (sleep, screen lock, CLI) mid-create or mid-join
/// leaves the flow where it is: it finishes or fails on its own.
#[test]
fn a_lock_from_the_agent_does_not_interrupt_a_create_or_join() {
    use deadbolt_client::protocol::{Change, Status};
    let locked = Status {
        pid: 1,
        version: "fixture".into(),
        protocol: deadbolt_client::protocol::PROTOCOL_VERSION,
        program: None,
        home: String::new(),
        initialized: true,
        unlocked: false,
        locks_in_secs: None,
        caller: deadbolt_client::protocol::CallerInfo::unverified("fixture"),
        device: None,
        vaults: Vec::new(),
        peers_online: 0,
        peers: 0,
        touch_id_available: false,
        touch_id_enabled: false,
        touch_id_ready: false,
        touch_id_reset: false,
    };
    for scene in ["creating", "ticket", "code", "joining"] {
        let mut rt = runtime(scene, false);
        rt.frame(FRAME);
        let step = rt.state.onboarding.step.clone();
        rt.update(|s, tx| s.apply(Done::Changed(Change::Locked), tx));
        rt.update(|s, tx| s.apply(Done::Status(Some(locked.clone())), tx));
        rt.update(|s, tx| s.apply(Done::Changed(Change::Stopping), tx));
        rt.update(|s, tx| s.apply(Done::WatchLost, tx));
        rt.frame(FRAME);
        assert_eq!(rt.state.screen, Screen::Onboarding, "{scene}");
        assert_eq!(rt.state.onboarding.step, step, "{scene}");
    }
}

#[test]
fn notices_say_how_serious_they_are() {
    for (scene, severity) in [
        ("join-cancelled", Severity::Neutral),
        ("join-declined", Severity::Caution),
        ("join-failed", Severity::Danger),
    ] {
        let rt = runtime(scene, true);
        let notice = rt.state.onboarding.notice.as_ref().unwrap();
        assert_eq!(notice.severity, severity, "{scene}");
    }
}

#[test]
fn nothing_animates_on_first_paint() {
    for scene in ["welcome", "create", "ticket", "code", "creating"] {
        let mut rt = runtime(scene, true);
        rt.frame(0.0);
        for e in rt.elements() {
            assert!(
                !e.moving || e.loop_phase.is_some(),
                "{scene}: {:?} moves on the first frame",
                e.key
            );
        }
    }
}

fn board(clipboard: &MemoryClipboard) -> Option<String> {
    clipboard.text().map(|t| t.as_str().to_owned())
}

/// The ticket scene after "Copy command", with a clipboard the test can read.
fn ticket_copied() -> (Runtime<App>, MemoryClipboard) {
    let mut rt = runtime("ticket", true);
    let clipboard = rune::clipboard::memory();
    rt.use_clipboard(&clipboard);
    rt.frame(FRAME);
    rt.update(|s, tx| s.copy_ticket(tx));
    rt.frame(FRAME);
    assert!(
        board(&clipboard).is_some_and(|t| t.starts_with("deadbolt pair DBPAIR")),
        "the whole command is on the clipboard"
    );
    (rt, clipboard)
}

fn failure(message: &str) -> Failure {
    Failure {
        code: None,
        message: message.into(),
    }
}

#[test]
fn a_copied_ticket_leaves_the_clipboard_with_the_screen() {
    // Closing the window.
    let (mut rt, clip) = ticket_copied();
    rt.update(|s, tx| s.close(tx));
    assert_eq!(board(&clip), None, "close clears it");
    assert!(rt.state.onboarding.ticket.is_none());

    // The agent stopping, which leaves onboarding for the failed screen.
    let (mut rt, clip) = ticket_copied();
    rt.update(|s, tx| s.apply(Done::Status(None), tx));
    assert!(matches!(rt.state.screen, Screen::Failed(_)));
    assert_eq!(board(&clip), None, "leaving clears it");

    // The ticket expiring, which ends the join.
    let (mut rt, clip) = ticket_copied();
    rt.state.onboarding.worker = Worker::scripted(vec![(
        0.0,
        Progress::Joined(Err(failure("the ticket expired"))),
    )]);
    rt.frame(FRAME);
    assert_eq!(rt.state.onboarding.step, Step::Join);
    assert_eq!(board(&clip), None, "the end of the join clears it");

    // Something the person copied since stays, and the button stops saying
    // the ticket is copied.
    let (mut rt, clip) = ticket_copied();
    clip.set_text("mine");
    rt.frame(FRAME);
    assert!(rt.state.onboarding.copied.is_none());
    rt.update(|s, tx| s.close(tx));
    assert_eq!(board(&clip).as_deref(), Some("mine"));
}

#[test]
fn a_ticket_that_fails_to_copy_says_so() {
    let mut rt = runtime("ticket", true);
    let clip = rune::clipboard::memory();
    clip.fail_writes(Some("no pasteboard"));
    rt.use_clipboard(&clip);
    rt.frame(FRAME);
    rt.update(|s, tx| s.copy_ticket(tx));
    settle(&mut rt, 0.4);
    assert!(rt.state.onboarding.copied.is_none());
    assert!(shows(&rt, "Couldn't copy") && shows(&rt, "no pasteboard"));
    assert!(!shows(&rt, "Copied"));
}

#[test]
fn a_late_they_match_after_they_dont_does_nothing() {
    let mut rt = runtime("code", true);
    rt.frame(FRAME);
    rt.update(|s, _| s.answer_code(false));
    rt.update(|s, _| s.answer_code(true));
    assert!(matches!(rt.state.onboarding.step, Step::Confirm { .. }));
}

#[test]
fn cancelling_while_the_device_is_set_up_waits_for_it() {
    let mut rt = runtime("join", true);
    rt.update(|s, _| {
        let o = &mut s.onboarding;
        o.plan = vec![Stage::Protecting, Stage::MakingTicket];
        o.stage = Some(Stage::Protecting);
        o.step = Step::Working(Flow::Join);
    });
    settle(&mut rt, 0.1);
    assert!(shows(&rt, "Cancel"));
    rt.key(key(Key::Escape));
    settle(&mut rt, 0.4);
    assert_eq!(rt.state.onboarding.step, Step::Working(Flow::Join));
    assert!(shows(&rt, "Stopping") && shows(&rt, "finishes setting up"));
    assert!(!shows(&rt, "Cancel"), "nothing more to cancel");

    // The setup finishes, then the join stops; the form knows the device is set up.
    rt.state.onboarding.worker = Worker::scripted(vec![
        (0.0, Progress::DeviceReady { set_up: true }),
        (0.0, Progress::Joined(Err(failure("cancelled")))),
    ]);
    settle(&mut rt, 0.4);
    let o = &rt.state.onboarding;
    assert_eq!(o.step, Step::Join);
    assert!(o.device_ready, "no passphrase asked again");
    let notice = o.notice.as_ref().unwrap();
    assert_eq!(notice.severity, Severity::Neutral);
    assert!(notice.body.contains("set up now"), "{notice:?}");
}

/// At the smallest window a tall step (Create with its hints and a notice)
/// keeps clear of the title bar band and Back, and scrolls to its button.
#[test]
fn a_tall_step_stays_under_the_title_bar_and_scrolls() {
    let mut rt = runtime("create-typing", true);
    rt.update(|s, _| {
        s.onboarding.notice = Some(deadbolt_app::onboarding::Notice {
            severity: Severity::Danger,
            title: "Couldn't create the vault".into(),
            body: "Connecting to the agent: connection refused. Try again.".into(),
        })
    });
    rt.set_viewport((640.0, 420.0), 1.0);
    settle(&mut rt, 0.6);
    let rect = |rt: &Runtime<App>, key: &str| find(rt, key).unwrap().rect;
    let back = rect(&rt, "back");
    let panel = rect(&rt, "panel");
    assert!(
        panel[1] >= 48.0 && panel[1] >= back[1] + back[3],
        "the panel starts under the band: {panel:?}, Back {back:?}"
    );
    let submit = rect(&rt, "submit");
    assert!(
        submit[1] + submit[3] > 420.0,
        "the step is taller than the room: {submit:?}"
    );
    rt.wheel(320.0, 300.0, -600.0);
    settle(&mut rt, 0.4);
    let submit = rect(&rt, "submit");
    assert!(
        submit[1] + submit[3] <= 420.0,
        "scrolled to the button: {submit:?}"
    );
    assert_eq!(rect(&rt, "back"), back, "Back stays in the band");
}
