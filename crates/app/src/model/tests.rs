use deadbolt_client::protocol::Change;
use rune::{Env, Runtime};

use super::unlock::unlock_message;
use super::{App, Failure, Screen, take_secret};
use crate::agent::{Done, Values};

#[test]
fn a_backed_off_unlock_says_when_to_try_again() {
    use deadbolt_client::protocol::ErrorCode;
    let backed_off = Failure {
        code: Some(ErrorCode::RateLimited),
        message: "Too many wrong passphrases. Try again in 30 s.".into(),
    };
    assert_eq!(
        unlock_message(&backed_off),
        "Too many wrong passphrases. Try again in 30 s."
    );
    let wrong = Failure {
        code: Some(ErrorCode::Failed),
        message: "wrong passphrase".into(),
    };
    assert_eq!(
        unlock_message(&wrong),
        "That passphrase didn't unlock this device."
    );
}

#[test]
fn take_secret_empties_the_field() {
    let mut f = rune::TextEdit::new("").secure();
    f.paste("hunter22");
    f.focused = true;
    assert_eq!(take_secret(&mut f).as_str(), "hunter22");
    assert_eq!((f.text.as_str(), f.focus, f.anchor), ("", 0, 0));
    assert!(f.focused && f.is_secure());
}

fn vault() -> Runtime<App> {
    main("vault")
}

fn main(scene: &str) -> Runtime<App> {
    let app = rune::tooling::initial_state(&crate::spec(), Some(scene));
    Runtime::new(
        app,
        crate::view::app,
        (820.0, 540.0),
        Env {
            system_dark: true,
            scale: 1.0,
        },
    )
}

fn panel(scene: &str) -> Runtime<App> {
    let app = rune::tooling::initial_state(&crate::panel::spec(), Some(scene));
    let mut rt = Runtime::new(
        app,
        crate::panel::view::panel,
        crate::panel::SIZE,
        Env {
            system_dark: true,
            scale: 1.0,
        },
    );
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.frame(0.0);
    rt
}

fn forgotten(app: &App) -> bool {
    app.items.is_empty() && app.detail.is_none() && app.selected.is_none() && !app.loaded
}

/// A list or an item fetched before a lock, a stop or a lost watch can land
/// after it. It must not bring the values back, not even once the vault is
/// open again.
#[test]
fn replies_from_before_a_lock_are_dropped() {
    let ends: [fn() -> Done; 3] = [
        || Done::Changed(Change::Locked),
        || Done::Changed(Change::Stopping),
        || Done::WatchLost,
    ];
    for end in ends {
        let mut rt = vault();
        let unlocked = rt.state.status.clone();
        let (generation, seq) = (rt.state.generation, rt.state.seq);
        let item = rt.state.detail.clone().expect("the scene shows an item");
        let items = rt.state.items.clone();
        let late = |rt: &mut Runtime<App>| {
            let (item, items) = (item.clone(), items.clone());
            rt.update(|s, tx| {
                s.apply(
                    Done::Item {
                        seq,
                        result: Ok(Values::new(item)),
                    },
                    tx,
                );
                s.apply(
                    Done::Items {
                        generation,
                        result: Ok(items),
                    },
                    tx,
                );
            });
        };

        rt.update(|s, tx| s.apply(end(), tx));
        assert_eq!(rt.state.screen, Screen::Locked);
        late(&mut rt);
        assert!(forgotten(&rt.state), "repopulated while locked");

        // Unlocked again (the new list is in flight): the old replies still don't count.
        rt.update(|s, tx| s.apply(Done::Status(unlocked.clone()), tx));
        assert_eq!(rt.state.screen, Screen::Vault);
        late(&mut rt);
        assert!(forgotten(&rt.state), "repopulated after unlocking");
    }
}

/// The panel forgets everything as it hides; a lock and the replies to
/// what it asked before, landing while it's hidden, bring nothing back.
#[test]
fn a_hidden_panel_keeps_nothing() {
    let mut rt = panel("filtering");
    let item = rt.state.detail.clone().expect("the scene shows an item");
    let items = rt.state.items.clone();
    let (generation, seq) = (rt.state.generation, rt.state.seq);
    rt.update(|s, tx| s.dismiss(tx));
    for _ in 0..30 {
        rt.frame(1.0 / 60.0);
    }
    assert_eq!(rt.state.panel_phase(), Some(crate::panel::Phase::Hidden));
    assert!(forgotten(&rt.state));
    assert_eq!(rt.state.search.text, "", "the query too");

    rt.update(|s, tx| {
        s.apply(Done::Changed(Change::Locked), tx);
        s.apply(
            Done::Item {
                seq,
                result: Ok(Values::new(item)),
            },
            tx,
        );
        s.apply(
            Done::Items {
                generation,
                result: Ok(items),
            },
            tx,
        );
    });
    assert_eq!(rt.state.screen, Screen::Locked);
    assert!(forgotten(&rt.state));
}

/// A part-typed passphrase goes as soon as either window leaves Locked
/// without it: unlocked elsewhere (the other window, the CLI), the agent
/// gone, or the device reset to onboarding.
#[test]
fn leaving_locked_wipes_a_part_typed_passphrase() {
    let windows: [fn() -> Runtime<App>; 2] = [|| main("locked"), || panel("locked")];
    let exits: [fn(&App) -> Done; 3] = [
        |s| {
            let mut status = s.status.clone().expect("the scene has a status");
            status.unlocked = true;
            Done::Status(Some(status))
        },
        |_| Done::Status(None),
        |s| {
            let mut status = s.status.clone().expect("the scene has a status");
            status.initialized = false;
            Done::Status(Some(status))
        },
    ];
    for window in windows {
        for exit in exits {
            let mut rt = window();
            assert_eq!(rt.state.screen, Screen::Locked);
            rt.update(|s, _| {
                s.passphrase.paste("hunt");
                s.passphrase_changed();
            });
            rt.update(|s, tx| {
                let done = exit(s);
                s.apply(done, tx);
            });
            assert_ne!(rt.state.screen, Screen::Locked);
            assert_eq!(rt.state.passphrase.text, "", "left {:?}", rt.state.screen);
        }
    }
}

#[test]
fn touch_id_auto_prompts_on_launch_and_focus_never_on_background_lock() {
    use crate::agent::{Agent, Failure, Job};

    let mut rt = vault();
    let (agent, jobs, _replies) = Agent::scripted();
    rt.state.agent = agent;
    if let Some(st) = &mut rt.state.status {
        st.touch_id_available = true;
        st.touch_id_enabled = true;
    }
    let mut locked_status = rt.state.status.clone().unwrap();
    locked_status.unlocked = false;
    locked_status.touch_id_ready = true;

    // Window loses focus (user switches to another app), then agent locks in background.
    rt.update(|s, tx| s.main_focus(false, tx));
    rt.update(|s, tx| {
        s.apply(Done::Changed(Change::Locked), tx);
        s.apply(Done::Status(Some(locked_status.clone())), tx);
    });
    assert_eq!(rt.state.screen, Screen::Locked);
    assert!(
        !jobs.try_iter().any(|j| matches!(j, Job::UnlockBiometric)),
        "background lock must not prompt Touch ID"
    );

    // User brings the window forward: Touch ID auto-prompts once.
    rt.update(|s, tx| s.main_focus(true, tx));
    assert!(
        jobs.try_iter().any(|j| matches!(j, Job::UnlockBiometric)),
        "focusing the locked window prompts Touch ID"
    );
    assert!(rt.state.touch_id_unlocking);

    // The macOS Touch ID sheet takes and returns focus when cancelled;
    // it must not re-prompt in a loop.
    rt.update(|s, tx| s.main_focus(false, tx));
    rt.update(|s, tx| {
        s.apply(
            Done::UnlockedBiometric(Err((
                Failure {
                    code: None,
                    message: "Touch ID was cancelled: user cancel".into(),
                },
                Some(Box::new(locked_status.clone())),
            ))),
            tx,
        );
        s.main_focus(true, tx);
    });
    assert!(
        !jobs.try_iter().any(|j| matches!(j, Job::UnlockBiometric)),
        "cancelling Touch ID must not loop on focus return"
    );
    assert_eq!(rt.state.unlock_error, None);
    assert!(rt.state.passphrase.focused);

    // If the biometric slot was reset, the lock screen says so and hides Use Touch ID.
    let mut reset_status = locked_status.clone();
    reset_status.touch_id_ready = false;
    reset_status.touch_id_reset = true;
    rt.update(|s, tx| {
        s.unlock_touch_id();
        s.apply(
            Done::UnlockedBiometric(Err((
                Failure {
                    code: None,
                    message: "Touch ID was reset (expired after 14 days); enter your passphrase"
                        .into(),
                },
                Some(Box::new(reset_status)),
            ))),
            tx,
        );
    });
    rt.frame(1.0 / 60.0);
    assert!(rt.state.touch_id_reset());
    assert!(!rt.state.touch_id_ready());
    assert!(
        rt.elements().iter().any(|e| {
            e.text
                .as_deref()
                .is_some_and(|t| t.contains("Touch ID was reset; enter your passphrase"))
        }),
        "shows reset notice"
    );
    assert!(rt.find("touch-id").is_none());

    // When Touch ID is enabled in config.toml before a biometric slot has ever
    // been enrolled (`touch_id_reset == false`, `touch_id_ready == false`),
    // the lock screen asks for the passphrase once rather than claiming a reset.
    let mut never_enrolled_status = locked_status.clone();
    never_enrolled_status.touch_id_ready = false;
    never_enrolled_status.touch_id_reset = false;
    rt.update(|s, tx| {
        s.apply(Done::Status(Some(never_enrolled_status)), tx);
    });
    rt.frame(1.0 / 60.0);
    assert!(!rt.state.touch_id_reset());
    assert!(!rt.state.touch_id_ready());
    assert!(
        rt.elements().iter().any(|e| {
            e.text.as_deref().is_some_and(|t| {
                t.contains("Enter your passphrase once to finish turning on Touch ID")
            })
        }),
        "shows first-time finish setup notice instead of reset notice"
    );

    // Hidden main window (`window_focused == false` on `--panel` launch) does not
    // auto-prompt on `Connected` until the window is actually focused.
    let mut hidden = App::new(Agent::offline());
    let (hidden_agent, hidden_jobs, _hidden_replies) = Agent::scripted();
    hidden.agent = hidden_agent;
    assert!(!hidden.window_focused);
    hidden.apply(
        Done::Connected(Ok(locked_status.clone())),
        &mut rune::Tx::default(),
    );
    assert_eq!(hidden.screen, Screen::Locked);
    assert!(
        !hidden_jobs
            .try_iter()
            .any(|j| matches!(j, Job::UnlockBiometric)),
        "unfocused main window must not auto-prompt on Connected"
    );
    hidden.main_focus(true, &mut rune::Tx::default());
    assert!(
        hidden_jobs
            .try_iter()
            .any(|j| matches!(j, Job::UnlockBiometric)),
        "focusing main window after Connected prompts Touch ID"
    );
}

#[test]
fn quick_panel_touch_id_unlocks_and_dismisses_if_unfocused_on_cancel() {
    use crate::agent::{Agent, Failure, Job};
    use crate::panel::Phase;

    let mut rt = panel("locked-touch-id");
    let (agent, jobs, _replies) = Agent::scripted();
    rt.state.agent = agent;
    let locked_status = rt.state.status.clone().unwrap();
    let mut unlocked_status = locked_status.clone();
    unlocked_status.unlocked = true;
    unlocked_status.touch_id_ready = false;

    // Summoning the locked panel marks it focused and auto-prompts Touch ID.
    rt.update(|s, tx| s.summon(tx));
    assert!(rt.state.window_focused);
    assert!(
        jobs.try_iter().any(|j| matches!(j, Job::UnlockBiometric)),
        "summon prompts Touch ID"
    );
    assert!(rt.state.touch_id_unlocking);

    // Focus loss while the Touch ID sheet is up does not immediately dismiss the panel.
    rt.update(|s, tx| s.panel_focus(false, tx));
    assert_eq!(rt.state.panel_phase(), Some(Phase::Open));

    // If the Touch ID prompt fails/cancels while the panel is still unfocused
    // (user clicked away to another app), the panel dismisses itself.
    rt.update(|s, tx| {
        s.apply(
            Done::UnlockedBiometric(Err((
                Failure {
                    code: None,
                    message: "Touch ID prompt was cancelled".into(),
                },
                Some(Box::new(locked_status)),
            ))),
            tx,
        );
    });
    assert!(matches!(
        rt.state.panel_phase(),
        Some(Phase::Closing { .. })
    ));

    // Summon again and complete Touch ID: the panel enters the vault and
    // re-arms focus so a subsequent blur dismisses it.
    rt.update(|s, tx| s.summon(tx));
    rt.update(|s, tx| s.panel_focus(false, tx));
    rt.update(|s, tx| {
        s.apply(Done::UnlockedBiometric(Ok(unlocked_status)), tx);
    });
    assert_eq!(rt.state.screen, Screen::Vault);
    assert_eq!(rt.state.panel_phase(), Some(Phase::Open));
    assert!(rt.state.search.focused);
    assert!(rt.state.window_focused);

    rt.update(|s, tx| s.panel_focus(false, tx));
    assert!(matches!(
        rt.state.panel_phase(),
        Some(Phase::Closing { .. })
    ));
}

#[test]
fn settings_touch_id_toggle_sends_command_and_reverts_on_failure() {
    use crate::agent::{Agent, Failure, Job};

    let mut rt = main("settings-touch-id");
    let (agent, jobs, _replies) = Agent::scripted();
    rt.state.agent = agent;
    assert!(rt.state.touch_id_enabled());
    let initial_status = rt.state.status.clone().unwrap();

    rt.update(|s, _| s.toggle_touch_id());
    assert!(!rt.state.touch_id_enabled());
    assert!(rt.state.touch_id_busy);
    assert!(jobs.try_iter().any(|j| matches!(j, Job::TouchIdSet(false))));

    // While `touch_id_busy` is true, an incoming Status reply (e.g. from watch)
    // must not flip the switch back to its pre-toggle value.
    rt.update(|s, tx| {
        s.apply(Done::Status(Some(initial_status.clone())), tx);
    });
    assert!(
        !rt.state.touch_id_enabled(),
        "pending toggle value preserved across intermediate Status replies"
    );

    // On TouchIdSet failure, the fresh Status from the agent restores the switch.
    rt.update(|s, tx| {
        s.apply(
            Done::TouchIdSet {
                enabled: false,
                result: Err((
                    Failure {
                        code: None,
                        message: "Touch ID failed".into(),
                    },
                    Some(Box::new(initial_status)),
                )),
            },
            tx,
        );
    });
    assert!(
        !rt.state.touch_id_enabled(),
        "restored from fresh Status on failure"
    );
    assert_eq!(rt.state.touch_id_error.as_deref(), Some("Touch ID failed"));
}
