//! DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2.
//!
//! An unlock that moved a v1 store shows every moved vault's new recovery
//! kit on the save step, one after another, then opens the vault. A lock on
//! the way drops them all.

use deadbolt_app::daemon::{Daemon, Done, Job};
use deadbolt_app::model::{App, Screen};
use deadbolt_app::onboarding::Step;
use deadbolt_proto::daemon::{Change, MigratedVault, Secret, Status, VaultInfo};
use rune::{Env, Key, KeyEvent, Mods, Runtime};

const FRAME: f64 = 1.0 / 60.0;
const PERSONAL: &str = "abandon ability able about above absent absorb abstract absurd abuse \
     access accident across act action actor adapt add address admit adult advance advice aerobic";
const TEAM: &str = "zoo zone zero youth young yellow year wrong write wrist world worth \
     worry work wood wonder woman wolf wise wire winter wink wine window";

fn locked() -> Runtime<App> {
    let app = rune::tooling::initial_state(&deadbolt_app::spec(), Some("locked"));
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
    settle(&mut rt);
    assert_eq!(rt.state.screen, Screen::Locked);
    rt
}

fn settle(rt: &mut Runtime<App>) {
    for _ in 0..24 {
        rt.frame(FRAME);
    }
}

fn shows(rt: &Runtime<App>, s: &str) -> bool {
    rt.elements()
        .iter()
        .any(|e| e.text.as_deref().is_some_and(|t| t.contains(s)) && e.opacity > 0.99)
}

fn click(rt: &mut Runtime<App>, key: &str) {
    let e = rt
        .elements()
        .into_iter()
        .rfind(|e| e.key.as_deref() == Some(key))
        .unwrap_or_else(|| panic!("{key} is on screen"));
    let (x, y) = (e.rect[0] + e.rect[2] / 2.0, e.rect[1] + e.rect[3] / 2.0);
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    settle(rt);
}

fn vault(id: &str, name: &str, default: bool) -> VaultInfo {
    VaultInfo {
        id: id.into(),
        name: name.into(),
        default,
        members: 1,
        member: true,
        error: None,
    }
}

/// The unlock's status and what it moved: two vaults, two kits.
fn upgraded(rt: &Runtime<App>) -> Done {
    let personal = vault("b3f9c21a00", "personal", true);
    let team = vault("7e01d4c900", "team", false);
    let mut status: Status = rt.state.status.clone().expect("a status");
    status.unlocked = true;
    status.vaults = vec![personal.clone(), team.clone()];
    Done::Upgraded {
        status: Some(Box::new(status)),
        migrated: vec![
            MigratedVault {
                vault: personal,
                items: 5,
                recovery_kit: Secret::new(PERSONAL),
            },
            MigratedVault {
                vault: team,
                items: 1,
                recovery_kit: Secret::new(TEAM),
            },
        ],
    }
}

fn showing(rt: &Runtime<App>) -> (String, String) {
    let Step::Recovery(recovery) = &rt.state.onboarding.step else {
        panic!("the save step shows: {:?}", rt.state.onboarding.step);
    };
    (recovery.vault.clone(), recovery.text().to_owned())
}

#[test]
fn an_upgrade_shows_each_moved_vaults_kit_then_opens_the_vault() {
    let mut rt = locked();
    let done = upgraded(&rt);
    rt.update(|s, tx| s.apply(done, tx));
    settle(&mut rt);

    assert_eq!(rt.state.screen, Screen::Onboarding);
    assert_eq!(showing(&rt), ("personal".into(), PERSONAL.into()));
    assert!(shows(&rt, "Upgraded to Deadbolt v2. Vault 1 of 2 moved"));
    assert!(shows(&rt, "Save your recovery kit"));
    assert!(shows(&rt, "abandon"));

    // A status from elsewhere doesn't skip the words.
    let status = rt.state.status.clone();
    rt.update(|s, tx| s.apply(Done::Status(status), tx));
    assert_eq!(showing(&rt).0, "personal");

    click(&mut rt, "save-recovery");
    assert_eq!(rt.state.screen, Screen::Onboarding);
    assert_eq!(showing(&rt), ("team".into(), TEAM.into()));
    assert!(shows(&rt, "Vault 2 of 2 moved"));
    assert!(shows(&rt, "zoo"));
    assert!(!shows(&rt, "abandon"));

    click(&mut rt, "save-recovery");
    assert_eq!(rt.state.screen, Screen::Vault);
    assert_eq!(rt.state.onboarding.step, Step::Welcome);
    assert!(!shows(&rt, "Save your recovery kit"));
    assert!(!shows(&rt, "zoo"));
}

#[test]
fn an_upgrade_without_status_keeps_every_recovery_kit_until_confirmed() {
    let mut rt = locked();
    let Done::Upgraded { migrated, .. } = upgraded(&rt) else {
        unreachable!();
    };
    rt.update(|s, tx| {
        s.apply(
            Done::Upgraded {
                status: None,
                migrated,
            },
            tx,
        )
    });
    settle(&mut rt);

    assert_eq!(rt.state.screen, Screen::Onboarding);
    assert!(!rt.state.status.as_ref().unwrap().unlocked);
    for (vault, words) in [("personal", PERSONAL), ("team", TEAM)] {
        assert_eq!(showing(&rt), (vault.into(), words.into()));
        assert!(shows(&rt, "Save your recovery kit"));
        assert_eq!(words.split_whitespace().count(), 24);
        for word in words.split_whitespace() {
            assert!(shows(&rt, word), "missing recovery word {word}");
        }
        click(&mut rt, "save-recovery");
    }
    assert_eq!(rt.state.screen, Screen::Vault);
    assert_eq!(rt.state.onboarding.step, Step::Welcome);
    assert!(!shows(&rt, "Save your recovery kit"));
}

#[test]
fn a_lock_during_an_upgrade_drops_every_kit() {
    let mut rt = locked();
    let done = upgraded(&rt);
    rt.update(|s, tx| s.apply(done, tx));
    settle(&mut rt);
    assert_eq!(showing(&rt).0, "personal");

    let mut status = rt.state.status.clone().expect("a status");
    status.unlocked = false;
    rt.update(|s, tx| s.apply(Done::Status(Some(status)), tx));
    settle(&mut rt);
    assert_eq!(rt.state.screen, Screen::Locked);
    assert_eq!(rt.state.onboarding.step, Step::Welcome);
    assert!(!shows(&rt, "abandon"));
}
#[test]
fn the_daemon_stopping_during_an_upgrade_drops_every_kit() {
    let mut rt = locked();
    let done = upgraded(&rt);
    rt.update(|s, tx| s.apply(done, tx));
    settle(&mut rt);
    assert_eq!(showing(&rt).0, "personal");

    rt.update(|s, tx| s.apply(Done::Changed(Change::Stopping), tx));
    settle(&mut rt);
    assert_eq!(rt.state.screen, Screen::Locked);
    assert_eq!(rt.state.onboarding.step, Step::Welcome);
    assert!(!shows(&rt, "abandon"));
}

/// The quick panel can't show an upgrade's kits: it sends people to the
/// window, and never unlocks a v1 store itself.
#[test]
fn the_panel_sends_a_v1_upgrade_to_the_window() {
    let app = rune::tooling::initial_state(&deadbolt_app::panel::spec(), Some("locked"));
    let mut rt = Runtime::new(
        app,
        deadbolt_app::panel::view::panel,
        deadbolt_app::panel::SIZE,
        Env {
            system_dark: true,
            scale: 1.0,
        },
    );
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.on_key = Some(|s, ev, tx| s.panel_key(ev, tx));
    let (daemon, jobs, _replies) = Daemon::scripted();
    rt.state.daemon = daemon;
    rt.state.status.as_mut().expect("a status").v1_store = true;
    settle(&mut rt);
    assert_eq!(rt.state.screen, Screen::Locked);
    assert!(shows(&rt, "Open Deadbolt to upgrade to v2"));
    assert!(!shows(&rt, "Enter your passphrase"));

    // Neither Return nor a passphrase somehow typed sends an unlock.
    rt.state.passphrase.paste("hunter22");
    rt.update(|s, _| s.submit_unlock());
    rt.key(KeyEvent {
        key: Key::Enter,
        mods: Mods::default(),
    });
    settle(&mut rt);
    let sent: Vec<Job> = jobs.try_iter().collect();
    assert!(
        !sent.iter().any(|job| matches!(job, Job::Unlock(_))),
        "no unlock from the panel"
    );
    assert!(!rt.state.unlocking);
}
