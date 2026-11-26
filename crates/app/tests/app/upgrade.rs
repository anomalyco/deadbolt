//! DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2.
//!
//! An unlock that moved a v1 store shows every moved vault's new recovery
//! kit on the save step, one after another, then opens the vault. A lock on
//! the way drops them all.

use deadbolt_app::daemon::Done;
use deadbolt_app::model::{App, Screen};
use deadbolt_app::onboarding::Step;
use deadbolt_proto::daemon::{MigratedVault, Secret, Status, VaultInfo};
use rune::{Env, Runtime};

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
        status: Box::new(status),
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
