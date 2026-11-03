//! Headless tests for password health: zero layout shift in `vault-head` when
//! `Done::Health` arrives, risk dots vs upgrade quietness, keyboard navigation
//! inside `Security` (`⇧⌘H`, `1`–`7`, `↑↓`, `O`, `I`, `⏎`), the Fix flow with
//! `url`-aware generation and `Copy current password` (`⇧⌘C`), and forgetting
//! on lock.

use deadbolt_app::daemon::{Done, Job};
use deadbolt_app::health::Tab;
use deadbolt_app::model::App;
use deadbolt_client::protocol::{FindingKind, HealthReport};
use rune::{Key, Mods, Runtime};
use zeroize::Zeroizing;

use crate::edit::rig;

fn rect_of(rt: &Runtime<App>, key: &str) -> [f32; 4] {
    rt.elements()
        .into_iter()
        .rfind(|e| e.key.as_deref() == Some(key))
        .unwrap_or_else(|| panic!("missing element {key}"))
        .rect
}

#[test]
fn vault_head_keeps_exact_height_when_health_arrives_and_clears_on_lock() {
    let mut r = rig("vault");
    let before = rect_of(&r.rt, "vault-head");
    let list_before = rect_of(&r.rt, "list");

    // Extract the fixture report from `vault-risk` and apply it via `Done::Health`.
    let sample = rune::tooling::initial_state(&deadbolt_app::spec(), Some("vault-risk"));
    let report: HealthReport = sample.health.report.expect("fixture report");
    r.rt.update(|s, _| s.request_health(false));
    let seq = r
        .sent()
        .into_iter()
        .find_map(|j| match j {
            Job::Health { seq, online: false } => Some(seq),
            _ => None,
        })
        .expect("health job sent");
    r.reply(Done::Health {
        seq,
        result: Ok(report),
    });

    assert!(r.shows("4 risks"));
    assert!(r.shows("Exposed in 14,203 data breaches"));
    assert!(r.shows("Login · Changed Mar 14, 2024"));

    let after = rect_of(&r.rt, "vault-head");
    let list_after = rect_of(&r.rt, "list");
    assert_eq!(
        before[3], after[3],
        "vault-head height must not shift ({before:?} vs {after:?})"
    );
    assert_eq!(
        list_before[1], list_after[1],
        "item list y-origin must not shift"
    );

    // Upgrade-only item (`gitlab.com`, PasskeyAvailable) gets no risk dot in the sidebar,
    // while risk items (`github.com`, `Linear`, `Cloudflare`, `Hetzner`) do.
    let gitlab =
        r.rt.state
            .items
            .iter()
            .find(|i| i.label == "gitlab.com")
            .unwrap();
    assert_eq!(r.rt.state.health.risk_for(&gitlab.id), None);

    // Locking wipes the health report completely.
    r.command('l');
    assert!(r.sent().into_iter().any(|j| matches!(j, Job::Lock)));
    r.reply(Done::Locked(Ok(())));
    assert!(r.rt.state.health.report.is_none());
    assert!(!r.rt.state.security_open());
}

#[test]
fn security_view_navigates_tabs_opens_change_urls_ignores_and_runs_fix_flow() {
    let mut r = rig("vault-risk");
    let board = rune::clipboard::memory();
    r.rt.use_clipboard(&board);
    let clip = || board.text().map(|t| t.as_str().to_owned());

    // ⇧⌘H opens the Security view.
    r.press(
        Key::Command('h'),
        Mods {
            cmd: true,
            shift: true,
            ..Mods::default()
        },
    );
    assert!(r.rt.state.security_open());
    assert_eq!(r.rt.state.health.tab, Tab::Risks);

    // Category tabs `1`–`6` switch cleanly via keyboard.
    r.tap(Key::Text("3".into()));
    assert_eq!(r.rt.state.health.tab, Tab::Reused);
    assert_eq!(r.rt.state.health.rows().len(), 2);

    r.tap(Key::Text("6".into()));
    assert_eq!(r.rt.state.health.tab, Tab::Passkeys);
    assert_eq!(r.rt.state.health.rows().len(), 1);

    r.tap(Key::Text("1".into()));
    assert_eq!(r.rt.state.health.tab, Tab::Risks);
    assert_eq!(r.rt.state.health.row, 0);

    // `O` on `github.com` opens its direct `change-urls.json` page rather than bare homepage.
    r.tap(Key::Text("o".into()));
    assert_eq!(
        r.rt.take_url_requests(),
        vec!["https://github.com/settings/security".to_owned()]
    );

    // `I` sends `Job::HealthIgnore` for the active row's finding.
    r.tap(Key::Text("i".into()));
    assert!(r.sent().into_iter().any(|j| matches!(
        j,
        Job::HealthIgnore {
            kind: FindingKind::Breached,
            ignored: true,
            ..
        }
    )));

    // `⏎` starts the Fix flow on `github.com`: closes Security, opens the edit form,
    // passes `url: Some("https://github.com")` to `Job::Generate`, copies the new candidate
    // when it lands, and preserves `⇧⌘C` (`Copy current password`) from `base`.
    r.tap(Key::Enter);
    assert!(!r.rt.state.security_open());
    assert!(r.rt.state.editing());

    let gen_seq = r
        .sent()
        .into_iter()
        .find_map(|j| match j {
            Job::Generate {
                url: Some(url),
                seq,
                ..
            } => {
                assert_eq!(url, "https://github.com");
                Some(seq)
            }
            _ => None,
        })
        .expect("expected Generate with url");

    r.reply(Done::Generated {
        seq: gen_seq,
        result: Ok(Zeroizing::new("NewStrongCandidate#2026!".into())),
    });

    // Candidate is revealed in the input and copied to the concealed clipboard.
    assert_eq!(r.value("password"), "NewStrongCandidate#2026!");
    assert!(r.input("password").edit.is_revealed());
    assert_eq!(clip().as_deref(), Some("NewStrongCandidate#2026!"));

    // Website asks for Current Password first: `⇧⌘C` copies the old password from `base`
    // while keeping `NewStrongCandidate#2026!` in the form field!
    r.press(
        Key::Command('c'),
        Mods {
            cmd: true,
            shift: true,
            ..Mods::default()
        },
    );
    assert_eq!(clip().as_deref(), Some("correct-horse-battery-staple"));
    assert_eq!(r.value("password"), "NewStrongCandidate#2026!");
}
