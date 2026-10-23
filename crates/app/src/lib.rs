//! Deadbolt's desktop app: a thin Rune client of the running agent, over
//! the same socket protocol as the CLI. See docs/app.md.

pub mod agent;
pub mod binary;
pub mod clipboard;
pub mod install;
pub mod model;
pub mod onboarding;
pub mod secret;
pub mod theme;
pub mod view;

use deadbolt_client::Paths;
use deadbolt_client::protocol::{DeviceInfo, FieldInfo, ItemInfo, Status, VaultInfo};
use rune::{AppSpec, KeyEvent, Tx, Waker};

use agent::{Agent, Job};
use clipboard::Clipboard;
use model::{App, Screen};
use onboarding::worker::{Progress, Stage, Worker};
use onboarding::{Flow, Notice, Pairing, Severity, Step};

pub fn spec() -> AppSpec<App> {
    AppSpec {
        title: "Deadbolt",
        size: (820.0, 540.0),
        min_size: Some((640.0, 420.0)),
        init: || App::new(Agent::offline(), Clipboard::memory().0),
        view: view::app,
        scenes: SCENES,
        fonts: theme::FONTS,
        families: theme::FAMILIES,
        setup: Some(setup),
        poll: Some(|s, now, tx| s.poll(now, tx)),
        on_key: Some(|s: &mut App, ev: &KeyEvent, tx: &mut Tx| s.on_key(ev, tx)),
    }
}

/// Runs the app against this user's agent and clipboard, unless `argv` asks
/// for Rune's tooling (`--snap`, `--tree`, `--script`, `--scene`, …): those
/// runs get no agent and an in-memory clipboard, so a snapshot or tree dump
/// can never hold real vault data.
pub fn run() {
    let live = is_live(&rune::tooling::Args::parse());
    rune::App::new(spec())
        .init(move || {
            let mut app = if live {
                let mut app = App::new(
                    Agent::spawn(Paths::get(), agent::launch()),
                    Clipboard::system(),
                );
                app.onboarding.worker = Worker::new(Paths::get(), agent::launch());
                if let Some(source) = std::env::current_exe()
                    .ok()
                    .as_deref()
                    .and_then(binary::bundled)
                    && let Some(home) = std::env::var_os("HOME")
                {
                    app.installer = Some(install::Installer::live(
                        source,
                        home.into(),
                        Paths::get().config.with_file_name("app-command-offered"),
                    ));
                }
                app
            } else {
                App::new(Agent::offline(), Clipboard::memory().0)
            };
            app.reduced_motion = rune::extra_args().iter().any(|a| a == "--reduced-motion");
            app
        })
        .on_close(|s, tx| s.close(tx))
        .run();
}

/// True for a plain windowed run: no headless output, no scene, no script.
pub fn is_live(args: &rune::tooling::Args) -> bool {
    !args.headless() && args.scene.is_none() && args.script.is_none()
}

fn setup(s: &mut App, waker: Waker) {
    s.onboarding.worker.set_waker(waker.clone());
    if let Some(installer) = &s.installer {
        installer.set_waker(waker.clone());
    }
    s.agent.set_waker(waker);
    s.agent.send(Job::Connect);
}

// -------------------------------------------------------------------------------------------
// Scenes: synthetic data for snapshots and review.

type Scene = (&'static str, fn(&mut App));

const SCENES: &[Scene] = &[
    ("command-offer", |s| {
        vault(s);
        s.installer = Some(install::Installer::fixture());
    }),
    ("install-command", |s| {
        vault(s);
        let mut i = install::Installer::fixture();
        i.show();
        s.installer = Some(i);
    }),
    ("command-installed", |s| {
        vault(s);
        let mut i = install::Installer::fixture();
        i.show();
        i.apply();
        s.installer = Some(i);
    }),
    ("connecting", |_| {}),
    ("welcome", welcome),
    ("welcome-set-up", |s| {
        welcome(s);
        s.onboarding.device_ready = true;
    }),
    ("create", |s| form(s, Flow::Create)),
    ("create-typing", |s| {
        form(s, Flow::Create);
        type_secret(&mut s.onboarding.passphrase, "correct horse");
        type_secret(&mut s.onboarding.repeat, "correct hose");
        s.onboarding.passphrase.mask.focused = false;
        s.onboarding.repeat.mask.focused = true;
    }),
    ("create-ready", |s| {
        form(s, Flow::Create);
        type_secret(&mut s.onboarding.passphrase, "correct horse battery staple");
        type_secret(&mut s.onboarding.repeat, "correct horse battery staple");
        s.onboarding.passphrase.mask.focused = false;
        s.onboarding.repeat.mask.focused = true;
    }),
    ("create-invalid", |s| {
        form(s, Flow::Create);
        s.onboarding.vault = rune::TextEdit::new("My Vault");
        type_secret(&mut s.onboarding.passphrase, "hunter2");
        s.submit_create();
    }),
    ("create-failed", |s| {
        form(s, Flow::Create);
        s.onboarding.notice = Some(Notice {
            severity: Severity::Danger,
            title: "Couldn't create the vault".into(),
            body: "Connecting to the agent: connection refused. Try again.".into(),
        });
    }),
    // Creating, then created at 1.2 s: the moment, then the empty vault at 2.7 s.
    ("creating", |s| {
        working(
            s,
            Flow::Create,
            vec![Stage::Protecting, Stage::CreatingVault],
        );
        s.onboarding.worker = Worker::scripted(vec![
            (0.8, Progress::Stage(Stage::CreatingVault)),
            (1.2, Progress::Created(Ok(vault_info("personal")))),
        ]);
    }),
    ("join", |s| form(s, Flow::Join)),
    ("ticket", |s| {
        welcome(s);
        s.onboarding.device_ready = true;
        s.onboarding.step = Step::Ticket;
        let text = zeroize::Zeroizing::new(fixture_ticket());
        s.onboarding.ticket = Some(onboarding::Ticket {
            qr: onboarding::qr::Matrix::new(&text),
            text,
        });
    }),
    ("code", |s| {
        welcome(s);
        s.onboarding.device_ready = true;
        s.onboarding.pairing = Some(pairing());
        s.onboarding.step = Step::Confirm {
            code: "482913".into(),
            vault: "personal".into(),
            inviter: "studio".into(),
        };
    }),
    // Codes confirmed, then joined at 0.6 s.
    ("joining", |s| {
        working(s, Flow::Join, vec![Stage::Joining]);
        s.onboarding.device_ready = true;
        s.onboarding.pairing = Some(pairing());
        s.onboarding.worker =
            Worker::scripted(vec![(0.6, Progress::Joined(Ok(vault_info("personal"))))]);
    }),
    ("join-declined", |s| {
        join_notice(
            s,
            Severity::Caution,
            "Stopped: the codes didn't match",
            "Nothing was shared and the ticket no longer works. Make a new one and compare again. If you didn't start pairing on your other device, someone else may have seen the ticket.",
        );
    }),
    ("join-cancelled", |s| {
        join_notice(
            s,
            Severity::Neutral,
            "Join cancelled",
            "Nothing was shared. Make a new ticket when you're ready.",
        );
    }),
    ("join-failed", |s| {
        join_notice(
            s,
            Severity::Danger,
            "Couldn't join",
            "The agent stopped. Try again.",
        );
    }),
    ("failed", |s| {
        s.screen =
            Screen::Failed("connecting to the agent: Connection refused (os error 61)".into());
    }),
    ("locked", locked),
    ("locked-error", |s| {
        locked(s);
        s.unlock_error = Some("That passphrase didn't unlock this device.".into());
    }),
    ("vault", vault),
    ("search", |s| {
        vault(s);
        s.search = rune::TextEdit::new("git");
        s.search.focused = true;
        s.keep_selection_visible();
        detail_for_selection(s);
    }),
    ("copied", |s| {
        vault(s);
        s.copy_field("password", &mut Tx::default());
    }),
    ("revealed", |s| {
        vault(s);
        s.toggle_reveal("password");
    }),
    ("empty", |s| {
        vault(s);
        s.items.clear();
        s.selected = None;
        s.detail = None;
    }),
];

fn welcome(s: &mut App) {
    s.screen = Screen::Onboarding;
    s.onboarding.device = rune::TextEdit::new("Dax's MacBook Pro");
}

fn form(s: &mut App, flow: Flow) {
    welcome(s);
    s.choose(flow);
}

fn working(s: &mut App, flow: Flow, plan: Vec<Stage>) {
    welcome(s);
    s.status = Some(status(true));
    s.onboarding.stage = plan.first().copied();
    s.onboarding.plan = plan;
    s.onboarding.step = Step::Working(flow);
}

fn join_notice(s: &mut App, severity: Severity, title: &str, body: &str) {
    welcome(s);
    s.onboarding.device_ready = true;
    s.choose(Flow::Join);
    s.onboarding.notice = Some(Notice {
        severity,
        title: title.into(),
        body: body.into(),
    });
}

fn type_secret(field: &mut secret::SecretEdit, text: &str) {
    for c in text.chars() {
        field.key(&rune::KeyEvent {
            key: rune::Key::Text(c.to_string()),
            mods: rune::Mods::default(),
        });
    }
}

fn pairing() -> Pairing {
    Pairing {
        vault: "personal".into(),
        inviter: "studio".into(),
    }
}

fn vault_info(name: &str) -> VaultInfo {
    VaultInfo {
        id: "v1".into(),
        name: name.into(),
        default: true,
        members: 1,
        member: true,
    }
}

/// A ticket-shaped string: `DBPAIR` and 274 base32 characters, the length of
/// a real ticket with a relay and a few direct addresses.
fn fixture_ticket() -> String {
    const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut x: u32 = 0x2545_f491;
    let body: String = (0..274)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            BASE32[(x % 32) as usize] as char
        })
        .collect();
    format!("DBPAIR{body}")
}

fn status(unlocked: bool) -> Status {
    Status {
        pid: 1,
        version: "fixture".into(),
        protocol: deadbolt_client::protocol::PROTOCOL_VERSION,
        program: None,
        home: String::new(),
        initialized: true,
        unlocked,
        locks_in_secs: None,
        device: Some(DeviceInfo {
            id: "d1".into(),
            name: Some("studio".into()),
            this: true,
            connected: true,
            last_seen: None,
        }),
        vaults: vec![VaultInfo {
            id: "v1".into(),
            name: "personal".into(),
            default: true,
            members: 2,
            member: true,
        }],
        peers_online: 1,
        peers: 1,
    }
}

fn locked(s: &mut App) {
    s.status = Some(status(false));
    s.screen = Screen::Locked;
    s.passphrase.mask.focused = true;
}

const FIXTURE: &[(&str, &str, &str, Option<&str>)] = &[
    ("3f9a1c", "login", "github.com", Some("dax")),
    ("7b20e4", "login", "Linear", Some("dax@anoma.ly")),
    ("a81d55", "card", "Visa •••• 4242", Some("08/29")),
    ("c4e7f0", "login", "fly.io", Some("ops@anoma.ly")),
    ("e01b9d", "login", "gitlab.com", Some("dax")),
    ("f5c312", "login", "Cloudflare", Some("dax@anoma.ly")),
    ("09ad7e", "login", "Hetzner", Some("billing@anoma.ly")),
];

fn vault(s: &mut App) {
    s.status = Some(status(true));
    s.screen = Screen::Vault;
    s.items = FIXTURE
        .iter()
        .map(|(id, kind, label, detail)| ItemInfo {
            id: format!("{id}0000000000000000000000000000000000000000000000000000000000"),
            short: id[..4].into(),
            kind: (*kind).into(),
            label: (*label).into(),
            detail: detail.map(Into::into),
            fields: Vec::new(),
        })
        .collect();
    s.items.sort_by_key(|i| i.label.to_lowercase());
    s.loaded = true;
    s.search.focused = true;
    s.selected = s
        .items
        .iter()
        .find(|i| i.label == "github.com")
        .map(|i| i.id.clone());
    detail_for_selection(s);
}

fn detail_for_selection(s: &mut App) {
    let Some(item) = s.selected_item().cloned() else {
        return;
    };
    let field = |name: &str, kind: &str, value: &str| FieldInfo {
        name: name.into(),
        kind: kind.into(),
        value: value.into(),
    };
    let fields = match item.kind.as_str() {
        "card" => vec![
            field("number", "secret", "4242424242424242"),
            field("expiry", "month", "2029-08"),
            field("cvv", "secret", "123"),
            field("cardholder", "text", "Dax Raad"),
        ],
        _ => vec![
            field("password", "secret", "correct-horse-battery-staple"),
            field("username", "text", item.detail.as_deref().unwrap_or("")),
            field(
                "url",
                "url",
                &format!("https://{}", item.label.to_lowercase()),
            ),
            field("notes", "note", "Recovery codes are in the safe."),
        ],
    };
    s.detail = Some(ItemInfo { fields, ..item });
}

#[cfg(test)]
mod tests {
    use super::is_live;
    use rune::tooling::Args;

    fn live(argv: &[&str]) -> bool {
        is_live(&Args::parse_from(
            argv.iter().map(|a| a.to_string()).collect(),
        ))
    }

    #[test]
    fn tooling_runs_never_reach_the_agent() {
        for argv in [
            &["--snap", "out.png"][..],
            &["--tree", "tree.json"],
            &["--trace", "run.jsonl"],
            &["--frames", "30", "--out", "frames"],
            &["--strip", "strip.png"],
            &["--script", "s.json"],
            &["--list-scenes"],
            &["--list-windows"],
            &["--first-pixels"],
            &["--scene", "vault"],
            &["--theme", "light", "--snap", "out.png"],
        ] {
            assert!(!live(argv), "{argv:?} would connect to the agent");
        }
        assert!(live(&[]));
        assert!(live(&["--reduced-motion"]));
        assert!(live(&["--theme", "light"]));
    }
}
