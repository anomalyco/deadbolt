//! Deadbolt's desktop app: a thin Rune client of the running agent, over
//! the same socket protocol as the CLI. See docs/app.md.

pub mod agent;
pub mod binary;
pub mod edit;
pub mod import;
pub mod install;
pub mod mirror;
pub mod model;
pub mod onboarding;
pub mod panel;
pub mod shortcut;
pub mod view;

use deadbolt_client::Paths;
use deadbolt_client::protocol::{
    Code, DeviceInfo, FieldInfo, ImportReport, ImportSource, ItemInfo, MirrorAction, MirrorReport,
    Status, Tally, VaultInfo,
};
use rune::{AppSpec, KeyEvent, SecretCopy, Tx, Waker};

use agent::{Agent, Job};
use model::{App, Screen};
use onboarding::worker::{Progress, Stage, Worker};
use onboarding::{Flow, Notice, Pairing, Severity, Step};

pub fn spec() -> AppSpec<App> {
    AppSpec {
        title: "Deadbolt",
        size: (820.0, 540.0),
        min_size: Some((640.0, 420.0)),
        init: || App::new(Agent::offline()),
        view: view::app,
        scenes: SCENES,
        fonts: rune_theme_opencode::FONTS,
        families: rune_theme_opencode::FAMILIES,
        setup: Some(setup),
        poll: Some(|s, now, tx| s.poll(now, tx)),
        on_key: Some(|s: &mut App, ev: &KeyEvent, tx: &mut Tx| s.on_key(ev, tx)),
    }
}

/// Runs the app against this user's agent and clipboard, unless `argv` asks
/// for Rune's tooling (`--snap`, `--tree`, `--script`, `--scene`, …): those
/// runs get no agent (and Rune keeps headless runs off the clipboard), so a
/// snapshot or tree dump can never hold real vault data.
///
/// Two windows: the main one (`--window main` for tooling) and the quick
/// panel (`--window panel`), which the global shortcut (⇧⌘Space unless
/// changed in Settings) or "Open Quick Panel" in the app and Dock menus
/// brings up (off macOS, the main window's hint). `--panel` starts with the
/// panel instead of the main window. Headless runs register the default
/// shortcut on the panel virtually, so a script's `{"shortcut": …}` and
/// `{"menu": …}` steps reach it without touching the desktop.
pub fn run() {
    let args = rune::tooling::Args::parse();
    let (live, headless) = (is_live(&args), args.headless());
    let extra = rune::extra_args();
    let reduced_motion = extra.iter().any(|a| a == "--reduced-motion");
    let panel_first = extra.iter().any(|a| a == panel::window::FLAG);
    // A headless `--desktop` run drives every window, so they can reach each
    // other as in a live run (the menus' items act on the main window).
    let wired = live || std::env::args().any(|a| a == "--desktop");
    // Started for the panel, Deadbolt runs without a Dock icon so launching
    // doesn't activate it and the app you were in keeps focus; opening the
    // main window brings the icon back (`Windows::open_main`).
    let accessory = live && panel_first;
    let shortcut_file = live.then(|| Paths::get().config.with_file_name("app-shortcut"));
    let chosen = shortcut_file
        .as_deref()
        .map_or_else(|| Some(shortcut::default()), shortcut::load);
    rune::run_windows_with(rune::RunOptions { accessory }, move |_| {
        let mut main = rune::App::new(spec()).chrome(view::CHROME);
        let mut quick = rune::App::new(panel::spec()).windowless();
        // Native menus are macOS's; headless scripts reach them everywhere.
        if cfg!(target_os = "macos") || headless {
            for item in panel::window::menu(chosen.as_ref()) {
                quick = quick.menu_item(item);
            }
        }
        let windows = panel::window::Windows::new(main.handle(), quick.handle());
        let main_windows = windows.clone();
        let quick_handle = quick.handle();
        main = main
            .init(move || {
                let mut app = if live {
                    let mut app = App::new(Agent::spawn(Paths::get(), agent::launch()));
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
                    if let Some(file) = shortcut_file {
                        app.hotkey = shortcut::Hotkey::live(quick_handle, file, chosen);
                    }
                    app
                } else {
                    App::new(Agent::offline())
                };
                if wired {
                    app.windows = Some(main_windows);
                }
                app.reduced_motion = reduced_motion;
                app
            })
            .on_focus(|s, focused, tx| s.main_focus(focused, tx))
            .on_close(|s, tx| s.quit(tx));
        // Registers on the panel's App and sets its menu: Rune attaches every
        // window before any queued update runs.
        if live {
            main.handle()
                .update(move |s, _| s.start_shortcut(panel_first));
        }
        let panel_windows = windows.clone();
        let mut quick = quick
            .init(move || {
                let mut app = if live {
                    App::panel(Agent::spawn(Paths::get(), agent::launch()))
                } else {
                    App::panel(Agent::offline())
                };
                if wired {
                    app.windows = Some(panel_windows);
                    if let Some(panel) = &mut app.panel {
                        panel.phase = panel::Phase::Hidden;
                    }
                }
                app.reduced_motion = reduced_motion;
                app
            })
            .on_focus(|s, focused, tx| s.panel_focus(focused, tx))
            .on_close(|s, tx| s.panel_closed(tx));
        if headless {
            quick = quick.global_shortcut(shortcut::DEFAULT, |s, tx| s.toggle_panel(tx));
        }
        // Headless too, so a `--script` with displays and a pointer shows where it's placed.
        if panel_first {
            main = windows.start_with_panel(main);
        }
        vec![
            rune::WindowSpec::from_app("main", main),
            rune::WindowSpec::from_app("panel", quick).configured_options(panel::window::options()),
        ]
    });
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

/// Puts a copy in flight in a scene: the handler's write is never made, and
/// Rune's pending copy stands in for it, so the countdown runs and clears nothing.
fn staged(s: &mut App, copy: fn(&mut App, &mut Tx)) {
    copy(s, &mut Tx::default());
    if let Some(c) = &mut s.copy {
        c.copied = Some(SecretCopy::pending());
    }
}

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
        s.onboarding.passphrase.replace_text("correct horse");
        s.onboarding.repeat.replace_text("correct hose");
        s.onboarding.passphrase.focused = false;
        s.onboarding.repeat.focused = true;
    }),
    ("create-ready", |s| {
        form(s, Flow::Create);
        s.onboarding
            .passphrase
            .replace_text("correct horse battery staple");
        s.onboarding
            .repeat
            .replace_text("correct horse battery staple");
        s.onboarding.passphrase.focused = false;
        s.onboarding.repeat.focused = true;
    }),
    ("create-invalid", |s| {
        form(s, Flow::Create);
        s.onboarding.vault = rune::TextEdit::new("My Vault");
        s.onboarding.passphrase.replace_text("hunter2");
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
    ("locked-touch-id", |s| {
        locked(s);
        if let Some(st) = &mut s.status {
            st.touch_id_available = true;
            st.touch_id_enabled = true;
            st.touch_id_ready = true;
        }
    }),
    ("locked-touch-id-reset", |s| {
        locked(s);
        if let Some(st) = &mut s.status {
            st.touch_id_available = true;
            st.touch_id_enabled = true;
            st.touch_id_reset = true;
        }
    }),
    ("vault", vault),
    ("note", |s| kind_scene(s, "note")),
    ("note-revealed", |s| {
        kind_scene(s, "note");
        s.toggle_reveal("notes");
    }),
    ("ssh", |s| kind_scene(s, "ssh")),
    ("ssh-revealed", |s| {
        kind_scene(s, "ssh");
        s.toggle_reveal("private-key");
    }),
    ("identity", |s| kind_scene(s, "identity")),
    ("passkey", |s| kind_scene(s, "passkey")),
    ("passkey-delete", |s| {
        kind_scene(s, "passkey");
        s.ask_delete();
    }),
    ("search", |s| {
        vault(s);
        s.search = rune::TextEdit::new("git");
        s.search.focused = true;
        s.keep_selection_visible();
        detail_for_selection(s);
    }),
    ("copied", |s| {
        vault(s);
        staged(s, |s, tx| s.copy_field("password", tx));
    }),
    ("revealed", |s| {
        vault(s);
        s.toggle_reveal("password");
    }),
    // ⌥⏎ just copied github.com's one-time code.
    ("code-copied", |s| {
        vault(s);
        staged(s, |s, tx| s.copy_field("otp", tx));
    }),
    ("empty", empty_vault),
    // A 1Password export dragged over the empty vault.
    ("import-hover", |s| {
        empty_vault(s);
        s.import.hover = true;
    }),
    // What a 1Password export would bring in.
    ("import-preview", |s| {
        empty_vault(s);
        s.import.open = true;
        s.import.phase = import::Phase::Preview(import_preview(ImportReport {
            new: [
                ("login".into(), 214),
                ("card".into(), 3),
                ("note".into(), 12),
                ("ssh".into(), 2),
                ("identity".into(), 1),
            ]
            .into(),
            duplicates: 0,
            ..import_report()
        }));
    }),
    // A second look at an export already imported, from a vault with items.
    ("import-nothing-new", |s| {
        vault(s);
        s.import.open = true;
        s.import.phase = import::Phase::Preview(import_preview(ImportReport {
            duplicates: 232,
            ..import_report()
        }));
    }),
    // An export of documents only: nothing Deadbolt takes.
    ("import-nothing-to-import", |s| {
        vault(s);
        s.import.open = true;
        s.import.phase = import::Phase::Preview(import_preview(ImportReport {
            duplicates: 0,
            warnings: Vec::new(),
            ..import_report()
        }));
    }),
    // Import found the file changed since its preview: a fresh preview.
    ("import-changed", |s| {
        empty_vault(s);
        s.import.open = true;
        s.import.phase = import::Phase::Preview(import::Preview {
            changed: true,
            ..import_preview(ImportReport {
                new: [("login".into(), 215), ("card".into(), 3)].into(),
                duplicates: 0,
                ..import_report()
            })
        });
    }),
    ("import-error", |s| {
        empty_vault(s);
        s.import.error = Some(Notice {
            severity: Severity::Caution,
            title: "Passwords.json isn't an export Deadbolt can read".into(),
            body: "This is an encrypted export; export as unencrypted .json.".into(),
        });
    }),
    // ⇧⌘I in a vault with items.
    ("import", |s| {
        vault(s);
        s.show_import();
    }),
    // ⌘N: a new login, with a password from the generator.
    ("new-login", |s| {
        vault(s);
        s.new_item();
        generated(s);
    }),
    // A new card, its number typed.
    ("new-card", |s| {
        vault(s);
        s.new_item();
        s.pick_kind("card");
        if let Some(form) = &mut s.edit.form {
            form.name.replace_text("Visa");
        }
        typed(s, "cardholder", "Dax Raad");
        typed(s, "number", "4242 4242 4242 4242");
        typed(s, "expiry", "08/29");
    }),
    // A new identity, its address over two lines.
    ("new-identity", |s| {
        vault(s);
        s.new_item();
        s.pick_kind("identity");
        if let Some(form) = &mut s.edit.form {
            form.name.replace_text("Dax Raad");
        }
        typed(s, "email", "dax@anoma.ly");
        typed(s, "address", "1 Main St\nSpringfield, IL 12345");
    }),
    // A new secure note, its body typed (hidden: one row of dots).
    ("new-note", |s| {
        vault(s);
        s.new_item();
        s.pick_kind("note");
        if let Some(form) = &mut s.edit.form {
            form.name.replace_text("Alarm codes");
        }
        typed(s, "notes", "Front door: 4417\nGarage: 0932\n");
    }),
    // A new SSH key, its private key pasted (hidden) and its public key
    // wrapping.
    ("new-ssh", |s| {
        vault(s);
        s.new_item();
        s.pick_kind("ssh");
        if let Some(form) = &mut s.edit.form {
            form.name.replace_text("Deploy key");
        }
        typed(s, "private-key", FIXTURE_PRIVATE_KEY);
        typed(s, "public-key", FIXTURE_PUBLIC_KEY);
    }),
    // ⌘E on an SSH key: its private key kept, empty under its placeholder.
    ("edit-ssh", |s| {
        kind_scene(s, "ssh");
        s.edit_selected();
    }),
    // The same, its private key shown and wrapping.
    ("edit-ssh-revealed", |s| {
        kind_scene(s, "ssh");
        s.edit_selected();
        s.toggle_shown(0);
    }),
    // ⌘E on github.com, its username changed.
    ("edit", |s| {
        vault(s);
        s.edit_selected();
        typed(s, "username", "kit@anoma.ly");
    }),
    // The agent refused a card number.
    ("edit-invalid", |s| {
        vault(s);
        s.new_item();
        s.pick_kind("card");
        typed(s, "number", "4242 4242");
        s.save();
        let seq = s.edit_seq();
        s.apply(
            agent::Done::Saved {
                seq,
                result: Err(agent::Failure {
                    code: None,
                    message: "invalid value for number: must be 12-19 digits".into(),
                }),
            },
            &mut Tx::default(),
        );
    }),
    // ⌘⌫ on github.com.
    ("delete-confirm", |s| {
        vault(s);
        s.ask_delete();
    }),
    // Another device changed github.com while it was open here.
    ("edit-conflict", |s| {
        vault(s);
        s.edit_selected();
        typed(s, "username", "kit@anoma.ly");
        if let Some(mut item) = s.detail.clone() {
            if let Some(f) = item.fields.iter_mut().find(|f| f.name == "password") {
                f.value = "a-new-password-from-the-studio".into();
            }
            s.edit_item_landed(&item);
            s.detail = Some(item);
        }
    }),
    // macOS's Finder search holds ⌥⌘Space: recording it shows the conflict
    // in place (scripts/settings-shortcut.json).
    ("settings", |s| {
        vault(s);
        let mut i = install::Installer::fixture();
        i.offered = true;
        s.installer = Some(i);
        s.hotkey = shortcut::Hotkey::new(Some(shortcut::default()), vec![other_shortcut()])
            .taken_by("Finder search");
        s.start_shortcut(false);
        s.settings_open = true;
    }),
    // Changed to ⌥⌘Space: Settings offers the default back.
    ("settings-changed", |s| {
        vault(s);
        s.hotkey = shortcut::Hotkey::new(Some(other_shortcut()), Vec::new());
        s.start_shortcut(false);
        s.settings_open = true;
    }),
    ("shortcut-conflict", |s| {
        vault(s);
        s.hotkey = shortcut::Hotkey::new(Some(shortcut::default()), vec![shortcut::default()]);
        s.start_shortcut(false);
    }),
    // ⇧⌘Space was taken at launch: Settings says so and offers to try again.
    ("settings-unavailable", |s| {
        vault(s);
        s.hotkey = shortcut::Hotkey::new(Some(shortcut::default()), vec![shortcut::default()]);
        s.start_shortcut(false);
        s.settings_open = true;
    }),
    // Settings on a Mac with Touch ID enabled.
    ("settings-touch-id", |s| {
        vault(s);
        if let Some(st) = &mut s.status {
            st.touch_id_available = true;
            st.touch_id_enabled = true;
        }
        let mut i = install::Installer::fixture();
        i.offered = true;
        s.installer = Some(i);
        s.hotkey = shortcut::Hotkey::new(Some(shortcut::default()), Vec::new());
        s.start_shortcut(false);
        s.settings_open = true;
    }),
    // github.com mirrored from 1Password, shown, then opened with ⌘E.
    ("mirrored", mirrored),
    ("edit-mirrored", |s| {
        mirrored(s);
        s.edit_selected();
    }),
    // Settings after a sync from 1Password, and one 1Password refused.
    ("settings-synced", |s| {
        vault(s);
        s.settings_open = true;
        s.sync_one_password();
        let item = |action, title: &str| deadbolt_client::protocol::MirrorItem {
            action,
            title: title.into(),
            reason: None,
        };
        let mut items = vec![item(MirrorAction::Update, "github.com"); 12];
        items.extend(vec![item(MirrorAction::Add, "Cloudflare"); 3]);
        let report = MirrorReport {
            applied: true,
            unchanged: 214,
            items,
            warnings: Vec::new(),
            dropped: Vec::new(),
        };
        s.apply(
            agent::Done::Mirrored {
                seq: 1,
                result: Ok(report),
            },
            &mut Tx::default(),
        );
    }),
    ("settings-sync-failed", |s| {
        vault(s);
        s.settings_open = true;
        s.sync_one_password();
        let failure = agent::Failure {
            code: None,
            message: "1Password: not signed in. Sign in to the 1Password app and turn on \
                Settings › Developer › Integrate with 1Password CLI"
                .into(),
        };
        s.apply(
            agent::Done::Mirrored {
                seq: 1,
                result: Err(failure),
            },
            &mut Tx::default(),
        );
    }),
];

/// The vault with github.com mirrored from 1Password, selected.
fn mirrored(s: &mut App) {
    vault(s);
    for item in s.items.iter_mut().filter(|i| i.label == "github.com") {
        item.source = Some("1Password".into());
    }
    detail_for_selection(s);
}

/// ⌥⌘Space, the scenes' other shortcut.
#[expect(clippy::expect_used, reason = "a constant")]
fn other_shortcut() -> rune::Shortcut {
    "alt+super+space".parse().expect("parses")
}

/// The quick panel's states (`--window panel --scene NAME`).
pub(crate) const PANEL_SCENES: &[Scene] = &[
    ("connecting", |_| {}),
    // Just opened: empty search, every item, the first selected.
    ("empty", panel_vault),
    ("filtering", |s| {
        panel_vault(s);
        s.search = rune::TextEdit::new("git");
        s.search.focused = true;
        s.keep_selection_visible();
        detail_for_selection(s);
    }),
    ("no-match", |s| {
        panel_vault(s);
        s.search = rune::TextEdit::new("bitbucket");
        s.search.focused = true;
        s.keep_selection_visible();
    }),
    // ⏎ just copied github.com's password: the confirmation, then it closes at 1.1 s.
    ("copied", |s| {
        panel_vault(s);
        staged(s, |s, tx| s.copy_selected("password", tx));
    }),
    ("locked", locked),
    ("locked-error", |s| {
        locked(s);
        s.unlock_error = Some("That passphrase didn't unlock this device.".into());
    }),
    ("locked-touch-id", |s| {
        locked(s);
        if let Some(st) = &mut s.status {
            st.touch_id_available = true;
            st.touch_id_enabled = true;
            st.touch_id_ready = true;
        }
    }),
    ("locked-touch-id-reset", |s| {
        locked(s);
        if let Some(st) = &mut s.status {
            st.touch_id_available = true;
            st.touch_id_enabled = true;
            st.touch_id_reset = true;
        }
    }),
    ("not-set-up", |s| {
        s.status = Some(Status {
            initialized: false,
            device: None,
            vaults: Vec::new(),
            ..status(false)
        });
        s.screen = Screen::Onboarding;
    }),
    ("empty-vault", |s| {
        panel_vault(s);
        s.items.clear();
        s.select(None);
    }),
    ("failed", |s| {
        s.screen =
            Screen::Failed("connecting to the agent: Connection refused (os error 61)".into());
    }),
];

/// The vault as the panel opens on it: no item's values until one is selected.
fn panel_vault(s: &mut App) {
    vault(s);
    s.search = rune::TextEdit::new("");
    s.search.focused = true;
    s.selected = None;
    s.set_detail(None);
    s.keep_selection_visible();
    detail_for_selection(s);
}

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
        touch_id_available: false,
        touch_id_enabled: false,
        touch_id_ready: false,
        touch_id_reset: false,
    }
}

fn locked(s: &mut App) {
    s.status = Some(status(false));
    s.screen = Screen::Locked;
    s.passphrase.focused = true;
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

fn empty_vault(s: &mut App) {
    vault(s);
    s.items.clear();
    s.selected = None;
    s.set_detail(None);
}

fn import_report() -> ImportReport {
    let tally = |count, one: &str, many: &str| Tally {
        count,
        one: one.into(),
        many: many.into(),
    };
    ImportReport {
        source: ImportSource::OnePassword,
        new: Default::default(),
        duplicates: 0,
        skipped: vec![tally(3, "document", "documents")],
        warnings: vec![tally(2, "URL kept as text", "URLs kept as text")],
        dropped: vec![
            tally(9, "tag", "tags"),
            tally(4, "attachment", "attachments"),
        ],
    }
}

fn import_preview(report: ImportReport) -> import::Preview {
    import::Preview {
        path: "/fixture/1PasswordExport-2026-10-25.1pux".into(),
        name: "1PasswordExport-2026-10-25.1pux".into(),
        report,
        digest: blake3::hash(b"fixture"),
        changed: false,
    }
}

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
            source: None,
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

/// The vault with a secure note, an SSH key, an identity and a passkey, one selected.
fn kind_scene(s: &mut App, kind: &str) {
    vault(s);
    for (id, kind, label, detail) in [
        ("b7c1e2", "note", "Alarm codes", None),
        ("d2a9f0", "ssh", "Deploy key", Some("deploy@anoma.ly")),
        ("5e8b31", "identity", "Dax Raad", Some("dax@anoma.ly")),
        ("9c4f7a", "passkey", "github.com", Some("thdxr")),
    ] {
        s.items.push(ItemInfo {
            id: format!("{id}0000000000000000000000000000000000000000000000000000000000"),
            short: id[..4].into(),
            kind: kind.into(),
            label: label.into(),
            detail: detail.map(Into::into),
            fields: Vec::new(),
            source: None,
        });
    }
    s.items.sort_by_key(|i| i.label.to_lowercase());
    s.selected = s
        .items
        .iter()
        .find(|i| i.kind == kind)
        .map(|i| i.id.clone());
    detail_for_selection(s);
}

/// The scenes' SSH key, as a key file has it: one long base64 line, and a
/// final line break.
const FIXTURE_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFixtureFixtureFixtureFixtureFixtureFixtureFixtureFixture00\n-----END PRIVATE KEY-----\n";
const FIXTURE_PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureFixtureFixtureFixtureFixture deploy@anoma.ly";

/// The open form's field `name`, typed into.
fn typed(s: &mut App, name: &str, value: &str) {
    if let Some(input) = s
        .edit
        .form
        .as_mut()
        .and_then(|f| f.fields.iter_mut().find(|i| i.name == name))
    {
        input.edit.replace_text(value);
    }
}

/// The generator's answer to the open form, as the agent would give it.
fn generated(s: &mut App) {
    let Some(seq) = s.generating() else { return };
    let password = zeroize::Zeroizing::new("Vq7#mRz2!pKx9@wLt4&nBe8".to_owned());
    s.apply(
        agent::Done::Generated {
            seq,
            result: Ok(password),
        },
        &mut Tx::default(),
    );
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
    let mut fields = match item.kind.as_str() {
        "card" => vec![
            field("number", "secret", "4242424242424242"),
            field("expiry", "month", "2029-08"),
            field("cvv", "secret", "123"),
            field("cardholder", "text", "Dax Raad"),
        ],
        "note" => vec![field(
            "notes",
            "secret",
            "Front door: 4417\nGarage: 0932\nThe panel is behind the coats.",
        )],
        "ssh" => vec![
            field("private-key", "secret", FIXTURE_PRIVATE_KEY),
            field("public-key", "text", FIXTURE_PUBLIC_KEY),
            field(
                "fingerprint",
                "text",
                "SHA256:Fx7tQ2mVb9yLr4cWkP0sN8hJd3aZe6uGo1iTq5XwYnE",
            ),
            field("comment", "text", "deploy@anoma.ly"),
        ],
        // As the agent sends it: everything but the private key.
        "passkey" => vec![
            field("rp-id", "text", &item.label),
            field("username", "text", item.detail.as_deref().unwrap_or("")),
            field("credential-id", "text", "q5Zt0bJ8xW1cR4mN7pLs2A"),
            field("user-handle", "text", "MTIzNDU2Nzg"),
            field("created", "date", "2026-10-27"),
        ],
        "identity" => vec![
            field("name", "text", "Dax Raad"),
            field("email", "email", "dax@anoma.ly"),
            field("phone", "text", "+1 555 0100"),
            field(
                "address",
                "note",
                "1 Main St\nApt 2\nSpringfield, IL 12345\nUS",
            ),
            field("birthday", "date", "1990-03-01"),
            field("passport", "secret", "X1234567"),
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
    let otp = item.kind == "login" && matches!(item.label.as_str(), "github.com" | "Cloudflare");
    if otp {
        // The app never holds the secret: the agent leaves it out.
        fields.insert(3, field("otp", "otp", ""));
    }
    s.set_detail(Some(ItemInfo { fields, ..item }));
    if otp {
        s.on_code(Ok(fixture_code()), &mut Tx::default());
    }
}

/// RFC 6238's SHA-1 secret ("12345678901234567890") at a fixed time,
/// 1999999992: 18 s of the code's 30 left (`totp::tests::the_app_scenes_code`).
fn fixture_code() -> Code {
    Code {
        code: "279037".to_owned().into(),
        period: 30,
        valid_until: 2_000_000_010,
        remaining_ms: 18_000,
    }
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
