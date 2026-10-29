//! Synthetic scenes for headless snapshots, scripts and tests (`--scene`).

mod fixtures;

pub use fixtures::{LOOPBACK_COST, MANY};

use deadbolt_client::protocol::{
    AgentClientInfo, AgentGrantInfo, Fill, ImportReport, MirrorAction, MirrorItem, MirrorReport,
    Status,
};
use rune::{SecretCopy, Tx};

use crate::agent;
use crate::model::{App, Screen};
use crate::onboarding::worker::{Progress, Stage, Worker};
use crate::onboarding::{self, Flow, Step};
use crate::view::{Notice, Severity};
use crate::{import, install, settings, shortcut};
use fixtures::{
    FIXTURE_PRIVATE_KEY, FIXTURE_PUBLIC_KEY, detail_for_selection, empty_vault, fixture_ticket,
    form, generated, import_preview, import_report, join_notice, kind_scene, locked, locked_error,
    locked_touch_id, locked_touch_id_reset, mirrored, new_of, other_shortcut, pairing, panel_vault,
    settings_touch_id, show_preview, status, typed, vault, vault_243, vault_info,
    vault_with_offered_installer, welcome, working,
};

pub(crate) type Scene = (&'static str, fn(&mut App));

/// Puts a copy in flight in a scene: the handler's write is never made, and
/// Rune's pending copy stands in for it, so the countdown runs and clears nothing.
fn staged(s: &mut App, copy: fn(&mut App, &mut Tx)) {
    copy(s, &mut Tx::default());
    if let Some(c) = &mut s.copy {
        c.copied = Some(SecretCopy::pending());
    }
}

fn failed(s: &mut App) {
    s.screen = Screen::Failed("connecting to the agent: Connection refused (os error 61)".into());
}

pub(crate) const SCENES: &[Scene] = &[
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
    ("vault-243", vault_243),
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
        s.onboarding.notice = Some(Notice::new(
            Severity::Danger,
            "Couldn't create the vault",
            "Connecting to the agent: connection refused. Try again.",
        ));
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
    ("failed", failed),
    ("locked", locked),
    ("locked-error", locked_error),
    ("locked-touch-id", locked_touch_id),
    ("locked-touch-id-reset", locked_touch_id_reset),
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
    ("api", |s| kind_scene(s, "api")),
    ("database", |s| kind_scene(s, "database")),
    ("wifi", |s| kind_scene(s, "wifi")),
    ("document", |s| kind_scene(s, "document")),
    ("passport", |s| kind_scene(s, "passport")),
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
        show_preview(
            s,
            import_preview(ImportReport {
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
            }),
        );
    }),
    // A second look at an export already imported, from a vault with items.
    ("import-nothing-new", |s| {
        vault(s);
        show_preview(
            s,
            import_preview(ImportReport {
                duplicates: 232,
                ..import_report()
            }),
        );
    }),
    // An export of documents only: nothing Deadbolt takes.
    ("import-nothing-to-import", |s| {
        vault(s);
        show_preview(
            s,
            import_preview(ImportReport {
                duplicates: 0,
                warnings: Vec::new(),
                ..import_report()
            }),
        );
    }),
    // Import found the file changed since its preview: a fresh preview.
    ("import-changed", |s| {
        empty_vault(s);
        show_preview(
            s,
            import::Preview {
                changed: true,
                ..import_preview(ImportReport {
                    new: [("login".into(), 215), ("card".into(), 3)].into(),
                    duplicates: 0,
                    ..import_report()
                })
            },
        );
    }),
    ("import-error", |s| {
        empty_vault(s);
        s.import.error = Some(Notice::new(
            Severity::Caution,
            "Passwords.json isn't an export Deadbolt can read",
            "This is an encrypted export; export as unencrypted .json.",
        ));
    }),
    // ⇧⌘I in a vault with items.
    ("import", |s| {
        vault(s);
        s.show_import();
    }),
    // ⌘N: a new login, with a password from the generator (its type list
    // closed).
    ("new-login", |s| {
        vault(s);
        s.new_item();
        s.close_types();
        generated(s);
    }),
    // ⌘N as it opens: the type list, unfiltered, its filter focused.
    ("picker-open", |s| {
        vault(s);
        s.new_item();
        generated(s);
    }),
    // The type list filtered by "key": SSH key, then API credential.
    ("picker-key", |s| {
        vault(s);
        s.new_item();
        generated(s);
        s.edit.types.filter.replace_text("key");
        s.types_filtered();
    }),
    // A new card, its number typed.
    ("new-card", |s| {
        new_of(s, "card", "Visa");
        typed(s, "cardholder", "Dax Raad");
        typed(s, "number", "4242 4242 4242 4242");
        typed(s, "expiry", "08/29");
    }),
    // A new identity: its name and address in parts.
    ("new-identity", |s| {
        new_of(s, "identity", "Home");
        typed(s, "given-name", "Dax");
        typed(s, "family-name", "Raad");
        typed(s, "email", "dax@anoma.ly");
        typed(s, "address-line1", "1 Main St");
        typed(s, "city", "Springfield");
    }),
    // A new secure note, its body typed (hidden: one row of dots).
    ("new-note", |s| {
        new_of(s, "note", "Alarm codes");
        typed(s, "notes", "Front door: 4417\nGarage: 0932\n");
    }),
    // A new SSH key, its private key pasted (hidden) and its public key wrapping.
    ("new-ssh", |s| {
        new_of(s, "ssh", "Deploy key");
        typed(s, "private-key", FIXTURE_PRIVATE_KEY);
        typed(s, "public-key", FIXTURE_PUBLIC_KEY);
    }),
    // A new API credential: its key hidden, what it's for typed.
    ("new-api", |s| {
        new_of(s, "api", "Stripe");
        typed(s, "credential", "sk_live_51HxY2c");
        typed(s, "username", "deploy-bot");
        typed(s, "type", "bearer");
        typed(s, "environment", "production");
    }),
    // A new database: where it is and how to sign in.
    ("new-database", |s| {
        new_of(s, "database", "Production");
        typed(s, "type", "postgres");
        typed(s, "host", "db.anoma.ly");
        typed(s, "port", "5432");
        typed(s, "database", "app");
        typed(s, "username", "app");
        typed(s, "password", "pg-secret");
    }),
    // A new document, its file not chosen yet.
    ("new-document", |s| new_of(s, "document", "Passport scan")),
    // A new Wi-Fi network.
    ("new-wifi", |s| {
        new_of(s, "wifi", "Home");
        typed(s, "ssid", "Raad Home 5G");
        typed(s, "password", "correct-horse");
        typed(s, "security", "WPA3");
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
        vault_with_offered_installer(s);
        s.hotkey = shortcut::Hotkey::new(Some(shortcut::default()), vec![other_shortcut()])
            .taken_by("Finder search");
        s.start_shortcut(false);
        s.open_settings();
    }),
    // Changed to ⌥⌘Space: Settings offers the default back.
    ("settings-changed", |s| {
        vault(s);
        s.hotkey = shortcut::Hotkey::new(Some(other_shortcut()), Vec::new());
        s.start_shortcut(false);
        s.open_settings();
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
        s.open_settings();
    }),
    // Settings on a Mac with Touch ID enabled.
    ("settings-touch-id", settings_touch_id),
    // github.com mirrored from 1Password, shown, then opened with ⌘E.
    ("mirrored", mirrored),
    ("edit-mirrored", |s| {
        mirrored(s);
        s.edit_selected();
    }),
    // Settings after a sync from 1Password, and one 1Password refused.
    ("settings-synced", |s| {
        vault(s);
        s.open_settings();
        s.sync_one_password();
        let item = |action, title: &str| MirrorItem {
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
    // The card, selected.
    ("card", |s| {
        vault(s);
        s.selected = s
            .items
            .iter()
            .find(|i| i.kind == "card")
            .map(|i| i.id.clone());
        detail_for_selection(s);
    }),
    // ⇥ moved into github.com's fields, on its password.
    ("field", |s| {
        vault(s);
        s.search.focused = false;
        s.nav.field = Some(1);
    }),
    // ⌘K on github.com.
    ("actions", |s| {
        vault(s);
        s.open_palette();
    }),
    // ?: every shortcut.
    ("sheet", |s| {
        vault(s);
        s.nav.sheet = true;
    }),
    // Settings' Agents open: Browse paired, with a site-wide grant and one
    // for a single login, its passkey included.
    ("settings-agents", |s| {
        vault(s);
        s.open_settings();
        s.toggle_agents();
        let grant =
            |id: &str, site: Option<&str>, login: Option<&str>, fields, passkeys| AgentGrantInfo {
                id: id.into(),
                client_id: "1b48513abb66721c".into(),
                client_name: Some("browse".into()),
                site: site.map(Into::into),
                login: None,
                login_label: login.map(Into::into),
                fields,
                passkeys,
                created: 0,
                expires_at: None,
                expired: false,
            };
        let listing = (
            vec![AgentClientInfo {
                id: "1b48513abb66721c".into(),
                name: "browse".into(),
                created: 0,
                last_used: None,
            }],
            vec![
                grant(
                    "a0",
                    None,
                    None,
                    vec![Fill::Username, Fill::Password, Fill::Totp],
                    true,
                ),
                grant(
                    "a1",
                    Some("github.com"),
                    None,
                    vec![Fill::Username, Fill::Password],
                    false,
                ),
                grant(
                    "a2",
                    Some("vercel.com"),
                    Some("kit@example.com"),
                    vec![Fill::Totp],
                    true,
                ),
            ],
        );
        s.apply(
            agent::Done::Agents {
                seq: 1,
                result: Ok(listing),
            },
            &mut Tx::default(),
        );
        s.nav.row = settings::rows(s)
            .iter()
            .position(|r| *r == settings::Row::Agents)
            .unwrap_or(0);
    }),
    // ⌘, on a Mac with Touch ID, the keys on its second row.
    ("settings-page", |s| {
        settings_touch_id(s);
        s.nav.row = 1;
    }),
    ("settings-sync-failed", |s| {
        vault(s);
        s.open_settings();
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
    ("locked-error", locked_error),
    ("locked-touch-id", locked_touch_id),
    ("locked-touch-id-reset", locked_touch_id_reset),
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
    ("failed", failed),
];
