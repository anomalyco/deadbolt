//! Synthetic vault, item and loopback-agent fixtures shared across scenes.

use deadbolt_client::protocol::{
    Code, DeviceInfo, FieldInfo, Finding, HealthCounts, HealthPeer, HealthReport, ImportReport,
    ImportSource, ItemHealth, ItemInfo, RiskLevel, Status, Tally, VaultInfo, WeakReason,
};
use rune::Tx;

use crate::agent::{self, Agent, Job};
use crate::model::{App, Screen};
use crate::onboarding::worker::Stage;
use crate::onboarding::{Flow, Step};
use crate::view::{Notice, Severity};
use crate::{import, install, shortcut};

/// How long the `vault-243` scene's agent takes over each request, about
/// what a real one does with its connection and peer check.
pub const LOOPBACK_COST: f64 = 0.03;
/// Items in the `vault-243` scene.
pub const MANY: usize = 243;

/// The scenes' SSH key, as a key file has it: one long base64 line, and a
/// final line break.
pub(super) const FIXTURE_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFixtureFixtureFixtureFixtureFixtureFixtureFixtureFixture00\n-----END PRIVATE KEY-----\n";
pub(super) const FIXTURE_PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureFixtureFixtureFixtureFixture deploy@anoma.ly";

const FIXTURE: &[(&str, &str, &str, Option<&str>)] = &[
    ("3f9a1c", "login", "github.com", Some("dax")),
    ("7b20e4", "login", "Linear", Some("dax@anoma.ly")),
    ("a81d55", "card", "Visa •••• 4242", Some("08/29")),
    ("c4e7f0", "login", "fly.io", Some("ops@anoma.ly")),
    ("e01b9d", "login", "gitlab.com", Some("dax")),
    ("f5c312", "login", "Cloudflare", Some("dax@anoma.ly")),
    ("09ad7e", "login", "Hetzner", Some("billing@anoma.ly")),
];

pub(super) fn locked(s: &mut App) {
    s.status = Some(status(false));
    s.screen = Screen::Locked;
    s.passphrase.focused = true;
}

pub(super) fn locked_error(s: &mut App) {
    locked(s);
    s.unlock_error = Some("That passphrase didn't unlock this device.".into());
}

pub(super) fn locked_touch_id(s: &mut App) {
    locked(s);
    if let Some(st) = &mut s.status {
        st.touch_id_available = true;
        st.touch_id_enabled = true;
        st.touch_id_ready = true;
    }
}

pub(super) fn locked_touch_id_reset(s: &mut App) {
    locked(s);
    if let Some(st) = &mut s.status {
        st.touch_id_available = true;
        st.touch_id_enabled = true;
        st.touch_id_reset = true;
    }
}

pub(super) fn vault_with_offered_installer(s: &mut App) {
    vault(s);
    let mut i = install::Installer::fixture();
    i.offered = true;
    s.installer = Some(i);
}

pub(super) fn settings_touch_id(s: &mut App) {
    vault_with_offered_installer(s);
    if let Some(st) = &mut s.status {
        st.touch_id_available = true;
        st.touch_id_enabled = true;
    }
    s.hotkey = shortcut::Hotkey::new(Some(shortcut::default()), Vec::new());
    s.start_shortcut(false);
    s.open_settings();
}

pub(super) fn show_preview(s: &mut App, preview: import::Preview) {
    s.import.open = true;
    s.import.phase = import::Phase::Preview(preview);
}

pub(super) fn new_of(s: &mut App, kind: &str, name: &str) {
    vault(s);
    s.new_item();
    s.choose_type(kind);
    if let Some(form) = &mut s.edit.form {
        form.name.replace_text(name);
    }
}

/// The vault with github.com mirrored from 1Password, selected.
pub(super) fn mirrored(s: &mut App) {
    vault(s);
    for item in s.items.iter_mut().filter(|i| i.label == "github.com") {
        item.source = Some("1Password".into());
    }
    detail_for_selection(s);
}

/// ⌥⌘Space, the scenes' other shortcut.
#[expect(clippy::expect_used, reason = "a constant")]
pub(super) fn other_shortcut() -> rune::Shortcut {
    "alt+super+space".parse().expect("parses")
}

/// The vault as the panel opens on it: no item's values until one is selected.
pub(super) fn panel_vault(s: &mut App) {
    vault(s);
    s.search = rune::TextEdit::new("");
    s.search.focused = true;
    s.selected = None;
    s.set_detail(None);
    s.keep_selection_visible();
    detail_for_selection(s);
}

pub(super) fn welcome(s: &mut App) {
    s.screen = Screen::Onboarding;
    s.onboarding.device = rune::TextEdit::new("Dax's MacBook Pro");
}

pub(super) fn form(s: &mut App, flow: Flow) {
    welcome(s);
    s.choose(flow);
}

pub(super) fn working(s: &mut App, flow: Flow, plan: Vec<Stage>) {
    welcome(s);
    s.status = Some(status(true));
    s.onboarding.stage = plan.first().copied();
    s.onboarding.plan = plan;
    s.onboarding.step = Step::Working(flow);
}

pub(super) fn join_notice(s: &mut App, severity: Severity, title: &str, body: &str) {
    welcome(s);
    s.onboarding.device_ready = true;
    s.choose(Flow::Join);
    s.onboarding.notice = Some(Notice::new(severity, title, body));
}

pub(super) fn vault_info(name: &str) -> VaultInfo {
    VaultInfo {
        id: "v1".into(),
        name: name.into(),
        default: true,
        members: 1,
        member: true,
        error: None,
    }
}

/// A pairing code as `deadbolt join` shows it.
pub(super) fn fixture_pairing_code() -> String {
    "violin-garden-tiger-lamp-zoo".into()
}

/// The device that pairs this one in the join scenes.
pub(super) fn inviter() -> DeviceInfo {
    DeviceInfo {
        id: "5f0c9a2e".into(),
        name: Some("studio".into()),
        this: false,
        connected: true,
        last_seen: None,
    }
}

pub(super) fn status(unlocked: bool) -> Status {
    Status {
        pid: 1,
        version: "fixture".into(),
        protocol: deadbolt_client::protocol::PROTOCOL_VERSION,
        program: None,
        home: String::new(),
        initialized: true,
        unlocked,
        locks_in_secs: None,
        caller: deadbolt_client::protocol::CallerInfo::unverified("fixture"),
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
            error: None,
        }],
        peers_online: 1,
        peers: 1,
        touch_id_available: false,
        touch_id_enabled: false,
        touch_id_ready: false,
        touch_id_reset: false,
    }
}

pub(super) fn empty_vault(s: &mut App) {
    vault(s);
    s.items.clear();
    s.selected = None;
    s.set_detail(None);
}

pub(super) fn import_report() -> ImportReport {
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
        sign_in: Default::default(),
    }
}

pub(super) fn import_preview(report: ImportReport) -> import::Preview {
    import::Preview {
        path: "/fixture/1PasswordExport-2026-10-25.1pux".into(),
        name: "1PasswordExport-2026-10-25.1pux".into(),
        report,
        digest: blake3::hash(b"fixture"),
        changed: false,
    }
}

fn fixture_item(id: &str, kind: &str, label: &str, detail: Option<&str>) -> ItemInfo {
    let (favorite, tags): (bool, &[&str]) = match label {
        "github.com" if kind == "login" => (true, &["dev", "work/aws"]),
        "Cloudflare" => (true, &["work/infra"]),
        "Hetzner" => (false, &["work/infra"]),
        "Linear" => (false, &["work"]),
        _ => (false, &[]),
    };
    ItemInfo {
        id: format!("{id}0000000000000000000000000000000000000000000000000000000000"),
        short: id[..4].into(),
        kind: kind.into(),
        label: label.into(),
        detail: detail.map(Into::into),
        fields: Vec::new(),
        source: None,
        favorite,
        tags: tags.iter().map(|t| (*t).to_owned()).collect(),
        deleted_at: None,
    }
}

pub(super) fn vault(s: &mut App) {
    s.status = Some(status(true));
    s.screen = Screen::Vault;
    s.items = FIXTURE
        .iter()
        .map(|&(id, kind, label, detail)| fixture_item(id, kind, label, detail))
        .collect();
    crate::model::sort_items(&mut s.items);
    s.loaded = true;
    s.search.focused = true;
    s.selected = s
        .items
        .iter()
        .find(|i| i.label == "github.com")
        .map(|i| i.id.clone());
    detail_for_selection(s);
}

/// A vault of `MANY` logins with an agent that answers on the app's clock
/// (`Agent::loopback`), for holding an arrow down the list.
pub(super) fn vault_243(s: &mut App) {
    s.agent = Agent::loopback(many_answer, LOOPBACK_COST);
    s.status = Some(status(true));
    s.screen = Screen::Vault;
    s.items = (0..MANY).map(many_item).collect();
    s.loaded = true;
    s.search.focused = true;
    let first = s.items.first().map(|i| i.id.clone());
    s.select(first);
}

/// The vault with Recently Deleted open on four items, deleted hours to
/// weeks ago, newest first as the agent lists them.
pub(super) fn trash(s: &mut App) {
    vault(s);
    s.open_trash();
    let now = crate::activity::now();
    let items = [
        (
            "d41e07",
            "login",
            "netflix.com",
            Some("dax@anoma.ly"),
            3 * 3600,
        ),
        ("6b0a93", "note", "Spare key", None, 30 * 3600),
        ("2fc581", "card", "Visa •••• 1881", Some("02/26"), 6 * 86400),
        (
            "8e3d2a",
            "database",
            "staging on db.anoma.ly",
            Some("app"),
            23 * 86400,
        ),
    ]
    .map(|(id, kind, label, detail, age)| ItemInfo {
        deleted_at: Some(now - age),
        ..fixture_item(id, kind, label, detail)
    });
    let seq = s.trash.seq();
    s.apply(
        agent::Done::Trash {
            seq,
            result: Ok((None, items.to_vec())),
        },
        &mut Tx::default(),
    );
}

/// Recently Deleted with netflix.com open, read-only.
pub(super) fn trash_item(s: &mut App) {
    trash(s);
    let Some(listed) = s.trash.items.first().cloned() else {
        return;
    };
    s.open_deleted(&listed.id);
    let field = |name: &str, kind: &str, value: &str| FieldInfo {
        name: name.into(),
        kind: kind.into(),
        value: value.into(),
    };
    let item = ItemInfo {
        fields: vec![
            field("username", "text", "dax@anoma.ly"),
            field("password", "secret", "fixture-netflix-password"),
            field("url", "url", "https://netflix.com/login"),
            field("notes", "note", "The family plan. Kitchen TV and the iPad."),
        ],
        ..listed
    };
    let seq = s.trash.item_seq();
    s.apply(
        agent::Done::TrashItem {
            seq,
            result: Ok(agent::Values::new(item)),
        },
        &mut Tx::default(),
    );
}

fn many_item(i: usize) -> ItemInfo {
    const SITES: [&str; 9] = [
        "acme",
        "brightline",
        "cobalt",
        "driftwood",
        "ember",
        "fathom",
        "granite",
        "harbor",
        "ironwood",
    ];
    ItemInfo {
        id: format!("{i:04x}{}", "0".repeat(60)),
        short: format!("{i:04x}"),
        kind: "login".into(),
        label: format!("{}-{i:03}.com", SITES[i * SITES.len() / MANY]),
        detail: Some(format!("user{i}@anoma.ly")),
        fields: Vec::new(),
        source: None,
        favorite: false,
        tags: Vec::new(),
        deleted_at: None,
    }
}

fn many_answer(job: Job) -> Option<agent::Done> {
    let values = |id: &str| {
        let i = usize::from_str_radix(id.get(..4)?, 16).ok()?;
        let item = many_item(i);
        let field = |name: &str, kind: &str, value: String| FieldInfo {
            name: name.into(),
            kind: kind.into(),
            value,
        };
        let fields = vec![
            field("password", "secret", format!("fixture-password-{i}")),
            field("username", "text", item.detail.clone().unwrap_or_default()),
            field("url", "url", format!("https://{}", item.label)),
            field("notes", "note", format!("Fixture item {i} of {MANY}.")),
        ];
        Some(agent::Values::new(ItemInfo { fields, ..item }))
    };
    let missing = || agent::Failure {
        code: None,
        message: "no such item".into(),
    };
    Some(match job {
        Job::Get { id, seq, .. } => agent::Done::Item {
            seq,
            result: values(&id).ok_or_else(missing),
        },
        Job::Peek { id, epoch, .. } => agent::Done::Peeked {
            result: values(&id).ok_or_else(missing),
            id,
            epoch,
        },
        _ => return None,
    })
}

/// The vault with a secure note, an SSH key, an identity and a passkey, one selected.
pub(super) fn kind_scene(s: &mut App, kind: &str) {
    vault(s);
    for (id, item_kind, label, detail) in [
        ("b7c1e2", "note", "Alarm codes", None),
        ("d2a9f0", "ssh", "Deploy key", Some("deploy@anoma.ly")),
        ("5e8b31", "identity", "Dax Raad", Some("dax@anoma.ly")),
        ("9c4f7a", "passkey", "github.com", Some("thdxr")),
        ("a41c09", "api", "Stripe", Some("deploy-bot")),
        ("c3e870", "database", "app on db.anoma.ly", Some("app")),
        ("e6d215", "wifi", "Raad Home 5G", Some("WPA3")),
        ("f09b44", "document", "Passport scan", Some("812.4 KB")),
        ("1b7d62", "passport", "Dax Raad", Some("United States")),
    ] {
        s.items.push(fixture_item(id, item_kind, label, detail));
    }
    crate::model::sort_items(&mut s.items);
    s.selected = s
        .items
        .iter()
        .find(|i| i.kind == kind)
        .map(|i| i.id.clone());
    detail_for_selection(s);
}

pub(super) fn typed(s: &mut App, name: &str, value: &str) {
    if let Some(input) = s
        .edit
        .form
        .as_mut()
        .and_then(|f| f.fields.iter_mut().find(|i| i.name == name))
    {
        input.edit.replace_text(value);
    }
}

pub(super) fn generated(s: &mut App) {
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

pub(super) fn detail_for_selection(s: &mut App) {
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
        "api" => vec![
            field("credential", "secret", "sk_live_51HxY2cQx8"),
            field("username", "text", "deploy-bot"),
            field("type", "text", "bearer"),
            field("url", "url", "https://api.stripe.com"),
            field("environment", "text", "production"),
            field("expires", "date", "2027-06-30"),
        ],
        "database" => vec![
            field("type", "text", "postgres"),
            field("host", "text", "db.anoma.ly"),
            field("port", "text", "5432"),
            field("database", "text", "app"),
            field("username", "text", "app"),
            field("password", "secret", "pg-secret-77"),
            field(
                "connection-string",
                "secret",
                "postgres://app:pg-secret-77@db.anoma.ly:5432/app",
            ),
        ],
        "wifi" => vec![
            field("ssid", "text", "Raad Home 5G"),
            field("password", "secret", "correct-horse"),
            field("security", "text", "WPA3"),
        ],
        // As the agent lists it: the file's name, not its contents.
        "document" => vec![
            field("file", "file", "passport-scan.pdf"),
            field("notes", "note", "Scanned 2026-03-02."),
        ],
        "passport" => vec![
            field("full-name", "text", "Dax Raad"),
            field("number", "secret", "X12345678"),
            field("issuing-country", "text", "United States"),
            field("nationality", "text", "American"),
            field("birthday", "date", "1990-03-01"),
            field("issued", "date", "2021-05-10"),
            field("expires", "date", "2031-05-09"),
        ],
        "identity" => vec![
            field("given-name", "text", "Dax"),
            field("family-name", "text", "Raad"),
            field("email", "email", "dax@anoma.ly"),
            field("phone", "text", "+15550100"),
            field("address-line1", "text", "1 Main St"),
            field("address-line2", "text", "Apt 2"),
            field("city", "text", "Springfield"),
            field("region", "text", "IL"),
            field("postal-code", "text", "12345"),
            field("country", "text", "US"),
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

pub(super) fn vault_with_health(s: &mut App) {
    vault(s);
    let full_id = |short: &str| {
        format!("{short}0000000000000000000000000000000000000000000000000000000000")
    };
    let github = full_id("3f9a1c");
    let linear = full_id("7b20e4");
    let cloudflare = full_id("f5c312");
    let hetzner = full_id("09ad7e");
    let gitlab = full_id("e01b9d");

    let items = vec![
        ItemHealth {
            vault: "v1".into(),
            vault_name: "personal".into(),
            id: github,
            kind: "login".into(),
            label: "github.com".into(),
            detail: Some("dax".into()),
            site_url: Some("https://github.com".into()),
            change_url: Some("https://github.com/settings/security".into()),
            password_changed: Some("2024-03-14".into()),
            risk: Some(RiskLevel::Danger),
            findings: vec![Finding::Breached { count: 14_203 }],
            ignored: Vec::new(),
        },
        ItemHealth {
            vault: "v1".into(),
            vault_name: "personal".into(),
            id: linear.clone(),
            kind: "login".into(),
            label: "Linear".into(),
            detail: Some("dax@anoma.ly".into()),
            site_url: Some("https://linear.app".into()),
            change_url: None,
            password_changed: Some("2025-11-02".into()),
            risk: Some(RiskLevel::Danger),
            findings: vec![
                Finding::Reused {
                    count: 2,
                    others: vec![HealthPeer {
                        vault: "v1".into(),
                        vault_name: "personal".into(),
                        id: cloudflare.clone(),
                        label: "Cloudflare".into(),
                        detail: Some("dax@anoma.ly".into()),
                    }],
                },
                Finding::MissingTwoFactor {
                    doc_url: Some("https://linear.app/docs/account-security".into()),
                },
            ],
            ignored: Vec::new(),
        },
        ItemHealth {
            vault: "v1".into(),
            vault_name: "personal".into(),
            id: cloudflare,
            kind: "login".into(),
            label: "Cloudflare".into(),
            detail: Some("dax@anoma.ly".into()),
            site_url: Some("https://cloudflare.com".into()),
            change_url: Some("https://dash.cloudflare.com/profile/authentication".into()),
            password_changed: None,
            risk: Some(RiskLevel::Danger),
            findings: vec![Finding::Reused {
                count: 2,
                others: vec![HealthPeer {
                    vault: "v1".into(),
                    vault_name: "personal".into(),
                    id: linear,
                    label: "Linear".into(),
                    detail: Some("dax@anoma.ly".into()),
                }],
            }],
            ignored: Vec::new(),
        },
        ItemHealth {
            vault: "v1".into(),
            vault_name: "personal".into(),
            id: hetzner,
            kind: "login".into(),
            label: "Hetzner".into(),
            detail: Some("billing@anoma.ly".into()),
            site_url: Some("https://console.hetzner.cloud".into()),
            change_url: None,
            password_changed: None,
            risk: Some(RiskLevel::Caution),
            findings: vec![Finding::Weak {
                score: 1,
                reason: WeakReason::Common,
            }],
            ignored: Vec::new(),
        },
        ItemHealth {
            vault: "v1".into(),
            vault_name: "personal".into(),
            id: gitlab,
            kind: "login".into(),
            label: "gitlab.com".into(),
            detail: Some("dax".into()),
            site_url: Some("https://gitlab.com".into()),
            change_url: Some("https://gitlab.com/-/profile/password/edit".into()),
            password_changed: None,
            risk: None,
            findings: vec![Finding::PasskeyAvailable {
                passwordless: true,
                mfa: true,
                doc_url: Some("https://docs.gitlab.com".into()),
            }],
            ignored: Vec::new(),
        },
    ];

    s.health.report = Some(HealthReport {
        vault: Some("v1".into()),
        counts: HealthCounts {
            risk_items: 4,
            breached: 1,
            site_breach: 0,
            reused: 2,
            weak: 1,
            missing_two_factor: 1,
            passkeys_available: 1,
            ignored: 0,
        },
        items,
        breach_checks_enabled: true,
        breach_last_checked: Some(2_000_000_000),
    });
}
