use super::*;

fn wiped_on_drop<T: ZeroizeOnDrop>() {}

/// Values are wiped as fields drop.
#[test]
fn field_values_are_wiped() {
    wiped_on_drop::<FieldInput>();
    wiped_on_drop::<FieldInfo>();
    let mut input = FieldInput {
        name: "password".into(),
        kind: None,
        value: "hunter22".into(),
    };
    input.zeroize();
    assert!(input.value.is_empty());
}

#[test]
fn field_debug_redacts_values() {
    let input = FieldInput {
        name: "password".into(),
        kind: None,
        value: "private-marker".into(),
    };
    let info = FieldInfo {
        name: "notes".into(),
        kind: "secret".into(),
        value: "private-marker".into(),
    };
    for debug in [format!("{input:?}"), format!("{info:?}")] {
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains("private-marker"), "{debug}");
    }
}

#[test]
fn mirror_reports_read_as_lines() {
    let item = |action, title: &str, reason: Option<&str>| MirrorItem {
        action,
        title: title.into(),
        reason: reason.map(Into::into),
    };
    let mut report = MirrorReport {
        applied: true,
        unchanged: 40,
        items: vec![
            item(MirrorAction::Add, "Bank", None),
            item(MirrorAction::Update, "GitHub", Some("password")),
            item(MirrorAction::Update, "Wi-Fi", Some("notes")),
            item(MirrorAction::Skip, "Scan", Some("document")),
        ],
        warnings: vec![],
        dropped: vec![Tally {
            count: 2,
            one: "attachment".into(),
            many: "attachments".into(),
        }],
    };
    assert_eq!(report.summary(), "2 updated, 1 added");
    assert_eq!(
        report.lines(),
        [
            "2 updated, 1 added (40 unchanged, 1 skipped)",
            "  add     Bank",
            "  update  GitHub (password)",
            "  update  Wi-Fi (notes)",
            "  skip    Scan (document)",
            "not mirrored: 2 attachments",
        ]
    );
    assert!(report.changed());
    report.applied = false;
    assert_eq!(report.summary(), "2 would update, 1 would add");
    report.items.retain(|i| i.action == MirrorAction::Skip);
    assert!(!report.changed());
    assert_eq!(report.summary(), "Nothing to do");
    report.applied = true;
    assert_eq!(report.summary(), "Up to date");
}

#[test]
fn sign_in_providers_are_ids_or_one_line() {
    for (text, id) in [
        ("google", "google"),
        ("Google", "google"),
        ("Sign in with GitHub", "github"),
        ("twitter", "x"),
        (" Linked In ", "linkedin"),
        ("Acme\tcorp\nSSO ", "Acme corp SSO"),
    ] {
        assert_eq!(sign_in_provider(text).as_deref(), Some(id), "{text:?}");
    }
    assert_eq!(sign_in_provider(" \n"), None);
    assert_eq!(
        sign_in_provider(&"é".repeat(100)).unwrap().chars().count(),
        64
    );
    assert_eq!(
        (sign_in_name("github"), sign_in_name("Acme")),
        ("GitHub", "Acme")
    );
}

#[test]
fn import_reports_read_as_lines() {
    let tally = |count, one: &str, many: &str| Tally {
        count,
        one: one.into(),
        many: many.into(),
    };
    let report = ImportReport {
        source: ImportSource::OnePassword,
        new: [("login".into(), 3), ("card".into(), 1)].into(),
        duplicates: 2,
        skipped: vec![tally(1, "secure note", "secure notes")],
        warnings: vec![tally(2, "URL kept as text", "URLs kept as text")],
        dropped: vec![tally(1, "favorite", "favorites"), tally(3, "tag", "tags")],
        sign_in: SignInCounts {
            providers: [
                ("google".into(), 2),
                ("x".into(), 1),
                ("Acme SSO".into(), 2),
            ]
            .into(),
            linked: 3,
        },
    };
    assert_eq!(
        report.lines(true),
        [
            "imported 4 from 1Password (logins 3, cards 1)",
            "kept 5 sign-in methods (Acme SSO 2, Google 2, X 1)",
            "linked 3 to their accounts",
            "skipped 2 duplicates",
            "skipped 1 secure note",
            "warning: 2 URLs kept as text",
            "dropped: 1 favorite, 3 tags",
        ]
    );
    let kinds = ImportReport {
        source: ImportSource::Bitwarden,
        new: [
            ("identity".into(), 1),
            ("note".into(), 2),
            ("ssh".into(), 1),
            ("future".into(), 1),
        ]
        .into(),
        duplicates: 0,
        skipped: vec![],
        warnings: vec![],
        dropped: vec![],
        sign_in: SignInCounts::default(),
    };
    assert_eq!(
        kinds.lines(true),
        [
            "imported 5 from Bitwarden (logins 0, cards 0, secure notes 2, SSH keys 1, identities 1, future 1)"
        ]
    );
    assert_eq!(
        kinds.counts(),
        [("note", 2), ("ssh", 1), ("identity", 1), ("future", 1)]
    );
    assert_eq!(
        (noun("ssh", 1), noun("identity", 2)),
        ("SSH key", "identities")
    );
    let empty = ImportReport {
        source: ImportSource::ApplePasswords,
        new: BTreeMap::new(),
        duplicates: 1,
        skipped: vec![],
        warnings: vec![],
        dropped: vec![],
        sign_in: SignInCounts::default(),
    };
    assert_eq!(
        empty.lines(false),
        [
            "dry run: would import 0 from Apple Passwords (logins 0, cards 0)",
            "skipped 1 duplicate",
        ]
    );
    let json = serde_json::to_string(&Reply::Import { report: empty }).unwrap();
    assert!(json.contains(r#""source":"apple-passwords""#), "{json}");
}

#[test]
fn app_activate_and_its_replies_are_flat_json_lines() {
    let request = serde_json::to_string(&Request {
        v: PROTOCOL_VERSION,
        claimed: None,
        command: Command::AppActivate {
            token: Some("launcher-token".into()),
        },
    })
    .unwrap();
    assert_eq!(
        request,
        format!(r#"{{"v":{PROTOCOL_VERSION},"cmd":"app-activate","token":"launcher-token"}}"#)
    );
    let replies = [
        (
            Reply::Activated,
            r#"{"type":"ok","reply":{"reply":"activated"}}"#,
        ),
        (Reply::NoApp, r#"{"type":"ok","reply":{"reply":"no-app"}}"#),
    ];
    for (reply, json) in replies {
        let line = serde_json::to_string(&Message::Ok { reply }).unwrap();
        assert_eq!(line, json);
    }
}

#[test]
fn watch_round_trips_as_flat_json_lines() {
    let request = serde_json::to_string(&Request {
        v: PROTOCOL_VERSION,
        claimed: None,
        command: Command::Watch { app: true },
    })
    .unwrap();
    assert_eq!(
        request,
        format!(r#"{{"v":{PROTOCOL_VERSION},"cmd":"watch","app":true}}"#)
    );
    assert!(matches!(
        serde_json::from_str::<Request>(&request).unwrap().command,
        Command::Watch { app: true }
    ));
    let changes = [
        (Change::Watching, r#"{"type":"change","change":"watching"}"#),
        (Change::Locked, r#"{"type":"change","change":"locked"}"#),
        (Change::Unlocked, r#"{"type":"change","change":"unlocked"}"#),
        (Change::Vaults, r#"{"type":"change","change":"vaults"}"#),
        (
            Change::Items { vault: "ab".into() },
            r#"{"type":"change","change":"items","vault":"ab"}"#,
        ),
        (
            Change::Devices { vault: "ab".into() },
            r#"{"type":"change","change":"devices","vault":"ab"}"#,
        ),
        (Change::Activity, r#"{"type":"change","change":"activity"}"#),
        (Change::Resync, r#"{"type":"change","change":"resync"}"#),
        (Change::Stopping, r#"{"type":"change","change":"stopping"}"#),
        (
            Change::Activate {
                token: Some("t".into()),
            },
            r#"{"type":"change","change":"activate","token":"t"}"#,
        ),
        (
            Change::Activate { token: None },
            r#"{"type":"change","change":"activate","token":null}"#,
        ),
    ];
    for (change, json) in changes {
        let line = serde_json::to_string(&Message::Change {
            change: change.clone(),
        })
        .unwrap();
        assert_eq!(line, json);
        match serde_json::from_str::<Message>(&line).unwrap() {
            Message::Change { change: back } => assert_eq!(back, change),
            other => panic!("expected a change, got {other:?}"),
        }
    }
}

/// A claim rides beside the command and is left out when there is none,
/// so a status request reads the same to agents of every protocol.
#[test]
fn a_claim_rides_beside_the_command() {
    let claimed = Request {
        v: PROTOCOL_VERSION,
        claimed: Some(Claim {
            caller: Some("deploy bot".into()),
            opencode_session: None,
        }),
        command: Command::Status,
    };
    let line = serde_json::to_string(&claimed).unwrap();
    assert_eq!(
        line,
        format!(
            r#"{{"v":{PROTOCOL_VERSION},"claimed":{{"caller":"deploy bot","opencode_session":null}},"cmd":"status"}}"#
        )
    );
    let back = serde_json::from_str::<Request>(&line).unwrap();
    assert_eq!(back.claimed, claimed.claimed);
    let old = serde_json::from_str::<Request>(r#"{"v":1,"cmd":"status"}"#).unwrap();
    assert!(old.claimed.is_none() && matches!(old.command, Command::Status));
}

#[test]
fn an_item_set_carries_its_unset_fields() {
    let command = Command::ItemSet {
        vault: None,
        query: vec!["a".into()],
        fields: Vec::new(),
        name: None,
        unset: vec!["notes".into()],
        favorite: None,
        add_tags: Vec::new(),
        remove_tags: Vec::new(),
    };
    let line = serde_json::to_string(&command).unwrap();
    assert!(line.contains(r#""unset":["notes"]"#), "{line}");
    match serde_json::from_str::<Command>(&line).unwrap() {
        Command::ItemSet { unset, .. } => assert_eq!(unset, ["notes"]),
        other => panic!("expected item-set, got {other:?}"),
    }
    // An older client's item-set, without unset, is refused.
    let old = r#"{"cmd":"item-set","vault":null,"query":["a"],"fields":[],"name":"x"}"#;
    assert!(serde_json::from_str::<Command>(old).is_err());
}

#[test]
fn generate_round_trips() {
    let request = serde_json::to_string(&Request {
        v: PROTOCOL_VERSION,
        claimed: None,
        command: Command::Generate {
            length: 20,
            symbols: false,
        },
    })
    .unwrap();
    assert!(
        request.ends_with(r#""cmd":"generate","length":20,"symbols":false}"#),
        "{request}"
    );
    assert!(matches!(
        serde_json::from_str::<Request>(&request).unwrap().command,
        Command::Generate {
            length: 20,
            symbols: false
        }
    ));
    let reply = serde_json::to_string(&Message::Ok {
        reply: Reply::Password {
            password: Zeroizing::new("hunter2hunter2".into()),
        },
    })
    .unwrap();
    assert_eq!(
        reply,
        r#"{"type":"ok","reply":{"reply":"password","password":"hunter2hunter2"}}"#
    );
    match serde_json::from_str::<Message>(&reply).unwrap() {
        Message::Ok {
            reply: Reply::Password { password },
        } => assert_eq!(*password, "hunter2hunter2"),
        other => panic!("expected a password, got {other:?}"),
    }
}
