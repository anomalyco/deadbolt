use std::collections::BTreeMap;

use crate::health::{
    Finding, FindingKind, IGNORE_ALWAYS, PassphraseStrength, RiskLevel, SiteBreach, WeakReason,
    build_memo, change_password_url, check_weak, directory, evaluate, hibp_key_of, hibp_parts,
    item_fingerprint, passphrase_strength,
};
use crate::{DataOp, DeviceSecret, Field, FieldType, Item, Vault};

const REUSE_KEY: [u8; 32] = [0x11; 32];
const HIBP_KEY: [u8; 32] = [0x22; 32];

fn memos_for(vault: &Vault) -> Vec<crate::health::ItemMemo> {
    let vid = vault.id().to_string();
    let vname = vault.name();
    vault
        .items()
        .iter()
        .map(|item| build_memo(&REUSE_KEY, &HIBP_KEY, &vid, vname, item, None))
        .collect()
}

#[test]
fn non_password_secrets_and_pins_never_trigger_password_health() {
    let secret = DeviceSecret::from_bytes(&[1; 32]);
    let (mut vault, _) = Vault::create(&secret, "personal").unwrap();
    let ops = vec![
        DataOp::create(
            "card",
            Some("Visa".into()),
            [
                (
                    "number".into(),
                    Field::new(FieldType::Secret, "4242424242424242"),
                ),
                ("pin".into(), Field::new(FieldType::Secret, "1234")),
                ("cvv".into(), Field::new(FieldType::Secret, "123")),
            ],
        ),
        DataOp::create(
            "bank",
            Some("Checking".into()),
            [
                (
                    "account-number".into(),
                    Field::new(FieldType::Secret, "00012345"),
                ),
                ("pin".into(), Field::new(FieldType::Secret, "0000")),
            ],
        ),
        DataOp::create(
            "membership",
            Some("Library".into()),
            [
                ("member-id".into(), Field::new(FieldType::Secret, "12345")),
                ("pin".into(), Field::new(FieldType::Secret, "1234")),
            ],
        ),
        DataOp::create(
            "api",
            Some("Short token".into()),
            [("credential".into(), Field::new(FieldType::Secret, "1234"))],
        ),
        DataOp::create(
            "note",
            Some("Door code".into()),
            [("notes".into(), Field::new(FieldType::Secret, "1234"))],
        ),
        DataOp::create(
            "crypto",
            Some("Wallet".into()),
            [(
                "recovery-phrase".into(),
                Field::new(FieldType::Secret, "password"),
            )],
        ),
        // Extra secret field `pin` on a login whose real password is strong.
        DataOp::create(
            "login",
            Some("Brokerage".into()),
            [
                (
                    "password".into(),
                    Field::new(FieldType::Secret, "Vq7#mRz2!pKx9@wLt4&nBe8"),
                ),
                ("pin".into(), Field::new(FieldType::Secret, "1234")),
            ],
        ),
    ];
    vault.create_items(&secret, ops).unwrap();

    let memos = memos_for(&vault);
    let mut breached = BTreeMap::new();
    breached.insert(hibp_key_of(&HIBP_KEY, "1234"), 9_000_000);
    let (counts, items) = evaluate(&memos, None, &breached, None);
    assert_eq!(counts.risk_items, 0, "{items:?}");
    assert!(items.is_empty(), "{items:?}");
}

#[test]
fn zxcvbn_catches_common_context_and_pattern_passwords_and_passes_generated() {
    assert_eq!(
        check_weak("pw123", &[]).map(|w| w.reason),
        Some(WeakReason::TooShort)
    );
    assert_eq!(
        check_weak("P@ssw0rd", &[]).map(|w| w.reason),
        Some(WeakReason::Common)
    );
    assert_eq!(
        check_weak("qwertyuiop", &[]).map(|w| w.reason),
        Some(WeakReason::Common)
    );
    assert_eq!(
        check_weak("alexgithub24", &["alex", "github"]).map(|w| w.reason),
        Some(WeakReason::Context)
    );

    for _ in 0..20 {
        let generated = crate::password::generate(24, true).unwrap();
        assert_eq!(check_weak(&generated, &["github", "alex"]), None);
    }

    assert_eq!(passphrase_strength("short"), PassphraseStrength::TooShort);
    assert_eq!(passphrase_strength("hunter22"), PassphraseStrength::Weak);
    assert_eq!(
        passphrase_strength("aaaaaaaaaaaaaaaaaaaaaaaa"),
        PassphraseStrength::Weak
    );
    assert_eq!(
        passphrase_strength("velvet-orbit-lantern-spruce"),
        PassphraseStrength::Strong
    );
}

#[test]
fn reuse_collapses_same_account_and_shared_domains_but_flags_distinct_accounts() {
    let secret = DeviceSecret::from_bytes(&[2; 32]);
    let (mut personal, _) = Vault::create(&secret, "personal").unwrap();
    let (mut work, _) = Vault::create(&secret, "work").unwrap();
    let shared_pw = "Vq7#mRz2!pKx9@wLt4&nBe8";
    let dup_pw = "Kp9$xLm4@qRt7!wNz2&vBc6";

    personal
        .create_items(
            &secret,
            [
                // Same account across github.com and gist.github.com -> NOT reused.
                DataOp::create(
                    "login",
                    Some("GitHub".into()),
                    [
                        (
                            "url".into(),
                            Field::new(FieldType::Url, "https://github.com"),
                        ),
                        ("username".into(), Field::new(FieldType::Text, "alex")),
                        ("password".into(), Field::new(FieldType::Secret, dup_pw)),
                    ],
                ),
                DataOp::create(
                    "login",
                    Some("GitHub Gist".into()),
                    [
                        (
                            "url".into(),
                            Field::new(FieldType::Url, "https://gist.github.com"),
                        ),
                        ("username".into(), Field::new(FieldType::Text, "Alex")),
                        ("password".into(), Field::new(FieldType::Secret, dup_pw)),
                    ],
                ),
                // Same account across shared-credentials group (envato.com + themeforest.net) -> NOT reused.
                DataOp::create(
                    "login",
                    Some("Envato".into()),
                    [
                        (
                            "url".into(),
                            Field::new(FieldType::Url, "https://envato.com"),
                        ),
                        ("username".into(), Field::new(FieldType::Text, "alex")),
                        (
                            "password".into(),
                            Field::new(FieldType::Secret, "Zn4!mQp8#rTv2@xLw9&kBc5"),
                        ),
                    ],
                ),
                DataOp::create(
                    "login",
                    Some("ThemeForest".into()),
                    [
                        (
                            "url".into(),
                            Field::new(FieldType::Url, "https://themeforest.net"),
                        ),
                        ("username".into(), Field::new(FieldType::Text, "alex")),
                        (
                            "password".into(),
                            Field::new(FieldType::Secret, "Zn4!mQp8#rTv2@xLw9&kBc5"),
                        ),
                    ],
                ),
                // Reused across personal login and work database -> FLAGGED.
                DataOp::create(
                    "login",
                    Some("Linear".into()),
                    [
                        (
                            "url".into(),
                            Field::new(FieldType::Url, "https://linear.app"),
                        ),
                        ("username".into(), Field::new(FieldType::Text, "alex")),
                        ("password".into(), Field::new(FieldType::Secret, shared_pw)),
                    ],
                ),
                // Two Wi-Fi bands sharing a router password -> NOT reused.
                DataOp::create(
                    "wifi",
                    Some("Home 2.4G".into()),
                    [
                        ("ssid".into(), Field::new(FieldType::Text, "Home-24")),
                        (
                            "password".into(),
                            Field::new(FieldType::Secret, "Rt8#vBn3!pQm9@xLz5&wKc2"),
                        ),
                    ],
                ),
                DataOp::create(
                    "wifi",
                    Some("Home 5G".into()),
                    [
                        ("ssid".into(), Field::new(FieldType::Text, "Home-5")),
                        (
                            "password".into(),
                            Field::new(FieldType::Secret, "Rt8#vBn3!pQm9@xLz5&wKc2"),
                        ),
                    ],
                ),
            ],
        )
        .unwrap();

    work.create_item(
        &secret,
        "database",
        Some("Staging DB".into()),
        [("password".into(), Field::new(FieldType::Secret, shared_pw))],
    )
    .unwrap();

    let mut memos = memos_for(&personal);
    memos.extend(memos_for(&work));

    let (counts, items) = evaluate(
        &memos,
        Some(&personal.id().to_string()),
        &BTreeMap::new(),
        None,
    );
    assert_eq!(counts.reused, 1, "{items:?}");
    let linear = items.iter().find(|i| i.label == "Linear").unwrap();
    assert_eq!(linear.risk, Some(RiskLevel::Danger));
    assert!(linear.findings.iter().any(|f| matches!(
        f,
        Finding::Reused { count: 2, others } if others.len() == 1 && others[0].label == "Staging DB"
    )));
}

#[test]
fn directory_rollups_match_google_and_apple_and_passkeys_satisfy_2fa() {
    assert!(directory::tfa_for_url("https://accounts.google.com").is_some());
    // Apple ID uses device/SMS prompts and passkeys rather than RFC-6238 TOTP,
    // so it is in `passkeys` (rolled up from `appleid.apple.com`) and not `2fa`.
    assert!(directory::tfa_for_url("https://apple.com").is_none());
    assert!(directory::passkey_for_url("https://apple.com").is_some());
    assert!(directory::tfa_for_url("https://github.com/login").is_some());
    assert!(directory::passkey_for_url("https://github.com").is_some());
    assert!(change_password_url("https://adobe.com").is_some());

    let secret = DeviceSecret::from_bytes(&[3; 32]);
    let (mut vault, _) = Vault::create(&secret, "personal").unwrap();
    let (gh_id, _) = vault
        .create_item(
            &secret,
            "login",
            Some("GitHub".into()),
            [
                (
                    "url".into(),
                    Field::new(FieldType::Url, "https://github.com"),
                ),
                ("username".into(), Field::new(FieldType::Text, "alex")),
                (
                    "password".into(),
                    Field::new(FieldType::Secret, "Vq7#mRz2!pKx9@wLt4&nBe8"),
                ),
            ],
        )
        .unwrap();
    // SSO login (`sign-in-with`) should never nag about missing 2FA or password.
    vault
        .create_item(
            &secret,
            "login",
            Some("Notion".into()),
            [
                (
                    "url".into(),
                    Field::new(FieldType::Url, "https://notion.so"),
                ),
                ("sign-in-with".into(), Field::new(FieldType::Text, "google")),
            ],
        )
        .unwrap();

    let memos = memos_for(&vault);
    let (counts, items) = evaluate(&memos, None, &BTreeMap::new(), None);
    assert_eq!(counts.risk_items, 0);
    assert_eq!(counts.missing_two_factor, 1);
    assert_eq!(counts.passkeys_available, 1);
    assert!(!items.iter().any(|i| i.label == "Notion"));

    // Adding a passkey for github.com + alex clears both MissingTwoFactor and PasskeyAvailable.
    vault
        .create_item(
            &secret,
            "passkey",
            None,
            [
                ("rp-id".into(), Field::new(FieldType::Text, "github.com")),
                ("username".into(), Field::new(FieldType::Text, "alex")),
                ("credential-id".into(), Field::new(FieldType::Text, "cred1")),
                ("user-handle".into(), Field::new(FieldType::Text, "user1")),
                ("private-key".into(), Field::new(FieldType::Secret, "pk1")),
            ],
        )
        .unwrap();
    let _ = gh_id;
    let memos = memos_for(&vault);
    let (counts, _) = evaluate(&memos, None, &BTreeMap::new(), None);
    assert_eq!(counts.missing_two_factor, 0);
    assert_eq!(counts.passkeys_available, 0);
}

#[test]
fn breach_dates_and_synced_ignores_lapse_automatically_when_password_changes() {
    let secret = DeviceSecret::from_bytes(&[4; 32]);
    let (mut vault, _) = Vault::create(&secret, "personal").unwrap();
    let (id, _) = vault
        .create_item(
            &secret,
            "login",
            Some("Example".into()),
            [
                (
                    "url".into(),
                    Field::new(FieldType::Url, "https://breached.example.com"),
                ),
                ("password".into(), Field::new(FieldType::Secret, "hunter22")),
            ],
        )
        .unwrap();
    vault
        .write(
            &secret,
            vec![DataOp::password_changed(id, Some("2020-01-01".into()))],
        )
        .unwrap();

    let mut extra_breaches = BTreeMap::new();
    extra_breaches.insert(
        "breached.example.com".into(),
        SiteBreach {
            domain: "breached.example.com".into(),
            title: "Example Corp".into(),
            date: "2020-05-15".into(),
            added: "2020-06-01".into(),
        },
    );

    let item: Item = vault.item(&id).unwrap();
    let pw_entry = item.password_entry.unwrap();

    let memos = memos_for(&vault);
    let (counts, _) = evaluate(&memos, None, &BTreeMap::new(), Some(&extra_breaches));
    assert_eq!(
        (counts.site_breach, counts.weak, counts.risk_items),
        (1, 1, 1)
    );

    // Ignore Weak bound to current password_entry, and MissingTwoFactor item-wide.
    vault
        .write(
            &secret,
            vec![
                DataOp::ignore(id, FindingKind::Weak.as_str(), Some(pw_entry)),
                DataOp::ignore(id, FindingKind::SiteBreach.as_str(), Some(pw_entry)),
                DataOp::ignore(
                    id,
                    FindingKind::MissingTwoFactor.as_str(),
                    Some(IGNORE_ALWAYS),
                ),
            ],
        )
        .unwrap();

    let memos = memos_for(&vault);
    let (counts, items) = evaluate(&memos, None, &BTreeMap::new(), Some(&extra_breaches));
    assert_eq!(
        (
            counts.weak,
            counts.site_breach,
            counts.risk_items,
            counts.ignored
        ),
        (0, 0, 0, 2)
    );
    assert_eq!(items[0].ignored.len(), 2);

    // Changing the password to another weak password gives a new entry hash ->
    // the Weak ignore lapses automatically, while stamping a post-breach date
    // clears SiteBreach.
    vault
        .write(
            &secret,
            vec![
                DataOp::set(id, "password", Field::new(FieldType::Secret, "monkey123")),
                DataOp::password_changed(id, Some("2026-10-30".into())),
            ],
        )
        .unwrap();

    let memos = memos_for(&vault);
    let (counts, _) = evaluate(&memos, None, &BTreeMap::new(), Some(&extra_breaches));
    assert_eq!(
        (
            counts.weak,
            counts.site_breach,
            counts.risk_items,
            counts.ignored
        ),
        (1, 0, 1, 0)
    );
}

#[test]
fn hibp_parts_match_sha1_test_vector_and_incremental_fingerprints_hold() {
    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    let (prefix, suffix, key) = hibp_parts(&HIBP_KEY, "password");
    assert_eq!(&prefix, b"5BAA6");
    assert_eq!(&*suffix, b"1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    assert_eq!(key, hibp_key_of(&HIBP_KEY, "password"));

    let secret = DeviceSecret::from_bytes(&[5; 32]);
    let (mut vault, _) = Vault::create(&secret, "personal").unwrap();
    let ops: Vec<DataOp> = (0..500)
        .map(|i| {
            DataOp::create(
                "login",
                Some(format!("Site {i}")),
                [
                    (
                        "url".into(),
                        Field::new(FieldType::Url, format!("https://site-{i}.example.com")),
                    ),
                    (
                        "password".into(),
                        Field::new(FieldType::Secret, format!("Vq7#mRz2!pKx9@wLt4&{i:04}")),
                    ),
                ],
            )
        })
        .collect();
    let (ids, _) = vault.create_items(&secret, ops).unwrap();
    let before: BTreeMap<_, _> = vault
        .items()
        .into_iter()
        .map(|it| (it.id, item_fingerprint(&REUSE_KEY, "personal", &it)))
        .collect();

    vault
        .write(
            &secret,
            vec![DataOp::set(
                ids[0],
                "password",
                Field::new(FieldType::Secret, "Changed-Strong-99!#xK2m"),
            )],
        )
        .unwrap();

    let changed = vault
        .items()
        .into_iter()
        .filter(|it| before.get(&it.id) != Some(&item_fingerprint(&REUSE_KEY, "personal", it)))
        .count();
    assert_eq!(changed, 1, "only the 1 edited item changes fingerprint");
}
