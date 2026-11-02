use super::*;
use deadbolt_core::listing::normalize;

fn loaded(dir: &std::path::Path) -> Loaded {
    let params = deadbolt_store::KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    let mut loaded = Loaded::setup(dir, b"test", "test", params).unwrap();
    loaded.create_vault("personal").unwrap();
    loaded
}

fn import(s: &mut Loaded, export: &str, apply: bool) -> ImportReport {
    super::import(s, None, crate::import::parse(export).unwrap(), apply).unwrap()
}

fn count(s: &Loaded) -> usize {
    let vault = s.resolve(None).unwrap();
    s.vault(&vault).items().len()
}

fn input(name: &str, value: &str) -> FieldInput {
    FieldInput {
        name: name.into(),
        kind: None,
        value: value.into(),
    }
}

fn otp_input(name: &str, value: &str) -> FieldInput {
    FieldInput {
        name: name.into(),
        kind: Some("otp".into()),
        value: value.into(),
    }
}

fn at(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

fn words(query: &str) -> Vec<String> {
    query.split(' ').map(String::from).collect()
}

#[test]
fn codes_come_from_the_otp_field() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    // RFC 6238's SHA-1 secret, "12345678901234567890".
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let otp = format!("otpauth://totp/Site:dax?secret={secret}&digits=8&issuer=Site");
    let fields = vec![input("password", "pw"), input("otp", &otp)];
    create(&mut s, None, "login", Some("Site".into()), fields).unwrap();
    let code = code(&s, None, &words("site"), Duration::from_millis(59_250)).unwrap();
    assert_eq!(code.code.as_str(), "94287082");
    assert_eq!(
        (code.period, code.valid_until, code.remaining_ms),
        (30, 60, 750)
    );

    let fields = vec![input("password", "pw"), input("backup", "x")];
    create(&mut s, None, "login", Some("Plain".into()), fields).unwrap();
    let error = super::code(&s, None, &words("plain"), at(59)).unwrap_err();
    assert_eq!(error.to_string(), "Plain has no one-time password");
    let fields = vec![otp_input("backup", &secret.to_lowercase())];
    set(&mut s, None, &words("plain"), fields, None, &[]).unwrap();
    let code = super::code(&s, None, &words("plain"), at(59)).unwrap();
    assert_eq!(code.code.as_str(), "287082");
}

/// Under a millisecond before the boundary still reads as time left.
#[test]
fn a_code_always_has_time_left() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let fields = vec![input("password", "pw"), input("otp", "JBSWY3DPEHPK3PXP")];
    create(&mut s, None, "login", Some("Site".into()), fields).unwrap();
    let code = code(&s, None, &words("site"), Duration::from_micros(59_999_700)).unwrap();
    assert_eq!((code.valid_until, code.remaining_ms), (60, 1));
}

/// Every field of type otp comes back empty unless asked for.
#[test]
fn items_leave_otp_secrets_unless_asked() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let extra = otp_input("backup", "KRSXG5CTMVRXEZLU");
    let fields = vec![
        input("password", "pw"),
        input("otp", "JBSWY3DPEHPK3PXP"),
        extra,
    ];
    create(&mut s, None, "login", Some("Site".into()), fields).unwrap();
    let values = |otp| {
        let item = get(&s, None, &words("site"), otp, false, &[], false).unwrap();
        item.fields
            .into_iter()
            .map(|f| (f.name.clone(), f.value.clone()))
            .collect::<Vec<_>>()
    };
    let pair = |a: &str, b: &str| (a.to_owned(), b.to_owned());
    assert_eq!(
        values(false),
        [pair("password", "pw"), pair("otp", ""), pair("backup", "")]
    );
    assert_eq!(
        values(true),
        [
            pair("password", "pw"),
            pair("otp", "JBSWY3DPEHPK3PXP"),
            pair("backup", "KRSXG5CTMVRXEZLU")
        ]
    );
}

/// Asking for one file sends that file alone: an item with five files
/// near the item's cap between them still reads one at a time.
#[test]
fn a_get_carries_only_the_files_it_names() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let each = deadbolt_core::item::MAX_FILE / 5 - 1024;
    let fields: Vec<FieldInput> = (0..5u8)
        .map(|i| FieldInput {
            name: format!("part-{i}"),
            kind: Some("file".into()),
            value: deadbolt_core::item::file_value(&format!("{i}.bin"), &vec![i; each]).to_string(),
        })
        .collect();
    create(&mut s, None, "note", Some("Parts".into()), fields).unwrap();
    // A sixth would take the item past the cap.
    let sixth = FieldInput {
        name: "part-5".into(),
        kind: Some("file".into()),
        value: deadbolt_core::item::file_value("5.bin", &vec![5; each]).to_string(),
    };
    let error = set(&mut s, None, &words("parts"), vec![sixth], None, &[]).unwrap_err();
    assert!(
        error.to_string().contains("at most 10 MiB together"),
        "{error}"
    );

    let item = get(
        &s,
        None,
        &words("parts"),
        false,
        false,
        &["part-3".to_string()],
        false,
    )
    .unwrap();
    for field in &item.fields {
        let (name, contents) = deadbolt_core::item::file_parts(&field.value);
        if field.name == "part-3" {
            let decoded = data_encoding::BASE64.decode(contents.unwrap().as_bytes());
            assert_eq!(decoded.unwrap(), vec![3; each]);
        } else {
            assert_eq!(contents, None, "{}", field.name);
            assert!(name.ends_with(".bin"));
        }
    }
    let reply = serde_json::to_string(&item).unwrap();
    assert!(
        reply.len() < each * 4 / 3 + 4096,
        "one file's worth: {}",
        reply.len()
    );
    let none = get(&s, None, &words("parts"), false, false, &[], false).unwrap();
    assert!(none.fields.iter().all(|f| !f.value.contains('\n')));
}

#[test]
fn otp_values_must_be_totp_secrets_when_written() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let hotp = "otpauth://hotp/Site?secret=JBSWY3DPEHPK3PXP&counter=1";
    let fields = vec![input("password", "pw"), input("otp", hotp)];
    let error = create(&mut s, None, "login", Some("Site".into()), fields).unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid value for otp: counter-based (HOTP) codes are not supported"
    );
    let fields = vec![input("password", "pw")];
    create(&mut s, None, "login", Some("Site".into()), fields).unwrap();
    let error = set(
        &mut s,
        None,
        &words("site"),
        vec![input("otp", "123456")],
        None,
        &[],
    );
    assert_eq!(
        error.unwrap_err().to_string(),
        "invalid value for otp: the secret is not base32"
    );
    assert_eq!(count(&s), 1);

    // A value written before the check is still in the vault, and says why it has no code.
    let vault = s.resolve(None).unwrap();
    s.update(vault, |v, secret| {
        let fields = vec![
            ("password".to_string(), Field::new(FieldType::Secret, "pw")),
            ("otp".to_string(), Field::new(FieldType::Otp, hotp)),
        ];
        Ok(v.create_item(secret, "login", Some("Old".into()), fields)?)
    })
    .unwrap();
    let error = code(&s, None, &words("old"), at(59)).unwrap_err();
    assert_eq!(
        error.to_string(),
        "the one-time password of Old is invalid: counter-based (HOTP) codes are not supported"
    );
}

#[test]
fn imports_skip_duplicates_and_a_dry_run_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let export = "name,url,username,password\n\
        GitHub,https://github.com/login,dax,pw-1\n\
        GitHub again,https://www.GitHub.com/,dax,pw-1\n\
        Other user,https://github.com,kit,pw-1\n\
        New password,https://github.com,dax,pw-2\n\
        No url,,dax,pw-1\n\
        No url again,not a url,dax,pw-1\n\
        Prod DB,,postgres,pg-pw\n\
        Staging DB,,postgres,pg-pw\n\
        Prod DB,,postgres,pg-pw\n\
        ,,postgres,pg-pw\n\
        ,,postgres,pg-pw\n";
    let report = import(&mut s, export, false);
    assert_eq!((report.count("login"), report.duplicates), (8, 3));
    assert_eq!(count(&s), 0);
    let report = import(&mut s, export, true);
    assert_eq!((report.count("login"), report.duplicates), (8, 3));
    assert_eq!(count(&s), 8);
    let again = import(&mut s, export, true);
    assert_eq!((again.count("login"), again.duplicates), (0, 11));
    assert_eq!(
        again.lines(true)[..2],
        [
            "imported 0 from CSV (logins 0, cards 0)",
            "skipped 11 duplicates",
        ]
    );
    assert_eq!(count(&s), 8);
}

/// A 1PUX with "Sign in with" logins: one linked to an account later
/// in the export, one without a link, one linked to an item not in it.
fn sign_in_export(with_account: bool, with_rest: bool) -> String {
    let sso = |uuid: &str, title: &str, url: &str, value: &str| {
        format!(
            r#"{{"uuid": "{uuid}", "state": "active", "categoryUuid": "001", "updatedAt": 1,
              "details": {{"sections": [{{"title": "", "fields": [
                {{"title": "", "id": "sso", "value": {{"ssoLogin": {value}}}}}]}}]}},
              "overview": {{"title": "{title}", "url": "{url}"}}}}"#
        )
    };
    let mut items = Vec::new();
    if with_rest {
        items.push(sso(
            "notion",
            "Notion",
            "https://www.notion.so",
            r#"{"provider": "google", "item": {"itemUuid": "gacct", "vaultUuid": "v1"}}"#,
        ));
        items.push(sso(
            "figma",
            "Figma",
            "https://figma.com",
            r#"{"provider": "twitter"}"#,
        ));
        items.push(sso(
            "linear",
            "Linear",
            "https://linear.app",
            r#"{"provider": "github", "item": {"itemUuid": "gone", "vaultUuid": "v1"}}"#,
        ));
    }
    if with_account {
        items.push(
            r#"{"uuid": "gacct", "state": "active", "categoryUuid": "001", "updatedAt": 1,
              "details": {"loginFields": [
                {"value": "dax@gmail.com", "designation": "username"},
                {"value": "google-pw", "fieldType": "P", "designation": "password"}]},
              "overview": {"title": "Google", "url": "https://accounts.google.com"}}"#
                .to_string(),
        );
    }
    format!(
        r#"{{"accounts": [{{"attrs": {{"uuid": "USER"}}, "vaults": [{{"attrs": {{"uuid": "v1"}}, "items": [{}]}}]}}]}}"#,
        items.join(",")
    )
}

#[test]
fn sign_in_methods_are_kept_and_linked_to_their_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let export = sign_in_export(true, true);
    let report = import(&mut s, &export, false);
    let lines = [
        "kept 3 sign-in methods (GitHub 1, Google 1, X 1)",
        "linked 1 to their accounts",
        "warning: 1 sign-in method links to an account not in this export (kept without the link)",
    ];
    assert_eq!(report.lines(false)[1..], lines);
    assert_eq!(count(&s), 0);
    let report = import(&mut s, &export, true);
    assert_eq!(report.lines(true)[1..], lines);
    let vault = s.resolve(None).unwrap();
    let named = |s: &Loaded, name: &str| {
        s.vault(&vault)
            .items()
            .into_iter()
            .find(|i| i.name.as_deref() == Some(name))
            .unwrap()
    };
    let google = named(&s, "Google");
    let notion = named(&s, "Notion");
    let value = |item: &Item, field: &str| item.fields.get(field).map(|f| f.value.clone());
    assert_eq!(value(&notion, "sign-in-with").as_deref(), Some("google"));
    assert_eq!(
        value(&notion, "sign-in-account"),
        Some(hex(google.id.as_bytes()))
    );
    assert_eq!(value(&notion, "password"), None);
    // Its source still records the digest of the item as it is.
    let version = MirrorVersion::parse(&notion.source.as_ref().unwrap().version).unwrap();
    assert_eq!(
        version.digest,
        digest(
            &notion.kind,
            notion.name.as_deref(),
            &notion.fields,
            notion.favorite,
            &notion.tags,
        )
    );
    let figma = named(&s, "Figma");
    assert_eq!(value(&figma, "sign-in-with").as_deref(), Some("x"));
    assert_eq!(value(&named(&s, "Linear"), "sign-in-account"), None);
    let listed = list(&s, None, &words("notion"), None, false).unwrap();
    assert_eq!(listed[0].detail.as_deref(), Some("Sign in with Google"));
    // The link is not content: importing again adds nothing.
    let again = import(&mut s, &export, true);
    assert_eq!((again.total(), again.duplicates), (0, 4));
    assert_eq!(again.lines(true)[1..], ["skipped 4 duplicates"]);
    assert_eq!(count(&s), 4);
}

/// An account imported before, and so a duplicate now, is linked to.
#[test]
fn sign_in_methods_link_to_an_account_already_here() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    import(&mut s, &sign_in_export(true, false), true);
    let report = import(&mut s, &sign_in_export(true, true), true);
    assert_eq!((report.total(), report.duplicates), (3, 1));
    assert_eq!(report.sign_in.linked, 1);
    let vault = s.resolve(None).unwrap();
    let items = s.vault(&vault).items();
    let google = items
        .iter()
        .find(|i| i.name.as_deref() == Some("Google"))
        .unwrap();
    let notion = items
        .iter()
        .find(|i| i.name.as_deref() == Some("Notion"))
        .unwrap();
    assert_eq!(
        notion.fields["sign-in-account"].value,
        hex(google.id.as_bytes())
    );
}

/// The app saves an edit as one change: fields set, emptied ones
/// removed and the name, in one entry.
#[test]
fn a_set_removes_its_unset_fields_in_the_same_entry() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let input = |name: &str, value: &str| FieldInput {
        name: name.into(),
        kind: None,
        value: value.into(),
    };
    let fields = vec![input("password", "pw-1"), input("notes", "old")];
    let id = create(&mut s, None, "login", None, fields).unwrap().id;
    let vault = s.resolve(None).unwrap();
    let before = s.vault(&vault).entries().len();
    let query = [id];
    let unset = ["notes".to_string()];
    let fields = vec![input("password", "pw-2")];
    let name = Some("GitHub".into());
    let item = set(&mut s, None, &query, fields, name, &unset).unwrap();
    assert_eq!(s.vault(&vault).entries().len(), before + 1);
    assert_eq!(item.label, "GitHub");
    let item = get(&s, None, &query, false, false, &[], false).unwrap();
    let fields: Vec<(&str, &str)> = item
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f.value.as_str()))
        .collect();
    assert_eq!(fields, [("password", "pw-2")]);

    let card = vec![input("number", "4242424242424242")];
    let card = [create(&mut s, None, "card", None, card).unwrap().id];
    let required = ["number".to_string()];
    let error = set(&mut s, None, &card, vec![], None, &required).unwrap_err();
    assert!(error.to_string().contains("required"), "{error}");
    let twice = set(
        &mut s,
        None,
        &query,
        vec![input("url", "a.com")],
        None,
        &["url".into()],
    );
    assert!(twice.unwrap_err().to_string().contains("twice"));
    // The card's creation, and nothing refused.
    assert_eq!(s.vault(&vault).entries().len(), before + 2);
}

/// An edit that empties a field another device already removed still
/// saves, and only its other changes are written. A name the item could
/// never have, or a required field, is still refused.
#[test]
fn a_set_skips_unset_fields_already_gone() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let input = |name: &str, value: &str| FieldInput {
        name: name.into(),
        kind: None,
        value: value.into(),
    };
    let fields = vec![input("password", "pw-1"), input("url", "a.com")];
    let id = create(&mut s, None, "login", None, fields).unwrap().id;
    let vault = s.resolve(None).unwrap();
    let before = s.vault(&vault).entries().len();
    let query = [id];
    let gone = ["notes".to_string(), "pin-hint".to_string()];
    set(&mut s, None, &query, vec![], None, &gone).unwrap();
    assert_eq!(s.vault(&vault).entries().len(), before, "nothing to write");
    let unset = ["notes".to_string(), "url".to_string()];
    let item = set(
        &mut s,
        None,
        &query,
        vec![input("password", "pw-2")],
        None,
        &unset,
    );
    assert!(item.is_ok(), "{item:?}");
    assert_eq!(s.vault(&vault).entries().len(), before + 1);
    let item = get(&s, None, &query, false, false, &[], false).unwrap();
    let names: Vec<&str> = item.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["password"]);

    let bad = set(&mut s, None, &query, vec![], None, &["Not A Name".into()]);
    assert!(bad.unwrap_err().to_string().contains("invalid field name"));
    let card = vec![input("number", "4242424242424242")];
    let card = create(&mut s, None, "card", None, card).unwrap().id;
    let error = set(&mut s, None, &[card], vec![], None, &["expiry".into()]);
    assert!(error.is_ok(), "an optional field: {error:?}");
    assert_eq!(s.vault(&vault).entries().len(), before + 2);
}

#[test]
fn favorites_sort_first_and_nested_tags_filter_and_disambiguate() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    create_with(
        &mut s,
        None,
        "login",
        Some("Alpha".into()),
        vec![input("password", "pw-a"), input("username", "personal")],
        false,
        vec!["personal".into()],
    )
    .unwrap();
    create_with(
        &mut s,
        None,
        "login",
        Some("Zeta".into()),
        vec![input("password", "pw-z"), input("username", "ops")],
        true,
        vec!["Work/AWS".into()],
    )
    .unwrap();

    // Favorites come first in `list`.
    let all = list(&s, None, &[], None, false).unwrap();
    let labels: Vec<&str> = all.iter().map(|i| i.label.as_str()).collect();
    assert_eq!(labels, ["Zeta", "Alpha"]);
    assert!(all[0].favorite && !all[1].favorite);
    assert_eq!(all[0].tags, ["Work/AWS"]);

    // Parent tag `work` matches `Work/AWS`, both via `--tag` and `#work`.
    let by_flag = list_filtered(&s, None, &[], None, false, &["work".into()], false).unwrap();
    assert_eq!(by_flag.len(), 1);
    assert_eq!(by_flag[0].label, "Zeta");
    let by_hash = list(&s, None, &["#work/aws".into()], None, false).unwrap();
    assert_eq!(by_hash.len(), 1);
    assert_eq!(by_hash[0].label, "Zeta");

    // `tags()` lists both parent prefixes and leaves with counts.
    let counts: Vec<(String, usize)> = tags(&s, None)
        .unwrap()
        .into_iter()
        .map(|t| (t.tag, t.count))
        .collect();
    assert_eq!(
        counts,
        [
            ("personal".into(), 1),
            ("Work".into(), 1),
            ("Work/AWS".into(), 1),
        ]
    );

    // `set_with` unstars, adds a tag, and removes `work/aws` case-insensitively in one entry.
    let updated = set_with(
        &mut s,
        None,
        &["#work".into()],
        vec![],
        None,
        &[],
        Some(false),
        &["prod".into()],
        &["work/aws".into()],
    )
    .unwrap();
    assert!(!updated.favorite);
    assert_eq!(updated.tags, ["prod"]);
}

#[test]
fn deleted_items_list_apart_and_restore() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    for name in ["Alpha", "Beta", "Gamma"] {
        let fields = vec![input("password", &format!("{name}-pw"))];
        create(&mut s, None, "login", Some(name.into()), fields).unwrap();
    }
    remove(&mut s, None, &words("alpha")).unwrap();
    remove(&mut s, None, &words("beta")).unwrap();
    let labels = |s: &Loaded, deleted| {
        list(s, None, &[], None, deleted)
            .unwrap()
            .into_iter()
            .map(|i| (i.label, i.deleted_at.is_some()))
            .collect::<Vec<_>>()
    };
    assert_eq!(labels(&s, false), [("Gamma".into(), false)]);
    let mut gone = labels(&s, true);
    gone.sort();
    assert_eq!(gone, [("Alpha".into(), true), ("Beta".into(), true)]);
    assert!(get(&s, None, &words("alpha"), false, false, &[], false).is_err());
    let alpha = get(&s, None, &words("alpha"), false, false, &[], true).unwrap();
    assert_eq!(alpha.fields[0].value, "Alpha-pw");
    assert!(restore(&mut s, None, &words("gamma")).is_err());

    let back = restore(&mut s, None, &words("alpha")).unwrap();
    assert_eq!((back.label.as_str(), back.deleted_at), ("Alpha", None));
    let alpha = get(&s, None, &words("alpha"), false, false, &[], false).unwrap();
    assert_eq!(alpha.fields[0].value, "Alpha-pw");
    assert_eq!(labels(&s, true), [("Beta".into(), true)]);
}

#[test]
fn cards_are_the_same_by_number() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let vault = s.resolve(None).unwrap();
    let fields = vec![(
        "number".to_string(),
        Field::new(FieldType::Secret, "4242424242424242"),
    )];
    s.update(vault, |v, secret| {
        v.create_items(secret, [DataOp::create("card", None, fields)])?;
        Ok(())
    })
    .unwrap();
    let export = r#"{"encrypted": false, "items": [
        {"type": 3, "name": "Visa", "card": {"number": "4242 4242 4242 4242", "code": "123"}},
        {"type": 3, "name": "Amex", "card": {"number": "378282246310005"}},
        {"type": 3, "name": "Amex", "card": {"number": "3782-822463-10005"}}
    ]}"#;
    let report = import(&mut s, export, true);
    assert_eq!((report.count("card"), report.duplicates), (1, 2));
    assert_eq!(count(&s), 2);
}

#[test]
fn notes_ssh_keys_and_identities_import_once() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let export = r#"{"encrypted": false, "items": [
        {"type": 2, "name": "Alarm", "notes": "code 1234"},
        {"type": 2, "name": "Alarm", "notes": "code 1234"},
        {"type": 2, "name": "Alarm", "notes": "code 5678"},
        {"type": 5, "name": "Deploy", "sshKey": {"privateKey": "-----BEGIN KEY-----\nabc\n"}},
        {"type": 5, "name": "Deploy copy", "sshKey": {"privateKey": "-----BEGIN KEY-----\nabc"}},
        {"type": 4, "name": "Me", "identity": {"firstName": "Dax", "email": "dax@example.com"}},
        {"type": 4, "name": "Me", "identity": {"firstName": "Dax", "email": "dax@example.com"}}
    ]}"#;
    let report = import(&mut s, export, true);
    assert_eq!(
        (report.counts(), report.duplicates),
        (vec![("note", 2), ("ssh", 1), ("identity", 1)], 3)
    );
    assert_eq!(count(&s), 4);
    let again = import(&mut s, export, true);
    assert_eq!((again.total(), again.duplicates), (0, 7));
    assert_eq!(count(&s), 4);
}

#[test]
fn logins_without_a_password_are_the_same_only_when_whole() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let export = r#"{"encrypted": false, "items": [
        {"type": 1, "name": "Prod DB", "login": {"username": "admin", "uris": [{"uri": "https://db.example.com"}]},
         "fields": [{"name": "port", "value": "5432", "type": 0}]},
        {"type": 1, "name": "Prod DB", "login": {"username": "admin", "uris": [{"uri": "https://db.example.com"}]},
         "fields": [{"name": "port", "value": "5433", "type": 0}]},
        {"type": 1, "name": "Prod DB", "login": {"username": "admin", "uris": [{"uri": "https://db.example.com"}]},
         "fields": [{"name": "port", "value": "5432", "type": 0}]}
    ]}"#;
    let report = import(&mut s, export, true);
    assert_eq!((report.count("login"), report.duplicates), (2, 1));
    assert_eq!(count(&s), 2);
    let again = import(&mut s, export, true);
    assert_eq!((again.total(), again.duplicates), (0, 3));
}

#[test]
fn hosts() {
    for (url, host_) in [
        ("https://www.GitHub.com/login", "github.com"),
        (
            "https://user:pw@mail.example.org:8443/x?y",
            "mail.example.org",
        ),
        ("example.com/path", "example.com"),
        ("ssh://git@host", "host"),
        ("https://[::1]:8080/x", "[::1]"),
        ("https://[2001:DB8::1]", "[2001:db8::1]"),
        ("https://user@[::1]", "[::1]"),
        ("https://bücher.de", "xn--bcher-kva.de"),
        // Labelled where autofill would fill it, not where it seems to go.
        ("https://evil.com\\@github.com", "evil.com"),
        ("https://evil.com\\@www.github.com/login", "evil.com"),
        ("https://github.com@evil.com", "evil.com"),
        ("https://exa mple.com", ""),
        ("", ""),
    ] {
        assert_eq!(host(url), host_, "{url}");
    }
}

fn item(kind: &str, name: Option<&str>, fields: &[(&str, &str)]) -> Item {
    Item {
        id: ItemId::from_bytes([0xee; 16]),
        kind: kind.into(),
        name: name.map(Into::into),
        fields: fields
            .iter()
            .map(|(k, v)| (k.to_string(), Field::new(FieldType::Text, *v)))
            .collect(),
        source: None,
        favorite: false,
        tags: BTreeSet::new(),
        password_entry: None,
        password_changed: None,
        ignored: BTreeMap::new(),
        deleted: false,
    }
}

#[test]
fn search_skips_the_derived_label() {
    let q = |words: &[&str]| -> Vec<String> { words.iter().map(|w| w.to_string()).collect() };
    let unbranded = item("card", None, &[("number", "4242424242424242")]);
    let branded = item(
        "card",
        None,
        &[("number", "5555555555554444"), ("brand", "Visa")],
    );
    let named = item("card", Some("Travel"), &[("number", "6011000990139424")]);
    let login = item("login", None, &[("password", "x")]);
    let note = item("note", None, &[("notes", "body text")]);
    assert_eq!(label(&unbranded), "card •••• 4242");
    assert_eq!(label(&login), "login");
    assert_eq!((label(&note), detail(&note)), ("note".into(), None));
    assert!(!matches(&note, &q(&["body"]), false));
    let key = item(
        "ssh",
        None,
        &[("private-key", "k"), ("comment", "dax@laptop")],
    );
    assert_eq!(label(&key), "dax@laptop");
    assert!(matches(&key, &q(&["laptop"]), false));
    let printed = item(
        "ssh",
        None,
        &[("private-key", "k"), ("fingerprint", "SHA256:xyz")],
    );
    assert!(matches(&printed, &q(&["sha256:xyz"]), false));
    assert!(!matches(&printed, &q(&["k"]), false));
    let me = item(
        "identity",
        Some("Me"),
        &[
            ("given-name", "Dax"),
            ("family-name", "Raad"),
            ("email", "dax@example.com"),
        ],
    );
    assert_eq!(detail(&me).as_deref(), Some("dax@example.com"));
    assert!(matches(&me, &q(&["raad", "example"]), false));
    let unnamed = item(
        "identity",
        None,
        &[("given-name", "Dax"), ("family-name", "Raad")],
    );
    assert_eq!(label(&unnamed), "Dax Raad");
    // One made before names had parts still reads by its old name.
    let legacy = item("identity", None, &[("name", "Kit Langton")]);
    assert_eq!(label(&legacy), "Kit Langton");
    assert!(matches(&legacy, &q(&["langton"]), false));
    let phone = item("identity", None, &[("phone", "+1 555 0100")]);
    assert!(matches(&phone, &q(&["0100"]), false));
    // The type word and the label's filler match no item, branded or not.
    for words in [&["card"][..], &["login"], &["••••"]] {
        for it in [&unbranded, &branded, &named, &login] {
            assert!(
                !matches(it, &q(words), false),
                "{words:?} matched {}",
                label(it)
            );
        }
    }
    assert!(matches(&branded, &q(&["visa", "4444"]), false));
    assert!(matches(&unbranded, &q(&["4242"]), false));
    assert!(matches(&named, &q(&["travel", "9424"]), false));
}

#[test]
fn login_labels_use_the_browser_title_rules() {
    for (name, fields, expected) in [
        (
            Some("Personal"),
            vec![("url", "https://www.github.com")],
            "Personal",
        ),
        (None, vec![("url", "https://www.github.com")], "github.com"),
        (
            None,
            vec![("url", "https://[2001:DB8::1]")],
            "[2001:db8::1]",
        ),
        (None, vec![("url", "not a url"), ("username", "kit")], "kit"),
        (
            None,
            vec![("url", "https://www."), ("username", "kit")],
            "kit",
        ),
        (None, vec![("url", "https://www.")], "login"),
        (None, vec![("password", "never a title")], "login"),
    ] {
        assert_eq!(label(&item("login", name, &fields)), expected);
    }
}

#[test]
fn short_ids_are_unique_prefixes() {
    let mut ids = vec!["abcd1234".to_string(), "abcd5678".into(), "ffff0000".into()];
    ids.sort();
    assert_eq!(short_id(&ids, "abcd1234"), "abcd1");
    assert_eq!(short_id(&ids, "abcd5678"), "abcd5");
    assert_eq!(short_id(&ids, "ffff0000"), "ffff");
}

#[test]
fn normalizes_input() {
    let n = |k, name, f: FieldType, v: &str| normalize(k, name, &f, v.into());
    assert_eq!(
        n("card", "number", FieldType::Secret, "4242 4242-4242 4242"),
        "4242424242424242"
    );
    assert_eq!(n("card", "expiry", FieldType::Month, "4/27"), "2027-04");
    assert_eq!(n("card", "expiry", FieldType::Month, "12/2031"), "2031-12");
    assert_eq!(n("card", "expiry", FieldType::Month, "2031-12"), "2031-12");
    assert_eq!(n("card", "expiry", FieldType::Month, " 4 / 27 "), "2027-04");
    for bad in ["4/2x", "4/203", "x/27"] {
        assert_eq!(n("card", "expiry", FieldType::Month, bad), bad);
    }
    assert_eq!(
        n("login", "url", FieldType::Url, "github.com"),
        "https://github.com"
    );
    assert_eq!(n("login", "url", FieldType::Url, "ftp://x"), "ftp://x");
    assert_eq!(n("login", "url", FieldType::Url, ""), "");
    assert_eq!(
        n("identity", "phone", FieldType::Text, "+1 (555) 010-0100"),
        "+15550100100"
    );
    assert_eq!(
        n("identity", "phone", FieldType::Text, "(555) 010-0100"),
        "(555) 010-0100"
    );
    assert_eq!(n("identity", "country", FieldType::Text, "gb"), "GB");
    assert_eq!(n("identity", "country", FieldType::Text, "Wales"), "Wales");
}

#[test]
fn live_write_lookup_matches_the_listing_including_ambiguity() {
    let temp = tempfile::tempdir().unwrap();
    let mut s = loaded(temp.path());
    for title in ["A", "B"] {
        create(
            &mut s,
            None,
            "login",
            Some(title.into()),
            vec![
                input("username", "shared"),
                input("password", "not-a-search-term"),
            ],
        )
        .unwrap();
    }
    let vid = s.resolve(None).unwrap();
    let compare = |v: &Vault| {
        let listing = Listing::new(v);
        for q in [
            "shared",
            "#",
            "#tag",
            "A",
            "absent",
            "not-a-search-term",
            &listing.items[0].id.to_string(),
        ] {
            let q = words(q);
            assert_eq!(
                find_live(v, &q).map_err(|e| e.to_string()),
                listing.find(&q).cloned().map_err(|e| e.to_string())
            );
        }
    };
    compare(s.vault(&vid));
    let id = s.vault(&vid).items()[0].id;
    write(&mut s, vid, vec![DataOp::tag_add(id, "tag")]).unwrap();
    compare(s.vault(&vid));
}
