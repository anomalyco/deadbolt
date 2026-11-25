use super::*;
use deadbolt_engine::items::list;

fn words(query: &str) -> Vec<String> {
    query.split(' ').map(String::from).collect()
}

fn loaded(dir: &std::path::Path) -> Loaded {
    let params = crate::disk::KdfParams {
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

#[test]
fn imports_skip_duplicates_and_a_dry_run_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let export = "name,url,username,password\n\
        GitHub,https://github.com/login,sam,pw-1\n\
        GitHub again,https://www.GitHub.com/,sam,pw-1\n\
        Other user,https://github.com,alex,pw-1\n\
        New password,https://github.com,sam,pw-2\n\
        No url,,sam,pw-1\n\
        No url again,not a url,sam,pw-1\n\
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
                {"value": "sam@gmail.com", "designation": "username"},
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
        {"type": 4, "name": "Me", "identity": {"firstName": "Sam", "email": "sam@example.com"}},
        {"type": 4, "name": "Me", "identity": {"firstName": "Sam", "email": "sam@example.com"}}
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
