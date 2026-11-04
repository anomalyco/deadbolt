use deadbolt_core::{Entry, Hash, Payload};
use serde_json::json;

use super::*;
use crate::import::onepassword::tests::USER;
use crate::import::op::tests::items as op_items;
use crate::protocol::FieldInput;

const ACCOUNT: &str = "AAAABBBBCCCCDDDDEEEEFFFFGG";
const PRIVATE: &str = "v1v1v1v1v1v1v1v1v1v1v1v1v1";
const SHARED: &str = "v2v2v2v2v2v2v2v2v2v2v2v2v2";

/// Every value in the fixture worth leaking.
const SECRETS: [&str; 10] = [
    "op-github-pw",
    "op-recovery-111",
    "op-note-secret",
    "op-wifi-pw",
    "4242",
    "op-api-key",
    "op-ssh-pass",
    "op-license-pw",
    "op-account-12345678",
    "JBSWY3DPEHPK3PXP",
];

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

fn account() -> Account {
    Account {
        id: ACCOUNT.into(),
        user: Some(USER.into()),
    }
}

/// What `known` reads, then what `fetch` gets from an `op` holding
/// `items`, mirroring `vaults` only.
fn fetched(s: &Loaded, items: &[Value], vaults: Option<&[&str]>) -> (Known, Fetched) {
    fetched_from(s, items, vaults, account())
}

fn fetched_from(
    s: &Loaded,
    items: &[Value],
    vaults: Option<&[&str]>,
    account: Account,
) -> (Known, Fetched) {
    let known = known(s, None).unwrap();
    let vaults: Option<BTreeSet<String>> =
        vaults.map(|v| v.iter().map(|v| v.to_string()).collect());
    // `op item list` gives no fields, sections or files.
    let listed: Vec<Value> = items
        .iter()
        .map(|i| {
            let mut i = i.clone();
            for key in ["fields", "sections", "files"] {
                i.as_object_mut().unwrap().remove(key);
            }
            i
        })
        .collect();
    let (_, requested) = wanted(&listed, &account, vaults.as_ref(), &known);
    let items = items
        .iter()
        .filter_map(|i| {
            let (_, id, _) = op::identity(i)?;
            requested.contains(&id).then(|| (id, i.clone()))
        })
        .collect();
    let fetched = Fetched {
        account,
        vaults,
        listed,
        requested,
        items,
    };
    (known, fetched)
}

/// The ids of the items a sync would fetch.
fn requested(s: &Loaded, items: &[Value]) -> Vec<String> {
    let (_, fetched) = fetched(s, items, None);
    fetched.requested.into_iter().collect()
}

fn checked(report: MirrorReport) -> MirrorReport {
    let text = format!("{report:?}\n{}", report.lines().join("\n"));
    for secret in SECRETS {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
    report
}

fn sync(s: &mut Loaded, items: &[Value]) -> MirrorReport {
    sync_vaults(s, items, None)
}

fn sync_vaults(s: &mut Loaded, items: &[Value], vaults: Option<&[&str]>) -> MirrorReport {
    let (known, fetched) = fetched(s, items, vaults);
    checked(apply(s, &known, fetched, true).unwrap())
}

fn entries(s: &Loaded) -> Vec<Hash> {
    let vault = s.resolve(None).unwrap();
    s.vault(&vault).entries().iter().map(|e| e.hash()).collect()
}

/// The data ops of the entries written since `before`.
fn written(s: &Loaded, before: &[Hash]) -> Vec<DataOp> {
    let vault = s.resolve(None).unwrap();
    s.vault(&vault)
        .entries()
        .into_iter()
        .filter(|e| !before.contains(&e.hash()))
        .flat_map(|e: &Entry| match e.payload() {
            Payload::Data(ops) => ops.clone(),
            _ => vec![],
        })
        .collect()
}

fn items(s: &Loaded) -> Vec<Item> {
    let vault = s.resolve(None).unwrap();
    s.vault(&vault).items()
}

fn named(s: &Loaded, name: &str) -> Vec<Item> {
    items(s)
        .into_iter()
        .filter(|i| i.name.as_deref() == Some(name))
        .collect()
}

fn version(item: &Item) -> MirrorVersion {
    MirrorVersion::parse(&item.source.as_ref().unwrap().version).unwrap()
}

fn actions(report: &MirrorReport) -> Vec<(MirrorAction, &str, Option<&str>)> {
    report
        .items
        .iter()
        .map(|i| (i.action, i.title.as_str(), i.reason.as_deref()))
        .collect()
}

fn titled<'a>(items: &'a mut [Value], title: &str) -> &'a mut Value {
    items.iter_mut().find(|i| i["title"] == title).unwrap()
}

fn input(name: &str, value: &str) -> FieldInput {
    FieldInput {
        name: name.into(),
        kind: None,
        value: value.into(),
    }
}

fn create(s: &mut Loaded, kind: &str, name: &str, fields: &[(&str, &str)]) {
    let fields = fields.iter().map(|(n, v)| input(n, v)).collect();
    super::super::items::create(s, None, kind, Some(name.into()), fields).unwrap();
}

fn set(s: &mut Loaded, name: &str, field: &str, value: &str) {
    let words = vec![name.to_string()];
    super::super::items::set(s, None, &words, vec![input(field, value)], None, &[]).unwrap();
}

/// The test export, imported the way it was before imports recorded
/// where items came from.
fn import_without_sources(s: &mut Loaded) {
    let (mut items, report) =
        crate::import::parse(crate::import::onepassword::tests::EXPORT).unwrap();
    for item in &mut items {
        item.source = None;
    }
    super::super::items::import(s, None, (items, report), true).unwrap();
}

fn import(s: &mut Loaded) {
    let parsed = crate::import::parse(crate::import::onepassword::tests::EXPORT).unwrap();
    super::super::items::import(s, None, parsed, true).unwrap();
}

const SKIPPED: [(MirrorAction, &str, Option<&str>); 3] = [
    (
        MirrorAction::Skip,
        "Deploy key",
        Some("SSH key without a private key"),
    ),
    (MirrorAction::Skip, "Future", Some("item of unknown type")),
    (MirrorAction::Skip, "Scan", Some("document")),
];

const BESIDE: &str = "added beside an item with the same name";

#[test]
fn adds_everything_then_writes_nothing_until_something_changes() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let op = op_items();
    let report = sync(&mut s, &op);
    assert_eq!(report.count(MirrorAction::Add), 11);
    assert_eq!(&actions(&report)[11..], SKIPPED);
    assert_eq!(report.summary(), "11 added");
    assert!(
        report.dropped.iter().any(|t| t.one == "attachment"),
        "{:?}",
        report.dropped
    );
    let github = &named(&s, "GitHub")[0];
    let source = github.source.as_ref().unwrap();
    assert_eq!(
        source.id,
        format!("1password/{ACCOUNT}/{PRIVATE}/item1item1item1item1item1a")
    );
    assert_eq!(version(github).origin, Origin::Sync);
    assert_eq!(
        source_app(github.source.as_ref()).as_deref(),
        Some("1Password")
    );
    assert!(
        !github
            .fields
            .values()
            .any(|f| f.value.contains("1password/"))
    );

    // Unchanged on both sides: nothing fetched (but the SSH key that
    // could not be mirrored), nothing written.
    let before = entries(&s);
    assert_eq!(requested(&s, &op), ["item9"]);
    let report = sync(&mut s, &op);
    assert_eq!(report.unchanged, 11);
    assert!(!report.changed());
    assert_eq!(entries(&s), before);
    assert_eq!(report.lines()[0], "Up to date (11 unchanged, 3 skipped)");
}

#[test]
fn a_change_writes_only_the_fields_that_differ() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let mut op = op_items();
    sync(&mut s, &op);
    let github = titled(&mut op, "GitHub");
    github["fields"][1]["value"] = json!("op-github-pw-2");
    github["updated_at"] = json!("2024-04-01T00:00:00Z");
    let before = entries(&s);
    let report = sync(&mut s, &op);
    assert_eq!(
        actions(&report)[0],
        (MirrorAction::Update, "GitHub", Some("password"))
    );
    assert_eq!(report.unchanged, 10);
    let ops = written(&s, &before);
    assert_eq!(ops.len(), 2, "the password and the source");
    assert!(
        matches!(&ops[0], DataOp::Edit { change: Change::Set { field, .. }, .. } if field == "password")
    );
    assert!(matches!(
        &ops[1],
        DataOp::Edit {
            change: Change::Source(Some(_)),
            ..
        }
    ));
    let github = &named(&s, "GitHub")[0];
    assert_eq!(github.fields["password"].value, "op-github-pw-2");
    assert_eq!(version(github).updated, 1_711_929_600);

    // Same content, newer time (a passkey changed): nothing written.
    titled(&mut op, "GitHub")["updated_at"] = json!("2024-05-01T00:00:00Z");
    let before = entries(&s);
    let report = sync(&mut s, &op);
    assert!(!report.changed());
    assert_eq!(entries(&s), before);
}

#[test]
fn one_password_wins_over_edits_made_here() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let op = op_items();
    sync(&mut s, &op);
    set(&mut s, "A note", "notes", "mine");
    assert_eq!(requested(&s, &op), ["item3item3item3item3item3a", "item9"]);
    let report = sync(&mut s, &op);
    assert_eq!(
        actions(&report)[0],
        (MirrorAction::Update, "A note", Some("notes"))
    );
    assert_eq!(
        named(&s, "A note")[0].fields["notes"].value,
        "op-note-secret"
    );
}

#[test]
fn deletes_only_what_the_mirror_added() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let mut op = op_items();
    sync(&mut s, &op);
    create(&mut s, "login", "Mine", &[("password", "kit-pw")]);
    op.retain(|i| i["title"] != "A note" && i["title"] != "Visa");
    let report = sync(&mut s, &op);
    assert_eq!(
        actions(&report)[..2],
        [
            (MirrorAction::Delete, "A note", None),
            (MirrorAction::Delete, "Visa", None)
        ]
    );
    assert!(named(&s, "A note").is_empty());
    assert_eq!(named(&s, "Mine").len(), 1);

    // Nothing listed at all is more likely a mistake than a wipe.
    let before = entries(&s);
    let (known, fetched) = fetched(&s, &[], None);
    let error = apply(&mut s, &known, fetched, true).unwrap_err();
    assert_eq!(
        error.to_string(),
        "1Password listed no items: leaving the 9 mirrored items alone"
    );
    assert_eq!(entries(&s), before);
}

#[test]
fn takes_over_the_same_content_and_adds_the_rest_beside() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    import_without_sources(&mut s);
    create(&mut s, "login", "Mine", &[("password", "kit-pw")]);
    let count = items(&s).len();
    let mut op = op_items();
    let report = sync(&mut s, &op);
    // `op` gives the card's contact address as one line, so that card
    // is not plainly the same as the imported one: it is added, and the
    // import left as it was. An identity's address splits into the
    // same parts either way.
    assert_eq!(report.count(MirrorAction::Adopt), 10, "{report:?}");
    assert_eq!(
        actions(&report)[..1],
        [(MirrorAction::Add, "Visa", Some(BESIDE))]
    );
    assert!(
        report
            .items
            .iter()
            .all(|i| i.action != MirrorAction::Adopt || i.reason.is_none())
    );
    assert_eq!(items(&s).len(), count + 1);
    assert_eq!(named(&s, "Me").len(), 1);
    let visa = named(&s, "Visa");
    assert_eq!(visa.len(), 2);
    let mine = visa.iter().find(|i| i.source.is_none()).unwrap();
    assert!(mine.fields["address"].value.contains('\n'));
    assert!(named(&s, "Mine")[0].source.is_none());
    let report = sync(&mut s, &op);
    assert_eq!(report.unchanged, 11);

    // Deleted in 1Password: kept, and no longer mirrored.
    op.retain(|i| i["title"] != "A note");
    let report = sync(&mut s, &op);
    assert_eq!(report.count(MirrorAction::Release), 1);
    let note = &named(&s, "A note")[0];
    assert!(note.source.is_none());
    assert!(!note.deleted);
}

#[test]
fn a_login_with_the_same_username_and_url_is_taken_over_keeping_its_own_fields() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    create(
        &mut s,
        "login",
        "GitHub (work)",
        &[
            ("username", "dax@example.com"),
            ("password", "mine"),
            ("url", "https://github.com/login"),
            ("pin", "2468"),
        ],
    );
    let before = entries(&s);
    let (known, fetched_) = fetched(&s, &op_items(), None);
    let dry = checked(apply(&mut s, &known, fetched_, false).unwrap());
    assert_eq!(entries(&s), before);
    let (_, title, reason) = actions(&dry)
        .into_iter()
        .find(|(a, ..)| *a == MirrorAction::Adopt)
        .unwrap();
    assert_eq!(title, "GitHub");
    let reason = reason.unwrap();
    assert!(
        reason.starts_with("takes over, changes: title, "),
        "{reason}"
    );
    assert!(
        reason.contains("password") && !reason.contains("pin"),
        "{reason}"
    );
    assert!(
        dry.lines()
            .iter()
            .any(|l| l.starts_with("  adopt   GitHub (takes over, changes: "))
    );

    let report = sync(&mut s, &op_items());
    assert_eq!(dry.items, report.items);
    let github = &named(&s, "GitHub")[0];
    assert_eq!(github.fields["password"].value, "op-github-pw");
    assert_eq!(github.fields["pin"].value, "2468");
    assert!(github.favorite);
    assert_eq!(github.tags, BTreeSet::from(["dev".into(), "work".into()]));
    assert_eq!(version(github).origin, Origin::Adopted);
    assert!(named(&s, "GitHub (work)").is_empty());

    // A tag added only in Deadbolt survives a 1Password sync, while a tag
    // 1Password wrote and later removed goes.
    super::super::items::set_with(
        &mut s,
        None,
        &["GitHub".into()],
        vec![],
        None,
        &[],
        None,
        &["local/only".into()],
        &[],
    )
    .unwrap();

    // Later changes keep it too.
    let mut op = op_items();
    let item = titled(&mut op, "GitHub");
    item["fields"][1]["value"] = json!("op-github-pw-2");
    item["tags"] = json!(["work"]);
    item["updated_at"] = json!("2024-04-01T00:00:00Z");
    let report = sync(&mut s, &op);
    assert_eq!(
        actions(&report)[0],
        (MirrorAction::Update, "GitHub", Some("password, tags"))
    );
    let after = &named(&s, "GitHub")[0];
    assert_eq!(after.fields["pin"].value, "2468");
    assert_eq!(
        after.tags,
        BTreeSet::from(["local/only".into(), "work".into()])
    );
    // And it is fresh: written as it now is, with its own field.
    assert_eq!(requested(&s, &op), ["item9"]);

    // A field deleted in 1Password goes; one added here since stays.
    set(&mut s, "GitHub", "door", "1357");
    let item = titled(&mut op, "GitHub");
    item["fields"]
        .as_array_mut()
        .unwrap()
        .retain(|f| f["id"] != "notesPlain");
    item["updated_at"] = json!("2024-05-01T00:00:00Z");
    assert!(named(&s, "GitHub")[0].fields.contains_key("notes"));
    let report = sync(&mut s, &op);
    assert_eq!(
        actions(&report)[0],
        (MirrorAction::Update, "GitHub", Some("notes"))
    );
    let github = &named(&s, "GitHub")[0];
    assert!(!github.fields.contains_key("notes"));
    assert_eq!(github.fields["pin"].value, "2468");
    assert_eq!(github.fields["door"].value, "1357");
    assert!(!version(github).fields.contains("door"));
    assert_eq!(requested(&s, &op), ["item9"]);
}

#[test]
fn a_login_matched_here_already_makes_another_with_its_username_and_url_ambiguous() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let mut op = op_items();
    sync(&mut s, &op);
    create(
        &mut s,
        "login",
        "GitHub (work)",
        &[
            ("username", "dax@example.com"),
            ("password", "mine"),
            ("url", "https://github.com/login"),
        ],
    );
    let mut twin = titled(&mut op, "GitHub").clone();
    twin["id"] = json!("twin1twin1twin1twin1twin1a");
    twin["title"] = json!("GitHub 2");
    twin["fields"][1]["value"] = json!("op-github-pw-2");
    op.push(twin);
    let report = sync(&mut s, &op);
    assert_eq!(
        actions(&report)[0],
        (
            MirrorAction::Add,
            "GitHub 2",
            Some("added beside 2 items with the same username and URL")
        ),
        "{report:?}"
    );
    assert_eq!(report.count(MirrorAction::Adopt), 0);
    let mine = &named(&s, "GitHub (work)")[0];
    assert!(mine.source.is_none());
    assert_eq!(mine.fields["password"].value, "mine");
}

#[test]
fn an_import_is_never_taken_over_by_another_item() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    import(&mut s);
    let imported: Vec<Item> = items(&s);
    // The same items, from another account: none is the one exported.
    let other = Account {
        id: "OTHEROTHEROTHEROTHEROTHERO".into(),
        user: Some("U2".into()),
    };
    let (known, fetched) = fetched_from(&s, &op_items(), None, other);
    let report = checked(apply(&mut s, &known, fetched, true).unwrap());
    assert_eq!(report.count(MirrorAction::Adopt), 0, "{report:?}");
    assert_eq!(report.count(MirrorAction::Add), 11);
    for item in imported {
        let now = items(&s).into_iter().find(|i| i.id == item.id).unwrap();
        assert_eq!(now.source, item.source);
        assert_eq!(now.fields, item.fields);
    }
}

#[test]
fn mirrors_of_two_accounts_are_told_apart() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let op = op_items();
    sync(&mut s, &op);
    let other = Account {
        id: "OTHEROTHEROTHEROTHEROTHERO".into(),
        user: None,
    };
    let (known, theirs) = fetched_from(&s, &op, None, other.clone());
    checked(apply(&mut s, &known, theirs, true).unwrap());
    // Each is fresh in its own account.
    assert_eq!(requested(&s, &op), ["item9"]);
    let (_, theirs) = fetched_from(&s, &op, None, other);
    assert_eq!(theirs.requested.into_iter().collect::<Vec<_>>(), ["item9"]);

    // An edit to the other account's copy during a sync of this one
    // holds up nothing.
    let mut changed = op.clone();
    let github = titled(&mut changed, "GitHub");
    github["fields"][1]["value"] = json!("op-github-pw-2");
    github["updated_at"] = json!("2024-04-01T00:00:00Z");
    let (known, fetched) = fetched(&s, &changed, None);
    let theirs = named(&s, "GitHub")
        .into_iter()
        .find(|i| i.source.as_ref().unwrap().id.contains("OTHER"))
        .unwrap();
    let mut field = theirs.fields["password"].clone();
    field.value = "theirs".into();
    let vault = s.resolve(None).unwrap();
    s.update(vault, |v, secret| {
        v.write(secret, vec![DataOp::set(theirs.id, "password", field)])?;
        Ok(())
    })
    .unwrap();
    let report = checked(apply(&mut s, &known, fetched, true).unwrap());
    assert_eq!(
        actions(&report)[0],
        (MirrorAction::Update, "GitHub", Some("password")),
        "{report:?}"
    );
}

#[test]
fn an_item_that_only_shares_a_name_is_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    create(&mut s, "note", "A note", &[("notes", "mine")]);
    // A login without a URL is no stronger.
    create(
        &mut s,
        "login",
        "GitHub",
        &[("username", "dax@example.com"), ("password", "mine")],
    );
    let report = sync(&mut s, &op_items());
    assert_eq!(report.count(MirrorAction::Adopt), 0, "{report:?}");
    assert!(actions(&report).contains(&(MirrorAction::Add, "A note", Some(BESIDE))));
    assert!(actions(&report).contains(&(MirrorAction::Add, "GitHub", Some(BESIDE))));
    for name in ["A note", "GitHub"] {
        let both = named(&s, name);
        assert_eq!(both.len(), 2);
        let mine = both.iter().find(|i| i.source.is_none()).unwrap();
        assert!(mine.fields.values().any(|f| f.value == "mine"));
    }
}

#[test]
fn an_import_is_taken_over_by_id() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    import(&mut s);
    // A .1pux import only records where it came from.
    let github = &named(&s, "GitHub")[0];
    assert_eq!(version(github).origin, Origin::Import);
    assert_eq!(source_app(github.source.as_ref()), None);
    let count = items(&s).len();

    let op = op_items();
    let report = sync(&mut s, &op);
    assert_eq!(report.count(MirrorAction::Adopt), 11, "{report:?}");
    assert_eq!(report.count(MirrorAction::Add), 0);
    // It names the user, `op` the account: the same item all the same,
    // so even the one whose address `op` gives differently.
    let changed: Vec<_> = actions(&report)
        .into_iter()
        .filter(|(_, _, reason)| reason.is_some_and(|r| r.starts_with("takes over")))
        .collect();
    assert_eq!(
        changed,
        [(
            MirrorAction::Adopt,
            "Visa",
            Some("takes over, changes: address")
        )]
    );
    assert_eq!(items(&s).len(), count);
    let github = &named(&s, "GitHub")[0];
    assert_eq!(
        github.source.as_ref().unwrap().id,
        format!("1password/{ACCOUNT}/{PRIVATE}/item1item1item1item1item1a")
    );
    assert_eq!(version(github).origin, Origin::Adopted);
    assert_eq!(
        source_app(github.source.as_ref()).as_deref(),
        Some("1Password")
    );
    // The export's "Old key" is gone from 1Password; never mirrored, it
    // is left as it was.
    let old = &named(&s, "Old key")[0];
    assert_eq!(version(old).origin, Origin::Import);

    let before = entries(&s);
    assert_eq!(requested(&s, &op), ["item9"]);
    let report = sync(&mut s, &op);
    assert_eq!(report.unchanged, 11);
    assert_eq!(&actions(&report), &SKIPPED);
    assert_eq!(entries(&s), before);
}

#[test]
fn ambiguity_is_reported_from_the_side_it_is_on() {
    let github = |password: &'static str| {
        [
            ("username", "dax@example.com"),
            ("password", password),
            ("url", "https://github.com/login"),
        ]
    };
    // Two here.
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    for password in ["one", "two"] {
        create(&mut s, "login", "GitHub", &github(password));
    }
    let report = sync(&mut s, &op_items());
    assert!(
        actions(&report).contains(&(
            MirrorAction::Add,
            "GitHub",
            Some("added beside 2 items with the same username and URL")
        )),
        "{report:?}"
    );
    assert_eq!(report.count(MirrorAction::Add), 11);
    let mine: Vec<_> = named(&s, "GitHub")
        .into_iter()
        .filter(|i| i.source.is_none())
        .collect();
    assert_eq!(mine.len(), 2);

    // Two in 1Password.
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    create(&mut s, "login", "GitHub", &github("one"));
    let mut op = op_items();
    let mut twin = titled(&mut op, "GitHub").clone();
    twin["id"] = json!("twin1twin1twin1twin1twin1a");
    op.push(twin);
    let report = sync(&mut s, &op);
    let reason = "2 1Password items have this username and URL; added beside the one here";
    assert_eq!(
        actions(&report)
            .iter()
            .filter(|a| **a == (MirrorAction::Add, "GitHub", Some(reason)))
            .count(),
        2,
        "{report:?}"
    );
    assert_eq!(named(&s, "GitHub").len(), 3);
}

#[test]
fn the_same_content_settles_a_tie_and_the_rest_are_added() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    import_without_sources(&mut s);
    let mut op = op_items();
    let mut twin = titled(&mut op, "GitHub").clone();
    twin["id"] = json!("twin1twin1twin1twin1twin1a");
    twin["fields"][1]["value"] = json!("op-github-pw-2");
    op.push(twin);
    let report = sync(&mut s, &op);
    assert_eq!(report.count(MirrorAction::Adopt), 10, "{report:?}");
    assert!(actions(&report).contains(&(MirrorAction::Adopt, "GitHub", None)));
    assert!(actions(&report).contains(&(MirrorAction::Add, "GitHub", None)));
    let github = named(&s, "GitHub");
    assert_eq!(github.len(), 2);
    assert!(github.iter().all(|i| i.source.is_some()));
    let passwords: BTreeSet<_> = github
        .iter()
        .map(|i| i.fields["password"].value.as_str())
        .collect();
    assert_eq!(
        passwords,
        BTreeSet::from(["op-github-pw", "op-github-pw-2"])
    );
}

#[test]
fn a_move_between_vaults_keeps_the_one_mirror() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let mut op = op_items();
    sync(&mut s, &op);
    let id = named(&s, "GitHub")[0].id;
    titled(&mut op, "GitHub")["vault"] = json!({ "id": SHARED, "name": "Shared" });

    // A sync of the vault it left only leaves it alone.
    let report = sync_vaults(&mut s, &op, Some(&[PRIVATE]));
    assert!(!report.changed(), "{report:?}");

    let report = sync(&mut s, &op);
    assert_eq!(actions(&report)[0], (MirrorAction::Update, "GitHub", None));
    assert_eq!(report.count(MirrorAction::Update), 1);
    let github = named(&s, "GitHub");
    assert_eq!(github.len(), 1);
    assert_eq!(github[0].id, id);
    assert_eq!(
        github[0].source.as_ref().unwrap().id,
        format!("1password/{ACCOUNT}/{SHARED}/item1item1item1item1item1a")
    );
    assert_eq!(requested(&s, &op), ["item9"]);
}

#[test]
fn an_item_changed_during_the_fetch_is_left_for_next_time() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let mut op = op_items();
    sync(&mut s, &op);
    let github = titled(&mut op, "GitHub");
    github["fields"][1]["value"] = json!("op-github-pw-2");
    github["updated_at"] = json!("2024-04-01T00:00:00Z");
    let (known, fetched) = fetched(&s, &op, None);
    assert!(fetched.items.contains_key("item1item1item1item1item1a"));
    assert!(!fetched.items.contains_key("item3item3item3item3item3a"));

    // Meanwhile, here: one is edited and another deleted.
    set(&mut s, "GitHub", "notes", "mine");
    let words = vec!["A note".to_string()];
    super::super::items::remove(&mut s, None, &words).unwrap();
    let report = checked(apply(&mut s, &known, fetched, true).unwrap());
    let raced: Vec<_> = actions(&report)
        .into_iter()
        .filter(|(.., reason)| *reason == Some(RACED))
        .collect();
    assert_eq!(
        raced,
        [
            (MirrorAction::Skip, "A note", Some(RACED)),
            (MirrorAction::Skip, "GitHub", Some(RACED)),
        ]
    );
    assert!(!report.changed());
    assert_eq!(report.unchanged, 9);
    assert_eq!(named(&s, "GitHub")[0].fields["notes"].value, "mine");
    assert!(named(&s, "A note").is_empty());

    // The next sync fetches both again; 1Password wins.
    let report = sync(&mut s, &op);
    assert_eq!(report.count(MirrorAction::Update), 1, "{report:?}");
    assert_eq!(report.count(MirrorAction::Add), 1);
    assert_eq!(
        named(&s, "GitHub")[0].fields["password"].value,
        "op-github-pw-2"
    );
}

/// Writes a copy of `name`'s source on a new item with its content.
fn duplicate(s: &mut Loaded, name: &str, origin: Origin) {
    let item = named(s, name).remove(0);
    let mut source = item.source.clone().unwrap();
    let mut version = MirrorVersion::parse(&source.version).unwrap();
    version.origin = origin;
    if origin == Origin::Adopted {
        version.fields = item.fields.keys().cloned().collect();
        version.tags = item
            .tags
            .iter()
            .map(|t| deadbolt_core::tag::fold_tag(t))
            .collect();
    }
    source.version = version.to_string();
    let vault = s.resolve(None).unwrap();
    s.update(vault, |v, secret| {
        v.write(secret, vec![DataOp::source(item.id, Some(source.clone()))])?;
        let copy = DataOp::create_with(
            &item.kind,
            item.name.clone(),
            item.fields.clone(),
            Some(source),
            item.favorite,
            item.tags.clone(),
        );
        v.create_items(secret, vec![copy])?;
        Ok(())
    })
    .unwrap();
}

#[test]
fn second_copies_are_settled_only_in_the_vaults_mirrored() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let op = op_items();
    sync(&mut s, &op);
    duplicate(&mut s, "GitHub", Origin::Sync);
    let report = sync_vaults(&mut s, &op, Some(&[SHARED]));
    assert!(!report.changed(), "{report:?}");
    assert_eq!(named(&s, "GitHub").len(), 2);
    let report = sync(&mut s, &op);
    assert_eq!(
        actions(&report)[0],
        (MirrorAction::Delete, "GitHub", Some("a second copy"))
    );
    assert_eq!(named(&s, "GitHub").len(), 1);

    // Two adopted copies: one is released, not deleted.
    duplicate(&mut s, "GitHub", Origin::Adopted);
    let report = sync(&mut s, &op);
    assert_eq!(
        actions(&report)[0],
        (MirrorAction::Release, "GitHub", Some("a second copy"))
    );
    let github = named(&s, "GitHub");
    assert_eq!(github.len(), 2);
    assert_eq!(github.iter().filter(|i| i.source.is_none()).count(), 1);
}

#[test]
fn a_dry_run_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let mut op = op_items();
    let before = entries(&s);
    let (known, fetched_) = fetched(&s, &op, None);
    let dry = apply(&mut s, &known, fetched_, false).unwrap();
    assert!(!dry.applied);
    assert_eq!(entries(&s), before);
    assert_eq!(dry.summary(), "11 would add");
    let real = sync(&mut s, &op);
    assert_eq!(dry.items, real.items);

    op.retain(|i| i["title"] != "Visa");
    let before = entries(&s);
    let (known, fetched_) = fetched(&s, &op, None);
    let dry = apply(&mut s, &known, fetched_, false).unwrap();
    assert_eq!(dry.lines()[1], "  delete  Visa");
    assert_eq!(entries(&s), before);
}

#[test]
fn vaults_left_out_are_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let op = op_items();
    sync(&mut s, &op);
    let report = sync_vaults(&mut s, &op, Some(&[PRIVATE]));
    assert!(!report.changed(), "{report:?}");
    assert_eq!(report.unchanged, 3);
    assert_eq!(named(&s, "Visa").len(), 1);
}

/// A fake `op` in `dir` that runs `script` for any arguments.
fn fake_op(dir: &std::path::Path, script: &str) -> Op {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("op");
    std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    Op::at(path)
}

#[tokio::test]
async fn chooses_the_account_already_mirrored() {
    let dir = tempfile::tempdir().unwrap();
    let accounts = json!([
        { "url": "https://my.1password.com/", "email": "dax@example.com", "user_uuid": USER, "account_uuid": ACCOUNT },
        { "url": "team.1password.com", "email": "dax@example.com", "user_uuid": "U2", "account_uuid": "A2" },
    ]);
    std::fs::write(dir.path().join("accounts.json"), accounts.to_string()).unwrap();
    let op = fake_op(dir.path(), r#"cat "$(dirname "$0")/accounts.json""#);
    let none = BTreeSet::new();
    let set = |ids: &[&str]| ids.iter().map(|id| id.to_string()).collect::<BTreeSet<_>>();
    let error = super::account(&op, None, &none, &none).await.err().unwrap();
    assert_eq!(
        error.to_string(),
        "2 1Password accounts: choose one with --account \
         (dax@example.com on my.1password.com, dax@example.com on team.1password.com)"
    );
    let chosen = super::account(&op, Some("my.1password.com"), &none, &none)
        .await
        .unwrap();
    assert_eq!(chosen.id, ACCOUNT);
    let chosen = super::account(&op, Some("https://team.1password.com/"), &none, &none)
        .await
        .unwrap();
    assert_eq!(chosen.id, "A2");
    // A vault mirroring one, or holding its import, names it.
    for (mirrored, imported) in [
        (set(&[ACCOUNT]), none.clone()),
        (none.clone(), set(&[USER])),
        // Mirrors outrank an import from another account.
        (set(&[ACCOUNT]), set(&["U2"])),
    ] {
        let chosen = super::account(&op, None, &mirrored, &imported)
            .await
            .unwrap();
        assert_eq!(
            (chosen.id.as_str(), chosen.user.as_deref()),
            (ACCOUNT, Some(USER))
        );
    }
    let error = super::account(&op, None, &none, &set(&[USER, "U2"])).await;
    assert!(error.is_err());
}

#[tokio::test]
async fn a_stuck_op_is_killed() {
    let dir = tempfile::tempdir().unwrap();
    let pid = dir.path().join("pid");
    let script = format!("echo $$ > '{}'\nexec sleep 30", pid.display());
    let mut op = fake_op(dir.path(), &script);
    op.timeout = Duration::from_millis(300);
    let started = std::time::Instant::now();
    let error = op
        .json(&["item", "list"], None, Duration::ZERO)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), TIMED_OUT);
    assert!(started.elapsed() < Duration::from_secs(10));
    let pid = std::fs::read_to_string(&pid).unwrap();
    assert!(gone(pid.trim()).await, "op {pid} still running");
}

/// Whether process `pid` has exited, within a few seconds.
pub(crate) async fn gone(pid: &str) -> bool {
    for _ in 0..100 {
        let alive = std::process::Command::new("kill")
            .args(["-0", pid])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success();
        if !alive {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[test]
fn op_errors_say_what_to_do() {
    let cases = [
        (
            "[ERROR] 2024/03/09 16:00:00 You are not currently signed in. Please run `op signin --help` for instructions",
            NOT_SIGNED_IN,
        ),
        (
            "[ERROR] 2024/03/09 16:00:00 authorization prompt dismissed, please try again",
            NOT_ALLOWED,
        ),
        ("[ERROR] 2024/03/09 16:00:00 1Password is locked", LOCKED),
        (
            "[ERROR] 2024/03/09 16:00:00 error initializing client: connecting to desktop app: cannot connect",
            NO_APP,
        ),
    ];
    for (stderr, hint) in cases {
        assert_eq!(failure(stderr).to_string(), hint, "{stderr}");
    }
    assert_eq!(
        failure("[ERROR] 2024/03/09 16:00:00 \"Nope\" isn't a vault in this account.\nmore")
            .to_string(),
        "the 1Password CLI failed: \"Nope\" isn't a vault in this account."
    );
    assert_eq!(
        failure("").to_string(),
        "the 1Password CLI failed: it gave no reason"
    );
}
