use super::*;
use deadbolt_core::listing::normalize;

use crate::testing::engine as loaded;

fn count(s: &Engine) -> usize {
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
    let mut s = loaded();
    // RFC 6238's SHA-1 secret, "12345678901234567890".
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let otp = format!("otpauth://totp/Site:sam?secret={secret}&digits=8&issuer=Site");
    let fields = vec![input("password", "pw"), input("otp", &otp)];
    create(&mut s, None, "login", Some("Site".into()), fields).unwrap();
    let code = code(&s, None, &words("site"), Duration::from_millis(59_250)).unwrap();
    assert_eq!(code.code.expose(), "94287082");
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
    assert_eq!(code.code.expose(), "287082");
}

/// Under a millisecond before the boundary still reads as time left.
#[test]
fn a_code_always_has_time_left() {
    let mut s = loaded();
    let fields = vec![input("password", "pw"), input("otp", "JBSWY3DPEHPK3PXP")];
    create(&mut s, None, "login", Some("Site".into()), fields).unwrap();
    let code = code(&s, None, &words("site"), Duration::from_micros(59_999_700)).unwrap();
    assert_eq!((code.valid_until, code.remaining_ms), (60, 1));
}

/// Every field of type otp comes back empty unless asked for.
#[test]
fn items_leave_otp_secrets_unless_asked() {
    let mut s = loaded();
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
    let mut s = loaded();
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
    let mut s = loaded();
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

/// The app saves an edit as one change: fields set, emptied ones
/// removed and the name, in one entry.
#[test]
fn a_set_removes_its_unset_fields_in_the_same_entry() {
    let mut s = loaded();
    let input = |name: &str, value: &str| FieldInput {
        name: name.into(),
        kind: None,
        value: value.into(),
    };
    let fields = vec![input("password", "pw-1"), input("notes", "old")];
    let id = create(&mut s, None, "login", None, fields).unwrap().id;
    let vault = s.resolve(None).unwrap();
    let before = s.vault(&vault).frames().count();
    let query = [id];
    let unset = ["notes".to_string()];
    let fields = vec![input("password", "pw-2")];
    let name = Some("GitHub".into());
    let item = set(&mut s, None, &query, fields, name, &unset).unwrap();
    assert_eq!(s.vault(&vault).frames().count(), before + 1);
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
    assert_eq!(s.vault(&vault).frames().count(), before + 2);
}

/// An edit that empties a field another device already removed still
/// saves, and only its other changes are written. A name the item could
/// never have, or a required field, is still refused.
#[test]
fn a_set_skips_unset_fields_already_gone() {
    let mut s = loaded();
    let input = |name: &str, value: &str| FieldInput {
        name: name.into(),
        kind: None,
        value: value.into(),
    };
    let fields = vec![input("password", "pw-1"), input("url", "a.com")];
    let id = create(&mut s, None, "login", None, fields).unwrap().id;
    let vault = s.resolve(None).unwrap();
    let before = s.vault(&vault).frames().count();
    let query = [id];
    let gone = ["notes".to_string(), "pin-hint".to_string()];
    set(&mut s, None, &query, vec![], None, &gone).unwrap();
    assert_eq!(s.vault(&vault).frames().count(), before, "nothing to write");
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
    assert_eq!(s.vault(&vault).frames().count(), before + 1);
    let item = get(&s, None, &query, false, false, &[], false).unwrap();
    let names: Vec<&str> = item.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["password"]);

    let bad = set(&mut s, None, &query, vec![], None, &["Not A Name".into()]);
    assert!(bad.unwrap_err().to_string().contains("invalid field name"));
    let card = vec![input("number", "4242424242424242")];
    let card = create(&mut s, None, "card", None, card).unwrap().id;
    let error = set(&mut s, None, &[card], vec![], None, &["expiry".into()]);
    assert!(error.is_ok(), "an optional field: {error:?}");
    assert_eq!(s.vault(&vault).frames().count(), before + 2);
}

#[test]
fn favorites_sort_first_and_nested_tags_filter_and_disambiguate() {
    let mut s = loaded();
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
    let mut s = loaded();
    for name in ["Alpha", "Beta", "Gamma"] {
        let fields = vec![input("password", &format!("{name}-pw"))];
        create(&mut s, None, "login", Some(name.into()), fields).unwrap();
    }
    remove(&mut s, None, &words("alpha")).unwrap();
    remove(&mut s, None, &words("beta")).unwrap();
    let labels = |s: &Engine, deleted| {
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
        &[("private-key", "k"), ("comment", "sam@laptop")],
    );
    assert_eq!(label(&key), "sam@laptop");
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
            ("given-name", "Sam"),
            ("family-name", "Rivera"),
            ("email", "sam@example.com"),
        ],
    );
    assert_eq!(detail(&me).as_deref(), Some("sam@example.com"));
    assert!(matches(&me, &q(&["rivera", "example"]), false));
    let unnamed = item(
        "identity",
        None,
        &[("given-name", "Sam"), ("family-name", "Rivera")],
    );
    assert_eq!(label(&unnamed), "Sam Rivera");
    // One made before names had parts still reads by its old name.
    let legacy = item("identity", None, &[("name", "Alex Mercer")]);
    assert_eq!(label(&legacy), "Alex Mercer");
    assert!(matches(&legacy, &q(&["mercer"]), false));
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
        (
            None,
            vec![("url", "not a url"), ("username", "alex")],
            "alex",
        ),
        (
            None,
            vec![("url", "https://www."), ("username", "alex")],
            "alex",
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

/// A whole id finds that item only: never another whose text holds it,
/// even once the item it names is gone.
#[test]
fn a_whole_id_names_one_item_and_never_a_text_match() {
    let mut s = loaded();
    let target = create(
        &mut s,
        None,
        "login",
        Some("Target".into()),
        vec![input("password", "pw")],
    )
    .unwrap();
    let decoy = create(
        &mut s,
        None,
        "login",
        Some(target.id.clone()),
        vec![input("password", "pw")],
    )
    .unwrap();
    let vid = s.resolve(None).unwrap();
    let q = vec![target.id.clone()];
    assert_eq!(
        find_live(s.vault(&vid), &q).unwrap().id.to_string(),
        target.id
    );
    let id = s
        .vault(&vid)
        .items()
        .into_iter()
        .find(|i| i.id.to_string() == target.id)
        .unwrap()
        .id;
    write(&mut s, vid, vec![DataOp::delete(id, 1)]).unwrap();
    assert!(
        find_live(s.vault(&vid), &q).is_err(),
        "the decoy {} named after it isn't it",
        decoy.id
    );
    // A shorter prefix, or words of the name, still search.
    assert_eq!(
        find_live(s.vault(&vid), &[decoy.id[..8].to_string()])
            .unwrap()
            .id
            .to_string(),
        decoy.id
    );
}

#[test]
fn live_write_lookup_matches_the_listing_including_ambiguity() {
    let mut s = loaded();
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
