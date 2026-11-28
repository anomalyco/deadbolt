use super::*;

use crate::testing::engine as loaded;

fn login(s: &mut Engine, fields: &[(&str, &str)]) -> LoginRef {
    let inputs = fields
        .iter()
        .map(|(name, value)| FieldInput {
            name: (*name).into(),
            kind: None,
            value: (*value).into(),
        })
        .collect();
    let info = create(s, None, "login", None, inputs).unwrap();
    LoginRef {
        vault: hex(s.resolve(None).unwrap().as_bytes()),
        item: info.id,
    }
}

fn save<'a>(title: &'a str, url: &'a str, password: &'a Secret) -> Save<'a> {
    Save {
        origin: "https://example.com",
        login: None,
        title,
        url,
        username: "alex",
        password,
    }
}

#[test]
fn one_time_passwords_fill_as_the_current_code() {
    let mut s = loaded();
    // RFC 6238's SHA-1 secret, "12345678901234567890" in base32.
    let github = login(
        &mut s,
        &[
            ("url", "https://github.com"),
            ("otp", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        ],
    );
    for (now, code) in [
        (59, "287082"),
        (1_111_111_109, "081804"),
        (1_234_567_890, "005924"),
    ] {
        let values = fill(
            &s,
            "https://github.com",
            &github,
            &[Fill::Totp],
            Duration::from_secs(now),
        )
        .unwrap();
        assert_eq!(
            values.totp.as_ref().map(Secret::expose),
            Some(code),
            "at {now}"
        );
        assert!(values.username.is_none() && values.password.is_none());
    }
}

#[test]
fn a_provider_link_is_a_login_that_signs_in_with_the_provider_login() {
    let mut s = loaded();
    // The Google login lives in a vault of its own, not the default one.
    let work = s.create_vault("work").unwrap();
    let input = |name: &str, value: &str| FieldInput {
        name: name.into(),
        kind: None,
        value: value.into(),
    };
    let created = create(
        &mut s,
        Some(&hex(work.as_bytes())),
        "login",
        None,
        vec![
            input("url", "https://accounts.google.com"),
            input("username", "alex@gmail.com"),
            input("password", "hunter22"),
        ],
    )
    .unwrap();
    let google = LoginRef {
        vault: hex(work.as_bytes()),
        item: created.id,
    };
    let elsewhere = login(
        &mut s,
        &[
            ("url", "https://google.com.evil.example"),
            ("username", "alex@gmail.com"),
            ("password", "hunter22"),
        ],
    );
    fn link_to<'a>(account: &'a LoginRef, url: &'a str, provider: &'a str) -> Link<'a> {
        Link {
            origin: "https://shop.com",
            title: "shop.com",
            url,
            provider,
            account,
            test_hosts: false,
        }
    }
    let (saved, made) = link(&mut s, link_to(&google, "https://shop.com", "Google")).unwrap();
    assert!(made);
    assert_eq!(
        saved.vault, google.vault,
        "the link lands beside the provider login"
    );
    let listed = list(&s, "https://shop.com").unwrap().1;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].login, saved);
    assert!(!listed[0].has_password && listed[0].username.is_none());
    let sign_in = listed[0].sign_in.as_ref().unwrap();
    assert_eq!(
        (sign_in.provider.as_str(), sign_in.account.as_deref()),
        ("google", Some("alex@gmail.com"))
    );
    // Linked again: the same login, nothing new.
    assert_eq!(
        link(&mut s, link_to(&google, "https://shop.com", "google")).unwrap(),
        (saved, false)
    );
    // Not off the page's site, not a provider without sign-in hosts or
    // one Deadbolt doesn't know, not a login saved elsewhere than the
    // provider's host, and not a login that isn't here.
    assert!(link(&mut s, link_to(&google, "https://elsewhere.com", "google")).is_err());
    assert!(link(&mut s, link_to(&google, "https://shop.com", "okta")).is_err());
    assert!(link(&mut s, link_to(&google, "https://shop.com", "My SSO")).is_err());
    assert!(link(&mut s, link_to(&elsewhere, "https://shop.com", "google")).is_err());
    let missing = LoginRef {
        item: "0".repeat(32),
        ..google.clone()
    };
    assert!(link(&mut s, link_to(&missing, "https://shop.com", "google")).is_err());
    assert_eq!(list(&s, "https://shop.com").unwrap().1.len(), 1);
}

fn titles(s: &Engine, origin: &str) -> Vec<String> {
    list(s, origin)
        .unwrap()
        .1
        .into_iter()
        .map(|l| l.title)
        .collect()
}

#[test]
fn logins_rank_by_origin_host_parent_site_then_use_then_title() {
    let mut s = loaded();
    for (title, url) in [
        ("a site", "https://www.example.com"),
        ("b parent", "https://example.com"),
        ("c host", "https://accounts.example.com:8443"),
        ("d origin", "https://accounts.example.com/login"),
        ("e shared parent", "https://billing.accounts.example.com"),
        ("f elsewhere", "https://example.org"),
    ] {
        create(
            &mut s,
            None,
            "login",
            Some(title.into()),
            vec![FieldInput {
                name: "url".into(),
                kind: None,
                value: url.into(),
            }],
        )
        .unwrap();
    }
    assert_eq!(
        titles(&s, "https://accounts.example.com"),
        [
            "d origin",
            "c host",
            "b parent",
            "e shared parent",
            "a site"
        ]
    );
    // From the apex, `www` and `accounts` are both its children.
    assert_eq!(
        titles(&s, "https://example.com"),
        [
            "b parent",
            "a site",
            "c host",
            "d origin",
            "e shared parent"
        ]
    );
}

#[test]
fn local_ports_are_different_origins_and_the_last_filled_comes_first() {
    let mut s = loaded();
    let vite = login(
        &mut s,
        &[("url", "http://localhost:5173"), ("username", "vite")],
    );
    let next = login(
        &mut s,
        &[("url", "http://localhost:3000"), ("username", "next")],
    );
    let other = login(
        &mut s,
        &[
            ("url", "http://localhost:3000/admin"),
            ("username", "admin"),
        ],
    );
    let usernames = |s: &Engine, origin: &str| -> Vec<String> {
        list(s, origin)
            .unwrap()
            .1
            .into_iter()
            .filter_map(|l| l.username)
            .collect()
    };
    assert_eq!(
        usernames(&s, "http://localhost:3000"),
        ["admin", "next", "vite"]
    );
    assert_eq!(
        usernames(&s, "http://localhost:5173"),
        ["vite", "admin", "next"]
    );

    let origin = "http://localhost:3000";
    fill(
        &s,
        origin,
        &next,
        &[Fill::Username],
        Duration::from_secs(100),
    )
    .unwrap();
    assert_eq!(usernames(&s, origin), ["next", "admin", "vite"]);
    fill(
        &s,
        origin,
        &other,
        &[Fill::Username],
        Duration::from_secs(200),
    )
    .unwrap();
    assert_eq!(usernames(&s, origin), ["admin", "next", "vite"]);
    // Use never lifts a login over a closer one.
    fill(
        &s,
        "http://localhost:5173",
        &vite,
        &[Fill::Username],
        Duration::from_secs(300),
    )
    .unwrap();
    assert_eq!(usernames(&s, origin), ["admin", "next", "vite"]);
}

#[test]
fn a_check_without_a_username_matches_by_password_alone() {
    let mut s = loaded();
    let origin = "https://example.com";
    let alex = login(
        &mut s,
        &[("url", origin), ("username", "alex"), ("password", "old")],
    );
    login(
        &mut s,
        &[("url", origin), ("username", "sam"), ("password", "other")],
    );
    let (status, matches) = check(&s, origin, None, &Secret::new("old")).unwrap();
    assert_eq!((status, matches), (SiteStatus::Same, vec![alex]));
    let (status, matches) = check(&s, origin, None, &Secret::new("nope")).unwrap();
    assert_eq!((status, matches), (SiteStatus::New, vec![]));
    let (status, _) = check(&s, origin, Some("alex"), &Secret::new("nope")).unwrap();
    assert_eq!(status, SiteStatus::Update);
}

#[test]
fn checks_share_case_whitespace_and_password_rules_with_the_browser() {
    let mut s = loaded();
    let origin = "https://example.com";
    let alex = login(
        &mut s,
        &[("url", origin), ("username", "Alex"), ("password", "old")],
    );
    let changed = login(
        &mut s,
        &[("url", origin), ("username", "alex"), ("password", "new")],
    );
    let unnamed = login(&mut s, &[("url", origin), ("password", "anonymous")]);
    login(
        &mut s,
        &[
            ("url", "https://elsewhere.com"),
            ("username", "Alex"),
            ("password", "old"),
        ],
    );
    for (username, password, status, mut expected) in [
        (Some(" ALEX "), "old", SiteStatus::Same, vec![alex.clone()]),
        (
            Some("alex"),
            "OLD",
            SiteStatus::Update,
            vec![alex.clone(), changed],
        ),
        (Some("other"), "old", SiteStatus::New, vec![]),
        (None, "old", SiteStatus::Same, vec![alex]),
        (None, "missing", SiteStatus::New, vec![]),
        (Some("  "), "anonymous", SiteStatus::Same, vec![unnamed]),
    ] {
        let (actual, mut matches) = check(&s, origin, username, &Secret::new(password)).unwrap();
        matches.sort_by(|a, b| a.item.cmp(&b.item));
        expected.sort_by(|a, b| a.item.cmp(&b.item));
        assert_eq!((actual, matches), (status, expected));
    }
}

#[test]
fn same_password_wins_over_updates_across_vaults() {
    let mut s = loaded();
    let origin = "https://example.com";
    let first = login(
        &mut s,
        &[("url", origin), ("username", "alex"), ("password", "old")],
    );
    let vault = s.create_vault("work").unwrap();
    let second = create(
        &mut s,
        Some("work"),
        "login",
        None,
        [("url", origin), ("username", "alex"), ("password", "new")]
            .into_iter()
            .map(|(name, value)| FieldInput {
                name: name.into(),
                kind: None,
                value: value.into(),
            })
            .collect(),
    )
    .unwrap();
    let second = LoginRef {
        vault: hex(vault.as_bytes()),
        item: second.id,
    };
    for (password, expected) in [("old", first.clone()), ("new", second.clone())] {
        assert_eq!(
            check(&s, origin, Some("alex"), &Secret::new(password)).unwrap(),
            (SiteStatus::Same, vec![expected])
        );
    }
    let (status, matches) = check(&s, origin, Some("alex"), &Secret::new("different")).unwrap();
    assert_eq!(status, SiteStatus::Update);
    assert_eq!(matches.len(), 2);
    assert!(matches.contains(&first) && matches.contains(&second));
}

#[test]
fn page_updates_change_only_the_password() {
    let mut s = loaded();
    let password = Secret::new("original");
    let (saved, _) = super::save(
        &mut s,
        save("Original title", "https://example.com/login", &password),
    )
    .unwrap();
    let page = site("https://example.com").unwrap();
    let (_, before) = find(&s, &saved, &page).unwrap();
    let password = Secret::new("replacement");
    let mut update = save("Replacement title", "https://example.com/other", &password);
    update.login = Some(&saved);
    update.username = "different";
    assert_eq!(super::save(&mut s, update).unwrap(), (saved.clone(), false));
    let (_, mut after) = find(&s, &saved, &page).unwrap();
    assert_eq!(value(&after, "password"), Some("replacement"));
    assert!(after.password_changed.is_some());
    assert_ne!(after.password_entry, before.password_entry);
    after
        .fields
        .insert("password".into(), before.fields["password"].clone());
    after.password_entry = before.password_entry;
    after.password_changed = before.password_changed.clone();
    assert_eq!(after, before);
}

/// A "Sign in with" login lists its provider and the username of the
/// login it signs in with, and fills nothing of that login.
#[test]
fn sign_in_logins_name_their_account_and_fill_none_of_it() {
    let mut s = loaded();
    let google = login(
        &mut s,
        &[
            ("url", "https://accounts.google.com"),
            ("username", "sam@gmail.com"),
            ("password", "google-pw"),
        ],
    );
    let notion = login(
        &mut s,
        &[
            ("url", "https://www.notion.so"),
            ("sign-in-with", "google"),
            ("sign-in-account", &google.item),
        ],
    );
    let gone = "0".repeat(32);
    let github = login(
        &mut s,
        &[("url", "https://www.github.com"), ("password", "github-pw")],
    );
    login(
        &mut s,
        &[
            ("url", "https://notion.so"),
            ("sign-in-with", "github"),
            ("sign-in-account", &github.item),
        ],
    );
    login(
        &mut s,
        &[
            ("url", "https://notion.so/login"),
            ("sign-in-with", "github"),
            ("sign-in-account", &gone),
        ],
    );
    let (_, logins) = list(&s, "https://www.notion.so").unwrap();
    let sign_ins: Vec<_> = logins.iter().map(|l| l.sign_in.clone()).collect();
    assert!(sign_ins.contains(&Some(SignIn {
        provider: "google".into(),
        account: Some("sam@gmail.com".into()),
    })));
    assert!(sign_ins.contains(&Some(SignIn {
        provider: "github".into(),
        account: None,
    })));
    assert!(sign_ins.contains(&Some(SignIn {
        provider: "github".into(),
        account: Some("github.com".into()),
    })));
    assert!(
        logins
            .iter()
            .all(|l| !l.has_password && l.username.is_none())
    );
    let (_, logins) = list(&s, "https://accounts.google.com").unwrap();
    assert_eq!(logins[0].sign_in, None);
    let values = fill(
        &s,
        "https://www.notion.so",
        &notion,
        &[Fill::Username, Fill::Password],
        Duration::ZERO,
    )
    .unwrap();
    assert_eq!(values, SiteValues::default());
}

#[test]
fn page_titles_become_item_names() {
    assert_eq!(
        item_name("  GitHub \t\n·  Sign in\u{7}\u{0}x "),
        "GitHub · Sign in x"
    );
    assert_eq!(item_name("\u{7}\n "), "");
    let long = "é".repeat(127) + " and more";
    assert_eq!(item_name(&long), "é".repeat(127));
    assert_eq!(item_name(&"a".repeat(300)).chars().count(), 128);

    let mut s = loaded();
    let password = Secret::new("pw");
    let title = format!("Example\t—\nSign in {}\u{1b}", "x".repeat(200));
    let (saved, created) =
        super::save(&mut s, save(&title, "https://example.com/login", &password)).unwrap();
    assert!(created);
    let vault = s.resolve(None).unwrap();
    let item = s
        .vault(&vault)
        .items()
        .into_iter()
        .find(|i| hex(i.id.as_bytes()) == saved.item)
        .unwrap();
    let name = item.name.unwrap();
    assert!(name.starts_with("Example — Sign in xxx"), "{name:?}");
    assert_eq!(name.chars().count(), 128);
    for title in ["", " \t\n\u{7}", "example.com"] {
        let (saved, _) =
            super::save(&mut s, save(title, "https://example.com/login", &password)).unwrap();
        let (_, item) = find(&s, &saved, &site("https://example.com").unwrap()).unwrap();
        assert_eq!(item.name, None);
        assert_eq!(autofill::login_title(&item), "example.com");
    }
}

#[test]
fn saved_urls_are_secure_pages_on_the_site() {
    let mut s = loaded();
    let password = Secret::new("pw");
    for url in [
        "javascript:alert(1)//example.com",
        "data:text/html,example.com",
        "ftp://example.com",
        "http://example.com/login",
        "example.com",
        "https://example.com/a b",
    ] {
        assert!(
            super::save(&mut s, save("Example", url, &password)).is_err(),
            "{url}"
        );
    }
    let error = super::save(&mut s, save("Example", "https://evil.com", &password)).unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<deadbolt_proto::daemon::DaemonError>()
            .map(|e| e.code),
        Some(ErrorCode::DomainMismatch)
    );
    assert!(
        s.vault(&s.resolve(None).unwrap()).items().is_empty(),
        "nothing saved"
    );
    super::save(
        &mut s,
        save("Example", "  https://example.com/login\n", &password),
    )
    .unwrap();
    let vault = s.resolve(None).unwrap();
    let items = s.vault(&vault).items();
    assert_eq!(items[0].fields["url"].value, "https://example.com/login");
}

/// x.com is twitter.com's `to` site in Apple's shared-credentials list: a
/// twitter.com login is listed and filled there, but x.com never saves,
/// links or updates one.
mod shared_sites {
    use super::*;

    const X: &str = "https://x.com";

    fn twitter(s: &mut Engine, password: &str) -> LoginRef {
        login(
            s,
            &[
                ("url", "https://twitter.com/login"),
                ("username", "alex"),
                ("password", password),
            ],
        )
    }

    fn checked(s: &Engine, username: Option<&str>, password: &str) -> (SiteStatus, Vec<LoginRef>) {
        check(s, X, username, &Secret::new(password)).unwrap()
    }

    fn mismatch(error: anyhow::Error) -> bool {
        crate::code(&error) == Some(ErrorCode::DomainMismatch)
    }

    #[test]
    fn a_shared_login_lists_and_fills_but_is_never_updated() {
        let mut s = loaded();
        let bird = twitter(&mut s, "bird-pw");
        assert_eq!(list(&s, X).unwrap().1[0].login, bird);
        let values = fill(&s, X, &bird, &[Fill::Password], Duration::ZERO).unwrap();
        assert_eq!(
            values.password.as_ref().map(Secret::expose),
            Some("bird-pw")
        );

        // A new password for the same username is a new login here, not an
        // update of twitter.com's; the same password is already saved.
        assert_eq!(
            checked(&s, Some("alex"), "other-pw"),
            (SiteStatus::New, vec![])
        );
        assert_eq!(
            checked(&s, Some("alex"), "bird-pw"),
            (SiteStatus::Same, vec![])
        );
        assert_eq!(checked(&s, None, "bird-pw"), (SiteStatus::Same, vec![]));
        assert_eq!(
            checked(&s, Some("sam"), "bird-pw"),
            (SiteStatus::New, vec![])
        );

        // Nor can x.com write a new password into it.
        let password = Secret::new("clobbered");
        let update = Save {
            origin: X,
            login: Some(&bird),
            ..save("X", "https://x.com/settings", &password)
        };
        assert!(mismatch(crate::autofill::save(&mut s, update).unwrap_err()));
        let values = fill(&s, X, &bird, &[Fill::Password], Duration::ZERO).unwrap();
        assert_eq!(
            values.password.as_ref().map(Secret::expose),
            Some("bird-pw")
        );
    }

    #[test]
    fn updates_go_to_the_sites_own_logins_closest_first() {
        let mut s = loaded();
        twitter(&mut s, "bird-pw");
        // Made farthest first, so item-id order would rarely be rank order.
        let made: Vec<LoginRef> = ["https://help.x.com", "http://x.com", "https://x.com/login"]
            .into_iter()
            .map(|url| {
                login(
                    &mut s,
                    &[("url", url), ("username", "alex"), ("password", "old")],
                )
            })
            .collect();
        let closest_first: Vec<LoginRef> = made.into_iter().rev().collect();
        assert_eq!(
            checked(&s, Some("alex"), "new-pw"),
            (SiteStatus::Update, closest_first)
        );
    }

    #[test]
    fn a_page_saves_only_urls_of_its_own_site() {
        let mut s = loaded();
        let password = Secret::new("pw");
        let planted = Save {
            origin: X,
            ..save("Twitter", "https://twitter.com/login", &password)
        };
        assert!(mismatch(
            crate::autofill::save(&mut s, planted).unwrap_err()
        ));
        let own = Save {
            origin: X,
            ..save("X", "https://x.com/login", &password)
        };
        assert!(crate::autofill::save(&mut s, own).unwrap().1);
    }

    #[test]
    fn a_page_links_only_itself_though_a_shared_site_is_linked() {
        let mut s = loaded();
        let google = login(
            &mut s,
            &[
                ("url", "https://accounts.google.com"),
                ("username", "alex@gmail.com"),
                ("password", "hunter22"),
            ],
        );
        fn linking<'a>(account: &'a LoginRef, origin: &'a str, url: &'a str) -> Link<'a> {
            Link {
                origin,
                title: "",
                url,
                provider: "google",
                account,
                test_hosts: false,
            }
        }
        let twitter = "https://twitter.com";
        let (on_twitter, made) = link(&mut s, linking(&google, twitter, twitter)).unwrap();
        assert!(made);
        // x.com is offered twitter.com's link, but gets one of its own.
        assert!(list(&s, X).unwrap().1.iter().any(|l| l.login == on_twitter));
        assert!(mismatch(
            link(&mut s, linking(&google, X, "https://twitter.com/login")).unwrap_err()
        ));
        let (on_x, made) = link(&mut s, linking(&google, X, X)).unwrap();
        assert!(made && on_x != on_twitter);
        assert_eq!(link(&mut s, linking(&google, X, X)).unwrap(), (on_x, false));
    }
}
