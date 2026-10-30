//! Browser autofill: which logins belong to a web page, and the values a
//! page may have. The agent decides, not the browser host: every request
//! names the page's origin, and a login is only listed, filled or updated
//! for a page on the site of one of its URLs (see [`crate::site`]).
//!
//! A site's logins are listed closest first (see [`autofill::rank`]), then the
//! most recently filled on this device, then by title.

use std::time::Duration;

use anyhow::{Result, anyhow};
use deadbolt_core::autofill::{self, Status, item_name};
pub(super) use deadbolt_core::autofill::{otp, urls, value};
use deadbolt_core::totp::Totp;
use deadbolt_core::{Item, ItemId, VaultId};

use super::items::{create, label};
use super::session::{Loaded, hex, unhex};
use super::{ErrorCode, fail};
use crate::protocol::{
    FieldInput, Fill, LoginRef, Secret, SignIn, SiteLogin, SiteStatus, SiteValues,
};
use crate::site::{Site, page_url};

pub(super) fn site(origin: &str) -> Result<Site> {
    Site::from_origin(origin).map_err(|reason| anyhow!("{origin}: {reason}"))
}

pub(super) fn login_ref(vault: &VaultId, item: &ItemId) -> LoginRef {
    LoginRef {
        vault: hex(vault.as_bytes()),
        item: hex(item.as_bytes()),
    }
}

/// Every login on `site`, in every vault.
pub(super) fn logins<'a>(
    s: &'a Loaded,
    site: &'a Site,
) -> impl Iterator<Item = (VaultId, Item)> + 'a {
    s.vaults.iter().flat_map(move |(id, vault)| {
        vault
            .items()
            .into_iter()
            .filter(|item| item.kind == "login" && site.matches(urls(item)))
            .map(move |item| (*id, item))
    })
}

/// The login `login` names, refused unless it's on `site`.
pub(super) fn find(s: &Loaded, login: &LoginRef, site: &Site) -> Result<(VaultId, Item)> {
    let not_found = || fail(ErrorCode::NotFound, "no such login");
    let vault = VaultId::from_bytes(unhex(&login.vault).map_err(|_| not_found())?);
    let id = ItemId::from_bytes(unhex(&login.item).map_err(|_| not_found())?);
    let item = s
        .vaults
        .get(&vault)
        .and_then(|v| v.item(&id))
        .filter(|item| !item.deleted && item.kind == "login")
        .ok_or_else(not_found)?;
    if !site.matches(urls(&item)) {
        return Err(fail(
            ErrorCode::DomainMismatch,
            format!("{} isn't saved for {}", label(&item), site.domain),
        ));
    }
    Ok((vault, item))
}

fn filled_key(login: &LoginRef) -> String {
    format!("{}:{}", login.vault, login.item)
}

/// How a login signs in with another account: its `sign-in-with`, and the
/// username (else the title) of its `sign-in-account`, if that login is in
/// one of the vaults here. Nothing else of that login.
pub(super) fn sign_in(s: &Loaded, item: &Item) -> Option<SignIn> {
    let provider = value(item, "sign-in-with")?.to_string();
    let account = value(item, "sign-in-account")
        .and_then(|id| unhex(id).ok())
        .map(ItemId::from_bytes)
        .filter(|id| *id != item.id)
        .and_then(|id| {
            s.vaults
                .values()
                .find_map(|v| v.item(&id).filter(|i| !i.deleted))
        })
        .map(|account| {
            value(&account, "username")
                .map(str::to_string)
                .unwrap_or_else(|| label(&account))
        });
    Some(SignIn { provider, account })
}

pub fn list(s: &Loaded, origin: &str) -> Result<(String, Vec<SiteLogin>)> {
    let site = site(origin)?;
    let filled = s.filled();
    let mut found: Vec<_> = logins(s, &site)
        .map(|(vault, item)| {
            let login = SiteLogin {
                login: login_ref(&vault, &item.id),
                vault: s.vault(&vault).name().to_string(),
                title: label(&item),
                username: value(&item, "username").map(str::to_string),
                has_password: value(&item, "password").is_some(),
                has_otp: otp(&item).is_some_and(|f| !f.value.is_empty()),
                urls: urls(&item)
                    .filter(|url| site.matches_url(url))
                    .map(str::to_string)
                    .collect(),
                sign_in: sign_in(s, &item),
            };
            let used = filled.get(&filled_key(&login.login)).copied().unwrap_or(0);
            (autofill::rank(origin, &item, used), login)
        })
        .collect();
    found.sort_by(|(ra, a), (rb, b)| {
        ra.cmp(rb)
            .then_with(|| (&a.login.vault, &a.login.item).cmp(&(&b.login.vault, &b.login.item)))
    });
    Ok((site.domain, found.into_iter().map(|(_, l)| l).collect()))
}

/// The values `want` names that the login has, at `now` for a code.
pub fn fill(
    s: &Loaded,
    origin: &str,
    login: &LoginRef,
    want: &[Fill],
    now: Duration,
) -> Result<SiteValues> {
    let site = site(origin)?;
    let (_, item) = find(s, login, &site)?;
    let mut values = SiteValues::default();
    for fill in want {
        match fill {
            Fill::Username => values.username = value(&item, "username").map(str::to_string),
            Fill::Password => values.password = value(&item, "password").map(Secret::new),
            Fill::Totp => {
                let Some(field) = otp(&item).filter(|f| !f.value.is_empty()) else {
                    continue;
                };
                let totp = Totp::parse(&field.value).map_err(|e| {
                    anyhow!("the one-time password of {} is invalid: {e}", label(&item))
                })?;
                values.totp = Some(Secret::new(totp.code(now.as_secs())));
            }
        }
    }
    s.set_filled(filled_key(login), now.as_secs())?;
    Ok(values)
}

/// Without a username, a login with any username and the same password is
/// `same`, and nothing is `update`.
pub fn check(
    s: &Loaded,
    origin: &str,
    username: Option<&str>,
    password: &Secret,
) -> Result<(SiteStatus, Vec<LoginRef>)> {
    let site = site(origin)?;
    let mut status = Status::New;
    let mut matches = Vec::new();
    for (vault, saved) in &s.vaults {
        let items = saved.items();
        let (checked, ids) = autofill::check(
            items
                .iter()
                .filter(|item| item.kind == "login" && site.matches(urls(item))),
            username,
            password.expose(),
        );
        if checked > status {
            status = checked;
            matches.clear();
        }
        if checked == status {
            matches.extend(ids.iter().map(|id| login_ref(vault, id)));
        }
    }
    let status = match status {
        Status::New => SiteStatus::New,
        Status::Update => SiteStatus::Update,
        Status::Same => SiteStatus::Same,
    };
    Ok((status, matches))
}

/// What to save from a page.
pub struct Save<'a> {
    pub origin: &'a str,
    pub login: Option<&'a LoginRef>,
    pub title: &'a str,
    pub url: &'a str,
    pub username: &'a str,
    pub password: &'a Secret,
}

/// Saves a new login in the default vault, or `save.login`'s new
/// password. Returns the login and whether it is new.
pub fn save(s: &mut Loaded, save: Save) -> Result<(LoginRef, bool)> {
    let site = site(save.origin)?;
    if save.password.expose().is_empty() {
        return Err(anyhow!("the password is empty"));
    }
    let url = page_url(save.url).map_err(|reason| anyhow!("{reason}"))?;
    if !site.matches_url(url) {
        return Err(fail(
            ErrorCode::DomainMismatch,
            format!("{url} isn't on {}", site.domain),
        ));
    }
    if let Some(login) = save.login {
        let (vault, item) = find(s, login, &site)?;
        let today = crate::config::today_utc();
        s.update(vault, |v, secret| {
            Ok(v.write(
                secret,
                autofill::password_update_at(item.id, save.password.expose(), &today),
            )?)
        })?;
        return Ok((login_ref(&vault, &item.id), false));
    }
    let vault = s.resolve(None)?;
    let input = |name: &str, value: &str| FieldInput {
        name: name.into(),
        kind: None,
        value: value.into(),
    };
    let mut inputs = vec![input("url", url)];
    if !save.username.trim().is_empty() {
        inputs.push(input("username", save.username.trim()));
    }
    inputs.push(input("password", save.password.expose()));
    let title = item_name(save.title);
    let name = Some(title).filter(|t| !t.is_empty() && *t != site.domain);
    let info = create(s, None, "login", name, inputs)?;
    Ok((
        LoginRef {
            vault: hex(vault.as_bytes()),
            item: info.id,
        },
        true,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn login(s: &mut Loaded, fields: &[(&str, &str)]) -> LoginRef {
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
            username: "kit",
            password,
        }
    }

    #[test]
    fn one_time_passwords_fill_as_the_current_code() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
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

    fn titles(s: &Loaded, origin: &str) -> Vec<String> {
        list(s, origin)
            .unwrap()
            .1
            .into_iter()
            .map(|l| l.title)
            .collect()
    }

    #[test]
    fn logins_rank_by_origin_host_parent_site_then_use_then_title() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
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
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
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
        let usernames = |s: &Loaded, origin: &str| -> Vec<String> {
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
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let origin = "https://example.com";
        let kit = login(
            &mut s,
            &[("url", origin), ("username", "kit"), ("password", "old")],
        );
        login(
            &mut s,
            &[("url", origin), ("username", "dax"), ("password", "other")],
        );
        let (status, matches) = check(&s, origin, None, &Secret::new("old")).unwrap();
        assert_eq!((status, matches), (SiteStatus::Same, vec![kit]));
        let (status, matches) = check(&s, origin, None, &Secret::new("nope")).unwrap();
        assert_eq!((status, matches), (SiteStatus::New, vec![]));
        let (status, _) = check(&s, origin, Some("kit"), &Secret::new("nope")).unwrap();
        assert_eq!(status, SiteStatus::Update);
    }

    #[test]
    fn checks_share_case_whitespace_and_password_rules_with_the_browser() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let origin = "https://example.com";
        let kit = login(
            &mut s,
            &[("url", origin), ("username", "Kit"), ("password", "old")],
        );
        let changed = login(
            &mut s,
            &[("url", origin), ("username", "kit"), ("password", "new")],
        );
        let unnamed = login(&mut s, &[("url", origin), ("password", "anonymous")]);
        login(
            &mut s,
            &[
                ("url", "https://elsewhere.com"),
                ("username", "Kit"),
                ("password", "old"),
            ],
        );
        for (username, password, status, mut expected) in [
            (Some(" KIT "), "old", SiteStatus::Same, vec![kit.clone()]),
            (
                Some("kit"),
                "OLD",
                SiteStatus::Update,
                vec![kit.clone(), changed],
            ),
            (Some("other"), "old", SiteStatus::New, vec![]),
            (None, "old", SiteStatus::Same, vec![kit]),
            (None, "missing", SiteStatus::New, vec![]),
            (Some("  "), "anonymous", SiteStatus::Same, vec![unnamed]),
        ] {
            let (actual, mut matches) =
                check(&s, origin, username, &Secret::new(password)).unwrap();
            matches.sort_by(|a, b| a.item.cmp(&b.item));
            expected.sort_by(|a, b| a.item.cmp(&b.item));
            assert_eq!((actual, matches), (status, expected));
        }
    }

    #[test]
    fn same_password_wins_over_updates_across_vaults() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let origin = "https://example.com";
        let first = login(
            &mut s,
            &[("url", origin), ("username", "kit"), ("password", "old")],
        );
        let vault = s.create_vault("work").unwrap();
        let second = create(
            &mut s,
            Some("work"),
            "login",
            None,
            [("url", origin), ("username", "kit"), ("password", "new")]
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
                check(&s, origin, Some("kit"), &Secret::new(password)).unwrap(),
                (SiteStatus::Same, vec![expected])
            );
        }
        let (status, matches) = check(&s, origin, Some("kit"), &Secret::new("different")).unwrap();
        assert_eq!(status, SiteStatus::Update);
        assert_eq!(matches.len(), 2);
        assert!(matches.contains(&first) && matches.contains(&second));
    }

    #[test]
    fn page_updates_change_only_the_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
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
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let google = login(
            &mut s,
            &[
                ("url", "https://accounts.google.com"),
                ("username", "dax@gmail.com"),
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
            account: Some("dax@gmail.com".into()),
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

        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
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
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
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
        let error =
            super::save(&mut s, save("Example", "https://evil.com", &password)).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<crate::client::AgentError>()
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
}
