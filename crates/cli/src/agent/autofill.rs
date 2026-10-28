//! Browser autofill: which logins belong to a web page, and the values a
//! page may have. The agent decides, not the browser host: every request
//! names the page's origin, and a login is only listed, filled or updated
//! for a page on the site of one of its URLs (see [`crate::site`]).

use std::time::Duration;

use anyhow::{Result, anyhow};
use deadbolt_core::totp::Totp;
use deadbolt_core::{
    DataOp, Field, FieldType, Item, ItemId, VaultId, item::check_new_value, schema,
};

use super::items::{create, label};
use super::session::{Loaded, hex, unhex};
use super::{ErrorCode, fail};
use crate::protocol::{
    FieldInput, Fill, LoginRef, Secret, SignIn, SiteLogin, SiteStatus, SiteValues,
};
use crate::site::{Site, page_url};

fn site(origin: &str) -> Result<Site> {
    Site::from_origin(origin).map_err(|reason| anyhow!("{origin}: {reason}"))
}

fn value<'a>(item: &'a Item, field: &str) -> Option<&'a str> {
    item.fields
        .get(field)
        .map(|f| f.value.as_str())
        .filter(|v| !v.is_empty())
}

/// A login's URLs: its fields of type url (`url`, and `url-2`… from imports).
fn urls(item: &Item) -> impl Iterator<Item = &str> {
    item.fields
        .values()
        .filter(|f| f.kind == FieldType::Url)
        .map(|f| f.value.as_str())
}

/// The `otp` field, else the first of type otp, as `ItemCode` picks it.
fn otp(item: &Item) -> Option<&Field> {
    item.fields
        .get("otp")
        .filter(|f| f.kind == FieldType::Otp)
        .or_else(|| item.fields.values().find(|f| f.kind == FieldType::Otp))
}

fn login_ref(vault: &VaultId, item: &ItemId) -> LoginRef {
    LoginRef {
        vault: hex(vault.as_bytes()),
        item: hex(item.as_bytes()),
    }
}

/// Every login on `site`, in every vault.
fn logins<'a>(s: &'a Loaded, site: &'a Site) -> impl Iterator<Item = (VaultId, Item)> + 'a {
    s.vaults.iter().flat_map(move |(id, vault)| {
        vault
            .items()
            .into_iter()
            .filter(|item| item.kind == "login" && site.matches(urls(item)))
            .map(move |item| (*id, item))
    })
}

/// The login `login` names, refused unless it's on `site`.
fn find(s: &Loaded, login: &LoginRef, site: &Site) -> Result<(VaultId, Item)> {
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

/// How a login signs in with another account: its `sign-in-with`, and the
/// username (else the title) of its `sign-in-account`, if that login is in
/// one of the vaults here. Nothing else of that login.
fn sign_in(s: &Loaded, item: &Item) -> Option<SignIn> {
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
    let mut found: Vec<SiteLogin> = logins(s, &site)
        .map(|(vault, item)| SiteLogin {
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
        })
        .collect();
    found.sort_by(|a, b| {
        (
            a.title.to_lowercase(),
            &a.username,
            &a.login.vault,
            &a.login.item,
        )
            .cmp(&(
                b.title.to_lowercase(),
                &b.username,
                &b.login.vault,
                &b.login.item,
            ))
    });
    Ok((site.domain, found))
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
    Ok(values)
}

fn same_username(saved: Option<&str>, typed: &str) -> bool {
    saved.unwrap_or_default().trim().to_lowercase() == typed.trim().to_lowercase()
}

/// Constant-time: BLAKE3 hashes compare in constant time, and hashing
/// first hides the lengths too.
fn same_password(saved: Option<&str>, typed: &str) -> bool {
    blake3::hash(saved.unwrap_or_default().as_bytes()) == blake3::hash(typed.as_bytes())
}

pub fn check(
    s: &Loaded,
    origin: &str,
    username: &str,
    password: &Secret,
) -> Result<(SiteStatus, Vec<LoginRef>)> {
    let site = site(origin)?;
    let mut same = Vec::new();
    let mut other = Vec::new();
    for (vault, item) in logins(s, &site) {
        if !same_username(value(&item, "username"), username) {
            continue;
        }
        let login = login_ref(&vault, &item.id);
        if same_password(value(&item, "password"), password.expose()) {
            same.push(login);
        } else {
            other.push(login);
        }
    }
    Ok(if !same.is_empty() {
        (SiteStatus::Same, same)
    } else if !other.is_empty() {
        (SiteStatus::Update, other)
    } else {
        (SiteStatus::New, other)
    })
}

/// The longest item name the vault takes.
const MAX_NAME: usize = 128;

/// A page title as an item name: runs of spaces and control characters
/// become one space, trimmed, and cut to [`MAX_NAME`] characters.
fn item_name(title: &str) -> String {
    let mut name = String::new();
    for word in title.split(|c: char| c.is_whitespace() || c.is_control()) {
        if word.is_empty() {
            continue;
        }
        if !name.is_empty() {
            name.push(' ');
        }
        name.push_str(word);
    }
    if let Some((end, _)) = name.char_indices().nth(MAX_NAME) {
        name.truncate(end);
        name.truncate(name.trim_end().len());
    }
    name
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
        let kind = schema("login")
            .and_then(|s| s.field("password"))
            .map_or(FieldType::Secret, |f| f.kind.clone());
        let field = Field::new(kind, save.password.expose());
        check_new_value("password", &field)?;
        s.update(vault, |v, secret| {
            Ok(v.write(secret, vec![DataOp::set(item.id, "password", field)])?)
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
