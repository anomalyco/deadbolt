//! New passwords for web sign-up and change-password forms, and the
//! pending ones the agent holds until a sign-up or change goes through.
//!
//! A site's rules come from Apple's password-manager-resources quirks
//! (`data/password-rules`, compiled in), else from the field's
//! `passwordrules` attribute. Rules that allow only weak passwords get none.
//!
//! Nothing is saved when a password is made. It's a candidate, bound to the
//! page's origin, until the extension says it went into the page (it's then
//! pending) or didn't (it's forgotten). A pending one waits until the
//! extension saves it after a successful submit, it expires, newer pending
//! ones push it out or the agent locks (the session holding it is dropped
//! and the values wiped). Candidates never push out a pending password.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use deadbolt_core::password_rules::{self, CharSet, Refused, Rules};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{ErrorCode, fail};
use crate::protocol::{PagePassword, Secret};
use crate::site::{Site, registrable_domain, url_host};

/// How long a generated password waits for its sign-up to go through.
pub const PENDING_TTL: Duration = Duration::from_secs(15 * 60);
/// How long a candidate waits to go into the page.
pub const CANDIDATE_TTL: Duration = Duration::from_secs(2 * 60);
/// The most pending passwords held at once; the oldest goes first.
const MAX_PENDING: usize = 16;
/// The most candidates held at once, apart from those; the oldest goes first.
const MAX_CANDIDATES: usize = 4;
/// The longest `passwordrules` or `pattern` set taken from a page.
const MAX_RULES: usize = 1024;

#[derive(Deserialize)]
struct Quirk {
    #[serde(rename = "password-rules")]
    rules: String,
}

static QUIRKS: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    serde_json::from_str::<HashMap<String, Quirk>>(include_str!(
        "../../data/password-rules/password-rules.json"
    ))
    .map(|quirks| quirks.into_iter().map(|(k, v)| (k, v.rules)).collect())
    .unwrap_or_default()
});

/// The quirk for `host`, or for the nearest parent of it on its site.
fn quirk(host: &str) -> Option<&'static str> {
    let site = registrable_domain(host);
    let mut name = host;
    loop {
        if let Some(rules) = QUIRKS.get(name) {
            return Some(rules);
        }
        if name == site {
            return None;
        }
        name = name.split_once('.')?.1;
    }
}

/// What a page says about the field a password is for.
#[derive(Debug, Default)]
pub struct FieldRules<'a> {
    pub rules: Option<&'a str>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub allowed: Option<&'a str>,
}

impl<'a> FieldRules<'a> {
    pub fn of(field: &'a crate::protocol::SiteField) -> Self {
        Self {
            rules: field.rules.as_deref(),
            min_length: field.min_length,
            max_length: field.max_length,
            allowed: field.allowed.as_deref(),
        }
    }
}

/// The rules and limits a password for the field on the page at `origin`
/// follows.
fn rules_for(origin: &str, field: &FieldRules) -> Result<(Rules, password_rules::Field)> {
    Site::from_origin(origin).map_err(|reason| anyhow!("{origin}: {reason}"))?;
    let host = url_host(origin).ok_or_else(|| anyhow!("{origin}: no host"))?;
    if field.rules.is_some_and(|r| r.len() > MAX_RULES)
        || field.allowed.is_some_and(|a| a.len() > MAX_RULES)
    {
        return Err(anyhow!("the field's rules are too long"));
    }
    let rules = quirk(&host)
        .or(field.rules)
        .map(Rules::parse)
        .unwrap_or_default();
    let limits = password_rules::Field {
        min_length: field.min_length,
        max_length: field.max_length,
        allowed: field.allowed.map(CharSet::of),
    };
    Ok((rules, limits))
}

fn refused(refused: Refused) -> anyhow::Error {
    match refused {
        Refused::Weak => fail(ErrorCode::Weak, refused.to_string()),
        Refused::Impossible => fail(ErrorCode::Failed, refused.to_string()),
    }
}

/// Whether [`generate`] would make a password for the field.
pub fn check(origin: &str, field: &FieldRules) -> Result<()> {
    let (rules, limits) = rules_for(origin, field)?;
    password_rules::strength(&rules, limits).map_err(refused)?;
    Ok(())
}

/// A password for the field on the page at `origin`.
pub fn generate(origin: &str, field: &FieldRules) -> Result<Zeroizing<String>> {
    let (rules, limits) = rules_for(origin, field)?;
    password_rules::generate(&rules, limits).map_err(refused)
}

struct Held {
    id: String,
    origin: String,
    password: Secret,
    made: Instant,
}

/// Generated passwords: candidates not yet in a page, and pending ones
/// waiting for their sign-up to go through.
#[derive(Default)]
pub struct Pending {
    candidates: Vec<Held>,
    pending: Vec<Held>,
}

impl Pending {
    /// Holds `password` for `origin` as a candidate; returns the id that
    /// names it. Only another candidate makes room for it.
    pub fn offer(&mut self, origin: &str, password: Secret, now: Instant) -> Result<String> {
        self.expire(now);
        if self.candidates.len() >= MAX_CANDIDATES {
            self.candidates.remove(0);
        }
        let id = deadbolt_core::password::generate(16, false)?.to_string();
        self.candidates.push(Held {
            id: id.clone(),
            origin: origin.to_string(),
            password,
            made: now,
        });
        Ok(id)
    }

    /// The candidate `id` went into the page at `origin`: it's pending from
    /// now, and the oldest pending password makes room for it.
    pub fn keep(&mut self, origin: &str, id: &str, now: Instant) -> Result<()> {
        self.expire(now);
        let at = self
            .candidates
            .iter()
            .position(|h| h.id == id && h.origin == origin)
            .ok_or_else(|| fail(ErrorCode::NotFound, "the generated password has expired"))?;
        let mut held = self.candidates.remove(at);
        held.made = now;
        if self.pending.len() >= MAX_PENDING {
            self.pending.remove(0);
        }
        self.pending.push(held);
        Ok(())
    }

    /// Forgets the candidate `id` for `origin`.
    pub fn drop_candidate(&mut self, origin: &str, id: &str) {
        self.candidates
            .retain(|h| !(h.id == id && h.origin == origin));
    }

    /// The password `password` stands for on the page at `origin`. A
    /// generated one must be pending for that origin.
    pub fn resolve(
        &mut self,
        origin: &str,
        password: &PagePassword,
        now: Instant,
    ) -> Result<Secret> {
        self.expire(now);
        match password {
            PagePassword::Typed(secret) => Ok(secret.clone()),
            PagePassword::Generated(id) => self
                .pending
                .iter()
                .find(|h| &h.id == id && h.origin == origin)
                .map(|h| h.password.clone())
                .ok_or_else(|| fail(ErrorCode::NotFound, "the generated password has expired")),
        }
    }

    /// Forgets the password `password` names, once it's saved.
    pub fn saved(&mut self, password: &PagePassword) {
        if let PagePassword::Generated(id) = password {
            self.pending.retain(|h| &h.id != id);
        }
    }

    fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|h| now.saturating_duration_since(h.made) < PENDING_TTL);
        self.candidates
            .retain(|h| now.saturating_duration_since(h.made) < CANDIDATE_TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_quirk_parses_and_generates_or_is_weak() {
        assert!(QUIRKS.len() > 100, "the vendored rules load");
        let mut weak = 0;
        for (domain, text) in QUIRKS.iter() {
            let rules = Rules::parse(text);
            let password = match password_rules::generate(&rules, password_rules::Field::default())
            {
                Err(Refused::Weak) => {
                    weak += 1;
                    continue;
                }
                result => result.unwrap_or_else(|_| panic!("{domain}: {text}")),
            };
            if let Some(max) = rules.max_length {
                assert!(password.len() <= max, "{domain}");
            }
            if let Some(min) = rules.min_length {
                assert!(password.len() >= min.min(256), "{domain}");
            }
        }
        // Sites that cap passwords at a few digits, or at eight characters.
        assert!(weak < QUIRKS.len() / 10, "{weak} weak");
    }

    #[test]
    fn quirks_apply_to_the_site_and_its_subdomains() {
        // "minlength: 6; maxlength: 16;" for 163.com.
        assert_eq!(quirk("163.com"), Some("minlength: 6; maxlength: 16;"));
        assert_eq!(quirk("mail.163.com"), quirk("163.com"));
        assert_eq!(quirk("example.com"), None);
        let password = generate("https://mail.163.com", &FieldRules::default()).unwrap();
        assert_eq!(password.len(), 16);
    }

    #[test]
    fn a_quirk_wins_over_the_page_and_the_field_limits_both() {
        let field = FieldRules {
            rules: Some("minlength: 30"),
            ..FieldRules::default()
        };
        assert_eq!(generate("https://163.com", &field).unwrap().len(), 16);
        assert_eq!(generate("https://example.com", &field).unwrap().len(), 30);
        let digits = FieldRules {
            max_length: Some(24),
            allowed: Some("0123456789"),
            ..FieldRules::default()
        };
        let digits = generate("https://example.com", &digits).unwrap();
        assert!(digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()));
        assert!(generate("http://example.com", &FieldRules::default()).is_err());
    }

    #[test]
    fn weak_fields_are_refused_with_their_own_code() {
        let code = |result: Result<()>| crate::client::code(&result.unwrap_err());
        let pin = FieldRules {
            max_length: Some(8),
            allowed: Some("0123456789"),
            ..FieldRules::default()
        };
        assert_eq!(
            code(check("https://example.com", &pin)),
            Some(ErrorCode::Weak)
        );
        assert_eq!(
            code(generate("https://example.com", &pin).map(drop)),
            Some(ErrorCode::Weak)
        );
        let one = FieldRules {
            rules: Some("allowed: [a]; minlength: 100"),
            ..FieldRules::default()
        };
        assert_eq!(
            code(check("https://example.com", &one)),
            Some(ErrorCode::Weak)
        );
        let none = FieldRules {
            rules: Some("minlength: 30; maxlength: 10"),
            ..FieldRules::default()
        };
        assert_eq!(
            code(check("https://example.com", &none)),
            Some(ErrorCode::Failed)
        );
        assert!(check("https://example.com", &FieldRules::default()).is_ok());
    }

    #[test]
    fn pending_passwords_are_bound_to_their_origin_and_expire() {
        let mut pending = Pending::default();
        let t0 = Instant::now();
        let id = pending
            .offer("https://example.com", Secret::new("hunter22"), t0)
            .unwrap();
        let generated = PagePassword::Generated(id.clone());
        assert!(
            pending
                .resolve("https://example.com", &generated, t0)
                .is_err(),
            "a candidate isn't pending until it's in the page"
        );
        assert!(pending.keep("https://evil.example.com", &id, t0).is_err());
        pending.keep("https://example.com", &id, t0).unwrap();
        let got = pending
            .resolve("https://example.com", &generated, t0)
            .unwrap();
        assert_eq!(got.expose(), "hunter22");
        assert!(
            pending
                .resolve("https://evil.example.com", &generated, t0)
                .is_err()
        );
        assert!(
            pending
                .resolve(
                    "https://example.com",
                    &PagePassword::Generated("nope".into()),
                    t0
                )
                .is_err()
        );
        assert!(
            pending
                .resolve("https://example.com", &generated, t0 + PENDING_TTL)
                .is_err(),
            "expired"
        );

        let id = pending
            .offer("https://example.com", Secret::new("again"), t0)
            .unwrap();
        pending.keep("https://example.com", &id, t0).unwrap();
        let generated = PagePassword::Generated(id);
        pending.saved(&generated);
        assert!(
            pending
                .resolve("https://example.com", &generated, t0)
                .is_err(),
            "saved"
        );
        for n in 0..MAX_PENDING + 3 {
            let id = pending
                .offer("https://example.com", Secret::new(format!("{n}")), t0)
                .unwrap();
            pending.keep("https://example.com", &id, t0).unwrap();
        }
        assert_eq!(pending.pending.len(), MAX_PENDING);
    }

    #[test]
    fn candidates_never_push_out_pending_passwords() {
        let mut pending = Pending::default();
        let t0 = Instant::now();
        let origin = "https://example.com";
        let kept: Vec<String> = (0..MAX_PENDING)
            .map(|n| {
                let id = pending
                    .offer(origin, Secret::new(format!("kept {n}")), t0)
                    .unwrap();
                pending.keep(origin, &id, t0).unwrap();
                id
            })
            .collect();
        // A page turning down candidate after candidate, and menus closed
        // without a pick.
        let mut last = String::new();
        for n in 0..100 {
            last = pending
                .offer(origin, Secret::new(format!("candidate {n}")), t0)
                .unwrap();
            if n % 2 == 0 {
                pending.drop_candidate(origin, &last);
            }
        }
        for id in &kept {
            let got = pending.resolve(origin, &PagePassword::Generated(id.clone()), t0);
            assert!(got.is_ok(), "{id} was pushed out");
        }
        assert!(pending.candidates.len() <= MAX_CANDIDATES);
        // A dropped candidate can't be kept; nor one from another origin.
        let dropped = pending.offer(origin, Secret::new("x"), t0).unwrap();
        pending.drop_candidate(origin, &dropped);
        assert!(pending.keep(origin, &dropped, t0).is_err());
        assert!(pending.keep("https://other.example", &last, t0).is_err());
        // Candidates expire sooner than pending passwords.
        assert!(pending.keep(origin, &last, t0 + CANDIDATE_TTL).is_err());
    }
}
