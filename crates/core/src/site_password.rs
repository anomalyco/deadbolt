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
use std::time::Duration;

use crate::password_rules::{self, CharSet, Refused, Rules};
use serde::Deserialize;
use zeroize::Zeroizing;

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
        "../data/password-rules/password-rules.json"
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Origin(String),
    #[error("the field's rules are too long")]
    RulesTooLong,
    #[error(transparent)]
    Refused(#[from] Refused),
    #[error("the generated password has expired")]
    Expired,
    #[error(transparent)]
    Identifier(#[from] crate::password::LengthError),
}

type Result<T> = std::result::Result<T, Error>;

/// The rules and limits a password for the field on the page at `origin`
/// follows.
fn rules_for(origin: &str, field: &FieldRules) -> Result<(Rules, password_rules::Field)> {
    Site::from_origin(origin).map_err(|reason| Error::Origin(format!("{origin}: {reason}")))?;
    let host = url_host(origin).ok_or_else(|| Error::Origin(format!("{origin}: no host")))?;
    if field.rules.is_some_and(|r| r.len() > MAX_RULES)
        || field.allowed.is_some_and(|a| a.len() > MAX_RULES)
    {
        return Err(Error::RulesTooLong);
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

/// Whether [`generate`] would make a password for the field.
pub fn check(origin: &str, field: &FieldRules) -> Result<()> {
    let (rules, limits) = rules_for(origin, field)?;
    password_rules::strength(&rules, limits).map_err(Error::from)?;
    Ok(())
}

/// A password for the field on the page at `origin`.
pub fn generate(origin: &str, field: &FieldRules) -> Result<Zeroizing<String>> {
    let (rules, limits) = rules_for(origin, field)?;
    password_rules::generate(&rules, limits).map_err(Error::from)
}

struct Held {
    id: String,
    origin: String,
    password: Zeroizing<String>,
    made: Duration,
}

/// Generated passwords: candidates not yet in a page, and pending ones
/// waiting for their sign-up to go through. Timestamps are elapsed time from
/// a caller-owned monotonic clock; the same clock must serve every operation.
#[derive(Default)]
pub struct Pending {
    candidates: Vec<Held>,
    pending: Vec<Held>,
}

impl Pending {
    /// Holds `password` for `origin` as a candidate; returns the id that
    /// names it. Only another candidate makes room for it.
    pub fn offer(
        &mut self,
        origin: &str,
        password: Zeroizing<String>,
        now: Duration,
    ) -> Result<String> {
        self.expire(now);
        if self.candidates.len() >= MAX_CANDIDATES {
            self.candidates.remove(0);
        }
        let id = crate::password::generate(16, false)?.to_string();
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
    pub fn keep(&mut self, origin: &str, id: &str, now: Duration) -> Result<()> {
        self.expire(now);
        let at = self
            .candidates
            .iter()
            .position(|h| h.id == id && h.origin == origin)
            .ok_or(Error::Expired)?;
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

    /// The pending password named by `id` on the page at `origin`.
    /// Candidates cannot be resolved before they are kept.
    pub fn resolve(&mut self, origin: &str, id: &str, now: Duration) -> Result<Zeroizing<String>> {
        self.expire(now);
        self.pending
            .iter()
            .find(|h| h.id == id && h.origin == origin)
            .map(|h| h.password.clone())
            .ok_or(Error::Expired)
    }

    /// Forgets a pending password after the caller durably saves it.
    pub fn saved(&mut self, id: &str) {
        self.pending.retain(|h| h.id != id);
    }

    /// Wipes expired values, including on requests using a typed password.
    pub fn expire(&mut self, now: Duration) {
        self.pending
            .retain(|h| now.saturating_sub(h.made) < PENDING_TTL);
        self.candidates
            .retain(|h| now.saturating_sub(h.made) < CANDIDATE_TTL);
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
    fn pending_passwords_are_bound_to_their_origin_and_expire() {
        let mut pending = Pending::default();
        let t0 = Duration::ZERO;
        let id = pending
            .offer("https://example.com", Zeroizing::new("hunter22".into()), t0)
            .unwrap();
        let generated = id.clone();
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
        assert_eq!(got.as_str(), "hunter22");
        assert!(
            pending
                .resolve("https://evil.example.com", &generated, t0)
                .is_err()
        );
        assert!(pending.resolve("https://example.com", "nope", t0).is_err());
        assert!(
            pending
                .resolve("https://example.com", &generated, t0 + PENDING_TTL)
                .is_err(),
            "expired"
        );

        let id = pending
            .offer("https://example.com", Zeroizing::new("again".into()), t0)
            .unwrap();
        pending.keep("https://example.com", &id, t0).unwrap();
        let generated = id;
        pending.saved(&generated);
        assert!(
            pending
                .resolve("https://example.com", &generated, t0)
                .is_err(),
            "saved"
        );
        for n in 0..MAX_PENDING + 3 {
            let id = pending
                .offer("https://example.com", Zeroizing::new(format!("{n}")), t0)
                .unwrap();
            pending.keep("https://example.com", &id, t0).unwrap();
        }
        assert_eq!(pending.pending.len(), MAX_PENDING);
    }

    #[test]
    fn candidates_never_push_out_pending_passwords() {
        let mut pending = Pending::default();
        let t0 = Duration::ZERO;
        let origin = "https://example.com";
        let kept: Vec<String> = (0..MAX_PENDING)
            .map(|n| {
                let id = pending
                    .offer(origin, Zeroizing::new(format!("kept {n}")), t0)
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
                .offer(origin, Zeroizing::new(format!("candidate {n}")), t0)
                .unwrap();
            if n % 2 == 0 {
                pending.drop_candidate(origin, &last);
            }
        }
        for id in &kept {
            let got = pending.resolve(origin, id, t0);
            assert!(got.is_ok(), "{id} was pushed out");
        }
        assert!(pending.candidates.len() <= MAX_CANDIDATES);
        // A dropped candidate can't be kept; nor one from another origin.
        let dropped = pending
            .offer(origin, Zeroizing::new("x".into()), t0)
            .unwrap();
        pending.drop_candidate(origin, &dropped);
        assert!(pending.keep(origin, &dropped, t0).is_err());
        assert!(pending.keep("https://other.example", &last, t0).is_err());
        // Candidates expire sooner than pending passwords.
        assert!(pending.keep(origin, &last, t0 + CANDIDATE_TTL).is_err());
    }
}
