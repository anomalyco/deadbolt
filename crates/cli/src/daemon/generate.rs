//! Native protocol and monotonic-clock adapters for shared site generation.

use std::time::Instant;

use anyhow::Result;
use deadbolt_core::password_rules::Refused;
use deadbolt_core::site_password::{self, FieldRules};
use zeroize::Zeroizing;

use super::{ErrorCode, fail};
use crate::protocol::{PagePassword, Secret, SiteField};

pub fn field_rules(field: &SiteField) -> FieldRules<'_> {
    FieldRules {
        rules: field.rules.as_deref(),
        min_length: field.min_length,
        max_length: field.max_length,
        allowed: field.allowed.as_deref(),
    }
}

fn error(error: site_password::Error) -> anyhow::Error {
    let code = match error {
        site_password::Error::Refused(Refused::Weak) => ErrorCode::Weak,
        site_password::Error::Refused(Refused::Impossible) => ErrorCode::Failed,
        site_password::Error::Expired => ErrorCode::NotFound,
        _ => return error.into(),
    };
    fail(code, error.to_string())
}

pub fn check(origin: &str, field: &FieldRules) -> Result<()> {
    site_password::check(origin, field).map_err(error)
}

pub fn generate(origin: &str, field: &FieldRules) -> Result<Zeroizing<String>> {
    site_password::generate(origin, field).map_err(error)
}

pub struct Pending {
    passwords: site_password::Pending,
    epoch: Instant,
}

impl Default for Pending {
    fn default() -> Self {
        Self {
            passwords: site_password::Pending::default(),
            epoch: Instant::now(),
        }
    }
}

impl Pending {
    pub fn offer(&mut self, origin: &str, password: Secret, now: Instant) -> Result<String> {
        self.passwords
            .offer(
                origin,
                Zeroizing::new(password.expose().to_owned()),
                now.saturating_duration_since(self.epoch),
            )
            .map_err(error)
    }

    pub fn keep(&mut self, origin: &str, id: &str, now: Instant) -> Result<()> {
        self.passwords
            .keep(origin, id, now.saturating_duration_since(self.epoch))
            .map_err(error)
    }

    pub fn drop_candidate(&mut self, origin: &str, id: &str) {
        self.passwords.drop_candidate(origin, id);
    }

    pub fn resolve(
        &mut self,
        origin: &str,
        password: &PagePassword,
        now: Instant,
    ) -> Result<Secret> {
        self.passwords
            .expire(now.saturating_duration_since(self.epoch));
        match password {
            PagePassword::Typed(secret) => Ok(secret.clone()),
            PagePassword::Generated(id) => self
                .passwords
                .resolve(origin, id, now.saturating_duration_since(self.epoch))
                .map(|password| Secret::new(password.as_str()))
                .map_err(error),
        }
    }

    pub fn saved(&mut self, password: &PagePassword) {
        if let PagePassword::Generated(id) = password {
            self.passwords.saved(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
