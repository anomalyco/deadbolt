//! A learned form: where a login's fields are on one page of its site, for
//! a form the extension's detector passed over. The user taught it by
//! filling that form by hand once; it's kept on the login item, in the
//! encrypted vault, as the text field [`RECIPE_FIELD`], so it syncs to every
//! paired device with the rest of the item.
//!
//! A recipe holds the form's shape only, never a value: the page's origin
//! and path (without its query or fragment), a fingerprint of the form's
//! controls, and for each field its role, its place among the form's
//! controls and its `id`, `name` and `autocomplete` attributes. It is at
//! most [`MAX_RECIPE_BYTES`] of JSON, and any key it doesn't name is refused,
//! so nothing else can ride along in one.
//!
//! ```json
//! {"v":1,"origin":"https://bank.example","pathPattern":"/signon","clusterFingerprint":"9f2c41d0",
//!  "slots":[{"role":"username","name":"txt1","nthInput":0},{"role":"password","name":"txt2","nthInput":1}]}
//! ```

use serde::{Deserialize, Serialize};
use url::Url;

use crate::site::Site;

/// The login field a recipe is kept in.
pub const RECIPE_FIELD: &str = "autofill-recipe";

/// The most a recipe's JSON may be.
pub const MAX_RECIPE_BYTES: usize = 512;

/// The only recipe version.
pub const RECIPE_VERSION: u8 = 1;

/// The most fields a recipe locates.
pub const MAX_SLOTS: usize = 4;

/// The longest path pattern.
pub const MAX_PATH: usize = 128;

/// The longest fingerprint, and the longest `id`, `name` or `autocomplete`.
pub const MAX_TOKEN: usize = 64;

/// The roles a recipe's fields may have.
pub const ROLES: [&str; 6] = [
    "username",
    "email",
    "phone",
    "password",
    "new-password",
    "otp",
];

/// The extension reads at most this many controls per page, so a field's
/// place among them is below it.
pub const MAX_NTH_INPUT: u16 = 300;

/// Where a login's fields are on one page of its site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SiteRecipe {
    /// [`RECIPE_VERSION`].
    pub v: u8,
    /// The page's exact origin: `https://host[:port]`, or plain http on a
    /// local development host.
    pub origin: String,
    /// The page's path, segments that look like ids as `*`.
    pub path_pattern: String,
    /// The form's fingerprint: a hash of its controls' shapes.
    pub cluster_fingerprint: String,
    pub slots: Vec<RecipeSlot>,
}

/// One field of a learned form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipeSlot {
    /// One of [`ROLES`].
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autocomplete: Option<String>,
    /// Its place among the form's controls, from 0.
    pub nth_input: u16,
}

/// Why a recipe was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecipeError {
    #[error("a learned form is at most {MAX_RECIPE_BYTES} bytes")]
    TooLarge,
    #[error("not a learned form: {0}")]
    Malformed(String),
    #[error("a learned form of version {0} isn't one this version reads")]
    Version(u8),
    #[error("a learned form's origin must be a page's own origin on the login's site")]
    Origin,
    #[error("a learned form's path is one path of at most {MAX_PATH} characters, without a query")]
    Path,
    #[error("a learned form's fingerprint is 1 to {MAX_TOKEN} letters and digits")]
    Fingerprint,
    #[error("a learned form has 1 to {MAX_SLOTS} fields, each at its own place")]
    Slots,
    #[error("a learned form's field is a username, email, phone, password, new password or code")]
    Role,
    #[error("a learned form's field names are at most {MAX_TOKEN} characters without spaces")]
    Token,
}

impl SiteRecipe {
    /// Reads `raw` as a recipe for a page on `expected_site`, refusing one
    /// that's too large, has any key it doesn't name, or points anywhere
    /// but a page of that site itself (never one that only shares its
    /// credentials).
    pub fn parse_and_validate(raw: &str, expected_site: &Site) -> Result<Self, RecipeError> {
        if raw.len() > MAX_RECIPE_BYTES {
            return Err(RecipeError::TooLarge);
        }
        let recipe: Self =
            serde_json::from_str(raw).map_err(|e| RecipeError::Malformed(e.to_string()))?;
        recipe.validate(expected_site)?;
        Ok(recipe)
    }

    /// Checks every rule [`parse_and_validate`](Self::parse_and_validate) does, but the size.
    pub fn validate(&self, expected_site: &Site) -> Result<(), RecipeError> {
        if self.v != RECIPE_VERSION {
            return Err(RecipeError::Version(self.v));
        }
        if canonical_origin(&self.origin).as_deref() != Some(self.origin.as_str())
            || Site::from_origin(&self.origin).as_ref() != Ok(expected_site)
            || !expected_site.owns_url(&self.origin)
        {
            return Err(RecipeError::Origin);
        }
        if !valid_path(&self.path_pattern) {
            return Err(RecipeError::Path);
        }
        let fp = &self.cluster_fingerprint;
        if fp.is_empty()
            || fp.len() > MAX_TOKEN
            || !fp
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'_'))
        {
            return Err(RecipeError::Fingerprint);
        }
        if self.slots.is_empty() || self.slots.len() > MAX_SLOTS {
            return Err(RecipeError::Slots);
        }
        for (i, slot) in self.slots.iter().enumerate() {
            if !ROLES.contains(&slot.role.as_str()) {
                return Err(RecipeError::Role);
            }
            if slot.nth_input >= MAX_NTH_INPUT
                || self.slots[..i]
                    .iter()
                    .any(|s| s.nth_input == slot.nth_input)
            {
                return Err(RecipeError::Slots);
            }
            let tokens = [&slot.id, &slot.name, &slot.autocomplete];
            if !tokens.into_iter().flatten().all(|t| valid_token(t)) {
                return Err(RecipeError::Token);
            }
        }
        Ok(())
    }

    /// The recipe as it's stored: compact JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// A page origin as the browser serializes it (`https://host[:port]`,
/// lowercase, punycode, the default port left out), if `origin` is one:
/// nothing after the host and port.
pub fn canonical_origin(origin: &str) -> Option<String> {
    let url = Url::parse(origin.trim()).ok()?;
    if !matches!(url.scheme(), "https" | "http")
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let serialized = url.origin().ascii_serialization();
    (serialized != "null").then_some(serialized)
}

/// One path without a query or fragment: starts with `/`, at most
/// [`MAX_PATH`] characters, no whitespace or control characters.
fn valid_path(path: &str) -> bool {
    path.starts_with('/')
        && path.chars().count() <= MAX_PATH
        && !path
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#'))
}

/// An attribute value short enough and plain enough to be a field's name.
fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.chars().count() <= MAX_TOKEN
        && !token.chars().any(|c| c.is_whitespace() || c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(origin: &str) -> Site {
        Site::from_origin(origin).unwrap()
    }

    const BANK: &str = r#"{"v":1,"origin":"https://portal.bank.example","pathPattern":"/banking/*/signon","clusterFingerprint":"9f2c41d0","slots":[{"role":"username","name":"txt1","nthInput":0},{"role":"password","id":"txt2","autocomplete":"current-password","nthInput":1}]}"#;

    fn with_slots(slots: &str) -> String {
        BANK.split(r#""slots":"#).next().unwrap().to_string() + r#""slots":"# + slots + "}"
    }

    #[test]
    fn a_recipe_round_trips_as_compact_json() {
        let recipe = SiteRecipe::parse_and_validate(BANK, &site("https://bank.example")).unwrap();
        assert_eq!(recipe.origin, "https://portal.bank.example");
        assert_eq!(recipe.slots.len(), 2);
        assert_eq!(recipe.slots[0].name.as_deref(), Some("txt1"));
        assert_eq!(
            recipe.slots[1].autocomplete.as_deref(),
            Some("current-password")
        );
        assert_eq!(recipe.to_json(), BANK);
        assert!(BANK.len() < MAX_RECIPE_BYTES);
    }

    #[test]
    fn a_recipe_over_512_bytes_is_refused() {
        let long = BANK.replace(
            "/banking/*/signon",
            &format!("/{}", "a".repeat(MAX_RECIPE_BYTES)),
        );
        assert!(long.len() > MAX_RECIPE_BYTES);
        assert_eq!(
            SiteRecipe::parse_and_validate(&long, &site("https://bank.example")),
            Err(RecipeError::TooLarge)
        );
    }

    /// No key the schema doesn't name, at the top or in a field: a value
    /// can't ride along in one.
    #[test]
    fn unknown_fields_are_refused() {
        let bank = site("https://bank.example");
        for raw in [
            BANK.replacen(r#""v":1,"#, r#""v":1,"password":"hunter2","#, 1),
            BANK.replacen(r#""nthInput":0"#, r#""nthInput":0,"value":"alex""#, 1),
        ] {
            assert!(
                matches!(
                    SiteRecipe::parse_and_validate(&raw, &bank),
                    Err(RecipeError::Malformed(_))
                ),
                "{raw}"
            );
        }
    }

    /// Only a page of the login's site itself: never another site, a site
    /// that only shares its credentials, or anything but a bare origin.
    #[test]
    fn origins_off_the_site_are_refused() {
        let bank = site("https://bank.example");
        for origin in [
            "https://bank.example.evil.test",
            "https://evilbank.example",
            "https://other.example",
            "http://bank.example",
            "https://bank.example/login",
            "https://Bank.Example",
            "https://user@bank.example",
        ] {
            let raw = BANK.replace("https://portal.bank.example", origin);
            assert_eq!(
                SiteRecipe::parse_and_validate(&raw, &bank),
                Err(RecipeError::Origin),
                "{origin}"
            );
        }
        // Sites that share credentials by Apple's list still don't share recipes.
        let raw = BANK.replace("https://portal.bank.example", "https://twitter.com");
        assert_eq!(
            SiteRecipe::parse_and_validate(&raw, &site("https://x.com")),
            Err(RecipeError::Origin)
        );
        // A local development host over http is a page of its own.
        let raw = BANK.replace("https://portal.bank.example", "http://localhost:3000");
        assert!(SiteRecipe::parse_and_validate(&raw, &site("http://localhost:3000")).is_ok());
    }

    #[test]
    fn a_path_with_a_query_or_fragment_is_refused() {
        let bank = site("https://bank.example");
        let long = format!("/{}", "a".repeat(MAX_PATH));
        for path in [
            "/signon?token=abc",
            "/signon#sid",
            "signon",
            "/sign on",
            &long,
        ] {
            let raw = BANK.replace("/banking/*/signon", path);
            assert_eq!(
                SiteRecipe::parse_and_validate(&raw, &bank),
                Err(RecipeError::Path),
                "{path}"
            );
        }
    }

    #[test]
    fn fields_are_few_known_and_plainly_named() {
        let bank = site("https://bank.example");
        let check = |from: &str, to: &str| {
            SiteRecipe::parse_and_validate(&BANK.replacen(from, to, 1), &bank).unwrap_err()
        };
        assert_eq!(
            check(r#""role":"username""#, r#""role":"cvv""#),
            RecipeError::Role
        );
        assert_eq!(
            check(r#""name":"txt1""#, r#""name":"a b""#),
            RecipeError::Token
        );
        assert_eq!(
            check(r#""name":"txt1""#, r#""name":"""#),
            RecipeError::Token
        );
        assert_eq!(
            check(r#""nthInput":1"#, r#""nthInput":0"#),
            RecipeError::Slots
        );
        assert_eq!(
            check(r#""nthInput":1"#, r#""nthInput":300"#),
            RecipeError::Slots
        );
        assert_eq!(check(r#""v":1"#, r#""v":2"#), RecipeError::Version(2));
        assert_eq!(
            check(
                r#""clusterFingerprint":"9f2c41d0""#,
                r#""clusterFingerprint":"9f 2c""#
            ),
            RecipeError::Fingerprint
        );
        assert_eq!(
            SiteRecipe::parse_and_validate(&with_slots("[]"), &bank),
            Err(RecipeError::Slots)
        );
        let five = (0..5)
            .map(|n| format!(r#"{{"role":"otp","nthInput":{n}}}"#))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            SiteRecipe::parse_and_validate(&with_slots(&format!("[{five}]")), &bank),
            Err(RecipeError::Slots)
        );
    }

    #[test]
    fn page_origins_serialize_as_browsers_do() {
        assert_eq!(
            canonical_origin("https://GitHub.com").as_deref(),
            Some("https://github.com")
        );
        assert_eq!(
            canonical_origin("https://github.com:443").as_deref(),
            Some("https://github.com")
        );
        assert_eq!(
            canonical_origin("http://localhost:5173").as_deref(),
            Some("http://localhost:5173")
        );
        assert_eq!(canonical_origin("https://github.com/login"), None);
        assert_eq!(canonical_origin("ftp://github.com"), None);
    }
}
