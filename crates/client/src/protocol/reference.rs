//! Secret references (`docs/agent-control.md`, "CLI"):
//! `deadbolt://[vault/]item/field`, naming one field of one item, the item
//! by its title or short id. Without a vault, the default vault. A `/` or
//! `%` in a name is written `%2F` or `%25`.

use std::fmt;

use serde::{Deserialize, Serialize};

pub const SCHEME: &str = "deadbolt://";

/// One field of one item, as a reference names it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Reference {
    /// The vault's name or id; `None` for the default vault.
    pub vault: Option<String>,
    /// The item's title or short id.
    pub item: String,
    pub field: String,
}

impl Reference {
    /// Parses `deadbolt://[vault/]item/field`. Each part is percent-decoded
    /// and must not be empty.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let Some(rest) = text.strip_prefix(SCHEME) else {
            return Err(format!(
                "{text:?} isn't a reference: it starts with {SCHEME} (deadbolt://vault/item/field)"
            ));
        };
        let parts = rest
            .split('/')
            .map(decode)
            .collect::<Result<Vec<String>, String>>()
            .map_err(|e| format!("{text:?}: {e}"))?;
        if parts.iter().any(|p| p.trim().is_empty()) {
            return Err(format!(
                "{text:?} has an empty part: a reference is deadbolt://[vault/]item/field"
            ));
        }
        let mut parts = parts.into_iter();
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(item), Some(field), None, None) => Ok(Reference {
                vault: None,
                item,
                field,
            }),
            (Some(vault), Some(item), Some(field), None) => Ok(Reference {
                vault: Some(vault),
                item,
                field,
            }),
            _ => Err(format!(
                "{text:?} isn't deadbolt://[vault/]item/field (write a / in a name as %2F)"
            )),
        }
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(SCHEME)?;
        if let Some(vault) = &self.vault {
            write!(f, "{}/", encode(vault))?;
        }
        write!(f, "{}/{}", encode(&self.item), encode(&self.field))
    }
}

fn encode(part: &str) -> String {
    part.replace('%', "%25").replace('/', "%2F")
}

fn decode(part: &str) -> Result<String, String> {
    let bytes = part.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or("a % that isn't followed by two hex digits")?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "a percent-encoded part that isn't UTF-8".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(vault: Option<&str>, item: &str, field: &str) -> Reference {
        Reference {
            vault: vault.map(Into::into),
            item: item.into(),
            field: field.into(),
        }
    }

    #[test]
    fn references_name_an_optional_vault_an_item_and_a_field() {
        assert_eq!(
            Reference::parse("deadbolt://personal/GitHub/token").unwrap(),
            r(Some("personal"), "GitHub", "token")
        );
        assert_eq!(
            Reference::parse(" deadbolt://a1b2/password ").unwrap(),
            r(None, "a1b2", "password")
        );
        // Names with spaces, slashes and percent signs.
        let odd = Reference::parse("deadbolt://work/CI%2FCD key/api token").unwrap();
        assert_eq!(odd, r(Some("work"), "CI/CD key", "api token"));
        assert_eq!(
            odd.to_string(),
            "deadbolt://work/CI%2FCD key/api token",
            "round trips"
        );
        assert_eq!(
            Reference::parse(&r(None, "100%", "x").to_string()).unwrap(),
            r(None, "100%", "x")
        );
        for bad in [
            "GitHub/token",
            "op://vault/item/field",
            "deadbolt://GitHub",
            "deadbolt://a/b/c/d",
            "deadbolt://personal//token",
            "deadbolt:///GitHub/token",
            "deadbolt://GitHub/",
            "deadbolt://Git%zzHub/token",
            "deadbolt://Git%FFHub/token",
        ] {
            assert!(Reference::parse(bad).is_err(), "{bad}");
        }
    }
}
