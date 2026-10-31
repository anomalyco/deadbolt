//! What clients show of items and how they take input for them: type
//! names, sign-in providers, an item's label, detail and search words, and
//! typing and normalizing a field's value. The native agent and the
//! browser-only device both use these, so an item is named, found and
//! written the same way on every device.

use crate::forms::last_four;
use crate::item::{ItemError, check_new_value};
use crate::{Field, FieldType, Item, schema};

/// The sign-in providers a login's `sign-in-with` names by id, with their
/// names and other names for them.
pub const SIGN_IN_PROVIDERS: [(&str, &str, &[&str]); 12] = [
    ("google", "Google", &[]),
    ("apple", "Apple", &[]),
    ("github", "GitHub", &[]),
    ("microsoft", "Microsoft", &[]),
    ("facebook", "Facebook", &["meta"]),
    ("x", "X", &["twitter"]),
    ("amazon", "Amazon", &[]),
    ("discord", "Discord", &[]),
    ("slack", "Slack", &[]),
    ("okta", "Okta", &[]),
    ("linkedin", "LinkedIn", &[]),
    ("gitlab", "GitLab", &[]),
];

/// A provider as a `sign-in-with` value: the id of a known one, matched
/// by id, name or other name in any case and spacing ("Sign in with
/// Twitter" is `x`); any other as one line of at most 64 characters.
/// `None` if blank.
pub fn sign_in_provider(text: &str) -> Option<String> {
    let line = text
        .split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let bare = line
        .to_lowercase()
        .strip_prefix("sign in with ")
        .map_or_else(|| line.to_lowercase(), str::to_string);
    let bare: String = bare.chars().filter(|c| c.is_alphanumeric()).collect();
    if let Some((id, ..)) = SIGN_IN_PROVIDERS.iter().find(|(id, name, other)| {
        *id == bare || name.to_lowercase() == bare || other.contains(&bare.as_str())
    }) {
        return Some((*id).to_string());
    }
    let line: String = line.chars().take(64).collect();
    let line = line.trim_end();
    (!line.is_empty()).then(|| line.to_string())
}

/// What a provider is called: "Google" for `google`; one this version
/// doesn't know by its value.
pub fn sign_in_name(provider: &str) -> &str {
    SIGN_IN_PROVIDERS
        .iter()
        .find(|(id, ..)| *id == provider)
        .map_or(provider, |(_, name, _)| name)
}

/// The item types clients name, in the order they list them: the type, then
/// what one and several are called.
pub const KINDS: [(&str, &str, &str); 18] = [
    ("login", "login", "logins"),
    ("card", "card", "cards"),
    ("note", "secure note", "secure notes"),
    ("ssh", "SSH key", "SSH keys"),
    ("identity", "identity", "identities"),
    ("passkey", "passkey", "passkeys"),
    ("api", "API credential", "API credentials"),
    ("database", "database", "databases"),
    ("server", "server", "servers"),
    ("wifi", "Wi-Fi network", "Wi-Fi networks"),
    ("license", "software license", "software licenses"),
    ("bank", "bank account", "bank accounts"),
    ("document", "document", "documents"),
    ("passport", "passport", "passports"),
    ("driver-license", "driver's license", "driver's licenses"),
    ("membership", "membership", "memberships"),
    ("crypto", "crypto wallet", "crypto wallets"),
    ("id-document", "ID document", "ID documents"),
];

/// What `count` items of type `kind` are called: "secure note", "SSH keys".
/// A type this version doesn't know is called by its identifier.
pub fn noun(kind: &str, count: usize) -> &str {
    KINDS
        .iter()
        .find(|(k, ..)| *k == kind)
        .map_or(kind, |(_, one, many)| if count == 1 { one } else { many })
}

/// The field an item is for, which clients copy or print by default: a
/// login's password, a card's number, a secure note's body, an SSH key's
/// public key, an identity's email, a passkey's username, an API
/// credential's credential, a database's, server's or Wi-Fi network's
/// password, a license's key, a bank account's number, a document's file,
/// an ID's number, a membership's id, a wallet's recovery phrase. `None`
/// for a type this version doesn't know.
pub fn primary_field(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "login" | "database" | "server" | "wifi" => "password",
        "card" | "passport" | "driver-license" | "id-document" => "number",
        "note" => "notes",
        "ssh" => "public-key",
        "identity" => "email",
        "passkey" => "username",
        "api" => "credential",
        "license" => "license-key",
        "bank" => "account-number",
        "document" => "file",
        "membership" => "member-id",
        "crypto" => "recovery-phrase",
        _ => return None,
    })
}

/// `month` of a 2- or 4-digit `year` (20YY) as `YYYY-MM`. The month is not
/// range-checked here; the item rules do that. Shared by the agent's input
/// normalization and the importer.
pub fn format_month(month: u8, year: &str) -> Option<String> {
    let year = year.trim();
    if !year.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let year = match year.len() {
        2 => format!("20{year}"),
        4 => year.to_string(),
        _ => return None,
    };
    Some(format!("{year}-{month:02}"))
}

/// A URL without a scheme gets `https://`.
pub fn with_scheme(url: String) -> String {
    if url.is_empty() || url.contains("://") {
        url
    } else {
        format!("https://{url}")
    }
}

/// The host of a URL as autofill reads it ([`crate::site::url_host`]),
/// without `www.`, so a label or a search shows the site a login fills on.
pub fn host(url: &str) -> String {
    let Some(host) = crate::site::url_host(url) else {
        return String::new();
    };
    let host = host.strip_prefix("www.").unwrap_or(&host);
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn value<'a>(item: &'a Item, field: &str) -> Option<&'a str> {
    item.fields.get(field).map(|f| f.value.as_str())
}

/// The item's name, else a label derived from its fields.
pub fn label(item: &Item) -> String {
    if let Some(name) = &item.name {
        return name.clone();
    }
    match item.kind.as_str() {
        "login" => crate::autofill::login_title(item),
        "card" | "identity" => crate::forms::title(item),
        "ssh" => value(item, "comment").unwrap_or("SSH key").into(),
        "passkey" => value(item, "rp-id").unwrap_or("passkey").into(),
        "api" => value(item, "url")
            .map(host)
            .filter(|h| !h.is_empty())
            .or_else(|| value(item, "host").map(str::to_string))
            .unwrap_or_else(|| "API credential".into()),
        "database" => match (value(item, "database"), value(item, "host")) {
            (Some(db), Some(host)) => format!("{db} on {host}"),
            (db, host) => db.or(host).unwrap_or("database").into(),
        },
        "server" => value(item, "url")
            .map(host)
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "server".into()),
        "wifi" => value(item, "ssid").unwrap_or("Wi-Fi network").into(),
        "license" => value(item, "product").unwrap_or("software license").into(),
        "bank" => value(item, "bank").unwrap_or("bank account").into(),
        "document" => value(item, "file")
            .map(|f| crate::item::file_parts(f).0)
            .unwrap_or("document")
            .into(),
        "passport" | "driver-license" | "id-document" => value(item, "full-name")
            .map(str::to_string)
            .unwrap_or_else(|| noun(&item.kind, 1).into()),
        "membership" => value(item, "organization").unwrap_or("membership").into(),
        "crypto" => value(item, "network").unwrap_or("crypto wallet").into(),
        // A secure note's body is secret: never a label.
        kind => kind.into(),
    }
}

/// A login's username (else how it signs in: "Sign in with Google"), a
/// card's expiry (`MM/YY`), an SSH key's comment or fingerprint, an
/// identity's email, a passkey's username, and for the other types the
/// first plain field that tells one from another (an API credential's
/// username or type, a database's username, ...). A secure note has none.
pub fn detail(item: &Item) -> Option<String> {
    let first = |fields: &[&str]| {
        fields
            .iter()
            .find_map(|f| value(item, f))
            .map(str::to_string)
    };
    match item.kind.as_str() {
        "login" => first(&["username"]).or_else(|| {
            value(item, "sign-in-with").map(|p| format!("Sign in with {}", sign_in_name(p)))
        }),
        "card" => value(item, "expiry")
            .and_then(|e| e.split_once('-'))
            .map(|(year, month)| format!("{month}/{}", &year[year.len().saturating_sub(2)..])),
        "ssh" => first(&["comment", "fingerprint"]),
        "identity" => first(&["email", "phone"]),
        "passkey" | "server" => first(&["username"]),
        "api" => first(&["username", "type", "environment"]),
        "database" => first(&["username", "type"]),
        "wifi" => first(&["security"]),
        "license" => first(&["licensed-to", "version"]),
        "bank" => first(&["account-holder"]),
        "document" => value(item, "file")
            .and_then(|f| crate::item::file_parts(f).1)
            .and_then(crate::item::file_size)
            .map(file_size),
        "passport" | "id-document" => first(&["type", "issuing-country", "country"]),
        "driver-license" => first(&["state", "country"]),
        "membership" => first(&["member-name"]),
        "crypto" => first(&["address"]),
        _ => None,
    }
}

/// A file's size as people read it: "812 bytes", "1.2 MB".
pub fn file_size(bytes: usize) -> String {
    match bytes {
        0..1_000 => format!("{bytes} bytes"),
        1_000..1_000_000 => format!("{:.1} KB", bytes as f64 / 1e3),
        _ => format!("{:.1} MB", bytes as f64 / 1e6),
    }
}

pub fn searchable(item: &Item) -> Vec<String> {
    let mut texts = Vec::new();
    texts.extend(item.name.clone());
    texts.extend(value(item, "url").map(host));
    let fields: &[&str] = match item.kind.as_str() {
        "login" => &["username"],
        "card" => &["cardholder", "brand"],
        "ssh" => &["comment", "fingerprint"],
        "identity" => &[
            "given-name",
            "family-name",
            "nickname",
            "organization",
            "email",
            "phone",
            "name",
        ],
        "passkey" => &["rp-id", "username"],
        "api" => &["username", "type", "host", "environment"],
        "database" => &["type", "host", "database", "username"],
        "server" => &["username"],
        "wifi" => &["ssid"],
        "license" => &["product", "licensed-to", "email"],
        "bank" => &["bank", "account-holder"],
        "passport" | "driver-license" | "id-document" => &["full-name", "type"],
        "membership" => &["organization", "member-name"],
        "crypto" => &["network", "address"],
        _ => &[],
    };
    texts.extend(
        fields
            .iter()
            .filter_map(|f| value(item, f))
            .map(str::to_string),
    );
    if item.kind == "card" {
        texts.extend(last_four(item).map(str::to_string));
    }
    // Every file's name and every tag, on any item.
    texts.extend(
        item.fields
            .values()
            .filter(|f| f.kind == FieldType::File)
            .map(|f| crate::item::file_parts(&f.value).0.to_string()),
    );
    texts.extend(item.tags.iter().cloned());
    texts.into_iter().map(|t| t.to_lowercase()).collect()
}

/// Normalizes common input forms: card numbers without spaces or dashes,
/// `MM/YY` and `MM/YYYY` months, URLs without a scheme (https), an
/// identity's or membership's international phone number in E.164 form and
/// an identity's country code in upper case.
pub fn normalize(kind: &str, name: &str, field: &FieldType, value: String) -> String {
    match (kind, name) {
        ("card", "number") => {
            return value
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .collect();
        }
        ("identity" | "membership", "phone") => {
            return crate::item::phone(&value).unwrap_or(value);
        }
        ("identity", "country") => {
            return crate::item::country(&value).map_or(value, str::to_string);
        }
        _ => {}
    }
    match field {
        FieldType::Month => {
            let parsed = value
                .split_once('/')
                .and_then(|(month, year)| format_month(month.trim().parse().ok()?, year));
            parsed.unwrap_or(value)
        }
        FieldType::Url => with_scheme(value),
        _ => value,
    }
}

/// One field of user input, typed and normalized: an explicit `field_type`,
/// else the item type's field type, else the field's current type in
/// `existing`, else `text`. Checked as a new value.
pub fn input_field(
    kind: &str,
    existing: Option<&Item>,
    name: &str,
    field_type: Option<&str>,
    value: String,
) -> Result<Field, ItemError> {
    let field = match field_type {
        Some(k) => FieldType::parse(k),
        None => schema(kind)
            .and_then(|s| s.field(name))
            .map(|f| f.kind.clone())
            .or_else(|| existing?.fields.get(name).map(|f| f.kind.clone()))
            .unwrap_or(FieldType::Text),
    };
    let value = normalize(kind, name, &field, value);
    let field = Field::new(field, value);
    check_new_value(name, &field)?;
    Ok(field)
}
