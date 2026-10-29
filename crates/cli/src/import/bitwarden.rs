//! Bitwarden's unencrypted JSON export (`{encrypted, folders[], items[]}`,
//! see bitwarden/clients `libs/common/src/models/export`).

use anyhow::{Result, bail};
use deadbolt_core::FieldType;
use serde_json::Value;

use super::{
    ATTACHMENT, BAD_CVV, BAD_EMAIL, BAD_EXPIRY, BAD_OTP, BANK_ACCOUNT, Builder, COLLECTION,
    DRIVERS_LICENSE, FAVORITE, FOLDER, Imported, LINKED_FIELD, NO_NUMBER, NO_PRIVATE_KEY, PASSKEYS,
    PASSPORT, PASSWORD_HISTORY, Summary, UNKNOWN_TYPE, array, field_name, item_name, month, number,
    text,
};
use crate::protocol::ImportSource;

/// `expMonth`/`expYear` as `YYYY-MM`. `None` if either is missing,
/// `Some(Err(raw))` if they do not form a month.
fn expiry(card: &Value) -> Option<Result<String, String>> {
    let m = text(card, "expMonth")?;
    let y = text(card, "expYear")?;
    Some(month(&m, &y).ok_or_else(|| format!("{}/{}", m.trim(), y.trim())))
}

impl Builder {
    fn custom_fields(&mut self, item: &Value, summary: &mut Summary) {
        for field in array(item, "fields") {
            let kind = match number(field, "type") {
                Some(0 | 2) => FieldType::Text,
                Some(3) => {
                    summary.drop_some(LINKED_FIELD, 1);
                    continue;
                }
                _ => FieldType::Secret,
            };
            let Some(value) = text(field, "value") else {
                continue;
            };
            let name = field_name(&text(field, "name").unwrap_or_default());
            self.extra(&name, kind, value);
        }
    }
}

fn login(item: &Value, summary: &mut Summary) -> Option<Imported> {
    let login = item.get("login").unwrap_or(&Value::Null);
    let mut b = Builder::new("login");
    b.known("password", text(login, "password"));
    b.known("username", text(login, "username"));
    b.known_or_extra("otp", text(login, "totp"), BAD_OTP, summary);
    b.known("notes", text(item, "notes"));
    b.urls(
        array(login, "uris").iter().filter_map(|u| text(u, "uri")),
        summary,
    );
    if !array(login, "fido2Credentials").is_empty() {
        summary.drop_some(PASSKEYS, 1);
    }
    b.custom_fields(item, summary);
    b.finish("login", item_name(text(item, "name")), summary)
}

fn card(item: &Value, summary: &mut Summary) -> Option<Imported> {
    let card = item.get("card").unwrap_or(&Value::Null);
    let mut b = Builder::new("card");
    let number = text(card, "number")
        .map(|n| {
            n.chars()
                .filter(|c| !c.is_whitespace() && !matches!(c, '-' | '.'))
                .collect::<String>()
        })
        .filter(|n| !n.is_empty());
    if number.is_none() || !b.known("number", number) {
        summary.skip(NO_NUMBER);
        return None;
    }
    let cvv = text(card, "code").map(|c| c.trim().to_string());
    b.known_or_extra("cvv", cvv, BAD_CVV, summary);
    match expiry(card) {
        Some(Ok(month)) => {
            b.known("expiry", Some(month));
        }
        Some(Err(raw)) => b.known_or_extra("expiry", Some(raw), BAD_EXPIRY, summary),
        None => {}
    }
    b.known("cardholder", text(card, "cardholderName"));
    b.known("brand", text(card, "brand"));
    b.known("notes", text(item, "notes"));
    b.custom_fields(item, summary);
    b.finish("card", item_name(text(item, "name")), summary)
}

fn note(item: &Value, summary: &mut Summary) -> Option<Imported> {
    let mut b = Builder::new("note");
    b.known("notes", text(item, "notes"));
    b.custom_fields(item, summary);
    b.finish("note", item_name(text(item, "name")), summary)
}

fn ssh(item: &Value, summary: &mut Summary) -> Option<Imported> {
    let key = item.get("sshKey").unwrap_or(&Value::Null);
    let Some(private) = text(key, "privateKey").filter(|k| !k.trim().is_empty()) else {
        summary.skip(NO_PRIVATE_KEY);
        return None;
    };
    let mut b = Builder::new("ssh");
    b.known("private-key", Some(private));
    b.known("public-key", text(key, "publicKey"));
    b.known("fingerprint", text(key, "keyFingerprint"));
    b.known("notes", text(item, "notes"));
    b.custom_fields(item, summary);
    b.finish("ssh", item_name(text(item, "name")), summary)
}

fn identity(item: &Value, summary: &mut Summary) -> Option<Imported> {
    let id = item.get("identity").unwrap_or(&Value::Null);
    let get = |key: &str| text(id, key);
    let mut b = Builder::new("identity");
    b.known("honorific", get("title"));
    b.known("given-name", get("firstName"));
    b.known("additional-name", get("middleName"));
    b.known("family-name", get("lastName"));
    b.known("organization", get("company"));
    b.known_or_extra("email", get("email"), BAD_EMAIL, summary);
    b.phone(get("phone"));
    b.postal_address(
        [get("address1"), get("address2"), get("address3")],
        [get("city"), get("state"), get("postalCode"), get("country")],
        summary,
    );
    b.known("national-id", get("ssn"));
    b.known("passport", get("passportNumber"));
    b.known("license", get("licenseNumber"));
    if let Some(value) = get("username") {
        b.extra("username", FieldType::Text, value);
    }
    b.known("notes", text(item, "notes"));
    b.custom_fields(item, summary);
    b.finish("identity", item_name(text(item, "name")), summary)
}

/// Maps a Bitwarden JSON export.
pub fn export(export: &Value) -> Result<(Vec<Imported>, Summary)> {
    if export.get("encrypted").and_then(Value::as_bool) == Some(true) {
        bail!("this is an encrypted export; export as unencrypted .json");
    }
    let Some(items) = export.get("items").and_then(Value::as_array) else {
        bail!("not a Bitwarden JSON export: no \"items\" list");
    };
    let mut summary = Summary::new(ImportSource::Bitwarden);
    summary.drop_some(FOLDER, array(export, "folders").len());
    summary.drop_some(COLLECTION, array(export, "collections").len());
    let mut out = Vec::new();
    for item in items {
        let mapped = match number(item, "type") {
            Some(1) => login(item, &mut summary),
            Some(2) => note(item, &mut summary),
            Some(3) => card(item, &mut summary),
            Some(4) => identity(item, &mut summary),
            Some(5) => ssh(item, &mut summary),
            other => {
                summary.skip(match other {
                    Some(6) => BANK_ACCOUNT,
                    Some(7) => DRIVERS_LICENSE,
                    Some(8) => PASSPORT,
                    _ => UNKNOWN_TYPE,
                });
                continue;
            }
        };
        let Some(mapped) = mapped else {
            continue;
        };
        if item.get("favorite").and_then(Value::as_bool) == Some(true) {
            summary.drop_some(FAVORITE, 1);
        }
        summary.drop_some(ATTACHMENT, array(item, "attachments").len());
        if !array(item, "passwordHistory").is_empty() {
            summary.drop_some(PASSWORD_HISTORY, 1);
        }
        summary.add(&mapped);
        out.push(mapped);
    }
    Ok((out, summary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::tests::{fields, lines};
    use crate::import::{ImportReport, parse};

    fn bitwarden(text: &str) -> Result<(Vec<Imported>, ImportReport)> {
        let (items, report) = parse(text)?;
        assert_eq!(report.source, ImportSource::Bitwarden);
        Ok((items, report))
    }

    /// Shaped like a real export from the Bitwarden web vault.
    const EXPORT: &str = r#"{
  "encrypted": false,
  "folders": [
    { "id": "4f5e2a3b-0c1d-4e2f-9a8b-7c6d5e4f3a2b", "name": "Work" },
    { "id": "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d", "name": "Finance" }
  ],
  "items": [
    {
      "passwordHistory": [
        { "lastUsedDate": "2024-01-02T03:04:05.000Z", "password": "old-hunter2" }
      ],
      "revisionDate": "2024-05-06T07:08:09.123Z",
      "creationDate": "2023-01-01T00:00:00.000Z",
      "deletedDate": null,
      "id": "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "organizationId": null,
      "folderId": "4f5e2a3b-0c1d-4e2f-9a8b-7c6d5e4f3a2b",
      "type": 1,
      "reprompt": 0,
      "name": "GitHub",
      "notes": "work account",
      "favorite": true,
      "fields": [
        { "name": "Recovery Code", "value": "rc-secret-1", "type": 1, "linkedId": null },
        { "name": "Notes", "value": "a text note", "type": 0, "linkedId": null },
        { "name": "notes", "value": "another", "type": 0, "linkedId": null },
        { "name": "2FA enabled?", "value": "true", "type": 2, "linkedId": null },
        { "name": "Username", "value": null, "type": 3, "linkedId": 100 },
        { "name": "empty", "value": "", "type": 0, "linkedId": null },
        { "name": null, "value": "unnamed-secret", "type": 1, "linkedId": null }
      ],
      "login": {
        "fido2Credentials": [],
        "uris": [
          { "match": null, "uri": "not a url" },
          { "match": null, "uri": "https://github.com/login" },
          { "match": 3, "uri": "github.com" },
          { "match": null, "uri": "androidapp://com.github.android" }
        ],
        "username": "dax",
        "password": "hunter2-github",
        "totp": "JBSWY3DPEHPK3PXP"
      },
      "collectionIds": null
    },
    {
      "id": "1b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "organizationId": null,
      "folderId": null,
      "type": 1,
      "reprompt": 0,
      "name": "No password",
      "notes": null,
      "favorite": false,
      "login": { "uris": [], "username": "someone", "password": null, "totp": null },
      "collectionIds": null
    },
    {
      "id": "2b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 1,
      "name": "",
      "favorite": false,
      "login": { "password": "minimal-pw" }
    },
    {
      "passwordHistory": null,
      "id": "3b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "organizationId": null,
      "folderId": "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d",
      "type": 3,
      "reprompt": 0,
      "name": "Visa",
      "notes": null,
      "favorite": false,
      "card": {
        "cardholderName": "Dax Raad",
        "brand": "Visa",
        "number": "4242 4242 4242 4242",
        "expMonth": "4",
        "expYear": "27",
        "code": "12x"
      },
      "collectionIds": null
    },
    {
      "id": "4b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 3,
      "name": "Amex",
      "favorite": false,
      "card": {
        "cardholderName": null,
        "brand": "Amex",
        "number": "378282246310005",
        "expMonth": "12",
        "expYear": null,
        "code": "1234"
      }
    },
    {
      "id": "5b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 3,
      "name": "Broken card",
      "favorite": false,
      "card": { "number": "1234", "expMonth": "1", "expYear": "2030", "code": "123" }
    },
    {
      "id": "6b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 2,
      "name": "Wifi",
      "notes": "the wifi password",
      "favorite": false,
      "secureNote": { "type": 0 }
    },
    {
      "id": "7b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 4,
      "name": "Me",
      "favorite": false,
      "notes": "primary",
      "identity": {
        "title": "Mr", "firstName": "Dax", "middleName": null, "lastName": "Raad",
        "address1": "1 Main St", "address2": "Apt 2", "address3": null, "city": "Springfield",
        "state": "IL", "postalCode": "12345", "country": "US", "company": "Anomaly",
        "email": "dax@example.com", "phone": "+1 555 0100", "ssn": "000-00-0000",
        "username": "dax", "passportNumber": "X1234567", "licenseNumber": null
      }
    },
    {
      "id": "8b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 5,
      "name": "Deploy key",
      "favorite": false,
      "sshKey": { "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----", "publicKey": "ssh-ed25519 AAAA", "keyFingerprint": "SHA256:x" }
    },
    { "id": "ab1c", "type": 5, "name": "Half key", "favorite": false, "sshKey": { "privateKey": "", "publicKey": "ssh-ed25519 BBBB" } },
    { "id": "bb1c", "type": 2, "name": null, "notes": "  ", "favorite": false, "secureNote": { "type": 0 } },
    {
      "id": "9b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "type": 4,
      "name": "Also me",
      "favorite": false,
      "identity": {}
    }
  ]
}"#;

    #[test]
    fn maps_a_bitwarden_export() {
        let (items, summary) = bitwarden(EXPORT).unwrap();
        let kinds: Vec<_> = items.iter().map(|i| i.kind).collect();
        assert_eq!(
            kinds,
            [
                "login", "login", "login", "card", "card", "note", "identity", "ssh", "identity"
            ]
        );
        let github = &items[0];
        assert_eq!(
            (github.kind, github.name.as_deref()),
            ("login", Some("GitHub"))
        );
        assert_eq!(
            fields(github),
            [
                ("field", "secret", "unnamed-secret"),
                ("field-2fa-enabled", "text", "true"),
                ("notes", "note", "work account"),
                ("notes-2", "text", "a text note"),
                ("notes-3", "text", "another"),
                ("otp", "otp", "JBSWY3DPEHPK3PXP"),
                ("password", "secret", "hunter2-github"),
                ("recovery-code", "secret", "rc-secret-1"),
                ("url", "url", "https://github.com/login"),
                ("url-2", "text", "not a url"),
                ("url-3", "url", "https://github.com"),
                ("url-4", "url", "androidapp://com.github.android"),
                ("username", "text", "dax"),
            ]
        );
        // A login needs no password.
        assert_eq!(fields(&items[1]), [("username", "text", "someone")]);
        assert_eq!(items[2].name, None);
        assert_eq!(fields(&items[2]), [("password", "secret", "minimal-pw")]);
        assert_eq!(
            fields(&items[3]),
            [
                ("brand", "text", "Visa"),
                ("cardholder", "text", "Dax Raad"),
                ("cvv-2", "secret", "12x"),
                ("expiry", "month", "2027-04"),
                ("number", "secret", "4242424242424242"),
            ]
        );
        assert_eq!(
            fields(&items[4]),
            [
                ("brand", "text", "Amex"),
                ("cvv", "secret", "1234"),
                ("number", "secret", "378282246310005"),
            ]
        );
        // A secure note's body is secret.
        assert_eq!(
            (items[5].name.as_deref(), fields(&items[5])),
            (Some("Wifi"), vec![("notes", "secret", "the wifi password")])
        );
        assert_eq!(
            fields(&items[6]),
            [
                ("address-line1", "text", "1 Main St"),
                ("address-line2", "text", "Apt 2"),
                ("city", "text", "Springfield"),
                ("country", "text", "US"),
                ("email", "email", "dax@example.com"),
                ("family-name", "text", "Raad"),
                ("given-name", "text", "Dax"),
                ("honorific", "text", "Mr"),
                ("national-id", "secret", "000-00-0000"),
                ("notes", "note", "primary"),
                ("organization", "text", "Anomaly"),
                ("passport", "secret", "X1234567"),
                ("phone", "text", "+15550100"),
                ("postal-code", "text", "12345"),
                ("region", "text", "IL"),
                ("username", "text", "dax"),
            ]
        );
        assert_eq!(
            fields(&items[7]),
            [
                ("fingerprint", "text", "SHA256:x"),
                (
                    "private-key",
                    "secret",
                    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----"
                ),
                ("public-key", "text", "ssh-ed25519 AAAA"),
            ]
        );
        assert_eq!(
            (items[8].name.as_deref(), fields(&items[8])),
            (Some("Also me"), vec![])
        );
        assert_eq!(
            summary.counts(),
            [
                ("login", 3),
                ("card", 2),
                ("note", 1),
                ("ssh", 1),
                ("identity", 2)
            ]
        );
        assert_eq!(
            lines(&summary),
            [
                "imported 9 from Bitwarden (logins 3, cards 2, secure notes 1, SSH keys 1, identities 2)",
                "skipped 1 SSH key without a private key",
                "skipped 1 card without a valid number",
                "skipped 1 empty item",
                "warning: 1 URL that is not an absolute URL kept as text",
                "warning: 1 invalid card code (cvv) kept as an extra field",
                "dropped: 1 favorite, 2 folders, 1 item's password history, 1 linked field",
            ]
        );
    }

    #[test]
    fn card_expiry() {
        let card = |m: &str, y: &str| serde_json::json!({ "expMonth": m, "expYear": y });
        assert_eq!(expiry(&card("4", "27")), Some(Ok("2027-04".into())));
        assert_eq!(expiry(&card("12", "2031")), Some(Ok("2031-12".into())));
        assert_eq!(expiry(&card(" 04 ", " 27 ")), Some(Ok("2027-04".into())));
        assert_eq!(expiry(&card("", "2031")), None);
        assert_eq!(expiry(&serde_json::json!({ "expMonth": "1" })), None);
        assert_eq!(expiry(&card("1", "203")), Some(Err("1/203".into())));
        assert_eq!(expiry(&card("1", "2x")), Some(Err("1/2x".into())));
        assert_eq!(expiry(&card("13", "2031")), Some(Err("13/2031".into())));
        assert_eq!(expiry(&card("+1", "2031")), Some(Err("+1/2031".into())));
    }

    #[test]
    fn rejects_encrypted_and_foreign_files() {
        let encrypted = r#"{"encrypted": true, "passwordProtected": true, "salt": "x", "kdfType": 0, "kdfIterations": 600000, "encKeyValidation_DO_NOT_EDIT": "2.x", "data": "2.y"}"#;
        let error = bitwarden(encrypted).err().unwrap().to_string();
        assert_eq!(
            error,
            "this is an encrypted export; export as unencrypted .json"
        );
        assert!(parse(r#"{"encrypted": false}"#).is_err());
        let error = parse(r#"{"items": [{"login": {"password": "s3cret"#)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("s3cret"), "{error}");
    }

    #[test]
    fn blank_values_are_left_out() {
        let export = r#"{"encrypted": false, "items": [
            {"type": 3, "name": "Visa", "card": {"number": "4242424242424242", "code": " ", "brand": "  "},
             "fields": [{"name": "pin", "value": "   ", "type": 1}]},
            {"type": 3, "name": "Dashes", "card": {"number": "--"}},
            {"type": 1, "name": "Blank", "login": {"username": "dax", "password": "  "}}
        ]}"#;
        let (items, summary) = bitwarden(export).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(
            fields(&items[0]),
            [("number", "secret", "4242424242424242")]
        );
        assert_eq!(fields(&items[1]), [("username", "text", "dax")]);
        assert_eq!(
            lines(&summary),
            [
                "imported 2 from Bitwarden (logins 1, cards 1)",
                "skipped 1 card without a valid number",
            ]
        );
    }

    /// A custom field named like one of the type's own fields fills it when
    /// it's unset and the value fits, rather than becoming `pin-2`.
    #[test]
    fn custom_fields_fill_the_types_own_fields() {
        let export = r#"{"encrypted": false, "items": [
            {"type": 3, "name": "Visa", "card": {"number": "4242424242424242"},
             "fields": [{"name": "PIN", "value": "1234", "type": 1}]},
            {"type": 3, "name": "Amex", "card": {"number": "378282246310005"},
             "fields": [{"name": "pin", "value": "5678", "type": 0}, {"name": "cvv", "value": "abc", "type": 1}]},
            {"type": 5, "name": "Deploy", "sshKey": {"privateKey": "bw-key"},
             "fields": [{"name": "passphrase", "value": "bw-pass", "type": 1}, {"name": "comment", "value": "me@host", "type": 0}]},
            {"type": 4, "name": "Me", "identity": {"firstName": "Dax"},
             "fields": [{"name": "passport", "value": "bw-pp", "type": 1}, {"name": "license", "value": "bw-dl", "type": 0},
                        {"name": "email", "value": "not an email", "type": 0}, {"name": "phone", "value": "bw-phone", "type": 1}]}
        ]}"#;
        let (items, _) = bitwarden(export).unwrap();
        assert_eq!(
            fields(&items[0]),
            [
                ("number", "secret", "4242424242424242"),
                ("pin", "secret", "1234"),
            ]
        );
        // A plain-text PIN is made secret; a CVV that isn't one stays aside.
        assert_eq!(
            fields(&items[1]),
            [
                ("cvv-2", "secret", "abc"),
                ("number", "secret", "378282246310005"),
                ("pin", "secret", "5678"),
            ]
        );
        assert_eq!(
            fields(&items[2]),
            [
                ("comment", "text", "me@host"),
                ("passphrase", "secret", "bw-pass"),
                ("private-key", "secret", "bw-key"),
            ]
        );
        // A hidden value never fills a plain-text field.
        assert_eq!(
            fields(&items[3]),
            [
                ("email-2", "text", "not an email"),
                ("given-name", "text", "Dax"),
                ("license", "secret", "bw-dl"),
                ("passport", "secret", "bw-pp"),
                ("phone-2", "secret", "bw-phone"),
            ]
        );
    }

    #[test]
    fn counts_unsupported_types() {
        let export = r#"{"encrypted": false, "folders": [], "items": [
            {"type": 6, "name": "Bank"}, {"type": 7, "name": "DL"}, {"type": 8, "name": "PP"},
            {"type": 99, "name": "Future"}, {"name": "No type"},
            {"type": 3, "name": "No card", "card": null}
        ]}"#;
        let (items, summary) = bitwarden(export).unwrap();
        assert!(items.is_empty());
        assert_eq!(
            lines(&summary),
            [
                "imported 0 from Bitwarden (logins 0, cards 0)",
                "skipped 1 bank account",
                "skipped 1 card without a valid number",
                "skipped 1 driver's license",
                "skipped 2 items of unknown type",
                "skipped 1 passport",
            ]
        );
    }
}
