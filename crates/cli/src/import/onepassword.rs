//! 1Password's 1PUX export: the `export.data` JSON inside the `.1pux` zip
//! (`{accounts: [{vaults: [{attrs, items: [...]}]}]}`). Items from every
//! account and vault go into the one target vault.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use deadbolt_core::FieldType;
use serde_json::Value;

use super::{
    ARCHIVED, ATTACHMENT, BAD_BIRTHDAY, BAD_CVV, BAD_EMAIL, BAD_EXPIRY, BAD_OTP, Builder, FAVORITE,
    Imported, LINKED_FIELD, NO_NUMBER, NO_PRIVATE_KEY, PASSWORD_HISTORY, Reason, Summary, TAG,
    UNKNOWN_TYPE, address, array, field_name, item_name, join, month, number, scalar, text,
};
use crate::protocol::ImportSource;

/// Item categories that are skipped, by `categoryUuid`.
fn skipped(category: &str) -> Reason {
    match category {
        "006" => ("document", "documents"),
        _ => UNKNOWN_TYPE,
    }
}

/// A field of an item, from `loginFields` or a section, with its value as
/// text. `key` is the value's type: a section value's key (`concealed`,
/// `totp`, `monthYear`, ...), or `concealed`/`string` for login fields.
struct Entry {
    title: String,
    id: String,
    key: String,
    designation: Option<String>,
    value: String,
}

impl Entry {
    fn is(&self, name: &str) -> bool {
        self.id.eq_ignore_ascii_case(name) || self.title.eq_ignore_ascii_case(name)
    }

    fn kind(&self) -> FieldType {
        match self.key.as_str() {
            "concealed" | "totp" | "creditCardNumber" | "sshKey" => FieldType::Secret,
            "url" => FieldType::Url,
            "email" => FieldType::Email,
            "monthYear" => FieldType::Month,
            "date" => FieldType::Date,
            "address" => FieldType::Note,
            _ => FieldType::Text,
        }
    }

    fn is_totp(&self) -> bool {
        self.key == "totp" || self.id.starts_with("TOTP_")
    }
}

/// An item's fields, and how many fields were references to other items
/// and files, which are not imported.
struct Entries {
    entries: Vec<Entry>,
    references: usize,
    files: usize,
}

impl Entries {
    fn new(details: &Value) -> Self {
        let mut out = Self {
            entries: Vec::new(),
            references: 0,
            files: 0,
        };
        for field in array(details, "loginFields") {
            let Some(value) = text(field, "value") else {
                continue;
            };
            let secret = text(field, "fieldType").as_deref() == Some("P");
            out.entries.push(Entry {
                title: text(field, "name").unwrap_or_default(),
                id: text(field, "id").unwrap_or_default(),
                key: if secret { "concealed" } else { "string" }.into(),
                designation: text(field, "designation"),
                value,
            });
        }
        for section in array(details, "sections") {
            let section_title = text(section, "title").unwrap_or_default();
            for field in array(section, "fields") {
                let Some((key, value)) = field
                    .get("value")
                    .and_then(Value::as_object)
                    .and_then(|v| v.iter().next())
                else {
                    continue;
                };
                match key.as_str() {
                    "reference" => out.references += 1,
                    "file" => out.files += 1,
                    _ => {}
                }
                let Some(value) = section_value(key, value) else {
                    continue;
                };
                out.entries.push(Entry {
                    title: text(field, "title").unwrap_or_else(|| section_title.clone()),
                    id: text(field, "id").unwrap_or_default(),
                    key: key.clone(),
                    designation: None,
                    value,
                });
            }
        }
        out
    }

    /// Removes and returns the first field `pick` chooses.
    fn take(&mut self, pick: impl Fn(&Entry) -> bool) -> Option<String> {
        let at = self.entries.iter().position(pick)?;
        Some(self.entries.remove(at).value)
    }

    /// The rest become extra fields, named by their titles.
    fn extras(self, b: &mut Builder, summary: &mut Summary) {
        for entry in self.entries {
            let kind = entry.kind();
            let base = field_name(if entry.title.is_empty() {
                &entry.id
            } else {
                &entry.title
            });
            if kind == FieldType::Url {
                b.urls([entry.value], summary);
            } else {
                b.extra(&base, kind, entry.value);
            }
        }
        summary.drop_some(LINKED_FIELD, self.references);
        summary.drop_some(ATTACHMENT, self.files);
    }
}

/// A section field's value as text. Files and references have none.
fn section_value(key: &str, value: &Value) -> Option<String> {
    match key {
        "file" | "reference" => None,
        "email" if value.is_object() => text(value, "email_address"),
        // The top-level key's format varies; the metadata's is PKCS#8 PEM.
        "sshKey" if value.is_object() => value
            .get("metadata")
            .and_then(|m| text(m, "privateKey"))
            .or_else(|| text(value, "privateKey")),
        "date" => value.as_i64().map(date),
        "monthYear" => match value {
            Value::Number(n) => n.as_i64().map(month_year),
            _ => scalar(value),
        },
        "address" => address(
            [text(value, "street")],
            text(value, "city"),
            text(value, "state"),
            text(value, "zip"),
            text(value, "country"),
        ),
        _ => scalar(value),
    }
}

/// `YYYYMM` as `YYYY-MM`, or the number as text if it isn't one.
fn month_year(n: i64) -> String {
    u8::try_from(n % 100)
        .ok()
        .and_then(|m| month(&m.to_string(), &(n / 100).to_string()))
        .unwrap_or_else(|| n.to_string())
}

/// A 1Password date, Unix seconds, as `YYYY-MM-DD`: the nearest day, so a
/// day's local midnight from UTC+11 to UTC-12, or its noon UTC, lands on it
/// rather than the day before.
fn date(secs: i64) -> String {
    // Howard Hinnant's days-to-civil.
    let z = (secs + 43_199).div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// 1Password's card type codes as card brands.
fn brand(code: String) -> String {
    let name = match code.to_lowercase().as_str() {
        "visa" => "Visa",
        "mc" | "mastercard" => "Mastercard",
        "amex" => "American Express",
        "discover" => "Discover",
        "diners" => "Diners Club",
        "carteblanche" => "Carte Blanche",
        "jcb" => "JCB",
        "maestro" => "Maestro",
        "visaelectron" => "Visa Electron",
        "laser" => "Laser",
        "unionpay" => "UnionPay",
        _ => return code,
    };
    name.into()
}

/// An item's website and its other URLs.
fn urls(overview: &Value) -> impl Iterator<Item = String> + '_ {
    text(overview, "url").into_iter().chain(
        array(overview, "urls")
            .iter()
            .filter_map(|u| text(u, "url")),
    )
}

fn login(item: &Value, summary: &mut Summary) -> Option<Imported> {
    let details = item.get("details").unwrap_or(&Value::Null);
    let overview = item.get("overview").unwrap_or(&Value::Null);
    let mut entries = Entries::new(details);
    let password = entries
        .take(|e| e.designation.as_deref() == Some("password"))
        .or_else(|| text(details, "password"))
        .or_else(|| entries.take(|e| e.designation.is_none() && e.is("password")))
        .or_else(|| entries.take(|e| e.designation.is_none() && e.is("credential")))
        .or_else(|| entries.take(|e| e.designation.is_none() && e.is("wireless_password")));
    let mut b = Builder::new("login");
    b.known("password", password);
    let username = entries
        .take(|e| e.designation.as_deref() == Some("username"))
        .or_else(|| entries.take(|e| e.designation.is_none() && e.is("username")));
    b.known("username", username);
    b.known_or_extra("otp", entries.take(Entry::is_totp), BAD_OTP, summary);
    b.known("notes", text(details, "notesPlain"));
    b.urls(urls(overview), summary);
    entries.extras(&mut b, summary);
    b.finish("login", item_name(text(overview, "title")), summary)
}

fn card(item: &Value, summary: &mut Summary) -> Option<Imported> {
    let details = item.get("details").unwrap_or(&Value::Null);
    let overview = item.get("overview").unwrap_or(&Value::Null);
    let mut entries = Entries::new(details);
    let mut b = Builder::new("card");
    let number = entries
        .take(|e| e.id == "ccnum")
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
    let cvv = entries
        .take(|e| e.id == "cvv")
        .map(|c| c.trim().to_string());
    b.known_or_extra("cvv", cvv, BAD_CVV, summary);
    let expiry = entries.take(|e| e.id == "expiry").map(|e| {
        e.split_once('/')
            .and_then(|(m, y)| month(m, y))
            .unwrap_or(e)
    });
    b.known_or_extra("expiry", expiry, BAD_EXPIRY, summary);
    b.known("cardholder", entries.take(|e| e.id == "cardholder"));
    b.known("brand", entries.take(|e| e.id == "type").map(brand));
    b.known("pin", entries.take(|e| e.id == "pin"));
    b.known("notes", text(details, "notesPlain"));
    b.urls(urls(overview), summary);
    entries.extras(&mut b, summary);
    b.finish("card", item_name(text(overview, "title")), summary)
}

/// A secure note, and every category with no closer type here (software
/// licenses, bank accounts, passports, memberships, ...): the notes are the
/// body and every field is kept, secret where 1Password conceals it.
fn note(item: &Value, category: &str, summary: &mut Summary) -> Option<Imported> {
    let details = item.get("details").unwrap_or(&Value::Null);
    let overview = item.get("overview").unwrap_or(&Value::Null);
    let mut b = Builder::new("note");
    b.known("notes", text(details, "notesPlain"));
    b.urls(urls(overview), summary);
    let mut entries = Entries::new(details);
    // ID and account numbers 1Password leaves in plain text are secret here.
    let secret: &[&str] = match category {
        "101" => &["accountNo", "iban"],
        "103" | "106" | "108" => &["number"],
        _ => &[],
    };
    for entry in &mut entries.entries {
        if secret.contains(&entry.id.as_str()) {
            entry.key = "concealed".into();
        }
    }
    entries.extras(&mut b, summary);
    b.finish("note", item_name(text(overview, "title")), summary)
}

/// The `sshKey` value's metadata: the public key and fingerprint.
fn ssh_metadata(details: &Value) -> &Value {
    array(details, "sections")
        .iter()
        .flat_map(|section| array(section, "fields"))
        .find_map(|field| field.get("value")?.get("sshKey")?.get("metadata"))
        .unwrap_or(&Value::Null)
}

fn ssh(item: &Value, summary: &mut Summary) -> Option<Imported> {
    let details = item.get("details").unwrap_or(&Value::Null);
    let overview = item.get("overview").unwrap_or(&Value::Null);
    let mut entries = Entries::new(details);
    let Some(private) = entries.take(|e| e.key == "sshKey") else {
        summary.skip(NO_PRIVATE_KEY);
        return None;
    };
    let mut b = Builder::new("ssh");
    b.known("private-key", Some(private));
    // 1Password 8 keeps these in the item's fields; older exports only in
    // the key's metadata.
    let metadata = ssh_metadata(details);
    let mut field = |names: [&str; 2]| entries.take(|e| names.iter().any(|n| e.is(n)));
    let public = field(["public_key", "public key"]).or_else(|| text(metadata, "publicKey"));
    let fingerprint =
        field(["fingerprint", "fingerprint"]).or_else(|| text(metadata, "fingerprint"));
    let passphrase = field(["passphrase", "password"]);
    let comment = field(["comment", "comment"]);
    b.known("public-key", public);
    b.known("fingerprint", fingerprint);
    b.known("passphrase", passphrase);
    b.known("comment", comment);
    b.known("notes", text(details, "notesPlain"));
    b.urls(urls(overview), summary);
    entries.extras(&mut b, summary);
    b.finish("ssh", item_name(text(overview, "title")), summary)
}

fn identity(item: &Value, summary: &mut Summary) -> Option<Imported> {
    let details = item.get("details").unwrap_or(&Value::Null);
    let overview = item.get("overview").unwrap_or(&Value::Null);
    let mut entries = Entries::new(details);
    let mut b = Builder::new("identity");
    let mut by_id = |id: &str| entries.take(|e| e.id == id);
    let name = join(
        [by_id("firstname"), by_id("initial"), by_id("lastname")],
        " ",
    );
    b.known("name", name);
    let birthday = by_id("birthdate");
    let phone = by_id("defphone")
        .or_else(|| by_id("cellphone"))
        .or_else(|| by_id("homephone"))
        .or_else(|| by_id("busphone"));
    let email = by_id("email");
    let address = by_id("address");
    b.known_or_extra("birthday", birthday, BAD_BIRTHDAY, summary);
    b.known("phone", phone);
    b.known_or_extra("email", email, BAD_EMAIL, summary);
    b.known("address", address);
    b.known("notes", text(details, "notesPlain"));
    b.urls(urls(overview), summary);
    entries.extras(&mut b, summary);
    b.finish("identity", item_name(text(overview, "title")), summary)
}

/// Maps a 1PUX `export.data`.
pub fn export(export: &Value) -> Result<(Vec<Imported>, Summary)> {
    let Some(accounts) = export.get("accounts").and_then(Value::as_array) else {
        bail!("not a 1Password export: no \"accounts\" list");
    };
    let mut summary = Summary::new(ImportSource::OnePassword);
    let mut tags = BTreeSet::new();
    let mut out = Vec::new();
    let items = accounts
        .iter()
        .flat_map(|account| array(account, "vaults"))
        .flat_map(|vault| array(vault, "items"));
    for item in items {
        if text(item, "state").as_deref() == Some("archived") {
            summary.skip(ARCHIVED);
            continue;
        }
        let category = text(item, "categoryUuid").unwrap_or_default();
        let mapped = match category.as_str() {
            "001" | "005" | "102" | "109" | "110" | "112" => login(item, &mut summary),
            "002" => card(item, &mut summary),
            "004" => identity(item, &mut summary),
            "114" => ssh(item, &mut summary),
            "003" | "100" | "101" | "103" | "104" | "105" | "106" | "107" | "108" | "111"
            | "113" => note(item, &category, &mut summary),
            other => {
                summary.skip(skipped(other));
                continue;
            }
        };
        let Some(mapped) = mapped else {
            continue;
        };
        let details = item.get("details").unwrap_or(&Value::Null);
        let overview = item.get("overview").unwrap_or(&Value::Null);
        if number(item, "favIndex").is_some_and(|i| i > 0) {
            summary.drop_some(FAVORITE, 1);
        }
        tags.extend(array(overview, "tags").iter().filter_map(scalar));
        if !array(details, "passwordHistory").is_empty() {
            summary.drop_some(PASSWORD_HISTORY, 1);
        }
        summary.add(&mapped);
        out.push(mapped);
    }
    summary.drop_some(TAG, tags.len());
    Ok((out, summary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::parse;
    use crate::import::tests::{fields, lines};

    /// Shaped like the `export.data` of a 1Password 8 `.1pux`: two vaults.
    const EXPORT: &str = r#"{
  "accounts": [
    {
      "attrs": {
        "accountName": "Dax",
        "name": "Dax Raad",
        "avatar": "",
        "email": "dax@example.com",
        "uuid": "AAAABBBBCCCCDDDDEEEEFFFFGG",
        "domain": "https://my.1password.com/"
      },
      "vaults": [
        {
          "attrs": { "uuid": "v1v1v1v1v1v1v1v1v1v1v1v1v1", "desc": "", "avatar": "", "name": "Private", "type": "P" },
          "items": [
            {
              "uuid": "item1item1item1item1item1a",
              "favIndex": 1,
              "createdAt": 1700000000,
              "updatedAt": 1710000000,
              "state": "active",
              "categoryUuid": "001",
              "details": {
                "loginFields": [
                  { "value": "dax@example.com", "id": "", "name": "email", "fieldType": "E", "designation": "username" },
                  { "value": "op-github-pw", "id": "", "name": "password", "fieldType": "P", "designation": "password" },
                  { "value": "✓", "id": "remember", "name": "remember_me", "fieldType": "C" },
                  { "value": "", "id": "", "name": "commit", "fieldType": "I" }
                ],
                "notesPlain": "work account\nsecond line",
                "sections": [
                  {
                    "title": "Security",
                    "name": "add more",
                    "fields": [
                      { "title": "one-time password", "id": "TOTP_abc123", "value": { "totp": "otpauth://totp/GitHub:dax?secret=JBSWY3DPEHPK3PXP&issuer=GitHub" }, "guarded": false, "multiline": false },
                      { "title": "Recovery codes", "id": "f1", "value": { "concealed": "op-recovery-111" } },
                      { "title": "", "id": "f2", "value": { "string": "untitled value" } },
                      { "title": "member since", "id": "f3", "value": { "date": 1704067200 } },
                      { "title": "backup email", "id": "f4", "value": { "email": { "email_address": "backup@example.com", "provider": null } } },
                      { "title": "renews", "id": "f5", "value": { "monthYear": 202812 } },
                      { "title": "other login", "id": "f6", "value": { "reference": "item9item9item9item9item9a" } },
                      { "title": "empty", "id": "f7", "value": { "string": "" } },
                      { "title": "blank", "id": "f9", "value": { "concealed": "   " } },
                      { "title": "", "id": "f10", "value": { "file": { "documentId": "doc1doc1doc1doc1doc1doc1d1", "fileName": "recovery.pdf", "decryptedSize": 1024 } } }
                    ]
                  },
                  { "title": "Docs", "name": "docs", "fields": [
                    { "title": "status page", "id": "f8", "value": { "url": "https://www.githubstatus.com" } }
                  ] }
                ],
                "passwordHistory": [ { "value": "op-old-pw", "time": 1690000000 } ]
              },
              "overview": {
                "subtitle": "dax@example.com",
                "urls": [
                  { "label": "", "url": "https://github.com/login" },
                  { "label": "gist", "url": "gist.github.com" }
                ],
                "title": "GitHub",
                "url": "https://github.com/login",
                "ps": 100,
                "tags": ["work", "dev"]
              }
            },
            {
              "uuid": "item2item2item2item2item2a",
              "favIndex": 0,
              "state": "active",
              "categoryUuid": "005",
              "details": { "loginFields": [], "notesPlain": "", "sections": [], "passwordHistory": [], "password": "op-wifi-pw" },
              "overview": { "title": "Garage door", "tags": ["home"] }
            },
            {
              "uuid": "item3item3item3item3item3a",
              "favIndex": 0,
              "state": "active",
              "categoryUuid": "003",
              "details": { "loginFields": [], "notesPlain": "op-note-secret", "sections": [], "passwordHistory": [] },
              "overview": { "title": "A note" }
            },
            {
              "uuid": "item4item4item4item4item4a",
              "favIndex": 0,
              "state": "archived",
              "categoryUuid": "001",
              "details": { "loginFields": [ { "value": "op-archived-pw", "name": "password", "fieldType": "P", "designation": "password" } ] },
              "overview": { "title": "Old site", "url": "https://old.example.com" }
            }
          ]
        },
        {
          "attrs": { "uuid": "v2v2v2v2v2v2v2v2v2v2v2v2v2", "name": "Shared", "type": "U" },
          "items": [
            {
              "uuid": "item5item5item5item5item5a",
              "favIndex": 2,
              "state": "active",
              "categoryUuid": "002",
              "details": {
                "loginFields": [],
                "notesPlain": "",
                "sections": [
                  {
                    "title": "",
                    "name": "",
                    "fields": [
                      { "title": "cardholder name", "id": "cardholder", "value": { "string": "Dax Raad" } },
                      { "title": "type", "id": "type", "value": { "creditCardType": "visa" } },
                      { "title": "number", "id": "ccnum", "value": { "creditCardNumber": "4242 4242 4242 4242" } },
                      { "title": "verification number", "id": "cvv", "value": { "concealed": "321" } },
                      { "title": "website", "id": "site", "value": { "url": "https://bank.example" } },
                      { "title": "expiry date", "id": "expiry", "value": { "monthYear": 202704 } },
                      { "title": "valid from", "id": "validFrom", "value": { "monthYear": 202204 } },
                      { "title": "PIN", "id": "pin", "value": { "concealed": "9876" } }
                    ]
                  },
                  {
                    "title": "Contact Information",
                    "name": "contactInfo",
                    "fields": [
                      { "title": "issuing bank", "id": "bank", "value": { "string": "Example Bank" } },
                      { "title": "phone (intl)", "id": "phoneIntl", "value": { "phone": "+1 555 0100" } },
                      { "title": "address", "id": "addr", "value": { "address": { "street": "1 Main St", "city": "Springfield", "country": "us", "zip": "12345", "state": "" } } }
                    ]
                  }
                ],
                "passwordHistory": []
              },
              "overview": { "title": "Visa", "subtitle": "4242 ****", "url": "bank.example", "urls": [ { "url": "https://bank.example" }, { "url": "https://cards.bank.example" } ] }
            },
            {
              "uuid": "item6item6item6item6item6a",
              "favIndex": 0,
              "state": "active",
              "categoryUuid": "112",
              "details": {
                "sections": [ { "title": "", "fields": [
                  { "title": "username", "id": "username", "value": { "string": "deploy-bot" } },
                  { "title": "credential", "id": "credential", "value": { "concealed": "op-api-key" } },
                  { "title": "hostname", "id": "hostname", "value": { "string": "api.example.com" } }
                ] } ]
              },
              "overview": { "title": "Deploy API" }
            },
            {
              "uuid": "item7item7item7item7item7a",
              "favIndex": 0,
              "state": "active",
              "categoryUuid": "001",
              "details": { "loginFields": [ { "value": "nobody", "name": "username", "fieldType": "T", "designation": "username" } ] },
              "overview": { "title": "No password" }
            },
            {
              "uuid": "item8",
              "state": "active",
              "categoryUuid": "004",
              "details": {
                "notesPlain": "",
                "sections": [
                  { "title": "Identification", "name": "name", "fields": [
                    { "title": "first name", "id": "firstname", "value": { "string": "Dax" } },
                    { "title": "initial", "id": "initial", "value": { "string": "" } },
                    { "title": "last name", "id": "lastname", "value": { "string": "Raad" } },
                    { "title": "birth date", "id": "birthdate", "value": { "date": 636246000 } },
                    { "title": "company", "id": "company", "value": { "string": "Anomaly" } }
                  ] },
                  { "title": "Address", "name": "address", "fields": [
                    { "title": "address", "id": "address", "value": { "address": { "street": "1 Main St", "city": "Springfield", "state": "IL", "zip": "12345", "country": "us" } } },
                    { "title": "default phone", "id": "defphone", "value": { "phone": "+1 555 0100" } }
                  ] },
                  { "title": "Internet Details", "name": "internet", "fields": [
                    { "title": "email", "id": "email", "value": { "email": { "email_address": "not an email", "provider": null } } }
                  ] }
                ]
              },
              "overview": { "title": "Me" }
            },
            {
              "uuid": "itemC",
              "state": "active",
              "categoryUuid": "114",
              "details": {
                "notesPlain": "for CI",
                "sections": [ { "title": "", "name": "", "fields": [
                  { "title": "private key", "id": "private_key", "value": { "sshKey": {
                    "privateKey": "-----BEGIN PRIVATE KEY-----\npkcs8\n-----END PRIVATE KEY-----",
                    "metadata": {
                      "privateKey": "-----BEGIN PRIVATE KEY-----\npkcs8\n-----END PRIVATE KEY-----",
                      "publicKey": "ssh-ed25519 AAAAC3Nz deploy@ci",
                      "fingerprint": "SHA256:abc",
                      "keyType": "ed25519"
                    }
                  } } },
                  { "title": "public key", "id": "public_key", "value": { "string": "ssh-ed25519 AAAAC3Nz deploy@ci" } },
                  { "title": "fingerprint", "id": "fingerprint", "value": { "string": "SHA256:abc" } },
                  { "title": "key type", "id": "key_type", "value": { "string": "ed25519" } }
                ] },
                { "title": "More", "name": "more", "fields": [
                  { "title": "passphrase", "id": "f1", "value": { "concealed": "op-ssh-pass" } },
                  { "title": "comment", "id": "f2", "value": { "string": "deploy@ci" } }
                ] } ]
              },
              "overview": { "title": "CI key" }
            },
            {
              "uuid": "itemE",
              "state": "active",
              "categoryUuid": "114",
              "details": {
                "sections": [ { "title": "", "name": "", "fields": [
                  { "title": "private key", "id": "private_key", "value": { "sshKey": {
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nopenssh\n-----END OPENSSH PRIVATE KEY-----",
                    "metadata": {
                      "privateKey": "-----BEGIN PRIVATE KEY-----\nold\n-----END PRIVATE KEY-----",
                      "publicKey": "ssh-rsa AAAAB3 old",
                      "fingerprint": "SHA256:old",
                      "keyType": "rsa"
                    }
                  } } }
                ] } ]
              },
              "overview": { "title": "Old key" }
            },
            { "uuid": "item9", "state": "active", "categoryUuid": "114", "details": {}, "overview": { "title": "Deploy key" } },
            {
              "uuid": "itemD",
              "state": "active",
              "categoryUuid": "100",
              "details": {
                "notesPlain": "bought 2024",
                "sections": [ { "title": "", "name": "", "fields": [
                  { "title": "license key", "id": "reg_code", "value": { "string": "ABCD-1234" } },
                  { "title": "version", "id": "product_version", "value": { "string": "5" } },
                  { "title": "password", "id": "retail_password", "value": { "concealed": "op-license-pw" } }
                ] } ]
              },
              "overview": { "title": "Editor" }
            },
            {
              "uuid": "itemF",
              "state": "active",
              "categoryUuid": "101",
              "details": { "sections": [ { "title": "", "name": "", "fields": [
                { "title": "bank name", "id": "bankName", "value": { "string": "Example Bank" } },
                { "title": "account number", "id": "accountNo", "value": { "string": "op-account-12345678" } },
                { "title": "IBAN", "id": "iban", "value": { "string": "op-iban-DE00" } },
                { "title": "PIN", "id": "telephonePin", "value": { "concealed": "op-phone-pin" } }
              ] } ] },
              "overview": { "title": "Checking" }
            },
            {
              "uuid": "itemG",
              "state": "active",
              "categoryUuid": "106",
              "details": { "sections": [ { "title": "", "name": "", "fields": [
                { "title": "full name", "id": "fullname", "value": { "string": "Dax Raad" } },
                { "title": "number", "id": "number", "value": { "string": "op-passport-X123" } }
              ] } ] },
              "overview": { "title": "Passport" }
            },
            { "uuid": "itemA", "state": "active", "categoryUuid": "006", "details": { "documentAttributes": { "fileName": "passport.pdf" } }, "overview": { "title": "Scan" } },
            { "uuid": "itemB", "state": "active", "categoryUuid": "999", "details": {}, "overview": { "title": "Future" } }
          ]
        }
      ]
    }
  ]
}"#;

    #[test]
    fn maps_a_1pux_export() {
        let (items, report) = parse(EXPORT).unwrap();
        assert_eq!(report.source, ImportSource::OnePassword);
        let kinds: Vec<_> = items
            .iter()
            .map(|i| (i.kind, i.name.as_deref().unwrap_or_default()))
            .collect();
        assert_eq!(
            kinds,
            [
                ("login", "GitHub"),
                ("login", "Garage door"),
                ("note", "A note"),
                ("card", "Visa"),
                ("login", "Deploy API"),
                ("login", "No password"),
                ("identity", "Me"),
                ("ssh", "CI key"),
                ("ssh", "Old key"),
                ("note", "Editor"),
                ("note", "Checking"),
                ("note", "Passport"),
            ]
        );
        let github = &items[0];
        assert_eq!(
            fields(github),
            [
                ("backup-email", "email", "backup@example.com"),
                ("member-since", "date", "2024-01-01"),
                ("notes", "note", "work account\nsecond line"),
                (
                    "otp",
                    "otp",
                    "otpauth://totp/GitHub:dax?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
                ),
                ("password", "secret", "op-github-pw"),
                ("recovery-codes", "secret", "op-recovery-111"),
                ("remember_me", "text", "✓"),
                ("renews", "month", "2028-12"),
                ("security", "text", "untitled value"),
                ("url", "url", "https://github.com/login"),
                ("url-2", "url", "https://gist.github.com"),
                ("url-3", "url", "https://www.githubstatus.com"),
                ("username", "text", "dax@example.com"),
            ]
        );
        assert_eq!(fields(&items[1]), [("password", "secret", "op-wifi-pw")]);
        // A secure note's body is secret.
        assert_eq!(fields(&items[2]), [("notes", "secret", "op-note-secret")]);
        assert_eq!(
            fields(&items[3]),
            [
                ("address", "note", "1 Main St\nSpringfield, 12345\nus"),
                ("brand", "text", "Visa"),
                ("cardholder", "text", "Dax Raad"),
                ("cvv", "secret", "321"),
                ("expiry", "month", "2027-04"),
                ("issuing-bank", "text", "Example Bank"),
                ("number", "secret", "4242424242424242"),
                ("phone-intl", "text", "+1 555 0100"),
                ("pin", "secret", "9876"),
                ("url", "url", "https://bank.example"),
                ("url-2", "url", "https://cards.bank.example"),
                ("valid-from", "month", "2022-04"),
            ]
        );
        assert_eq!(
            fields(&items[4]),
            [
                ("hostname", "text", "api.example.com"),
                ("password", "secret", "op-api-key"),
                ("username", "text", "deploy-bot"),
            ]
        );
        // A login needs no password.
        assert_eq!(fields(&items[5]), [("username", "text", "nobody")]);
        assert_eq!(
            fields(&items[6]),
            [
                ("address", "note", "1 Main St\nSpringfield, IL 12345\nus"),
                ("birthday", "date", "1990-03-01"),
                ("company", "text", "Anomaly"),
                ("email-2", "text", "not an email"),
                ("name", "text", "Dax Raad"),
                ("phone", "text", "+1 555 0100"),
            ]
        );
        // A 1Password 8 key: its values from the item's fields, each once.
        assert_eq!(
            fields(&items[7]),
            [
                ("comment", "text", "deploy@ci"),
                ("fingerprint", "text", "SHA256:abc"),
                ("key-type", "text", "ed25519"),
                ("notes", "note", "for CI"),
                ("passphrase", "secret", "op-ssh-pass"),
                (
                    "private-key",
                    "secret",
                    "-----BEGIN PRIVATE KEY-----\npkcs8\n-----END PRIVATE KEY-----"
                ),
                ("public-key", "text", "ssh-ed25519 AAAAC3Nz deploy@ci"),
            ]
        );
        // An older one: the PKCS#8 key and the rest from its metadata.
        assert_eq!(
            fields(&items[8]),
            [
                ("fingerprint", "text", "SHA256:old"),
                (
                    "private-key",
                    "secret",
                    "-----BEGIN PRIVATE KEY-----\nold\n-----END PRIVATE KEY-----"
                ),
                ("public-key", "text", "ssh-rsa AAAAB3 old"),
            ]
        );
        // Other categories are notes that keep every field.
        assert_eq!(
            fields(&items[9]),
            [
                ("license-key", "text", "ABCD-1234"),
                ("notes", "secret", "bought 2024"),
                ("password", "secret", "op-license-pw"),
                ("version", "text", "5"),
            ]
        );
        // ID and account numbers are secret, though 1Password exports them
        // as plain strings.
        assert_eq!(
            fields(&items[10]),
            [
                ("account-number", "secret", "op-account-12345678"),
                ("bank-name", "text", "Example Bank"),
                ("iban", "secret", "op-iban-DE00"),
                ("pin", "secret", "op-phone-pin"),
            ]
        );
        assert_eq!(
            fields(&items[11]),
            [
                ("full-name", "text", "Dax Raad"),
                ("number", "secret", "op-passport-X123"),
            ]
        );
        assert_eq!(
            lines(&report),
            [
                "imported 12 from 1Password (logins 4, cards 1, secure notes 4, SSH keys 2, identities 1)",
                "skipped 1 SSH key without a private key",
                "skipped 1 archived item",
                "skipped 1 document",
                "skipped 1 item of unknown type",
                "warning: 1 invalid email address kept as text",
                "dropped: 1 attachment, 2 favorites, 1 item's password history, 1 linked field, 3 tags",
            ]
        );
    }

    #[test]
    fn dates_and_months() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_704_067_200), "2024-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(-86_400), "1969-12-31");
        // 1990-03-01 at midnight in UTC, CET, PST, UTC+11 and UTC-12, and at
        // noon UTC.
        for secs in [
            636_249_600,
            636_249_600 - 3_600,
            636_249_600 + 8 * 3_600,
            636_249_600 - 11 * 3_600,
            636_249_600 + 12 * 3_600,
        ] {
            assert_eq!(date(secs), "1990-03-01", "{secs}");
        }
        assert_eq!(date(636_249_600 + 12 * 3_600 + 1), "1990-03-02");
        assert_eq!(month_year(202_704), "2027-04");
        assert_eq!(month_year(202_713), "202713");
        assert_eq!(month_year(7), "7");
    }

    #[test]
    fn errors_name_no_values() {
        let error =
            parse(r#"{"accounts": [{"vaults": [{"items": [{"details": {"password": "op-s3cret"#)
                .err()
                .unwrap()
                .to_string();
        assert!(!error.contains("op-s3cret"), "{error}");
        assert!(parse(r#"{"accounts": {}}"#).is_err());
    }
}
