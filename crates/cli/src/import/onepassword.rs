//! 1Password's 1PUX export: the `export.data` JSON inside the `.1pux` zip
//! (`{accounts: [{vaults: [{attrs, items: [...]}]}]}`). Items from every
//! account and vault go into the one target vault. Its documents and the
//! files attached to other items come from the zip's `files/`, read by the
//! client beside the text (`deadbolt_client::export`).
//!
//! Categories map to the type closest to them: API credentials, databases,
//! servers, Wi-Fi routers, software licenses, bank accounts, documents,
//! passports, driver's licenses, memberships, crypto wallets and social
//! security numbers have types of their own; outdoor licenses, reward
//! programs, email accounts and medical records become secure notes that
//! keep every field.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use deadbolt_core::item::valid_source;
use deadbolt_core::{FieldType, Source};
use serde_json::Value;

use super::{
    ARCHIVED, ATTACHMENT, BAD_BIRTHDAY, BAD_CVV, BAD_EMAIL, BAD_EXPIRY, BAD_OTP, BAD_VALUE,
    BIG_ATTACHMENT, BIG_FILE, Builder, Imported, LINKED_FIELD, MISSING_ATTACHMENT, MISSING_FILE,
    MirrorVersion, NO_NUMBER, NO_PRIVATE_KEY, Origin, PASSWORD_HISTORY, Summary, UNKNOWN_TYPE,
    address, array, field_name, item_name, month, number, scalar, tags, text,
};
use crate::items::with_scheme;
use crate::protocol::{ExportFile, ImportSource, sign_in_provider};

/// A `.1pux`'s attachments, as the client read them from `files/`; `None`
/// for the `op` CLI's items, which come without their files.
#[derive(Clone, Copy)]
pub(super) struct Files<'a>(Option<&'a [ExportFile]>);

impl<'a> Files<'a> {
    pub(super) const NONE: Files<'static> = Files(None);

    /// The file with `documentId` `id` (named `<id>__<fileName>` in the
    /// archive, or `<id>`), in base64.
    fn get(&self, id: &str) -> Result<&'a str, Missing> {
        let file = self
            .0
            .ok_or(Missing::Gone)?
            .iter()
            .find(|f| {
                f.name
                    .strip_prefix(id)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with("__"))
            })
            .ok_or(Missing::Gone)?;
        if file.too_large {
            return Err(Missing::TooLarge);
        }
        Ok(file.data.as_str())
    }
}

/// Why a file an item names isn't imported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Missing {
    /// Not in the export (or, from the `op` CLI, not fetched).
    Gone,
    /// Over 10 MiB, alone or with the item's other files.
    TooLarge,
}

/// A file a 1Password item names: an attachment or a document's file.
struct Attachment {
    title: String,
    file_name: String,
    /// Its `documentId`; `None` where the item doesn't say (the `op` CLI's).
    id: Option<String>,
}

impl Attachment {
    fn new(title: String, value: &Value) -> Self {
        Self {
            title,
            file_name: text(value, "fileName").unwrap_or_else(|| "attachment".into()),
            id: text(value, "documentId"),
        }
    }

    /// The file field's value, if its contents came and `budget` (the
    /// bytes the item may still hold in files) has room; the budget shrinks
    /// by what it takes.
    fn value(&self, files: Files, budget: &mut usize) -> Result<String, Missing> {
        let data = files.get(self.id.as_deref().ok_or(Missing::Gone)?)?;
        let size = deadbolt_core::item::file_size(data).ok_or(Missing::Gone)?;
        if size > *budget {
            return Err(Missing::TooLarge);
        }
        *budget -= size;
        Ok(format!("{}\n{data}", file_name(&self.file_name)))
    }
}

/// A file name another app gave, as a valid one: separators (`/`, `\`,
/// `:`) and control characters become `_`, at most 255 characters.
fn file_name(name: &str) -> String {
    let name: String = name
        .trim()
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':') || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .take(deadbolt_core::item::MAX_FILE_NAME)
        .collect();
    let name = name.trim().to_string();
    if deadbolt_core::item::valid_file_name(&name) {
        name
    } else {
        "attachment".into()
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

/// An item's fields, its attachments, and how many fields were references
/// to other items, which are not imported.
struct Entries {
    entries: Vec<Entry>,
    references: usize,
    attachments: Vec<Attachment>,
    /// A "Sign in with" field (`ssoLogin`): the provider, and the vault and
    /// item ids of the login it signs in with, if it names one.
    sign_in: Option<(String, Option<(String, String)>)>,
}

impl Entries {
    fn new(details: &Value) -> Self {
        let mut out = Self {
            entries: Vec::new(),
            references: 0,
            attachments: Vec::new(),
            sign_in: None,
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
                    "file" => {
                        let title = text(field, "title").unwrap_or_default();
                        out.attachments.push(Attachment::new(title, value));
                        continue;
                    }
                    "ssoLogin" => {
                        if out.sign_in.is_none()
                            && let Some(provider) = text(value, "provider")
                        {
                            let link = value.get("item").and_then(|item| {
                                Some((text(item, "vaultUuid")?, text(item, "itemUuid")?))
                            });
                            out.sign_in = Some((provider, link));
                        }
                        continue;
                    }
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

    /// The rest become extra fields, named by their titles, and the
    /// attachments file fields, named by their titles or file names. An
    /// item's files hold at most `MAX_FILE` bytes in all, so its create
    /// fits in one entry; the rest are dropped and counted.
    fn extras(self, b: &mut Builder, files: Files, summary: &mut Summary) {
        let mut budget = deadbolt_core::item::MAX_FILE.saturating_sub(b.file_bytes());
        for attachment in &self.attachments {
            let value = match attachment.value(files, &mut budget) {
                Ok(value) => value,
                Err(_) if files.0.is_none() => {
                    summary.drop_some(ATTACHMENT, 1);
                    continue;
                }
                Err(Missing::Gone) => {
                    summary.drop_some(MISSING_ATTACHMENT, 1);
                    continue;
                }
                Err(Missing::TooLarge) => {
                    summary.drop_some(BIG_ATTACHMENT, 1);
                    continue;
                }
            };
            let base = if attachment.title.trim().is_empty() {
                let name = attachment.file_name.as_str();
                let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
                field_name(stem)
            } else {
                field_name(&attachment.title)
            };
            b.extra(&base, FieldType::File, value);
        }
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
    }
}

/// A section field's value as text. Files and references have none.
fn section_value(key: &str, value: &Value) -> Option<String> {
    match key {
        "file" | "reference" | "ssoLogin" => None,
        "email" if value.is_object() => text(value, "email_address"),
        // The top-level key's format varies; the metadata's is PKCS#8 PEM.
        "sshKey" if value.is_object() => value
            .get("metadata")
            .and_then(|m| text(m, "privateKey"))
            .or_else(|| text(value, "privateKey")),
        // The `op` CLI's dates may come as text (`YYYY-MM-DD`) already.
        "date" => value.as_i64().map(date).or_else(|| scalar(value)),
        "monthYear" => match value {
            Value::Number(n) => n.as_i64().map(month_year),
            _ => scalar(value),
        },
        "address" if value.is_object() => address(
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
pub(crate) fn date(secs: i64) -> String {
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

fn login(item: &Value, files: Files, summary: &mut Summary) -> Option<Imported> {
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
    let sign_in = entries.sign_in.take();
    let mut link = None;
    if let Some((provider, to)) = sign_in
        && b.known("sign-in-with", sign_in_provider(&provider))
    {
        link = to;
    }
    entries.extras(&mut b, files, summary);
    let mut item = b.finish("login", item_name(text(overview, "title")), summary)?;
    item.sign_in_link = link;
    Some(item)
}

fn card(item: &Value, files: Files, summary: &mut Summary) -> Option<Imported> {
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
    entries.extras(&mut b, files, summary);
    b.finish("card", item_name(text(overview, "title")), summary)
}

/// A secure note, and every category with no closer type here (outdoor
/// licenses, reward programs, email accounts, medical records): the notes
/// are the body and every field is kept, secret where 1Password conceals it.
fn note(item: &Value, files: Files, summary: &mut Summary) -> Option<Imported> {
    let details = item.get("details").unwrap_or(&Value::Null);
    let overview = item.get("overview").unwrap_or(&Value::Null);
    let mut b = Builder::new("note");
    b.known("notes", text(details, "notesPlain"));
    b.urls(urls(overview), summary);
    Entries::new(details).extras(&mut b, files, summary);
    b.finish("note", item_name(text(overview, "title")), summary)
}

/// Which of a 1Password category's fields (by id, else title, any case)
/// fill a type's known fields here, in the order taken.
type FieldMap = &'static [(&'static str, &'static [&'static str])];

/// The types of their own a category maps to, with their fields.
fn typed_kind(category: &str) -> Option<(&'static str, FieldMap)> {
    Some(match category {
        "112" => (
            "api",
            &[
                ("credential", &["credential"]),
                ("username", &["username"]),
                ("type", &["type"]),
                ("host", &["hostname"]),
                ("expires", &["expires"]),
            ],
        ),
        "102" => (
            "database",
            &[
                ("type", &["database_type", "type"]),
                ("host", &["hostname", "server"]),
                ("port", &["port"]),
                ("database", &["database"]),
                ("username", &["username"]),
                ("password", &["password"]),
                (
                    "connection-string",
                    &["connection_string", "connection string"],
                ),
            ],
        ),
        "110" => (
            "server",
            &[
                ("url", &["url"]),
                ("username", &["username"]),
                ("password", &["password"]),
                ("admin-console", &["admin_console_url", "admin console url"]),
            ],
        ),
        "109" => (
            "wifi",
            &[
                ("ssid", &["network_name", "network name"]),
                (
                    "password",
                    &["wireless_password", "wireless network password"],
                ),
                ("security", &["wireless_security", "security"]),
            ],
        ),
        "100" => (
            "license",
            &[
                ("version", &["product_version", "version"]),
                ("license-key", &["reg_code", "license key"]),
                ("licensed-to", &["reg_name", "licensed to"]),
                ("email", &["reg_email", "registered email"]),
                ("order-number", &["order_number", "order number"]),
                ("purchased", &["order_date", "purchase date"]),
            ],
        ),
        "101" => (
            "bank",
            &[
                ("bank", &["bankName", "bank name"]),
                ("account-holder", &["owner", "name on account"]),
                ("account-number", &["accountNo", "account number"]),
                ("routing-number", &["routingNo", "routing number"]),
                ("iban", &["iban"]),
                ("swift", &["swift"]),
                ("pin", &["telephonePin", "pin"]),
            ],
        ),
        "106" => (
            "passport",
            &[
                ("full-name", &["fullname", "full name"]),
                ("number", &["number"]),
                ("type", &["type"]),
                ("issuing-country", &["issuing_country", "issuing country"]),
                (
                    "issuing-authority",
                    &["issuing_authority", "issuing authority"],
                ),
                ("nationality", &["nationality"]),
                ("sex", &["sex"]),
                ("birthday", &["birthdate", "date of birth"]),
                ("birthplace", &["birthplace", "place of birth"]),
                ("issued", &["issue_date", "issued on"]),
                ("expires", &["expiry_date", "expiry date"]),
            ],
        ),
        "103" => (
            "driver-license",
            &[
                ("full-name", &["fullname", "full name"]),
                ("number", &["number"]),
                ("class", &["class"]),
                ("conditions", &["conditions"]),
                ("state", &["state"]),
                ("country", &["country"]),
                ("address", &["address"]),
                ("birthday", &["birthdate", "date of birth"]),
                ("sex", &["sex"]),
                ("height", &["height"]),
                ("expires", &["expiry_date", "expiry date"]),
            ],
        ),
        "105" => (
            "membership",
            &[
                ("organization", &["org_name", "group"]),
                ("member-name", &["member_name", "member name"]),
                ("member-id", &["membership_no", "member id"]),
                ("pin", &["pin"]),
                ("url", &["website"]),
                ("phone", &["phone", "telephone"]),
                ("member-since", &["member_since", "member since"]),
                ("expires", &["expiry_date", "expiry date"]),
            ],
        ),
        "115" => (
            "crypto",
            &[
                (
                    "recovery-phrase",
                    &["recoveryPhrase", "recovery phrase", "seed phrase"],
                ),
                ("password", &["password"]),
                ("address", &["walletAddress", "wallet address", "address"]),
            ],
        ),
        "108" => (
            "id-document",
            &[("full-name", &["name"]), ("number", &["number"])],
        ),
        _ => return None,
    })
}

/// A category with a type of its own here: the fields its map names fill
/// the known fields (a value that doesn't fit stays as an extra field, with
/// a warning), the rest stay as extra fields. `None`, counting nothing, if
/// a required field has no value (an API credential without a credential),
/// so it can be kept as a secure note instead.
fn typed(
    item: &Value,
    (kind, map): (&'static str, FieldMap),
    files: Files,
    summary: &mut Summary,
) -> Option<Imported> {
    let details = item.get("details").unwrap_or(&Value::Null);
    let overview = item.get("overview").unwrap_or(&Value::Null);
    let mut entries = Entries::new(details);
    let mut b = Builder::new(kind);
    let mut warnings = Summary::new(ImportSource::OnePassword);
    for (field, names) in map {
        let value = entries.take(|e| names.iter().any(|n| e.is(n)));
        let value = match b.kind(field) {
            FieldType::Url => value.map(with_scheme),
            _ if *field == "phone" => value.map(|v| deadbolt_core::item::phone(&v).unwrap_or(v)),
            _ => value,
        };
        b.known_or_extra(field, value, BAD_VALUE, &mut warnings);
    }
    if !b.has_required() {
        return None;
    }
    summary.merge(warnings);
    b.known("notes", text(details, "notesPlain"));
    b.urls(urls(overview), summary);
    entries.extras(&mut b, files, summary);
    b.finish(kind, item_name(text(overview, "title")), summary)
}

/// A document: its file, from the export's `files/`, and its notes. One
/// whose file didn't come (too large, or missing) is skipped and counted.
fn document(item: &Value, files: Files, summary: &mut Summary) -> Option<Imported> {
    let details = item.get("details").unwrap_or(&Value::Null);
    let overview = item.get("overview").unwrap_or(&Value::Null);
    let mut budget = deadbolt_core::item::MAX_FILE;
    let file = details
        .get("documentAttributes")
        .map_or(Err(Missing::Gone), |a| {
            Attachment::new(String::new(), a).value(files, &mut budget)
        });
    let mut b = Builder::new("document");
    let reason = match &file {
        Err(Missing::TooLarge) => BIG_FILE,
        _ => MISSING_FILE,
    };
    if !b.known("file", file.ok()) || !b.has_required() {
        summary.skip(reason);
        return None;
    }
    b.known("notes", text(details, "notesPlain"));
    b.urls(urls(overview), summary);
    Entries::new(details).extras(&mut b, files, summary);
    b.finish("document", item_name(text(overview, "title")), summary)
}

/// The `sshKey` value's metadata: the public key and fingerprint.
fn ssh_metadata(details: &Value) -> &Value {
    array(details, "sections")
        .iter()
        .flat_map(|section| array(section, "fields"))
        .find_map(|field| field.get("value")?.get("sshKey")?.get("metadata"))
        .unwrap_or(&Value::Null)
}

fn ssh(item: &Value, files: Files, summary: &mut Summary) -> Option<Imported> {
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
    entries.extras(&mut b, files, summary);
    b.finish("ssh", item_name(text(overview, "title")), summary)
}

/// A 1Password address as its parts: street, city, state, zip and
/// country. An export has them apart; the `op` CLI joins them with ", ",
/// leaving out empty ones, so that text is split back: the country is the
/// last part if it is a country code, then the street and the city, then a
/// part with digits is the zip and one without the state. Text that doesn't
/// split that way is all street.
fn address_parts(value: &Value) -> Option<[Option<String>; 5]> {
    if value.is_object() {
        return Some([
            text(value, "street"),
            text(value, "city"),
            text(value, "state"),
            text(value, "zip"),
            text(value, "country"),
        ]);
    }
    let line = scalar(value)?;
    let mut parts: Vec<String> = line.split(", ").map(|p| p.trim().to_string()).collect();
    let country = parts
        .last()
        .filter(|c| deadbolt_core::item::country(c).is_some())
        .cloned();
    if country.is_some() {
        parts.pop();
    }
    let all_street = || [Some(line.clone()), None, None, None, None];
    if parts.is_empty() || parts.len() > 4 || parts.iter().any(String::is_empty) {
        return Some(all_street());
    }
    let mut it = parts.into_iter();
    let (street, city) = (it.next(), it.next());
    let (mut state, mut zip) = (None, None);
    for part in it {
        let slot = if part.bytes().any(|b| b.is_ascii_digit()) {
            &mut zip
        } else {
            &mut state
        };
        if slot.replace(part).is_some() {
            return Some(all_street());
        }
    }
    Some([street, city, state, zip, country])
}

/// The value of an identity's address field (`address`), as given.
fn identity_address(details: &Value) -> Option<&Value> {
    array(details, "sections")
        .iter()
        .flat_map(|section| array(section, "fields"))
        .filter(|field| text(field, "id").as_deref() == Some("address"))
        .find_map(|field| field.get("value")?.get("address"))
}

fn identity(item: &Value, files: Files, summary: &mut Summary) -> Option<Imported> {
    let details = item.get("details").unwrap_or(&Value::Null);
    let overview = item.get("overview").unwrap_or(&Value::Null);
    let mut entries = Entries::new(details);
    let mut b = Builder::new("identity");
    let mut by_id = |id: &str| entries.take(|e| e.id == id);
    b.known("given-name", by_id("firstname"));
    b.known("additional-name", by_id("initial"));
    b.known("family-name", by_id("lastname"));
    b.known("organization", by_id("company"));
    b.known("job-title", by_id("jobtitle"));
    let birthday = by_id("birthdate");
    let phone = by_id("defphone")
        .or_else(|| by_id("cellphone"))
        .or_else(|| by_id("homephone"))
        .or_else(|| by_id("busphone"));
    let email = by_id("email");
    b.known_or_extra("birthday", birthday, BAD_BIRTHDAY, summary);
    b.phone(phone);
    b.known_or_extra("email", email, BAD_EMAIL, summary);
    if let Some([street, city, state, zip, country]) =
        identity_address(details).and_then(address_parts)
    {
        entries.take(|e| e.id == "address" && e.key == "address");
        b.postal_address([street], [city, state, zip, country], summary);
    }
    b.known("notes", text(details, "notesPlain"));
    b.urls(urls(overview), summary);
    entries.extras(&mut b, files, summary);
    b.finish("identity", item_name(text(overview, "title")), summary)
}

/// Maps one 1PUX item, or says why it is skipped. The `op` CLI's items are
/// mapped through here too (see [`super::op`]), so both agree.
pub(super) fn item(item: &Value, files: Files, summary: &mut Summary) -> Option<Imported> {
    if text(item, "state").as_deref() == Some("archived") {
        summary.skip(ARCHIVED);
        return None;
    }
    let category = text(item, "categoryUuid").unwrap_or_default();
    let mut mapped = match category.as_str() {
        "001" | "005" => login(item, files, summary),
        "002" => card(item, files, summary),
        "004" => identity(item, files, summary),
        "114" => ssh(item, files, summary),
        "006" => document(item, files, summary),
        "003" | "104" | "107" | "111" | "113" => note(item, files, summary),
        other => match typed_kind(other) {
            Some(kind) => typed(item, kind, files, summary).or_else(|| note(item, files, summary)),
            None => {
                summary.skip(UNKNOWN_TYPE);
                return None;
            }
        },
    }?;
    let details = item.get("details").unwrap_or(&Value::Null);
    let overview = item.get("overview").unwrap_or(&Value::Null);
    mapped.favorite = number(item, "favIndex").is_some_and(|i| i > 0);
    mapped.tags = tags::collect(array(overview, "tags").iter().filter_map(scalar));
    if !array(details, "passwordHistory").is_empty() {
        summary.drop_some(PASSWORD_HISTORY, 1);
    }
    let mut mapped = mapped;
    if let Some(pw_field) = deadbolt_core::health::audited_password_field(mapped.kind)
        && mapped.fields.contains_key(pw_field)
    {
        let hist_max = array(details, "passwordHistory")
            .iter()
            .filter_map(|h| number(h, "time"))
            .max();
        mapped.password_changed = hist_max
            .or_else(|| number(item, "updatedAt"))
            .filter(|&secs| secs > 0)
            .map(date)
            .filter(|d| deadbolt_core::item::valid_date(d));
    }
    summary.add(&mapped);
    Some(mapped)
}

/// What a mirror of a 1Password item records: which item it is, and the
/// version mirrored (see [`MirrorVersion`]).
pub fn source(account: &str, vault: &str, item: &str, version: &MirrorVersion) -> Source {
    Source {
        id: source_id(account, vault, item),
        version: version.to_string(),
    }
}

pub fn source_id(account: &str, vault: &str, item: &str) -> String {
    format!("{SOURCE_PREFIX}{account}/{vault}/{item}")
}

/// How a 1Password item's source id starts.
pub const SOURCE_PREFIX: &str = "1password/";

/// A 1Password source id's account, vault and item ids; `None` if it
/// isn't one.
pub fn source_key(id: &str) -> Option<(&str, &str, &str)> {
    let mut parts = id.strip_prefix(SOURCE_PREFIX)?.splitn(3, '/');
    let (account, vault, item) = (parts.next()?, parts.next()?, parts.next()?);
    (!vault.is_empty() && !item.is_empty()).then_some((account, vault, item))
}

/// Maps a 1PUX `export.data`. Each item records where it came from, so a
/// later sync from 1Password takes it over rather than adding it again.
pub fn export(export: &Value, files: &[ExportFile]) -> Result<(Vec<Imported>, Summary)> {
    let files = Files(Some(files));
    let Some(accounts) = export.get("accounts").and_then(Value::as_array) else {
        bail!("not a 1Password export: no \"accounts\" list");
    };
    let mut summary = Summary::new(ImportSource::OnePassword);
    let mut out = Vec::new();
    for account in accounts {
        // The user's id in the account, not the account's (`op account
        // list` gives both).
        let user_id = account
            .get("attrs")
            .and_then(|a| text(a, "uuid"))
            .unwrap_or_default();
        for vault in array(account, "vaults") {
            let vault_id = vault.get("attrs").and_then(|a| text(a, "uuid"));
            for entry in array(vault, "items") {
                let Some(mut mapped) = item(entry, files, &mut summary) else {
                    continue;
                };
                if let (Some(vault_id), Some(item_id)) = (&vault_id, text(entry, "uuid")) {
                    let version = MirrorVersion {
                        updated: number(entry, "updatedAt").unwrap_or(0),
                        digest: mapped.digest(),
                        origin: Origin::Import,
                        fields: BTreeSet::new(),
                        tags: BTreeSet::new(),
                    };
                    let source = source(&user_id, vault_id, &item_id, &version);
                    mapped.source = valid_source(&source).then_some(source);
                }

                out.push(mapped);
            }
        }
    }
    Ok((out, summary))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::import::parse;
    use crate::import::tests::{fields, lines};

    /// The user id in [`EXPORT`]; `op account list` gives it as `user_uuid`.
    pub const USER: &str = "USERUSERUSERUSERUSERUSERUS";

    /// Shaped like the `export.data` of a 1Password 8 `.1pux`: two vaults.
    pub const EXPORT: &str = r#"{
  "accounts": [
    {
      "attrs": {
        "accountName": "Dax",
        "name": "Dax Raad",
        "avatar": "",
        "email": "dax@example.com",
        "uuid": "USERUSERUSERUSERUSERUSERUS",
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
                ("api", "Deploy API"),
                ("login", "No password"),
                ("identity", "Me"),
                ("ssh", "CI key"),
                ("ssh", "Old key"),
                ("license", "Editor"),
                ("bank", "Checking"),
                ("passport", "Passport"),
            ]
        );
        let github = &items[0];
        // Each item records which 1Password item it is, so a sync can take
        // it over. A .1pux names the user, not the account.
        let source = github.source.as_ref().unwrap();
        assert_eq!(
            source.id,
            format!("1password/{USER}/v1v1v1v1v1v1v1v1v1v1v1v1v1/item1item1item1item1item1a")
        );
        let version = MirrorVersion::parse(&source.version).unwrap();
        assert_eq!(
            (version.updated, version.origin),
            (1_710_000_000, Origin::Import)
        );
        assert!(!version.mirrored());
        assert_eq!(
            source_key(&source.id),
            Some((
                USER,
                "v1v1v1v1v1v1v1v1v1v1v1v1v1",
                "item1item1item1item1item1a"
            ))
        );
        assert!(items.iter().all(|i| i.source.is_some()));
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
        // An API credential is a type of its own.
        assert_eq!(
            fields(&items[4]),
            [
                ("credential", "secret", "op-api-key"),
                ("host", "text", "api.example.com"),
                ("username", "text", "deploy-bot"),
            ]
        );
        // A login needs no password.
        assert_eq!(fields(&items[5]), [("username", "text", "nobody")]);
        assert_eq!(
            fields(&items[6]),
            [
                ("address-line1", "text", "1 Main St"),
                ("birthday", "date", "1990-03-01"),
                ("city", "text", "Springfield"),
                ("country", "text", "US"),
                ("email-2", "text", "not an email"),
                ("family-name", "text", "Raad"),
                ("given-name", "text", "Dax"),
                ("organization", "text", "Anomaly"),
                ("phone", "text", "+15550100"),
                ("postal-code", "text", "12345"),
                ("region", "text", "IL"),
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
        // Licenses, bank accounts and passports have types of their own; a
        // field their type doesn't know stays an extra field. License keys,
        // ID and account numbers are secret, though 1Password exports them
        // as plain strings.
        assert_eq!(
            fields(&items[9]),
            [
                ("license-key", "secret", "ABCD-1234"),
                ("notes", "note", "bought 2024"),
                ("password", "secret", "op-license-pw"),
                ("version", "text", "5"),
            ]
        );
        assert_eq!(
            fields(&items[10]),
            [
                ("account-number", "secret", "op-account-12345678"),
                ("bank", "text", "Example Bank"),
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
        assert!(github.favorite);
        assert_eq!(github.tags, BTreeSet::from(["dev".into(), "work".into()]));
        assert!(!items[1].favorite);
        assert_eq!(items[1].tags, BTreeSet::from(["home".into()]));
        assert!(items[3].favorite);
        assert_eq!(
            lines(&report),
            [
                "imported 12 from 1Password (logins 3, cards 1, secure notes 1, SSH keys 2, identities 1, API credentials 1, software licenses 1, bank accounts 1, passports 1)",
                "skipped 1 SSH key without a private key",
                "skipped 1 archived item",
                "skipped 1 document whose file is missing from the export",
                "skipped 1 item of unknown type",
                "warning: 1 invalid email address kept as text",
                "dropped: 1 attachment missing from the export, 1 item's password history, 1 linked field",
            ]
        );
    }

    /// One item of each 1Password category, as `export.data` has them.
    const CATEGORIES: &str = r#"{"accounts": [{"attrs": {"uuid": "USER"}, "vaults": [{"attrs": {"uuid": "v1"}, "items": [
      {"uuid": "c001", "categoryUuid": "001", "overview": {"title": "Site", "url": "https://site.example"},
       "details": {"loginFields": [{"value": "pw", "fieldType": "P", "designation": "password"}],
         "sections": [{"title": "", "fields": [
           {"title": "", "id": "f1", "value": {"file": {"fileName": "recovery codes.txt", "documentId": "doc1", "decryptedSize": 5}}},
           {"title": "contract", "id": "f2", "value": {"file": {"fileName": "big.bin", "documentId": "doc9", "decryptedSize": 99}}}]}]}},
      {"uuid": "c002", "categoryUuid": "002", "overview": {"title": "Visa"},
       "details": {"sections": [{"fields": [{"id": "ccnum", "value": {"creditCardNumber": "4242424242424242"}}]}]}},
      {"uuid": "c003", "categoryUuid": "003", "overview": {"title": "Note"}, "details": {"notesPlain": "body"}},
      {"uuid": "c004", "categoryUuid": "004", "overview": {"title": "Me"},
       "details": {"sections": [{"fields": [{"id": "firstname", "value": {"string": "Dax"}}]}]}},
      {"uuid": "c005", "categoryUuid": "005", "overview": {"title": "Door"}, "details": {"password": "door-pw"}},
      {"uuid": "c006", "categoryUuid": "006", "overview": {"title": "Scan"},
       "details": {"notesPlain": "front page", "documentAttributes": {"fileName": "scan.pdf", "documentId": "doc2", "decryptedSize": 4}}},
      {"uuid": "c100", "categoryUuid": "100", "overview": {"title": "Editor"},
       "details": {"sections": [{"fields": [
         {"id": "reg_code", "value": {"string": "KEY-1"}}, {"id": "reg_name", "value": {"string": "Dax"}},
         {"id": "order_date", "value": {"date": 1704067200}}]}]}},
      {"uuid": "c101", "categoryUuid": "101", "overview": {"title": "Checking"},
       "details": {"sections": [{"fields": [
         {"id": "bankName", "value": {"string": "Example Bank"}}, {"id": "accountNo", "value": {"string": "12345678"}},
         {"id": "routingNo", "value": {"string": "021000021"}}]}]}},
      {"uuid": "c102", "categoryUuid": "102", "overview": {"title": "Prod DB"},
       "details": {"sections": [{"fields": [
         {"id": "database_type", "value": {"menu": "postgresql"}}, {"id": "hostname", "value": {"string": "db.example"}},
         {"id": "port", "value": {"string": "5432"}}, {"id": "database", "value": {"string": "app"}},
         {"id": "username", "value": {"string": "app"}}, {"id": "password", "value": {"concealed": "db-pw"}},
         {"id": "sid", "value": {"string": "ORCL"}}]}]}},
      {"uuid": "c103", "categoryUuid": "103", "overview": {"title": "License"},
       "details": {"sections": [{"fields": [
         {"id": "fullname", "value": {"string": "Dax Raad"}}, {"id": "number", "value": {"string": "D123"}},
         {"id": "state", "value": {"string": "IL"}}, {"id": "expiry_date", "value": {"monthYear": 203006}}]}]}},
      {"uuid": "c104", "categoryUuid": "104", "overview": {"title": "Fishing"},
       "details": {"sections": [{"fields": [{"id": "name", "value": {"string": "Dax"}}]}]}},
      {"uuid": "c105", "categoryUuid": "105", "overview": {"title": "Gym"},
       "details": {"sections": [{"fields": [
         {"id": "org_name", "value": {"string": "Gym Co"}}, {"id": "membership_no", "value": {"string": "M-77"}},
         {"id": "member_since", "value": {"monthYear": 202001}}, {"id": "phone", "value": {"phone": "+1 555 0100"}}]}]}},
      {"uuid": "c106", "categoryUuid": "106", "overview": {"title": "Passport"},
       "details": {"sections": [{"fields": [
         {"id": "number", "value": {"string": "X123"}}, {"id": "issuing_country", "value": {"string": "United States"}},
         {"id": "expiry_date", "value": {"date": 1893456000}}]}]}},
      {"uuid": "c107", "categoryUuid": "107", "overview": {"title": "Miles"},
       "details": {"sections": [{"fields": [{"id": "membership_no", "value": {"string": "R-1"}}]}]}},
      {"uuid": "c108", "categoryUuid": "108", "overview": {"title": "SSN"},
       "details": {"sections": [{"fields": [
         {"id": "name", "value": {"string": "Dax Raad"}}, {"id": "number", "value": {"concealed": "078-05-1120"}}]}]}},
      {"uuid": "c109", "categoryUuid": "109", "overview": {"title": "Home Wi-Fi"},
       "details": {"sections": [{"fields": [
         {"id": "network_name", "value": {"string": "Home"}}, {"id": "wireless_password", "value": {"concealed": "wifi-pw"}},
         {"id": "wireless_security", "value": {"menu": "wpa2p"}}, {"id": "password", "value": {"concealed": "router-pw"}}]}]}},
      {"uuid": "c110", "categoryUuid": "110", "overview": {"title": "Box"},
       "details": {"sections": [{"fields": [
         {"id": "url", "value": {"string": "box.example"}}, {"id": "username", "value": {"string": "root"}},
         {"id": "password", "value": {"concealed": "root-pw"}}]}]}},
      {"uuid": "c111", "categoryUuid": "111", "overview": {"title": "Mail"},
       "details": {"sections": [{"fields": [{"id": "pop_username", "value": {"string": "dax"}}]}]}},
      {"uuid": "c112", "categoryUuid": "112", "overview": {"title": "Stripe"},
       "details": {"sections": [{"fields": [
         {"id": "credential", "value": {"concealed": "sk_live_1"}}, {"id": "type", "value": {"menu": "bearer"}},
         {"id": "expires", "value": {"date": 1893456000}}]}]}},
      {"uuid": "c112b", "categoryUuid": "112", "overview": {"title": "Half API"},
       "details": {"sections": [{"fields": [{"id": "username", "value": {"string": "bot"}}]}]}},
      {"uuid": "c113", "categoryUuid": "113", "overview": {"title": "Doctor"},
       "details": {"sections": [{"fields": [{"id": "healthcareprofessional", "value": {"string": "Dr. Who"}}]}]}},
      {"uuid": "c114", "categoryUuid": "114", "overview": {"title": "Key"},
       "details": {"sections": [{"fields": [{"id": "private_key", "value": {"sshKey": {"privateKey": "-----BEGIN-----"}}}]}]}},
      {"uuid": "c115", "categoryUuid": "115", "overview": {"title": "Wallet"},
       "details": {"sections": [{"fields": [
         {"title": "Recovery Phrase", "id": "x1", "value": {"concealed": "abandon ability able"}},
         {"title": "Wallet Address", "id": "x2", "value": {"string": "bc1qxy"}}]}]}},
      {"uuid": "c006b", "categoryUuid": "006", "overview": {"title": "Missing"},
       "details": {"documentAttributes": {"fileName": "gone.pdf", "documentId": "doc404"}}}
    ]}]}]}"#;

    #[test]
    fn maps_every_category_and_its_files() {
        let files = [
            ExportFile {
                name: "doc1__recovery codes.txt".into(),
                data: "Y29kZXM=".into(),
                too_large: false,
            },
            ExportFile {
                name: "doc2__scan.pdf".into(),
                data: "JVBERg==".into(),
                too_large: false,
            },
            // Left out by the client as over the cap.
            ExportFile {
                name: "doc9__big.bin".into(),
                data: String::new(),
                too_large: true,
            },
        ];
        let (items, report) = crate::import::parse_with(CATEGORIES, &files).unwrap();
        let kinds: Vec<(&str, &str)> = items
            .iter()
            .map(|i| (i.name.as_deref().unwrap(), i.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                ("Site", "login"),
                ("Visa", "card"),
                ("Note", "note"),
                ("Me", "identity"),
                ("Door", "login"),
                ("Scan", "document"),
                ("Editor", "license"),
                ("Checking", "bank"),
                ("Prod DB", "database"),
                ("License", "driver-license"),
                ("Fishing", "note"),
                ("Gym", "membership"),
                ("Passport", "passport"),
                ("Miles", "note"),
                ("SSN", "id-document"),
                ("Home Wi-Fi", "wifi"),
                ("Box", "server"),
                ("Mail", "note"),
                ("Stripe", "api"),
                ("Half API", "note"),
                ("Doctor", "note"),
                ("Key", "ssh"),
                ("Wallet", "crypto"),
            ]
        );
        let by = |name: &str| {
            items
                .iter()
                .find(|i| i.name.as_deref() == Some(name))
                .unwrap()
        };
        // An attachment is a file field, named by its file; one that didn't
        // come is dropped and counted.
        assert_eq!(
            fields(by("Site")),
            [
                ("password", "secret", "pw"),
                ("recovery-codes", "file", "recovery codes.txt\nY29kZXM="),
                ("url", "url", "https://site.example"),
            ]
        );
        assert_eq!(
            fields(by("Scan")),
            [
                ("file", "file", "scan.pdf\nJVBERg=="),
                ("notes", "note", "front page"),
            ]
        );
        assert_eq!(
            fields(by("Editor")),
            [
                ("license-key", "secret", "KEY-1"),
                ("licensed-to", "text", "Dax"),
                ("purchased", "date", "2024-01-01"),
            ]
        );
        assert_eq!(
            fields(by("Checking")),
            [
                ("account-number", "secret", "12345678"),
                ("bank", "text", "Example Bank"),
                ("routing-number", "text", "021000021"),
            ]
        );
        assert_eq!(
            fields(by("Prod DB")),
            [
                ("database", "text", "app"),
                ("host", "text", "db.example"),
                ("password", "secret", "db-pw"),
                ("port", "text", "5432"),
                ("sid", "text", "ORCL"),
                ("type", "text", "postgresql"),
                ("username", "text", "app"),
            ]
        );
        assert_eq!(
            fields(by("License")),
            [
                ("expires", "month", "2030-06"),
                ("full-name", "text", "Dax Raad"),
                ("number", "secret", "D123"),
                ("state", "text", "IL"),
            ]
        );
        assert_eq!(
            fields(by("Gym")),
            [
                ("member-id", "secret", "M-77"),
                ("member-since", "month", "2020-01"),
                ("organization", "text", "Gym Co"),
                ("phone", "text", "+15550100"),
            ]
        );
        assert_eq!(
            fields(by("Passport")),
            [
                ("expires", "date", "2030-01-01"),
                ("issuing-country", "text", "United States"),
                ("number", "secret", "X123"),
            ]
        );
        assert_eq!(
            fields(by("SSN")),
            [
                ("full-name", "text", "Dax Raad"),
                ("number", "secret", "078-05-1120"),
            ]
        );
        assert_eq!(
            fields(by("Home Wi-Fi")),
            [
                ("password", "secret", "wifi-pw"),
                ("password-2", "secret", "router-pw"),
                ("security", "text", "wpa2p"),
                ("ssid", "text", "Home"),
            ]
        );
        assert_eq!(
            fields(by("Box")),
            [
                ("password", "secret", "root-pw"),
                ("url", "url", "https://box.example"),
                ("username", "text", "root"),
            ]
        );
        assert_eq!(
            fields(by("Stripe")),
            [
                ("credential", "secret", "sk_live_1"),
                ("expires", "date", "2030-01-01"),
                ("type", "text", "bearer"),
            ]
        );
        // Without a credential, an API credential is kept as a note.
        assert_eq!(fields(by("Half API")), [("username", "text", "bot")]);
        assert_eq!(
            fields(by("Wallet")),
            [
                ("address", "text", "bc1qxy"),
                ("recovery-phrase", "secret", "abandon ability able"),
            ]
        );
        assert_eq!(
            lines(&report)[1..],
            [
                "skipped 1 document whose file is missing from the export",
                "dropped: 1 attachment over the 10 MiB an item's files hold",
            ]
        );
    }

    /// An item's files hold at most `MAX_FILE` bytes in all: past that,
    /// attachments are dropped, so its create fits in one entry.
    #[test]
    fn an_items_files_fit_in_one_entry() {
        let data = data_encoding::BASE64.encode(&vec![7; 6 * 1024 * 1024]);
        let export = r#"{"accounts": [{"vaults": [{"items": [{"categoryUuid": "003", "overview": {"title": "Big"},
            "details": {"sections": [{"fields": [
              {"id": "a", "value": {"file": {"fileName": "a.bin", "documentId": "da"}}},
              {"id": "b", "value": {"file": {"fileName": "b.bin", "documentId": "db"}}}]}]}}]}]}]}"#;
        let files = ["da__a.bin", "db__b.bin"].map(|name| ExportFile {
            name: name.into(),
            data: data.clone(),
            too_large: false,
        });
        let (items, report) = crate::import::parse_with(export, &files).unwrap();
        let names: Vec<&str> = items[0].fields.keys().map(String::as_str).collect();
        assert_eq!(names, ["a"]);
        assert_eq!(
            lines(&report)[1..],
            ["dropped: 1 attachment over the 10 MiB an item's files hold"]
        );
    }

    #[test]
    fn addresses_split_as_op_joins_them() {
        let parts = |v: Value| address_parts(&v).unwrap();
        let s = |v: &str| Some(v.to_string());
        assert_eq!(
            parts("1 Main St, Springfield, IL, 12345, us".into()),
            [
                s("1 Main St"),
                s("Springfield"),
                s("IL"),
                s("12345"),
                s("us")
            ]
        );
        assert_eq!(
            parts("1 Main St, Springfield, 12345, us".into()),
            [s("1 Main St"), s("Springfield"), None, s("12345"), s("us")]
        );
        assert_eq!(
            parts("1 Main St, Springfield".into()),
            [s("1 Main St"), s("Springfield"), None, None, None]
        );
        // Two zips, or too many parts: all street, nothing lost.
        for odd in ["1 Main St, Springfield, 12, 34", "a, b, c, d, e, f"] {
            assert_eq!(parts(odd.into()), [s(odd), None, None, None, None]);
        }
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
