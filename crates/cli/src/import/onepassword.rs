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
    // 1Password 8 keeps these in the item's fields; older exports only in
    // the key's metadata.
    let metadata = ssh_metadata(details);
    let mut field = |names: [&str; 2]| entries.take(|e| names.iter().any(|n| e.is(n)));
    let mut public = field(["public_key", "public key"]).or_else(|| text(metadata, "publicKey"));
    let mut fingerprint =
        field(["fingerprint", "fingerprint"]).or_else(|| text(metadata, "fingerprint"));
    let passphrase = field(["passphrase", "password"]);
    let mut comment = field(["comment", "comment"]);
    if (public.is_none() || fingerprint.is_none())
        && let Some((derived_pub, derived_fp, derived_comment)) =
            crate::daemon::ssh_keys::derive_fields(
                &private,
                passphrase.as_deref(),
                comment.as_deref(),
            )
    {
        public = public.or(Some(derived_pub));
        fingerprint = fingerprint.or(Some(derived_fp));
        comment = comment.or(derived_comment);
    }
    b.known("private-key", Some(private));
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
pub(crate) mod tests;
