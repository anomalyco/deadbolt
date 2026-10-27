//! Items from the 1Password CLI (`op item get --format json`). Each one is
//! rewritten in the shape of a 1PUX export's item and mapped by
//! [`super::onepassword::item`], so a sync and an import of the same item
//! make the same deadbolt item.
//!
//! `op` describes a field by `type` (`STRING`, `CONCEALED`, `OTP`, ...) and
//! `purpose` (`USERNAME`, `PASSWORD`, `NOTES`) and groups it by `section`;
//! 1PUX by a value key (`string`, `concealed`, `totp`, ...) inside a section,
//! with a login's username and password in `loginFields`.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use deadbolt_core::Source;

use super::{Imported, MirrorVersion, Origin, PASSKEYS, Summary, onepassword, text};
use crate::protocol::{ImportReport, ImportSource};

/// The 1PUX `categoryUuid` of an `op` category.
pub fn category(name: &str) -> Option<&'static str> {
    Some(match name {
        "LOGIN" => "001",
        "CREDIT_CARD" => "002",
        "SECURE_NOTE" => "003",
        "IDENTITY" => "004",
        "PASSWORD" => "005",
        "DOCUMENT" => "006",
        "SOFTWARE_LICENSE" => "100",
        "BANK_ACCOUNT" => "101",
        "DATABASE" => "102",
        "DRIVER_LICENSE" => "103",
        "OUTDOOR_LICENSE" => "104",
        "MEMBERSHIP" => "105",
        "PASSPORT" => "106",
        "REWARD_PROGRAM" => "107",
        "SOCIAL_SECURITY_NUMBER" => "108",
        "WIRELESS_ROUTER" => "109",
        "SERVER" => "110",
        "EMAIL_ACCOUNT" => "111",
        "API_CREDENTIAL" => "112",
        "MEDICAL_RECORD" => "113",
        "SSH_KEY" => "114",
        _ => return None,
    })
}

/// Whether items of this `op` category are mirrored at all, so the rest
/// need not be fetched.
pub fn mirrored(name: &str) -> bool {
    category(name).is_some_and(|c| c != "006")
}

/// Why items of an `op` category that isn't mirrored are skipped.
pub fn not_mirrored(name: &str) -> &'static str {
    match name {
        "DOCUMENT" => "document",
        _ => "item of unknown type",
    }
}

/// What mapping several items did besides producing them.
pub struct Mapping {
    summary: Summary,
}

impl Default for Mapping {
    fn default() -> Self {
        Self {
            summary: Summary::new(ImportSource::OnePassword),
        }
    }
}

/// An `op` item, mapped.
pub struct Mapped {
    pub item: Imported,
    pub vault: String,
    pub id: String,
    /// When it last changed in 1Password, in Unix seconds.
    pub updated: i64,
}

impl Mapped {
    /// What its copy in `account` records, holding what `digest` is of.
    /// One taken over records the fields 1Password wrote, unless they are
    /// too many to: then a later sync removes none of its fields.
    pub fn source(&self, account: &str, origin: Origin, digest: String) -> Source {
        let mut version = MirrorVersion {
            updated: self.updated,
            digest,
            origin,
            fields: match origin {
                Origin::Adopted => self.item.fields.keys().cloned().collect(),
                Origin::Sync | Origin::Import => BTreeSet::new(),
            },
        };
        let source = onepassword::source(account, &self.vault, &self.id, &version);
        if deadbolt_core::item::valid_source(&source) {
            return source;
        }
        version.fields.clear();
        onepassword::source(account, &self.vault, &self.id, &version)
    }
}

/// The vault id, item id and change time `op item list` and `op item get`
/// give an item; `None` if they are missing.
pub fn identity(item: &Value) -> Option<(String, String, i64)> {
    let vault = item.get("vault").and_then(|v| text(v, "id"))?;
    let id = text(item, "id")?;
    let updated = text(item, "updated_at")
        .as_deref()
        .and_then(unix)
        .unwrap_or(0);
    let source = onepassword::source_id("-", &vault, &id);
    deadbolt_core::item::valid_source(&Source {
        id: source,
        version: String::new(),
    })
    .then_some((vault, id, updated))
}

impl Mapping {
    /// Maps one `op` item; an error says why it is skipped.
    pub fn item(&mut self, item: &Value) -> Result<Mapped, &'static str> {
        let Some((vault, id, updated)) = identity(item) else {
            return Err("item without an id");
        };
        let mut summary = Summary::new(ImportSource::OnePassword);
        let mapped = onepassword::item(&to_1pux(item, &mut summary), &mut summary);
        let reason = summary.skip_reason();
        self.summary.merge(summary);
        let item = mapped.ok_or(reason.unwrap_or("item that could not be imported"))?;
        Ok(Mapped {
            item,
            vault,
            id,
            updated,
        })
    }

    /// Values left out or kept differently, as an import would report them.
    pub fn report(self) -> ImportReport {
        self.summary.report()
    }
}

/// An `op` item as a 1PUX item.
fn to_1pux(item: &Value, summary: &mut Summary) -> Value {
    let category = text(item, "category")
        .as_deref()
        .and_then(category)
        .unwrap_or("999");
    let mut login_fields = Vec::new();
    let mut notes = None;
    // Sections in the order their first field appears; fields without one
    // go in an untitled section.
    let mut sections: Vec<(String, String, Vec<Value>)> = Vec::new();
    let section_title = |id: &str, field: &Value| {
        field
            .get("section")
            .and_then(|s| text(s, "label"))
            .or_else(|| {
                super::array(item, "sections")
                    .iter()
                    .find(|s| text(s, "id").as_deref() == Some(id))
                    .and_then(|s| text(s, "label"))
            })
            .unwrap_or_default()
    };
    for field in super::array(item, "fields") {
        let kind = text(field, "type").unwrap_or_default();
        let label = text(field, "label").unwrap_or_default();
        let id = text(field, "id").unwrap_or_default();
        let value = field.get("value").cloned().unwrap_or(Value::Null);
        if kind == "PASSKEY" {
            summary.drop_some(PASSKEYS, 1);
            continue;
        }
        match text(field, "purpose").as_deref() {
            Some("NOTES") => {
                notes = text(field, "value");
                continue;
            }
            Some(purpose @ ("USERNAME" | "PASSWORD")) => {
                let password = purpose == "PASSWORD";
                login_fields.push(json!({
                    "value": value,
                    "id": id,
                    "name": label,
                    "fieldType": if password { "P" } else { "T" },
                    "designation": if password { "password" } else { "username" },
                }));
                continue;
            }
            _ => {}
        }
        let section = field
            .get("section")
            .and_then(|s| text(s, "id"))
            .unwrap_or_default();
        let (key, value) = section_value(&kind, value);
        let entry = json!({ "title": label, "id": id, "value": { key: value } });
        match sections.iter_mut().find(|(sid, ..)| *sid == section) {
            Some((.., fields)) => fields.push(entry),
            None => {
                let title = section_title(&section, field);
                sections.push((section, title, vec![entry]));
            }
        }
    }
    // Attachments are counted, as an export's are, but never fetched.
    let files: Vec<Value> = super::array(item, "files")
        .iter()
        .map(|_| json!({ "title": "", "id": "", "value": { "file": {} } }))
        .collect();
    if !files.is_empty() {
        sections.push((String::new(), String::new(), files));
    }
    let sections: Vec<Value> = sections
        .into_iter()
        .map(|(name, title, fields)| json!({ "name": name, "title": title, "fields": fields }))
        .collect();

    let urls: Vec<&Value> = super::array(item, "urls").iter().collect();
    let primary = urls
        .iter()
        .find(|u| u.get("primary").and_then(Value::as_bool) == Some(true))
        .or(urls.first())
        .and_then(|u| text(u, "href"));
    let urls: Vec<Value> = urls
        .iter()
        .filter_map(|u| text(u, "href"))
        .map(|href| json!({ "url": href }))
        .collect();

    let mut details = Map::new();
    details.insert("loginFields".into(), login_fields.into());
    details.insert("sections".into(), sections.into());
    if let Some(notes) = notes {
        details.insert("notesPlain".into(), notes.into());
    }
    let archived = text(item, "state").is_some_and(|s| s.eq_ignore_ascii_case("archived"));
    let favorite = item.get("favorite").and_then(Value::as_bool) == Some(true);
    json!({
        "uuid": text(item, "id"),
        "categoryUuid": category,
        "state": if archived { "archived" } else { "active" },
        "favIndex": i32::from(favorite),
        "details": details,
        "overview": {
            "title": text(item, "title"),
            "url": primary,
            "urls": urls,
            "tags": item.get("tags").cloned().unwrap_or(Value::Null),
        },
    })
}

/// A section field's 1PUX value key and value, from its `op` type.
fn section_value(kind: &str, value: Value) -> (&'static str, Value) {
    let key = match kind {
        "CONCEALED" => "concealed",
        "EMAIL" => "email",
        "URL" => "url",
        "OTP" => "totp",
        "PHONE" => "phone",
        "ADDRESS" => "address",
        "REFERENCE" => "reference",
        "CREDIT_CARD_NUMBER" => "creditCardNumber",
        "CREDIT_CARD_TYPE" => "creditCardType",
        "SSHKEY" => {
            return ("sshKey", json!({ "metadata": { "privateKey": value } }));
        }
        "DATE" => {
            let secs = value.as_str().and_then(|s| s.trim().parse::<i64>().ok());
            return ("date", secs.map_or(value, Value::from));
        }
        "MONTH_YEAR" => return ("monthYear", month_year(value)),
        _ => "string",
    };
    (key, value)
}

/// `YYYYMM`, `MM/YYYY` or `YYYY/MM` as the number `YYYYMM` 1PUX uses;
/// anything else as it is.
fn month_year(value: Value) -> Value {
    fn parse(s: &str) -> Option<i64> {
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        match s.split_once('/') {
            None if s.len() == 6 && digits(s) => s.parse().ok(),
            Some((a, b)) if digits(a) && digits(b) => {
                let (month, year) = if a.len() == 4 { (b, a) } else { (a, b) };
                let year: i64 = year.parse().ok()?;
                let year = if year < 100 { 2000 + year } else { year };
                Some(year * 100 + month.parse::<i64>().ok()?)
            }
            _ => None,
        }
    }
    match value.as_str().map(str::trim).and_then(parse) {
        Some(n) => n.into(),
        None => value,
    }
}

/// An RFC 3339 time (`2024-03-09T16:00:00Z`, `...00.123+01:00`) as Unix
/// seconds.
pub fn unix(time: &str) -> Option<i64> {
    let b = time.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = time.get(r)?;
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse().ok())?
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut rest = &time[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        rest = frac.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let (h, m) = rest.get(1..)?.split_once(':')?;
            sign * (h.parse::<i64>().ok()? * 3600 + m.parse::<i64>().ok()? * 60)
        }
    };
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Howard Hinnant's days-from-civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::import::tests::fields;

    /// `op item get --format json` of the same items as the 1PUX test
    /// export, one JSON object after another as `op` prints them.
    pub const ITEMS: &str = include_str!("../../tests/fixtures/op-items.json");

    pub fn items() -> Vec<Value> {
        serde_json::Deserializer::from_str(ITEMS)
            .into_iter::<Value>()
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn a_taken_over_copy_records_the_fields_1password_wrote_if_it_can() {
        use deadbolt_core::{Field, FieldType};
        let mapped = |count: usize| Mapped {
            item: Imported {
                kind: "note",
                name: Some("n".into()),
                fields: (0..count)
                    .map(|i| (format!("{i:0>60}"), Field::new(FieldType::Text, "v")))
                    .collect(),
                source: None,
            },
            vault: "v1v1v1v1v1v1v1v1v1v1v1v1v1".into(),
            id: "item1item1item1item1item1a".into(),
            updated: 1,
        };
        let version = |count, origin| {
            let source = mapped(count).source("A", origin, "d".into());
            assert!(deadbolt_core::item::valid_source(&source));
            MirrorVersion::parse(&source.version).unwrap()
        };
        assert_eq!(version(3, Origin::Adopted).fields.len(), 3);
        assert!(version(3, Origin::Sync).fields.is_empty());
        // Too many to record: none, so a later sync removes none.
        let many = version(100, Origin::Adopted);
        assert_eq!(many.origin, Origin::Adopted);
        assert!(many.fields.is_empty());
    }

    #[test]
    fn maps_items_exactly_as_an_export_does() {
        let (exported, _) = crate::import::parse(onepassword::tests::EXPORT).unwrap();
        let by_name = |name: &str| {
            exported
                .iter()
                .find(|i| i.name.as_deref() == Some(name))
                .unwrap()
        };
        let mut mapping = Mapping::default();
        let mut mapped = 0;
        let mut same = 0;
        for item in items() {
            let title = text(&item, "title").unwrap();
            let Ok(ours) = mapping.item(&item) else {
                continue;
            };
            let theirs = by_name(&title);
            assert_eq!(ours.item.kind, theirs.kind, "{title}");
            // `op` gives an address as one line of text, an export in parts.
            let (address, rest): (Vec<_>, Vec<_>) = fields(&ours.item)
                .into_iter()
                .partition(|(name, ..)| *name == "address");
            let theirs_rest: Vec<_> = fields(theirs)
                .into_iter()
                .filter(|(name, ..)| *name != "address")
                .collect();
            assert_eq!(rest, theirs_rest, "{title}");
            if let [(_, _, address)] = address.as_slice() {
                assert!(address.starts_with("1 Main St, Springfield, "), "{address}");
                assert!(!address.contains('\n'));
            } else {
                // Same item, same content: the same digest as the import's.
                let source =
                    ours.source(onepassword::tests::USER, Origin::Import, ours.item.digest());
                assert_eq!(Some(source), theirs.source, "{title}");
                same += 1;
            }
            mapped += 1;
        }
        assert_eq!((mapped, same), (11, 9));
    }

    #[test]
    fn says_why_an_item_is_skipped() {
        let mut mapping = Mapping::default();
        let reasons: Vec<_> = items()
            .iter()
            .filter_map(|item| mapping.item(item).err())
            .collect();
        assert_eq!(
            reasons,
            [
                "SSH key without a private key",
                "document",
                "item of unknown type"
            ]
        );
        let lines = mapping.report().lines(true);
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("dropped:") && l.contains("1 attachment")),
            "{lines:?}"
        );
    }

    #[test]
    fn categories_match_the_export_codes() {
        assert_eq!(category("LOGIN"), Some("001"));
        assert_eq!(category("SSH_KEY"), Some("114"));
        assert_eq!(category("CRYPTO_WALLET"), None);
        assert!(mirrored("API_CREDENTIAL"));
        assert!(!mirrored("DOCUMENT"));
        assert!(!mirrored("CRYPTO_WALLET"));
    }

    #[test]
    fn times_and_months() {
        assert_eq!(unix("2024-03-09T16:00:00Z"), Some(1_710_000_000));
        assert_eq!(unix("2024-03-09T17:00:00.250+01:00"), Some(1_710_000_000));
        assert_eq!(unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(unix("2000-02-29T00:00:00Z"), Some(951_782_400));
        for bad in [
            "",
            "2024-03-09",
            "2024-13-09T16:00:00Z",
            "2024-03-09T16:00:00",
        ] {
            assert_eq!(unix(bad), None, "{bad}");
        }
        assert_eq!(month_year("202704".into()), json!(202_704));
        assert_eq!(month_year("04/2027".into()), json!(202_704));
        assert_eq!(month_year("4/27".into()), json!(202_704));
        assert_eq!(month_year("2027/04".into()), json!(202_704));
        assert_eq!(month_year("soon".into()), json!("soon"));
    }
}
