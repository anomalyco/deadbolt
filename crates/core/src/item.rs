//! Item types, field types and the rules every item obeys.
//!
//! An item has a type, fixed when it is created. A type's [`Schema`] lists
//! its known fields, each with a fixed [`FieldType`], and which of them are
//! required. Items may also carry extra fields of any field type.
//!
//! The guarantees ([`check`]) are enforced by every device: an item is
//! created by one op carrying all required fields; a known field always has
//! its schema's field type; required fields cannot be removed; the type
//! cannot change (no op changes it). [`crate::Vault::write`] rejects ops that
//! break them; [`crate::Vault::apply`] accepts the entry but ignores those
//! ops, one by one. Whether an op is valid depends only on the op and the
//! item's `Create` (which must be in the op's causal past), so the result is
//! the same in every order entries arrive in.

use std::collections::BTreeMap;
use std::fmt;

use crate::entry::{Change, Source, valid_name};

/// How a field's value is interpreted and shown. An open identifier on the
/// wire; [`FieldType::Other`] holds types this version does not know, which
/// are never valid.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldType {
    Text,
    /// Hidden unless asked for.
    Secret,
    Url,
    Email,
    /// A TOTP secret.
    Otp,
    /// A month, stored `YYYY-MM`.
    Month,
    /// A day, stored `YYYY-MM-DD`.
    Date,
    /// Multi-line text.
    Note,
    /// A file: its name, a line break, then its contents in base64
    /// ([`file_value`]), at most [`MAX_FILE`] bytes.
    File,
    Other(String),
}

impl FieldType {
    /// Parses the wire identifier; unknown identifiers become [`FieldType::Other`].
    pub fn parse(s: &str) -> Self {
        match s {
            "text" => Self::Text,
            "secret" => Self::Secret,
            "url" => Self::Url,
            "email" => Self::Email,
            "otp" => Self::Otp,
            "month" => Self::Month,
            "date" => Self::Date,
            "note" => Self::Note,
            "file" => Self::File,
            other => Self::Other(other.into()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Text => "text",
            Self::Secret => "secret",
            Self::Url => "url",
            Self::Email => "email",
            Self::Otp => "otp",
            Self::Month => "month",
            Self::Date => "date",
            Self::Note => "note",
            Self::File => "file",
            Self::Other(s) => s,
        }
    }

    /// Whether values of this type are hidden unless asked for.
    pub fn is_secret(&self) -> bool {
        matches!(self, Self::Secret | Self::Otp)
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A field's value together with its type. Concurrent edits resolve per
/// field, and the type travels with the value.
#[derive(Clone, PartialEq, Eq)]
pub struct Field {
    pub kind: FieldType,
    pub value: String,
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("kind", &self.kind)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Drop for Field {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.value);
    }
}

#[test]
fn field_debug_redacts_values_of_every_kind() {
    for kind in [
        FieldType::Secret,
        FieldType::Otp,
        FieldType::Note,
        FieldType::Text,
    ] {
        let field = Field::new(kind, "private-marker");
        let debug = format!("{field:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("private-marker"));
    }
}

impl Field {
    pub fn new(kind: FieldType, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }
}

/// The largest file a [`FieldType::File`] field holds. Its value is base64,
/// 4/3 as long, and an item's create or change travels in one entry of at
/// most [`crate::MAX_ENTRY_LEN`] (16 MiB), so a file fits with room to spare;
/// larger files would need chunking, which the log doesn't do.
pub const MAX_FILE: usize = 10 * 1024 * 1024;

/// The longest file name, in characters.
pub const MAX_FILE_NAME: usize = 255;

/// A file field's value: `name`, a line break, then `contents` in standard
/// base64 with padding.
pub fn file_value(name: &str, contents: &[u8]) -> String {
    let mut value = String::with_capacity(name.len() + 1 + contents.len().div_ceil(3) * 4);
    value.push_str(name);
    value.push('\n');
    value.push_str(&data_encoding::BASE64.encode(contents));
    value
}

/// A file field's name and its contents in base64. The contents are `None`
/// where a value holds the name alone: what the agent lists in place of a
/// file it wasn't asked for.
pub fn file_parts(value: &str) -> (&str, Option<&str>) {
    match value.split_once('\n') {
        Some((name, contents)) => (name, Some(contents)),
        None => (value, None),
    }
}

/// A file field's contents, decoded; `None` if the value holds none or
/// they aren't base64.
pub fn file_contents(value: &str) -> Option<Vec<u8>> {
    data_encoding::BASE64
        .decode(file_parts(value).1?.as_bytes())
        .ok()
}

/// How many bytes base64 `contents` decode to, if they are base64.
pub fn file_size(contents: &str) -> Option<usize> {
    let b = contents.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let pad = b.iter().rev().take_while(|c| **c == b'=').count();
    let alphabet = |c: &u8| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/');
    (pad <= 2 && b[..b.len() - pad].iter().all(alphabet)).then(|| b.len() / 4 * 3 - pad)
}

/// A file name: 1–255 characters on one line, no `/`, not `.` or `..`,
/// without surrounding whitespace.
pub fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.trim() == name
        && name.chars().count() <= MAX_FILE_NAME
        && !name.chars().any(|c| c.is_control() || c == '/')
        && name != "."
        && name != ".."
}

#[test]
fn file_values() {
    let value = file_value("scan.pdf", b"%PDF-1.7 hello");
    assert_eq!(file_parts(&value).0, "scan.pdf");
    assert_eq!(
        file_contents(&value).as_deref(),
        Some(&b"%PDF-1.7 hello"[..])
    );
    assert_eq!(file_size(file_parts(&value).1.unwrap()), Some(14));
    for (contents, size) in [("", Some(0)), ("YQ==", Some(1)), ("YWI=", Some(2))] {
        assert_eq!(file_size(contents), size, "{contents}");
    }
    for bad in ["YQ=", "Y===", "YQ==YQ==x", "Y-Q="] {
        assert_eq!(file_size(bad), None, "{bad}");
    }
    assert_eq!(file_parts("scan.pdf"), ("scan.pdf", None));
    for bad in ["", " a", "a/b", "..", "a\tb", &"x".repeat(256)] {
        assert!(!valid_file_name(bad), "{bad:?}");
    }
    let field = |v: &str| Field::new(FieldType::File, v);
    let document = schema("document").unwrap();
    assert!(check_field(document, "file", &field(&value)).is_ok());
    assert!(check_field(document, "file", &field("scan.pdf\n")).is_ok());
    for bad in ["scan.pdf", "\nYQ==", "a/b\nYQ==", "scan.pdf\nnot base64"] {
        assert!(
            check_field(document, "file", &field(bad)).is_err(),
            "{bad:?}"
        );
    }
    // The size cap, without building a 10 MiB value twice.
    let at_cap = file_value("big.bin", &vec![0; MAX_FILE]);
    assert!(check_field(document, "file", &field(&at_cap)).is_ok());
    let over = file_value("big.bin", &vec![0; MAX_FILE + 1]);
    let error = check_field(document, "file", &field(&over)).unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid value for file: files can be at most 10 MiB"
    );
    // A file may be an extra field of any item.
    let login = schema("login").unwrap();
    assert!(check_field(login, "receipt", &field(&value)).is_ok());
    assert!(check_field(login, "receipt", &field("receipt")).is_err());
}

/// Extra constraint on a known field's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Any,
    /// Only ASCII digits, this many.
    Digits {
        min: usize,
        max: usize,
    },
    /// One line: no control characters or surrounding whitespace, at most
    /// this many characters.
    Line {
        max: usize,
    },
    /// Another item's id: 32 lowercase hex digits.
    ItemRef,
    /// A telephone number: one line of at most 64 characters, in E.164
    /// form (`+15550100`) whenever it reads as an international number
    /// ([`phone`]); a national number stays as typed.
    Phone,
    /// An ISO 3166-1 alpha-2 country code, upper case ([`country`]).
    Country,
}

/// A known field of an item type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaField {
    pub name: &'static str,
    pub kind: FieldType,
    pub required: bool,
    pub format: Format,
    /// Whether values usually span lines (edit in a multi-line editor). Any
    /// value of a text, secret or note field may hold line breaks; this is
    /// the hint, not a rule. Always true for [`FieldType::Note`].
    pub multiline: bool,
}

/// A built-in item type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schema {
    pub kind: &'static str,
    pub fields: &'static [SchemaField],
}

impl Schema {
    pub fn field(&self, name: &str) -> Option<&SchemaField> {
        self.fields.iter().find(|f| f.name == name)
    }
}

const fn known(name: &'static str, kind: FieldType, required: bool) -> SchemaField {
    SchemaField {
        multiline: matches!(kind, FieldType::Note),
        name,
        kind,
        required,
        format: Format::Any,
    }
}

/// A secret that spans lines: a secure note's body, a private key.
const fn secret_lines(name: &'static str, required: bool) -> SchemaField {
    SchemaField {
        name,
        kind: FieldType::Secret,
        required,
        format: Format::Any,
        multiline: true,
    }
}

const fn digits(name: &'static str, required: bool, min: usize, max: usize) -> SchemaField {
    SchemaField {
        name,
        kind: FieldType::Secret,
        required,
        format: Format::Digits { min, max },
        multiline: false,
    }
}

/// A field of any type, not required.
const fn optional(name: &'static str, kind: FieldType) -> SchemaField {
    known(name, kind, false)
}

/// A plain text field with a format.
const fn formatted(name: &'static str, format: Format) -> SchemaField {
    SchemaField {
        name,
        kind: FieldType::Text,
        required: false,
        format,
        multiline: false,
    }
}

/// The officially assigned ISO 3166-1 alpha-2 codes, sorted.
const COUNTRIES: &str = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ \
BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ \
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ \
DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR \
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU \
ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ \
LA LB LC LI LK LR LS LT LU LV LY \
MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ \
NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY \
QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ \
TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ \
VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW";

/// `text` as an ISO 3166-1 alpha-2 country code, in any case and with
/// surrounding space (`" us"` is `US`); `None` if it isn't one.
pub fn country(text: &str) -> Option<&'static str> {
    let code = text.trim().to_ascii_uppercase();
    if code.len() != 2 {
        return None;
    }
    COUNTRIES.split(' ').find(|c| *c == code)
}

/// `text` in E.164 form (`+` and 7–15 digits, the first not 0) if it reads
/// as an international number: a `+` (or `00`), then digits with spaces,
/// dots, dashes, slashes or parentheses between. `None` for anything else,
/// such as a national number or one with an extension, which is kept as
/// typed.
pub fn phone(text: &str) -> Option<String> {
    let text = text.trim();
    let rest = text.strip_prefix('+').or_else(|| text.strip_prefix("00"))?;
    let mut digits = String::from("+");
    for c in rest.chars() {
        match c {
            '0'..='9' => digits.push(c),
            ' ' | '.' | '-' | '/' | '(' | ')' | '\u{a0}' => {}
            _ => return None,
        }
    }
    let n = digits.len() - 1;
    ((7..=15).contains(&n) && !digits[1..].starts_with('0')).then_some(digits)
}

#[test]
fn countries_and_phones() {
    assert_eq!(COUNTRIES.split(' ').count(), 249);
    let codes: Vec<&str> = COUNTRIES.split(' ').collect();
    assert!(codes.windows(2).all(|w| w[0] < w[1]), "sorted, no repeats");
    assert_eq!(country(" us"), Some("US"));
    assert_eq!(country("GB"), Some("GB"));
    for bad in ["UK", "USA", "", "U", "XK", "United States"] {
        assert_eq!(country(bad), None, "{bad}");
    }
    assert_eq!(phone("+1 (555) 010-0100").as_deref(), Some("+15550100100"));
    assert_eq!(phone("0044 20 7946 0958").as_deref(), Some("+442079460958"));
    assert_eq!(phone("+1 555 0100").as_deref(), Some("+15550100"));
    for national in [
        "(555) 010-0100",
        "+1 555 0100 x12",
        "+0 123 4567",
        "+12345",
        "",
    ] {
        assert_eq!(phone(national), None, "{national}");
    }
}

static SCHEMAS: [Schema; 18] = [
    // `sign-in-with` names the provider of a "Sign in with Google" login
    // (`google`, `apple`, ...; see `deadbolt_client::protocol::sign_in_provider`)
    // and `sign-in-account` the login it signs in with, by id. Neither is
    // secret. See docs/autofill.md.
    Schema {
        kind: "login",
        fields: &[
            known("password", FieldType::Secret, false),
            known("username", FieldType::Text, false),
            known("url", FieldType::Url, false),
            known("otp", FieldType::Otp, false),
            known("notes", FieldType::Note, false),
            formatted("sign-in-with", Format::Line { max: 64 }),
            formatted("sign-in-account", Format::ItemRef),
        ],
    },
    Schema {
        kind: "card",
        fields: &[
            digits("number", true, 12, 19),
            known("expiry", FieldType::Month, false),
            digits("cvv", false, 3, 4),
            known("cardholder", FieldType::Text, false),
            known("pin", FieldType::Secret, false),
            known("brand", FieldType::Text, false),
            known("notes", FieldType::Note, false),
            // An identity whose address is the card's billing address.
            formatted("billing", Format::ItemRef),
        ],
    },
    // A secure note: the name is its title, and its body is secret.
    Schema {
        kind: "note",
        fields: &[secret_lines("notes", false)],
    },
    Schema {
        kind: "ssh",
        fields: &[
            secret_lines("private-key", true),
            known("public-key", FieldType::Text, false),
            known("fingerprint", FieldType::Text, false),
            known("passphrase", FieldType::Secret, false),
            known("comment", FieldType::Text, false),
            known("notes", FieldType::Note, false),
        ],
    },
    // A person's details as forms ask for them, named after the HTML
    // autocomplete tokens: `city` is `address-level2` and `region`
    // `address-level1`. See docs/autofill.md, "Forms".
    Schema {
        kind: "identity",
        fields: &[
            known("honorific", FieldType::Text, false),
            known("given-name", FieldType::Text, false),
            known("additional-name", FieldType::Text, false),
            known("family-name", FieldType::Text, false),
            known("nickname", FieldType::Text, false),
            known("organization", FieldType::Text, false),
            known("job-title", FieldType::Text, false),
            known("email", FieldType::Email, false),
            formatted("phone", Format::Phone),
            known("address-line1", FieldType::Text, false),
            known("address-line2", FieldType::Text, false),
            known("address-line3", FieldType::Text, false),
            known("city", FieldType::Text, false),
            known("region", FieldType::Text, false),
            known("postal-code", FieldType::Text, false),
            formatted("country", Format::Country),
            known("birthday", FieldType::Date, false),
            known("national-id", FieldType::Secret, false),
            known("passport", FieldType::Secret, false),
            known("license", FieldType::Secret, false),
            known("notes", FieldType::Note, false),
        ],
    },
    // A WebAuthn passkey: an item of its own, found by relying party id
    // rather than URL. Binary values are base64url; the private key is a
    // PKCS#8 P-256 key that only the agent reads (see docs/autofill.md).
    Schema {
        kind: "passkey",
        fields: &[
            known("rp-id", FieldType::Text, true),
            known("username", FieldType::Text, false),
            known("display-name", FieldType::Text, false),
            known("credential-id", FieldType::Text, true),
            known("user-handle", FieldType::Text, true),
            known("private-key", FieldType::Secret, true),
            known("created", FieldType::Date, false),
            known("notes", FieldType::Note, false),
        ],
    },
    // An API credential: a token or key and what it's for. `type` says how
    // it's used (bearer, basic, aws-access-key, ...), `username` is the key
    // id or account it goes with.
    Schema {
        kind: "api",
        fields: &[
            known("credential", FieldType::Secret, true),
            optional("username", FieldType::Text),
            optional("type", FieldType::Text),
            optional("url", FieldType::Url),
            optional("host", FieldType::Text),
            optional("environment", FieldType::Text),
            optional("expires", FieldType::Date),
            optional("notes", FieldType::Note),
        ],
    },
    Schema {
        kind: "database",
        fields: &[
            optional("type", FieldType::Text),
            optional("host", FieldType::Text),
            formatted("port", Format::Digits { min: 1, max: 5 }),
            optional("database", FieldType::Text),
            optional("username", FieldType::Text),
            optional("password", FieldType::Secret),
            optional("connection-string", FieldType::Secret),
            optional("notes", FieldType::Note),
        ],
    },
    Schema {
        kind: "server",
        fields: &[
            optional("url", FieldType::Url),
            optional("username", FieldType::Text),
            optional("password", FieldType::Secret),
            optional("admin-console", FieldType::Url),
            optional("notes", FieldType::Note),
        ],
    },
    Schema {
        kind: "wifi",
        fields: &[
            optional("ssid", FieldType::Text),
            optional("password", FieldType::Secret),
            optional("security", FieldType::Text),
            optional("notes", FieldType::Note),
        ],
    },
    // A software license.
    Schema {
        kind: "license",
        fields: &[
            optional("product", FieldType::Text),
            optional("version", FieldType::Text),
            secret_lines("license-key", false),
            optional("licensed-to", FieldType::Text),
            optional("email", FieldType::Email),
            optional("order-number", FieldType::Text),
            optional("purchased", FieldType::Date),
            optional("expires", FieldType::Date),
            optional("notes", FieldType::Note),
        ],
    },
    // A bank account.
    Schema {
        kind: "bank",
        fields: &[
            optional("bank", FieldType::Text),
            optional("account-holder", FieldType::Text),
            optional("account-number", FieldType::Secret),
            optional("routing-number", FieldType::Text),
            optional("iban", FieldType::Secret),
            optional("swift", FieldType::Text),
            optional("pin", FieldType::Secret),
            optional("notes", FieldType::Note),
        ],
    },
    // A file: its name travels in the value ([`file_value`]). Any other item
    // may carry files too, as extra fields of type file.
    Schema {
        kind: "document",
        fields: &[
            known("file", FieldType::File, true),
            optional("notes", FieldType::Note),
        ],
    },
    // Documents as 1Password models them. Their numbers are secret; their
    // countries are free text, as the documents print them.
    Schema {
        kind: "passport",
        fields: &[
            optional("full-name", FieldType::Text),
            optional("number", FieldType::Secret),
            optional("type", FieldType::Text),
            optional("issuing-country", FieldType::Text),
            optional("issuing-authority", FieldType::Text),
            optional("nationality", FieldType::Text),
            optional("sex", FieldType::Text),
            optional("birthday", FieldType::Date),
            optional("birthplace", FieldType::Text),
            optional("issued", FieldType::Date),
            optional("expires", FieldType::Date),
            optional("notes", FieldType::Note),
        ],
    },
    Schema {
        kind: "driver-license",
        fields: &[
            optional("full-name", FieldType::Text),
            optional("number", FieldType::Secret),
            optional("class", FieldType::Text),
            optional("conditions", FieldType::Text),
            optional("state", FieldType::Text),
            optional("country", FieldType::Text),
            optional("address", FieldType::Note),
            optional("birthday", FieldType::Date),
            optional("sex", FieldType::Text),
            optional("height", FieldType::Text),
            optional("expires", FieldType::Month),
            optional("notes", FieldType::Note),
        ],
    },
    Schema {
        kind: "membership",
        fields: &[
            optional("organization", FieldType::Text),
            optional("member-name", FieldType::Text),
            optional("member-id", FieldType::Text),
            optional("pin", FieldType::Secret),
            optional("url", FieldType::Url),
            formatted("phone", Format::Phone),
            optional("member-since", FieldType::Month),
            optional("expires", FieldType::Month),
            optional("notes", FieldType::Note),
        ],
    },
    // A cryptocurrency wallet.
    Schema {
        kind: "crypto",
        fields: &[
            secret_lines("recovery-phrase", false),
            optional("password", FieldType::Secret),
            optional("address", FieldType::Text),
            optional("network", FieldType::Text),
            optional("notes", FieldType::Note),
        ],
    },
    // Another identity document: a social security number, a national ID
    // card, a residence permit; `type` says which.
    Schema {
        kind: "id-document",
        fields: &[
            optional("full-name", FieldType::Text),
            optional("number", FieldType::Secret),
            optional("type", FieldType::Text),
            optional("country", FieldType::Text),
            optional("issued", FieldType::Date),
            optional("expires", FieldType::Date),
            optional("notes", FieldType::Note),
        ],
    },
];

#[test]
fn every_schema_names_each_field_once_with_valid_names() {
    let mut kinds = std::collections::BTreeSet::new();
    for schema in schemas() {
        assert!(kinds.insert(schema.kind), "{} twice", schema.kind);
        let mut names = std::collections::BTreeSet::new();
        for field in schema.fields {
            assert!(
                valid_field_name(field.name),
                "{}.{}",
                schema.kind,
                field.name
            );
            assert!(
                names.insert(field.name),
                "{}.{} twice",
                schema.kind,
                field.name
            );
        }
    }
}

#[test]
fn new_kinds_check_their_fields() {
    let ok = |kind: &str, name: &str, field: Field| {
        check_field(schema(kind).unwrap(), name, &field).is_ok()
    };
    let text = |v: &str| Field::new(FieldType::Text, v);
    let secret = |v: &str| Field::new(FieldType::Secret, v);
    assert!(ok("api", "credential", secret("sk_live_x")));
    assert!(!ok("api", "credential", text("sk_live_x")), "secret only");
    assert!(ok(
        "api",
        "expires",
        Field::new(FieldType::Date, "2027-01-31")
    ));
    assert!(!ok(
        "api",
        "expires",
        Field::new(FieldType::Date, "2027-02-31")
    ));
    assert!(ok("database", "port", text("5432")));
    for bad in ["", "543210", "54a", " 5432"] {
        assert!(!ok("database", "port", text(bad)), "{bad:?}");
    }
    assert!(!ok("database", "password", text("pw")), "secret only");
    assert!(ok("wifi", "ssid", text("Home")));
    assert!(ok("license", "license-key", secret("AAAA-BBBB\nCCCC")));
    assert!(ok("bank", "iban", secret("DE89370400440532013000")));
    assert!(!ok("bank", "account-number", text("123")), "secret only");
    assert!(ok(
        "membership",
        "expires",
        Field::new(FieldType::Month, "2027-04")
    ));
    assert!(ok("membership", "phone", text("+15550100")));
    assert!(!ok("membership", "phone", text("+1 555 0100")));
    assert!(ok(
        "crypto",
        "recovery-phrase",
        secret("abandon ability able")
    ));
    assert!(ok("passport", "number", secret("X1234567")));
    assert!(ok(
        "driver-license",
        "expires",
        Field::new(FieldType::Month, "2030-06")
    ));
    assert!(ok("id-document", "number", secret("078-05-1120")));

    // Required fields at create: an API credential needs its credential, a
    // document its file; the others need only a name or a field.
    let none = BTreeMap::new();
    assert_eq!(
        check_create("api", Some("Stripe"), &none, None),
        Err(ItemError::MissingField("credential"))
    );
    assert_eq!(
        check_create("document", Some("Scan"), &none, None),
        Err(ItemError::MissingField("file"))
    );
    for kind in [
        "database",
        "server",
        "wifi",
        "license",
        "bank",
        "passport",
        "driver-license",
        "membership",
        "crypto",
        "id-document",
    ] {
        assert_eq!(check_create(kind, Some("x"), &none, None), Ok(()), "{kind}");
        assert_eq!(check_create(kind, None, &none, None), Err(ItemError::Empty));
    }
}

/// The built-in item types.
pub fn schemas() -> &'static [Schema] {
    &SCHEMAS
}

/// The schema of item type `kind`, if this version knows it.
pub fn schema(kind: &str) -> Option<&'static Schema> {
    SCHEMAS.iter().find(|s| s.kind == kind)
}

/// Whether `name` is a valid field name; the same rule as vault names.
pub fn valid_field_name(name: &str) -> bool {
    valid_name(name)
}

/// Whether `name` is a valid item name: 1–128 characters, no control
/// characters, not only whitespace.
pub fn valid_item_name(name: &str) -> bool {
    !name.trim().is_empty() && name.chars().count() <= 128 && !name.chars().any(char::is_control)
}

/// Whether `source` is valid: an id of 1–256 characters and a version of
/// at most 2048, neither with control characters.
pub fn valid_source(source: &Source) -> bool {
    let clean = |s: &str, max: usize| s.chars().count() <= max && !s.chars().any(char::is_control);
    !source.id.is_empty() && clean(&source.id, 256) && clean(&source.version, 2048)
}

/// Why an item op is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ItemError {
    #[error("unknown item type {0:?}")]
    UnknownType(String),
    #[error("no such item")]
    NoSuchItem,
    #[error("missing required field {0}")]
    MissingField(&'static str),
    #[error(
        "invalid field name {0:?}: use 1-64 lowercase letters, digits, - or _, starting with a letter"
    )]
    InvalidFieldName(String),
    #[error("unknown field type {0:?}")]
    UnknownFieldType(String),
    #[error("field {field} must be of type {expected}")]
    WrongFieldType { field: String, expected: FieldType },
    #[error("invalid value for {field}: {reason}")]
    InvalidValue { field: String, reason: String },
    #[error("field {0} is required and cannot be removed")]
    RequiredField(String),
    #[error("invalid item name: use 1-128 characters without control characters")]
    InvalidItemName,
    #[error("an item needs a name or a field")]
    Empty,
    #[error("invalid item source")]
    InvalidSource,
}

fn invalid(field: &str, reason: impl Into<String>) -> ItemError {
    ItemError::InvalidValue {
        field: field.into(),
        reason: reason.into(),
    }
}

fn check_value(name: &str, field: &Field) -> Result<(), ItemError> {
    let value = field.value.as_str();
    if value.is_empty() {
        return Err(invalid(name, "empty"));
    }
    match &field.kind {
        FieldType::Other(kind) => return Err(ItemError::UnknownFieldType(kind.clone())),
        FieldType::Url => {
            let valid = value.split_once("://").is_some_and(|(scheme, rest)| {
                let mut chars = scheme.chars();
                chars.next().is_some_and(|c| c.is_ascii_alphabetic())
                    && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
                    && !rest.is_empty()
            }) && !value.chars().any(char::is_whitespace);
            if !valid {
                return Err(invalid(name, "not an absolute URL"));
            }
        }
        FieldType::Email if !value.contains('@') => {
            return Err(invalid(name, "not an email address"));
        }
        FieldType::Month => {
            let b = value.as_bytes();
            let month = value.get(5..).and_then(|m| m.parse::<u8>().ok());
            let valid = b.len() == 7
                && b[..4].iter().all(u8::is_ascii_digit)
                && b[4] == b'-'
                && b[5..].iter().all(u8::is_ascii_digit)
                && month.is_some_and(|m| (1..=12).contains(&m));
            if !valid {
                return Err(invalid(name, "not a month (YYYY-MM)"));
            }
        }
        FieldType::Date if !valid_date(value) => {
            return Err(invalid(name, "not a date (YYYY-MM-DD)"));
        }
        FieldType::File => {
            let (file, contents) = file_parts(value);
            if !valid_file_name(file) {
                return Err(invalid(name, "not a file name"));
            }
            match contents.map(file_size) {
                None | Some(None) => return Err(invalid(name, "not a file")),
                Some(Some(size)) if size > MAX_FILE => {
                    return Err(invalid(
                        name,
                        format!("files can be at most {} MiB", MAX_FILE >> 20),
                    ));
                }
                Some(Some(_)) => {}
            }
        }
        _ => {}
    }
    Ok(())
}

/// `YYYY-MM-DD`, a day that exists.
fn valid_date(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| {
        b[r.clone()]
            .iter()
            .all(u8::is_ascii_digit)
            .then(|| value[r].parse::<u32>().ok())
            .flatten()
    };
    let (Some(year), Some(month), Some(day)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

#[test]
fn dates() {
    for ok in ["2024-02-29", "1970-01-01", "2026-12-31"] {
        assert!(valid_date(ok), "{ok}");
    }
    for bad in [
        "2023-02-29",
        "2026-13-01",
        "2026-04-31",
        "2026-1-01",
        "26-01-01",
        "2026-01-00",
        "+026-01-01",
    ] {
        assert!(!valid_date(bad), "{bad}");
    }
}

/// Checks one field of an item of type `schema` (known type, name, value).
pub fn check_field(schema: &Schema, name: &str, field: &Field) -> Result<(), ItemError> {
    if !valid_field_name(name) {
        return Err(ItemError::InvalidFieldName(name.into()));
    }
    check_value(name, field)?;
    if let Some(known) = schema.field(name) {
        if field.kind != known.kind {
            return Err(ItemError::WrongFieldType {
                field: name.into(),
                expected: known.kind.clone(),
            });
        }
        let value = field.value.as_str();
        match known.format {
            Format::Any => {}
            Format::Digits { min, max } => {
                let n = value.len();
                if !value.bytes().all(|b| b.is_ascii_digit()) || n < min || n > max {
                    return Err(invalid(name, format!("must be {min}-{max} digits")));
                }
            }
            Format::Line { max } => {
                if value.chars().any(char::is_control)
                    || value.trim() != value
                    || value.chars().count() > max
                {
                    return Err(invalid(
                        name,
                        format!("must be one line of at most {max} characters"),
                    ));
                }
            }
            Format::ItemRef => {
                let hex = |b: &u8| b.is_ascii_digit() || (b'a'..=b'f').contains(b);
                if value.len() != 32 || !value.bytes().all(|b| hex(&b)) {
                    return Err(invalid(name, "not an item id"));
                }
            }
            Format::Phone => {
                if value.chars().any(char::is_control)
                    || value.trim() != value
                    || value.chars().count() > 64
                {
                    return Err(invalid(name, "must be one line of at most 64 characters"));
                }
                if phone(value).is_some_and(|e164| e164 != value) {
                    return Err(invalid(
                        name,
                        "an international number is stored as +15550100",
                    ));
                }
            }
            Format::Country => {
                if country(value) != Some(value) {
                    return Err(invalid(name, "not an ISO country code (US, GB, ...)"));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn sign_in_fields() {
    let login = schema("login").unwrap();
    let text = |v: &str| Field::new(FieldType::Text, v);
    assert!(check_field(login, "sign-in-with", &text("google")).is_ok());
    assert!(check_field(login, "sign-in-with", &text("My company SSO")).is_ok());
    for bad in [" google", "a\nb", &"x".repeat(65)] {
        assert!(
            check_field(login, "sign-in-with", &text(bad)).is_err(),
            "{bad:?}"
        );
    }
    let id = "0123456789abcdef0123456789abcdef";
    assert!(check_field(login, "sign-in-account", &text(id)).is_ok());
    for bad in [&id[1..], &id.to_uppercase(), &format!("{}g", &id[1..])] {
        assert!(
            check_field(login, "sign-in-account", &text(bad)).is_err(),
            "{bad}"
        );
    }
    // Not secret: never masked.
    let secret = Field::new(FieldType::Secret, "google");
    assert!(check_field(login, "sign-in-with", &secret).is_err());
}

#[test]
fn identity_and_card_fields() {
    let identity = schema("identity").unwrap();
    let text = |v: &str| Field::new(FieldType::Text, v);
    for (name, ok) in [
        ("phone", "+15550100"),
        ("phone", "(555) 010-0100"),
        ("phone", "+1 555 0100 ext. 3"),
        ("country", "US"),
        ("given-name", "Kit"),
        ("address-line1", "123 Main St"),
    ] {
        assert!(
            check_field(identity, name, &text(ok)).is_ok(),
            "{name} {ok}"
        );
    }
    for (name, bad) in [
        ("phone", "+1 555 0100"),
        ("phone", "555\n0100"),
        ("country", "us"),
        ("country", "USA"),
        ("country", "ZZ"),
    ] {
        assert!(
            check_field(identity, name, &text(bad)).is_err(),
            "{name} {bad}"
        );
    }
    let date = |v: &str| Field::new(FieldType::Date, v);
    assert!(check_field(identity, "birthday", &date("1990-03-01")).is_ok());
    assert!(check_field(identity, "birthday", &date("1990-13-01")).is_err());
    // The old free-text fields are extras like any other.
    assert!(identity.field("name").is_none() && identity.field("address").is_none());
    assert!(
        check_field(
            identity,
            "address",
            &Field::new(FieldType::Note, "1 Main St\nX")
        )
        .is_ok()
    );

    let card = schema("card").unwrap();
    let id = "0123456789abcdef0123456789abcdef";
    assert!(check_field(card, "billing", &text(id)).is_ok());
    assert!(check_field(card, "billing", &text("home")).is_err());
}

/// Checks what only values written now must satisfy: an otp must be a TOTP
/// secret ([`crate::totp::Totp::parse`]). Entries are not held to it, so
/// values already in a vault stay valid on every device.
pub fn check_new_value(name: &str, field: &Field) -> Result<(), ItemError> {
    if field.kind == FieldType::Otp {
        crate::totp::Totp::parse(&field.value).map_err(|e| invalid(name, e.to_string()))?;
    }
    Ok(())
}

/// Checks a change to an existing item of type `kind`.
pub(crate) fn check_change(kind: &str, change: &Change) -> Result<(), ItemError> {
    let schema = schema(kind).ok_or_else(|| ItemError::UnknownType(kind.into()))?;
    match change {
        Change::Set { field, value } => check_field(schema, field, value),
        Change::Remove { field } => {
            if !valid_field_name(field) {
                return Err(ItemError::InvalidFieldName(field.clone()));
            }
            if schema.field(field).is_some_and(|f| f.required) {
                return Err(ItemError::RequiredField(field.clone()));
            }
            Ok(())
        }
        Change::Name(Some(name)) if !valid_item_name(name) => Err(ItemError::InvalidItemName),
        Change::Source(Some(source)) if !valid_source(source) => Err(ItemError::InvalidSource),
        Change::Name(_) | Change::Delete | Change::Source(_) => Ok(()),
    }
}

/// Checks a `Create` op.
pub fn check_create(
    kind: &str,
    name: Option<&str>,
    fields: &BTreeMap<String, Field>,
    source: Option<&Source>,
) -> Result<(), ItemError> {
    let schema = schema(kind).ok_or_else(|| ItemError::UnknownType(kind.into()))?;
    if source.is_some_and(|s| !valid_source(s)) {
        return Err(ItemError::InvalidSource);
    }
    if let Some(missing) = schema
        .fields
        .iter()
        .find(|f| f.required && !fields.contains_key(f.name))
    {
        return Err(ItemError::MissingField(missing.name));
    }
    if name.is_some_and(|n| !valid_item_name(n)) {
        return Err(ItemError::InvalidItemName);
    }
    if name.is_none() && fields.is_empty() {
        return Err(ItemError::Empty);
    }
    fields
        .iter()
        .try_for_each(|(name, field)| check_field(schema, name, field))
}
