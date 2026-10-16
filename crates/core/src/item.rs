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

use crate::entry::{Change, valid_name};

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
    /// Multi-line text.
    Note,
    Other(String),
}

impl FieldType {
    pub const KNOWN: [FieldType; 7] = [
        FieldType::Text,
        FieldType::Secret,
        FieldType::Url,
        FieldType::Email,
        FieldType::Otp,
        FieldType::Month,
        FieldType::Note,
    ];

    /// Parses the wire identifier; unknown identifiers become [`FieldType::Other`].
    pub fn parse(s: &str) -> Self {
        match s {
            "text" => Self::Text,
            "secret" => Self::Secret,
            "url" => Self::Url,
            "email" => Self::Email,
            "otp" => Self::Otp,
            "month" => Self::Month,
            "note" => Self::Note,
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
            Self::Note => "note",
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub kind: FieldType,
    pub value: String,
}

impl Field {
    pub fn new(kind: FieldType, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }
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
}

/// A known field of an item type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaField {
    pub name: &'static str,
    pub kind: FieldType,
    pub required: bool,
    pub format: Format,
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
        name,
        kind,
        required,
        format: Format::Any,
    }
}

const fn digits(name: &'static str, required: bool, min: usize, max: usize) -> SchemaField {
    SchemaField {
        name,
        kind: FieldType::Secret,
        required,
        format: Format::Digits { min, max },
    }
}

static SCHEMAS: [Schema; 2] = [
    Schema {
        kind: "login",
        fields: &[
            known("password", FieldType::Secret, true),
            known("username", FieldType::Text, false),
            known("url", FieldType::Url, false),
            known("otp", FieldType::Otp, false),
            known("notes", FieldType::Note, false),
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
        ],
    },
];

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
        _ => {}
    }
    Ok(())
}

/// Checks one field of an item of type `schema` (known type, name, value).
pub(crate) fn check_field(schema: &Schema, name: &str, field: &Field) -> Result<(), ItemError> {
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
        if let Format::Digits { min, max } = known.format {
            let n = field.value.len();
            if !field.value.bytes().all(|b| b.is_ascii_digit()) || n < min || n > max {
                return Err(invalid(name, format!("must be {min}-{max} digits")));
            }
        }
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
        Change::Name(_) | Change::Delete => Ok(()),
    }
}

/// Checks a `Create` op.
pub(crate) fn check_create(
    kind: &str,
    name: Option<&str>,
    fields: &BTreeMap<String, Field>,
) -> Result<(), ItemError> {
    let schema = schema(kind).ok_or_else(|| ItemError::UnknownType(kind.into()))?;
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
    fields
        .iter()
        .try_for_each(|(name, field)| check_field(schema, name, field))
}
