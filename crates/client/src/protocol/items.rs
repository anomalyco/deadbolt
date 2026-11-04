//! The items a daemon holds: `ItemInfo` and its fields, the forms an item
//! fills, and the field input an item is written with. Values are wiped on
//! drop.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::LoginRef;

/// The kinds of item forms fill from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FormKind {
    Identity,
    Card,
}

impl FormKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Card => "card",
        }
    }
}
pub use deadbolt_core::forms::{CARD_FORM_FIELDS, CARD_VERIFIED_FIELDS, IDENTITY_FORM_FIELDS};
pub use deadbolt_core::listing::{
    KINDS, SIGN_IN_PROVIDERS, noun, primary_field, sign_in_name, sign_in_provider,
};

/// An identity a form can be filled from, without values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormIdentity {
    pub item: LoginRef,
    /// The name of its vault.
    pub vault: String,
    pub title: String,
    /// Who and where: "Kit Langton · 123 Main St, Brooklyn". May be empty.
    pub summary: String,
    /// The form fields it has a value for.
    pub fields: Vec<String>,
}

/// A card a form can be filled from, without its number or code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormCard {
    pub item: LoginRef,
    pub vault: String,
    pub title: String,
    pub brand: Option<String>,
    pub last4: String,
    /// `YYYY-MM`.
    pub expiry: Option<String>,
    pub cardholder: Option<String>,
    /// Its billing address's identity, if that is in one of the vaults here.
    pub billing: Option<LoginRef>,
    pub fields: Vec<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SshKeyKind {
    Ed25519,
    EcdsaP256,
}
/// A file from an export, beside its text: a `.1pux`'s attachment, named
/// as in the archive's `files/` (`<documentId>__<fileName>`), its contents
/// in base64. `too_large` (and no contents) for one over the cap or past
/// what fits in the request, so the daemon can say why it's left out. Wiped
/// on drop; Debug leaves out the contents.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ExportFile {
    pub name: String,
    pub data: String,
    #[serde(default)]
    pub too_large: bool,
}

impl std::fmt::Debug for ExportFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportFile")
            .field("name", &self.name)
            .field("data", &"<redacted>")
            .finish()
    }
}

/// A field as typed by the user. Without `kind`, the daemon uses the item
/// type's field type, else the field's current type, else `text`. Wiped on
/// drop; Debug leaves out the value.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct FieldInput {
    pub name: String,
    pub kind: Option<String>,
    pub value: String,
}

impl std::fmt::Debug for FieldInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldInput")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("value", &"<redacted>")
            .finish()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagCount {
    pub tag: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemInfo {
    pub id: String,
    /// Shortest unique id prefix, at least 4 characters.
    pub short: String,
    pub kind: String,
    /// The name, or one derived from the fields.
    pub label: String,
    /// What the item is, if anything says: a login's username (else "Sign
    /// in with Google" for one that signs in with another account), a card's
    /// expiry, an SSH key's comment or fingerprint, an identity's email or
    /// phone. Never a secure note's body.
    pub detail: Option<String>,
    /// Known fields in schema order, then extra fields by name. Empty in lists.
    pub fields: Vec<FieldInfo>,
    /// The app the item is mirrored from ("1Password"), which overwrites
    /// changes made here; `None` for the user's own.
    pub source: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    /// When a deleted item was deleted (seconds since the Unix epoch, on
    /// the deleting device's clock), in `ItemList` with `deleted`. `None`
    /// for live items, and for deletes from before deletes were timed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<u64>,
}

/// The field an item's one-time code comes from, as the daemon picks it:
/// `otp`, else the first field of type otp.
pub fn code_field(fields: &[FieldInfo]) -> Option<usize> {
    let otp = |f: &FieldInfo| f.kind == "otp";
    fields
        .iter()
        .position(|f| f.name == "otp" && otp(f))
        .or_else(|| fields.iter().position(otp))
}

/// Wiped on drop; Debug leaves out the value.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct FieldInfo {
    pub name: String,
    pub kind: String,
    pub value: String,
}

impl std::fmt::Debug for FieldInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldInfo")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("value", &"<redacted>")
            .finish()
    }
}
