//! Secrets for commands: what `resolve` is for and what it finds.

use serde::{Deserialize, Serialize};

use super::Secret;

/// What resolved secrets are for: a command's environment (`deadbolt
/// run`), a file (`deadbolt inject`) or printing (`deadbolt read`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    Run,
    Inject,
    Read,
}

/// One resolved reference: which item and field it found, and the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSecret {
    /// The vault's name.
    pub vault: String,
    /// The item's id.
    pub item: String,
    pub title: String,
    pub field: String,
    pub value: Secret,
    /// A file field: `value` is its name and contents in base64, which only
    /// `inject` writes out (decoded), for a template that is that one
    /// reference.
    #[serde(default)]
    pub file: bool,
}
