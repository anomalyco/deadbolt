//! Password health protocol types. Never carry secret values or hashes.

use serde::{Deserialize, Serialize};

pub use deadbolt_core::health::{
    Finding, FindingKind, HealthCounts, HealthPeer, ItemHealth, PassphraseStrength, RiskLevel,
    WeakReason, audited_password_field, passphrase_strength,
};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReport {
    /// Vault id when scoped to one vault; `None` when reporting across all vaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    pub counts: HealthCounts,
    pub items: Vec<ItemHealth>,
    /// Whether opt-in HIBP online breach checks are enabled in `config.toml`.
    pub breach_checks_enabled: bool,
    /// Unix seconds when HIBP was last checked on this device, if ever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breach_last_checked: Option<u64>,
}
