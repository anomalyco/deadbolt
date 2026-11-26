//! Structured JSON report for `deadbolt update --json` (and `--check --json`).

use serde::Serialize;

use super::method::{Install, Manager, method_key, upgrade_command};
use super::protocol::Decision;

/// Structured output emitted by `deadbolt update --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct UpdateReport {
    pub(super) current: String,
    pub(super) latest: String,
    pub(super) channel: String,
    pub(super) available: bool,
    pub(super) method: String,
    pub(super) action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) notes_url: Option<String>,
}

/// Builds the JSON report for `deadbolt update --json`.
pub(super) fn build_report(
    current: &str,
    manifest_version: &str,
    channel: &str,
    install: &Install,
    decision: &Decision,
    check: bool,
    extension_available: bool,
) -> UpdateReport {
    let method = method_key(install).to_string();
    match decision {
        Decision::None(reason) => UpdateReport {
            current: current.to_string(),
            latest: manifest_version.to_string(),
            channel: channel.to_string(),
            available: extension_available,
            method,
            action: if extension_available {
                if check { "install" } else { "updated" }
            } else {
                "none"
            },
            reason: Some(*reason),
            command: None,
            notes_url: None,
        },
        Decision::Install {
            reason, version, ..
        } => UpdateReport {
            current: current.to_string(),
            latest: version.clone(),
            channel: channel.to_string(),
            available: true,
            method,
            action: if check { "install" } else { "updated" },
            reason: Some(reason.as_str()),
            command: None,
            notes_url: None,
        },
        Decision::Notify {
            reason,
            version,
            command,
            notes_url,
            ..
        } => {
            let manager = match install {
                Install::Managed(manager) => Some(*manager),
                _ => None,
            };
            let upgrade = manager.and_then(|m| upgrade_command(m, version));
            let action = if !check && upgrade.is_some() {
                "updated"
            } else {
                "notify"
            };
            let command = match (manager, upgrade, command) {
                (_, Some(upgrade), _) => Some(upgrade.shown),
                (Some(Manager::Package), None, _) => Some(Manager::Package.hint(channel)),
                (Some(m), None, None) => Some(m.hint(channel)),
                (_, None, Some(cmd)) => Some(cmd.clone()),
                (None, None, None) => None,
            };
            UpdateReport {
                current: current.to_string(),
                latest: version.clone(),
                channel: channel.to_string(),
                available: true,
                method,
                action,
                reason: Some(reason.as_str()),
                command,
                notes_url: notes_url.clone(),
            }
        }
        Decision::Reject(reason) => UpdateReport {
            current: current.to_string(),
            latest: manifest_version.to_string(),
            channel: channel.to_string(),
            available: false,
            method,
            action: "reject",
            reason: Some(*reason),
            command: None,
            notes_url: None,
        },
    }
}
