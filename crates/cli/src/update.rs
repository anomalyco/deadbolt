//! `deadbolt update`: updates this Deadbolt from the Anomaly release service
//! (docs/releasing.md, "Updater"), following the service's client rules
//! (`anomalyco/release` docs/protocol.md). What it updates depends on how
//! this binary is installed ([`method`]): Deadbolt.app (the `desktop`
//! artifact) or a standalone CLI (`cli`) replace themselves; npm, pnpm, bun,
//! yarn and Homebrew installs run that manager, pinned to the version it
//! serves; Nix, Cargo and system installs get their manager's command. An
//! unpacked browser extension registered with `deadbolt browser install
//! --extension-dir` is updated too (`extension`).
//!
//! The daemon checks in the background ([`available`]) and only ever says
//! so: nothing is installed unless the user runs `deadbolt update`.
//!
//! Nothing downloaded runs or replaces anything before its size and SHA-256
//! match the manifest and, on macOS, its code signature satisfies what the
//! running install would ([`APP_REQUIREMENT`]). Each replacement is staged
//! beside its destination and renamed into place.

mod extension;
mod install;
mod method;
mod notice;
mod protocol;
mod replace;
mod service;

pub use self::extension::{extension_dir_ok, switch_extension};
pub use self::install::{UpdateArgs, available, run};
pub use self::notice::notice;
pub(crate) use self::protocol::build_channel;

#[cfg(test)]
use anyhow::Result;
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Command;
#[cfg(test)]
use url::Url;

#[cfg(test)]
use crate::config::ExtensionBuild;
#[cfg(test)]
use crate::protocol::UpdateInfo;

#[cfg(test)]
use self::extension::{
    EXTENSION_LIMIT, EXTENSION_MARKER, extension_build, extension_version, unpack_extension,
};
#[cfg(test)]
use self::install::{
    OUTPUT_LINES, UpdateState, check_sequence, output_tail, platform_package, served_by_npm,
    static_for, upgrade_failure, user_link,
};
#[cfg(test)]
use self::method::{
    CASKROOMS, Install, Manager, PACKAGE, PLATFORM_PACKAGES, classify, installed_with,
    lists_package, manager_order, package_of, upgrade_command,
};
#[cfg(test)]
use self::notice::{NOTICE_EVERY, notice_due, notice_line};
#[cfg(test)]
use self::protocol::{Decision, Reason, Running, Target, decide, rollout_bucket};
#[cfg(test)]
use self::replace::{
    CODESIGN, check_app_zip, link_inside, pax_path, requirement, root_may_update, satisfies,
    signature_required, swap, unpack_cli,
};
#[cfg(test)]
use self::service::{SERVICE, SERVICE_OVERRIDE, file_url, loopback_or};

/// What `Deadbolt.app` must satisfy (identifier, team, Developer ID,
/// notarized), the release's `verify-macos` check.
const APP_REQUIREMENT: &str = include_str!("../../app/update-requirement.txt");

#[cfg(test)]
mod tests;
