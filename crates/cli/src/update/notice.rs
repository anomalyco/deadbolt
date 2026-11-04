//! Telling people an update exists: one line, at most daily per version.

use std::time::Duration;

use crate::paths::Paths;
use crate::protocol::UpdateInfo;

use super::install::state_dir;
use super::method::installed_with;

/// Remembers the last notice, `<version> <unix seconds>`, in the state
/// directory.
const NOTICE_FILE: &str = "update-notice";
/// How often one version's notice may show.
pub(super) const NOTICE_EVERY: u64 = 24 * 3600;

/// Whether to tell of `version` at `now`, after the notice `last`
/// ([`NOTICE_FILE`]'s text): another version at once, the same one a day
/// later.
pub(super) fn notice_due(last: Option<&str>, version: &str, now: u64) -> bool {
    let Some((seen, at)) = last.and_then(|t| t.trim().split_once(' ')) else {
        return true;
    };
    let Ok(at) = at.parse::<u64>() else {
        return true;
    };
    seen != version || at > now || now - at >= NOTICE_EVERY
}

pub(super) fn notice_line(update: &UpdateInfo) -> String {
    format!(
        "deadbolt {} is out ({}): run deadbolt update",
        update.version,
        installed_with(&update.method)
    )
}

/// Ends a command at a terminal with one line on stderr when the running
/// daemon's check found an update, at most once a day for each version.
/// With no daemon running it says nothing, and never asks the network.
pub async fn notice(paths: &Paths) {
    let status = tokio::time::timeout(Duration::from_secs(1), crate::client::status(paths)).await;
    let Some(update) = status.ok().flatten().and_then(|s| s.update) else {
        return;
    };
    let file = state_dir(paths).join(NOTICE_FILE);
    let now = crate::config::now();
    let last = std::fs::read_to_string(&file).ok();
    if !notice_due(last.as_deref(), &update.version, now) {
        return;
    }
    eprintln!("{}", notice_line(&update));
    std::fs::create_dir_all(state_dir(paths)).ok();
    crate::browser::write_atomic(&file, &format!("{} {now}\n", update.version)).ok();
}
