//! The background update check (docs/releasing.md, "Updater"): ten seconds
//! after the daemon starts, then on its channel's schedule, whether a newer
//! Deadbolt is out for this install ([`crate::update::available`]). It only
//! tells: `status` carries it and watchers hear `update` when it changes.
//! Nothing is ever downloaded or installed here; `deadbolt update` does that.
//! It needs no unlock, and a failure backs off and is tried again, never
//! past an hour.

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use super::Daemon;
use crate::protocol::UpdateInfo;
use crate::update::{Checked, Etags};

/// Turns the check off when set to anything but empty or `0`.
pub const OPT_OUT: &str = "DEADBOLT_NO_UPDATE_CHECK";
/// macOS's administrator or user preference that turns the check off for
/// this app, as a Mac fleet sets it:
/// `defaults write pw.deadbolt.app DisableUpdates 1`.
const DISABLE_UPDATES: &str = "DisableUpdates";
/// The preference domains read for it: Deadbolt.app's and the CLI's, since
/// the daemon may run from either.
const PREFERENCE_DOMAINS: [&str; 2] = ["pw.deadbolt.app", "pw.deadbolt.cli"];
/// Debug builds only: check this channel (a build from source follows
/// none), at once and every second, for tests.
const TEST_CHANNEL: &str = "DEADBOLT_UPDATE_CHECK_CHANNEL";

/// The wait after startup, so a launch storm isn't also a check storm.
const START_DELAY: Duration = Duration::from_secs(10);
/// The dev channel moves fast.
const DEV_EVERY: Duration = Duration::from_secs(10 * 60);
/// Stable and beta are the protocol's floor: at least once an hour.
const RELEASE_EVERY: Duration = Duration::from_secs(60 * 60);
/// A failed dev check retries within the minute.
const DEV_BACKOFF: Duration = Duration::from_secs(60);
/// A failed stable or beta check retries in five minutes.
const RELEASE_BACKOFF: Duration = Duration::from_secs(5 * 60);
/// However many failures, a check is never more than an hour away.
const MAX_BACKOFF: Duration = Duration::from_secs(60 * 60);
/// The test channel checks every second, with no startup delay.
const TEST_EVERY: Duration = Duration::from_secs(1);

/// What to check, how often, and the first retry after a failure.
#[derive(Debug, PartialEq, Eq)]
struct Schedule {
    channel: String,
    every: Duration,
    backoff: Duration,
    delay: Duration,
}

/// Whether `DEADBOLT_NO_UPDATE_CHECK`'s value turns the check off.
fn opted_out(value: Option<&str>) -> bool {
    value.is_some_and(|v| !v.is_empty() && v != "0")
}

/// Whether and when to check: release builds that know their channel
/// (`built`), unless `off`; the test channel in debug builds.
fn schedule(built: Option<&str>, off: bool, test: Option<&str>) -> Option<Schedule> {
    if off {
        return None;
    }
    if let Some(channel) = test.filter(|c| !c.is_empty()) {
        return Some(Schedule {
            channel: channel.into(),
            every: TEST_EVERY,
            backoff: TEST_EVERY,
            delay: Duration::ZERO,
        });
    }
    let channel = built?.to_string();
    let (every, backoff) = match channel.as_str() {
        "dev" => (DEV_EVERY, DEV_BACKOFF),
        _ => (RELEASE_EVERY, RELEASE_BACKOFF),
    };
    Some(Schedule {
        channel,
        every,
        backoff,
        delay: START_DELAY,
    })
}

/// The wait after `failures` consecutive failed checks: `initial`, doubled
/// each time, capped at [`MAX_BACKOFF`] so failures never back off past an
/// hour.
fn retry_delay(initial: Duration, failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    initial.saturating_mul(1 << doublings).min(MAX_BACKOFF)
}

/// Whether a `defaults` value says updates are off: `1`, `true` or
/// `yes`, in any case or whitespace.
fn disabled_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

/// Whether macOS's `DisableUpdates` preference turns the check off.
/// `read` returns a domain's `defaults` value, `None` on any error; an
/// unreadable or unset preference, or a machine that isn't a Mac, leaves
/// updates on.
fn updates_disabled(macos: bool, read: impl Fn(&str) -> Option<String>) -> bool {
    macos
        && PREFERENCE_DOMAINS
            .iter()
            .any(|domain| read(domain).as_deref().is_some_and(disabled_value))
}

/// [`updates_disabled`] for this Mac, through `defaults`, which reads the
/// user's preference and the administrators' managed one alike.
fn macos_disabled() -> bool {
    updates_disabled(cfg!(target_os = "macos"), |domain| {
        let output = Command::new("/usr/bin/defaults")
            .args(["read", domain, DISABLE_UPDATES])
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    })
}

/// Runs the check for as long as the daemon does.
pub async fn run(daemon: Arc<Daemon>) {
    let env = |name| crate::config::env(name).ok();
    let Some(schedule) = schedule(
        crate::update::build_channel(),
        opted_out(env(OPT_OUT).as_deref()) || macos_disabled(),
        crate::config::test_env(TEST_CHANNEL).as_deref(),
    ) else {
        return;
    };
    if !schedule.delay.is_zero() {
        tokio::time::sleep(schedule.delay).await;
    }
    let mut etags = Etags::new();
    let mut failures = 0;
    loop {
        match crate::update::available(&daemon.paths, &schedule.channel, &mut etags).await {
            Ok(Checked::Unchanged) => failures = 0,
            Ok(Checked::Found(found)) => {
                failures = 0;
                daemon.set_update(found);
            }
            Err(error) => {
                failures += 1;
                warn!("update check failed: {error:#}");
            }
        }
        let wait = match failures {
            0 => schedule.every,
            failures => retry_delay(schedule.backoff, failures),
        };
        tokio::time::sleep(wait).await;
    }
}

impl Daemon {
    /// Records what the check found, telling watchers when it changed.
    fn set_update(&self, found: Option<UpdateInfo>) {
        let mut update = self.update.lock().unwrap_or_else(|e| e.into_inner());
        if *update == found {
            return;
        }
        match &found {
            Some(found) => {
                info!(version = %found.version, method = %found.method, "update available")
            }
            None => info!("no update available"),
        }
        *update = found;
        drop(update);
        self.watchers.update();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_release_builds_unless_opted_out() {
        let release = schedule(Some("dev"), false, None).unwrap();
        assert_eq!(release.channel, "dev");
        assert_eq!(release.every, DEV_EVERY);
        assert_eq!(release.backoff, DEV_BACKOFF);
        assert_eq!(release.delay, START_DELAY);
        for channel in ["stable", "beta"] {
            let release = schedule(Some(channel), false, None).unwrap();
            assert_eq!(release.channel, channel);
            assert_eq!(release.every, RELEASE_EVERY);
            assert_eq!(release.backoff, RELEASE_BACKOFF);
        }
        assert_eq!(schedule(None, false, None), None);
        assert_eq!(schedule(Some("dev"), true, None), None);
        for off in ["1", "yes", "true"] {
            assert!(opted_out(Some(off)), "{off}");
        }
        for on in ["", "0"] {
            assert!(!opted_out(Some(on)), "{on}");
        }
        assert!(!opted_out(None));
        let test = schedule(None, false, Some("beta")).unwrap();
        assert_eq!(test.channel, "beta");
        assert_eq!(test.every, TEST_EVERY);
        assert_eq!(test.backoff, TEST_EVERY);
        assert_eq!(test.delay, Duration::ZERO);
        assert_eq!(
            schedule(Some("dev"), false, Some("")).unwrap().channel,
            "dev"
        );
    }

    #[test]
    fn failures_back_off_but_never_past_an_hour() {
        assert_eq!(retry_delay(DEV_BACKOFF, 1), Duration::from_secs(60));
        assert_eq!(retry_delay(DEV_BACKOFF, 2), Duration::from_secs(120));
        assert_eq!(retry_delay(DEV_BACKOFF, 3), Duration::from_secs(240));
        assert_eq!(retry_delay(RELEASE_BACKOFF, 1), Duration::from_secs(300));
        assert_eq!(retry_delay(RELEASE_BACKOFF, 2), Duration::from_secs(600));
        assert_eq!(retry_delay(DEV_BACKOFF, 7), MAX_BACKOFF);
        assert_eq!(retry_delay(DEV_BACKOFF, 99), MAX_BACKOFF);
        assert_eq!(retry_delay(RELEASE_BACKOFF, u32::MAX), MAX_BACKOFF);
        assert!(retry_delay(RELEASE_BACKOFF, 40) <= MAX_BACKOFF);
    }

    #[test]
    fn managed_macs_can_turn_the_check_off() {
        assert!(disabled_value("1"));
        assert!(disabled_value(" true\n"));
        assert!(disabled_value("YES"));
        assert!(!disabled_value("0"));
        assert!(!disabled_value(""));
        assert!(!disabled_value("no"));
        assert!(!disabled_value("garbage"));
        assert!(!updates_disabled(false, |_| Some("1".into())));
        assert!(updates_disabled(true, |_| Some("1".into())));
        assert!(!updates_disabled(true, |_| None));
        assert!(!updates_disabled(true, |_| Some("0".into())));
    }
}
