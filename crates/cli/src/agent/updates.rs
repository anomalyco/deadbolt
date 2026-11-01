//! The background update check (docs/releasing.md, "Updater"): shortly
//! after the agent starts, then every few hours, whether a newer Deadbolt
//! is out for this install ([`crate::update::available`]). It only tells:
//! `status` carries it and watchers hear `update` when it changes. Nothing
//! is ever downloaded or installed here; `deadbolt update` does that. It
//! needs no unlock, and a failure is logged and tried again next time.

use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use super::Agent;
use crate::protocol::UpdateInfo;

/// Turns the check off when set to anything but empty or `0`.
pub const OPT_OUT: &str = "DEADBOLT_NO_UPDATE_CHECK";
/// Debug builds only: check this channel (a build from source follows
/// none), at once and every second, for tests.
const TEST_CHANNEL: &str = "DEADBOLT_UPDATE_CHECK_CHANNEL";

const FIRST: Duration = Duration::from_secs(60);
const FIRST_JITTER: Duration = Duration::from_secs(60);
const EVERY: Duration = Duration::from_secs(6 * 3600);
const EVERY_JITTER: Duration = Duration::from_secs(30 * 60);

/// When to check.
#[derive(Debug, PartialEq, Eq)]
struct Schedule {
    channel: String,
    first: Duration,
    every: Duration,
    jitter: bool,
}

/// Whether and when to check: release builds that know their channel
/// (`built`), unless opted out; the test channel in debug builds.
fn schedule(built: Option<&str>, opt_out: Option<&str>, test: Option<&str>) -> Option<Schedule> {
    if opt_out.is_some_and(|v| !v.is_empty() && v != "0") {
        return None;
    }
    if let Some(channel) = test.filter(|c| !c.is_empty()) {
        return Some(Schedule {
            channel: channel.into(),
            first: Duration::ZERO,
            every: Duration::from_secs(1),
            jitter: false,
        });
    }
    Some(Schedule {
        channel: built?.into(),
        first: FIRST,
        every: EVERY,
        jitter: true,
    })
}

/// `base` plus up to `jitter`, from `random`, so installs don't all ask at
/// once.
fn jittered(base: Duration, jitter: Duration, random: u64) -> Duration {
    let spread = u64::try_from(jitter.as_millis()).unwrap_or(0);
    base + Duration::from_millis(random.checked_rem(spread).unwrap_or(0))
}

fn random() -> u64 {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).ok();
    u64::from_le_bytes(bytes)
}

/// Runs the check for as long as the agent does.
pub async fn run(agent: Arc<Agent>) {
    let env = |name| crate::config::env(name).ok();
    let Some(schedule) = schedule(
        crate::update::build_channel(),
        env(OPT_OUT).as_deref(),
        crate::config::test_env(TEST_CHANNEL).as_deref(),
    ) else {
        return;
    };
    let delay = |base, jitter| match schedule.jitter {
        true => jittered(base, jitter, random()),
        false => base,
    };
    tokio::time::sleep(delay(schedule.first, FIRST_JITTER)).await;
    loop {
        match crate::update::available(&agent.paths, &schedule.channel).await {
            Ok(found) => agent.set_update(found),
            Err(error) => warn!("update check failed: {error:#}"),
        }
        tokio::time::sleep(delay(schedule.every, EVERY_JITTER)).await;
    }
}

impl Agent {
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
        let release = schedule(Some("dev"), None, None).unwrap();
        assert_eq!(release.channel, "dev");
        assert_eq!((release.first, release.every), (FIRST, EVERY));
        assert!(release.jitter);
        assert_eq!(schedule(None, None, None), None);
        for off in ["1", "yes", "true"] {
            assert_eq!(schedule(Some("dev"), Some(off), None), None);
            assert_eq!(schedule(None, Some(off), Some("dev")), None);
        }
        for on in ["", "0"] {
            assert!(schedule(Some("stable"), Some(on), None).is_some());
        }
        let test = schedule(None, None, Some("beta")).unwrap();
        assert_eq!(test.channel, "beta");
        assert_eq!(test.first, Duration::ZERO);
        assert!(!test.jitter);
        assert_eq!(
            schedule(Some("dev"), None, Some("")).unwrap().channel,
            "dev"
        );
    }

    #[test]
    fn jitter_stays_within_its_spread() {
        for random in [0, 1, 59_999, 60_000, u64::MAX] {
            let delay = jittered(FIRST, FIRST_JITTER, random);
            assert!(delay >= FIRST && delay < FIRST + FIRST_JITTER, "{delay:?}");
        }
        assert_eq!(jittered(EVERY, Duration::ZERO, 7), EVERY);
    }
}
