//! Sleep and screen-lock events, for `lock_on_sleep`. Two sources feed one
//! channel, neither with unsafe code:
//!
//! - Every platform: the wall clock running ahead of the monotonic clock,
//!   which stops while the computer sleeps. Seen on wake, so it backs up the
//!   sources below and is all Linux has for now.
//! - macOS: an `osascript` helper that observes NSWorkspace's will-sleep
//!   notification and the `com.apple.screenIsLocked` distributed notification
//!   on its own run loop. The daemon's main thread runs Tokio, not a run loop,
//!   and objc2's observer APIs are all `unsafe`.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemEvent {
    /// The computer is about to sleep.
    #[cfg_attr(
        not(any(target_os = "macos", test)),
        expect(dead_code, reason = "only the macOS observer reports it")
    )]
    Sleep,
    /// The computer slept, seen on wake.
    Slept,
    #[cfg_attr(
        not(any(target_os = "macos", test)),
        expect(dead_code, reason = "only the macOS observer reports it")
    )]
    ScreenLocked,
}

/// How often the clocks are compared.
const CLOCK_TICK: Duration = Duration::from_secs(2);
/// Wall-clock time that passed beyond monotonic time to count as sleep, well
/// above clock corrections.
const SLEEP_GAP: Duration = Duration::from_secs(10);

/// Starts every source this platform has, sending into `events`. Dropping
/// the set stops them.
pub fn spawn(events: mpsc::Sender<SystemEvent>) -> JoinSet<()> {
    let mut sources = JoinSet::new();
    #[cfg(target_os = "macos")]
    sources.spawn(macos::run(events.clone()));
    sources.spawn(clock(events));
    sources
}

/// Whether the computer slept between two clock readings.
fn slept(wall: Duration, monotonic: Duration) -> bool {
    wall > monotonic + SLEEP_GAP
}

async fn clock(events: mpsc::Sender<SystemEvent>) {
    let mut tick = tokio::time::interval(CLOCK_TICK);
    let mut last = (crate::config::wall_clock(), std::time::Instant::now());
    loop {
        tick.tick().await;
        let now = (crate::config::wall_clock(), std::time::Instant::now());
        let wall = now.0.saturating_sub(last.0);
        let monotonic = now.1.saturating_duration_since(last.1);
        last = now;
        if slept(wall, monotonic) && events.send(SystemEvent::Slept).await.is_err() {
            return;
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::process::Stdio;
    use std::time::Duration;

    use anyhow::{Context, Result, bail};
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::sync::mpsc;
    use tracing::{info, warn};

    use super::SystemEvent;

    const SCREEN_LOCKED: &str = "com.apple.screenIsLocked";
    const RETRY: Duration = Duration::from_secs(5);
    const RETRY_MAX: Duration = Duration::from_secs(300);
    /// Prints `sleep` or `lock` per notification, and exits once its parent
    /// (the daemon) is gone.
    const HELPER: &str = r#"
ObjC.import('AppKit');
ObjC.import('stdlib');
ObjC.import('unistd');
function run(argv) {
  var out = $.NSFileHandle.fileHandleWithStandardOutput;
  var parent = $.getppid();
  function say(line) {
    out.writeData($(line + '\n').dataUsingEncoding($.NSUTF8StringEncoding));
  }
  ObjC.registerSubclass({
    name: 'DeadboltObserver',
    methods: {
      'sleep:': { types: ['void', ['id']], implementation: function () { say('sleep'); } },
      'lock:': { types: ['void', ['id']], implementation: function () { say('lock'); } },
      'tick:': {
        types: ['void', ['id']],
        implementation: function () { if ($.getppid() != parent) { $.exit(0); } },
      },
    },
  });
  var observer = $.DeadboltObserver.alloc.init;
  $.NSWorkspace.sharedWorkspace.notificationCenter.addObserverSelectorNameObject(
    observer, 'sleep:', $.NSWorkspaceWillSleepNotification, $());
  $.NSDistributedNotificationCenter.defaultCenter.addObserverSelectorNameObject(
    observer, 'lock:', argv[0], $());
  $.NSTimer.scheduledTimerWithTimeIntervalTargetSelectorUserInfoRepeats(5, observer, 'tick:', $(), true);
  say('ready');
  $.NSRunLoop.currentRunLoop.run;
}
"#;

    pub async fn run(events: mpsc::Sender<SystemEvent>) {
        let mut retry = RETRY;
        loop {
            match helper(&events, &mut retry).await {
                Ok(()) => return,
                Err(error) => warn!("sleep and screen-lock watcher stopped: {error:#}"),
            }
            tokio::time::sleep(retry).await;
            retry = (retry * 2).min(RETRY_MAX);
        }
    }

    /// Runs the helper until it exits (an error) or `events` closes.
    async fn helper(events: &mpsc::Sender<SystemEvent>, retry: &mut Duration) -> Result<()> {
        let mut child = tokio::process::Command::new("/usr/bin/osascript")
            .args(["-l", "JavaScript", "-e", HELPER, SCREEN_LOCKED])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("starting osascript")?;
        let stdout = child.stdout.take().context("no helper output")?;
        let mut lines = BufReader::new(stdout).lines();
        while let Some(line) = lines.next_line().await? {
            let event = match line.as_str() {
                "ready" => {
                    info!("watching for sleep and screen lock");
                    *retry = RETRY;
                    continue;
                }
                "sleep" => SystemEvent::Sleep,
                "lock" => SystemEvent::ScreenLocked,
                _ => continue,
            };
            if events.send(event).await.is_err() {
                return Ok(());
            }
        }
        bail!("osascript exited ({})", child.wait().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_clear_jump_of_the_wall_clock_counts_as_sleep() {
        let s = Duration::from_secs;
        assert!(!slept(s(2), s(2)));
        assert!(!slept(s(11), s(2)), "a clock correction is not sleep");
        assert!(slept(s(600), s(2)));
        assert!(
            !slept(s(0), s(2)),
            "the wall clock moving back is not sleep"
        );
    }
}
