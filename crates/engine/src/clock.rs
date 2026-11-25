//! Time, which the engine never reads itself: the host passes a [`Clock`].

use std::time::Duration;

/// The wall clock.
pub trait Clock: Send + Sync {
    /// Now, since the Unix epoch.
    fn now(&self) -> Duration;
}

/// A clock stopped at one instant, for tests and replays.
pub struct FixedClock(pub Duration);

impl Clock for FixedClock {
    fn now(&self) -> Duration {
        self.0
    }
}

/// `secs` (since the Unix epoch) as a UTC `YYYY-MM-DD` date.
pub fn utc_date(secs: u64) -> String {
    let z = (secs / 86_400) as i64 + 719_468;
    civil(z)
}

/// A 1Password date, Unix seconds, as `YYYY-MM-DD`: the nearest day, so a
/// day's local midnight from UTC+11 to UTC-12, or its noon UTC, lands on it
/// rather than the day before.
pub fn nearest_date(secs: i64) -> String {
    civil((secs + 43_199).div_euclid(86_400) + 719_468)
}

/// Howard Hinnant's days-to-civil, from days since 0000-03-01.
fn civil(z: i64) -> String {
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}
