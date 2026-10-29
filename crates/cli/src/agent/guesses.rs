//! Passphrase guesses: one backoff for every passphrase the agent checks
//! (unlock, unlock while unlocked, and the proof for pairing agent clients
//! and granting), so no request is a faster way to guess it than another.
//! One check runs at a time; after [`FREE_FAILURES`] wrong ones each check
//! waits [`FIRST_WAIT`], doubling up to [`LONGEST_WAIT`], and a right one
//! resets it. Either refusal is `rate-limited`.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;

use super::{ErrorCode, fail};

/// Wrong passphrases allowed before checks wait.
pub const FREE_FAILURES: u32 = 5;
pub const FIRST_WAIT: Duration = Duration::from_secs(30);
pub const LONGEST_WAIT: Duration = Duration::from_secs(10 * 60);

#[derive(Default)]
pub struct Backoff {
    failures: u32,
    until: Option<Instant>,
}

impl Backoff {
    /// How long until a passphrase may be checked again, if it must wait.
    pub fn wait(&self, now: Instant) -> Option<Duration> {
        self.until
            .and_then(|until| until.checked_duration_since(now))
            .filter(|d| !d.is_zero())
    }

    pub fn failed(&mut self, now: Instant) {
        self.failures += 1;
        if let Some(over) = self.failures.checked_sub(FREE_FAILURES) {
            let wait = FIRST_WAIT
                .saturating_mul(1u32 << over.min(10))
                .min(LONGEST_WAIT);
            self.until = Some(now + wait);
        }
    }

    pub fn succeeded(&mut self) {
        *self = Backoff::default();
    }
}

/// The agent's passphrase checks: the backoff and the one check running.
pub struct Guesses {
    backoff: Mutex<Backoff>,
    checking: tokio::sync::Mutex<()>,
}

impl Default for Guesses {
    fn default() -> Self {
        Guesses {
            backoff: Mutex::default(),
            checking: tokio::sync::Mutex::new(()),
        }
    }
}

/// The right to check one passphrase; say how it went with [`Turn::settle`].
pub struct Turn<'a> {
    guesses: &'a Guesses,
    _checking: tokio::sync::MutexGuard<'a, ()>,
}

impl Guesses {
    /// A turn to check a passphrase now, else `rate-limited`: another check
    /// is running, or wrong ones are being backed off.
    pub fn turn(&self) -> Result<Turn<'_>> {
        let Ok(checking) = self.checking.try_lock() else {
            return Err(fail(
                ErrorCode::RateLimited,
                "Another passphrase is being checked. Try again in a moment.",
            ));
        };
        let wait = self
            .backoff
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .wait(Instant::now());
        if let Some(wait) = wait {
            return Err(fail(
                ErrorCode::RateLimited,
                format!(
                    "Too many wrong passphrases. Try again in {} s.",
                    wait.as_secs() + u64::from(wait.subsec_nanos() > 0)
                ),
            ));
        }
        Ok(Turn {
            guesses: self,
            _checking: checking,
        })
    }
}

impl Turn<'_> {
    /// Records whether the passphrase was right.
    pub fn settle(self, right: bool) {
        let mut backoff = self
            .guesses
            .backoff
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if right {
            backoff.succeeded();
        } else {
            backoff.failed(Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::code;

    #[test]
    fn wrong_passphrases_wait_doubling_and_a_right_one_resets() {
        let start = Instant::now();
        let mut backoff = Backoff::default();
        for _ in 0..FREE_FAILURES - 1 {
            backoff.failed(start);
        }
        assert_eq!(backoff.wait(start), None);
        backoff.failed(start);
        assert_eq!(backoff.wait(start), Some(FIRST_WAIT));
        backoff.failed(start);
        assert_eq!(backoff.wait(start), Some(FIRST_WAIT * 2));
        for _ in 0..20 {
            backoff.failed(start);
        }
        assert_eq!(backoff.wait(start), Some(LONGEST_WAIT));
        assert_eq!(backoff.wait(start + LONGEST_WAIT), None);
        backoff.succeeded();
        assert_eq!(backoff.wait(start), None);
    }

    #[test]
    fn one_check_at_a_time_and_none_while_backing_off() {
        let guesses = Guesses::default();
        let turn = guesses.turn().unwrap();
        let busy = guesses.turn().err().unwrap();
        assert_eq!(code(&busy), Some(ErrorCode::RateLimited));
        turn.settle(false);
        for _ in 1..FREE_FAILURES {
            guesses.turn().unwrap().settle(false);
        }
        let waiting = guesses.turn().err().unwrap();
        assert_eq!(code(&waiting), Some(ErrorCode::RateLimited));
        assert!(
            waiting
                .to_string()
                .starts_with("Too many wrong passphrases. Try again in 30 s"),
            "{waiting}"
        );
    }
}
