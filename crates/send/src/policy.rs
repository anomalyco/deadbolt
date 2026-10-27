//! When a share may be opened. Times are Unix seconds from the caller's clock.

/// How many times, and until when, a share may be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// At least 1.
    pub opens: u32,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Open,
    /// Opened as many times as allowed.
    PickedUp,
    Expired,
    Revoked,
}

impl State {
    /// `open`, `picked-up`, `expired` or `revoked`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::PickedUp => "picked-up",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

/// Why an open was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Expired,
    /// Every open was used, or is being used right now.
    Used,
    Revoked,
}

/// A share's opens. An open is reserved when a receiver proves the secret
/// ([`Share::begin`]) and counted once the whole bundle went out
/// ([`Share::finish`] with `delivered`): the first receivers win, and one that
/// fails before then gives its open back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub policy: Policy,
    /// When each counted open happened.
    pub opened: Vec<u64>,
    pub in_flight: u32,
    pub revoked_at: Option<u64>,
}

impl Share {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: Policy {
                opens: policy.opens.max(1),
                ..policy
            },
            opened: Vec::new(),
            in_flight: 0,
            revoked_at: None,
        }
    }

    fn used(&self) -> u32 {
        self.opened.len() as u32
    }

    pub fn state(&self, now: u64) -> State {
        if self.revoked_at.is_some() {
            State::Revoked
        } else if self.used() >= self.policy.opens {
            State::PickedUp
        } else if now >= self.policy.expires_at {
            State::Expired
        } else {
            State::Open
        }
    }

    /// Whether the share can never be opened again.
    pub fn is_done(&self, now: u64) -> bool {
        self.state(now) != State::Open
    }

    /// Reserves an open.
    pub fn begin(&mut self, now: u64) -> Result<(), Refusal> {
        match self.state(now) {
            State::Revoked => Err(Refusal::Revoked),
            State::PickedUp => Err(Refusal::Used),
            State::Expired => Err(Refusal::Expired),
            State::Open if self.used() + self.in_flight >= self.policy.opens => Err(Refusal::Used),
            State::Open => {
                self.in_flight += 1;
                Ok(())
            }
        }
    }

    /// Ends a reserved open: counts it if the bundle was `delivered`, else gives
    /// it back.
    pub fn finish(&mut self, now: u64, delivered: bool) {
        self.in_flight = self.in_flight.saturating_sub(1);
        if delivered {
            self.opened.push(now);
        }
    }

    /// No further opens. One under way may still complete.
    pub fn revoke(&mut self, now: u64) {
        if self.revoked_at.is_none() && !self.is_done(now) {
            self.revoked_at = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(opens: u32) -> Share {
        Share::new(Policy {
            opens,
            expires_at: 100,
        })
    }

    #[test]
    fn single_use_by_default_and_first_opener_wins() {
        let mut s = share(1);
        assert_eq!(s.state(0), State::Open);
        s.begin(1).unwrap();
        // A second receiver while the first downloads is refused.
        assert_eq!(s.begin(2), Err(Refusal::Used));
        s.finish(3, true);
        assert_eq!(s.state(3), State::PickedUp);
        assert_eq!(s.opened, [3]);
        assert_eq!(s.begin(4), Err(Refusal::Used));
        // Picked up stays picked up past expiry.
        assert_eq!(s.state(1000), State::PickedUp);
    }

    #[test]
    fn a_failed_download_gives_its_open_back() {
        let mut s = share(1);
        s.begin(1).unwrap();
        s.finish(2, false);
        assert_eq!(s.state(2), State::Open);
        s.begin(3).unwrap();
        s.finish(4, true);
        assert_eq!(s.state(4), State::PickedUp);
    }

    #[test]
    fn several_opens() {
        let mut s = share(3);
        for t in 0..3 {
            s.begin(t).unwrap();
            s.finish(t, true);
        }
        assert_eq!(s.state(5), State::PickedUp);
        assert_eq!(s.begin(5), Err(Refusal::Used));
        assert_eq!(
            Share::new(Policy {
                opens: 0,
                expires_at: 9
            })
            .policy
            .opens,
            1
        );
    }

    #[test]
    fn expiry() {
        let mut s = share(2);
        s.begin(10).unwrap();
        s.finish(10, true);
        assert_eq!(s.state(99), State::Open);
        assert_eq!(s.state(100), State::Expired);
        assert_eq!(s.begin(100), Err(Refusal::Expired));
    }

    #[test]
    fn revoke() {
        let mut s = share(1);
        s.revoke(5);
        assert_eq!(s.state(5), State::Revoked);
        assert_eq!(s.begin(6), Err(Refusal::Revoked));
        // Revoking a finished share changes nothing.
        let mut done = share(1);
        done.begin(1).unwrap();
        done.finish(1, true);
        done.revoke(2);
        assert_eq!(done.state(2), State::PickedUp);
        assert_eq!(done.revoked_at, None);
        let mut expired = share(1);
        expired.revoke(200);
        assert_eq!(expired.state(200), State::Expired);
    }
}
