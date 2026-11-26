//! Where core's randomness comes from: the OS, unless a simulation has
//! seeded this thread ([`deterministic`], behind the `sim` feature).

/// Fills `out` from the OS's CSPRNG, or from this thread's seeded stream.
pub(crate) fn fill(out: &mut [u8]) -> Result<(), getrandom::Error> {
    #[cfg(feature = "sim")]
    if sim::fill(out) {
        return Ok(());
    }
    getrandom::fill(out)
}

#[cfg(feature = "sim")]
mod sim {
    use std::cell::RefCell;

    thread_local! {
        static STREAM: RefCell<Option<blake3::OutputReader>> = const { RefCell::new(None) };
    }

    pub(super) fn fill(out: &mut [u8]) -> bool {
        STREAM.with(|s| match s.borrow_mut().as_mut() {
            Some(stream) => {
                stream.fill(out);
                true
            }
            None => false,
        })
    }

    pub(super) fn seed(seed: Option<u64>) {
        let stream = seed.map(|seed| {
            let mut hasher = blake3::Hasher::new_derive_key("deadbolt 2026-11-25 sim rng");
            hasher.update(&seed.to_be_bytes());
            hasher.finalize_xof()
        });
        STREAM.with(|s| *s.borrow_mut() = stream);
    }
}

/// Makes every random draw core makes on this thread come from a stream
/// seeded with `seed`, or from the OS again with `None`. For the
/// deterministic simulator only: a seeded thread's keys are predictable.
#[cfg(feature = "sim")]
pub fn deterministic(seed: Option<u64>) {
    sim::seed(seed);
}
