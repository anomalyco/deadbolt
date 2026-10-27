//! Generated passwords: uniformly random characters from the OS random
//! number generator, with at least one of every class used.

use std::ops::RangeInclusive;

use zeroize::Zeroizing;

/// The lengths [`generate`] accepts.
pub const LENGTHS: RangeInclusive<usize> = 8..=256;
/// The length clients offer first.
pub const DEFAULT_LENGTH: usize = 24;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
/// The symbols a password with symbols draws from.
pub const SYMBOLS: &[u8] = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a generated password must be {} to {} characters", LENGTHS.start(), LENGTHS.end())]
pub struct LengthError;

/// A password of `length` lower- and uppercase letters and digits, and
/// symbols if `symbols`, with at least one of each.
pub fn generate(length: usize, symbols: bool) -> Result<Zeroizing<String>, LengthError> {
    if !LENGTHS.contains(&length) {
        return Err(LengthError);
    }
    let classes: &[&[u8]] = if symbols {
        &[LOWER, UPPER, DIGITS, SYMBOLS]
    } else {
        &[LOWER, UPPER, DIGITS]
    };
    let alphabet = Zeroizing::new(classes.concat());
    loop {
        let password: Zeroizing<String> = Zeroizing::new(
            (0..length)
                .map(|_| alphabet[random_index(alphabet.len())] as char)
                .collect(),
        );
        if classes
            .iter()
            .all(|class| password.bytes().any(|b| class.contains(&b)))
        {
            return Ok(password);
        }
    }
}

#[expect(
    clippy::expect_used,
    reason = "OS CSPRNG failure is unrecoverable; never substitute weak randomness"
)]
pub(crate) fn random_index(n: usize) -> usize {
    // Rejection sampling keeps every index equally likely.
    let limit = 256 - 256 % n;
    loop {
        let mut byte = [0u8; 1];
        getrandom::fill(&mut byte).expect("OS random number generator failed");
        if (byte[0] as usize) < limit {
            return byte[0] as usize % n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_passwords() {
        let password = generate(24, true).unwrap();
        assert_eq!(password.len(), 24);
        assert!(password.bytes().any(|b| SYMBOLS.contains(&b)));
        assert!(password.bytes().any(|b| b.is_ascii_digit()));
        assert!(password.bytes().any(|b| b.is_ascii_alphabetic()));
        let plain = generate(40, false).unwrap();
        assert!(plain.bytes().all(|b| b.is_ascii_alphanumeric()));
        assert_ne!(*generate(24, true).unwrap(), *password);
    }

    #[test]
    fn every_class_shows_up_even_in_short_passwords() {
        for symbols in [true, false] {
            for _ in 0..200 {
                let password = generate(8, symbols).unwrap();
                assert!(password.bytes().any(|b| b.is_ascii_lowercase()));
                assert!(password.bytes().any(|b| b.is_ascii_uppercase()));
                assert!(password.bytes().any(|b| b.is_ascii_digit()));
                assert_eq!(symbols, password.bytes().any(|b| SYMBOLS.contains(&b)));
            }
        }
    }

    #[test]
    fn lengths() {
        assert_eq!(generate(7, true), Err(LengthError));
        assert_eq!(generate(257, false), Err(LengthError));
        assert_eq!(generate(8, true).unwrap().len(), 8);
        assert_eq!(generate(256, false).unwrap().len(), 256);
        assert_eq!(
            LengthError.to_string(),
            "a generated password must be 8 to 256 characters"
        );
    }
}
