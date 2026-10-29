//! Pairing codes: four words from the BIP-39 English list (`words.txt`, MIT,
//! github.com/bitcoin/bips), 11 bits each, so 44 bits drawn from the OS CSPRNG.

use std::{fmt, str::FromStr, sync::OnceLock};

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

/// Words in a code.
pub const CODE_WORDS: usize = 4;
const LIST: &str = include_str!("words.txt");
const LIST_LEN: usize = 2048;

/// Argon2id salt for the rendezvous key: fixed, so both devices derive the same key
/// from the code alone, and specific to this use.
const LOOKUP_SALT: &[u8] = b"deadbolt/pair/2 rendezvous";
/// 64 MiB, six passes: a fraction of a second on a laptop, and a memory-hard cost on
/// every guess at the code.
const LOOKUP_M_COST_KIB: u32 = 64 * 1024;
const LOOKUP_T_COST: u32 = 6;

fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| LIST.lines().map(str::trim).collect())
}

/// A one-time pairing code, such as `violin-garden-tiger-lamp`. Wiped on drop; `Debug`
/// leaves it out.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingCode(Zeroizing<[u16; CODE_WORDS]>);

impl PairingCode {
    /// A fresh code from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 2 * CODE_WORDS]);
        getrandom::fill(bytes.as_mut()).map_err(|e| Error::Io(std::io::Error::other(e)))?;
        let mut indices = Zeroizing::new([0u16; CODE_WORDS]);
        let (pairs, _) = bytes.as_chunks::<2>();
        for (index, pair) in indices.iter_mut().zip(pairs) {
            // 2048 divides 65536, so every word is equally likely.
            *index = u16::from_be_bytes(*pair) % LIST_LEN as u16;
        }
        Ok(Self(indices))
    }

    /// The code as typed: lowercase words joined by `-`. This is the PAKE password.
    pub fn text(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(40));
        for (i, index) in self.0.iter().enumerate() {
            if i > 0 {
                out.push('-');
            }
            out.push_str(words()[usize::from(*index)]);
        }
        out
    }

    /// The rendezvous key both devices derive from the code: Argon2id over the whole
    /// code, used as an Ed25519 seed. The new device publishes its address under its
    /// public half. Blocking; a fraction of a second.
    pub fn lookup_secret(&self) -> Result<Zeroizing<[u8; 32]>> {
        let params = Params::new(LOOKUP_M_COST_KIB, LOOKUP_T_COST, 1, Some(32))
            .map_err(|e| Error::InvalidCode(format!("argon2 parameters: {e}")))?;
        let mut seed = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(self.text().as_bytes(), LOOKUP_SALT, seed.as_mut())
            .map_err(|e| Error::InvalidCode(format!("argon2: {e}")))?;
        Ok(seed)
    }
}

impl fmt::Display for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingCode(<redacted>)")
    }
}

/// Case-insensitive; words may be separated by `-`, spaces or both, with any whitespace
/// around them.
impl FromStr for PairingCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut lowered = Zeroizing::new(s.to_lowercase());
        let mut indices = Zeroizing::new([0u16; CODE_WORDS]);
        let mut count = 0;
        for word in lowered
            .split(|c: char| c == '-' || c.is_whitespace())
            .filter(|w| !w.is_empty())
        {
            if count == CODE_WORDS {
                return Err(Error::InvalidCode(format!("a code has {CODE_WORDS} words")));
            }
            let index = words()
                .iter()
                .position(|w| *w == word)
                .ok_or_else(|| Error::InvalidCode(format!("{word:?} is not a code word")))?;
            indices[count] = index as u16;
            count += 1;
        }
        lowered.zeroize();
        if count != CODE_WORDS {
            return Err(Error::InvalidCode(format!(
                "a code has {CODE_WORDS} words, like violin-garden-tiger-lamp"
            )));
        }
        Ok(Self(indices))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_bip39_english() {
        let words = words();
        assert_eq!(words.len(), LIST_LEN);
        assert_eq!(words[0], "abandon");
        assert_eq!(words[LIST_LEN - 1], "zoo");
        let unique: std::collections::BTreeSet<_> = words.iter().collect();
        assert_eq!(unique.len(), LIST_LEN);
        assert!(
            words
                .iter()
                .all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()))
        );
    }

    #[test]
    fn codes_round_trip_and_parse_loosely() {
        let code = PairingCode::generate().unwrap();
        let text = code.to_string();
        assert_eq!(text.split('-').count(), CODE_WORDS);
        assert_eq!(text.parse::<PairingCode>().unwrap(), code);
        let parsed: PairingCode = "  Violin garden-TIGER\t-  lamp\n".parse().unwrap();
        assert_eq!(parsed.to_string(), "violin-garden-tiger-lamp");
        assert!(!format!("{parsed:?}").contains("violin"));
    }

    #[test]
    fn bad_codes_are_refused() {
        for bad in [
            "",
            "violin-garden-tiger",
            "violin-garden-tiger-lamp-zoo",
            "violin-garden-tiger-lamps",
            "DBPAIRABCDEF",
        ] {
            assert!(bad.parse::<PairingCode>().is_err(), "{bad}");
        }
    }

    #[test]
    fn generated_codes_differ() {
        let a = PairingCode::generate().unwrap();
        let b = PairingCode::generate().unwrap();
        // 2^-44 chance of a false failure.
        assert_ne!(a, b);
    }

    #[test]
    fn lookup_is_deterministic_and_depends_on_every_word() {
        let code: PairingCode = "violin-garden-tiger-lamp".parse().unwrap();
        let again: PairingCode = "VIOLIN GARDEN TIGER LAMP".parse().unwrap();
        let other: PairingCode = "violin-garden-tiger-lady".parse().unwrap();
        let started = std::time::Instant::now();
        let key = code.lookup_secret().unwrap();
        let elapsed = started.elapsed();
        assert_eq!(key, again.lookup_secret().unwrap());
        assert_ne!(key, other.lookup_secret().unwrap());
        // Generous: debug builds optimize argon2 (Cargo.toml), CI machines vary.
        assert!(elapsed < std::time::Duration::from_secs(5), "{elapsed:?}");
    }
}
