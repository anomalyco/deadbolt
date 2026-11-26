//! The recovery kit: a vault's recovery secret as 24 BIP-39 English words.
//!
//! 32 bytes of entropy and the first byte of their SHA-256 make 264 bits,
//! read as 24 indexes of 11 bits into the BIP-39 English list (SHA-256 of
//! `recovery/english.txt`:
//! `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`).
//! The words are the entropy itself, not a BIP-39 seed: no PBKDF2 and no
//! passphrase, so the kit decodes back to exactly the [`RecoverySecret`].

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::v2::RecoverySecret;

/// Words in a kit.
pub const WORDS: usize = 24;

const LIST: &str = include_str!("recovery/english.txt");

fn wordlist() -> impl Iterator<Item = &'static str> {
    LIST.lines()
}

/// Why words don't make a recovery kit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KitError {
    #[error("a recovery kit has {WORDS} words, got {0}")]
    Length(usize),
    #[error("word {position} ({word:?}) is not a recovery kit word")]
    UnknownWord { position: usize, word: String },
    #[error("the words don't check out: a word is wrong or out of order")]
    Checksum,
}

/// The 24 words for `secret`, space-separated.
pub fn encode(secret: &RecoverySecret) -> Zeroizing<String> {
    let entropy = secret.as_bytes();
    let check = Sha256::digest(entropy)[0];
    let mut bits = Zeroizing::new([0u8; 33]);
    bits[..32].copy_from_slice(entropy);
    bits[32] = check;
    let words: Vec<&str> = wordlist().collect();
    let mut out = Zeroizing::new(String::with_capacity(WORDS * 9));
    for i in 0..WORDS {
        let index = (0..11).fold(0usize, |acc, b| {
            let bit = i * 11 + b;
            (acc << 1) | usize::from(bits[bit / 8] >> (7 - bit % 8) & 1)
        });
        if i > 0 {
            out.push(' ');
        }
        out.push_str(words[index]);
    }
    out
}

/// The recovery secret behind `phrase`: 24 words separated by any
/// whitespace, case-insensitive. The first four letters of a word are
/// enough, as BIP-39 guarantees they are unique.
pub fn decode(phrase: &str) -> Result<RecoverySecret, KitError> {
    let given: Vec<String> = phrase
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect();
    if given.len() != WORDS {
        return Err(KitError::Length(given.len()));
    }
    let mut bits = Zeroizing::new([0u8; 33]);
    for (i, word) in given.iter().enumerate() {
        let index = wordlist()
            .position(|w| w == word || (word.len() == 4 && w.starts_with(word.as_str())))
            .ok_or_else(|| KitError::UnknownWord {
                position: i + 1,
                word: word.clone(),
            })?;
        for b in 0..11 {
            if index >> (10 - b) & 1 == 1 {
                let bit = i * 11 + b;
                bits[bit / 8] |= 1 << (7 - bit % 8);
            }
        }
    }
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&bits[..32]);
    let secret = RecoverySecret::from_bytes(entropy);
    zeroize::Zeroize::zeroize(&mut entropy);
    if Sha256::digest(secret.as_bytes())[0] != bits[32] {
        return Err(KitError::Checksum);
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_bip39_english() {
        let words: Vec<_> = wordlist().collect();
        assert_eq!(words.len(), 2048);
        assert_eq!(words[0], "abandon");
        assert_eq!(words[2047], "zoo");
        let mut prefixes: Vec<_> = words.iter().map(|w| &w[..w.len().min(4)]).collect();
        prefixes.dedup();
        assert_eq!(prefixes.len(), 2048, "four-letter prefixes are unique");
    }

    #[test]
    fn known_vector() {
        // BIP-39 test vector: 32 zero bytes.
        let secret = RecoverySecret::from_bytes([0; 32]);
        let words = encode(&secret);
        assert_eq!(
            words.as_str(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        );
        let secret = RecoverySecret::from_bytes([0x7f; 32]);
        assert_eq!(
            encode(&secret).as_str(),
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
        );
    }

    #[test]
    fn round_trips_and_rejects_typos() {
        for seed in [[1u8; 32], [0xff; 32], [0x5a; 32]] {
            let secret = RecoverySecret::from_bytes(seed);
            let words = encode(&secret);
            assert_eq!(decode(&words).unwrap().as_bytes(), &seed);
            assert_eq!(decode(&words.to_uppercase()).unwrap().as_bytes(), &seed);
            let short: Vec<String> = words
                .split(' ')
                .map(|w| w[..w.len().min(4)].to_owned())
                .collect();
            assert_eq!(decode(&short.join("\n")).unwrap().as_bytes(), &seed);
            let mut swapped: Vec<&str> = words.split(' ').collect();
            swapped.swap(0, 1);
            if swapped[0] != swapped[1] {
                assert_eq!(decode(&swapped.join(" ")).unwrap_err(), KitError::Checksum);
            }
        }
        assert_eq!(decode("abandon").unwrap_err(), KitError::Length(1));
        assert!(matches!(
            decode(&["zzzz"; 24].join(" ")).unwrap_err(),
            KitError::UnknownWord { position: 1, .. }
        ));
    }
}
