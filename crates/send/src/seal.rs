//! Chunked XChaCha20-Poly1305 (a STREAM construction), so the sealed bundle
//! can't be truncated, reordered or extended.
//!
//! ```text
//! sealed = prefix(15) || chunk*      chunk = ciphertext(<= CHUNK_LEN) || tag(16)
//! nonce  = prefix(15) || last(1) || index(8, big-endian)
//! key    = BLAKE3 derive_key("deadbolt send 2026-10 bundle", content key)
//! ```
//!
//! Every chunk but the last holds exactly [`CHUNK_LEN`] bytes of plaintext, so the
//! sealed length alone says where the chunks end; the last one (possibly empty) is
//! sealed with `last = 1`.

use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Plaintext bytes per chunk.
pub const CHUNK_LEN: usize = 64 * 1024;
/// The largest sealed bundle a sender serves or a receiver accepts.
pub const MAX_SEALED_LEN: usize = 32 * 1024 * 1024;

const PREFIX_LEN: usize = 15;
const TAG_LEN: usize = 16;
const KEY_CONTEXT: &str = "deadbolt send 2026-10 bundle";

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    let key = Zeroizing::new(blake3::derive_key(KEY_CONTEXT, key));
    XChaCha20Poly1305::new((&*key).into())
}

fn nonce(prefix: &[u8], last: bool, index: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..PREFIX_LEN].copy_from_slice(prefix);
    nonce[PREFIX_LEN] = u8::from(last);
    nonce[PREFIX_LEN + 1..].copy_from_slice(&index.to_be_bytes());
    nonce
}

/// Seals `plaintext` under the content key `key`.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = cipher(key);
    let mut prefix = [0u8; PREFIX_LEN];
    getrandom::fill(&mut prefix).map_err(|e| Error::Rng(e.to_string()))?;
    let chunks = plaintext.len().div_ceil(CHUNK_LEN).max(1);
    let mut out = Vec::with_capacity(PREFIX_LEN + plaintext.len() + chunks * TAG_LEN);
    out.extend_from_slice(&prefix);
    for index in 0..chunks {
        let start = index * CHUNK_LEN;
        let end = (start + CHUNK_LEN).min(plaintext.len());
        let at = out.len();
        out.extend_from_slice(&plaintext[start..end]);
        let nonce = nonce(&prefix, index + 1 == chunks, index as u64);
        let tag = cipher
            .encrypt_inout_detached(&nonce.into(), &[], out[at..].as_mut().into())
            .map_err(|_| Error::Corrupt("chunk too long to encrypt".into()))?;
        out.extend_from_slice(&tag);
    }
    Ok(out)
}

/// Opens what [`seal`] sealed. Fails on any change, truncation or extension.
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let corrupt = |what: &str| Error::Corrupt(what.into());
    if sealed.len() > MAX_SEALED_LEN {
        return Err(Error::TooLarge {
            len: sealed.len(),
            max: MAX_SEALED_LEN,
        });
    }
    if sealed.len() < PREFIX_LEN + TAG_LEN {
        return Err(corrupt("too short"));
    }
    let (prefix, body) = sealed.split_at(PREFIX_LEN);
    let full = CHUNK_LEN + TAG_LEN;
    let rest = body.len() % full;
    if rest != 0 && rest < TAG_LEN {
        return Err(corrupt("truncated chunk"));
    }
    let chunks = body.len().div_ceil(full);
    let cipher = cipher(key);
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() - chunks * TAG_LEN));
    for (index, chunk) in body.chunks(full).enumerate() {
        let (ciphertext, tag) = chunk.split_at(chunk.len() - TAG_LEN);
        let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| corrupt("bad tag"))?;
        let at = out.len();
        out.extend_from_slice(ciphertext);
        let nonce = nonce(prefix, index + 1 == chunks, index as u64);
        cipher
            .decrypt_inout_detached(&nonce.into(), &[], out[at..].as_mut().into(), &tag.into())
            .map_err(|_| corrupt("authentication failed"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [3; 32];

    #[test]
    fn round_trips_every_chunk_boundary() {
        for len in [
            0,
            1,
            CHUNK_LEN - 1,
            CHUNK_LEN,
            CHUNK_LEN + 1,
            3 * CHUNK_LEN,
            3 * CHUNK_LEN + 17,
        ] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let sealed = seal(&KEY, &plaintext).unwrap();
            assert_eq!(
                sealed.len(),
                PREFIX_LEN + len + len.div_ceil(CHUNK_LEN).max(1) * TAG_LEN
            );
            assert_eq!(*open(&KEY, &sealed).unwrap(), plaintext, "len {len}");
        }
    }

    #[test]
    fn seals_are_randomized() {
        assert_ne!(seal(&KEY, b"same").unwrap(), seal(&KEY, b"same").unwrap());
    }

    #[test]
    fn tampering_fails() {
        let plaintext = vec![7u8; 2 * CHUNK_LEN + 5];
        let sealed = seal(&KEY, &plaintext).unwrap();
        assert!(open(&[4; 32], &sealed).is_err(), "wrong key");
        let mut flipped = sealed.clone();
        flipped[PREFIX_LEN + 10] ^= 1;
        assert!(open(&KEY, &flipped).is_err(), "flipped bit");
        // Dropping the last chunk leaves a full chunk not sealed as the last.
        let truncated = &sealed[..PREFIX_LEN + 2 * (CHUNK_LEN + TAG_LEN)];
        assert!(open(&KEY, truncated).is_err(), "truncated");
        assert!(open(&KEY, &sealed[..sealed.len() - 1]).is_err());
        let mut extended = sealed.clone();
        extended.extend_from_slice(&[0; TAG_LEN]);
        assert!(open(&KEY, &extended).is_err(), "extended");
        assert!(open(&KEY, &sealed[..PREFIX_LEN]).is_err(), "no chunk");
    }
}
