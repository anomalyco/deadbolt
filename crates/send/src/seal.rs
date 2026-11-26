//! Chunked XChaCha20-Poly1305 (a STREAM construction) behind a cleartext
//! [`PolicyHeader`], so the sealed bundle can't be truncated, reordered or
//! extended, and its header can't be changed.
//!
//! ```text
//! sealed = header(10) || prefix(15) || chunk*    chunk = ciphertext(<= CHUNK_LEN) || tag(16)
//! nonce  = prefix(15) || last(1) || index(8, big-endian)
//! aad    = header for chunk 0, empty for every later chunk
//! key    = BLAKE3 derive_key("deadbolt send 2026-11 bundle", content key)
//! ```
//!
//! Every chunk but the last holds exactly [`CHUNK_LEN`] bytes of plaintext, so the
//! sealed length alone says where the chunks end; the last one (possibly empty) is
//! sealed with `last = 1`. Chunk 0 authenticates the header, and every later
//! chunk's nonce carries the same random prefix, so no chunk opens under a
//! different header or alongside another seal's chunks.

use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::{HEADER_LEN, PolicyHeader};

/// Plaintext bytes per chunk.
pub const CHUNK_LEN: usize = 64 * 1024;
/// The largest sealed bundle a sender serves or a receiver accepts.
pub const MAX_SEALED_LEN: usize = 32 * 1024 * 1024;
/// Bytes sealing adds besides one tag per chunk: the header and the prefix.
pub const SEAL_OVERHEAD: usize = HEADER_LEN + PREFIX_LEN;

pub(crate) const PREFIX_LEN: usize = 15;
pub(crate) const TAG_LEN: usize = 16;
const KEY_CONTEXT: &str = "deadbolt send 2026-11 bundle";

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

/// Seals `plaintext` under the content key `key`, behind `header`.
/// Refuses a plaintext whose bundle would be over [`MAX_SEALED_LEN`], which
/// no receiver would accept.
pub fn seal(key: &[u8; 32], header: &PolicyHeader, plaintext: &[u8]) -> Result<Vec<u8>> {
    let chunks = plaintext.len().div_ceil(CHUNK_LEN).max(1);
    let len = sealed_len(plaintext.len(), chunks);
    if len.is_none_or(|len| len > MAX_SEALED_LEN) {
        return Err(Error::TooLarge {
            len: len.unwrap_or(usize::MAX),
            max: MAX_SEALED_LEN,
        });
    }
    let cipher = cipher(key);
    let head = header.encode();
    let mut prefix = [0u8; PREFIX_LEN];
    getrandom::fill(&mut prefix).map_err(|e| Error::Rng(e.to_string()))?;
    let mut out = Vec::with_capacity(len.unwrap_or_default());
    out.extend_from_slice(&head);
    out.extend_from_slice(&prefix);
    for index in 0..chunks {
        let start = index * CHUNK_LEN;
        let end = (start + CHUNK_LEN).min(plaintext.len());
        let at = out.len();
        out.extend_from_slice(&plaintext[start..end]);
        let nonce = nonce(&prefix, index + 1 == chunks, index as u64);
        let aad: &[u8] = if index == 0 { &head } else { &[] };
        let tag = cipher
            .encrypt_inout_detached(&nonce.into(), aad, out[at..].as_mut().into())
            .map_err(|_| Error::Corrupt("chunk too long to encrypt".into()))?;
        out.extend_from_slice(&tag);
    }
    Ok(out)
}

/// The sealed length of `plaintext_len` bytes in `chunks` chunks, `None`
/// past `usize`.
fn sealed_len(plaintext_len: usize, chunks: usize) -> Option<usize> {
    chunks
        .checked_mul(TAG_LEN)?
        .checked_add(plaintext_len)?
        .checked_add(SEAL_OVERHEAD)
}

/// Opens what [`seal`] sealed, returning its authenticated header. Fails on
/// any change (the header's included), truncation or extension. Checking the
/// header's expiry is the caller's.
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<(PolicyHeader, Zeroizing<Vec<u8>>)> {
    if sealed.len() > MAX_SEALED_LEN {
        return Err(Error::TooLarge {
            len: sealed.len(),
            max: MAX_SEALED_LEN,
        });
    }
    if sealed.len() < SEAL_OVERHEAD + TAG_LEN {
        return Err(Error::Corrupt("too short".into()));
    }
    let (head, body) = sealed.split_at(HEADER_LEN);
    let header = PolicyHeader::decode(head)?;
    Ok((header, open_body(key, head, body)?))
}

/// Opens `prefix || chunk*` with chunk 0 bound to `head`.
fn open_body(key: &[u8; 32], head: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    open_chunks(&cipher(key), head, sealed)
}

/// Opens `prefix || chunk*` under `cipher`, with chunk 0 bound to `aad0`.
pub(crate) fn open_chunks(
    cipher: &XChaCha20Poly1305,
    aad0: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let corrupt = |what: &str| Error::Corrupt(what.into());
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
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() - chunks * TAG_LEN));
    for (index, chunk) in body.chunks(full).enumerate() {
        let (ciphertext, tag) = chunk.split_at(chunk.len() - TAG_LEN);
        let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| corrupt("bad tag"))?;
        let at = out.len();
        out.extend_from_slice(ciphertext);
        let nonce = nonce(prefix, index + 1 == chunks, index as u64);
        let aad: &[u8] = if index == 0 { aad0 } else { &[] };
        cipher
            .decrypt_inout_detached(&nonce.into(), aad, out[at..].as_mut().into(), &tag.into())
            .map_err(|_| corrupt("authentication failed"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [3; 32];
    const HEADER: PolicyHeader = PolicyHeader {
        expires_unix: 1_800_000_000,
        multi_open: false,
    };

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
            let sealed = seal(&KEY, &HEADER, &plaintext).unwrap();
            assert_eq!(
                sealed.len(),
                SEAL_OVERHEAD + len + len.div_ceil(CHUNK_LEN).max(1) * TAG_LEN
            );
            let (header, opened) = open(&KEY, &sealed).unwrap();
            assert_eq!(header, HEADER);
            assert_eq!(*opened, plaintext, "len {len}");
        }
    }

    #[test]
    fn a_bundle_over_the_limit_is_never_sealed() {
        // The largest plaintext whose bundle fits, and one byte more.
        let fits = |len: usize| sealed_len(len, len.div_ceil(CHUNK_LEN).max(1)).unwrap();
        let mut largest = MAX_SEALED_LEN - SEAL_OVERHEAD;
        while fits(largest) > MAX_SEALED_LEN {
            largest -= 1;
        }
        let sealed = seal(&KEY, &HEADER, &vec![0u8; largest]).unwrap();
        assert_eq!(sealed.len(), fits(largest));
        assert!(open(&KEY, &sealed).is_ok());
        let err = seal(&KEY, &HEADER, &vec![0u8; largest + 1]).unwrap_err();
        assert!(
            matches!(err, Error::TooLarge { len, max } if len > max && max == MAX_SEALED_LEN),
            "{err}"
        );
        assert_eq!(sealed_len(usize::MAX, usize::MAX / CHUNK_LEN + 1), None);
    }

    #[test]
    fn seals_are_randomized() {
        assert_ne!(
            seal(&KEY, &HEADER, b"same").unwrap(),
            seal(&KEY, &HEADER, b"same").unwrap()
        );
    }

    #[test]
    fn tampering_fails() {
        let plaintext = vec![7u8; 2 * CHUNK_LEN + 5];
        let sealed = seal(&KEY, &HEADER, &plaintext).unwrap();
        assert!(open(&[4; 32], &sealed).is_err(), "wrong key");
        let mut flipped = sealed.clone();
        flipped[SEAL_OVERHEAD + 10] ^= 1;
        assert!(open(&KEY, &flipped).is_err(), "flipped bit");
        // Dropping the last chunk leaves a full chunk not sealed as the last.
        let truncated = &sealed[..SEAL_OVERHEAD + 2 * (CHUNK_LEN + TAG_LEN)];
        assert!(open(&KEY, truncated).is_err(), "truncated");
        assert!(open(&KEY, &sealed[..sealed.len() - 1]).is_err());
        let mut extended = sealed.clone();
        extended.extend_from_slice(&[0; TAG_LEN]);
        assert!(open(&KEY, &extended).is_err(), "extended");
        assert!(open(&KEY, &sealed[..SEAL_OVERHEAD]).is_err(), "no chunk");
    }

    /// Rewrites the header in place with a well-formed but different one.
    fn with_header(sealed: &[u8], header: PolicyHeader) -> Vec<u8> {
        let mut out = sealed.to_vec();
        out[..HEADER_LEN].copy_from_slice(&header.encode());
        out
    }

    #[test]
    fn every_header_field_is_bound_to_chunk_zero() {
        for len in [0, 5, CHUNK_LEN + 5] {
            let sealed = seal(&KEY, &HEADER, &vec![1u8; len]).unwrap();
            let later = PolicyHeader {
                expires_unix: HEADER.expires_unix + 1,
                ..HEADER
            };
            let multi = PolicyHeader {
                multi_open: true,
                ..HEADER
            };
            for (what, header) in [("expiry", later), ("multi-open", multi)] {
                let err = open(&KEY, &with_header(&sealed, header)).unwrap_err();
                assert!(
                    matches!(&err, Error::Corrupt(m) if m == "authentication failed"),
                    "{what}, len {len}: {err}"
                );
            }
            // An unknown version is refused when parsed, and the AEAD would
            // refuse it too: the whole header is chunk 0's associated data.
            let mut versioned = sealed.clone();
            versioned[0] = 2;
            assert!(open(&KEY, &versioned).is_err(), "version, len {len}");
            let mut head = HEADER.encode();
            head[0] = 2;
            assert!(
                open_body(&KEY, &head, &sealed[HEADER_LEN..]).is_err(),
                "version under the AEAD, len {len}"
            );
            assert!(open_body(&KEY, &HEADER.encode(), &sealed[HEADER_LEN..]).is_ok());
        }
    }

    #[test]
    fn chunks_do_not_move_between_seals() {
        // Same key, two seals: a later chunk of one never opens in the other.
        let a = seal(&KEY, &HEADER, &vec![1u8; 2 * CHUNK_LEN]).unwrap();
        let b = seal(&KEY, &HEADER, &vec![1u8; 2 * CHUNK_LEN]).unwrap();
        let split = SEAL_OVERHEAD + CHUNK_LEN + TAG_LEN;
        let mut spliced = a[..split].to_vec();
        spliced.extend_from_slice(&b[split..]);
        assert!(open(&KEY, &spliced).is_err());
    }
}
