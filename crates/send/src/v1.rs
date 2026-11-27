//! DELETABLE(v1-send): remove once existing v1 users have upgraded to v2.
//!
//! Opens, read-only, the bundles a sender from before the policy header
//! still serves: no header, chunk 0 sealed with empty associated data, and
//! the 2026-10 key context.
//!
//! ```text
//! sealed = prefix(15) || chunk*      chunk = ciphertext(<= CHUNK_LEN) || tag(16)
//! nonce  = prefix(15) || last(1) || index(8, big-endian)
//! key    = BLAKE3 derive_key("deadbolt send 2026-10 bundle", content key)
//! ```
//!
//! Nothing seals this format any more. A bundle that starts with a valid
//! [`PolicyHeader`] opens only as the current format, so a current bundle
//! never falls back here. A legacy bundle whose random prefix happens to
//! read as a header (about 1 in 32,768) is refused, never misread.
//!
//! To delete: remove this file, `mod v1` in `lib.rs`, and call
//! [`crate::open`] in `receive.rs` again.

use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::{HEADER_LEN, PolicyHeader};
use crate::seal::{MAX_SEALED_LEN, PREFIX_LEN, TAG_LEN, open_chunks};

const KEY_CONTEXT: &str = "deadbolt send 2026-10 bundle";

/// Opens a bundle a live sender served: the current format whenever it
/// starts with a policy header, the legacy one only when it doesn't. The
/// receiver doesn't check the header; the sender enforces it.
pub(crate) fn open_served(key: &[u8; 32], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if has_header(sealed) {
        return crate::seal::open(key, sealed).map(|(_, plaintext)| plaintext);
    }
    open(key, sealed)
}

/// Whether `sealed` starts with a header the current format accepts.
pub(crate) fn has_header(sealed: &[u8]) -> bool {
    sealed
        .get(..HEADER_LEN)
        .is_some_and(|head| PolicyHeader::decode(head).is_ok())
}

/// Opens a legacy bundle. Fails on any change, truncation or extension.
fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() > MAX_SEALED_LEN {
        return Err(Error::TooLarge {
            len: sealed.len(),
            max: MAX_SEALED_LEN,
        });
    }
    if sealed.len() < PREFIX_LEN + TAG_LEN {
        return Err(Error::Corrupt("too short".into()));
    }
    let key = Zeroizing::new(blake3::derive_key(KEY_CONTEXT, key));
    open_chunks(&XChaCha20Poly1305::new((&*key).into()), &[], sealed)
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::AeadInOut;

    use super::*;
    use crate::seal::{CHUNK_LEN, seal};

    const KEY: [u8; 32] = [3; 32];
    const HEADER: PolicyHeader = PolicyHeader {
        expires_unix: 1_800_000_000,
        multi_open: false,
    };

    /// The legacy sealer, as senders before the policy header had it, with
    /// the random prefix given.
    fn seal_legacy(key: &[u8; 32], prefix: [u8; PREFIX_LEN], plaintext: &[u8]) -> Vec<u8> {
        let key = Zeroizing::new(blake3::derive_key(KEY_CONTEXT, key));
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let chunks = plaintext.len().div_ceil(CHUNK_LEN).max(1);
        let mut out = prefix.to_vec();
        for index in 0..chunks {
            let start = index * CHUNK_LEN;
            let end = (start + CHUNK_LEN).min(plaintext.len());
            let at = out.len();
            out.extend_from_slice(&plaintext[start..end]);
            let mut nonce = [0u8; 24];
            nonce[..PREFIX_LEN].copy_from_slice(&prefix);
            nonce[PREFIX_LEN] = u8::from(index + 1 == chunks);
            nonce[PREFIX_LEN + 1..].copy_from_slice(&(index as u64).to_be_bytes());
            let tag = cipher
                .encrypt_inout_detached(&nonce.into(), &[], out[at..].as_mut().into())
                .unwrap();
            out.extend_from_slice(&tag);
        }
        out
    }

    #[test]
    fn legacy_bundles_open_at_every_chunk_boundary() {
        for len in [0, 1, CHUNK_LEN, CHUNK_LEN + 1, 2 * CHUNK_LEN + 17] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let sealed = seal_legacy(&KEY, [9; PREFIX_LEN], &plaintext);
            assert!(!has_header(&sealed));
            assert_eq!(*open_served(&KEY, &sealed).unwrap(), plaintext, "len {len}");
            assert!(
                open_served(&[4; 32], &sealed).is_err(),
                "wrong key, len {len}"
            );
            let mut flipped = sealed.clone();
            flipped[PREFIX_LEN + 1] ^= 1;
            assert!(open_served(&KEY, &flipped).is_err(), "flipped, len {len}");
        }
    }

    #[test]
    fn current_bundles_never_fall_back() {
        let sealed = seal(&KEY, &HEADER, b"current").unwrap();
        assert_eq!(*open_served(&KEY, &sealed).unwrap(), *b"current");
        // A changed but well-formed header fails as the current format.
        let mut later = sealed.clone();
        later[..HEADER_LEN].copy_from_slice(
            &PolicyHeader {
                expires_unix: HEADER.expires_unix + 1,
                ..HEADER
            }
            .encode(),
        );
        let err = open_served(&KEY, &later).unwrap_err();
        assert!(
            matches!(&err, Error::Corrupt(m) if m == "authentication failed"),
            "{err}"
        );
        // A legacy bundle that reads as a header is refused, not misread:
        // the header-shaped front decides the format.
        let mut prefix = [9; PREFIX_LEN];
        prefix[..2].copy_from_slice(&[1, 0]);
        let shaped = seal_legacy(&KEY, prefix, b"legacy");
        assert!(has_header(&shaped));
        assert!(open_served(&KEY, &shaped).is_err());
    }

    #[test]
    fn a_broken_header_never_opens_as_legacy() {
        // An unparseable header sends the bundle to the legacy opener, whose
        // key and layout differ, so a current bundle still fails.
        for byte in [0, 2, 0xff] {
            let mut sealed = seal(&KEY, &HEADER, b"current").unwrap();
            sealed[0] = byte;
            assert!(!has_header(&sealed));
            assert!(open_served(&KEY, &sealed).is_err(), "version {byte}");
        }
        let mut flags = seal(&KEY, &HEADER, b"current").unwrap();
        flags[1] = 0x80;
        assert!(open_served(&KEY, &flags).is_err(), "flags");
    }
}
