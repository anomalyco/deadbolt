//! The one AEAD (XChaCha20-Poly1305 with a random 24-byte nonce, always) and
//! the BLAKE3 KDF every key in this crate comes from.

use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// Bytes [`seal`] adds: the nonce in front, the tag behind.
pub const SEAL_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

pub type Key = Zeroizing<[u8; KEY_LEN]>;

pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(Error::Rng)?;
    Ok(out)
}

/// `blake3::derive_key(context, parts[0] || parts[1] || …)`.
pub(crate) fn kdf(context: &'static str, parts: &[&[u8]]) -> Key {
    let mut hasher = Zeroizing::new(blake3::Hasher::new_derive_key(context));
    for part in parts {
        hasher.update(part);
    }
    Zeroizing::new(hasher.finalize().into())
}

/// BLAKE3 keyed hash of the concatenation of `parts`.
pub(crate) fn keyed_hash(key: &[u8; KEY_LEN], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Zeroizing::new(blake3::Hasher::new_keyed(key));
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `nonce || ciphertext || tag` under a fresh random nonce.
pub(crate) fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = random::<NONCE_LEN>()?;
    let mut out = Vec::with_capacity(SEAL_OVERHEAD + plaintext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plaintext);
    let Ok(tag) =
        cipher.encrypt_inout_detached(&nonce.into(), aad, out[NONCE_LEN..].as_mut().into())
    else {
        // Still plaintext.
        zeroize::Zeroize::zeroize(&mut out);
        return Err(Error::InvalidInput("message too long to encrypt"));
    };
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Inverse of [`seal`].
pub(crate) fn open(key: &[u8; KEY_LEN], aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < SEAL_OVERHEAD {
        return Err(Error::Decrypt);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let (nonce, rest) = sealed.split_at(NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Decrypt)?;
    let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| Error::Decrypt)?;
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_inout_detached(&nonce.into(), aad, buf.as_mut_slice().into(), &tag.into())
        .map_err(|_| Error::Decrypt)?;
    Ok(buf)
}
