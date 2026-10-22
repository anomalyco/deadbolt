use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;

pub(crate) type SecretKey = Zeroizing<[u8; KEY_LEN]>;

pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(Error::Rng)?;
    Ok(out)
}

pub(crate) fn random_key() -> Result<SecretKey> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(key.as_mut_slice()).map_err(Error::Rng)?;
    Ok(key)
}

pub(crate) fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

/// Derives an independent subkey from `key` for one purpose (BLAKE3 KDF mode).
pub(crate) fn subkey(context: &str, key: &[u8; KEY_LEN]) -> SecretKey {
    Zeroizing::new(blake3::derive_key(context, key))
}

/// Keyed hash used to turn lookup keys into opaque database keys.
pub(crate) fn blind(key: &[u8; KEY_LEN], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Zeroizing::new(blake3::Hasher::new_keyed(key));
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Encrypts the concatenation of `parts` with a fresh random nonce.
/// Output: `nonce (24) || ciphertext || tag (16)`.
pub(crate) fn seal(cipher: &XChaCha20Poly1305, aad: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>> {
    let nonce = random::<NONCE_LEN>()?;
    let len: usize = parts.iter().map(|p| p.len()).sum();
    let mut out = Vec::with_capacity(NONCE_LEN + len + TAG_LEN);
    out.extend_from_slice(&nonce);
    for part in parts {
        out.extend_from_slice(part);
    }
    let tag = cipher
        .encrypt_inout_detached(&nonce.into(), aad, out[NONCE_LEN..].as_mut().into())
        .map_err(|_| Error::corrupt("message too long to encrypt"))?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Inverse of [`seal`]. Returns `None` if authentication fails.
pub(crate) fn open(
    cipher: &XChaCha20Poly1305,
    aad: &[u8],
    sealed: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let (nonce, rest) = sealed.split_at(NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
    let tag: [u8; TAG_LEN] = tag.try_into().ok()?;
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_inout_detached(&nonce.into(), aad, buf.as_mut_slice().into(), &tag.into())
        .ok()?;
    Some(buf)
}
