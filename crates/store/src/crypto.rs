use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;

pub(crate) type SecretKey = Zeroizing<[u8; KEY_LEN]>;

/// A key the open store holds for as long as it's open (the data key, the
/// device secret, the meta blinding key). On Unix it sits in pages of its own,
/// locked in RAM, out of core dumps on Linux, and wiped before they're freed
/// (`deadbolt_os::mem::LockedSecret`); elsewhere (wasm) it's a wiped array.
#[cfg(unix)]
pub(crate) type LiveKey = deadbolt_os::mem::LockedSecret<KEY_LEN>;
#[cfg(not(unix))]
pub(crate) type LiveKey = Zeroizing<[u8; KEY_LEN]>;

/// A [`LiveKey`] holding a copy of `key`. The caller wipes its own copy.
#[cfg(unix)]
pub(crate) fn live_key(key: &[u8; KEY_LEN]) -> LiveKey {
    LiveKey::from_bytes(key)
}

#[cfg(not(unix))]
pub(crate) fn live_key(key: &[u8; KEY_LEN]) -> LiveKey {
    Zeroizing::new(*key)
}

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

/// A random [`LiveKey`], filled in place.
pub(crate) fn random_live_key() -> Result<LiveKey> {
    let mut key = live_key(&[0; KEY_LEN]);
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
    let Ok(tag) =
        cipher.encrypt_inout_detached(&nonce.into(), aad, out[NONCE_LEN..].as_mut().into())
    else {
        // Still plaintext.
        zeroize::Zeroize::zeroize(&mut out);
        return Err(Error::corrupt("message too long to encrypt"));
    };
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
