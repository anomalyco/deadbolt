//! Content-addressed blobs (`blob/<blake3 hex>`) and the viewer's outbox
//! (`outbox/<random hex>.wrap`).
//!
//! Storing a blob takes the writer lock ([`crate::VaultDir::put_blob`]):
//! replacing a torn copy reads, deletes and recreates it, and two unlocked
//! writers racing through that could delete each other's complete copy.
//! Reading a blob needs no lock, since every read is checked against the
//! hash. The outbox needs none either: every entry has a fresh random name,
//! so the lock-free iOS viewer can leave one.

use crate::blocks::Blocks;
use crate::crypto;
use crate::error::{Error, Result};
use crate::names::{self, OUTBOX_DIR, OUTBOX_SUFFIX};

/// Stores a blob under its hash. Storing the same bytes again is a no-op; a
/// torn earlier write under that name is replaced. The caller holds the
/// writer lock: this is reached only through [`crate::VaultDir::put_blob`].
pub(crate) fn put_blob<B: Blocks>(blocks: &B, bytes: &[u8]) -> Result<[u8; 32]> {
    let hash: [u8; 32] = blake3::hash(bytes).into();
    let name = names::blob(&hash);
    match blocks.create_new(&name, bytes) {
        Ok(()) => Ok(hash),
        Err(Error::AlreadyExists { .. }) => {
            if blake3::hash(&blocks.read_all(&name)?) == hash {
                return Ok(hash);
            }
            blocks.delete(&name)?;
            blocks.create_new(&name, bytes)?;
            Ok(hash)
        }
        Err(err) => Err(err),
    }
}

/// A blob's bytes, checked against its hash.
pub fn get_blob<B: Blocks>(blocks: &B, hash: &[u8; 32]) -> Result<Vec<u8>> {
    let name = names::blob(hash);
    let bytes = blocks.read_all(&name)?;
    if blake3::hash(&bytes) != *hash {
        return Err(Error::CorruptBlob { name });
    }
    Ok(bytes)
}

/// Leaves a sealed entry in the outbox and returns its name.
pub fn put_outbox<B: Blocks>(blocks: &B, sealed: &[u8]) -> Result<String> {
    let name = names::outbox(&crypto::random::<16>()?);
    blocks.create_new(&name, sealed)?;
    Ok(name)
}

/// Outbox entries, sorted by name.
pub fn list_outbox<B: Blocks>(blocks: &B) -> Result<Vec<String>> {
    let mut names = blocks.list_prefix(OUTBOX_DIR)?;
    names.retain(|name| name.ends_with(OUTBOX_SUFFIX));
    Ok(names)
}
