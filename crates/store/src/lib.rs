//! Encrypted local storage for one deadbolt device.
//!
//! Holds the device secret (the Ed25519 device key seed) and the device's
//! copy of the vault's log entries, all encrypted at rest under the local
//! unlock key (see "Keys (two)" in `docs/design.md`). The API is synchronous
//! and treats entries and meta values as opaque bytes.
//!
//! ```no_run
//! # fn main() -> deadbolt_store::Result<()> {
//! # let dir = std::path::Path::new("/tmp/deadbolt");
//! let store = deadbolt_store::init(dir, b"passphrase", [7; 32])?;
//! store.append(&[1; 32], b"signed entry bytes")?;
//! store.lock();
//!
//! let store = deadbolt_store::unlock(dir, b"passphrase")?;
//! assert_eq!(store.device_secret(), &[7; 32]);
//! for entry in store.iter_all()? {
//!     let (hash, bytes) = entry?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Data directory layout
//!
//! ```text
//! <dir>/                          created with mode 0700 if missing
//!   store.redb                    the store: a single redb database, mode 0600
//!   .store.redb.init-<hex>        transient, only while `init` is running
//! ```
//!
//! `store.redb` tables:
//!
//! | table       | key                    | value                                   |
//! |-------------|------------------------|-----------------------------------------|
//! | `header`    | `"format"`             | format version, u32 LE (plaintext)      |
//! |             | `"kdf"`                | Argon2id params + salt (plaintext)      |
//! |             | `"keyset"`             | AEAD(unlock key, data key ‖ device secret) |
//! |             | `"log_len"`            | AEAD(data key, entry count u64 LE)      |
//! | `log`       | seq u64, from 0        | AEAD(data key, entry hash ‖ bytes)      |
//! | `log_index` | keyed-hash(entry hash) | seq                                     |
//! | `meta`      | keyed-hash(name)       | AEAD(data key, value)                   |
//!
//! Every AEAD value is `nonce (24) ‖ ciphertext ‖ tag (16)`.
//!
//! # Keys and crypto
//!
//! - **Local unlock key**: Argon2id v1.3 over the passphrase with a random
//!   16-byte salt; 256-bit output. Defaults: 64 MiB, 3 passes, 1 lane
//!   ([`KdfParams::DEFAULT`]). Parameters are stored in the header and
//!   authenticated as AAD of the key set, so they can be raised later.
//! - **Key set**: a random 256-bit data key and the 32-byte device secret,
//!   sealed together with XChaCha20-Poly1305 under the unlock key. AAD is
//!   `"deadbolt-store/v1/keyset" ‖ format version ‖ KDF header`. A wrong
//!   passphrase fails this AEAD check ([`Error::WrongPassphrase`]); no
//!   passphrase hash is stored or compared. Changing the passphrase only
//!   re-seals this record.
//! - **Data**: subkeys are derived from the data key with BLAKE3's KDF mode:
//!   one XChaCha20-Poly1305 key for all data records, and one BLAKE3 keyed-hash
//!   key each for the log index and meta names, so entry hashes and meta
//!   names never appear on disk in the clear. Every record's AAD carries a
//!   versioned purpose label plus its position (log seq or blinded meta
//!   name), so records cannot be swapped. The sealed `log_len` lets
//!   [`Unlocked::iter_all`] detect deleted or truncated entries.
//!
//! Nonces are 192-bit random, so there is no nonce state to keep.
//!
//! # Integrity
//!
//! Two layers:
//!
//! 1. On open, redb verifies every page checksum (`check_integrity`). A
//!    flipped byte anywhere in live data makes [`unlock`] fail with
//!    [`Error::Corrupt`]. redb can panic on some structurally damaged files;
//!    opening runs under `catch_unwind` and turns that into
//!    [`Error::Corrupt`] too (the panic message still goes to stderr).
//! 2. Every record is AEAD-sealed, so edits that keep redb's (non-
//!    cryptographic) checksums valid still fail: [`Error::Corrupt`] for data,
//!    [`Error::WrongPassphrase`] for the key set or KDF header.
//!
//! Not covered: someone with write access to the disk can replace the whole
//! file with an older copy, or delete meta values; both look like valid
//! older state. Detecting that would need state stored outside this file.
//!
//! # Backend
//!
//! [redb](https://docs.rs/redb): a pure-Rust, single-file, copy-on-write
//! B-tree with ACID transactions. A commit is durable when it returns (fsync),
//! and a crash mid-commit leaves the previous committed state intact. We turn
//! on its two-phase commit, which also makes redb refuse a damaged latest
//! commit rather than quietly rolling back to the one before. That gives
//! crash safety, a hash → entry index, and an atomic multi-record update
//! (entry + index + count) for free. A hand-rolled append-only file would
//! need its own framing, torn-tail recovery, index rebuild and atomic header
//! rewrite to match. redb also takes an exclusive file lock, so two processes
//! cannot open one store ([`Error::InUse`]). Only ciphertext and keyed hashes
//! reach redb, so its page cache never holds plaintext.
//!
//! # Memory
//!
//! Keys, the device secret, and decrypted values are kept in
//! [`zeroize::Zeroizing`] buffers and wiped on drop, as is Argon2's working
//! memory. Dropping [`Unlocked`] (or calling [`Unlocked::lock`]) locks the store.
//!
//! # OS keychain
//!
//! Not implemented. It would add a second key set slot wrapped under a
//! keychain-held key; see the note on [`unlock`].

mod crypto;
mod error;
mod kdf;
mod store;

#[cfg(test)]
mod tests;

pub use error::{Error, Result};
pub use kdf::KdfParams;
pub use store::{
    DB_FILE, EntryHash, FORMAT_VERSION, LogIter, Unlocked, init, init_with_params, is_initialized,
    unlock,
};
pub use zeroize::Zeroizing;
