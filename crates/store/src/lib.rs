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
//! store.append_batch([&b"signed entry bytes"[..]])?;
//! drop(store);
//!
//! let store = deadbolt_store::unlock(dir, b"passphrase")?;
//! assert_eq!(store.device_secret(), &[7; 32]);
//! for entry in store.iter_all()? {
//!     let bytes = entry?;
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
//! | `log`       | seq u64, from 0        | AEAD(data key, bytes)                   |
//! | `meta`      | keyed-hash(name)       | AEAD(data key, value)                   |
//! | `activity`  | id u64, increasing     | AEAD(data key, time u64 LE ‖ bytes)     |
//!
//! Every AEAD value is `nonce (24) ‖ ciphertext ‖ tag (16)`. The meta value
//! `"activity"` tallies the `activity` table's sealed bytes and the rows it
//! dropped to stay in budget.
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
//!   passphrase hash is stored or compared. Changing the passphrase would
//!   only re-seal this record.
//! - **Data**: subkeys are derived from the data key with BLAKE3's KDF mode:
//!   one XChaCha20-Poly1305 key for all data records, and one BLAKE3 keyed-hash
//!   key for meta names, so meta names never appear on disk in the clear.
//!   Every record's AAD carries a versioned purpose label plus its position
//!   (log seq or blinded meta name), so records cannot be swapped. The sealed
//!   `log_len` lets [`Unlocked::iter_all`] detect deleted or truncated entries.
//!
//! Nonces are 192-bit random, so there is no nonce state to keep.
//!
//! # Integrity
//!
//! Two layers:
//!
//! 1. On open, redb verifies every page checksum (`check_integrity`). A
//!    flipped byte anywhere in live data makes unlocking fail with
//!    [`Error::Corrupt`]. Only [`biometric_token_with_backend`], which reads
//!    public metadata, skips this walk. redb can panic on some structurally damaged files;
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
//! B-tree with ACID transactions. A successful commit is durable (fsync).
//! An interrupted or failed commit can leave either the old or new state; an
//! error is not proof of rollback. Signed-log callers must discard derived
//! state and reopen on [`Error::AppendUncertain`]. We turn
//! on its two-phase commit, which also makes redb refuse a damaged latest
//! commit rather than quietly rolling back to the one before. That gives
//! crash safety and an atomic multi-record update (entries + count) for free.
//! A hand-rolled append-only file would need its own framing, torn-tail
//! recovery and atomic header rewrite to match. redb also takes an exclusive
//! file lock, so two processes cannot open one store ([`Error::InUse`]). Only
//! ciphertext and keyed hashes reach redb, so its page cache never holds
//! plaintext.
//!
//! On wasm, use [`init_with_backend`] and [`unlock_with_backend`] with an
//! application-owned backend with an exclusive OPFS sync access handle in a dedicated
//! worker. The encrypted format and transactions are identical; OPFS `flush`
//! supplies the durability barrier and the access handle supplies the lock.
//! The caller publishes a newly initialized file only after creation succeeds.
//! Native path-based functions are not exported on wasm. Structurally damaged
//! databases can trap the wasm worker: wasm's default panic-abort build cannot
//! recover a redb panic with `catch_unwind`.
//!
//! # Memory
//!
//! Keys, the device secret, and decrypted values are kept in
//! [`zeroize::Zeroizing`] buffers and wiped on drop, as is Argon2's working
//! memory. Dropping [`Unlocked`] locks the store.
//!
//! # OS keychain / Secure Enclave
//!
//! Optional biometric unlock stores a second wrapped copy of the key set
//! (`"keyset.biometric"`) alongside an opaque platform token
//! (`"biometric.token"`), sealed with a random 256-bit key
//! ([`generate_biometric_key`]) that the caller wraps in the Secure Enclave.
//! On native, `unlock_biometric` opens the store with that key; changing the passphrase
//! or calling [`Unlocked::clear_biometric`] removes the slot.

mod crypto;
mod error;
mod kdf;
mod store;

#[cfg(test)]
mod tests;

pub use error::{Error, Result};
pub use kdf::KdfParams;
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use store::native::{
    biometric_token, clear_biometric, init, init_with_params, is_initialized, unlock,
    unlock_biometric,
};
pub use store::{
    ActivityPage, ActivityRow, Budget, DB_FILE, Dropped, FORMAT_VERSION, LogIter, PassphraseCheck,
    Unlocked, biometric_token_with_backend, generate_biometric_key, init_with_backend,
    unlock_biometric_with_backend, unlock_with_backend,
};
pub use zeroize::Zeroizing;
