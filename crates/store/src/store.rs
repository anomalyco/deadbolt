use std::fmt;
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
use std::fs::{self, File, OpenOptions};
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
use std::io;
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
use std::path::Path;
use std::path::PathBuf;

use chacha20poly1305::XChaCha20Poly1305;
use redb::{
    Database, ReadableDatabase, ReadableTable, StorageBackend, Table, TableDefinition,
    WriteTransaction,
};
use zeroize::Zeroizing;

use crate::crypto::{self, KEY_LEN, SecretKey};
use crate::error::{Error, Result};
use crate::kdf::{KdfHeader, KdfParams};

mod activity;

pub use activity::{ActivityPage, ActivityRow, Budget, Dropped};

/// Name of the database file inside the data directory.
pub const DB_FILE: &str = "store.redb";

/// On-disk format version. Bound into every AEAD label below.
pub const FORMAT_VERSION: u32 = 2;

// Plaintext header: format version, KDF header, wrapped key set, and the
// sealed log length.
pub(crate) const HEADER: TableDefinition<&str, &[u8]> = TableDefinition::new("header");
// seq (append order, contiguous from 0) -> seal(bytes)
pub(crate) const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("log");
// blind(name) -> seal(value)
pub(crate) const META: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("meta");

const H_FORMAT: &str = "format";
const H_KDF: &str = "kdf";
const H_KEYSET: &str = "keyset";
pub(crate) const H_KEYSET_BIOMETRIC: &str = "keyset.biometric";
pub(crate) const H_BIOMETRIC_TOKEN: &str = "biometric.token";
const H_LOG_LEN: &str = "log_len";

const AAD_KEYSET: &[u8] = b"deadbolt-store/v1/keyset";
const AAD_KEYSET_BIOMETRIC: &[u8] = b"deadbolt-store/v1/keyset.biometric";
const AAD_LOG: &[u8] = b"deadbolt-store/v1/log";
const AAD_LOG_LEN: &[u8] = b"deadbolt-store/v1/log-len";
const AAD_META: &[u8] = b"deadbolt-store/v1/meta";

const CTX_DATA: &str = "deadbolt-store v1 2026-10-15 data encryption";
const CTX_META_INDEX: &str = "deadbolt-store v1 2026-10-15 meta key blinding";

const CACHE_BYTES: usize = 16 * 1024 * 1024;

/// Returns true if `dir` contains a store.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub fn is_initialized(dir: &Path) -> bool {
    dir.join(DB_FILE).is_file()
}

/// Creates a new store in `dir` with [`KdfParams::DEFAULT`] and returns it
/// unlocked. See [`init_with_params`].
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub fn init(dir: &Path, passphrase: &[u8], device_secret: [u8; 32]) -> Result<Unlocked> {
    init_with_params(dir, passphrase, device_secret, KdfParams::DEFAULT)
}

/// Creates a new store in `dir` (created with mode 0700 if missing) and
/// returns it unlocked.
///
/// `device_secret` is stored encrypted under the local unlock key derived from
/// `passphrase`. Fails with [`Error::AlreadyExists`] if `dir` already holds a
/// store; an existing store is never modified.
///
/// The store is built in a temporary file and linked into place only once
/// fully written, so a crash during init leaves no half-initialized store.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub fn init_with_params(
    dir: &Path,
    passphrase: &[u8],
    device_secret: [u8; 32],
    params: KdfParams,
) -> Result<Unlocked> {
    let device_secret = Zeroizing::new(device_secret);
    let db_path = dir.join(DB_FILE);
    params.validate()?;
    create_private_dir(dir)?;
    if db_path.exists() {
        return Err(Error::AlreadyExists(dir.to_path_buf()));
    }

    let keyset = KeySet {
        data_key: crypto::random_key()?,
        device_secret,
    };
    let kdf = KdfHeader::generate(params)?;
    let wrapped = keyset.wrap(&kdf, passphrase)?;
    let keys = Keys::new(keyset);

    let tmp = TempFile(dir.join(format!(".{DB_FILE}.init-{}", hex(&crypto::random::<8>()?))));
    {
        let db = redb::Builder::new()
            .set_cache_size(CACHE_BYTES)
            .create_file(create_private_file(&tmp.0)?)?;
        initialize_db(&db, &keys, &kdf, &wrapped)?;
        File::open(&tmp.0)?.sync_all()?;
    }

    link_no_clobber(&tmp.0, &db_path).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => Error::AlreadyExists(dir.to_path_buf()),
        _ => Error::Io(e),
    })?;
    drop(tmp);
    sync_dir(dir)?;

    Ok(Unlocked {
        db: open_db(&db_path)?,
        dir: dir.to_path_buf(),
        keys,
    })
}

/// Opens the store in `dir` and decrypts its key set with `passphrase`.
///
/// Returns [`Error::WrongPassphrase`] if the AEAD check on the key set fails,
/// [`Error::NotInitialized`] if there is no store, and [`Error::InUse`] if it
/// is already open.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub fn unlock(dir: &Path, passphrase: &[u8]) -> Result<Unlocked> {
    let db_path = dir.join(DB_FILE);
    if !db_path.is_file() {
        return Err(Error::NotInitialized(dir.to_path_buf()));
    }
    let db = open_db(&db_path)?;
    let header = {
        let txn = db.begin_read()?;
        let table = txn.open_table(HEADER)?;
        Header::read(&table)?
    };
    let keyset = KeySet::unwrap(&header.kdf, &header.keyset, passphrase)?;
    Ok(Unlocked {
        db,
        dir: dir.to_path_buf(),
        keys: Keys::new(keyset),
    })
}

/// Creates a store on an empty, exclusively owned backend using the same
/// encrypted records and transactions as the native file store.
///
/// A nonempty backend is never overwritten. The caller must publish the store
/// only after success; if creation fails or is interrupted, discard that new
/// backend rather than treating it as initialized. For OPFS, keep the pending
/// file separate from the committed store (or publish its name in IndexedDB).
/// The backend must release its resources on drop, including preflight errors.
pub fn init_with_backend(
    backend: impl StorageBackend,
    passphrase: &[u8],
    device_secret: [u8; 32],
    params: KdfParams,
) -> Result<Unlocked> {
    let device_secret = Zeroizing::new(device_secret);
    params.validate()?;
    if backend.len()? != 0 {
        return Err(Error::AlreadyExists(PathBuf::from(DB_FILE)));
    }
    let keyset = KeySet {
        data_key: crypto::random_key()?,
        device_secret,
    };
    let kdf = KdfHeader::generate(params)?;
    let wrapped = keyset.wrap(&kdf, passphrase)?;
    let keys = Keys::new(keyset);
    let db = redb::Builder::new()
        .set_cache_size(CACHE_BYTES)
        .create_with_backend(backend)?;
    initialize_db(&db, &keys, &kdf, &wrapped)?;
    Ok(Unlocked {
        db,
        dir: PathBuf::from(DB_FILE),
        keys,
    })
}

/// Opens an existing, exclusively owned backend and decrypts the key set.
/// Dropping the result wipes its keys and closes the backend. An empty backend
/// is rejected without creating a database. As on native, all live redb page
/// checksums are checked before unwrapping the key set.
pub fn unlock_with_backend(backend: impl StorageBackend, passphrase: &[u8]) -> Result<Unlocked> {
    if backend.len()? == 0 {
        return Err(Error::NotInitialized(PathBuf::from(DB_FILE)));
    }
    let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Database> {
        let mut db = redb::Builder::new()
            .set_cache_size(CACHE_BYTES)
            .create_with_backend(backend)?;
        db.check_integrity()?;
        Ok(db)
    }));
    let db = opened.unwrap_or_else(|_| Err(Error::corrupt("database file is damaged")))?;
    let header = {
        let txn = db.begin_read()?;
        Header::read(&txn.open_table(HEADER)?)?
    };
    let keyset = KeySet::unwrap(&header.kdf, &header.keyset, passphrase)?;
    Ok(Unlocked {
        db,
        dir: PathBuf::from(DB_FILE),
        keys: Keys::new(keyset),
    })
}

fn initialize_db(db: &Database, keys: &Keys, kdf: &KdfHeader, wrapped: &[u8]) -> Result<()> {
    let txn = begin_write(db)?;
    {
        let mut header = txn.open_table(HEADER)?;
        header.insert(H_FORMAT, FORMAT_VERSION.to_le_bytes().as_slice())?;
        header.insert(H_KDF, kdf.encode().as_slice())?;
        header.insert(H_KEYSET, wrapped)?;
        write_log_len(keys, &mut header, 0)?;
        txn.open_table(LOG)?;
        txn.open_table(META)?;
        txn.open_table(activity::ACTIVITY)?;
    }
    txn.commit()?;
    Ok(())
}

/// Generates a fresh 256-bit wrapping key for [`Unlocked::set_biometric`].
pub fn generate_biometric_key() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    crypto::random_key()
}

/// Reads the opaque biometric token enrolled in `dir` without unlocking the
/// store. Returns `Ok(None)` if no biometric key set is enrolled.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub fn biometric_token(dir: &Path) -> Result<Option<Vec<u8>>> {
    let db_path = dir.join(DB_FILE);
    if !db_path.is_file() {
        return Err(Error::NotInitialized(dir.to_path_buf()));
    }
    let db = open_db(&db_path)?;
    let txn = db.begin_read()?;
    let table = txn.open_table(HEADER)?;
    let _header = Header::read(&table)?;
    Ok(read_biometric(&table)?.map(|(token, _)| token))
}

/// Opens the store in `dir` and decrypts its biometric key set with `key`.
///
/// Returns [`Error::InvalidBiometric`] if no biometric key set is enrolled or
/// `key` fails the AEAD check.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub fn unlock_biometric(dir: &Path, key: &[u8; KEY_LEN]) -> Result<Unlocked> {
    let db_path = dir.join(DB_FILE);
    if !db_path.is_file() {
        return Err(Error::NotInitialized(dir.to_path_buf()));
    }
    let db = open_db(&db_path)?;
    let (token, wrapped) = {
        let txn = db.begin_read()?;
        let table = txn.open_table(HEADER)?;
        let _header = Header::read(&table)?;
        read_biometric(&table)?.ok_or(Error::InvalidBiometric)?
    };
    let keyset = KeySet::unwrap_biometric(key, &token, &wrapped)?;
    Ok(Unlocked {
        db,
        dir: dir.to_path_buf(),
        keys: Keys::new(keyset),
    })
}

/// Removes the enrolled biometric key set and token from `dir` while the store
/// is locked. Returns whether a slot was present.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub fn clear_biometric(dir: &Path) -> Result<bool> {
    let db_path = dir.join(DB_FILE);
    if !db_path.is_file() {
        return Err(Error::NotInitialized(dir.to_path_buf()));
    }
    let db = open_db(&db_path)?;
    let txn = begin_write(&db)?;
    let removed = {
        let mut table = txn.open_table(HEADER)?;
        let _header = Header::read(&table)?;
        remove_biometric(&mut table)?
    };
    if removed {
        txn.commit()?;
    } else {
        txn.abort()?;
    }
    Ok(removed)
}

/// An open, decrypted store. Holds the device secret and data keys in memory
/// (wiped on drop) and an exclusive lock on the database file.
/// Dropping it locks the store.
pub struct Unlocked {
    db: Database,
    dir: PathBuf,
    keys: Keys,
}

impl fmt::Debug for Unlocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unlocked")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl Unlocked {
    /// The 32-byte device secret (Ed25519 seed) given at creation.
    pub fn device_secret(&self) -> &[u8; 32] {
        &self.keys.keyset.device_secret
    }

    /// Appends several entries in one durable transaction. Returns how many
    /// were added. Either all entries are written or none are.
    ///
    /// Deduplication and hash verification happen in `deadbolt-core::Vault`
    /// before entries are staged for persistence, so the store keeps only the
    /// sealed entry bytes in append order.
    pub fn append_batch<'a>(&self, entries: impl IntoIterator<Item = &'a [u8]>) -> Result<usize> {
        let txn = begin_write(&self.db)?;
        let added = {
            let mut header = txn.open_table(HEADER)?;
            let mut log = txn.open_table(LOG)?;
            let start = read_log_len(&self.keys, &header)?;
            let last = log.last()?.map(|(k, _)| k.value());
            if last.map_or(0, |k| k + 1) != start {
                return Err(Error::corrupt("log length does not match stored entries"));
            }
            let mut len = start;
            for bytes in entries {
                let row = crypto::seal(&self.keys.data, &log_aad(len), &[bytes])?;
                log.insert(len, row.as_slice())?;
                len += 1;
            }
            if len != start {
                write_log_len(&self.keys, &mut header, len)?;
            }
            len - start
        };
        if added > 0 {
            txn.commit()?;
        } else {
            txn.abort()?;
        }
        Ok(added as usize)
    }

    /// Iterates all entries in append order over a consistent snapshot.
    /// Yields an error (and then stops) on any tampering, including missing
    /// or reordered entries.
    pub fn iter_all(&self) -> Result<LogIter<'_>> {
        let txn = self.db.begin_read()?;
        let len = read_log_len(&self.keys, &txn.open_table(HEADER)?)?;
        let range = txn.open_table(LOG)?.range::<u64>(..)?;
        Ok(LogIter {
            keys: &self.keys,
            range,
            next_seq: 0,
            len,
            done: false,
        })
    }

    /// Reads a meta value.
    pub fn meta_get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(META)?;
        let blinded = self.keys.meta_blind(name);
        let Some(sealed) = table.get(&blinded)? else {
            return Ok(None);
        };
        crypto::open(&self.keys.data, &meta_aad(&blinded), sealed.value())
            .map(Some)
            .ok_or_else(|| Error::corrupt(format!("meta value {name:?} failed authentication")))
    }

    /// Sets a meta value, replacing any previous one.
    pub fn meta_set(&self, name: &str, value: &[u8]) -> Result<()> {
        let blinded = self.keys.meta_blind(name);
        let sealed = crypto::seal(&self.keys.data, &meta_aad(&blinded), &[value])?;
        let txn = begin_write(&self.db)?;
        txn.open_table(META)?.insert(&blinded, sealed.as_slice())?;
        txn.commit()?;
        Ok(())
    }

    /// The KDF parameters currently protecting the store.
    pub fn kdf_params(&self) -> Result<KdfParams> {
        let txn = self.db.begin_read()?;
        let header = Header::read(&txn.open_table(HEADER)?)?;
        Ok(header.kdf.params)
    }

    /// Re-wraps the key set under a new passphrase, keeping the current KDF
    /// parameters (with a fresh salt). Only the small key set is rewritten.
    pub fn change_passphrase(&self, old: &[u8], new: &[u8]) -> Result<()> {
        self.change_passphrase_with_params(old, new, self.kdf_params()?)
    }

    /// Like [`change_passphrase`](Self::change_passphrase), also switching to
    /// new KDF parameters. Passing the same passphrase twice just re-tunes the
    /// KDF.
    pub fn change_passphrase_with_params(
        &self,
        old: &[u8],
        new: &[u8],
        params: KdfParams,
    ) -> Result<()> {
        params.validate()?;
        // Everything happens inside one write transaction so concurrent
        // changes serialize and the swap is atomic.
        let txn = begin_write(&self.db)?;
        {
            let mut table = txn.open_table(HEADER)?;
            let header = Header::read(&table)?;
            let current = KeySet::unwrap(&header.kdf, &header.keyset, old)?;
            if current.encode() != self.keys.keyset.encode() {
                return Err(Error::corrupt(
                    "key set on disk differs from the open store",
                ));
            }
            let kdf = KdfHeader::generate(params)?;
            let wrapped = current.wrap(&kdf, new)?;
            table.insert(H_KDF, kdf.encode().as_slice())?;
            table.insert(H_KEYSET, wrapped.as_slice())?;
            if old != new {
                let _removed: bool = remove_biometric(&mut table)?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// What checks a passphrase against this store's key set
    /// ([`PassphraseCheck::matches`]), without holding the store while the
    /// KDF runs.
    pub fn passphrase_check(&self) -> Result<PassphraseCheck> {
        let txn = self.db.begin_read()?;
        let header = Header::read(&txn.open_table(HEADER)?)?;
        Ok(PassphraseCheck {
            kdf: header.kdf,
            wrapped: header.keyset,
            keyset: self.keys.keyset.encode(),
        })
    }

    /// Stores a second copy of the key set wrapped under `key`, bound to the
    /// opaque platform `token` (such as a Secure Enclave sealed key envelope).
    pub fn set_biometric(&self, key: &[u8; KEY_LEN], token: &[u8]) -> Result<()> {
        if token.is_empty() {
            return Err(Error::InvalidBiometric);
        }
        let wrapped = self.keys.keyset.wrap_biometric(key, token)?;
        let txn = begin_write(&self.db)?;
        {
            let mut table = txn.open_table(HEADER)?;
            table.insert(H_BIOMETRIC_TOKEN, token)?;
            table.insert(H_KEYSET_BIOMETRIC, wrapped.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// The opaque biometric token currently enrolled on this store, if any.
    pub fn biometric_token(&self) -> Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(HEADER)?;
        Ok(read_biometric(&table)?.map(|(token, _)| token))
    }

    /// Whether `key` opens the enrolled biometric key set, as
    /// native `unlock_biometric` would, while the store stays open: a key fresh
    /// from Touch ID proves the user is here now.
    pub fn check_biometric(&self, key: &[u8; KEY_LEN]) -> Result<bool> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(HEADER)?;
        let Some((token, wrapped)) = read_biometric(&table)? else {
            return Ok(false);
        };
        Ok(KeySet::unwrap_biometric(key, &token, &wrapped).is_ok())
    }

    /// Removes the enrolled biometric key set and token. Returns whether a slot
    /// was present.
    pub fn clear_biometric(&self) -> Result<bool> {
        let txn = begin_write(&self.db)?;
        let removed = {
            let mut table = txn.open_table(HEADER)?;
            remove_biometric(&mut table)?
        };
        if removed {
            txn.commit()?;
        } else {
            txn.abort()?;
        }
        Ok(removed)
    }
}

/// Iterator returned by [`Unlocked::iter_all`].
pub struct LogIter<'a> {
    keys: &'a Keys,
    range: redb::Range<'static, u64, &'static [u8]>,
    next_seq: u64,
    len: u64,
    done: bool,
}

impl Iterator for LogIter<'_> {
    type Item = Result<Zeroizing<Vec<u8>>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let item = match self.range.next() {
            None if self.next_seq == self.len => {
                self.done = true;
                return None;
            }
            None => Err(Error::corrupt("log is missing entries")),
            Some(Err(e)) => Err(e.into()),
            Some(Ok((seq, row))) => {
                let seq = seq.value();
                if seq != self.next_seq || seq >= self.len {
                    Err(Error::corrupt("log entries are missing or out of order"))
                } else {
                    self.next_seq += 1;
                    self.keys.open_log_row(seq, row.value())
                }
            }
        };
        if item.is_err() {
            self.done = true;
        }
        Some(item)
    }
}

/// The passphrase-wrapped key set of an open store, from
/// [`Unlocked::passphrase_check`].
pub struct PassphraseCheck {
    kdf: KdfHeader,
    wrapped: Vec<u8>,
    keyset: Zeroizing<[u8; 64]>,
}

impl PassphraseCheck {
    /// Whether `passphrase` unwraps the open store's key set. Runs the KDF.
    pub fn matches(&self, passphrase: &[u8]) -> bool {
        KeySet::unwrap(&self.kdf, &self.wrapped, passphrase)
            .is_ok_and(|keyset| keyset.encode() == self.keyset)
    }
}

struct KeySet {
    data_key: SecretKey,
    device_secret: Zeroizing<[u8; 32]>,
}

impl KeySet {
    fn encode(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        out[..32].copy_from_slice(self.data_key.as_slice());
        out[32..].copy_from_slice(self.device_secret.as_slice());
        out
    }

    fn wrap(&self, kdf: &KdfHeader, passphrase: &[u8]) -> Result<Vec<u8>> {
        let unlock_key = kdf.derive(passphrase)?;
        crypto::seal(
            &crypto::cipher(&unlock_key),
            &keyset_aad(kdf),
            &[self.encode().as_slice()],
        )
    }

    fn unwrap(kdf: &KdfHeader, wrapped: &[u8], passphrase: &[u8]) -> Result<Self> {
        let unlock_key = kdf.derive(passphrase)?;
        let plain = crypto::open(&crypto::cipher(&unlock_key), &keyset_aad(kdf), wrapped)
            .ok_or(Error::WrongPassphrase)?;
        Self::decode(&plain)
    }

    fn wrap_biometric(&self, key: &[u8; KEY_LEN], token: &[u8]) -> Result<Vec<u8>> {
        crypto::seal(
            &crypto::cipher(key),
            &biometric_keyset_aad(token),
            &[self.encode().as_slice()],
        )
    }

    fn unwrap_biometric(key: &[u8; KEY_LEN], token: &[u8], wrapped: &[u8]) -> Result<Self> {
        let plain = crypto::open(&crypto::cipher(key), &biometric_keyset_aad(token), wrapped)
            .ok_or(Error::InvalidBiometric)?;
        Self::decode(&plain).map_err(|_| Error::InvalidBiometric)
    }

    fn decode(plain: &[u8]) -> Result<Self> {
        if plain.len() != 64 {
            return Err(Error::corrupt("key set has the wrong length"));
        }
        let mut data_key = Zeroizing::new([0u8; KEY_LEN]);
        let mut device_secret = Zeroizing::new([0u8; 32]);
        data_key.copy_from_slice(&plain[..32]);
        device_secret.copy_from_slice(&plain[32..]);
        Ok(Self {
            data_key,
            device_secret,
        })
    }
}

pub(crate) struct Keys {
    keyset: KeySet,
    data: XChaCha20Poly1305,
    meta_index: SecretKey,
}

impl Keys {
    fn new(keyset: KeySet) -> Self {
        let data = crypto::subkey(CTX_DATA, &keyset.data_key);
        Self {
            data: crypto::cipher(&data),
            meta_index: crypto::subkey(CTX_META_INDEX, &keyset.data_key),
            keyset,
        }
    }

    pub(crate) fn meta_blind(&self, name: &str) -> [u8; 32] {
        crypto::blind(&self.meta_index, &[name.as_bytes()])
    }

    fn open_log_row(&self, seq: u64, row: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crypto::open(&self.data, &log_aad(seq), row)
            .ok_or_else(|| Error::corrupt(format!("log entry {seq} failed authentication")))
    }
}

struct Header {
    kdf: KdfHeader,
    keyset: Vec<u8>,
}

impl Header {
    fn read(table: &impl ReadableTable<&'static str, &'static [u8]>) -> Result<Self> {
        let field = |name: &str| -> Result<Vec<u8>> {
            Ok(table
                .get(name)?
                .ok_or_else(|| Error::corrupt(format!("header field {name:?} is missing")))?
                .value()
                .to_vec())
        };
        let format = field(H_FORMAT)?;
        let format = u32::from_le_bytes(
            format
                .as_slice()
                .try_into()
                .map_err(|_| Error::corrupt("format version has the wrong length"))?,
        );
        if format != FORMAT_VERSION {
            return Err(Error::UnsupportedFormat(format));
        }
        Ok(Self {
            kdf: KdfHeader::decode(&field(H_KDF)?)?,
            keyset: field(H_KEYSET)?,
        })
    }
}

fn read_log_len(
    keys: &Keys,
    table: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<u64> {
    let sealed = table
        .get(H_LOG_LEN)?
        .ok_or_else(|| Error::corrupt("log length is missing"))?;
    let plain = crypto::open(&keys.data, AAD_LOG_LEN, sealed.value())
        .ok_or_else(|| Error::corrupt("log length failed authentication"))?;
    let bytes: [u8; 8] = plain
        .as_slice()
        .try_into()
        .map_err(|_| Error::corrupt("log length has the wrong size"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn write_log_len(keys: &Keys, table: &mut Table<&str, &[u8]>, len: u64) -> Result<()> {
    let sealed = crypto::seal(&keys.data, AAD_LOG_LEN, &[&len.to_le_bytes()])?;
    table.insert(H_LOG_LEN, sealed.as_slice())?;
    Ok(())
}

fn keyset_aad(kdf: &KdfHeader) -> Vec<u8> {
    [AAD_KEYSET, &FORMAT_VERSION.to_le_bytes(), &kdf.encode()].concat()
}

fn biometric_keyset_aad(token: &[u8]) -> Vec<u8> {
    [
        AAD_KEYSET_BIOMETRIC,
        &FORMAT_VERSION.to_le_bytes(),
        &(token.len() as u64).to_le_bytes(),
        token,
    ]
    .concat()
}

fn read_biometric(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let token = table.get(H_BIOMETRIC_TOKEN)?.map(|v| v.value().to_vec());
    let keyset = table.get(H_KEYSET_BIOMETRIC)?.map(|v| v.value().to_vec());
    match (token, keyset) {
        (None, None) => Ok(None),
        (Some(token), Some(keyset)) => Ok(Some((token, keyset))),
        _ => Err(Error::corrupt("incomplete biometric key set in header")),
    }
}

fn remove_biometric(table: &mut Table<&str, &[u8]>) -> Result<bool> {
    let token = table.remove(H_BIOMETRIC_TOKEN)?.is_some();
    let keyset = table.remove(H_KEYSET_BIOMETRIC)?.is_some();
    Ok(token || keyset)
}

fn log_aad(seq: u64) -> Vec<u8> {
    [AAD_LOG, &seq.to_be_bytes()].concat()
}

fn meta_aad(blinded: &[u8; 32]) -> Vec<u8> {
    [AAD_META, blinded].concat()
}

/// Opens the database and verifies every page checksum before use.
///
/// redb can panic on structurally damaged files instead of returning an
/// error, so opening and checking run under `catch_unwind`; after a clean
/// check, damage below the B-tree level can only surface as an AEAD failure.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn open_db(path: &Path) -> Result<Database> {
    let opened = std::panic::catch_unwind(|| -> Result<Database> {
        let mut db = redb::Builder::new()
            .set_cache_size(CACHE_BYTES)
            .open(path)?;
        // Ok(false) means redb repaired the file (e.g. after a crash) by
        // rolling back to the last intact commit, which is fine.
        db.check_integrity()?;
        Ok(db)
    });
    opened.unwrap_or_else(|_| Err(Error::corrupt("database file is damaged")))
}

fn begin_write(db: &Database) -> Result<WriteTransaction> {
    let mut txn = db.begin_write()?;
    // Writes are infrequent and small; take the extra fsync for redb's most
    // conservative commit protocol.
    txn.set_two_phase_commit(true);
    Ok(txn)
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Moves `from` to `to`, failing with `AlreadyExists` instead of replacing
/// an existing `to`.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn link_no_clobber(from: &Path, to: &Path) -> io::Result<()> {
    match fs::hard_link(from, to) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists && !to.exists() => {
            // Filesystems without hard links: fall back to a checked rename.
            fs::rename(from, to)
        }
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => {
            Err(io::Error::from(io::ErrorKind::AlreadyExists))
        }
        result => result,
    }
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Removes the file on drop.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
struct TempFile(PathBuf);

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
impl Drop for TempFile {
    fn drop(&mut self) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "best-effort temporary-file cleanup; successful rename already removed this path"
        )]
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
impl Unlocked {
    pub(crate) fn keys_for_test(&self) -> &Keys {
        &self.keys
    }
}
