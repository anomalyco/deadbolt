use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use chacha20poly1305::XChaCha20Poly1305;
use redb::{Database, ReadableDatabase, ReadableTable, Table, TableDefinition, WriteTransaction};
use zeroize::Zeroizing;

use crate::crypto::{self, KEY_LEN, SecretKey};
use crate::error::{Error, Result};
use crate::kdf::{KdfHeader, KdfParams};

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
const H_LOG_LEN: &str = "log_len";

const AAD_KEYSET: &[u8] = b"deadbolt-store/v1/keyset";
const AAD_LOG: &[u8] = b"deadbolt-store/v1/log";
const AAD_LOG_LEN: &[u8] = b"deadbolt-store/v1/log-len";
const AAD_META: &[u8] = b"deadbolt-store/v1/meta";

const CTX_DATA: &str = "deadbolt-store v1 2026-10-15 data encryption";
const CTX_META_INDEX: &str = "deadbolt-store v1 2026-10-15 meta key blinding";

const CACHE_BYTES: usize = 16 * 1024 * 1024;

/// Returns true if `dir` contains a store.
pub fn is_initialized(dir: &Path) -> bool {
    dir.join(DB_FILE).is_file()
}

/// Creates a new store in `dir` with [`KdfParams::DEFAULT`] and returns it
/// unlocked. See [`init_with_params`].
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
        let txn = begin_write(&db)?;
        {
            let mut header = txn.open_table(HEADER)?;
            header.insert(H_FORMAT, FORMAT_VERSION.to_le_bytes().as_slice())?;
            header.insert(H_KDF, kdf.encode().as_slice())?;
            header.insert(H_KEYSET, wrapped.as_slice())?;
            write_log_len(&keys, &mut header, 0)?;
            txn.open_table(LOG)?;
            txn.open_table(META)?;
        }
        txn.commit()?;
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
//
// OS keychain unlock (design.md, "Keys"): store a second copy of the key set
// under a header slot such as "keyset.keychain", wrapped with a random 256-bit
// key that lives in a device-only, biometry-gated keychain item, and add an
// `unlock_with_keychain(dir, key)` that tries that slot. `change_passphrase`
// would leave that slot untouched; removing the keychain item drops the slot.
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
    /// The 32-byte device secret (Ed25519 seed) given to [`init`].
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
        }
        txn.commit()?;
        Ok(())
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

fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Moves `from` to `to`, failing with `AlreadyExists` instead of replacing
/// an existing `to`.
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

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Removes the file on drop.
struct TempFile(PathBuf);

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
