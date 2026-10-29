//! Native path-based APIs; encrypted records and transactions stay in the parent.
use std::{
    fs::{self, File, OpenOptions},
    io,
    path::Path,
};

use super::*;

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

/// Reads the opaque biometric token enrolled in `dir` without unlocking the
/// store. Returns `Ok(None)` if no biometric key set is enrolled.
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
