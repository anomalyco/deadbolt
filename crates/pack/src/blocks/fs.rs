//! [`FsBlocks`]: a vault directory on a real file system.
//!
//! - Create is `O_CREAT | O_EXCL` (`create_new`), append is `O_APPEND`, and
//!   both `sync_all` before returning (W2), then sync the directory on Unix
//!   so the new name is durable too.
//! - On Windows, Rust opens files with `FILE_SHARE_READ | FILE_SHARE_WRITE |
//!   FILE_SHARE_DELETE`, so a reader's open handle never blocks the writer
//!   deleting an old generation, and names are never reused (W6).
//! - `LOCK` holds an advisory exclusive lock for the single writer only. Its
//!   bytes are never written; readers never touch it.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use super::{BlockReader, Blocks, check_name, out_of_range, split_prefix};
use crate::error::{Error, Result};
use crate::names::LOCK;

pub struct FsBlocks {
    root: PathBuf,
    /// Test fault: the next append writes this many bytes, then fails.
    #[cfg(test)]
    fail_append: Mutex<Option<usize>>,
}

impl FsBlocks {
    /// The vault directory at `root`, created if missing.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(io_error(&root.to_string_lossy()))?;
        Ok(Self {
            root,
            #[cfg(test)]
            fail_append: Mutex::new(None),
        })
    }

    /// Makes the next [`Blocks::append_sync`] write only `landed` bytes and
    /// then fail, like a full disk or an I/O error part way through.
    #[cfg(test)]
    pub(crate) fn fail_next_append(&self, landed: usize) {
        *self
            .fail_append
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(landed);
    }

    fn write_append(&self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        if let Some(landed) = self
            .fail_append
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            file.write_all(&bytes[..landed.min(bytes.len())])?;
            return Err(io::Error::other("injected append failure"));
        }
        file.write_all(bytes)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        check_name(name)?;
        let mut path = self.root.clone();
        path.extend(name.split('/'));
        Ok(path)
    }

    /// The directory a new file goes in, created (and made durable) if needed.
    fn parent_of(&self, path: &Path, name: &str) -> Result<PathBuf> {
        let dir = path
            .parent()
            .map_or_else(|| self.root.clone(), Path::to_path_buf);
        if dir != self.root && !dir.is_dir() {
            fs::create_dir_all(&dir).map_err(io_error(name))?;
            sync_dir(&self.root, name)?;
        }
        Ok(dir)
    }
}

impl Blocks for FsBlocks {
    type Reader = FsReader;
    type Lock = FsLock;

    fn create_new(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let path = self.path(name)?;
        let dir = self.parent_of(&path, name)?;
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                return Err(Error::AlreadyExists {
                    name: name.to_owned(),
                });
            }
            Err(err) => return Err(io_error(name)(err)),
        };
        if let Err(err) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            drop(file);
            // Don't leave a half-written file behind a failed (not crashed)
            // write. If this fails too, the next open treats the leftover as a
            // torn write; the caller sees the write's own error either way.
            let _cleanup = fs::remove_file(&path);
            return Err(io_error(name)(err));
        }
        sync_dir(&dir, name)
    }

    fn append_sync(&self, name: &str, bytes: &[u8]) -> Result<u64> {
        let path = self.path(name)?;
        let (mut file, created) = match OpenOptions::new().append(true).open(&path) {
            Ok(file) => (file, false),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                self.parent_of(&path, name)?;
                let file = OpenOptions::new().append(true).create(true).open(&path);
                (file.map_err(io_error(name))?, true)
            }
            Err(err) => return Err(io_error(name)(err)),
        };
        let offset = file.metadata().map_err(io_error(name))?.len();
        if let Err(err) = self
            .write_append(&mut file, bytes)
            .and_then(|()| file.sync_all())
        {
            drop(file);
            // A failed (not crashed) append mustn't leave part of a record
            // behind: the caller retries, and a record appended after junk
            // would read as corruption. Cut back to where this append started,
            // through a plain write handle (an append-only one can't truncate
            // on Windows). If that fails too, the caller still sees the
            // write's own error, and the next writer's open cuts the junk off
            // as a torn tail.
            let _rollback = OpenOptions::new()
                .write(true)
                .open(&path)
                .and_then(|file| file.set_len(offset).and_then(|()| file.sync_all()));
            return Err(io_error(name)(err));
        }
        if created {
            let dir = path
                .parent()
                .map_or_else(|| self.root.clone(), Path::to_path_buf);
            sync_dir(&dir, name)?;
        }
        Ok(offset)
    }

    fn open_read(&self, name: &str) -> Result<FsReader> {
        let file = File::open(self.path(name)?).map_err(io_error(name))?;
        Ok(FsReader {
            name: name.to_owned(),
            file: Mutex::new(file),
        })
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let (dir, file_prefix) = split_prefix(prefix)?;
        let mut path = self.root.clone();
        path.extend(dir.split('/').filter(|part| !part.is_empty()));
        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(io_error(prefix)(err)),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(io_error(prefix))?;
            if !entry.file_type().map_err(io_error(prefix))?.is_file() {
                continue;
            }
            let Some(file) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let name = format!("{dir}{file}");
            if file.starts_with(file_prefix) && name != LOCK && check_name(&name).is_ok() {
                out.push(name);
            }
        }
        out.sort();
        Ok(out)
    }

    fn delete(&self, name: &str) -> Result<bool> {
        let path = self.path(name)?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(io_error(name)(err)),
        }
        let dir = path
            .parent()
            .map_or_else(|| self.root.clone(), Path::to_path_buf);
        sync_dir(&dir, name)?;
        Ok(true)
    }

    fn truncate_tail(&self, name: &str, len: u64) -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .open(self.path(name)?)
            .map_err(io_error(name))?;
        if len > file.metadata().map_err(io_error(name))?.len() {
            return Err(Error::InvalidTruncate {
                name: name.to_owned(),
                len,
            });
        }
        file.set_len(len)
            .and_then(|()| file.sync_all())
            .map_err(io_error(name))
    }

    fn try_lock_writer(&self) -> Result<FsLock> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.root.join(LOCK))
            .map_err(io_error(LOCK))?;
        // A lock stays held for a moment after its writer drops it while a
        // child process spawned elsewhere in this process still has the
        // inherited handle, until its exec closes it. Wait that out briefly.
        for _ in 0..LOCK_TRIES - 1 {
            match file.try_lock() {
                Ok(()) => return Ok(FsLock { _file: file }),
                Err(TryLockError::WouldBlock) => std::thread::sleep(LOCK_WAIT),
                Err(TryLockError::Error(err)) => return Err(io_error(LOCK)(err)),
            }
        }
        match file.try_lock() {
            Ok(()) => Ok(FsLock { _file: file }),
            Err(TryLockError::WouldBlock) => Err(Error::Locked),
            Err(TryLockError::Error(err)) => Err(io_error(LOCK)(err)),
        }
    }
}

/// Attempts at `LOCK` before reporting [`Error::Locked`], `LOCK_WAIT` apart.
const LOCK_TRIES: u32 = 10;
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_millis(10);

/// The writer's exclusive lock on `LOCK`; the OS releases it when this drops
/// (or the process dies).
pub struct FsLock {
    _file: File,
}

/// An open handle: it keeps reading a file a writer has since deleted.
pub struct FsReader {
    name: String,
    file: Mutex<File>,
}

impl BlockReader for FsReader {
    fn size(&self) -> Result<u64> {
        let file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(file.metadata().map_err(io_error(&self.name))?.len())
    }

    fn read_range(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        let mut buf = vec![0; len];
        file.seek(SeekFrom::Start(offset))
            .map_err(io_error(&self.name))?;
        match file.read_exact(&mut buf) {
            Ok(()) => Ok(buf),
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
                Err(out_of_range(&self.name, offset, len))
            }
            Err(err) => Err(io_error(&self.name)(err)),
        }
    }

    fn read_all(&self) -> Result<Vec<u8>> {
        let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        let mut buf = Vec::new();
        file.seek(SeekFrom::Start(0))
            .map_err(io_error(&self.name))?;
        file.read_to_end(&mut buf).map_err(io_error(&self.name))?;
        Ok(buf)
    }
}

fn io_error(name: &str) -> impl FnOnce(io::Error) -> Error + '_ {
    move |source| {
        if source.kind() == ErrorKind::NotFound {
            Error::not_found(name)
        } else {
            Error::Io {
                name: name.to_owned(),
                source,
            }
        }
    }
}

/// Makes a directory entry (a create or a delete) durable.
#[cfg(unix)]
fn sync_dir(dir: &Path, name: &str) -> Result<()> {
    File::open(dir)
        .and_then(|dir| dir.sync_all())
        .map_err(io_error(name))
}

/// Windows has no directory handle to sync; NTFS journals the entry.
#[cfg(not(unix))]
fn sync_dir(_dir: &Path, _name: &str) -> Result<()> {
    Ok(())
}
