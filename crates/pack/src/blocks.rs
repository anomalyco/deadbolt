//! Storage rule W1 at the trait boundary: a [`Blocks`] can create a file
//! that doesn't exist yet, append to one, read, list, delete, and cut a torn
//! tail off a log. It has no rename and no overwrite, so there is no
//! rename-on-open failure on Windows, no `move()` gap in OPFS, and no file
//! coordination between an app and its extensions: a file's bytes never change
//! under a reader except by growing at the end.
//!
//! - **W2** [`Blocks::create_new`] and [`Blocks::append_sync`] return only
//!   after the bytes are durable (`sync_all`, `F_FULLFSYNC` on Apple).
//! - **W6** Reads take no lock. A [`Blocks::Reader`] is an open handle, so a
//!   reader keeps reading a pack a compacting writer has since deleted.

use crate::error::{Error, Result};

#[cfg(not(target_arch = "wasm32"))]
mod fs;
mod mem;

#[cfg(not(target_arch = "wasm32"))]
pub use fs::{FsBlocks, FsLock, FsReader};
pub use mem::{MemBlocks, MemLock, MemReader, ReadOp};

/// An open, read-only handle on one file.
pub trait BlockReader {
    fn size(&self) -> Result<u64>;
    /// Exactly `len` bytes at `offset`, or [`Error::OutOfRange`].
    fn read_range(&self, offset: u64, len: usize) -> Result<Vec<u8>>;
    fn read_all(&self) -> Result<Vec<u8>>;
}

/// One vault directory's files. Names are `file` or `dir/file` (see
/// [`check_name`]).
pub trait Blocks {
    type Reader: BlockReader;
    /// Held by the single writer; dropping it releases the lock.
    type Lock;

    /// Writes a file that must not exist yet ([`Error::AlreadyExists`] if it
    /// does) and syncs it before returning.
    fn create_new(&self, name: &str, bytes: &[u8]) -> Result<()>;
    /// Appends to a file, creating it if missing, and syncs before returning.
    /// Returns the offset the bytes start at.
    fn append_sync(&self, name: &str, bytes: &[u8]) -> Result<u64>;
    fn open_read(&self, name: &str) -> Result<Self::Reader>;
    /// Names starting with `prefix` (which may name a directory, `blob/`),
    /// sorted.
    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>>;
    /// Whether the file existed.
    fn delete(&self, name: &str) -> Result<bool>;
    /// Cuts a file back to `len` bytes and syncs. Only for dropping a torn,
    /// unacknowledged append (W4) on open; it never grows a file.
    fn truncate_tail(&self, name: &str, len: u64) -> Result<()>;
    /// The single writer's lock; [`Error::Locked`] if another writer has it.
    fn try_lock_writer(&self) -> Result<Self::Lock>;

    fn read_all(&self, name: &str) -> Result<Vec<u8>> {
        self.open_read(name)?.read_all()
    }

    fn read_range(&self, name: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.open_read(name)?.read_range(offset, len)
    }
}

/// A name is one or two `/`-separated components of ASCII letters, digits,
/// `.`, `-` and `_`, none starting with `.`.
pub fn check_name(name: &str) -> Result<()> {
    let mut parts = 0;
    for part in name.split('/') {
        parts += 1;
        if parts > 2 || !valid_component(part) {
            return Err(Error::InvalidName {
                name: name.to_owned(),
            });
        }
    }
    Ok(())
}

/// A listing prefix: a valid directory part (with its `/`) and a file-name
/// prefix that may be empty.
pub(crate) fn split_prefix(prefix: &str) -> Result<(&str, &str)> {
    let (dir, file) = match prefix.rfind('/') {
        Some(i) => (&prefix[..=i], &prefix[i + 1..]),
        None => ("", prefix),
    };
    let dir_ok =
        dir.is_empty() || (dir.matches('/').count() == 1 && valid_component(&dir[..dir.len() - 1]));
    let file_ok = file.is_empty() || file.bytes().all(name_byte) && !file.starts_with('.');
    if dir_ok && file_ok {
        Ok((dir, file))
    } else {
        Err(Error::InvalidName {
            name: prefix.to_owned(),
        })
    }
}

fn valid_component(part: &str) -> bool {
    !part.is_empty() && !part.starts_with('.') && part.bytes().all(name_byte)
}

fn name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
}

pub(crate) fn out_of_range(name: &str, offset: u64, len: usize) -> Error {
    Error::OutOfRange {
        name: name.to_owned(),
        offset,
        len: len as u64,
    }
}

/// `bytes[offset..offset + len]`, or [`Error::OutOfRange`].
pub(crate) fn slice<'a>(name: &str, bytes: &'a [u8], offset: u64, len: usize) -> Result<&'a [u8]> {
    usize::try_from(offset)
        .ok()
        .and_then(|start| bytes.get(start..start.checked_add(len)?))
        .ok_or_else(|| out_of_range(name, offset, len))
}
