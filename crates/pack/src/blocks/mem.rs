//! [`MemBlocks`]: pure in-memory [`Blocks`] for wasm32 hosts and tests, with
//! fault injection. [`MemBlocks::crash_at`] cuts the power during the n-th
//! mutating call, landing none, some or all of its bytes;
//! [`MemBlocks::reboot`] then returns the surviving bytes as a fresh
//! instance, the way the next process would find them on disk.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::{BlockReader, Blocks, check_name, slice, split_prefix};
use crate::error::{Error, Result};

/// One read a [`MemReader`] served, for asserting what a reader touched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadOp {
    pub name: String,
    pub offset: u64,
    pub len: u64,
}

#[derive(Clone, Copy, Debug)]
struct Crash {
    at_op: u64,
    keep: Option<usize>,
}

/// What happens to a mutating call.
enum Fate {
    Whole,
    /// The power fails during it. `None`: nothing lands. `Some(n)`: the
    /// first `n` bytes of a write land (a delete or truncate completes).
    Crash(Option<usize>),
}

#[derive(Default)]
struct Inner {
    files: BTreeMap<String, Arc<Vec<u8>>>,
    locked: bool,
    crashed: bool,
    ops: u64,
    crash: Option<Crash>,
    reads: Vec<ReadOp>,
}

impl Inner {
    fn alive(&self) -> Result<()> {
        if self.crashed {
            Err(Error::Crashed)
        } else {
            Ok(())
        }
    }

    fn step(&mut self) -> Result<Fate> {
        self.alive()?;
        let op = self.ops;
        self.ops += 1;
        match self.crash {
            Some(crash) if crash.at_op == op => {
                self.crashed = true;
                Ok(Fate::Crash(crash.keep))
            }
            _ => Ok(Fate::Whole),
        }
    }
}

/// In-memory files. Clones share the same files.
#[derive(Clone, Default)]
pub struct MemBlocks {
    inner: Arc<Mutex<Inner>>,
}

impl MemBlocks {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Cut the power during mutating call number `op` (0-based, counted by
    /// [`MemBlocks::ops`]). With `keep = Some(n)` the first `n` bytes of a
    /// write land, and a delete or truncate completes; with `None` nothing
    /// lands. That call and every later one return [`Error::Crashed`].
    pub fn crash_at(&self, op: u64, keep: Option<usize>) {
        self.lock().crash = Some(Crash { at_op: op, keep });
    }

    /// Mutating calls so far (create, append, delete, truncate).
    pub fn ops(&self) -> u64 {
        self.lock().ops
    }

    pub fn crashed(&self) -> bool {
        self.lock().crashed
    }

    /// The bytes that survived, as a new instance with no lock held, no
    /// faults planned and fresh counters.
    pub fn reboot(&self) -> MemBlocks {
        let files = self.lock().files.clone();
        let fresh = MemBlocks::new();
        fresh.lock().files = files;
        fresh
    }

    pub fn file(&self, name: &str) -> Option<Vec<u8>> {
        self.lock().files.get(name).map(|bytes| bytes.to_vec())
    }

    pub fn names(&self) -> Vec<String> {
        self.lock().files.keys().cloned().collect()
    }

    /// Replaces a file's bytes outside the W1 rules, to stage damage.
    pub fn put_raw(&self, name: &str, bytes: &[u8]) {
        self.lock()
            .files
            .insert(name.to_owned(), Arc::new(bytes.to_vec()));
    }

    /// Removes a file outside the W1 rules, to stage damage.
    pub fn remove_raw(&self, name: &str) -> Option<Vec<u8>> {
        self.lock().files.remove(name).map(|bytes| bytes.to_vec())
    }

    /// Flips one bit of a file in place, to stage damage.
    pub fn flip_bit(&self, name: &str, offset: usize, bit: u8) {
        let mut inner = self.lock();
        if let Some(byte) = inner
            .files
            .get_mut(name)
            .and_then(|f| Arc::make_mut(f).get_mut(offset))
        {
            *byte ^= 1 << (bit & 7);
        }
    }

    /// Reads served since the last call.
    pub fn take_reads(&self) -> Vec<ReadOp> {
        std::mem::take(&mut self.lock().reads)
    }
}

impl Blocks for MemBlocks {
    type Reader = MemReader;
    type Lock = MemLock;

    fn create_new(&self, name: &str, bytes: &[u8]) -> Result<()> {
        check_name(name)?;
        let mut inner = self.lock();
        inner.alive()?;
        if inner.files.contains_key(name) {
            return Err(Error::AlreadyExists {
                name: name.to_owned(),
            });
        }
        match inner.step()? {
            Fate::Whole => {
                inner
                    .files
                    .insert(name.to_owned(), Arc::new(bytes.to_vec()));
                Ok(())
            }
            Fate::Crash(keep) => {
                if let Some(n) = keep {
                    let landed = bytes[..n.min(bytes.len())].to_vec();
                    inner.files.insert(name.to_owned(), Arc::new(landed));
                }
                Err(Error::Crashed)
            }
        }
    }

    fn append_sync(&self, name: &str, bytes: &[u8]) -> Result<u64> {
        check_name(name)?;
        let mut inner = self.lock();
        let fate = inner.step()?;
        let landed = match fate {
            Fate::Whole => bytes,
            Fate::Crash(None) => return Err(Error::Crashed),
            Fate::Crash(Some(n)) => &bytes[..n.min(bytes.len())],
        };
        let file = inner.files.entry(name.to_owned()).or_default();
        let offset = file.len() as u64;
        Arc::make_mut(file).extend_from_slice(landed);
        match fate {
            Fate::Whole => Ok(offset),
            Fate::Crash(_) => Err(Error::Crashed),
        }
    }

    fn open_read(&self, name: &str) -> Result<MemReader> {
        check_name(name)?;
        let inner = self.lock();
        inner.alive()?;
        let data = inner
            .files
            .get(name)
            .cloned()
            .ok_or_else(|| Error::not_found(name))?;
        Ok(MemReader {
            name: name.to_owned(),
            data,
            blocks: self.clone(),
        })
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let (dir, file) = split_prefix(prefix)?;
        let inner = self.lock();
        inner.alive()?;
        Ok(inner
            .files
            .keys()
            .filter(|name| {
                name.strip_prefix(dir)
                    .is_some_and(|rest| rest.starts_with(file) && !rest.contains('/'))
            })
            .cloned()
            .collect())
    }

    fn delete(&self, name: &str) -> Result<bool> {
        check_name(name)?;
        let mut inner = self.lock();
        match inner.step()? {
            Fate::Whole => Ok(inner.files.remove(name).is_some()),
            Fate::Crash(None) => Err(Error::Crashed),
            Fate::Crash(Some(_)) => {
                inner.files.remove(name);
                Err(Error::Crashed)
            }
        }
    }

    fn truncate_tail(&self, name: &str, len: u64) -> Result<()> {
        check_name(name)?;
        let mut inner = self.lock();
        inner.alive()?;
        let current = inner
            .files
            .get(name)
            .ok_or_else(|| Error::not_found(name))?
            .len();
        let keep = usize::try_from(len).ok().filter(|&keep| keep <= current);
        let Some(keep) = keep else {
            return Err(Error::InvalidTruncate {
                name: name.to_owned(),
                len,
            });
        };
        let fate = inner.step()?;
        if let Fate::Crash(None) = fate {
            return Err(Error::Crashed);
        }
        if let Some(file) = inner.files.get_mut(name) {
            Arc::make_mut(file).truncate(keep);
        }
        match fate {
            Fate::Whole => Ok(()),
            Fate::Crash(_) => Err(Error::Crashed),
        }
    }

    fn try_lock_writer(&self) -> Result<MemLock> {
        let mut inner = self.lock();
        inner.alive()?;
        if inner.locked {
            return Err(Error::Locked);
        }
        inner.locked = true;
        Ok(MemLock {
            blocks: self.clone(),
        })
    }
}

/// The writer lock on a [`MemBlocks`]; released on drop.
pub struct MemLock {
    blocks: MemBlocks,
}

impl Drop for MemLock {
    fn drop(&mut self) {
        self.blocks.lock().locked = false;
    }
}

/// A snapshot of one file as it was when opened, like an open handle on an
/// immutable file. Every read is logged ([`MemBlocks::take_reads`]).
pub struct MemReader {
    name: String,
    data: Arc<Vec<u8>>,
    blocks: MemBlocks,
}

impl MemReader {
    fn log(&self, offset: u64, len: u64) {
        self.blocks.lock().reads.push(ReadOp {
            name: self.name.clone(),
            offset,
            len,
        });
    }
}

impl BlockReader for MemReader {
    fn size(&self) -> Result<u64> {
        Ok(self.data.len() as u64)
    }

    fn read_range(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let bytes = slice(&self.name, &self.data, offset, len)?.to_vec();
        self.log(offset, len as u64);
        Ok(bytes)
    }

    fn read_all(&self) -> Result<Vec<u8>> {
        self.log(0, self.data.len() as u64);
        Ok(self.data.to_vec())
    }
}
