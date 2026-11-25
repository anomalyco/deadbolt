//! One vault directory, `<base>/v/<vault>/`, and its crash rules.
//!
//! - **W3 Open** ([`VaultDir::open`]): the highest `gen-<n>.pack` whose
//!   trailer verifies (a pack cut short mid-write is skipped and the one below
//!   used), then `members.log` and **every** `wal-*.log` present, oldest
//!   first, so no frame is lost across an interrupted compaction. Frames the
//!   pack already covers come back too; folding them again is a no-op.
//! - **W5 Compaction** ([`VaultDir::compact`]): write and sync
//!   `gen-(n+1).pack`, then create and sync `wal-(n+1).log` holding the
//!   carried tail, and only then delete every older generation and WAL. A
//!   crash at any step leaves a state W3 opens to the same frames.
//! - **W6 Readers** ([`VaultReader`]) take no lock and see a consistent
//!   snapshot while a writer appends or compacts.
//!
//! Generation numbers only go up, past every `gen-` and `wal-` file seen, so
//! no name is created twice.

use crate::blocks::{BlockReader, Blocks};
use crate::crypto::KEY_LEN;
use crate::error::{Error, Result};
use crate::log;
use crate::names::{
    self, ACTIVITY_PREFIX, ACTIVITY_SUFFIX, GEN_PREFIX, GEN_SUFFIX, MEMBERS_LOG, WAL_PREFIX,
    WAL_SUFFIX, numbered,
};
use crate::objects;
use crate::pack::{self, PackInput, PackReader, PackSummary};

/// What the writer found on open.
pub struct Loaded<R> {
    /// The generation in use, if any pack verified.
    pub generation: Option<u64>,
    pub pack: Option<PackReader<R>>,
    pub pack_hash: Option<[u8; 32]>,
    /// Newer packs that failed to verify and were passed over.
    pub skipped: Vec<u64>,
    pub members: Vec<Vec<u8>>,
    /// Records of every WAL, oldest generation first.
    pub wal: Vec<Vec<u8>>,
}

/// The single writer of one vault directory. Holds `LOCK` while it lives.
pub struct VaultDir<B: Blocks> {
    blocks: B,
    _lock: B::Lock,
    generation: Option<u64>,
    next_gen: u64,
}

impl<B: Blocks> VaultDir<B> {
    /// Takes the writer lock and opens the directory (W3), cutting torn tails
    /// off every log (W4).
    pub fn open(blocks: B) -> Result<(Self, Loaded<B::Reader>)> {
        let lock = blocks.try_lock_writer()?;
        let gens = numbered(&blocks, GEN_PREFIX, GEN_SUFFIX)?;
        let wals = numbered(&blocks, WAL_PREFIX, WAL_SUFFIX)?;
        let mut skipped = Vec::new();
        let mut chosen = None;
        for &n in gens.iter().rev() {
            match open_verified(&blocks, n) {
                Ok(found) => {
                    chosen = Some((n, found));
                    break;
                }
                Err(err) if is_bad_pack(&err) => skipped.push(n),
                Err(err) => return Err(err),
            }
        }
        let newest = gens
            .last()
            .into_iter()
            .chain(wals.last())
            .copied()
            .max()
            .unwrap_or(0);
        let next_gen = newest
            .checked_add(1)
            .ok_or(Error::InvalidInput("generation overflow"))?;
        let members = log::recover(&blocks, MEMBERS_LOG)?;
        let mut wal = Vec::new();
        for &n in &wals {
            wal.extend(log::recover(&blocks, &names::wal_log(n))?);
        }
        for k in numbered(&blocks, ACTIVITY_PREFIX, ACTIVITY_SUFFIX)? {
            log::recover(&blocks, &names::activity_log(k))?;
        }
        let (generation, pack, pack_hash) = match chosen {
            Some((n, (reader, hash))) => (Some(n), Some(reader), Some(hash)),
            None => (None, None, None),
        };
        let dir = Self {
            blocks,
            _lock: lock,
            generation,
            next_gen,
        };
        Ok((
            dir,
            Loaded {
                generation,
                pack,
                pack_hash,
                skipped,
                members,
                wal,
            },
        ))
    }

    pub fn blocks(&self) -> &B {
        &self.blocks
    }

    pub fn generation(&self) -> Option<u64> {
        self.generation
    }

    /// The generation the next [`VaultDir::compact`] writes.
    pub fn next_generation(&self) -> u64 {
        self.next_gen
    }

    /// The WAL new frames go to.
    pub fn active_wal(&self) -> String {
        names::wal_log(self.generation.unwrap_or(0))
    }

    pub fn append_member(&self, frame: &[u8]) -> Result<u64> {
        log::append(&self.blocks, MEMBERS_LOG, frame)
    }

    pub fn append_wal(&self, frame: &[u8]) -> Result<u64> {
        log::append(&self.blocks, &self.active_wal(), frame)
    }

    /// W5. `input` must cover every frame the directory holds except
    /// `carried`, which starts the new WAL. `input.generation` is set to
    /// [`VaultDir::next_generation`].
    pub fn compact(
        &mut self,
        mut input: PackInput,
        epoch_key: &[u8; KEY_LEN],
        carried: &[Vec<u8>],
    ) -> Result<PackSummary> {
        let m = self.next_gen;
        input.generation = m;
        // 1. The new pack, synced.
        let summary = pack::write(&self.blocks, &names::gen_pack(m), &input, epoch_key)?;
        // 2. The new WAL with the carried tail, synced in one write: torn, it
        //    is cut back on open, and the old WAL still holds those frames.
        let mut tail = Vec::new();
        for frame in carried {
            tail.extend(log::encode(frame)?);
        }
        self.blocks.create_new(&names::wal_log(m), &tail)?;
        self.generation = Some(m);
        self.next_gen = m + 1;
        // 3. Everything older, including packs a crash left unverifiable.
        for n in numbered(&self.blocks, GEN_PREFIX, GEN_SUFFIX)?
            .into_iter()
            .filter(|&n| n < m)
        {
            self.blocks.delete(&names::gen_pack(n))?;
        }
        for n in numbered(&self.blocks, WAL_PREFIX, WAL_SUFFIX)?
            .into_iter()
            .filter(|&n| n < m)
        {
            self.blocks.delete(&names::wal_log(n))?;
        }
        Ok(summary)
    }

    pub fn put_blob(&self, bytes: &[u8]) -> Result<[u8; 32]> {
        objects::put_blob(&self.blocks, bytes)
    }

    pub fn get_blob(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        objects::get_blob(&self.blocks, hash)
    }

    pub fn list_outbox(&self) -> Result<Vec<String>> {
        objects::list_outbox(&self.blocks)
    }

    pub fn read_outbox(&self, name: &str) -> Result<Vec<u8>> {
        self.blocks.read_all(name)
    }

    pub fn delete_outbox(&self, name: &str) -> Result<bool> {
        self.blocks.delete(name)
    }

    pub fn append_activity(&self, k: u64, sealed: &[u8]) -> Result<u64> {
        log::append(&self.blocks, &names::activity_log(k), sealed)
    }

    pub fn read_activity(&self, k: u64) -> Result<Vec<Vec<u8>>> {
        log::read(&self.blocks, &names::activity_log(k))
    }

    pub fn activity_logs(&self) -> Result<Vec<u64>> {
        numbered(&self.blocks, ACTIVITY_PREFIX, ACTIVITY_SUFFIX)
    }

    /// Drops one activity log (retention).
    pub fn delete_activity(&self, k: u64) -> Result<bool> {
        self.blocks.delete(&names::activity_log(k))
    }
}

fn open_verified<B: Blocks>(blocks: &B, n: u64) -> Result<(PackReader<B::Reader>, [u8; 32])> {
    let name = names::gen_pack(n);
    let reader = PackReader::open(blocks, &name)?;
    let hash = reader.verify_trailer()?;
    if reader.header().generation != n {
        return Err(Error::corrupt_pack(
            &name,
            "generation does not match the name",
        ));
    }
    Ok((reader, hash))
}

fn is_bad_pack(err: &Error) -> bool {
    matches!(err, Error::CorruptPack { .. } | Error::OutOfRange { .. })
}

/// How many times [`VaultReader::open`] starts over when a compaction
/// deletes a file between listing and opening it.
const READER_ATTEMPTS: usize = 16;

/// A lock-free snapshot of one vault directory (W6): open handles on the
/// newest verified pack, `members.log` and every WAL, taken WALs first so the
/// pack is never older than the WALs beside it. A writer may append, compact
/// and delete underneath; the handles keep reading what they opened.
pub struct VaultReader<R> {
    pack: Option<PackReader<R>>,
    members: Option<R>,
    wals: Vec<(u64, R)>,
}

impl<R: BlockReader> VaultReader<R> {
    pub fn open<B: Blocks<Reader = R>>(blocks: &B) -> Result<Self> {
        let mut last = None;
        for _ in 0..READER_ATTEMPTS {
            match Self::try_open(blocks) {
                Ok(reader) => return Ok(reader),
                Err(err) if err.is_not_found() => last = Some(err),
                Err(err) => return Err(err),
            }
        }
        Err(last.unwrap_or_else(|| Error::not_found(MEMBERS_LOG)))
    }

    fn try_open<B: Blocks<Reader = R>>(blocks: &B) -> Result<Self> {
        let mut wals = Vec::new();
        for n in numbered(blocks, WAL_PREFIX, WAL_SUFFIX)? {
            wals.push((n, blocks.open_read(&names::wal_log(n))?));
        }
        let members = match blocks.open_read(MEMBERS_LOG) {
            Ok(reader) => Some(reader),
            Err(err) if err.is_not_found() => None,
            Err(err) => return Err(err),
        };
        let mut pack = None;
        for n in numbered(blocks, GEN_PREFIX, GEN_SUFFIX)?.into_iter().rev() {
            match open_verified(blocks, n) {
                Ok((reader, _)) => {
                    pack = Some(reader);
                    break;
                }
                // Cut short or still being written: fall back a generation.
                Err(err) if is_bad_pack(&err) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(Self {
            pack,
            members,
            wals,
        })
    }

    pub fn pack(&self) -> Option<&PackReader<R>> {
        self.pack.as_ref()
    }

    pub fn members(&self) -> Result<Vec<Vec<u8>>> {
        match &self.members {
            Some(reader) => log::read_from(MEMBERS_LOG, reader),
            None => Ok(Vec::new()),
        }
    }

    /// Every complete WAL record, oldest generation first.
    pub fn wal(&self) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for (n, reader) in &self.wals {
            out.extend(log::read_from(&names::wal_log(*n), reader)?);
        }
        Ok(out)
    }

    /// Generations of the WALs this snapshot holds.
    pub fn wal_generations(&self) -> Vec<u64> {
        self.wals.iter().map(|(n, _)| *n).collect()
    }
}
