//! Append-only framed logs: `members.log`, `wal-<n>.log`, `activity-<k>.log`.
//!
//! ```text
//! record = magic[8] || len u32_le || payload[len] || chk[8]
//! magic  = "DBLG\x02\0\0\0"                 chk = BLAKE3(magic || len_le || payload)[..8]
//! ```
//!
//! **W2** [`append`] returns only after the record is synced: that is the
//! commit point. **W4** On open, a last record that runs past the end of the
//! file, or fails its check with nothing valid after it, is an append that was
//! never acknowledged: the writer cuts it off ([`recover`]) and readers skip it
//! ([`read`]). A bad record with valid records after it is corruption, never
//! a torn append, and is [`Error::CorruptLog`]: the caller quarantines the file
//! and refills it from a replica. Nothing ever truncates past it.
//!
//! A torn append only ever leaves a prefix of a record, so a header with the
//! magic and a sane length that runs past the end is torn as it stands: its
//! payload, which may hold anything (a whole encoded log included), is never
//! searched for records. Only a bad record that fits inside the file is
//! weighed against what follows it, and then only at magic positions, under
//! a hashing budget linear in the file's size ([`scan`]).

use std::collections::HashMap;

use crate::blocks::{BlockReader, Blocks};
use crate::error::{Error, Result};

/// The largest payload a record may carry. A corrupt length prefix can't make
/// a reader allocate more. Includes a maximum 16 MiB frame body, its 145-byte
/// header and 64-byte signature; the CLI checks this against the core frame cap.
pub const MAX_RECORD: usize = 16 * 1024 * 1024 + 209;
/// The sync marker every record starts with.
pub const MAGIC: [u8; 8] = *b"DBLG\x02\0\0\0";
const LEN: usize = 4;
/// Magic and length: the bytes before a record's payload.
pub const HEADER_LEN: usize = MAGIC.len() + LEN;
const CHK: usize = 8;
/// Bytes a record adds around its payload.
pub const RECORD_OVERHEAD: usize = HEADER_LEN + CHK;
/// How many bytes, per byte of log, [`scan`] may hash looking for valid
/// records past a bad one before it calls the log corrupt.
const SEARCH_BUDGET: usize = 4;

fn chk(len_le: &[u8], payload: &[u8]) -> [u8; CHK] {
    #[cfg(test)]
    hash_count::add(payload.len());
    let mut hasher = blake3::Hasher::new();
    hasher.update(&MAGIC);
    hasher.update(len_le);
    hasher.update(payload);
    let hash = hasher.finalize();
    let mut out = [0; CHK];
    out.copy_from_slice(&hash.as_bytes()[..CHK]);
    out
}

/// One framed record.
pub fn encode(payload: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|_| payload.len() <= MAX_RECORD)
        .ok_or(Error::RecordTooLarge {
            len: payload.len(),
            max: MAX_RECORD,
        })?;
    let len_le = len.to_le_bytes();
    let mut out = Vec::with_capacity(RECORD_OVERHEAD + payload.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&len_le);
    out.extend_from_slice(payload);
    out.extend_from_slice(&chk(&len_le, payload));
    Ok(out)
}

/// The header at `at`: whether it starts with the magic, and its length.
/// `None` when fewer than [`HEADER_LEN`] bytes remain.
fn header_at(bytes: &[u8], at: usize) -> Option<(bool, usize)> {
    let header = bytes.get(at..at.checked_add(HEADER_LEN)?)?;
    let (magic, len_le) = header.split_at(MAGIC.len());
    let len = usize::try_from(u32::from_le_bytes(len_le.try_into().ok()?)).ok()?;
    Some((magic == MAGIC, len))
}

/// The end of a record at `at` whose payload is `len` bytes, if it fits.
fn end_of(bytes: &[u8], at: usize, len: usize) -> Option<usize> {
    at.checked_add(RECORD_OVERHEAD)?
        .checked_add(len)
        .filter(|&end| end <= bytes.len())
}

/// Whether `len` makes a complete, valid record at `at` (whatever length
/// the header says): its end, if so.
fn valid_with_len(bytes: &[u8], at: usize, len: usize) -> Option<usize> {
    if len > MAX_RECORD || bytes.get(at..at + MAGIC.len())? != MAGIC {
        return None;
    }
    let end = end_of(bytes, at, len)?;
    let len_le = u32::try_from(len).ok()?.to_le_bytes();
    let payload = &bytes[at + HEADER_LEN..end - CHK];
    (bytes[end - CHK..end] == chk(&len_le, payload)).then_some(end)
}

/// The end of a complete, valid record starting at `at`.
fn record_at(bytes: &[u8], at: usize) -> Option<usize> {
    let (true, len) = header_at(bytes, at)? else {
        return None;
    };
    valid_with_len(bytes, at, len)
}

/// Whether the bytes from `at` on are a torn append as they stand: too few
/// to hold any record, or a sane header whose record runs past the end.
fn torn_as_is(bytes: &[u8], at: usize) -> bool {
    if bytes.len() - at < RECORD_OVERHEAD {
        return true;
    }
    matches!(header_at(bytes, at), Some((true, len)) if len <= MAX_RECORD && end_of(bytes, at, len).is_none())
}

/// What a log holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    pub records: Vec<Vec<u8>>,
    /// Bytes up to the end of the last valid record.
    pub valid_len: u64,
    /// Whether bytes past `valid_len` are a torn, unacknowledged append.
    pub torn: bool,
}

/// Parses a whole log (W4).
pub fn scan(file: &str, bytes: &[u8]) -> Result<Scan> {
    let mut records = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if let Some(end) = record_at(bytes, at) {
            records.push(bytes[at + HEADER_LEN..end - CHK].to_vec());
            at = end;
            continue;
        }
        if valid_after_bad(bytes, at) {
            return Err(Error::CorruptLog {
                file: file.to_owned(),
                offset: at as u64,
            });
        }
        return Ok(Scan {
            records,
            valid_len: at as u64,
            torn: true,
        });
    }
    Ok(Scan {
        records,
        valid_len: at as u64,
        torn: false,
    })
}

/// Whether valid records follow the bad record at `at`, which makes it
/// corruption rather than a torn append.
fn valid_after_bad(bytes: &[u8], at: usize) -> bool {
    let mut search = Search {
        bytes,
        valid: HashMap::new(),
        budget: bytes.len().saturating_mul(SEARCH_BUDGET),
    };
    if torn_as_is(bytes, at) {
        // A torn prefix, unless one flipped bit of its length is all that's
        // wrong with a record that has valid records after it.
        let Some((_, len)) = header_at(bytes, at) else {
            return false;
        };
        return (0..32).any(|bit| {
            valid_with_len(bytes, at, len ^ (1 << bit)).is_some_and(|end| search.chain(end))
        });
    }
    let Some(from) = at.checked_add(1) else {
        return false;
    };
    let last = bytes.len().saturating_sub(RECORD_OVERHEAD);
    let mut candidates = (from..=last).filter(|&p| bytes[p..].starts_with(&MAGIC));
    candidates.any(|p| search.chain(p) || search.spent())
}

/// The bounded search for valid records past a bad one.
struct Search<'a> {
    bytes: &'a [u8],
    /// Record ends found so far, by start, valid or not.
    valid: HashMap<usize, Option<usize>>,
    budget: usize,
}

impl Search<'_> {
    fn spent(&self) -> bool {
        self.budget == 0
    }

    /// The end of a valid record at `at`, hashing only a record whose end
    /// lands where another record (or the end of the file) could start.
    fn record(&mut self, at: usize) -> Option<usize> {
        if let Some(&known) = self.valid.get(&at) {
            return known;
        }
        let bytes = self.bytes;
        let found = header_at(bytes, at)
            .filter(|&(magic, len)| magic && len <= MAX_RECORD)
            .filter(|&(_, len)| {
                end_of(bytes, at, len).is_some_and(|end| {
                    let rest = &bytes[end..];
                    rest.starts_with(&MAGIC) || rest.len() < RECORD_OVERHEAD
                })
            })
            .and_then(|(_, len)| {
                if len > self.budget {
                    self.budget = 0;
                    return None;
                }
                self.budget -= len;
                valid_with_len(bytes, at, len)
            });
        self.valid.insert(at, found);
        found
    }

    /// Whether valid records start at `at` and run, back to back, to the end
    /// of the file or a torn tail, or for at least two records. A spent
    /// budget counts as found: corruption is the answer that loses nothing.
    fn chain(&mut self, at: usize) -> bool {
        let mut count = 0;
        let mut pos = at;
        while let Some(end) = self.record(pos) {
            count += 1;
            pos = end;
            if count >= 2 {
                return true;
            }
        }
        if self.spent() {
            return true;
        }
        count >= 1 && (pos == self.bytes.len() || torn_as_is(self.bytes, pos))
    }
}

/// Appends one record and syncs it (W2). Returns the record's offset.
pub fn append<B: Blocks>(blocks: &B, name: &str, payload: &[u8]) -> Result<u64> {
    blocks.append_sync(name, &encode(payload)?)
}

/// The writer's open: every record, after cutting off a torn tail so the next
/// append starts on a record boundary. A missing log is empty.
pub fn recover<B: Blocks>(blocks: &B, name: &str) -> Result<Vec<Vec<u8>>> {
    let bytes = match blocks.read_all(name) {
        Ok(bytes) => bytes,
        Err(err) if err.is_not_found() => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let scan = scan(name, &bytes)?;
    if scan.torn {
        blocks.truncate_tail(name, scan.valid_len)?;
    }
    Ok(scan.records)
}

/// A lock-free reader's view (W6): every complete record. A torn tail, which
/// may be an append in flight, is skipped and left alone.
pub fn read<B: Blocks>(blocks: &B, name: &str) -> Result<Vec<Vec<u8>>> {
    match blocks.open_read(name) {
        Ok(reader) => read_from(name, &reader),
        Err(err) if err.is_not_found() => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

/// [`read`] from a handle already open.
pub fn read_from<R: BlockReader>(name: &str, reader: &R) -> Result<Vec<Vec<u8>>> {
    Ok(scan(name, &reader.read_all()?)?.records)
}

/// Payload bytes checksummed on this thread, so tests can show a scan's
/// work stays linear.
#[cfg(test)]
pub(crate) mod hash_count {
    use std::cell::Cell;

    thread_local! {
        static HASHED: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn add(len: usize) {
        HASHED.set(HASHED.get() + len);
    }

    /// Payload bytes hashed on this thread since the last call.
    pub(crate) fn take() -> usize {
        HASHED.replace(0)
    }
}
