//! Append-only framed logs: `members.log`, `wal-<n>.log`, `activity-<k>.log`.
//!
//! ```text
//! record = len u32_le || payload[len] || chk[8]      chk = BLAKE3(len_le || payload)[..8]
//! ```
//!
//! **W2** [`append`] returns only after the record is synced: that is the
//! commit point. **W4** On open, a last record that runs past the end of the
//! file, or fails its check with nothing valid after it, is an append that was
//! never acknowledged: the writer cuts it off ([`recover`]) and readers skip it
//! ([`read`]). A bad record with a valid record anywhere after it is
//! corruption, never a torn append, and is [`Error::CorruptLog`]: the caller
//! quarantines the file and refills it from a replica. Nothing ever truncates
//! past it.

use crate::blocks::{BlockReader, Blocks};
use crate::error::{Error, Result};

/// The largest payload a record may carry. A corrupt length prefix can't make
/// a reader allocate more.
pub const MAX_RECORD: usize = 16 << 20;
const LEN: usize = 4;
const CHK: usize = 8;
/// Bytes a record adds around its payload.
pub const RECORD_OVERHEAD: usize = LEN + CHK;

fn chk(len_le: &[u8], payload: &[u8]) -> [u8; CHK] {
    let mut hasher = blake3::Hasher::new();
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
    out.extend_from_slice(&len_le);
    out.extend_from_slice(payload);
    out.extend_from_slice(&chk(&len_le, payload));
    Ok(out)
}

/// The payload range and end of a complete, valid record starting at `at`.
fn record_at(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let len_le = bytes.get(at..at.checked_add(LEN)?)?;
    let len = usize::try_from(u32::from_le_bytes(len_le.try_into().ok()?)).ok()?;
    if len > MAX_RECORD {
        return None;
    }
    let start = at + LEN;
    let end = start.checked_add(len)?.checked_add(CHK)?;
    let record = bytes.get(at..end)?;
    let payload = &record[LEN..LEN + len];
    (record[LEN + len..] == chk(len_le, payload)).then_some((start, end))
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
        if let Some((start, end)) = record_at(bytes, at) {
            records.push(bytes[start..end - CHK].to_vec());
            at = end;
            continue;
        }
        // A torn append leaves at most one partial record at the very end.
        // Any valid record after this one means the damage is in the middle.
        if (at + 1..bytes.len()).any(|later| record_at(bytes, later).is_some()) {
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
