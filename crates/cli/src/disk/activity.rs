//! Activity: what callers asked the daemon, sealed and kept on this device
//! only. Rows are opaque bytes with a time, appended to `activity-<k>.log`
//! chunks in the device directory.
//!
//! The rows have a budget ([`Budget`]): past it the oldest go. The logs are
//! append-only, so a row goes by raising a floor: a sealed floor record says
//! which ids are gone and tallies those that went to stay in budget. A chunk
//! goes once every row in it is under the floor; each chunk opens with a
//! copy of the floor, so the newest floor outlives the chunks before it.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use super::kdf::{self, KEY_LEN};
use super::{Error, Inner, Result, Unlocked};

const AAD_ACTIVITY: &[u8] = b"deadbolt/v2 activity";
const CTX_ACTIVITY: &str = "deadbolt/v2 2026-11-25 activity rows";
/// Records per chunk before the next one starts.
const CHUNK_RECORDS: usize = 512;
const TAG_ROW: u8 = 0;
const TAG_FLOOR: u8 = 1;

/// One stored Activity row, from [`Unlocked::activity_list`].
#[derive(Debug)]
pub struct ActivityRow {
    pub id: u64,
    pub bytes: Zeroizing<Vec<u8>>,
}

/// How much Activity may hold: past either limit the oldest rows go.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub rows: u64,
    /// Sealed bytes, as stored.
    pub bytes: u64,
}

/// Rows that went to keep Activity in its [`Budget`] (not those that aged
/// out): how many, the id and time of the newest of them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Dropped {
    pub count: u64,
    pub last_id: u64,
    pub last_time: u64,
}

/// A page of [`Unlocked::activity_list`].
#[derive(Debug, Default)]
pub struct ActivityPage {
    pub rows: Vec<ActivityRow>,
    /// When the page reached the oldest row kept, and rows went before it
    /// to stay in budget.
    pub dropped: Option<Dropped>,
}

struct Row {
    id: u64,
    time: u64,
    size: u64,
    chunk: u64,
}

/// What the chunks hold, read once per unlock.
pub(super) struct Index {
    rows: Vec<Row>,
    floor: u64,
    dropped: Dropped,
    bytes: u64,
    next_id: u64,
    chunk: u64,
    in_chunk: usize,
}

enum Record {
    Row { id: u64, time: u64, bytes: Zeroizing<Vec<u8>> },
    Floor { floor: u64, dropped: Dropped },
}

fn words(plain: &[u8], n: usize) -> Option<Vec<u64>> {
    (0..n)
        .map(|i| Some(u64::from_be_bytes(plain.get(i * 8..i * 8 + 8)?.try_into().ok()?)))
        .collect()
}

impl Unlocked {
    fn activity_key(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(blake3::derive_key(CTX_ACTIVITY, self.root.as_ref()))
    }

    fn aad(chunk: u64) -> Vec<u8> {
        [AAD_ACTIVITY, &chunk.to_be_bytes()].concat()
    }

    fn seal_record(&self, chunk: u64, record: &Record) -> Result<Vec<u8>> {
        let mut plain = Zeroizing::new(Vec::new());
        match record {
            Record::Row { id, time, bytes } => {
                plain.push(TAG_ROW);
                plain.extend_from_slice(&id.to_be_bytes());
                plain.extend_from_slice(&time.to_be_bytes());
                plain.extend_from_slice(bytes);
            }
            Record::Floor { floor, dropped } => {
                plain.push(TAG_FLOOR);
                for word in [*floor, dropped.count, dropped.last_id, dropped.last_time] {
                    plain.extend_from_slice(&word.to_be_bytes());
                }
            }
        }
        kdf::seal(&self.activity_key(), &Self::aad(chunk), &plain)
    }

    fn open_record(&self, chunk: u64, sealed: &[u8]) -> Result<Record> {
        let corrupt = || Error::corrupt(format!("activity chunk {chunk} failed authentication"));
        let plain = kdf::open(&self.activity_key(), &Self::aad(chunk), sealed).ok_or_else(corrupt)?;
        let (tag, rest) = plain.split_first().ok_or_else(corrupt)?;
        match *tag {
            TAG_ROW => {
                let w = words(rest, 2).ok_or_else(corrupt)?;
                Ok(Record::Row {
                    id: w[0],
                    time: w[1],
                    bytes: Zeroizing::new(rest[16..].to_vec()),
                })
            }
            TAG_FLOOR => {
                let w = words(rest, 4).ok_or_else(corrupt)?;
                Ok(Record::Floor {
                    floor: w[0],
                    dropped: Dropped {
                        count: w[1],
                        last_id: w[2],
                        last_time: w[3],
                    },
                })
            }
            _ => Err(corrupt()),
        }
    }

    /// Every chunk's records, oldest chunk first.
    fn read_chunks(&self, inner: &Inner) -> Result<Vec<(u64, Vec<Vec<u8>>)>> {
        let mut out = Vec::new();
        for k in inner.device.activity_logs()? {
            out.push((k, inner.device.read_activity(k)?));
        }
        Ok(out)
    }

    fn load_index(&self, inner: &Inner) -> Result<Index> {
        let mut rows = Vec::new();
        let mut seen = BTreeSet::new();
        let (mut floor, mut dropped) = (0, Dropped::default());
        let (mut chunk, mut in_chunk) = (0, 0);
        for (k, records) in self.read_chunks(inner)? {
            (chunk, in_chunk) = (k, records.len());
            for sealed in records {
                match self.open_record(k, &sealed)? {
                    Record::Row { id, time, .. } if seen.insert(id) => rows.push(Row {
                        id,
                        time,
                        size: sealed.len() as u64,
                        chunk: k,
                    }),
                    Record::Row { .. } => {}
                    Record::Floor { floor: f, dropped: d } if f >= floor => (floor, dropped) = (f, d),
                    Record::Floor { .. } => {}
                }
            }
        }
        let next_id = rows.iter().map(|r| r.id + 1).max().unwrap_or(0).max(floor);
        rows.retain(|r| r.id >= floor);
        rows.sort_by_key(|r| r.id);
        let bytes = rows.iter().map(|r| r.size).sum();
        Ok(Index {
            rows,
            floor,
            dropped,
            bytes,
            next_id,
            chunk,
            in_chunk,
        })
    }

    fn append_record(&self, inner: &mut Inner, record: &Record) -> Result<(u64, u64)> {
        let index = inner.activity.as_mut().ok_or_else(|| Error::corrupt("no activity index"))?;
        if index.in_chunk >= CHUNK_RECORDS {
            index.chunk += 1;
            index.in_chunk = 0;
            let floor = Record::Floor {
                floor: index.floor,
                dropped: index.dropped,
            };
            let (k, sealed) = (index.chunk, self.seal_record(index.chunk, &floor)?);
            inner.device.append_activity(k, &sealed)?;
            if let Some(index) = inner.activity.as_mut() {
                index.in_chunk += 1;
            }
        }
        let index = inner.activity.as_mut().ok_or_else(|| Error::corrupt("no activity index"))?;
        let k = index.chunk;
        let sealed = self.seal_record(k, record)?;
        inner.device.append_activity(k, &sealed)?;
        if let Some(index) = inner.activity.as_mut() {
            index.in_chunk += 1;
        }
        Ok((k, sealed.len() as u64))
    }

    fn index<'a>(&self, inner: &'a mut Inner) -> Result<&'a mut Index> {
        if inner.activity.is_none() {
            inner.activity = Some(self.load_index(inner)?);
        }
        inner.activity.as_mut().ok_or_else(|| Error::corrupt("no activity index"))
    }

    /// Appends `rows` (time, bytes), then removes the oldest rows timed
    /// before `keep_from`, and the oldest past `budget`. Returns the new
    /// rows' ids, in order.
    pub fn activity_append<'a>(
        &self,
        rows: impl IntoIterator<Item = (u64, &'a [u8])>,
        keep_from: u64,
        budget: Budget,
    ) -> Result<Vec<u64>> {
        let mut inner = self.inner();
        self.index(&mut inner)?;
        let mut ids = Vec::new();
        for (time, bytes) in rows {
            let id = self.index(&mut inner)?.next_id;
            let record = Record::Row {
                id,
                time,
                bytes: Zeroizing::new(bytes.to_vec()),
            };
            let (chunk, size) = self.append_record(&mut inner, &record)?;
            let index = self.index(&mut inner)?;
            index.next_id += 1;
            index.bytes += size;
            index.rows.push(Row {
                id,
                time,
                size,
                chunk,
            });
            ids.push(id);
        }
        let index = self.index(&mut inner)?;
        let mut moved = false;
        // Rows go in roughly in time order, so the old ones are first. The
        // newest row stays, whatever its size.
        while let Some(first) = index.rows.first() {
            let len = index.rows.len() as u64;
            let aged = first.time < keep_from && !ids.contains(&first.id);
            let over = (len > budget.rows || index.bytes > budget.bytes) && len > 1;
            if !aged && !over {
                break;
            }
            let row = index.rows.remove(0);
            index.bytes = index.bytes.saturating_sub(row.size);
            index.floor = row.id + 1;
            if !aged {
                index.dropped = Dropped {
                    count: index.dropped.count + 1,
                    last_id: row.id,
                    last_time: row.time,
                };
            }
            moved = true;
        }
        if moved {
            let floor = Record::Floor {
                floor: index.floor,
                dropped: index.dropped,
            };
            self.append_record(&mut inner, &floor)?;
            let index = self.index(&mut inner)?;
            let live: BTreeSet<u64> = index.rows.iter().map(|r| r.chunk).collect();
            let current = index.chunk;
            for k in inner.device.activity_logs()? {
                if k < current && !live.contains(&k) {
                    inner.device.delete_activity(k)?;
                }
            }
        }
        Ok(ids)
    }

    /// Rows timed at or after `since` and with ids before `before`, newest
    /// first, at most `limit`.
    pub fn activity_list(&self, since: u64, before: Option<u64>, limit: usize) -> Result<ActivityPage> {
        let mut inner = self.inner();
        let index = self.index(&mut inner)?;
        let mut chosen = Vec::new();
        let mut reached_start = true;
        for row in index.rows.iter().rev().filter(|r| before.is_none_or(|b| r.id < b)) {
            if row.time < since || chosen.len() >= limit {
                reached_start = false;
                break;
            }
            chosen.push((row.id, row.chunk));
        }
        let dropped = (reached_start && chosen.len() < limit)
            .then_some(index.dropped)
            .filter(|d| d.count > 0 && d.last_time >= since && before.is_none_or(|b| d.last_id < b));
        let chunks: BTreeSet<u64> = chosen.iter().map(|(_, k)| *k).collect();
        let mut found: BTreeMap<u64, ActivityRow> = BTreeMap::new();
        for k in chunks {
            for sealed in inner.device.read_activity(k)? {
                if let Record::Row { id, bytes, .. } = self.open_record(k, &sealed)?
                    && chosen.iter().any(|(c, _)| *c == id)
                {
                    found.entry(id).or_insert(ActivityRow { id, bytes });
                }
            }
        }
        Ok(ActivityPage {
            rows: chosen.iter().filter_map(|(id, _)| found.remove(id)).collect(),
            dropped,
        })
    }
}
