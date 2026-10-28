//! The Activity table: what callers asked the agent, sealed like everything
//! else and kept on this device only. Rows are opaque bytes with a time.
//!
//! The table has a budget ([`Budget`]): past it the oldest rows go, and a
//! sealed tally in `meta` (`"activity"`) counts them, so a listing that
//! reaches the oldest row can say how many came before it.

use redb::{
    ReadableDatabase, ReadableTable, ReadableTableMetadata, Table, TableDefinition, TableError,
};
use zeroize::Zeroizing;

use super::{Keys, META, Unlocked, begin_write, meta_aad};
use crate::crypto;
use crate::error::{Error, Result};

// id (increasing, from 0) -> seal(time u64 LE ‖ bytes)
pub(crate) const ACTIVITY: TableDefinition<u64, &[u8]> = TableDefinition::new("activity");

const AAD_ACTIVITY: &[u8] = b"deadbolt-store/v1/activity";
/// The `meta` name of the table's tally.
const TALLY: &str = "activity";

/// One stored Activity row, from [`Unlocked::activity_list`].
#[derive(Debug)]
pub struct ActivityRow {
    pub id: u64,
    /// Whatever time the row was appended with (Unix seconds, by convention).
    pub time: u64,
    pub bytes: Zeroizing<Vec<u8>>,
}

/// How much the table may hold: past either limit the oldest rows go.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub rows: u64,
    /// Sealed bytes, as stored.
    pub bytes: u64,
}

/// Rows that went to keep the table in its [`Budget`] (not those that aged
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

/// The table's sealed bytes, and what went to stay in budget.
#[derive(Default)]
struct Tally {
    bytes: u64,
    dropped: Dropped,
}

impl Tally {
    fn read(
        keys: &Keys,
        meta: &impl ReadableTable<&'static [u8; 32], &'static [u8]>,
    ) -> Result<Option<Tally>> {
        let blinded = keys.meta_blind(TALLY);
        let Some(sealed) = meta.get(&blinded)? else {
            return Ok(None);
        };
        let corrupt = || Error::corrupt("the activity tally failed authentication");
        let plain =
            crypto::open(&keys.data, &meta_aad(&blinded), sealed.value()).ok_or_else(corrupt)?;
        let word = |i: usize| -> Result<u64> {
            let bytes: [u8; 8] = plain
                .get(i * 8..i * 8 + 8)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(corrupt)?;
            Ok(u64::from_le_bytes(bytes))
        };
        Ok(Some(Tally {
            bytes: word(0)?,
            dropped: Dropped {
                count: word(1)?,
                last_id: word(2)?,
                last_time: word(3)?,
            },
        }))
    }

    fn write(&self, keys: &Keys, meta: &mut Table<&'static [u8; 32], &'static [u8]>) -> Result<()> {
        let blinded = keys.meta_blind(TALLY);
        let plain = [
            self.bytes,
            self.dropped.count,
            self.dropped.last_id,
            self.dropped.last_time,
        ]
        .map(u64::to_le_bytes)
        .concat();
        let sealed = crypto::seal(&keys.data, &meta_aad(&blinded), &[&plain])?;
        meta.insert(&blinded, sealed.as_slice())?;
        Ok(())
    }
}

impl Unlocked {
    /// Appends `rows` (time, bytes) in one transaction, then removes the
    /// oldest rows timed before `keep_from`, and the oldest past `budget`.
    /// Returns the new rows' ids, in order.
    pub fn activity_append<'a>(
        &self,
        rows: impl IntoIterator<Item = (u64, &'a [u8])>,
        keep_from: u64,
        budget: Budget,
    ) -> Result<Vec<u64>> {
        let txn = begin_write(&self.db)?;
        let ids = {
            let mut table = txn.open_table(ACTIVITY)?;
            let mut meta = txn.open_table(META)?;
            let mut tally = match Tally::read(&self.keys, &meta)? {
                Some(tally) => tally,
                None => Tally {
                    bytes: sealed_bytes(&table)?,
                    dropped: Dropped::default(),
                },
            };
            let first = table.last()?.map_or(0, |(id, _)| id.value() + 1);
            let mut ids = Vec::new();
            for (id, (time, bytes)) in (first..).zip(rows) {
                let row = crypto::seal(
                    &self.keys.data,
                    &activity_aad(id),
                    &[&time.to_le_bytes(), bytes],
                )?;
                table.insert(id, row.as_slice())?;
                tally.bytes += row.len() as u64;
                ids.push(id);
            }
            // Rows go in roughly in time order, so the old ones are first.
            // The newest row stays, whatever its size.
            loop {
                let len = table.len()?;
                let Some((id, time, size)) = table
                    .first()?
                    .map(|(id, sealed)| {
                        let id = id.value();
                        let size = sealed.value().len() as u64;
                        open_row(&self.keys, id, sealed.value()).map(|(time, _)| (id, time, size))
                    })
                    .transpose()?
                else {
                    break;
                };
                let aged = time < keep_from && !ids.contains(&id);
                let over = (len > budget.rows || tally.bytes > budget.bytes) && len > 1;
                if !aged && !over {
                    break;
                }
                table.remove(id)?;
                tally.bytes = tally.bytes.saturating_sub(size);
                if !aged {
                    tally.dropped = Dropped {
                        count: tally.dropped.count + 1,
                        last_id: id,
                        last_time: time,
                    };
                }
            }
            tally.write(&self.keys, &mut meta)?;
            ids
        };
        txn.commit()?;
        Ok(ids)
    }

    /// Rows timed at or after `since` and with ids before `before`, newest
    /// first, at most `limit`.
    pub fn activity_list(
        &self,
        since: u64,
        before: Option<u64>,
        limit: usize,
    ) -> Result<ActivityPage> {
        let txn = self.db.begin_read()?;
        let table = match txn.open_table(ACTIVITY) {
            Ok(table) => table,
            // A store made before Activity existed has no table yet.
            Err(TableError::TableDoesNotExist(_)) => return Ok(ActivityPage::default()),
            Err(e) => return Err(e.into()),
        };
        let mut page = ActivityPage::default();
        let mut reached_start = true;
        for row in table.range(..before.unwrap_or(u64::MAX))?.rev() {
            let (id, sealed) = row?;
            let id = id.value();
            let (time, bytes) = open_row(&self.keys, id, sealed.value())?;
            if time < since || page.rows.len() >= limit {
                reached_start = false;
                break;
            }
            page.rows.push(ActivityRow { id, time, bytes });
        }
        if reached_start && page.rows.len() < limit {
            let tally = Tally::read(&self.keys, &txn.open_table(META)?)?;
            page.dropped = tally.map(|t| t.dropped).filter(|d| {
                d.count > 0 && d.last_time >= since && before.is_none_or(|b| d.last_id < b)
            });
        }
        Ok(page)
    }
}

fn sealed_bytes(table: &impl ReadableTable<u64, &'static [u8]>) -> Result<u64> {
    let mut bytes = 0;
    for row in table.iter()? {
        bytes += row?.1.value().len() as u64;
    }
    Ok(bytes)
}

fn open_row(keys: &Keys, id: u64, sealed: &[u8]) -> Result<(u64, Zeroizing<Vec<u8>>)> {
    let corrupt = || Error::corrupt(format!("activity row {id} failed authentication"));
    let plain = crypto::open(&keys.data, &activity_aad(id), sealed).ok_or_else(corrupt)?;
    let time: [u8; 8] = plain
        .get(..8)
        .and_then(|t| t.try_into().ok())
        .ok_or_else(corrupt)?;
    Ok((
        u64::from_le_bytes(time),
        Zeroizing::new(plain[8..].to_vec()),
    ))
}

fn activity_aad(id: u64) -> Vec<u8> {
    [AAD_ACTIVITY, &id.to_be_bytes()].concat()
}

#[cfg(test)]
mod tests {
    use super::{Budget, Dropped};
    use crate::KdfParams;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };
    const ROOMY: Budget = Budget {
        rows: 1_000,
        bytes: 1 << 20,
    };

    fn times(store: &crate::Unlocked) -> Vec<u64> {
        let page = store.activity_list(0, None, 100).unwrap();
        page.rows.iter().map(|r| r.time).collect()
    }

    #[test]
    fn rows_list_newest_first_and_old_ones_go() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::init_with_params(dir.path(), b"pass", [1; 32], FAST).unwrap();
        assert!(store.activity_list(0, None, 10).unwrap().rows.is_empty());
        let ids = store
            .activity_append([(10, &b"a"[..]), (20, b"b"), (30, b"c")], 0, ROOMY)
            .unwrap();
        assert_eq!(ids, [0, 1, 2]);
        let page = store.activity_list(15, None, 10).unwrap();
        let seen: Vec<_> = page
            .rows
            .iter()
            .map(|r| (r.id, r.time, &r.bytes[..]))
            .collect();
        assert_eq!(seen, [(2, 30, &b"c"[..]), (1, 20, b"b")]);
        assert_eq!(store.activity_list(0, None, 1).unwrap().rows.len(), 1);
        // Pages go back by id.
        let older = store.activity_list(0, Some(2), 10).unwrap();
        let ids: Vec<_> = older.rows.iter().map(|r| r.id).collect();
        assert_eq!(ids, [1, 0]);

        // Keeping from 25 drops the rows at 10 and 20; ids keep increasing.
        assert_eq!(
            store.activity_append([(40, &b"d"[..])], 25, ROOMY).unwrap(),
            [3]
        );
        assert_eq!(times(&store), [40, 30]);
        assert_eq!(
            store.activity_list(0, None, 10).unwrap().dropped,
            None,
            "aged out, not dropped"
        );
        drop(store);

        let store = crate::unlock(dir.path(), b"pass").unwrap();
        assert_eq!(store.activity_list(0, None, 10).unwrap().rows.len(), 2);
    }

    /// Past its row or byte budget the table drops its oldest rows, and the
    /// listing that reaches the oldest one kept says how many went.
    #[test]
    fn the_table_keeps_to_its_budget() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::init_with_params(dir.path(), b"pass", [1; 32], FAST).unwrap();
        let three = Budget {
            rows: 3,
            bytes: 1 << 20,
        };
        for time in 1..=5 {
            store
                .activity_append([(time, &b"row"[..])], 0, three)
                .unwrap();
        }
        assert_eq!(times(&store), [5, 4, 3]);
        let page = store.activity_list(0, None, 10).unwrap();
        let dropped = Dropped {
            count: 2,
            last_id: 1,
            last_time: 2,
        };
        assert_eq!(page.dropped, Some(dropped));
        // Only the page that reaches the oldest row says so.
        assert_eq!(store.activity_list(0, None, 2).unwrap().dropped, None);
        assert_eq!(
            store.activity_list(0, Some(3), 2).unwrap().dropped,
            Some(dropped)
        );
        assert_eq!(store.activity_list(3, None, 10).unwrap().dropped, None);

        // Each sealed row of 100 bytes is 148 stored: 400 bytes keep two.
        let small = Budget {
            rows: 1_000,
            bytes: 400,
        };
        let big = [7u8; 100];
        for time in 6..=8 {
            store.activity_append([(time, &big[..])], 0, small).unwrap();
        }
        assert_eq!(times(&store), [8, 7]);
        drop(store);
        // The tally lasts across unlocks.
        let store = crate::unlock(dir.path(), b"pass").unwrap();
        store.activity_append([(9, &big[..])], 0, small).unwrap();
        assert_eq!(times(&store), [9, 8]);
        assert_eq!(
            store
                .activity_list(0, None, 10)
                .unwrap()
                .dropped
                .unwrap()
                .count,
            7
        );

        // However big, the newest row stays.
        let huge = vec![1u8; 1_000];
        store.activity_append([(10, &huge[..])], 0, small).unwrap();
        assert_eq!(times(&store), [10]);
    }
}
