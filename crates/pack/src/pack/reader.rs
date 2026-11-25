//! [`PackReader`]: lock-free, range-reading access to one pack (W6).

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::{
    Cursor, ENTRY_LEN, HEADER_LEN, KEY_HASH_LEN, PackHeader, PackId, PackKeys, RECORD_OVERHEAD,
    TRAILER_LEN, Tag, open_record,
};
use crate::blocks::{BlockReader, Blocks};
use crate::error::{Error, Result};

/// Where one record is, and the `ix` it was sealed under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordRef {
    pub ix: u32,
    pub off: u64,
    pub len: u32,
}

/// One item's two records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItemRef {
    /// Position in the pack, in ascending `head_off` order.
    pub item: u32,
    pub head: RecordRef,
    pub secret: RecordRef,
}

/// A decrypted index.
#[derive(Debug)]
pub struct PackIndex {
    /// `(key_hash, item)`, sorted.
    entries: Vec<([u8; KEY_HASH_LEN], u32)>,
    items: Vec<ItemRef>,
}

impl PackIndex {
    fn parse(file: &str, plain: &[u8], record_count: u32) -> Result<Self> {
        let corrupt = |reason| Error::corrupt_pack(file, reason);
        let (chunks, rest) = plain.as_chunks::<ENTRY_LEN>();
        if !rest.is_empty() {
            return Err(corrupt("index length"));
        }
        let mut raw = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let mut cursor = Cursor {
                bytes: chunk.as_slice(),
            };
            let parsed = (|| {
                Some((
                    cursor.take::<KEY_HASH_LEN>()?,
                    u64::from_be_bytes(cursor.take()?),
                    u32::from_be_bytes(cursor.take()?),
                    u64::from_be_bytes(cursor.take()?),
                    u32::from_be_bytes(cursor.take()?),
                ))
            })();
            raw.push(parsed.ok_or_else(|| corrupt("index entry"))?);
        }
        if raw.windows(2).any(|w| (w[0].0, w[0].1) > (w[1].0, w[1].1)) {
            return Err(corrupt("index out of order"));
        }
        // One item per distinct head offset, every entry for it agreeing.
        let mut by_head: BTreeMap<u64, (u32, u64, u32)> = BTreeMap::new();
        for &(_, head_off, head_len, secret_off, secret_len) in &raw {
            let at = (head_len, secret_off, secret_len);
            if *by_head.entry(head_off).or_insert(at) != at
                || secret_off != head_off + u64::from(head_len)
            {
                return Err(corrupt("index entries disagree"));
            }
        }
        let item_count = u32::try_from(by_head.len()).map_err(|_| corrupt("too many items"))?;
        if item_count.checked_mul(2).and_then(|n| n.checked_add(2)) != Some(record_count) {
            return Err(corrupt("index does not cover every record"));
        }
        let items: Vec<ItemRef> = by_head
            .iter()
            .zip(0u32..)
            .map(
                |((&head_off, &(head_len, secret_off, secret_len)), item)| ItemRef {
                    item,
                    head: RecordRef {
                        ix: 2 + 2 * item,
                        off: head_off,
                        len: head_len,
                    },
                    secret: RecordRef {
                        ix: 3 + 2 * item,
                        off: secret_off,
                        len: secret_len,
                    },
                },
            )
            .collect();
        let position: BTreeMap<u64, u32> = items
            .iter()
            .map(|item| (item.head.off, item.item))
            .collect();
        let entries = raw
            .iter()
            .map(|&(hash, head_off, ..)| (hash, position[&head_off]))
            .collect();
        Ok(Self { entries, items })
    }

    /// Every item filed under `key` (two logins on one site share a key).
    pub fn lookup_by_key(&self, keys: &PackKeys, key: &[u8]) -> Vec<ItemRef> {
        let hash = keys.key_hash(key);
        let start = self.entries.partition_point(|(h, _)| *h < hash);
        self.entries[start..]
            .iter()
            .take_while(|(h, _)| *h == hash)
            .map(|&(_, item)| self.items[item as usize])
            .collect()
    }

    /// Every item, in pack order.
    pub fn items(&self) -> &[ItemRef] {
        &self.items
    }

    /// Index entries (keys), not items.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// Reads one pack through an open handle, so it keeps working after a
/// compacting writer deletes the file. Opening reads only the header; records
/// are authenticated one by one, so trusting a record needs no full read
/// ([`PackReader::verify_trailer`] is for picking a generation, W3).
pub struct PackReader<R> {
    name: String,
    reader: R,
    header: PackHeader,
    id: PackId,
    size: u64,
}

impl<R: BlockReader> PackReader<R> {
    pub fn open<B: Blocks<Reader = R>>(blocks: &B, name: &str) -> Result<Self> {
        Self::from_reader(name, blocks.open_read(name)?)
    }

    pub fn from_reader(name: &str, reader: R) -> Result<Self> {
        let corrupt = |reason| Error::corrupt_pack(name, reason);
        let size = reader.size()?;
        let min = (HEADER_LEN + 2 * RECORD_OVERHEAD + TRAILER_LEN) as u64;
        if size < min {
            return Err(corrupt("too short"));
        }
        let header = PackHeader::decode(&reader.read_range(0, HEADER_LEN)?)
            .ok_or_else(|| corrupt("bad header"))?;
        let body_end = size - TRAILER_LEN as u64;
        let index_end = header.index_off.checked_add(u64::from(header.index_len));
        let sane = header.index_off >= (HEADER_LEN + RECORD_OVERHEAD) as u64
            && header.index_len as usize >= RECORD_OVERHEAD
            && index_end.is_some_and(|end| end <= body_end)
            && header.record_count >= 2
            && header.record_count.is_multiple_of(2);
        if !sane {
            return Err(corrupt("bad header"));
        }
        let id = header.id();
        Ok(Self {
            name: name.to_owned(),
            reader,
            header,
            id,
            size,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn header(&self) -> &PackHeader {
        &self.header
    }

    pub fn id(&self) -> PackId {
        self.id
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// Reads the whole pack and checks its trailer. Returns the pack hash.
    pub fn verify_trailer(&self) -> Result<[u8; 32]> {
        let bytes = self.reader.read_all()?;
        if bytes.len() as u64 != self.size {
            return Err(Error::corrupt_pack(&self.name, "size changed"));
        }
        let (body, trailer) = bytes.split_at(bytes.len() - TRAILER_LEN);
        let hash: [u8; 32] = blake3::hash(body).into();
        if trailer != hash {
            return Err(Error::corrupt_pack(&self.name, "trailer mismatch"));
        }
        Ok(hash)
    }

    /// Record 0: the opaque checkpoint metadata.
    pub fn read_meta(&self, keys: &PackKeys) -> Result<Zeroizing<Vec<u8>>> {
        let len = usize::try_from(self.header.index_off - HEADER_LEN as u64)
            .map_err(|_| Error::corrupt_pack(&self.name, "meta too large"))?;
        let record = self.reader.read_range(HEADER_LEN as u64, len)?;
        open_record(&self.name, keys, &self.id, 0, Tag::Meta, &record)
    }

    /// Record 1, decrypted and checked.
    pub fn read_index(&self, keys: &PackKeys) -> Result<PackIndex> {
        let record = self
            .reader
            .read_range(self.header.index_off, self.header.index_len as usize)?;
        let plain = open_record(&self.name, keys, &self.id, 1, Tag::Index, &record)?;
        PackIndex::parse(&self.name, &plain, self.header.record_count)
    }

    pub fn read_head(&self, keys: &PackKeys, item: &ItemRef) -> Result<Zeroizing<Vec<u8>>> {
        self.read_record(keys, &item.head, Tag::Head)
    }

    pub fn read_secret(&self, keys: &PackKeys, item: &ItemRef) -> Result<Zeroizing<Vec<u8>>> {
        self.read_record(keys, &item.secret, Tag::Secret)
    }

    /// One range read and one decryption.
    pub(crate) fn read_record(
        &self,
        keys: &PackKeys,
        at: &RecordRef,
        tag: Tag,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let fits = at.off.checked_add(u64::from(at.len)).is_some_and(|end| {
            at.off >= HEADER_LEN as u64 && end <= self.size - TRAILER_LEN as u64
        });
        if !fits {
            return Err(Error::corrupt_pack(&self.name, "record out of bounds"));
        }
        let record = self.reader.read_range(at.off, at.len as usize)?;
        open_record(&self.name, keys, &self.id, at.ix, tag, &record)
    }
}
