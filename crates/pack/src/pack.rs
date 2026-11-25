//! `gen-<n>.pack`: an immutable, encrypted checkpoint, byte-identical to the
//! remote `p/<pack_hash>`.
//!
//! ```text
//! PackHeader (136 B) = "DBPK\x02\0\0\0" || vault 32 || author 32 || seq u64_be || epoch 32
//!                      || gen u64_be || record_count u32_be || index_off u64_be || index_len u32_be
//! PackId   = BLAKE3(PackHeader)
//! record   = len u32_be || nonce 24 || AEAD(K_pack, nonce, body, aad = PackId || ix u32_be || tag u8)
//!            record 0 Meta, record 1 Index, then Head and Secret for each item
//! trailer  = BLAKE3(every prior byte)                                   = pack_hash
//! Index    = sorted (key_hash 16 || head_off u64_be || head_len u32_be || secret_off u64_be || secret_len u32_be)
//!            key_hash = BLAKE3-keyed(K_ix, key)[..16], for an item id, a site or an rp id
//!            no (key_hash, head_off) twice; the items' records tile the bytes from the
//!            index's end to the trailer, each Secret right after its Head
//! ```
//!
//! Meta is opaque here (the checkpoint's frontier and clocks belong to the
//! core). Head holds what lists and autofill menus show; Secret holds the
//! rest. A reader that has the index reads one item's Secret with one range
//! read and decrypts nothing else. Offsets and lengths count whole records,
//! length prefix included. Items are numbered by ascending `head_off`: item
//! `p` is records `2 + 2p` (Head) and `3 + 2p` (Secret), which is how a
//! reader knows the `ix` each record was sealed under.

mod reader;

pub use reader::{ItemRef, PackIndex, PackReader, RecordRef};

use zeroize::Zeroizing;

use crate::blocks::Blocks;
use crate::crypto::{self, KEY_LEN, Key, SEAL_OVERHEAD};
use crate::error::{Error, Result};

pub const PACK_MAGIC: [u8; 8] = *b"DBPK\x02\0\0\0";
pub const HEADER_LEN: usize = 136;
pub const TRAILER_LEN: usize = 32;
pub const KEY_HASH_LEN: usize = 16;
const ENTRY_LEN: usize = KEY_HASH_LEN + 8 + 4 + 8 + 4;
const PREFIX_LEN: usize = 4;
/// Bytes a pack record adds around its body.
pub const RECORD_OVERHEAD: usize = PREFIX_LEN + SEAL_OVERHEAD;

/// `BLAKE3(PackHeader)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PackId(pub [u8; 32]);

/// What a record holds; part of every record's AAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    Meta = 0,
    Index = 1,
    Head = 2,
    Secret = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackHeader {
    pub vault: [u8; 32],
    pub author: [u8; 32],
    pub seq: u64,
    pub epoch: [u8; 32],
    pub generation: u64,
    pub record_count: u32,
    pub index_off: u64,
    pub index_len: u32,
}

impl PackHeader {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0; HEADER_LEN];
        let parts: [&[u8]; 9] = [
            &PACK_MAGIC,
            &self.vault,
            &self.author,
            &self.seq.to_be_bytes(),
            &self.epoch,
            &self.generation.to_be_bytes(),
            &self.record_count.to_be_bytes(),
            &self.index_off.to_be_bytes(),
            &self.index_len.to_be_bytes(),
        ];
        let mut at = 0;
        for part in parts {
            out[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut cursor = Cursor {
            bytes: bytes.get(..HEADER_LEN)?,
        };
        if cursor.take::<8>()? != PACK_MAGIC {
            return None;
        }
        Some(Self {
            vault: cursor.take()?,
            author: cursor.take()?,
            seq: u64::from_be_bytes(cursor.take()?),
            epoch: cursor.take()?,
            generation: u64::from_be_bytes(cursor.take()?),
            record_count: u32::from_be_bytes(cursor.take()?),
            index_off: u64::from_be_bytes(cursor.take()?),
            index_len: u32::from_be_bytes(cursor.take()?),
        })
    }

    pub fn id(&self) -> PackId {
        PackId(blake3::hash(&self.encode()).into())
    }
}

pub(crate) struct Cursor<'a> {
    pub(crate) bytes: &'a [u8],
}

impl Cursor<'_> {
    pub(crate) fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.bytes.split_first_chunk::<N>()?;
        self.bytes = rest;
        Some(*head)
    }
}

/// The two pack-scoped keys. A pack's keys open that pack only, which is what
/// the iOS viewer is given: never the epoch key.
pub struct PackKeys {
    pack: Key,
    ix: Key,
}

impl PackKeys {
    /// `K_pack = KDF("epoch pack", K_e || vault || EpochId || PackId)`, and
    /// `K_ix` likewise with `"epoch index"`.
    pub fn derive(
        epoch_key: &[u8; KEY_LEN],
        vault: &[u8; 32],
        epoch: &[u8; 32],
        id: &PackId,
    ) -> Self {
        let parts: [&[u8]; 4] = [epoch_key, vault, epoch, &id.0];
        Self {
            pack: crypto::kdf("deadbolt/v2 epoch pack", &parts),
            ix: crypto::kdf("deadbolt/v2 epoch index", &parts),
        }
    }

    pub fn from_bytes(pack: [u8; KEY_LEN], ix: [u8; KEY_LEN]) -> Self {
        Self {
            pack: Zeroizing::new(pack),
            ix: Zeroizing::new(ix),
        }
    }

    pub fn pack_key(&self) -> &[u8; KEY_LEN] {
        &self.pack
    }

    pub fn index_key(&self) -> &[u8; KEY_LEN] {
        &self.ix
    }

    /// `BLAKE3-keyed(K_ix, key)[..16]`: what the index stores for `key`.
    pub fn key_hash(&self, key: &[u8]) -> [u8; KEY_HASH_LEN] {
        let hash = crypto::keyed_hash(&self.ix, &[key]);
        let mut out = [0; KEY_HASH_LEN];
        out.copy_from_slice(&hash[..KEY_HASH_LEN]);
        out
    }
}

/// One item: the lookup keys that find it, and its two records' plaintext.
pub struct PackItem {
    /// At least one: an item id, a site, an rp id.
    pub keys: Vec<Vec<u8>>,
    pub head: Zeroizing<Vec<u8>>,
    pub secret: Zeroizing<Vec<u8>>,
}

pub struct PackInput {
    pub vault: [u8; 32],
    pub author: [u8; 32],
    pub seq: u64,
    pub epoch: [u8; 32],
    pub generation: u64,
    pub meta: Zeroizing<Vec<u8>>,
    pub items: Vec<PackItem>,
}

/// A pack's identity, without its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackSummary {
    pub header: PackHeader,
    pub id: PackId,
    /// The trailer: `BLAKE3` of every byte before it. The remote name is
    /// `p/<pack_hash>`.
    pub hash: [u8; 32],
    pub len: u64,
}

pub struct EncodedPack {
    pub summary: PackSummary,
    pub bytes: Vec<u8>,
}

struct Layout {
    head_off: u64,
    head_len: u32,
    secret_off: u64,
    secret_len: u32,
}

/// Builds a pack's bytes under the epoch key `K_e`.
pub fn encode(input: &PackInput, epoch_key: &[u8; KEY_LEN]) -> Result<EncodedPack> {
    if input.items.iter().any(|item| item.keys.is_empty()) {
        return Err(Error::InvalidInput("every pack item needs a lookup key"));
    }
    // One index entry per distinct key of an item: a key given twice would
    // otherwise find the item twice.
    let item_keys: Vec<Vec<&[u8]>> = input
        .items
        .iter()
        .map(|item| {
            let mut keys: Vec<&[u8]> = item.keys.iter().map(Vec::as_slice).collect();
            keys.sort_unstable();
            keys.dedup();
            keys
        })
        .collect();
    let entries: usize = item_keys.iter().map(Vec::len).sum();
    let index_body = entries
        .checked_mul(ENTRY_LEN)
        .ok_or(Error::InvalidInput("index too large"))?;
    let meta_len = record_len(input.meta.len())?;
    let index_len = record_len(index_body)?;
    let index_off = HEADER_LEN as u64 + u64::from(meta_len);
    let mut off = index_off + u64::from(index_len);
    let mut layout = Vec::with_capacity(input.items.len());
    for item in &input.items {
        let head_len = record_len(item.head.len())?;
        let secret_len = record_len(item.secret.len())?;
        let secret_off = off + u64::from(head_len);
        layout.push(Layout {
            head_off: off,
            head_len,
            secret_off,
            secret_len,
        });
        off = secret_off + u64::from(secret_len);
    }
    let record_count = input
        .items
        .len()
        .checked_mul(2)
        .and_then(|n| u32::try_from(n + 2).ok())
        .ok_or(Error::InvalidInput("too many pack items"))?;
    let header = PackHeader {
        vault: input.vault,
        author: input.author,
        seq: input.seq,
        epoch: input.epoch,
        generation: input.generation,
        record_count,
        index_off,
        index_len,
    };
    let id = header.id();
    let keys = PackKeys::derive(epoch_key, &input.vault, &input.epoch, &id);

    let mut index: Vec<([u8; KEY_HASH_LEN], &Layout)> = Vec::with_capacity(entries);
    for (item, at) in item_keys.iter().zip(&layout) {
        index.extend(item.iter().map(|key| (keys.key_hash(key), at)));
    }
    index.sort_by_key(|(hash, at)| (*hash, at.head_off));
    let mut index_plain = Zeroizing::new(Vec::with_capacity(index_body));
    for (hash, at) in index {
        index_plain.extend_from_slice(&hash);
        index_plain.extend_from_slice(&at.head_off.to_be_bytes());
        index_plain.extend_from_slice(&at.head_len.to_be_bytes());
        index_plain.extend_from_slice(&at.secret_off.to_be_bytes());
        index_plain.extend_from_slice(&at.secret_len.to_be_bytes());
    }

    let total = usize::try_from(off).map_err(|_| Error::InvalidInput("pack too large"))?;
    let mut bytes = Vec::with_capacity(total + TRAILER_LEN);
    bytes.extend_from_slice(&header.encode());
    bytes.extend(seal_record(&keys, &id, 0, Tag::Meta, &input.meta)?);
    bytes.extend(seal_record(&keys, &id, 1, Tag::Index, &index_plain)?);
    for (ix, item) in (2u32..).step_by(2).zip(&input.items) {
        bytes.extend(seal_record(&keys, &id, ix, Tag::Head, &item.head)?);
        bytes.extend(seal_record(&keys, &id, ix + 1, Tag::Secret, &item.secret)?);
    }
    debug_assert_eq!(bytes.len(), total, "pack layout");
    let hash: [u8; 32] = blake3::hash(&bytes).into();
    bytes.extend_from_slice(&hash);
    let summary = PackSummary {
        header,
        id,
        hash,
        len: bytes.len() as u64,
    };
    Ok(EncodedPack { summary, bytes })
}

/// Writes a pack to `name` (create-new, synced) and returns its summary.
pub fn write<B: Blocks>(
    blocks: &B,
    name: &str,
    input: &PackInput,
    epoch_key: &[u8; KEY_LEN],
) -> Result<PackSummary> {
    let encoded = encode(input, epoch_key)?;
    blocks.create_new(name, &encoded.bytes)?;
    Ok(encoded.summary)
}

/// A whole record's length for a body of `body` bytes.
fn record_len(body: usize) -> Result<u32> {
    body.checked_add(RECORD_OVERHEAD)
        .and_then(|len| u32::try_from(len).ok())
        .ok_or(Error::InvalidInput("pack record too large"))
}

fn record_aad(id: &PackId, ix: u32, tag: Tag) -> [u8; 37] {
    let mut aad = [0; 37];
    aad[..32].copy_from_slice(&id.0);
    aad[32..36].copy_from_slice(&ix.to_be_bytes());
    aad[36] = tag as u8;
    aad
}

pub(crate) fn seal_record(
    keys: &PackKeys,
    id: &PackId,
    ix: u32,
    tag: Tag,
    body: &[u8],
) -> Result<Vec<u8>> {
    let sealed = crypto::seal(&keys.pack, &record_aad(id, ix, tag), body)?;
    let len =
        u32::try_from(sealed.len()).map_err(|_| Error::InvalidInput("pack record too large"))?;
    let mut out = Vec::with_capacity(PREFIX_LEN + sealed.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens one whole record (length prefix included).
pub(crate) fn open_record(
    file: &str,
    keys: &PackKeys,
    id: &PackId,
    ix: u32,
    tag: Tag,
    record: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let Some((len, sealed)) = record.split_first_chunk::<PREFIX_LEN>() else {
        return Err(Error::corrupt_pack(file, "short record"));
    };
    if usize::try_from(u32::from_be_bytes(*len)).ok() != Some(sealed.len()) {
        return Err(Error::corrupt_pack(file, "record length mismatch"));
    }
    crypto::open(&keys.pack, &record_aad(id, ix, tag), sealed)
}
