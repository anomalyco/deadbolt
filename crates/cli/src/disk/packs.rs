//! Each vault's checkpoint packs: `gen-<n>.pack`, laid out by
//! `deadbolt-viewer` (so the iOS viewer reads it as is) and installed with
//! `VaultDir::compact_encoded`, byte for byte what the checkpoint frame
//! committed to and what the remote stores as `p/<pack_hash>`.
//!
//! Local compaction carries every frame into the new WAL: this device
//! keeps its whole history, and only a remote collects behind a checkpoint.

use deadbolt_core::v2::{EpochId, EpochKey, Pack};
use deadbolt_core::{PackSite, VaultId};
use deadbolt_pack::{Blocks, MemBlocks, PackHeader, PackKeys, PackReader, VaultReader, names};
use deadbolt_viewer::{PackPlace, pack_input, read_pack};

use super::{Error, Result, Unlocked};

impl Unlocked {
    /// Lays `pack` out as `site.vault`'s next generation, sealed under
    /// `site.key`.
    pub fn seal_pack(&self, pack: &Pack, site: &PackSite) -> Result<Vec<u8>> {
        let mut inner = self.inner();
        let generation = self.held(&mut inner, site.vault)?.dir.next_generation();
        let place = PackPlace {
            vault: *site.vault.as_bytes(),
            author: *site.author.as_bytes(),
            seq: site.seq,
            epoch: *site.epoch.as_bytes(),
            generation,
        };
        let input = pack_input(pack, place).map_err(|e| Error::corrupt(e.to_string()))?;
        Ok(deadbolt_pack::pack::encode(&input, site.key.as_bytes())?.bytes)
    }

    /// Installs sealed pack bytes as `vault`'s newest generation, carrying
    /// every WAL frame into the new WAL.
    pub fn install_pack(&self, vault: VaultId, sealed: &[u8]) -> Result<u64> {
        let mut inner = self.inner();
        let held = self.held(&mut inner, vault)?;
        let carried = VaultReader::open(held.dir.blocks())?.wal()?;
        let summary = held.dir.compact_encoded(sealed, &carried)?;
        Ok(summary.header.generation)
    }

    /// The sealed bytes of `vault`'s newest verified pack (the one
    /// `VaultDir::open` chose), if it has one.
    pub fn load_pack(&self, vault: VaultId) -> Result<Option<Vec<u8>>> {
        let mut inner = self.inner();
        let held = self.held(&mut inner, vault)?;
        let Some(generation) = held.dir.generation() else {
            return Ok(None);
        };
        match held.dir.blocks().read_all(&names::gen_pack(generation)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The generation of `vault`'s newest local pack.
    pub fn pack_generation(&self, vault: VaultId) -> Result<Option<u64>> {
        let mut inner = self.inner();
        Ok(self.held(&mut inner, vault)?.dir.generation())
    }
}

/// Opens sealed pack bytes of `vault` with the key of the epoch their
/// header names: the header must name `vault`, the trailer verify and
/// every record open.
pub fn open_pack(
    sealed: &[u8],
    vault: VaultId,
    key_for: &dyn Fn(&EpochId) -> Option<EpochKey>,
) -> Result<Pack> {
    let header =
        PackHeader::decode(sealed).ok_or_else(|| Error::corrupt("not a checkpoint pack"))?;
    if header.vault != *vault.as_bytes() {
        return Err(Error::corrupt("the pack belongs to another vault"));
    }
    let epoch = EpochId::from_bytes(header.epoch);
    let key = key_for(&epoch).ok_or_else(|| Error::corrupt("no key for the pack's epoch"))?;
    let blocks = MemBlocks::new();
    blocks.create_new("pack", sealed)?;
    let reader = PackReader::open(&blocks, "pack")?;
    reader.verify_trailer()?;
    let keys = PackKeys::derive(key.as_bytes(), &header.vault, &header.epoch, &reader.id());
    read_pack(&reader, &keys).map_err(|e| Error::corrupt(e.to_string()))
}
