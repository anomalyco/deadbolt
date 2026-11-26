//! The app's side of a pack: laying a core [`Pack`] out as `deadbolt-pack`
//! input, and reading a whole pack back into one.

use deadbolt_core::PackSite;
use deadbolt_core::v2::Pack;
use deadbolt_core::v2::pack::ItemHead;
use deadbolt_pack::{BlockReader, PackInput, PackItem, PackKeys, PackReader};

use crate::error::{Result, ViewerError};
use crate::item::{ViewerHit, keys_of};

/// A core pack as `deadbolt-pack` input: Meta, then each item's Head and
/// Secret, filed under its id, its sites and its passkey's rp id.
pub fn pack_input(pack: &Pack, site: &PackSite, generation: u64) -> Result<PackInput> {
    let records = pack
        .split()
        .map_err(|err| ViewerError::invalid(err.to_string()))?;
    let mut items = Vec::with_capacity(records.items.len());
    for item in records.items {
        let head =
            ItemHead::decode(&item.head).map_err(|err| ViewerError::invalid(err.to_string()))?;
        let hit = ViewerHit::from_head(&head);
        items.push(PackItem {
            keys: keys_of(item.id.as_bytes(), hit.as_ref())?,
            head: item.head,
            secret: item.secret,
        });
    }
    Ok(PackInput {
        vault: *site.vault.as_bytes(),
        author: *site.author.as_bytes(),
        seq: site.seq,
        epoch: *site.epoch.as_bytes(),
        generation,
        meta: records.meta,
        items,
    })
}

/// Reads every record of a pack and rebuilds the core [`Pack`].
pub fn read_pack<R: BlockReader>(reader: &PackReader<R>, keys: &PackKeys) -> Result<Pack> {
    let meta = reader.read_meta(keys)?;
    let index = reader.read_index(keys)?;
    let mut records = Vec::with_capacity(index.items().len());
    for item in index.items() {
        records.push((
            reader.read_head(keys, item)?,
            reader.read_secret(keys, item)?,
        ));
    }
    Pack::join(&meta, records.iter().map(|(h, s)| (&h[..], &s[..])))
        .map_err(|err| ViewerError::corrupt(err.to_string()))
}
