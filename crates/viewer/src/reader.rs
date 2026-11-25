//! [`PackViewer`]: one pack generation, opened lock-free with pack-scoped
//! keys, read one record at a time.
//!
//! Opening reads each candidate pack's 136-byte header until one has the
//! bundle's `PackId`, then decrypts the index (record 1). A lookup reads
//! one Head record per hit; a fill reads one Secret record. Nothing else is
//! read or decrypted, so a fill touches a few hundred bytes past the index
//! however large the vault is.
//!
//! The viewer doesn't hash the whole pack against its trailer: that is for
//! choosing a generation on open (W3), and the bundle already names one.
//! Every record it reads is authenticated on its own, under `K_pack` with the
//! `PackId` (the header's hash) and the record's position in its AAD, and
//! the index is checked to tile the file exactly up to the trailer.

use std::path::Path;

use deadbolt_core::site;
use deadbolt_pack::names::{GEN_PREFIX, GEN_SUFFIX, parse_numbered};
use deadbolt_pack::pack::{ItemRef, PackIndex};
use deadbolt_pack::{BlockReader, Blocks, FsBlocks, PackKeys, PackReader};
use zeroize::Zeroizing;

use crate::bundle::ViewerKeyBundle;
use crate::error::{Result, ViewerError};
use crate::item::{ViewerHit, ViewerSecret, item_key, parse_item_id, rp_key, site_key, sites_of};

/// One pack generation, open for lookups and fills.
pub struct PackViewer<R> {
    reader: PackReader<R>,
    keys: PackKeys,
    index: PackIndex,
    vault: [u8; 32],
    device_kem: [u8; 32],
}

impl PackViewer<deadbolt_pack::blocks::FsReader> {
    /// [`PackViewer::open`] on the vault directory at `dir`.
    pub fn open_dir(dir: &Path, bundle: &ViewerKeyBundle, now_unix: u64) -> Result<Self> {
        if bundle.is_expired(now_unix) {
            return Err(ViewerError::Expired {
                expires_unix: bundle.expires_unix,
            });
        }
        if !dir.is_dir() {
            return Err(ViewerError::PackNotFound);
        }
        Self::open(&FsBlocks::open(dir)?, bundle, now_unix)
    }
}

impl<R: BlockReader> PackViewer<R> {
    /// Opens the `gen-<n>.pack` the bundle names. Refuses an expired bundle
    /// before touching a file, and keys that don't open the pack's index.
    pub fn open<B: Blocks<Reader = R>>(
        blocks: &B,
        bundle: &ViewerKeyBundle,
        now_unix: u64,
    ) -> Result<Self> {
        if bundle.is_expired(now_unix) {
            return Err(ViewerError::Expired {
                expires_unix: bundle.expires_unix,
            });
        }
        let reader = find_pack(blocks, &bundle.pack_id)?;
        if reader.header().vault != bundle.vault {
            return Err(ViewerError::corrupt("the pack belongs to another vault"));
        }
        let keys = bundle.pack_keys();
        let index = reader.read_index(&keys)?;
        Ok(Self {
            reader,
            keys,
            index,
            vault: bundle.vault,
            device_kem: bundle.device_kem,
        })
    }

    pub fn vault(&self) -> &[u8; 32] {
        &self.vault
    }

    pub fn device_kem(&self) -> &[u8; 32] {
        &self.device_kem
    }

    pub fn generation(&self) -> u64 {
        self.reader.header().generation
    }

    /// Items in the pack.
    pub fn item_count(&self) -> usize {
        self.index.items().len()
    }

    /// The logins and passkeys on the site of `query` (a URL, a host or a
    /// domain), closest match first, then by title.
    pub fn lookup_site(&self, query: &str) -> Result<Vec<ViewerHit>> {
        let host =
            site::url_host(query).ok_or_else(|| ViewerError::invalid("not a URL or host"))?;
        let host = host.strip_suffix('.').unwrap_or(&host).to_owned();
        let domain = site::registrable_domain(&host);
        let mut refs = self.refs(&site_key(&domain));
        refs.extend(self.refs(&rp_key(&host)));
        if host != domain {
            refs.extend(self.refs(&rp_key(&domain)));
        }
        refs.sort_by_key(|item| item.item);
        refs.dedup();
        let page = format!("https://{host}");
        let mut hits = Vec::with_capacity(refs.len());
        for item in &refs {
            let hit = self.head(item)?;
            // The index is a 128-bit hash: keep only what the Head confirms.
            let on_site = sites_of(&hit).contains(&domain)
                || hit
                    .passkey_rp_id
                    .as_deref()
                    .is_some_and(|rp| site::registrable_domain(rp) == domain);
            if !on_site {
                continue;
            }
            let rank = hit
                .urls
                .iter()
                .filter_map(|url| site::closeness(&page, url))
                .min();
            let rank = match (&hit.passkey_rp_id, rank) {
                (Some(rp), _) if *rp == host => Some(site::Closeness::Origin),
                (_, rank) => rank,
            };
            hits.push((rank.unwrap_or(site::Closeness::Site), hit));
        }
        hits.sort_by(|(a, x), (b, y)| a.cmp(b).then_with(|| x.title.cmp(&y.title)));
        Ok(hits.into_iter().map(|(_, hit)| hit).collect())
    }

    /// The passkeys for relying party `rp_id` exactly.
    pub fn lookup_rp(&self, rp_id: &str) -> Result<Vec<ViewerHit>> {
        let rp_id = rp_id.to_ascii_lowercase();
        let mut hits = Vec::new();
        for item in self.refs(&rp_key(&rp_id)) {
            let hit = self.head(&item)?;
            if hit.passkey_rp_id.as_deref() == Some(rp_id.as_str()) {
                hits.push(hit);
            }
        }
        hits.sort_by(|a, b| a.title.cmp(&b.title));
        Ok(hits)
    }

    /// One item's Head, by its 32-hex-digit id.
    pub fn lookup_item(&self, item_id: &str) -> Result<Option<ViewerHit>> {
        let id = parse_item_id(item_id)?;
        for item in self.refs(&item_key(&id)) {
            let hit = self.head(&item)?;
            if parse_item_id(&hit.item_id)? == id {
                return Ok(Some(hit));
            }
        }
        Ok(None)
    }

    /// One item's Secret: one range read, one decryption, no other item
    /// touched.
    pub fn fill_secret(&self, item_id: &str) -> Result<ViewerSecret> {
        let id = parse_item_id(item_id)?;
        for item in self.refs(&item_key(&id)) {
            let plain = self.reader.read_secret(&self.keys, &item)?;
            let secret = parse::<ViewerSecret>(&plain)?;
            if parse_item_id(&secret.item_id)? == id {
                return Ok(secret);
            }
        }
        Err(ViewerError::NotFound)
    }

    fn refs(&self, key: &[u8]) -> Vec<ItemRef> {
        self.index.lookup_by_key(&self.keys, key)
    }

    fn head(&self, item: &ItemRef) -> Result<ViewerHit> {
        parse(&self.reader.read_head(&self.keys, item)?)
    }
}

fn parse<T: serde::de::DeserializeOwned>(plain: &Zeroizing<Vec<u8>>) -> Result<T> {
    serde_json::from_slice(plain).map_err(|err| ViewerError::corrupt(err.to_string()))
}

/// The newest `gen-<n>.pack` whose header hashes to `pack_id`. Reads 136
/// bytes per pack it looks at; normally there is one.
fn find_pack<B: Blocks>(blocks: &B, pack_id: &[u8; 32]) -> Result<PackReader<B::Reader>> {
    let mut gens: Vec<u64> = blocks
        .list_prefix(GEN_PREFIX)?
        .iter()
        .filter_map(|name| parse_numbered(name, GEN_PREFIX, GEN_SUFFIX))
        .collect();
    gens.sort_unstable_by(|a, b| b.cmp(a));
    for n in gens {
        let name = deadbolt_pack::names::gen_pack(n);
        let reader = match PackReader::open(blocks, &name) {
            Ok(reader) => reader,
            // Deleted by a compaction since the listing, or cut short: not it.
            Err(
                deadbolt_pack::Error::NotFound { .. } | deadbolt_pack::Error::CorruptPack { .. },
            ) => {
                continue;
            }
            Err(err) => return Err(err.into()),
        };
        if reader.id().0 == *pack_id {
            if reader.header().generation != n {
                return Err(ViewerError::corrupt("generation does not match the name"));
            }
            return Ok(reader);
        }
    }
    Err(ViewerError::PackNotFound)
}
