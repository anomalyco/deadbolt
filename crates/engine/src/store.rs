//! Where the engine keeps its signed log and this device's own metadata.
//! The engine does no IO: a host hands it a [`VaultStore`] (the daemon's
//! sealed `store.redb`; [`MemoryStore`] for tests and hosts without one).

use std::collections::BTreeMap;
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

/// The engine's storage: an append-only log of signed entries and a map of
/// device-local metadata, both sealed at rest by the implementation.
pub trait VaultStore: Send + Sync {
    /// This device's signing key.
    fn device_secret(&self) -> &[u8; 32];

    /// Calls `each` with every stored entry, in append order. Stops at the
    /// first error, of `each` or of the store (a tampered or missing entry).
    fn for_each_entry(&self, each: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>;

    /// Appends `entries` durably, all or none. An error may leave the
    /// outcome unknown; [`VaultStore::uncertain`] says when.
    fn append(&self, entries: &mut dyn Iterator<Item = Zeroizing<Vec<u8>>>) -> Result<()>;

    fn meta_get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;

    fn meta_set(&self, name: &str, value: &[u8]) -> Result<()>;

    /// A diagnostic when `error`, from [`VaultStore::append`], may have
    /// committed anyway; `None` when the append certainly failed.
    fn uncertain(&self, error: &anyhow::Error) -> Option<String>;
}

/// Reads the JSON metadata value `name`.
pub fn get_json<T: DeserializeOwned>(store: &dyn VaultStore, name: &str) -> Result<Option<T>> {
    store
        .meta_get(name)?
        .map(|bytes| serde_json::from_slice(&bytes).with_context(|| format!("reading {name}")))
        .transpose()
}

/// Writes `value` as the JSON metadata value `name`.
pub fn set_json<T: Serialize>(store: &dyn VaultStore, name: &str, value: &T) -> Result<()> {
    store.meta_set(name, &serde_json::to_vec(value)?)
}

/// A store in memory, gone when dropped.
pub struct MemoryStore {
    secret: [u8; 32],
    log: Mutex<Vec<Zeroizing<Vec<u8>>>>,
    meta: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
}

impl MemoryStore {
    pub fn new(device_secret: [u8; 32]) -> Self {
        Self {
            secret: device_secret,
            log: Mutex::default(),
            meta: Mutex::default(),
        }
    }
}

impl VaultStore for MemoryStore {
    fn device_secret(&self) -> &[u8; 32] {
        &self.secret
    }

    fn for_each_entry(&self, each: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.iter().try_for_each(|entry| each(entry))
    }

    fn append(&self, entries: &mut dyn Iterator<Item = Zeroizing<Vec<u8>>>) -> Result<()> {
        let staged: Vec<_> = entries.collect();
        self.log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(staged);
        Ok(())
    }

    fn meta_get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let meta = self.meta.lock().unwrap_or_else(|e| e.into_inner());
        Ok(meta.get(name).cloned())
    }

    fn meta_set(&self, name: &str, value: &[u8]) -> Result<()> {
        self.meta
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name.into(), Zeroizing::new(value.to_vec()));
        Ok(())
    }

    fn uncertain(&self, _: &anyhow::Error) -> Option<String> {
        None
    }
}
