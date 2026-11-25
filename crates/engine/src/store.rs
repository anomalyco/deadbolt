//! Where the engine keeps its signed frames and this device's own metadata.
//! The engine does no IO: a host hands it a [`VaultStore`] (the daemon's
//! sealed vault directories; [`MemoryStore`] for tests and hosts without one).

use std::collections::BTreeMap;
use std::sync::Mutex;

use anyhow::{Context, Result};
use deadbolt_core::VaultId;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

/// The engine's storage: each vault's signed v2 frames and a map of
/// device-local metadata, sealed at rest by the implementation.
pub trait VaultStore: Send + Sync {
    /// The seed this device's signing, KEM and transport keys derive from.
    fn device_seed(&self) -> &[u8; 32];

    /// Calls `each` with every stored frame's encoding, vault by vault in
    /// the order they were added, each vault's frames in append order.
    /// Stops at the first error, of `each` or of the store (a tampered or
    /// missing frame).
    fn for_each_frame(&self, each: &mut dyn FnMut(VaultId, &[u8]) -> Result<()>) -> Result<()>;

    /// Appends `frames` to `vault` durably, all or none. An error may
    /// leave the outcome unknown; [`VaultStore::uncertain`] says when.
    fn append(&self, vault: VaultId, frames: &mut dyn Iterator<Item = Vec<u8>>) -> Result<()>;

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
    seed: Zeroizing<[u8; 32]>,
    frames: Mutex<Vec<(VaultId, Vec<u8>)>>,
    meta: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
}

impl MemoryStore {
    pub fn new(device_seed: [u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(device_seed),
            frames: Mutex::default(),
            meta: Mutex::default(),
        }
    }
}

impl VaultStore for MemoryStore {
    fn device_seed(&self) -> &[u8; 32] {
        &self.seed
    }

    fn for_each_frame(&self, each: &mut dyn FnMut(VaultId, &[u8]) -> Result<()>) -> Result<()> {
        let frames = self.frames.lock().unwrap_or_else(|e| e.into_inner());
        frames.iter().try_for_each(|(vault, frame)| each(*vault, frame))
    }

    fn append(&self, vault: VaultId, frames: &mut dyn Iterator<Item = Vec<u8>>) -> Result<()> {
        let staged: Vec<_> = frames.map(|f| (vault, f)).collect();
        self.frames
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
