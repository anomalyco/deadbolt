//! Durable single-vault helpers shared by browser and mobile devices.

use deadbolt_core::{Entry, Vault, VaultId};
use deadbolt_store::Unlocked;
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Store(#[from] deadbolt_store::Error),
    #[error(transparent)]
    Decode(#[from] deadbolt_core::DecodeError),
    #[error(
        "Vault {id} is unavailable: {reason}. Its encrypted entries are retained. Do not reset storage."
    )]
    Unavailable {
        id: VaultId,
        reason: deadbolt_core::Error,
    },
    #[error(
        "This device expects one vault, but storage contains {0}. No vault was selected or replaced; encrypted entries are retained."
    )]
    VaultCount(usize),
}

pub fn load(store: &Unlocked) -> Result<Vault, Error> {
    let mut grouped: BTreeMap<VaultId, Vec<Entry>> = BTreeMap::new();
    for bytes in store.iter_all()? {
        let entry = Entry::decode(&bytes?)?;
        grouped.entry(entry.vault()).or_default().push(entry);
    }
    if grouped.len() != 1 {
        return Err(Error::VaultCount(grouped.len()));
    }
    let (id, entries) = grouped.pop_first().ok_or(Error::VaultCount(0))?;
    Vault::load(entries).map_err(|reason| Error::Unavailable { id, reason })
}

/// Persist a validated `Vault::transact` delta, encoding one entry at a time.
/// On `AppendUncertain`, callers must quarantine the session until replay.
pub fn append(store: &Unlocked, entries: &[&Entry]) -> deadbolt_store::Result<()> {
    store.append_batch(entries.iter().copied().map(Entry::encode))?;
    Ok(())
}
