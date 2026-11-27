//! DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2,
//! with its `mod` and `use` in `daemon.rs`; callers of [`set_up`] go back
//! to `disk::is_initialized`.
//!
//! What the daemon asks of a data dir that may still hold a v1 store, with
//! or without the `v1-migrate` feature that can move it.

use anyhow::Result;

/// Whether `data` holds a v1 `store.redb` the next unlock moves to v2.
pub(crate) fn v1_store(data: &std::path::Path) -> bool {
    #[cfg(feature = "v1-migrate")]
    return super::migrate_v1::has_unmigrated_v1_store(data);
    #[cfg(not(feature = "v1-migrate"))]
    {
        let _ = data;
        false
    }
}

/// Whether this device is set up: a v2 device, or a v1 store to move.
pub(super) fn set_up(data: &std::path::Path) -> bool {
    crate::disk::is_initialized(data) || v1_store(data)
}

/// Refuses to set up a new device over a v1 store, which would hide it.
pub(super) fn refuse_v1_setup(data: &std::path::Path) -> Result<()> {
    #[cfg(feature = "v1-migrate")]
    if v1_store(data) {
        anyhow::bail!(super::migrate_v1::FOUND_V1);
    }
    let _ = data;
    Ok(())
}

/// A vault an unlock moved from v1: its new id, live items, and kit.
pub(super) type Moved = (deadbolt_core::VaultId, usize, zeroize::Zeroizing<String>);

/// Moves a v1 store in `dir` to v2 under `passphrase` if there is one.
/// Blocking (Argon2).
pub(super) fn migrate_first(
    dir: &std::path::Path,
    passphrase: &[u8],
    params: crate::disk::KdfParams,
) -> Result<Vec<Moved>> {
    #[cfg(feature = "v1-migrate")]
    if v1_store(dir) {
        let moved = super::migrate_v1::migrate(dir, passphrase, params)?;
        tracing::info!(vaults = moved.len(), "moved the v1 store to v2");
        return Ok(moved
            .into_iter()
            .map(|m| (m.vault, m.items, m.recovery_kit))
            .collect());
    }
    let _ = (dir, passphrase, params);
    Ok(Vec::new())
}
