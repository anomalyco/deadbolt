//! DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2.
//! Deleting it is this file, `migrate_v1/`, the `v1-migrate` feature in
//! `Cargo.toml`, `tests/cli/migrate_v1.rs`, and the lines marked
//! `DELETABLE(v1-migrate)`.
//!
//! Moves a v1 store (`store.redb`, one sealed log of signed entries) to v2
//! under the same passphrase, on the first unlock after an upgrade (and
//! `deadbolt migrate`, which is that unlock). Every vault is replayed from
//! its v1 entries and written as a new v2 vault with a fresh recovery root,
//! keeping its name, its items' ids and everything about them: fields and
//! files, names, favorites, tags, ignored findings, password dates, trash.
//! The default vault and the device name carry over. v2 can't sync with
//! v1, so each other device migrates too, then pairs again.
//!
//! Nothing touches `store.redb` until the end. The v2 store is built in
//! `<data>/.v1-migrate/`, reopened and checked item by item, marked
//! verified, and only then moved into place (`v/`, then `device/`).
//! Renaming `store.redb` to `store.redb.v1.bak` (never deleting it) is
//! the one commit point: until it lands, `store.redb` and the marker mean
//! the device is still on v1 and the `v/` and `device/` beside it are
//! this migration's, cleared and rebuilt on the next try, whose kits are
//! the ones shown. A failure before the marker leaves only the staging
//! folder, removed again.

mod build;
mod entry;
mod fit;
mod membership;
mod replay;
mod store;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

pub(crate) use build::Moved;

use crate::disk::KdfParams;

/// The v1 store, in the data directory.
pub(crate) const V1_FILE: &str = "store.redb";
/// What `store.redb` is renamed to once its vaults are on v2.
pub(crate) const BACKUP_FILE: &str = "store.redb.v1.bak";
/// What setup says while a v1 store waits to move.
pub(crate) const FOUND_V1: &str =
    "Found an existing v1 vault (store.redb). Unlock or run `deadbolt migrate` to upgrade to v2.";

const STAGING: &str = ".v1-migrate";
/// In the staging folder once the new store checked out: from then until
/// `store.redb` is renamed, the `v/` and `device/` in the data directory
/// are this migration's.
const VERIFIED: &str = "verified";
const DEVICE: &str = "device";
const VAULTS: &str = "v";

/// Whether `data` holds a v1 store still to move: no v2 device yet, or
/// only the one an interrupted cutover left.
pub(crate) fn has_unmigrated_v1_store(data: &Path) -> bool {
    data.join(V1_FILE).is_file()
        && (!crate::disk::is_initialized(data) || data.join(STAGING).join(VERIFIED).is_file())
}

/// Moves the v1 store in `data` to v2, as above. Blocking (Argon2, several
/// times). A wrong passphrase fails as [`crate::disk::Error::WrongPassphrase`]
/// and changes nothing.
pub(crate) fn migrate(data: &Path, passphrase: &[u8], params: KdfParams) -> Result<Vec<Moved>> {
    if !has_unmigrated_v1_store(data) {
        bail!("there is no v1 store to migrate here");
    }
    let staging = Staging::fresh(data)?;
    let v1 = store::read(
        &data.join(V1_FILE),
        &staging.dir.join("store.redb.copy"),
        passphrase,
    )?;
    let entries = v1
        .entries
        .iter()
        .map(|bytes| entry::Entry::decode(bytes))
        .collect::<Result<Vec<_>>>()?;
    let vaults: Vec<_> = replay::vaults(entries)?
        .into_iter()
        .map(fit::vault)
        .collect();
    let default = v1
        .default_vault
        .as_deref()
        .and_then(|hex| deadbolt_engine::unhex::<32>(hex).ok());
    let device_name = v1
        .device_name
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| crate::prompt::device_name(None));
    let plan = build::Plan {
        device_name: &device_name,
        default,
        vaults: &vaults,
    };
    let moved = build::build(&staging.dir.join("store"), passphrase, params, &plan)?;
    staging.cut_over(data)?;
    Ok(moved)
}

/// The staging folder, removed when dropped unless a cutover began and
/// didn't finish.
struct Staging {
    dir: PathBuf,
    /// Keep the folder, and its marker, for the next try to clear up after.
    keep: bool,
}

impl Staging {
    /// An empty staging folder, after undoing what an interrupted cutover
    /// left. Only called while `store.redb` is still there.
    fn fresh(data: &Path) -> Result<Self> {
        let dir = data.join(STAGING);
        if dir.join(VERIFIED).is_file() {
            // Cut short before the commit point: this `v/` and `device/`
            // are the migration's, and its kits may never have been shown.
            // Start over.
            for name in [VAULTS, DEVICE] {
                let moved = data.join(name);
                if moved.exists() {
                    fs::remove_dir_all(&moved).context("removing a half-moved v2 store")?;
                }
            }
        }
        if dir.exists() {
            fs::remove_dir_all(&dir).context("removing an earlier migration's files")?;
        }
        for (name, what) in [(VAULTS, "vaults"), (DEVICE, "device")] {
            if data.join(name).exists() {
                bail!(
                    "{} holds unfinished v2 {what} beside store.redb; move {} aside and try again",
                    data.display(),
                    data.join(name).display()
                );
            }
        }
        private_dir(&dir)?;
        Ok(Self { dir, keep: false })
    }

    /// Moves the checked store into `data`, then backs up `store.redb`,
    /// which commits.
    fn cut_over(mut self, data: &Path) -> Result<()> {
        let built = self.dir.join("store");
        fs::File::create(self.dir.join(VERIFIED))?.sync_all()?;
        sync_dir(&self.dir)?;
        // Until the rename below, a failure or crash leaves the marker, and
        // the next try clears what moved.
        self.keep = true;
        let vaults = built.join(VAULTS);
        if vaults.exists() {
            fs::rename(&vaults, data.join(VAULTS)).context("moving the new vaults into place")?;
        }
        fs::rename(built.join(DEVICE), data.join(DEVICE))
            .context("moving the new device into place")?;
        sync_dir(data)?;
        // The commit point. The old store stays, renamed, as the backup.
        let backup = backup_path(data);
        fs::rename(data.join(V1_FILE), &backup)
            .with_context(|| format!("renaming store.redb to {}", backup.display()))?;
        self.keep = false;
        sync_dir(data)?;
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        if let Err(error) = fs::remove_dir_all(&self.dir)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!("removing {}: {error}", self.dir.display());
        }
    }
}

/// `store.redb.v1.bak`, or `.1`, `.2`… after it if one is there already.
fn backup_path(data: &Path) -> PathBuf {
    let mut path = data.join(BACKUP_FILE);
    let mut n = 1;
    while path.exists() {
        path = data.join(format!("{BACKUP_FILE}.{n}"));
        n += 1;
    }
    path
}

fn private_dir(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

fn sync_dir(dir: &Path) -> Result<()> {
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A data dir as a cutover cut short before its commit point leaves it:
    /// `store.redb`, the moved v2 `v/` and `device/`, and the marker.
    fn interrupted() -> tempfile::TempDir {
        let data = tempfile::tempdir().unwrap();
        let fast = KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        };
        let seed = [4u8; 32];
        let mut loaded =
            crate::daemon::session::Loaded::setup_with(data.path(), b"pass", "laptop", fast, &seed)
                .unwrap();
        loaded.create_vault_with_kit("personal").unwrap();
        drop(loaded);
        fs::write(data.path().join(V1_FILE), b"v1").unwrap();
        assert!(crate::disk::is_initialized(data.path()));
        assert!(data.path().join(VAULTS).is_dir());
        data
    }

    #[test]
    fn a_v2_device_beside_a_stray_store_redb_is_on_v2() {
        let data = interrupted();
        assert!(!has_unmigrated_v1_store(data.path()));
    }

    #[test]
    fn an_interrupted_cutover_is_still_on_v1_and_starts_over() {
        let data = interrupted();
        let staging = data.path().join(STAGING);
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join(VERIFIED), b"").unwrap();
        assert!(has_unmigrated_v1_store(data.path()));

        let fresh = Staging::fresh(data.path()).unwrap();
        assert!(!data.path().join(DEVICE).exists());
        assert!(!data.path().join(VAULTS).exists());
        assert!(!fresh.dir.join(VERIFIED).exists());
        assert_eq!(fs::read(data.path().join(V1_FILE)).unwrap(), b"v1");
        assert!(has_unmigrated_v1_store(data.path()));
        drop(fresh);
        assert!(!staging.exists());
    }

    #[test]
    fn a_cutover_that_fails_before_committing_keeps_its_marker() {
        let data = tempfile::tempdir().unwrap();
        fs::write(data.path().join(V1_FILE), b"v1").unwrap();
        let staging = Staging::fresh(data.path()).unwrap();
        let marker = staging.dir.join(VERIFIED);
        // Nothing was built, so moving `device/` fails after the marker.
        assert!(staging.cut_over(data.path()).is_err());
        assert!(marker.is_file());
        assert!(data.path().join(V1_FILE).is_file());
        assert!(has_unmigrated_v1_store(data.path()));
        Staging::fresh(data.path()).unwrap();
        assert!(!marker.exists());
    }
}
