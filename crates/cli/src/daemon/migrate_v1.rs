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
//! `<data>/.v1-migrate/`, reopened and checked item by item, and only then
//! moved into place (`v/`, then `device/`, which is what makes the device
//! set up); after that `store.redb` is renamed to `store.redb.v1.bak`,
//! never deleted. A failure before the move leaves only the staging folder,
//! removed again; a crash during it is undone on the next try.

mod build;
mod entry;
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
/// In the staging folder once the new store checked out: from then on a
/// `v/` in the data directory without a `device/` is this migration's.
const VERIFIED: &str = "verified";
const DEVICE: &str = "device";
const VAULTS: &str = "v";

/// Whether `data` holds a v1 store and no v2 device yet.
pub(crate) fn has_unmigrated_v1_store(data: &Path) -> bool {
    data.join(V1_FILE).is_file() && !crate::disk::is_initialized(data)
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
        &staging.0.join("store.redb.copy"),
        passphrase,
    )?;
    let entries = v1
        .entries
        .iter()
        .map(|bytes| entry::Entry::decode(bytes))
        .collect::<Result<Vec<_>>>()?;
    let vaults = replay::vaults(entries)?;
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
    let moved = build::build(&staging.0.join("store"), passphrase, params, &plan)?;
    staging.cut_over(data)?;
    Ok(moved)
}

/// The staging folder, removed when dropped.
struct Staging(PathBuf);

impl Staging {
    /// An empty staging folder, after undoing what a crashed migration left.
    fn fresh(data: &Path) -> Result<Self> {
        let dir = data.join(STAGING);
        let vaults = data.join(VAULTS);
        if dir.join(VERIFIED).exists() && vaults.exists() && !data.join(DEVICE).exists() {
            // Cut short between moving `v/` and `device/`: the vaults are
            // this migration's, and its kits were never shown. Start over.
            fs::remove_dir_all(&vaults).context("removing a half-moved v2 store")?;
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
        Ok(Self(dir))
    }

    /// Moves the checked store into `data`, then backs up `store.redb`.
    fn cut_over(self, data: &Path) -> Result<()> {
        let built = self.0.join("store");
        fs::File::create(self.0.join(VERIFIED))?.sync_all()?;
        sync_dir(&self.0)?;
        let vaults = built.join(VAULTS);
        let moved_vaults = vaults.exists();
        if moved_vaults {
            fs::rename(&vaults, data.join(VAULTS)).context("moving the new vaults into place")?;
        }
        if let Err(error) = fs::rename(built.join(DEVICE), data.join(DEVICE)) {
            if moved_vaults && let Err(back) = fs::rename(data.join(VAULTS), &vaults) {
                tracing::warn!("moving the new vaults back: {back}");
            }
            return Err(error).context("moving the new device into place");
        }
        sync_dir(data)?;
        // On v2 now. The old store stays, renamed, as the backup.
        let backup = backup_path(data);
        fs::rename(data.join(V1_FILE), &backup)
            .with_context(|| format!("renaming store.redb to {}", backup.display()))?;
        sync_dir(data)?;
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!("removing {}: {error}", self.0.display());
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
