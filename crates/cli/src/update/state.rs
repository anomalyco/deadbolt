//! Update lock and remembered manifest sequence floors in the state directory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::protocol::validated;

/// One CLI update at a time per state directory, through the final replacement,
/// not just the floor write: an older in-flight download must not install last.
/// Keep the lock file in place; locking the atomically replaced JSON would let
/// another process lock a different inode.
pub(super) struct UpdateState {
    pub(super) dir: PathBuf,
    pub(super) lock: std::fs::File,
}

impl UpdateState {
    pub(super) fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join("update.lock");
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                bail!("another deadbolt update is running; try again when it finishes");
            }
            Err(error) => return Err(error).with_context(|| format!("locking {}", path.display())),
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            lock,
        })
    }
}

impl Drop for UpdateState {
    fn drop(&mut self) {
        // Closing our descriptor alone may leave the lock held by a concurrent
        // fork until exec closes its inherited CLOEXEC descriptor. The update
        // transaction is finished now; unlock the shared description explicitly.
        if let Err(error) = self.lock.unlock() {
            eprintln!(
                "warning: couldn't release {}: {error}",
                self.dir.join("update.lock").display()
            );
        }
    }
}

/// The highest manifest `sequence` seen for each artifact and channel, kept
/// in the state directory, so a replayed older manifest can't take an
/// install back. A real rollback is a new write with a higher sequence
/// (docs/protocol.md, "Operations"), so it passes.
pub(super) fn check_sequence(
    state: &UpdateState,
    artifact: &str,
    channel: &str,
    text: &str,
    allow_rollback: bool,
) -> Result<()> {
    let sequence = validated(artifact, channel, text)
        .map_err(|reason| anyhow::anyhow!("not a usable {artifact} manifest ({reason})"))?
        .sequence;
    let path = state.dir.join("release-sequences.json");
    let mut seen = read_floors(&state.dir)?;
    let key = format!("{artifact}/{channel}");
    let highest = seen.get(&key).copied().unwrap_or(0);
    if sequence < highest && !allow_rollback {
        bail!(
            "the service sent an older {artifact} manifest for {channel} (sequence {sequence}, \
             but {highest} was seen); pass --allow-rollback to accept it"
        );
    }
    if sequence > highest {
        seen.insert(key, sequence);
        crate::browser::write_atomic(&path, &serde_json::to_string(&seen)?)?;
    }
    Ok(())
}

/// The highest manifest sequences seen, from `release-sequences.json` in
/// `dir`, the state directory.
pub(super) fn read_floors(dir: &Path) -> Result<BTreeMap<String, u64>> {
    let path = dir.join("release-sequences.json");
    let recovery = || {
        format!(
            "reading {}: cannot use release sequence state; restore this file from a trusted \
             backup (or correct its read permissions). Deleting it loses all remembered \
             replay floors; deadbolt will not delete it automatically",
            path.display()
        )
    };
    Ok(match std::fs::read(&path) {
        Ok(bytes) if bytes.is_empty() => BTreeMap::new(),
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(recovery)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(error) => return Err(error).with_context(recovery),
    })
}
