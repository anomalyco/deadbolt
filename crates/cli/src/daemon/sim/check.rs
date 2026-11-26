//! The simulator's invariants: what every step must keep true, and when the
//! world counts as converged.

use super::{FILE_MARKER, SECRET_MARKER, World};
use anyhow::{Result, ensure};
use deadbolt_core::v2::{EpochId, Frame, FrameKind};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;

impl World {
    pub(super) fn check(&mut self) -> Result<()> {
        let mut all = BTreeMap::new();
        for d in &self.devices {
            if d.open() {
                d.with(|s| {
                    for v in s.vaults.values() {
                        for f in v.frames() {
                            all.insert(f.id(), f.clone());
                        }
                    }
                    Ok(())
                })?;
            }
        }
        let counted = deadbolt_core::v2::resolve(&self.vault, all.values(), []).authorized_frames;
        for (_, removal) in &self.removals {
            if all.contains_key(removal) {
                if counted.contains(removal) {
                    self.voided.remove(removal);
                } else {
                    self.voided.insert(*removal);
                }
            }
        }
        for forbidden in self.forbidden.values_mut() {
            forbidden.retain(|(removal, _)| !self.voided.contains(removal));
        }
        // A removal's descendants: the member frames that depend on it, and
        // the data sealed under the epochs those (and it) minted.
        for (target, removal) in &self.removals {
            if self.voided.contains(removal) {
                continue;
            }
            let mut descendants = BTreeSet::from([*removal]);
            loop {
                let before = descendants.len();
                for (id, f) in &all {
                    if f.member_body()
                        .is_some_and(|b| b.deps.iter().any(|d| descendants.contains(d)))
                    {
                        descendants.insert(*id);
                    }
                }
                if before == descendants.len() {
                    break;
                }
            }
            let epochs: BTreeSet<EpochId> = descendants
                .iter()
                .map(|id| EpochId::from_frame_id(*id))
                .collect();
            for (id, f) in &all {
                if f.header().kind != FrameKind::Member && epochs.contains(&f.header().epoch) {
                    descendants.insert(*id);
                }
            }
            let forbidden = self.forbidden.entry(*target).or_default();
            for id in descendants {
                if id != *removal
                    && let Some(frame) = all.get(&id)
                    && !forbidden
                        .iter()
                        .any(|(r, f)| *r == *removal && f.id() == id)
                {
                    forbidden.push((*removal, frame.clone()));
                }
            }
        }
        for (i, d) in self.devices.iter().enumerate() {
            if d.open() {
                d.with(|s| {
                    let accepted: BTreeSet<_> = s
                        .vaults
                        .values()
                        .flat_map(|v| v.frames().map(Frame::id))
                        .collect();
                    let mut persisted = Vec::new();
                    s.store.for_each_frame(&mut |_, bytes| {
                        persisted.push(Frame::decode(bytes)?.id());
                        Ok(())
                    })?;
                    let persisted_set: BTreeSet<_> = persisted.iter().copied().collect();
                    ensure!(
                        accepted == persisted_set && accepted.len() == persisted.len(),
                        "accepted/persisted mismatch on {i}"
                    );
                    for (_, f) in self.forbidden.get(&i).into_iter().flatten() {
                        ensure!(
                            !accepted.contains(&f.id()),
                            "removed device {i} accepted causal descendant"
                        );
                    }
                    Ok(())
                })?;
            }
            let unreported = d.unreported.lock().unwrap();
            ensure!(
                unreported.is_empty(),
                "device {i} accepted a batch watchers didn't hear about: {}",
                unreported.join("; ")
            );
            drop(unreported);
            let mut dirs = vec![d.dir.path().to_path_buf()];
            while let Some(dir) = dirs.pop() {
                for file in std::fs::read_dir(&dir)? {
                    let file = file?;
                    if file.file_type()?.is_dir() {
                        dirs.push(file.path());
                        continue;
                    }
                    // All filesystem mutations are through these real stores. An
                    // unchanged file retains the previous step's successful scan.
                    let meta = file.metadata()?;
                    let version = (meta.modified()?, meta.len());
                    if self.scanned.get(&file.path()) == Some(&version) {
                        continue;
                    }
                    let bytes = std::fs::read(file.path())?;
                    ensure!(
                        memchr::memmem::find(&bytes, SECRET_MARKER.as_bytes()).is_none()
                            && memchr::memmem::find(&bytes, FILE_MARKER.as_bytes()).is_none(),
                        "plaintext on device {i} disk: {}",
                        file.path().display()
                    );
                    self.scanned.insert(file.path(), version);
                }
            }
        }
        Ok(())
    }

    /// Whether device `i` was removed by anyone, whether or not every
    /// device has heard, and the fold counts it (as of the last check).
    pub(super) fn removed(&self, i: usize) -> bool {
        self.removals
            .iter()
            .any(|(target, r)| *target == i && !self.voided.contains(r))
    }

    /// Whether every device nobody removed agrees. A removed device (the
    /// creator included) is cut off and keeps its last view; so may the
    /// devices only it knew about, and those are removed too or never
    /// joined: a removal made concurrently with the remover's own removal
    /// only reaches the devices that can still talk to the remover.
    pub(super) fn converged(&self) -> Result<bool> {
        let mut reference = None;
        for (i, d) in self.devices.iter().enumerate() {
            if !self.removed(i) && d.with(|s| Ok(s.vaults.contains_key(&self.vault)))? {
                reference = Some(&self.devices[i]);
                break;
            }
        }
        let Some(reference) = reference else {
            return Ok(true);
        };
        let members =
            reference.with(|s| Ok(s.vault(&self.vault).members().collect::<BTreeSet<_>>()))?;
        let (heads, items, deleted, name, parked) = reference.with(|s| {
            let vault = s.vault(&self.vault);
            Ok((
                vault.heads(),
                vault.items(),
                vault.deleted(),
                vault.name().to_owned(),
                !vault.parked().is_empty(),
            ))
        })?;
        for (i, d) in self.devices.iter().enumerate() {
            if self.removed(i) || !members.contains(&d.id) {
                continue;
            }
            if !d.ready.load(Ordering::SeqCst) {
                return Ok(false);
            }
            let same = d.with(|s| {
                let vault = s
                    .vaults
                    .get(&self.vault)
                    .ok_or_else(|| anyhow::anyhow!("member missing vault"))?;
                // A parked vault (a mutual removal, a removed device back)
                // waits on a person: no member rewraps keys to the others
                // (`fulfill_reader_duty`), so only its frames and
                // membership converge, not what each device can read.
                let readable = parked
                    || !vault.parked().is_empty()
                    || (vault.items() == items && vault.deleted() == deleted);
                Ok(vault.heads() == heads
                    && vault.members().collect::<BTreeSet<_>>() == members
                    && vault.name() == name
                    && readable)
            })?;
            if !same {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
