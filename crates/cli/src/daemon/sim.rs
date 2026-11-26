//! Deterministic exploration through the production CLI handlers, core and
//! the pack-backed stores. Core's randomness and the engines' clock are
//! seeded per world, so a trace replays byte for byte.
mod check;
mod device;
mod network;
#[cfg(test)]
mod tests;

use super::{pairing, sync};
use anyhow::{Context, Result, ensure};
use deadbolt_core::VaultId;
use deadbolt_core::v2::{Frame, FrameId, MemberOp};
use deadbolt_net::{PairingCode, PairingStream, run_sync_session};
use device::{Device, Invitation, MAX};
use network::{Rng, drive, link};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::atomic::Ordering,
};

const DEVICES: usize = 4;
const SECRET_MARKER: &str = "SIM-SECRET-";
/// A file's contents start with the marker, so its value (base64) starts
/// with this: the marker's first nine bytes, encoded.
const FILE_MARKER: &str = "U0lNLVNFQ1JF";

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Action {
    Add(usize, u64),
    Edit(usize, u64),
    /// Sets a file field (its name and contents carrying the marker) on
    /// the first item, or a new note.
    Attach(usize, u64),
    Favorite(usize, bool),
    /// Adds a nested tag carrying [`SECRET_MARKER`] so disk and wire scans
    /// catch any plaintext tag leak.
    Tag(usize, u64),
    Untag(usize),
    Delete(usize),
    /// Restores the most recently deleted item.
    Restore(usize),
    Pair(usize),
    Remove(usize),
    Sync(usize, usize, u64, Option<usize>),
    Partition(usize, usize),
    Heal,
    Lock(usize),
    Unlock(usize),
    Crash(usize),
    Startup(usize),
    WriteFailure(usize),
    RevokeDuringSync(usize, u64, usize),
    /// Device `.0` removes device `.1`, as far as its own view allows:
    /// with partitions, removals that run concurrently and offline.
    RemoveBy(usize, usize),
}

/// 2023-11-14, the engines' fixed now.
const NOW: std::time::Duration = std::time::Duration::from_secs(1_700_000_000);

/// Whether `error` is a write the vault refused for a reason the simulation
/// can cause on purpose: writes parked, keys not yet shared, a rule broken.
fn refused(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|e| e.downcast_ref::<deadbolt_core::Error>().is_some())
}

/// Runs a local write, treating a refusal (see [`refused`]) as a no-op.
fn tolerate<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if refused(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

struct World {
    devices: Vec<Device>,
    vault: VaultId,
    blocked: BTreeSet<(usize, usize)>,
    // A removal's causal descendants must never reach its target, even as raw bytes.
    removals: Vec<(usize, FrameId)>,
    /// Recorded removals the fold over every open device's frames doesn't
    /// count: a junior device's removal of a senior one that wrote
    /// something concurrently loses to it. Not a removal, so it forbids
    /// nothing.
    voided: BTreeSet<FrameId>,
    /// Per target, the frames it must never receive, each with the removal
    /// that forbids it.
    forbidden: BTreeMap<usize, Vec<(FrameId, Frame)>>,
    scanned: BTreeMap<std::path::PathBuf, (std::time::SystemTime, u64)>,
    digest: blake3::Hasher,
}

impl World {
    fn new() -> Result<Self> {
        deadbolt_core::rng::deterministic(Some(42));
        crate::config::TEST_NOW.set(Some(NOW));
        let devices: Vec<_> = (0..DEVICES).map(Device::new).collect();
        let vault = devices[0].with(|s| s.create_vault("sim"))?;
        Ok(Self {
            devices,
            vault,
            blocked: BTreeSet::new(),
            removals: vec![],
            voided: BTreeSet::new(),
            forbidden: BTreeMap::new(),
            scanned: BTreeMap::new(),
            digest: blake3::Hasher::new(),
        })
    }

    fn pair(&mut self, to: usize) -> Result<()> {
        self.pair_with_cut(to, None)
    }

    fn pair_with_cut(&mut self, to: usize, cut: Option<usize>) -> Result<()> {
        if to == 0
            || !self.devices[0].ready.load(Ordering::SeqCst)
            || !self.devices[to].open()
            || !self.devices[0].open()
            || self.blocked.contains(&(0, to))
        {
            return Ok(());
        }
        if self.devices[to].with(|s| Ok(s.vaults.contains_key(&self.vault)))? {
            return Ok(());
        }
        // Removed keys cannot be re-added, including a failed welcome delivery,
        // and a removed inviter can't invite.
        if self.removals.iter().any(|(i, _)| *i == to) || self.removed(0) {
            return Ok(());
        }
        let (a, b, aw, bw) = link();
        let (mut ar, mut at) = tokio::io::split(a);
        let (mut br, mut bt) = tokio::io::split(b);
        let invite = Invitation {
            device: &self.devices[0],
            vault: self.vault,
        };
        // Fixed code and scalar seeds: the PAKE replays byte for byte.
        let code = PairingCode::from_str("violin-garden-tiger-lamp-zoo")?;
        let dial = PairingStream::new(
            self.devices[0].net,
            self.devices[to].net,
            &code,
            [7; 32],
            [9; 32],
            false,
            [to as u8; 32],
        );
        let listen = PairingStream::new(
            self.devices[to].net,
            self.devices[0].net,
            &code,
            [7; 32],
            [9; 32],
            true,
            [to as u8 + 100; 32],
        );
        let join = async {
            listen
                .prove(&mut bt, &mut br)
                .await?
                .complete(&mut bt, &mut br, MAX, &self.devices[to])
                .await
        };
        let (result, wires) = drive(
            dial.invite(&mut at, &mut ar, MAX, &invite),
            join,
            aw,
            bw,
            to as u64,
            cut,
            |_| false,
        );
        self.digest.update(&wires[0]);
        self.digest.update(&wires[1]);
        if result.is_none() && cut.is_some() {
            return Ok(());
        }
        let (a, b) = result.ok_or_else(|| anyhow::anyhow!("pair protocol stalled"))?;
        ensure!(
            a?.peer == self.devices[to].net && b?.peer == self.devices[0].net,
            "paired with the wrong device"
        );
        Ok(())
    }

    fn sync(
        &mut self,
        a: usize,
        b: usize,
        seed: u64,
        cut: Option<usize>,
        revoke_at: Option<usize>,
    ) -> Result<sync::Attempt> {
        if a == b
            || self.blocked.contains(&(a.min(b), a.max(b)))
            || !self.devices[a].open()
            || !self.devices[b].open()
        {
            return Ok(sync::Attempt::Unreachable);
        }
        if self.devices[a]
            .gate
            .check_dial(&self.devices[b].net)
            .is_err()
            || self.devices[b]
                .gate
                .check_dial(&self.devices[a].net)
                .is_err()
        {
            return Ok(sync::Attempt::Unreachable);
        }
        let (left, right, aw, bw) = link();
        let (mut ar, mut at) = tokio::io::split(left);
        let (mut br, mut bt) = tokio::io::split(right);
        let ah = self.devices[a].handler();
        let bh = self.devices[b].handler();
        let mut removal = None;
        let mut failure = None;
        let (result, wires) = drive(
            run_sync_session(&ah, self.devices[b].net, &mut at, &mut ar, MAX, true),
            run_sync_session(&bh, self.devices[a].net, &mut bt, &mut br, MAX, false),
            aw,
            bw,
            seed,
            cut,
            |tick| {
                if revoke_at == Some(tick) {
                    let target = self.devices[b].id;
                    // Only a current member can be removed.
                    match self.devices[a].with(|s| {
                        if !s.vault(&self.vault).is_member(&target) {
                            return Ok(None);
                        }
                        tolerate(s.update(self.vault, |v, a| Ok(v.remove(a, target)?)))
                    }) {
                        Ok(Some(frame)) => {
                            removal = Some(frame);
                            self.devices[a].gate.enforce_membership();
                        }
                        Ok(None) => {}
                        Err(error) => failure = Some(error),
                    }
                }
                failure.is_some()
                    || self.devices[a]
                        .gate
                        .check_dial(&self.devices[b].net)
                        .is_err()
                    || self.devices[b]
                        .gate
                        .check_dial(&self.devices[a].net)
                        .is_err()
            },
        );
        if let Some(error) = failure {
            return Err(error);
        }
        if let Some(frame) = removal {
            self.removals.push((b, frame));
        }
        ensure!(
            result.is_some()
                || cut.is_some()
                || removal.is_some()
                || self.devices[a]
                    .gate
                    .check_dial(&self.devices[b].net)
                    .is_err()
                || self.devices[b]
                    .gate
                    .check_dial(&self.devices[a].net)
                    .is_err(),
            "sync protocol stalled, network seed {seed}"
        );
        for (target, bytes) in [(b, &wires[0]), (a, &wires[1])] {
            for (_, frame) in self.forbidden.get(&target).into_iter().flatten() {
                let encoded = frame.encode();
                ensure!(
                    memchr::memmem::find(bytes, &encoded).is_none(),
                    "removed device {target} received post-removal bytes: {:?} {:?} by {} in {a}<->{b}",
                    frame.header().kind,
                    frame.member_body().map(|m| &m.op),
                    frame.header().author
                );
            }
        }
        self.digest.update(&wires[0]);
        self.digest.update(&wires[1]);
        Ok(if result.is_some_and(|(a, b)| a.is_ok() && b.is_ok()) {
            sync::Attempt::Complete
        } else {
            sync::Attempt::Interrupted
        })
    }

    fn startup(&mut self, i: usize) -> Result<()> {
        if !self.devices[i].open() || self.devices[i].ready.load(Ordering::SeqCst) {
            return Ok(());
        }
        let targets = self.devices[i].with(|s| Ok(s.peer_set()))?;
        let mut attempts = BTreeMap::new();
        for j in 0..DEVICES {
            let peer = self.devices[j].id;
            if targets.contains(&peer) {
                attempts.insert(peer, self.sync(i, j, (i * DEVICES + j) as u64, None, None)?);
            }
        }
        self.devices[i].with(|s| {
            if sync::barrier_complete(&s.peer_set(), &attempts) {
                self.devices[i].ready.store(true, Ordering::SeqCst);
            }
            Ok(())
        })
    }

    fn step(&mut self, action: &Action) -> Result<()> {
        match *action {
            Action::Pair(i) => self.pair(i)?,
            Action::Partition(a, b) => {
                self.blocked.insert((a.min(b), a.max(b)));
            }
            Action::Heal => self.blocked.clear(),
            Action::Lock(i) => {
                self.devices[i].state.lock().unwrap().take();
                self.devices[i].ready.store(false, Ordering::SeqCst);
            }
            Action::Unlock(i) if !self.devices[i].open() => self.devices[i].reopen()?,
            Action::Crash(i) if self.devices[i].open() => {
                let before = self.devices[i].with(|s| {
                    Ok(s.vaults
                        .iter()
                        .map(|(id, v)| (*id, v.heads()))
                        .collect::<BTreeMap<_, _>>())
                })?;
                self.devices[i].reopen()?;
                let after = self.devices[i].with(|s| {
                    Ok(s.vaults
                        .iter()
                        .map(|(id, v)| (*id, v.heads()))
                        .collect::<BTreeMap<_, _>>())
                })?;
                ensure!(before == after, "restart lost accepted log on {i}");
            }
            Action::Sync(a, b, seed, cut) => {
                self.sync(a, b, seed, cut, None)?;
            }
            Action::Startup(i) => self.startup(i)?,
            Action::RevokeDuringSync(b, seed, tick) if b != 0 => {
                self.sync(0, b, seed, None, Some(tick))?;
            }
            Action::WriteFailure(i) if self.can_write(i) => {
                self.devices[i].with(|s| {
                    let s: &mut deadbolt_engine::Engine = s;
                    let author = s.author();
                    let vault = s.vaults.get_mut(&self.vault).unwrap();
                    let name = vault.name().to_owned();
                    let frames = vault.frames().count();
                    let result = vault.transact(
                        |v| Ok(v.rename(&author, name)?),
                        |_, _| anyhow::bail!("injected disk full"),
                    );
                    ensure!(result.is_err(), "write fault was not injected");
                    ensure!(
                        vault.frames().count() == frames,
                        "a failed write left a frame"
                    );
                    Ok(())
                })?;
            }
            Action::Remove(i) if i != 0 => self.remove(0, i)?,
            Action::RemoveBy(by, target) if by != target => self.remove(by, target)?,
            Action::Add(i, value) | Action::Edit(i, value) if self.can_write(i) => {
                let value = format!("{SECRET_MARKER}{value:016x}-never-on-disk");
                self.write(i, |s| {
                    let fields = vec![crate::protocol::FieldInput {
                        name: "password".into(),
                        kind: None,
                        value,
                    }];
                    if matches!(action, Action::Edit(..))
                        && let Some(item) = s.vault(&self.vault).items().first()
                    {
                        super::items::set(s, None, &[item.id.to_string()], fields, None, &[])?;
                    } else {
                        super::items::create(s, None, "login", None, fields)?;
                    }
                    Ok(())
                })?;
            }
            Action::Attach(i, value) if self.can_write(i) => {
                let name = format!("{SECRET_MARKER}{value:016x}.txt");
                let contents = format!("{SECRET_MARKER}{value:016x}-never-on-disk");
                let file = deadbolt_core::item::file_value(&name, contents.as_bytes());
                self.write(i, |s| {
                    let fields = vec![crate::protocol::FieldInput {
                        name: "receipt".into(),
                        kind: Some("file".into()),
                        value: file.to_string(),
                    }];
                    match s.vault(&self.vault).items().first() {
                        Some(item) => {
                            let id = [item.id.to_string()];
                            super::items::set(s, None, &id, fields, None, &[])?;
                        }
                        None => {
                            super::items::create(s, None, "note", Some("n".into()), fields)?;
                        }
                    }
                    Ok(())
                })?;
            }
            Action::Favorite(i, fav) if self.can_write(i) => {
                let value = format!("{SECRET_MARKER}{i:04x}-fav-pw");
                self.write(i, |s| {
                    match s.vault(&self.vault).items().first() {
                        Some(item) => {
                            let id = [item.id.to_string()];
                            super::items::set_with(
                                s,
                                None,
                                &id,
                                vec![],
                                None,
                                &[],
                                Some(fav),
                                &[],
                                &[],
                            )?;
                        }
                        None => {
                            let fields = vec![crate::protocol::FieldInput {
                                name: "password".into(),
                                kind: None,
                                value,
                            }];
                            super::items::create_with(
                                s,
                                None,
                                "login",
                                None,
                                fields,
                                fav,
                                Vec::new(),
                            )?;
                        }
                    }
                    Ok(())
                })?;
            }
            Action::Tag(i, value) if self.can_write(i) => {
                let tag = format!("{SECRET_MARKER}{:08x}/sub", value & 0xffff_ffff);
                let pw = format!("{SECRET_MARKER}{value:016x}-tag-pw");
                self.write(i, |s| {
                    match s.vault(&self.vault).items().first() {
                        Some(item) if item.tags.len() < deadbolt_core::tag::MAX_TAGS => {
                            let id = [item.id.to_string()];
                            super::items::set_with(
                                s,
                                None,
                                &id,
                                vec![],
                                None,
                                &[],
                                None,
                                &[tag],
                                &[],
                            )?;
                        }
                        Some(_) => {}
                        None => {
                            let fields = vec![crate::protocol::FieldInput {
                                name: "password".into(),
                                kind: None,
                                value: pw,
                            }];
                            super::items::create_with(
                                s,
                                None,
                                "login",
                                None,
                                fields,
                                false,
                                vec![tag],
                            )?;
                        }
                    }
                    Ok(())
                })?;
            }
            Action::Untag(i) if self.can_write(i) => {
                self.write(i, |s| {
                    if let Some(item) = s.vault(&self.vault).items().first()
                        && let Some(tag) = item.tags.first().cloned()
                    {
                        let id = [item.id.to_string()];
                        super::items::set_with(s, None, &id, vec![], None, &[], None, &[], &[tag])?;
                    }
                    Ok(())
                })?;
            }
            Action::Delete(i) if self.can_write(i) => {
                self.write(i, |s| {
                    if let Some(item) = s.vault(&self.vault).items().first() {
                        super::items::remove(s, None, &[item.id.to_string()])?;
                    }
                    Ok(())
                })?;
            }
            Action::Restore(i) if self.can_write(i) => {
                self.write(i, |s| {
                    if let Some(gone) = s.vault(&self.vault).deleted().first() {
                        super::items::restore(s, None, &[gone.item.id.to_string()])?;
                    }
                    Ok(())
                })?;
            }
            _ => {}
        }
        self.check()
    }

    /// A local write on device `i`, which the vault may refuse.
    fn write(&self, i: usize, f: impl FnOnce(&mut device::Loaded) -> Result<()>) -> Result<()> {
        tolerate(self.devices[i].with(f)).map(drop)
    }

    /// Where device `i` stands in admission order: the creator first, then
    /// each device by the seq of the `Add` device 0 wrote for it (device 0
    /// invites every pairing). `None` if device 0 is locked or never added it.
    fn seniority(&self, i: usize) -> Result<Option<u64>> {
        if i == 0 {
            return Ok(Some(0));
        }
        if !self.devices[0].open() {
            return Ok(None);
        }
        let (inviter, device) = (self.devices[0].id, self.devices[i].id);
        self.devices[0].with(|s| {
            Ok(s.vaults.get(&self.vault).and_then(|v| {
                v.frames()
                    .filter(|f| f.header().author == inviter)
                    .filter(|f| {
                        f.member_body().is_some_and(|b| {
                            matches!(&b.op, Some(MemberOp::Add { device: d, .. }) if *d == device)
                        })
                    })
                    .map(|f| f.header().seq + 1)
                    .min()
            }))
        })
    }

    /// Device `by` removes `target`, if `by` is open, a member and sees
    /// `target` as one, whichever of them is senior.
    ///
    /// A junior device's removal of a senior one loses when the senior
    /// removed someone concurrently. The junior's gate still admits the
    /// removed senior for a membership-only push
    /// (`deadbolt_net::application::hello`), so the senior's winning frames
    /// reach it and the two reconverge without a third device.
    fn remove(&mut self, by: usize, target: usize) -> Result<()> {
        let peer = self.devices[target].id;
        if self.seniority(by)?.is_none() || self.seniority(target)?.is_none() {
            return Ok(());
        }
        if !self.can_write(by)
            || !self.devices[by].with(|s| Ok(s.vault(&self.vault).is_member(&peer)))?
        {
            return Ok(());
        }
        let removal = self.devices[by]
            .with(|s| tolerate(s.update(self.vault, |v, a| Ok(v.remove(a, peer)?))))?;
        if let Some(frame) = removal {
            self.removals.push((target, frame));
        }
        Ok(())
    }

    fn can_write(&self, i: usize) -> bool {
        self.devices[i]
            .with(|s| {
                Ok(s.vaults
                    .get(&self.vault)
                    .is_some_and(|v| v.is_member(&s.id)))
            })
            .unwrap_or(false)
    }

    fn converge(&mut self) -> Result<()> {
        self.blocked.clear();
        for d in &mut self.devices {
            if !d.open() {
                d.reopen()?;
            }
        }
        for round in 0..(DEVICES * 3) {
            let mut attempts = vec![BTreeMap::new(); DEVICES];
            for a in 0..DEVICES {
                for b in a + 1..DEVICES {
                    let attempt = self.sync(a, b, (round * DEVICES + b) as u64, None, None)?;
                    attempts[a].insert(self.devices[b].id, attempt);
                    attempts[b].insert(self.devices[a].id, attempt);
                }
            }
            for (a, attempts) in attempts.iter().enumerate() {
                let peers = self.devices[a].with(|s| Ok(s.peer_set()))?;
                if sync::barrier_complete(&peers, attempts) {
                    self.devices[a].ready.store(true, Ordering::SeqCst);
                }
            }
            self.check()?;
            if self.converged()? {
                return Ok(());
            }
        }
        anyhow::bail!("members did not converge within bounded rounds")
    }
}

impl Drop for World {
    fn drop(&mut self) {
        deadbolt_core::rng::deterministic(None);
        crate::config::TEST_NOW.set(None);
    }
}
