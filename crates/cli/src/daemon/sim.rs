//! Deterministic exploration through the production CLI handlers, core and redb.
mod device;
mod network;
#[cfg(test)]
mod tests;

use super::{pairing, sync};
use anyhow::{Context, Result, ensure};
use deadbolt_core::{
    DeviceId, Entry, Hash, Log, LogId, MAX_MEMBERSHIP_ENTRIES, MembershipOp, Payload, Vault,
    VaultId,
};
use deadbolt_net::{PairingCode, PairingStream, run_sync_session};
use device::{Device, Invitation, MAX, membership_writes};
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
    /// Raw signed membership entries, including a suffix beyond the author cap.
    MembershipFlood(usize, usize),
}

struct World {
    devices: Vec<Device>,
    vault: VaultId,
    blocked: BTreeSet<(usize, usize)>,
    // A removal's causal descendants must never reach its target, even as raw bytes.
    removals: Vec<(usize, Hash)>,
    forbidden: BTreeMap<usize, Vec<Entry>>,
    scanned: BTreeMap<std::path::PathBuf, (std::time::SystemTime, u64)>,
    digest: blake3::Hasher,
}

impl World {
    fn new() -> Result<Self> {
        let devices: Vec<_> = (0..DEVICES).map(Device::new).collect();
        let vault = devices[0].with(|s| {
            let nonce = [42; 32];
            let id = VaultId::derive(&s.id, &nonce);
            let genesis = Entry::sign(
                &s.secret(),
                id,
                0,
                [],
                Payload::Membership(MembershipOp::Create {
                    device: s.id,
                    nonce,
                    name: "sim".into(),
                }),
            );
            s.add_vault(Vault::from_genesis(genesis)?)?;
            Ok(id)
        })?;
        Ok(Self {
            devices,
            vault,
            blocked: BTreeSet::new(),
            removals: vec![],
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
        // A full non-removal budget cannot admit another device. Re-sending
        // an already committed admission still works without consuming a slot.
        if self.devices[0].with(|s| {
            Ok(!s
                .vault(&self.vault)
                .is_member(&DeviceId::from_bytes(self.devices[to].id))
                && membership_writes(s.vault(&self.vault), s.id) >= MAX_MEMBERSHIP_ENTRIES)
        })? {
            return Ok(());
        }
        // Removed keys cannot be re-added, including a failed welcome delivery.
        if self.removals.iter().any(|(i, _)| *i == to) {
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
            self.devices[0].id,
            self.devices[to].id,
            &code,
            [7; 32],
            [9; 32],
            false,
            [to as u8; 32],
        );
        let listen = PairingStream::new(
            self.devices[to].id,
            self.devices[0].id,
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
            a?.peer == self.devices[to].id && b?.peer == self.devices[0].id,
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
            .check_dial(&self.devices[b].id)
            .is_err()
            || self.devices[b]
                .gate
                .check_dial(&self.devices[a].id)
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
            run_sync_session(&ah, self.devices[b].id, &mut at, &mut ar, MAX, true),
            run_sync_session(&bh, self.devices[a].id, &mut bt, &mut br, MAX, false),
            aw,
            bw,
            seed,
            cut,
            |tick| {
                if revoke_at == Some(tick) {
                    let target = DeviceId::from_bytes(self.devices[b].id);
                    // Only a current member can be removed.
                    match self.devices[a].with(|s| {
                        if !s.vault(&self.vault).is_member(&target) {
                            return Ok(None);
                        }
                        s.update(self.vault, |v, key| Ok(v.remove(key, target)?))
                            .map(Some)
                    }) {
                        Ok(Some(entry)) => {
                            removal = Some(entry.hash());
                            self.devices[a].gate.enforce_membership();
                        }
                        Ok(None) => {}
                        Err(error) => failure = Some(error),
                    }
                }
                failure.is_some()
                    || self.devices[a]
                        .gate
                        .check_dial(&self.devices[b].id)
                        .is_err()
                    || self.devices[b]
                        .gate
                        .check_dial(&self.devices[a].id)
                        .is_err()
            },
        );
        if let Some(error) = failure {
            return Err(error);
        }
        if let Some(hash) = removal {
            self.removals.push((b, hash));
        }
        ensure!(
            result.is_some()
                || cut.is_some()
                || removal.is_some()
                || self.devices[a]
                    .gate
                    .check_dial(&self.devices[b].id)
                    .is_err()
                || self.devices[b]
                    .gate
                    .check_dial(&self.devices[a].id)
                    .is_err(),
            "sync protocol stalled, network seed {seed}"
        );
        for (target, bytes) in [(b, &wires[0]), (a, &wires[1])] {
            for entry in self.forbidden.get(&target).into_iter().flatten() {
                let encoded = entry.encode();
                ensure!(
                    memchr::memmem::find(bytes, &encoded).is_none(),
                    "removed device {target} received post-removal bytes"
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

    fn membership_flood(&mut self, author: usize, receiver: usize) -> Result<()> {
        if author == receiver || !self.can_write(author) || !self.can_write(receiver) {
            return Ok(());
        }
        // A simulated author keeps its accepted prefix, just as local writes
        // do. Otherwise later random actions could accidentally sign a fork.
        if self.sync(
            author,
            receiver,
            (author * DEVICES + receiver) as u64,
            None,
            None,
        )? != sync::Attempt::Complete
            || !self.can_write(author)
            || !self.can_write(receiver)
        {
            return Ok(());
        }
        let author_id = DeviceId::from_bytes(self.devices[author].id);
        let log = LogId {
            author: author_id,
            log: Log::Membership,
        };
        let (vault, consent) = self.devices[receiver].with(|s| {
            Ok((
                s.vault(&self.vault).clone(),
                s.secret().join_consent(&self.vault, &author_id),
            ))
        })?;
        if !vault.is_member(&author_id) {
            return Ok(());
        }
        // Reusing an admission consent is valid: the cap must bound even these
        // redundant Adds, not just membership operations that change the set.
        // Start at the receiver's frontier, so a repeated flood probes the
        // exhausted budget rather than accidentally replaying an earlier batch.
        let start = vault.heads().get(&log).map_or(0, |seq| seq + 1);
        let end = start + MAX_MEMBERSHIP_ENTRIES - membership_writes(&vault, author_id);
        let entries = self.devices[author].with(|s| {
            let mut deps: Vec<_> = vault
                .entries()
                .into_iter()
                .filter(|e| e.log() == Log::Membership)
                .map(Entry::hash)
                .collect();
            let mut entries = Vec::new();
            for seq in start..end + MAX_MEMBERSHIP_ENTRIES {
                let entry = Entry::sign(
                    &s.secret(),
                    self.vault,
                    seq,
                    deps,
                    Payload::Membership(MembershipOp::Add {
                        device: DeviceId::from_bytes(self.devices[receiver].id),
                        consent,
                    }),
                );
                deps = vec![entry.hash()];
                entries.push(entry);
            }
            Ok(entries)
        })?;
        let mut slowest = std::time::Duration::ZERO;
        for batch in entries.chunks(64) {
            let blobs: Vec<_> = batch.iter().map(Entry::encode).collect();
            for blob in &blobs {
                self.digest.update(blob);
            }
            let accepted = self.devices[receiver].with(|s| {
                let start = std::time::Instant::now();
                let added =
                    sync::receive(s, &author_id, blobs.clone(), true, &mut Default::default())?;
                let elapsed = start.elapsed();
                slowest = slowest.max(elapsed);
                // A generous regression watchdog, not a simulated deadline:
                // wall time never affects entry generation or delivery order.
                ensure!(
                    elapsed < std::time::Duration::from_secs(5),
                    "membership flood batch took {elapsed:?}"
                );
                let expected = batch.iter().filter(|entry| entry.seq() < end).count();
                ensure!(
                    added == expected,
                    "membership flood accepted {added}, expected {expected}"
                );
                let last = batch.last().unwrap().seq().min(end - 1);
                ensure!(
                    s.vault(&self.vault).heads().get(&log) == Some(last),
                    "membership cap head mismatch"
                );
                ensure!(
                    membership_writes(s.vault(&self.vault), author_id) <= MAX_MEMBERSHIP_ENTRIES,
                    "membership cap exceeded"
                );
                Ok(added)
            })?;
            self.devices[author].with(|s| {
                let added = sync::receive(
                    s,
                    &DeviceId::from_bytes(self.devices[receiver].id),
                    blobs,
                    true,
                    &mut Default::default(),
                )?;
                ensure!(added == accepted, "author lost its accepted flood prefix");
                Ok(())
            })?;
        }
        if std::env::var_os("DEADBOLT_SIM_TIMING").is_some() {
            eprintln!(
                "membership flood: {} entries, slowest 64-entry batch {slowest:?}",
                entries.len()
            );
        }
        Ok(())
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
            Action::MembershipFlood(a, b) => self.membership_flood(a, b)?,
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
                    let key = &s.secret();
                    let result = s.vaults.get_mut(&self.vault).unwrap().transact(
                        |v| Ok(v.write(key, vec![])?),
                        |_| anyhow::bail!("injected disk full"),
                    );
                    ensure!(result.is_err(), "write fault was not injected");
                    Ok(())
                })?;
            }
            Action::Remove(i) if i != 0 && self.devices[0].open() => {
                let peer = DeviceId::from_bytes(self.devices[i].id);
                if self.devices[0].with(|s| Ok(s.vault(&self.vault).is_member(&peer)))? {
                    let entry = self.devices[0]
                        .with(|s| s.update(self.vault, |v, key| Ok(v.remove(key, peer)?)))?;
                    self.removals.push((i, entry.hash()));
                }
            }
            Action::Add(i, value) | Action::Edit(i, value) if self.can_write(i) => {
                let value = format!("{SECRET_MARKER}{value:016x}-never-on-disk");
                self.devices[i].with(|s| {
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
                self.devices[i].with(|s| {
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
                self.devices[i].with(|s| {
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
                self.devices[i].with(|s| {
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
                self.devices[i].with(|s| {
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
                self.devices[i].with(|s| {
                    if let Some(item) = s.vault(&self.vault).items().first() {
                        super::items::remove(s, None, &[item.id.to_string()])?;
                    }
                    Ok(())
                })?;
            }
            Action::Restore(i) if self.can_write(i) => {
                self.devices[i].with(|s| {
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

    fn can_write(&self, i: usize) -> bool {
        self.devices[i]
            .with(|s| {
                Ok(s.vaults
                    .get(&self.vault)
                    .is_some_and(|v| v.is_member(&s.id)))
            })
            .unwrap_or(false)
    }

    fn check(&mut self) -> Result<()> {
        let mut all = BTreeMap::new();
        for d in &self.devices {
            if d.open() {
                d.with(|s| {
                    for v in s.vaults.values() {
                        for (log, _) in v
                            .heads()
                            .iter()
                            .filter(|(log, _)| log.log == Log::Membership)
                        {
                            ensure!(
                                membership_writes(v, log.author) <= MAX_MEMBERSHIP_ENTRIES,
                                "membership author exceeded entry cap"
                            );
                        }
                        for e in v.entries() {
                            all.insert(e.hash(), e.clone());
                        }
                    }
                    Ok(())
                })?;
            }
        }
        for (target, removal) in &self.removals {
            let mut descendants = BTreeSet::from([*removal]);
            loop {
                let before = descendants.len();
                for (hash, e) in &all {
                    if e.deps().iter().any(|h| descendants.contains(h)) {
                        descendants.insert(*hash);
                    }
                }
                if before == descendants.len() {
                    break;
                }
            }
            let forbidden = self.forbidden.entry(*target).or_default();
            for hash in descendants {
                if hash != *removal
                    && let Some(entry) = all.get(&hash)
                    && !forbidden.iter().any(|e| e.hash() == hash)
                {
                    forbidden.push(entry.clone());
                }
            }
        }
        for (i, d) in self.devices.iter().enumerate() {
            if d.open() {
                d.with(|s| {
                    let accepted: BTreeSet<_> = s
                        .vaults
                        .values()
                        .flat_map(|v| v.entries().into_iter().map(Entry::hash))
                        .collect();
                    let persisted: Vec<_> = s
                        .store
                        .iter_all()?
                        .map(|row| Ok(Entry::decode(&row?)?.hash()))
                        .collect::<Result<Vec<_>>>()?;
                    let persisted_set: BTreeSet<_> = persisted.iter().copied().collect();
                    ensure!(
                        accepted == persisted_set && accepted.len() == persisted.len(),
                        "accepted/persisted mismatch on {i}"
                    );
                    for e in self.forbidden.get(&i).into_iter().flatten() {
                        ensure!(
                            !accepted.contains(&e.hash()),
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
            for file in std::fs::read_dir(d.dir.path())? {
                let file = file?;
                if !file.file_type()?.is_file() {
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
                    "plaintext on device {i} disk"
                );
                self.scanned.insert(file.path(), version);
            }
        }
        Ok(())
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

    fn converged(&self) -> Result<bool> {
        let members = self.devices[0]
            .with(|s| Ok(s.vault(&self.vault).members().collect::<BTreeSet<_>>()))?;
        let (heads, items, deleted, name) = self.devices[0].with(|s| {
            let vault = s.vault(&self.vault);
            Ok((
                vault.heads(),
                vault.items(),
                vault.deleted(),
                vault.name().to_owned(),
            ))
        })?;
        let histories = self.devices[0].with(|s| {
            Ok(items
                .iter()
                .chain(deleted.iter().map(|gone| &gone.item))
                .map(|item| (item.id, s.vault(&self.vault).history(&item.id)))
                .collect::<BTreeMap<_, _>>())
        })?;
        for d in &self.devices {
            if !members.contains(&DeviceId::from_bytes(d.id)) {
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
                Ok(vault.heads() == heads
                    && vault.members().collect::<BTreeSet<_>>() == members
                    && vault.name() == name
                    && vault.items() == items
                    && vault.deleted() == deleted
                    && histories
                        .iter()
                        .all(|(id, history)| vault.history(id) == *history))
            })?;
            if !same {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
