//! Deterministic exploration through the production CLI handlers, core and redb.
mod network;

use super::{
    session::{Loaded, Meta},
    sync,
};
use anyhow::{Context, Result, ensure};
use deadbolt_core::{
    DataOp, DeviceId, DeviceSecret, Entry, Field, FieldType, Hash, MembershipOp, Payload,
    Signature, Vault, VaultId,
};
use deadbolt_net::{
    HandlerError, Inviter, Joiner, MembershipGate, PairingContext, PairingStream, PeerId,
    SyncHandler, run_sync_session,
};
use deadbolt_store::KdfParams;
use network::{Rng, drive, link};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::{Arc, Mutex},
};

const PASS: &[u8] = b"simulation-only";
const MAX: usize = 1 << 20;
const DEVICES: usize = 4;
const SECRET_MARKER: &str = "SIM-SECRET-";

struct Device {
    dir: tempfile::TempDir,
    state: Arc<Mutex<Option<Loaded>>>,
    gate: MembershipGate,
    id: PeerId,
    ready: bool,
}

impl Device {
    fn new(index: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = [index as u8 + 1; 32];
        let secret = DeviceSecret::from_bytes(&key);
        let id = *secret.device_id().as_bytes();
        let store = deadbolt_store::init_with_params(
            dir.path(),
            PASS,
            key,
            KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        let state = Arc::new(Mutex::new(Some(Loaded {
            store,
            secret,
            id: DeviceId::from_bytes(id),
            meta: Meta::default(),
            vaults: Default::default(),
        })));
        let member_state = state.clone();
        let gate = MembershipGate::new(Arc::new(move |peer: &PeerId| {
            member_state
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|s| s.peer_set().contains(peer))
        }));
        Self {
            dir,
            state,
            gate,
            id,
            ready: true,
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Loaded) -> Result<T>) -> Result<T> {
        let mut guard = self.state.lock().unwrap();
        f(guard.as_mut().ok_or_else(|| anyhow::anyhow!("locked"))?)
    }

    fn reopen(&mut self) -> Result<()> {
        self.state.lock().unwrap().take();
        *self.state.lock().unwrap() = Some(Loaded::open(self.dir.path(), PASS)?);
        self.ready = false;
        Ok(())
    }

    fn open(&self) -> bool {
        self.state.lock().unwrap().is_some()
    }

    fn handler(&self) -> Handler {
        Handler {
            state: self.state.clone(),
            ready: self.ready,
        }
    }
}

struct Handler {
    state: Arc<Mutex<Option<Loaded>>>,
    ready: bool,
}
impl SyncHandler for Handler {
    async fn heads(&self, peer: PeerId) -> Result<Vec<u8>, HandlerError> {
        let guard = self.state.lock().unwrap();
        sync::hello(
            guard.as_ref().ok_or("locked")?,
            &DeviceId::from_bytes(peer),
            None,
        )
        .map_err(|e| e.to_string().into())
    }
    async fn missing_for(
        &self,
        peer: PeerId,
        heads: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, HandlerError> {
        let mut guard = self.state.lock().unwrap();
        sync::missing_for(
            guard.as_mut().ok_or("locked")?,
            &DeviceId::from_bytes(peer),
            &heads,
            self.ready,
        )
        .map_err(|e| e.to_string().into())
    }
    async fn receive(&self, peer: PeerId, entries: Vec<Vec<u8>>) -> Result<(), HandlerError> {
        let mut guard = self.state.lock().unwrap();
        sync::receive(
            guard.as_mut().ok_or("locked")?,
            &DeviceId::from_bytes(peer),
            entries,
            self.ready,
        )
        .map(|_| ())
        .map_err(|e| e.to_string().into())
    }
}

struct Invitation<'a> {
    device: &'a Device,
    vault: VaultId,
}
impl Inviter for Invitation<'_> {
    async fn confirm(&self, _: &PairingContext) -> bool {
        true
    }
    async fn offer(&self, _: &PairingContext) -> Result<Vec<u8>, HandlerError> {
        Ok(self.vault.as_bytes().to_vec())
    }
    async fn welcome(
        &self,
        ctx: &PairingContext,
        join: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, HandlerError> {
        let consent = Signature::from_bytes(join.try_into().map_err(|_| "bad consent")?);
        self.device
            .with(|s| {
                s.update(self.vault, |v, key| {
                    Ok(v.add(key, DeviceId::from_bytes(ctx.remote), consent)?)
                })?;
                Ok(s.vault(&self.vault)
                    .entries()
                    .into_iter()
                    .map(Entry::encode)
                    .collect())
            })
            .map_err(|e| e.to_string().into())
    }
}
impl Joiner for Device {
    async fn confirm(&self, _: &PairingContext) -> bool {
        true
    }
    async fn join(&self, _: &PairingContext, offer: Vec<u8>) -> Result<Vec<u8>, HandlerError> {
        let id = VaultId::from_bytes(offer.try_into().map_err(|_| "bad offer")?);
        self.with(|s| Ok(s.secret.join_consent(&id).as_bytes().to_vec()))
            .map_err(|e| e.to_string().into())
    }
    async fn receive(&self, _: &PairingContext, welcome: Vec<Vec<u8>>) -> Result<(), HandlerError> {
        let entries = welcome
            .iter()
            .map(|e| Entry::decode(e))
            .collect::<Result<Vec<_>, _>>()?;
        self.with(|s| s.add_vault(Vault::load(entries.clone())?, &entries))
            .map_err(|e| e.to_string().into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Action {
    Add(usize, u64),
    Edit(usize, u64),
    Delete(usize),
    Pair(usize),
    Remove(usize),
    Sync(usize, usize, u64, Option<usize>),
    Partition(usize, usize),
    Heal,
    Lock(usize),
    Unlock(usize),
    Crash(usize),
    WriteFailure(usize),
    RevokeDuringSync(usize, u64, usize),
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
                &s.secret,
                id,
                0,
                [],
                Payload::Membership(MembershipOp::Create {
                    device: s.id,
                    nonce,
                    name: "sim".into(),
                }),
            );
            s.add_vault(Vault::from_genesis(genesis.clone())?, &[genesis])?;
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
        if to == 0
            || !self.devices[to].open()
            || !self.devices[0].open()
            || self.blocked.contains(&(0, to))
        {
            return Ok(());
        }
        if self.devices[to].with(|s| Ok(s.vaults.contains_key(&self.vault)))? {
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
        let dial = PairingStream::new(
            self.devices[0].id,
            self.devices[to].id,
            [7; 32],
            [9; 32],
            false,
        );
        let listen = PairingStream::new(
            self.devices[to].id,
            self.devices[0].id,
            [7; 32],
            [9; 32],
            true,
        );
        let join = async {
            listen
                .prove(&mut br)
                .await?
                .complete(&mut bt, &mut br, MAX, &self.devices[to])
                .await
        };
        let (result, _) = drive(
            dial.invite(&mut at, &mut ar, MAX, &invite),
            join,
            aw,
            bw,
            to as u64,
            None,
            |_| false,
        );
        let (a, b) = result.ok_or_else(|| anyhow::anyhow!("pair protocol stalled"))?;
        ensure!(a?.code == b?.code, "confirmation code mismatch");
        Ok(())
    }

    fn sync(
        &mut self,
        a: usize,
        b: usize,
        seed: u64,
        cut: Option<usize>,
        revoke_at: Option<usize>,
    ) -> Result<bool> {
        if a == b
            || self.blocked.contains(&(a.min(b), a.max(b)))
            || !self.devices[a].open()
            || !self.devices[b].open()
        {
            return Ok(false);
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
            return Ok(false);
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
                    match self.devices[a]
                        .with(|s| s.update(self.vault, |v, key| Ok(v.remove(key, target)?)))
                    {
                        Ok(entry) => {
                            removal = Some(entry.hash());
                            self.devices[a].gate.revoke(&self.devices[b].id);
                        }
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
        Ok(result.is_some_and(|(a, b)| a.is_ok() && b.is_ok()))
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
                self.devices[i].ready = false;
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
            Action::RevokeDuringSync(b, seed, tick) if b != 0 => {
                self.sync(0, b, seed, None, Some(tick))?;
            }
            Action::WriteFailure(i) if self.can_write(i) => {
                self.devices[i].with(|s| {
                    let key = &s.secret;
                    let result = super::session::update(
                        s.vaults.get_mut(&self.vault).unwrap(),
                        |_| anyhow::bail!("injected disk full"),
                        |v| Ok(v.rename(key, "failed-write")?),
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
                    s.update(self.vault, |v, key| {
                        if matches!(action, Action::Edit(..))
                            && let Some(item) = v.items().first()
                        {
                            v.write(
                                key,
                                vec![DataOp::set(
                                    item.id,
                                    "password",
                                    Field::new(FieldType::Secret, value),
                                )],
                            )?;
                        } else {
                            v.create_item(
                                key,
                                "login",
                                None,
                                [("password".into(), Field::new(FieldType::Secret, value))],
                            )?;
                        }
                        Ok(())
                    })
                })?;
            }
            Action::Delete(i) if self.can_write(i) => {
                self.devices[i].with(|s| {
                    s.update(self.vault, |v, key| {
                        if let Some(item) = v.items().first() {
                            v.write(key, vec![DataOp::delete(item.id)])?;
                        }
                        Ok(())
                    })
                })?;
            }
            _ => {}
        }
        self.check()
    }

    fn can_write(&self, i: usize) -> bool {
        self.devices[i].ready
            && self.devices[i]
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
                    let persisted = s
                        .store
                        .iter_all()?
                        .map(|row| row.map(|(hash, _)| Hash::from_bytes(hash)))
                        .collect::<Result<BTreeSet<_>, _>>()?;
                    ensure!(accepted == persisted, "accepted/persisted mismatch on {i}");
                    for e in self.forbidden.get(&i).into_iter().flatten() {
                        ensure!(
                            !accepted.contains(&e.hash()),
                            "removed device {i} accepted causal descendant"
                        );
                    }
                    Ok(())
                })?;
            }
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
                    memchr::memmem::find(&bytes, SECRET_MARKER.as_bytes()).is_none(),
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
            let mut succeeded = vec![HashSet::new(); DEVICES];
            for a in 0..DEVICES {
                for b in a + 1..DEVICES {
                    if self.sync(a, b, (round * DEVICES + b) as u64, None, None)? {
                        succeeded[a].insert(self.devices[b].id);
                        succeeded[b].insert(self.devices[a].id);
                    }
                }
            }
            for (a, succeeded) in succeeded.iter().enumerate() {
                let peers = self.devices[a].with(|s| Ok(s.peer_set()))?;
                if sync::barrier_complete(&peers, succeeded) {
                    self.devices[a].ready = true;
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
        let (heads, items) = self.devices[0]
            .with(|s| Ok((s.vault(&self.vault).heads(), s.vault(&self.vault).items())))?;
        for d in &self.devices {
            if !members.contains(&DeviceId::from_bytes(d.id)) {
                continue;
            }
            if !d.ready {
                return Ok(false);
            }
            let same = d.with(|s| {
                let vault = s
                    .vaults
                    .get(&self.vault)
                    .ok_or_else(|| anyhow::anyhow!("member missing vault"))?;
                Ok(vault.heads() == heads && vault.items() == items)
            })?;
            if !same {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn actions(seed: u64) -> Vec<Action> {
    let mut rng = Rng(seed);
    let mut actions = vec![Action::Pair(1), Action::Pair(2), Action::Pair(3)];
    for _ in 0..48 {
        let i = (rng.next() % DEVICES as u64) as usize;
        let j = (rng.next() % DEVICES as u64) as usize;
        let value = rng.next();
        actions.push(match rng.next() % 14 {
            0 => Action::Add(i, value),
            1 => Action::Edit(i, value),
            2 => Action::Delete(i),
            3 => Action::Pair(i),
            4 => Action::Remove(i),
            5 => Action::Lock(i),
            6 => Action::Unlock(i),
            7 => Action::Crash(i),
            8 => Action::Partition(i, j),
            9 => Action::Heal,
            10 => Action::Sync(i, j, value, Some((value % 500) as usize)),
            12 => Action::WriteFailure(i),
            13 => Action::RevokeDuringSync(i, value, (value % 400) as usize),
            _ => Action::Sync(i, j, value, None),
        });
    }
    actions
}

fn replay(actions: &[Action]) -> Result<String> {
    let timing = std::env::var_os("DEADBOLT_SIM_TIMING").is_some();
    let start = std::time::Instant::now();
    let mut world = World::new()?;
    if timing {
        eprintln!("init {:?}", start.elapsed());
    }
    for (i, action) in actions.iter().enumerate() {
        let start = std::time::Instant::now();
        world
            .step(action)
            .with_context(|| format!("step {i} {action:?}"))?;
        if timing {
            eprintln!("{action:?}: {:?}", start.elapsed());
        }
    }
    let start = std::time::Instant::now();
    world.converge()?;
    if timing {
        eprintln!("converge {:?}", start.elapsed());
    }
    Ok(world.digest.finalize().to_hex().to_string())
}

/// Delta debugging removes contiguous chunks, then individual actions. Every
/// candidate starts with fresh encrypted stores and the same deterministic keys.
fn shrink(mut actions: Vec<Action>, mut fails: impl FnMut(&[Action]) -> bool) -> Vec<Action> {
    let mut width = (actions.len() / 2).max(1);
    while width > 0 {
        let mut start = 0;
        while start + width <= actions.len() {
            let mut candidate = actions.clone();
            candidate.drain(start..start + width);
            if fails(&candidate) {
                actions = candidate;
                start = 0;
            } else {
                start += 1;
            }
        }
        width /= 2;
    }
    actions
}

#[test]
fn exploration() {
    let count = std::env::var("DEADBOLT_SIM_SEEDS")
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap_or(2);
    let first = std::env::var("DEADBOLT_SIM_SEED")
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap_or(0);
    if let Ok(trace) = std::env::var("DEADBOLT_SIM_TRACE") {
        replay(&serde_json::from_str::<Vec<Action>>(&trace).unwrap()).unwrap();
        return;
    }
    for seed in first..first + count {
        let actions = actions(seed);
        if let Err(error) = replay(&actions) {
            let failure = error.root_cause().to_string();
            let reduced = shrink(actions.clone(), |candidate| {
                replay(candidate).is_err_and(|e| e.root_cause().to_string() == failure)
            });
            panic!(
                "seed {seed}: {error:#}\nactions={}\nshrunk={}\nreplay with DEADBOLT_SIM_SEED={seed} DEADBOLT_SIM_SEEDS=1, or DEADBOLT_SIM_TRACE='<shrunk JSON>'",
                serde_json::to_string(&actions).unwrap(),
                serde_json::to_string(&reduced).unwrap()
            );
        }
    }
}

#[test]
fn replay_has_identical_wire_schedule() {
    let trace = vec![
        Action::Pair(1),
        Action::Add(0, 19),
        Action::Sync(0, 1, 47, Some(200)),
        Action::Crash(0),
        Action::Sync(1, 0, 63, None),
    ];
    assert_eq!(replay(&trace).unwrap(), replay(&trace).unwrap());
}

#[test]
fn removal_blocks_causal_data_via_a_stale_peer() {
    replay(&[
        Action::Pair(1),
        Action::Pair(2),
        Action::Add(0, 1),
        Action::Sync(0, 1, 10, None),
        Action::Partition(0, 1),
        Action::Remove(1),
        Action::Add(0, 2),
        Action::Sync(0, 2, 12, None),
        Action::Sync(2, 1, 13, None),
        Action::Heal,
        Action::Sync(0, 1, 14, None),
    ])
    .unwrap();
}

#[test]
fn shrinking_keeps_only_the_failure_dependencies() {
    let trace = vec![
        Action::Heal,
        Action::Pair(1),
        Action::Heal,
        Action::Remove(1),
        Action::Heal,
    ];
    let reduced = shrink(trace, |candidate| {
        candidate.iter().any(|a| matches!(a, Action::Pair(1)))
            && candidate.iter().any(|a| matches!(a, Action::Remove(1)))
    });
    assert!(matches!(
        reduced.as_slice(),
        [Action::Pair(1), Action::Remove(1)]
    ));
}
