//! Deterministic exploration through the production CLI handlers, core and redb.
mod network;

use super::{
    pairing,
    session::{Changes, Loaded, Meta},
    sync,
};
use anyhow::{Context, Result, ensure};
use deadbolt_core::{
    DeviceId, DeviceSecret, Entry, Hash, Log, LogId, MAX_MEMBERSHIP_ENTRIES, MembershipOp, Payload,
    Vault, VaultId,
};
use deadbolt_net::{
    Blob, HandlerError, Inviter, Joiner, MembershipGate, PairingCode, PairingContext,
    PairingStream, PeerId, SyncHandler, run_sync_session,
};
use deadbolt_store::KdfParams;
use network::{Rng, drive, link};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

const PASS: &[u8] = b"simulation-only";
const MAX: usize = 1 << 20;
const DEVICES: usize = 4;
const SECRET_MARKER: &str = "SIM-SECRET-";
/// A file's contents start with the marker, so its value (base64) starts
/// with this: the marker's first nine bytes, encoded.
const FILE_MARKER: &str = "U0lNLVNFQ1JF";

struct Device {
    dir: tempfile::TempDir,
    state: Arc<Mutex<Option<Loaded>>>,
    gate: MembershipGate,
    id: PeerId,
    ready: Arc<AtomicBool>,
    offer: Mutex<Option<pairing::Offer>>,
    /// Accepted sync batches whose changes went unreported to watchers.
    unreported: Arc<Mutex<Vec<String>>>,
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
        let health = super::health::State::new(&store);
        let state = Arc::new(Mutex::new(Some(Loaded {
            store,
            secret,
            id: DeviceId::from_bytes(id),
            meta: Meta::default(),
            vaults: Default::default(),
            unavailable: Default::default(),
            changes: Default::default(),
            health,
            append_uncertain: false,
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
            ready: Arc::new(AtomicBool::new(true)),
            offer: Mutex::default(),
            unreported: Arc::default(),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Loaded) -> Result<T>) -> Result<T> {
        let mut guard = self.state.lock().unwrap();
        f(guard.as_mut().ok_or_else(|| anyhow::anyhow!("locked"))?)
    }

    fn reopen(&mut self) -> Result<()> {
        self.state.lock().unwrap().take();
        *self.state.lock().unwrap() = Some(Loaded::open(self.dir.path(), PASS)?);
        self.ready.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn open(&self) -> bool {
        self.state.lock().unwrap().is_some()
    }

    fn handler(&self) -> Handler {
        Handler {
            state: self.state.clone(),
            ready: self.ready.clone(),
            unreported: self.unreported.clone(),
        }
    }
}

struct Handler {
    state: Arc<Mutex<Option<Loaded>>>,
    ready: Arc<AtomicBool>,
    unreported: Arc<Mutex<Vec<String>>>,
}

fn membership_writes(vault: &Vault, author: DeviceId) -> u64 {
    vault.entries().into_iter().filter(|entry| entry.author() == author
        && matches!(entry.payload(), Payload::Membership(op) if !matches!(op, MembershipOp::Remove { .. })))
        .count() as u64
}

/// Accepted (data, membership) entries per vault.
fn accepted(s: &Loaded) -> BTreeMap<VaultId, (usize, usize)> {
    s.vaults
        .iter()
        .map(|(id, v)| {
            let entries = v.entries();
            let data = entries.iter().filter(|e| e.log() == Log::Data).count();
            (*id, (data, entries.len() - data))
        })
        .collect()
}

/// What watchers must hear about a batch: every vault whose items or
/// membership grew, and nothing else.
fn report_problem(
    before: &BTreeMap<VaultId, (usize, usize)>,
    after: &BTreeMap<VaultId, (usize, usize)>,
    reported: &Changes,
) -> Option<String> {
    for (id, (data, membership)) in after {
        let (data_before, membership_before) = before.get(id).copied().unwrap_or_default();
        let items = *data > data_before;
        let members = *membership > membership_before;
        let problem = if items && !reported.items.contains(id) {
            "items grew unreported"
        } else if members && !reported.vaults {
            "membership grew unreported"
        } else if !items && !members && reported.items.contains(id) {
            "unchanged items reported"
        } else if !members && reported.devices.contains(id) {
            "unchanged devices reported"
        } else {
            continue;
        };
        return Some(format!("{id}: {problem}"));
    }
    None
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
    async fn missing_for(&self, peer: PeerId, heads: Vec<u8>) -> Result<Vec<Blob>, HandlerError> {
        let mut guard = self.state.lock().unwrap();
        sync::missing_for(
            guard.as_mut().ok_or("locked")?,
            &DeviceId::from_bytes(peer),
            &heads,
            self.ready.load(Ordering::SeqCst),
        )
        .map_err(|e| e.to_string().into())
    }
    async fn receive(&self, peer: PeerId, entries: Vec<Blob>) -> Result<(), HandlerError> {
        let mut guard = self.state.lock().unwrap();
        let s = guard.as_mut().ok_or("locked")?;
        // Local writes and pairing record changes too; judge only this batch.
        s.changes = Changes::default();
        let before = accepted(s);
        let result = sync::receive(
            s,
            &DeviceId::from_bytes(peer),
            entries,
            self.ready.load(Ordering::SeqCst),
        );
        let reported = std::mem::take(&mut s.changes);
        if let Some(problem) = report_problem(&before, &accepted(s), &reported) {
            self.unreported.lock().unwrap().push(problem);
        }
        result.map(|_| ()).map_err(|e| e.to_string().into())
    }
}

struct Invitation<'a> {
    device: &'a Device,
    vault: VaultId,
}
impl Inviter for Invitation<'_> {
    async fn offer(&self, ctx: &PairingContext) -> Result<Vec<u8>, HandlerError> {
        let device = DeviceId::from_bytes(ctx.remote);
        self.device
            .with(|s| pairing::offer(s, self.vault, &device, None))
            .map_err(|e| e.to_string().into())
    }
    async fn welcome(
        &self,
        ctx: &PairingContext,
        join: Vec<u8>,
    ) -> Result<Vec<Blob>, HandlerError> {
        self.device
            .with(|s| {
                pairing::welcome(s, self.vault, DeviceId::from_bytes(ctx.remote), &join, None)
                    .map(|(blobs, _)| blobs)
            })
            .map_err(|e| e.to_string().into())
    }
}
impl Joiner for Device {
    async fn join(&self, ctx: &PairingContext, offer: Vec<u8>) -> Result<Vec<u8>, HandlerError> {
        let inviter = DeviceId::from_bytes(ctx.remote);
        let (offer, vault) =
            pairing::read_offer(&offer).map_err(|e| -> HandlerError { e.to_string().into() })?;
        let join = self
            .with(|s| {
                anyhow::ensure!(!s.vaults.contains_key(&vault), "already held");
                pairing::join_blob(&s.secret, &s.meta.device_name, inviter, &vault, None)
            })
            .map_err(|e| -> HandlerError { e.to_string().into() })?;
        *self.offer.lock().unwrap() = Some(offer);
        Ok(join)
    }
    async fn receive(&self, ctx: &PairingContext, welcome: Vec<Blob>) -> Result<(), HandlerError> {
        let offer = self.offer.lock().unwrap().take().ok_or("no offer")?;
        self.with(|s| {
            pairing::apply_welcome(s, DeviceId::from_bytes(ctx.remote), offer, welcome).map(|_| ())
        })
        .map_err(|e| e.to_string().into())
    }
}

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
                s.secret.join_consent(&self.vault, &author_id),
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
                    &s.secret,
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
                let added = sync::receive(s, &author_id, blobs.clone(), true)?;
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
                    let key = &s.secret;
                    let result = super::session::update(
                        s.vaults.get_mut(&self.vault).unwrap(),
                        |_| anyhow::bail!("injected disk full"),
                        |v| Ok(v.write(key, vec![])?),
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
        let (heads, items, deleted) = self.devices[0].with(|s| {
            let vault = s.vault(&self.vault);
            Ok((vault.heads(), vault.items(), vault.deleted()))
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
                Ok(vault.heads() == heads && vault.items() == items && vault.deleted() == deleted)
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
        if rng.next().is_multiple_of(64) {
            actions.push(Action::MembershipFlood(i, j));
            continue;
        }
        actions.push(match rng.next() % 19 {
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
            11 => Action::Attach(i, value),
            12 => Action::WriteFailure(i),
            13 => Action::RevokeDuringSync(i, value, (value % 400) as usize),
            14 => Action::Startup(i),
            15 => Action::Restore(i),
            16 => Action::Favorite(i, value & 1 == 0),
            17 => Action::Tag(i, value),
            18 => Action::Untag(i),
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
fn membership_flood_is_bounded_durable_and_replayable() {
    for (author, receiver) in [(0, 1), (1, 0)] {
        let actions = [
            Action::Pair(1),
            Action::MembershipFlood(author, receiver),
            Action::Crash(receiver),
            Action::MembershipFlood(author, receiver),
            Action::Startup(receiver),
            Action::Add(receiver, 42),
            Action::Remove(1),
            Action::Add(0, 43),
        ];
        assert_eq!(replay(&actions).unwrap(), replay(&actions).unwrap());
    }
}

#[test]
fn exploration() {
    let count = crate::config::env("DEADBOLT_SIM_SEEDS")
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap_or(2);
    let first = crate::config::env("DEADBOLT_SIM_SEED")
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap_or(0);
    if let Ok(trace) = crate::config::env("DEADBOLT_SIM_TRACE") {
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

#[tokio::test]
async fn pairing_offer_rejects_a_removed_inviter() {
    let mut world = World::new().unwrap();
    world.pair(1).unwrap();
    let peer = DeviceId::from_bytes(world.devices[1].id);
    let removal = world.devices[0]
        .with(|s| s.update(world.vault, |v, key| Ok(v.remove(key, peer)?)))
        .unwrap();
    world.devices[1]
        .with(|s| s.update(world.vault, |v, _| Ok(v.apply(removal)?)))
        .unwrap();
    let invite = Invitation {
        device: &world.devices[1],
        vault: world.vault,
    };
    let ctx = PairingContext {
        local: world.devices[1].id,
        remote: world.devices[2].id,
    };
    let error = invite.offer(&ctx).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "this device is no longer a member of sim"
    );
    world.check().unwrap();
}

#[tokio::test]
async fn pairing_offer_rejects_a_removed_joiner() {
    let mut world = World::new().unwrap();
    world.pair(1).unwrap();
    world.step(&Action::Remove(1)).unwrap();
    let invite = Invitation {
        device: &world.devices[0],
        vault: world.vault,
    };
    let ctx = PairingContext {
        local: world.devices[0].id,
        remote: world.devices[1].id,
    };
    // Exercise the offer adapter directly: World::pair skips removed peers.
    let error = invite.offer(&ctx).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "that device was removed from sim and can't rejoin it"
    );
    let fresh = PairingContext {
        remote: world.devices[2].id,
        ..ctx
    };
    invite.offer(&fresh).await.unwrap();
    world.check().unwrap();
}

#[test]
fn pairing_cuts_preserve_committed_state() {
    for cut in [1, 20, 60, 120, 240] {
        let mut world = World::new().unwrap();
        world.pair_with_cut(1, Some(cut)).unwrap();
        world.check().unwrap();
        world.step(&Action::Crash(0)).unwrap();
        world.step(&Action::Crash(1)).unwrap();
    }
}

/// A cut after the inviter committed the `Add` leaves a member that never got
/// its welcome. Pairing it again completes without a second `Add`, and the
/// devices converge.
#[test]
fn pairing_again_after_a_cut_finishes_the_join() {
    for cut in [1, 20, 60, 120, 240] {
        let mut world = World::new().unwrap();
        world.pair_with_cut(1, Some(cut)).unwrap();
        world.step(&Action::Startup(0)).unwrap();
        world.step(&Action::Pair(1)).unwrap();
        assert!(
            world.devices[1]
                .with(|s| Ok(s.vaults.contains_key(&world.vault)))
                .unwrap()
        );
        let adds = world.devices[0]
            .with(|s| {
                Ok(s.vault(&world.vault)
                    .entries()
                    .into_iter()
                    .filter(|e| {
                        matches!(e.payload(), Payload::Membership(MembershipOp::Add { .. }))
                    })
                    .count())
            })
            .unwrap();
        assert_eq!(adds, 1, "cut {cut}");
        world.step(&Action::Add(1, 7)).unwrap();
        world.converge().unwrap();
    }
}

#[test]
fn startup_reopens_pairing_and_existing_handlers_observe_readiness() {
    let mut world = World::new().unwrap();
    world.step(&Action::Pair(1)).unwrap();
    world.step(&Action::Crash(0)).unwrap();
    let handler = world.devices[0].handler();
    assert!(!handler.ready.load(Ordering::SeqCst));
    world.step(&Action::Pair(2)).unwrap();
    assert!(!world.can_write(2));
    world.step(&Action::Startup(0)).unwrap();
    assert!(handler.ready.load(Ordering::SeqCst));
    world.step(&Action::Pair(2)).unwrap();
    assert!(world.can_write(2));
    world.step(&Action::Add(2, 42)).unwrap();
    world.converge().unwrap();
}

/// Two devices that can't see each other both delete an item, and one
/// restores it: the restore never saw the other delete, so once healed
/// every device has the item back.
#[test]
fn restore_beats_a_delete_it_never_saw() {
    let mut world = World::new().unwrap();
    for action in [
        Action::Pair(1),
        Action::Add(0, 1),
        Action::Sync(0, 1, 10, None),
        Action::Partition(0, 1),
        Action::Delete(0),
        Action::Delete(1),
        Action::Restore(0),
    ] {
        world.step(&action).unwrap();
    }
    let deleted = |world: &World, i: usize| {
        world.devices[i]
            .with(|s| Ok(s.vault(&world.vault).deleted().len()))
            .unwrap()
    };
    assert_eq!((deleted(&world, 0), deleted(&world, 1)), (0, 1));
    world.converge().unwrap();
    for i in 0..2 {
        assert_eq!(deleted(&world, i), 0);
        let items = world.devices[i]
            .with(|s| Ok(s.vault(&world.vault).items().len()))
            .unwrap();
        assert_eq!(items, 1);
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

#[test]
fn offline_unlock_keeps_local_items_available_and_failed_dials_finish_startup() {
    let mut world = World::new().unwrap();
    world.step(&Action::Pair(1)).unwrap();
    world.step(&Action::Add(0, 10)).unwrap();
    world.step(&Action::Lock(1)).unwrap();
    world.step(&Action::Crash(0)).unwrap();
    assert!(!world.devices[0].ready.load(Ordering::SeqCst));
    assert!(world.can_write(0));
    world.step(&Action::Add(0, 11)).unwrap();
    world.devices[0]
        .with(|s| {
            assert_eq!(s.vault(&world.vault).items().len(), 2);
            Ok(())
        })
        .unwrap();
    let result = world.sync(0, 1, 10, None, None).unwrap();
    assert_eq!(result, sync::Attempt::Unreachable);
    world.step(&Action::Startup(0)).unwrap();
    assert!(world.devices[0].ready.load(Ordering::SeqCst));
    world.converge().unwrap();
}

#[test]
fn startup_retries_an_interrupted_exchange() {
    let mut world = World::new().unwrap();
    world.step(&Action::Pair(1)).unwrap();
    world.step(&Action::Crash(0)).unwrap();
    let peers = world.devices[0].with(|s| Ok(s.peer_set())).unwrap();
    let failed = world.sync(0, 1, 31, Some(40), None).unwrap();
    assert_eq!(failed, sync::Attempt::Interrupted);
    assert!(!sync::barrier_complete(
        &peers,
        &BTreeMap::from([(world.devices[1].id, failed)])
    ));
    let retried = world.sync(0, 1, 32, None, None).unwrap();
    assert_eq!(retried, sync::Attempt::Complete);
    assert!(sync::barrier_complete(
        &peers,
        &BTreeMap::from([(world.devices[1].id, retried)])
    ));
    world.converge().unwrap();
}

#[test]
fn startup_learns_removal_before_sending_locally_written_data() {
    let mut world = World::new().unwrap();
    world.step(&Action::Pair(1)).unwrap();
    world.step(&Action::Pair(2)).unwrap();
    world.sync(0, 1, 10, None, None).unwrap();
    world.step(&Action::Crash(1)).unwrap();
    world.step(&Action::Remove(2)).unwrap();
    world.step(&Action::Add(1, 99)).unwrap();
    assert!(!world.devices[1].ready.load(Ordering::SeqCst));
    // The removed peer answers before the honest peer carrying its removal.
    let fast = world.sync(1, 2, 11, None, None).unwrap();
    assert_eq!(fast, sync::Attempt::Complete);
    world.devices[2]
        .with(|s| {
            assert!(s.vault(&world.vault).items().is_empty());
            Ok(())
        })
        .unwrap();
    let honest = world.sync(1, 0, 12, None, None).unwrap();
    let peers = world.devices[1].with(|s| Ok(s.peer_set())).unwrap();
    assert!(!peers.contains(&world.devices[2].id));
    world.devices[1].ready.store(
        sync::barrier_complete(
            &peers,
            &BTreeMap::from([(world.devices[0].id, honest), (world.devices[2].id, fast)]),
        ),
        Ordering::SeqCst,
    );
    assert!(world.devices[1].ready.load(Ordering::SeqCst));
    assert_eq!(
        world.sync(1, 2, 13, None, None).unwrap(),
        sync::Attempt::Unreachable
    );
    world.devices[2]
        .with(|s| {
            assert!(s.vault(&world.vault).items().is_empty());
            Ok(())
        })
        .unwrap();
    world.converge().unwrap();
}

/// A file's name and contents carry the marker, and neither reaches the
/// disk in the clear: the scan looks for the marker and its base64.
#[test]
fn files_never_reach_the_disk_in_the_clear() {
    assert_eq!(
        data_encoding::BASE64.encode(&SECRET_MARKER.as_bytes()[..9]),
        FILE_MARKER
    );
    let mut world = World::new().unwrap();
    world.step(&Action::Pair(1)).unwrap();
    world.step(&Action::Attach(0, 3)).unwrap();
    world.step(&Action::Attach(0, 4)).unwrap();
    world.converge().unwrap();
    let file = world.devices[1]
        .with(|s| {
            let item = s.vault(&world.vault).items()[0].clone();
            Ok(item.fields["receipt"].value.clone())
        })
        .unwrap();
    let (name, contents) = deadbolt_core::item::file_parts(&file);
    assert!(name.starts_with(SECRET_MARKER), "{name}");
    assert!(contents.unwrap().starts_with(FILE_MARKER));
}
