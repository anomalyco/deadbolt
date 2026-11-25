//! Simulated device, sync handler, and pairing roles for the deterministic simulator.

use super::super::{
    pairing,
    session::{Changes, Loaded},
    sync,
};
use anyhow::Result;
use deadbolt_core::{DeviceId, DeviceSecret, Log, MembershipOp, Payload, Vault, VaultId};
use deadbolt_net::{
    Blob, HandlerError, Inviter, Joiner, MembershipGate, PairingContext, PeerId, SyncHandler,
};
use deadbolt_store::KdfParams;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

pub(super) const PASS: &[u8] = b"simulation-only";
pub(super) const MAX: usize = 1 << 20;

pub(super) struct Device {
    pub(super) dir: tempfile::TempDir,
    pub(super) state: Arc<Mutex<Option<Loaded>>>,
    pub(super) gate: MembershipGate,
    pub(super) id: PeerId,
    pub(super) ready: Arc<AtomicBool>,
    pub(super) offer: Mutex<Option<pairing::Offer>>,
    /// Accepted sync batches whose changes went unreported to watchers.
    pub(super) unreported: Arc<Mutex<Vec<String>>>,
}

impl Device {
    pub(super) fn new(index: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = [index as u8 + 1; 32];
        let secret = DeviceSecret::from_bytes(&key);
        let id = *secret.device_id().as_bytes();
        let store = deadbolt_store::init_with_params(
            dir.path(),
            PASS,
            &key,
            KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        let state = Arc::new(Mutex::new(Some(Loaded::from_unlocked(store).unwrap())));
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

    pub(super) fn with<T>(&self, f: impl FnOnce(&mut Loaded) -> Result<T>) -> Result<T> {
        let mut guard = self.state.lock().unwrap();
        f(guard.as_mut().ok_or_else(|| anyhow::anyhow!("locked"))?)
    }

    pub(super) fn reopen(&mut self) -> Result<()> {
        self.state.lock().unwrap().take();
        *self.state.lock().unwrap() = Some(Loaded::open(self.dir.path(), PASS)?);
        self.ready.store(false, Ordering::SeqCst);
        Ok(())
    }

    pub(super) fn open(&self) -> bool {
        self.state.lock().unwrap().is_some()
    }

    pub(super) fn handler(&self) -> Handler {
        Handler {
            state: self.state.clone(),
            ready: self.ready.clone(),
            unreported: self.unreported.clone(),
        }
    }
}

pub(super) struct Handler {
    pub(super) state: Arc<Mutex<Option<Loaded>>>,
    pub(super) ready: Arc<AtomicBool>,
    pub(super) unreported: Arc<Mutex<Vec<String>>>,
}

pub(super) fn membership_writes(vault: &Vault, author: DeviceId) -> u64 {
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
    type ReceiveState = ();

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
    ) -> Result<deadbolt_net::Outgoing<'_>, HandlerError> {
        let mut guard = self.state.lock().unwrap();
        let history = sync::missing_for(
            guard.as_mut().ok_or("locked")?,
            &DeviceId::from_bytes(peer),
            &heads,
            self.ready.load(Ordering::SeqCst),
        )
        .map_err(|e| -> HandlerError { e.to_string().into() })?;
        Ok(history.outgoing(|h| {
            let g = self.state.lock().unwrap();
            Ok(h.next(
                g.as_ref().ok_or("locked")?,
                self.ready.load(Ordering::SeqCst),
            )?)
        }))
    }
    async fn receive(
        &self,
        peer: PeerId,
        entries: Vec<Blob>,
        _: &mut (),
        _: bool,
    ) -> Result<(), HandlerError> {
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

pub(super) struct Invitation<'a> {
    pub(super) device: &'a Device,
    pub(super) vault: VaultId,
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
    ) -> Result<deadbolt_net::Outgoing<'_>, HandlerError> {
        let history = self
            .device
            .with(|s| {
                pairing::welcome(s, self.vault, DeviceId::from_bytes(ctx.remote), &join, None)
                    .map(|(blobs, _)| blobs)
            })
            .map_err(|e| -> HandlerError { e.to_string().into() })?;
        Ok(history.outgoing(|h| {
            self.device
                .with(|s| Ok(h.next(s, self.device.ready.load(Ordering::SeqCst))?))
                .map_err(|e| e.to_string().into())
        }))
    }
}
impl Joiner for Device {
    type Welcome = deadbolt_net::application::WelcomeReplay;
    async fn join(&self, ctx: &PairingContext, offer: Vec<u8>) -> Result<Vec<u8>, HandlerError> {
        let inviter = DeviceId::from_bytes(ctx.remote);
        let (offer, vault) =
            pairing::read_offer(&offer).map_err(|e| -> HandlerError { e.to_string().into() })?;
        let join = self
            .with(|s| {
                anyhow::ensure!(!s.vaults.contains_key(&vault), "already held");
                pairing::join_blob(&s.secret(), &s.meta.device_name, inviter, &vault, None)
            })
            .map_err(|e| -> HandlerError { e.to_string().into() })?;
        *self.offer.lock().unwrap() = Some(offer);
        Ok(join)
    }
    async fn receive(
        &self,
        ctx: &PairingContext,
        welcome: Self::Welcome,
    ) -> Result<(), HandlerError> {
        let offer = self.offer.lock().unwrap().take().ok_or("no offer")?;
        self.with(|s| {
            pairing::apply_welcome(s, DeviceId::from_bytes(ctx.remote), offer, welcome).map(|_| ())
        })
        .map_err(|e| e.to_string().into())
    }
}
