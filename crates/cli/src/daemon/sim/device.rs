//! Simulated device, sync handler, and pairing roles for the deterministic simulator.

pub(super) use super::super::session::Loaded;
use super::super::{pairing, session::Changes, sync};
use crate::disk::KdfParams;
use anyhow::Result;
use deadbolt_core::v2::{DeviceKeys, FrameId, NetPublic};
use deadbolt_core::{DeviceId, VaultId};
use deadbolt_net::{
    Blob, HandlerError, Inviter, Joiner, MembershipGate, PairingContext, PeerId, SyncHandler,
};
use std::{
    collections::{BTreeMap, BTreeSet},
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
    /// The device id (`D_sign`).
    pub(super) id: DeviceId,
    /// The transport key (`D_net`) connections name it by.
    pub(super) net: PeerId,
    pub(super) ready: Arc<AtomicBool>,
    pub(super) offer: Mutex<Option<pairing::Offer>>,
    /// Accepted sync batches whose changes went unreported to watchers.
    pub(super) unreported: Arc<Mutex<Vec<String>>>,
}

impl Device {
    pub(super) fn new(index: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = [index as u8 + 1; 32];
        let keys = DeviceKeys::from_seed(&key);
        let id = keys.device_id();
        let net = *keys.net_public().as_bytes();
        let store = crate::disk::init_with_params(
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
                .is_some_and(|s| s.admitted_nets().contains(&NetPublic::from_bytes(*peer)))
        }));
        Self {
            dir,
            state,
            gate,
            id,
            net,
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

/// Accepted frames per vault.
fn accepted(s: &Loaded) -> BTreeMap<VaultId, BTreeSet<FrameId>> {
    s.vaults
        .iter()
        .map(|(id, v)| (*id, v.frames().map(|f| f.id()).collect()))
        .collect()
}

/// What watchers must hear about a batch: every vault whose new frames
/// touch its items, name or devices, and nothing else.
fn report_problem(
    s: &Loaded,
    before: &BTreeMap<VaultId, BTreeSet<FrameId>>,
    reported: &Changes,
) -> Option<String> {
    for (id, vault) in &s.vaults {
        let old = before.get(id);
        let mut touch = deadbolt_core::Touch::default();
        for frame in vault
            .frames()
            .filter(|f| old.is_none_or(|o| !o.contains(&f.id())))
        {
            let t = vault.touched(frame);
            touch.items |= t.items;
            touch.name |= t.name;
            touch.devices |= t.devices;
        }
        let problem = if touch.items && !reported.items.contains(id) {
            "items grew unreported"
        } else if (touch.devices || touch.name) && !reported.vaults {
            "membership grew unreported"
        } else if !touch.items && reported.items.contains(id) {
            "unchanged items reported"
        } else if !touch.devices && reported.devices.contains(id) {
            "unchanged devices reported"
        } else {
            continue;
        };
        return Some(format!("{id}: {problem}"));
    }
    None
}
impl SyncHandler for Handler {
    type ReceiveState = deadbolt_net::application::ReceiveStream;

    async fn heads(&self, peer: PeerId) -> Result<Vec<u8>, HandlerError> {
        let guard = self.state.lock().unwrap();
        let s = guard.as_ref().ok_or("locked")?;
        let peer = s.device_of(&peer).map_err(|e| e.to_string())?;
        sync::hello(s, &peer, None).map_err(|e| e.to_string().into())
    }
    async fn missing_for(
        &self,
        peer: PeerId,
        heads: Vec<u8>,
    ) -> Result<deadbolt_net::Outgoing<'_>, HandlerError> {
        let mut guard = self.state.lock().unwrap();
        let s = guard.as_mut().ok_or("locked")?;
        let peer = s.device_of(&peer).map_err(|e| e.to_string())?;
        let history = sync::missing_for(s, &peer, &heads, self.ready.load(Ordering::SeqCst))
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
        stream: &mut Self::ReceiveState,
        _: bool,
    ) -> Result<(), HandlerError> {
        let mut guard = self.state.lock().unwrap();
        let s = guard.as_mut().ok_or("locked")?;
        let peer = s.device_of(&peer).map_err(|e| e.to_string())?;
        // Local writes and pairing record changes too; judge only this batch.
        s.changes = Changes::default();
        let before = accepted(s);
        let result = sync::receive(s, &peer, entries, self.ready.load(Ordering::SeqCst), stream);
        let reported = std::mem::take(&mut s.changes);
        if let Some(problem) = report_problem(s, &before, &reported) {
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
        self.device
            .with(|s| pairing::offer(s, self.vault, &ctx.remote, None))
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
                let device = deadbolt_net::application::join_device(&join, &ctx.remote)?;
                pairing::welcome(s, self.vault, device, &join, None).map(|(blobs, _)| blobs)
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
    async fn join(&self, _: &PairingContext, offer: Vec<u8>) -> Result<Vec<u8>, HandlerError> {
        let (offer, vault) =
            pairing::read_offer(&offer).map_err(|e| -> HandlerError { e.to_string().into() })?;
        let inviter = offer.inviter()?;
        let join = self
            .with(|s| {
                anyhow::ensure!(!s.vaults.contains_key(&vault), "already held");
                pairing::join_blob(&s.keys(), &s.meta.device_name, inviter, &vault, None)
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
            let welcomed = pairing::verify_welcome_from(&s.keys(), &ctx.remote, offer, welcome)?;
            pairing::adopt(s, welcomed).map(|_| ())
        })
        .map_err(|e| e.to_string().into())
    }
}
