//! Browser adapters for the shared vault pairing and sync application rules.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use deadbolt_core::{DeviceId, DeviceSecret, Vault, VaultId, VaultWrite};
pub(crate) use deadbolt_net::application::Addr;
use deadbolt_net::application::{self, Hint, State, clean_name};
use deadbolt_net::{Blob, HandlerError, Inviter, PairingContext, PeerId, SyncHandler};

use super::{Error, Loaded, Result, enforce_membership, unhex};

impl State for Loaded {
    type Error = Error;

    fn device_id(&self) -> DeviceId {
        self.secret.device_id()
    }
    fn device_name(&self) -> &str {
        &self.name
    }
    fn vaults(&self) -> impl Iterator<Item = &Vault> {
        std::iter::once(&self.vault)
    }

    fn hints_for(&self, peer: &DeviceId) -> BTreeMap<String, Hint> {
        if !self.vault.is_member(peer) {
            return BTreeMap::new();
        }
        self.vault
            .members()
            .filter(|id| id != peer && *id != self.device_id())
            .map(|id| {
                let id = id.to_string();
                let hint = Hint {
                    name: self.peer_names.get(&id).cloned(),
                    addr: self.peers.get(&id).cloned(),
                    addr_seen: 0,
                };
                (id, hint)
            })
            .collect()
    }

    fn update<T>(
        &mut self,
        id: VaultId,
        change: impl FnOnce(
            &mut VaultWrite<'_>,
            &DeviceSecret,
        ) -> std::result::Result<T, application::Error>,
    ) -> Result<T> {
        if id != self.vault.id() {
            return Err(application::Error::VaultNotHeld.into());
        }
        self.mutate(|v, key| Ok(change(v, key)?))
    }

    fn learn(
        &mut self,
        peer: &DeviceId,
        name: &str,
        addr: Option<Addr>,
        hints: BTreeMap<String, Hint>,
    ) -> Result<()> {
        let old_peers = self.peers.clone();
        let old_names = self.peer_names.clone();
        let from = peer.to_string();
        let name = clean_name(name);
        if !name.is_empty() {
            self.peer_names.insert(from.clone(), name);
        }
        if let Some(addr) = addr {
            self.peers.insert(from.clone(), addr);
        }
        // Direct peer metadata wins. Gossip only fills gaps for known members;
        // neither names nor addresses ever grant membership.
        for (id, hint) in hints.into_iter().take(256) {
            let Ok(bytes) = unhex::<32>(&id) else {
                continue;
            };
            let device = DeviceId::from_bytes(bytes);
            if device == self.device_id() || id == from || !self.vault.is_member(&device) {
                continue;
            }
            if let Some(name) = hint
                .name
                .map(|name| clean_name(&name))
                .filter(|name| !name.is_empty())
            {
                self.peer_names.entry(id.clone()).or_insert(name);
            }
            if let Some(addr) = hint.addr {
                self.peers.entry(id).or_insert(addr);
            }
        }
        if self.peers != old_peers {
            self.store
                .meta_set("extension/peers", &serde_json::to_vec(&self.peers)?)?;
        }
        if self.peer_names != old_names {
            self.store.meta_set(
                "extension/peer-names",
                &serde_json::to_vec(&self.peer_names)?,
            )?;
        }
        Ok(())
    }

    fn received(&mut self, peer: &DeviceId) -> Result<()> {
        self.saw(peer)
    }
}

#[derive(Clone)]
pub(crate) struct Handler(pub Arc<Mutex<Option<Loaded>>>);

impl Handler {
    fn stream(&self, history: application::OutgoingHistory) -> deadbolt_net::Outgoing<'_> {
        history.outgoing(|h| self.with(|s| Ok(h.next(s, s.ready)?)).map_err(failure))
    }

    pub(crate) fn with<T>(&self, f: impl FnOnce(&mut Loaded) -> Result<T>) -> Result<T> {
        let mut state = self.0.lock().map_err(|_| Error::State)?;
        let result = f(state.as_mut().ok_or(Error::Locked)?);
        if let Err(error @ Error::UnconfirmedWrite(_)) = &result {
            // The final OPFS flush can fail after redb has switched roots.
            // Neither the old nor the staged heads can authorize another request.
            *state = None;
            drop(state); // The connection gate checks this same state.
            enforce_membership();
            super::stop_worker(&error.to_string());
        }
        result
    }
}

fn failure(error: Error) -> HandlerError {
    error.to_string().into()
}

impl application::RoundState for Handler {
    type Error = Error;

    fn ready(&self) -> Result<bool> {
        self.with(|s| Ok(s.ready))
    }

    fn targets(&self) -> Result<Vec<deadbolt_net::PeerAddr>> {
        self.with(|s| Ok(s.targets()))
    }

    fn saw(&self, peer: PeerId) -> Result<()> {
        self.with(|s| s.saw(&DeviceId::from_bytes(peer)))
    }

    fn publish_ready(&self, addr: Addr) -> Result<()> {
        self.with(|s| {
            s.ready = true;
            s.addr = Some(addr);
            Ok(())
        })
    }
}

impl SyncHandler for Handler {
    async fn heads(&self, peer: PeerId) -> std::result::Result<Vec<u8>, HandlerError> {
        self.with(|s| {
            Ok(application::hello(
                s,
                &DeviceId::from_bytes(peer),
                s.addr.clone(),
            )?)
        })
        .map_err(failure)
    }

    async fn missing_for(
        &self,
        peer: PeerId,
        bytes: Vec<u8>,
    ) -> std::result::Result<deadbolt_net::Outgoing<'_>, HandlerError> {
        let history = self
            .with(|s| {
                let ready = s.ready;
                application::missing_for(s, &DeviceId::from_bytes(peer), &bytes, ready)
            })
            .map_err(failure)?;
        Ok(self.stream(history))
    }

    async fn receive(
        &self,
        peer: PeerId,
        entries: Vec<Blob>,
    ) -> std::result::Result<(), HandlerError> {
        let result = self.with(|s| {
            let ready = s.ready;
            application::receive(s, &DeviceId::from_bytes(peer), entries, ready).map(drop)
        });
        enforce_membership();
        result.map_err(failure)
    }
}

impl Inviter for Handler {
    async fn offer(&self, ctx: &PairingContext) -> std::result::Result<Vec<u8>, HandlerError> {
        self.with(|s| {
            s.require_ready()?;
            Ok(application::offer(
                s,
                s.vault.id(),
                &DeviceId::from_bytes(ctx.remote),
                s.addr.clone(),
            )?)
        })
        .map_err(failure)
    }

    async fn welcome(
        &self,
        ctx: &PairingContext,
        bytes: Vec<u8>,
    ) -> std::result::Result<deadbolt_net::Outgoing<'_>, HandlerError> {
        let result = self.with(|s| {
            s.require_ready()?;
            let vault = s.vault.id();
            application::welcome(s, vault, DeviceId::from_bytes(ctx.remote), &bytes, None)
        });
        enforce_membership();
        Ok(self.stream(result.map_err(failure)?))
    }
}
