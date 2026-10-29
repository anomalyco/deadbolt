//! CLI-compatible application envelopes over deadbolt-net's authenticated
//! pairing and sync. The entries themselves are always decoded by core.
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use deadbolt_core::{DeviceId, Entry, Heads, Log, Signature};
use deadbolt_net::{Blob, HandlerError, Inviter, PairingContext, PeerAddr, PeerId, SyncHandler};
use serde::{Deserialize, Serialize};

use crate::{Error, Loaded, Result, enforce_membership, unhex};

#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct Addr {
    #[serde(default)]
    relay: Option<String>,
    #[serde(default)]
    direct: Vec<SocketAddr>,
}

impl Addr {
    pub(crate) fn from_peer(peer: PeerAddr) -> Self {
        Self {
            relay: peer.relay_url,
            direct: peer.direct_addrs,
        }
    }

    pub(crate) fn peer(&self, id: PeerId) -> PeerAddr {
        PeerAddr {
            id,
            relay_url: self.relay.clone(),
            direct_addrs: self.direct.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Hello {
    v: u32,
    name: String,
    addr: Option<Addr>,
    #[serde(default)]
    peers: BTreeMap<String, serde_json::Value>,
    vaults: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Join {
    v: u32,
    consent: String,
    name: String,
    addr: Option<Addr>,
}

#[derive(Clone)]
pub(crate) struct Handler(pub Arc<Mutex<Option<Loaded>>>);

impl Handler {
    pub(crate) fn with<T>(&self, f: impl FnOnce(&mut Loaded) -> Result<T>) -> Result<T> {
        let mut state = self.0.lock().map_err(|_| Error::State)?;
        f(state.as_mut().ok_or(Error::Locked)?)
    }

    fn learn(s: &mut Loaded, peer: PeerId, addr: Option<Addr>) -> Result<()> {
        if let Some(addr) = addr {
            s.peers.insert(data_encoding::HEXLOWER.encode(&peer), addr);
            s.store
                .meta_set("extension/peers", &serde_json::to_vec(&s.peers)?)?;
        }
        Ok(())
    }
}

fn failure(error: Error) -> HandlerError {
    error.to_string().into()
}

impl SyncHandler for Handler {
    async fn heads(&self, peer: PeerId) -> std::result::Result<Vec<u8>, HandlerError> {
        self.with(|s| {
            let vaults = if s.vault.is_member(&DeviceId::from_bytes(peer)) {
                BTreeMap::from([(
                    s.vault.id().to_string(),
                    data_encoding::HEXLOWER.encode(&s.vault.heads().encode()),
                )])
            } else {
                BTreeMap::new()
            };
            Ok(serde_json::to_vec(&Hello {
                v: 1,
                name: "Chromium".into(),
                addr: s.addr.clone(),
                peers: BTreeMap::new(),
                vaults,
            })?)
        })
        .map_err(failure)
    }

    async fn missing_for(
        &self,
        peer: PeerId,
        bytes: Vec<u8>,
    ) -> std::result::Result<Vec<Blob>, HandlerError> {
        self.with(|s| {
            let hello: Hello = serde_json::from_slice(&bytes)?;
            if hello.v != 1 {
                return Err(Error::Protocol("unsupported sync envelope"));
            }
            Self::learn(s, peer, hello.addr)?;
            let mut membership = Vec::new();
            let mut data = Vec::new();
            if s.vault.is_member(&DeviceId::from_bytes(peer))
                && let Some(heads) = hello.vaults.get(&s.vault.id().to_string())
            {
                let bytes = data_encoding::HEXLOWER
                    .decode(heads.as_bytes())
                    .map_err(|_| Error::Protocol("invalid heads"))?;
                let heads = Heads::decode(&bytes)?;
                for entry in s.vault.missing_for(&heads) {
                    match entry.log() {
                        Log::Membership => membership.push(entry.encode()),
                        Log::Data if s.ready => data.push(entry.encode()),
                        Log::Data => {}
                    }
                }
            }
            membership.append(&mut data);
            Ok(membership)
        })
        .map_err(failure)
    }

    async fn receive(
        &self,
        peer: PeerId,
        entries: Vec<Blob>,
    ) -> std::result::Result<(), HandlerError> {
        let result = self.with(|s| {
            let mut staged = s.vault.clone();
            for bytes in entries {
                let Ok(entry) = Entry::decode(&bytes) else {
                    continue;
                };
                if entry.vault() != staged.id() {
                    continue;
                }
                if entry.log() == Log::Data
                    && (!s.ready || !staged.is_member(&DeviceId::from_bytes(peer)))
                {
                    continue;
                }
                // Like the CLI, skip rejected entries without discarding valid
                // membership updates in the same batch (including removals of
                // a faulty author whose fork an honest peer relayed).
                if staged.apply(entry).is_err() {
                    continue;
                }
            }
            s.commit(staged)
        });
        enforce_membership();
        result.map_err(failure)
    }
}

impl Inviter for Handler {
    async fn offer(&self, _: &PairingContext) -> std::result::Result<Vec<u8>, HandlerError> {
        self.with(|s| {
            s.require_ready()?;
            Ok(serde_json::to_vec(&serde_json::json!({
                "v": 2, "vault": s.vault.id().to_string(), "vault_name": s.vault.name(),
                "name": "Chromium", "addr": s.addr,
            }))?)
        })
        .map_err(failure)
    }

    async fn welcome(
        &self,
        ctx: &PairingContext,
        bytes: Vec<u8>,
    ) -> std::result::Result<Vec<Blob>, HandlerError> {
        let result = self.with(|s| {
            s.require_ready()?;
            let join: Join = serde_json::from_slice(&bytes)?;
            if join.v != 2 {
                return Err(Error::Protocol("unsupported pairing envelope"));
            }
            let device = DeviceId::from_bytes(ctx.remote);
            if s.vault.was_removed(&device) {
                return Err(Error::Protocol("a removed device cannot rejoin"));
            }
            if !s.vault.is_member(&device) {
                let mut staged = s.vault.clone();
                staged.add(
                    &s.secret,
                    device,
                    Signature::from_bytes(unhex(&join.consent)?),
                )?;
                s.commit(staged)?;
            }
            // Names are display-only; never authority. The proof doesn't show peer names.
            drop(join.name);
            Self::learn(s, ctx.remote, join.addr)?;
            let mut welcome = vec![Blob::new(serde_json::to_vec(
                &serde_json::json!({"v": 2, "peers": {}}),
            )?)];
            welcome.extend(s.vault.entries().into_iter().map(Entry::encode));
            Ok(welcome)
        });
        enforce_membership();
        result.map_err(failure)
    }
}
