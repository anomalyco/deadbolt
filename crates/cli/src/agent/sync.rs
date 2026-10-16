//! Vault sync over deadbolt-net.
//!
//! The opaque heads blob is a JSON [`Hello`]: the sender's name and address,
//! hints about other members, and the core `Heads` of each vault it shares
//! with the receiver. Entries are sent for vaults both sides list and the
//! receiver is a member of, all membership entries first. Until the startup
//! round (membership with every reachable member) is done, only membership
//! entries are sent.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use deadbolt_core::{DeviceId, Entry, Heads, Log, VaultId};
use deadbolt_net::{HandlerError, PeerId, SyncHandler};
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use super::Agent;
use super::session::{Addr, Hint, Session, hex, now, unhex};
use crate::protocol::PeerSync;

pub const SYNC_INTERVAL: Duration = Duration::from_secs(30);
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Serialize, Deserialize)]
struct Hello {
    v: u32,
    name: String,
    addr: Option<Addr>,
    #[serde(default)]
    peers: BTreeMap<String, Hint>,
    /// Vault id (hex) -> core heads (hex).
    vaults: BTreeMap<String, String>,
}

pub struct Handler(pub Arc<Agent>);

fn handler_error(error: anyhow::Error) -> HandlerError {
    format!("{error:#}").into()
}

impl SyncHandler for Handler {
    async fn heads(&self, peer: PeerId) -> Result<Vec<u8>, HandlerError> {
        self.0
            .with(|s| hello(s, &DeviceId::from_bytes(peer)))
            .map_err(handler_error)
    }

    async fn missing_for(
        &self,
        peer: PeerId,
        peer_heads: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, HandlerError> {
        let ready = self.0.ready.load(Ordering::SeqCst);
        self.0
            .with(|s| missing_for(s, &DeviceId::from_bytes(peer), &peer_heads, ready))
            .map_err(handler_error)
    }

    async fn receive(&self, peer: PeerId, entries: Vec<Vec<u8>>) -> Result<(), HandlerError> {
        let agent = &self.0;
        let (node, removed, added) = agent
            .with(|s| {
                let added = receive(s, &DeviceId::from_bytes(peer), entries)?;
                Ok((s.node.clone(), agent.refresh(s), added))
            })
            .map_err(handler_error)?;
        agent.enforce(&node, &removed);
        if added > 0 {
            // Pass news on to the other members.
            agent.sync_now.notify_one();
        }
        Ok(())
    }
}

fn hello(s: &Session, peer: &DeviceId) -> Result<Vec<u8>> {
    let vaults = s
        .vaults
        .iter()
        .filter(|(_, vault)| vault.is_member(peer))
        .map(|(id, vault)| (id.to_string(), hex(&vault.heads().encode())))
        .collect();
    Ok(serde_json::to_vec(&Hello {
        v: 1,
        name: s.meta.device_name.clone(),
        addr: Some(s.own_addr()),
        peers: s.hints_for(peer),
        vaults,
    })?)
}

fn missing_for(
    s: &mut Session,
    peer: &DeviceId,
    bytes: &[u8],
    ready: bool,
) -> Result<Vec<Vec<u8>>> {
    let hello: Hello = serde_json::from_slice(bytes)?;
    s.learn(peer, Some(&hello.name), hello.addr, hello.peers);
    s.save_peers()?;
    let mut membership = Vec::new();
    let mut data = Vec::new();
    for (vault, heads) in &hello.vaults {
        let Ok(id) = unhex::<32>(vault).map(VaultId::from_bytes) else {
            continue;
        };
        let Some(vault) = s.vaults.get(&id).filter(|v| v.is_member(peer)) else {
            continue;
        };
        let heads = Heads::decode(&data_encoding::HEXLOWER.decode(heads.as_bytes())?)?;
        for entry in vault.missing_for(&heads) {
            match entry.log() {
                Log::Membership => membership.push(entry.encode()),
                Log::Data if ready => data.push(entry.encode()),
                Log::Data => {}
            }
        }
    }
    membership.append(&mut data);
    Ok(membership)
}

/// Applies entries from `peer`. Data entries are only taken from current
/// members of their vault; signed membership entries from any member of a
/// shared vault. Returns how many were new.
fn receive(s: &mut Session, peer: &DeviceId, entries: Vec<Vec<u8>>) -> Result<usize> {
    let mut added: Vec<Entry> = Vec::new();
    for bytes in entries {
        let entry = match Entry::decode(&bytes) {
            Ok(entry) => entry,
            Err(error) => {
                warn!(peer = %peer, "undecodable entry: {error}");
                continue;
            }
        };
        let Some(vault) = s.vaults.get_mut(&entry.vault()) else {
            continue;
        };
        if entry.log() == Log::Data && !vault.is_member(peer) {
            continue;
        }
        match vault.apply(entry.clone()) {
            Ok(true) => added.push(entry),
            Ok(false) => {}
            Err(error) => debug!(peer = %peer, "rejected entry: {error}"),
        }
    }
    s.persist(&added)?;
    s.peer_mut(peer).last_seen = Some(now());
    s.save_peers()?;
    if !added.is_empty() {
        info!(peer = %peer, entries = added.len(), "received");
    }
    Ok(added.len())
}

/// Syncs with every member of every vault, concurrently.
pub async fn sync_all(agent: &Arc<Agent>) -> Result<Vec<PeerSync>> {
    let (node, targets) = agent.with(|s| {
        let targets: Vec<_> = s
            .peer_set()
            .into_iter()
            .map(|id| s.addr_of(&DeviceId::from_bytes(id)))
            .collect();
        Ok((s.node.clone(), targets))
    })?;
    let mut tasks = JoinSet::new();
    for addr in targets {
        let node = node.clone();
        tasks.spawn(async move {
            let id = addr.id;
            let result = match tokio::time::timeout(SYNC_TIMEOUT, node.sync(addr)).await {
                Ok(Ok(outcome)) => Ok(outcome),
                Ok(Err(error)) => Err(error.to_string()),
                Err(_) => Err("timed out".to_string()),
            };
            (id, result)
        });
    }
    let mut results = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(result) = joined {
            results.push(result);
        }
    }
    let connected: HashSet<PeerId> = node.connected_peers().into_iter().collect();
    agent.with(|s| {
        let mut peers: Vec<PeerSync> = results
            .into_iter()
            .map(|(id, result)| {
                let device = s.device_info(&DeviceId::from_bytes(id), &connected);
                match result {
                    Ok(outcome) => PeerSync {
                        device,
                        sent: outcome.sent,
                        received: outcome.received,
                        error: None,
                    },
                    Err(error) => {
                        debug!(peer = %device.id, "sync failed: {error}");
                        PeerSync {
                            device,
                            sent: 0,
                            received: 0,
                            error: Some(error),
                        }
                    }
                }
            })
            .collect();
        peers.sort_by(|a, b| (&a.device.name, &a.device.id).cmp(&(&b.device.name, &b.device.id)));
        Ok(peers)
    })
}

/// The background sync loop, running while unlocked: a membership round with
/// every reachable member, then full syncs every [`SYNC_INTERVAL`] and
/// whenever something changed.
pub async fn run(agent: Arc<Agent>) {
    if let Err(error) = sync_all(&agent).await {
        warn!("startup sync failed: {error:#}");
    }
    agent.ready.store(true, Ordering::SeqCst);
    loop {
        if let Err(error) = sync_all(&agent).await {
            warn!("sync failed: {error:#}");
        }
        tokio::select! {
            _ = tokio::time::sleep(SYNC_INTERVAL) => {}
            _ = agent.sync_now.notified() => {}
        }
    }
}
