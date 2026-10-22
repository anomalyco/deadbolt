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
use super::session::{Addr, Hint, Loaded, hex, now, unhex};
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
            .with(|s| hello(s, &DeviceId::from_bytes(peer), Some(s.own_addr())))
            .map_err(handler_error)
    }

    async fn missing_for(
        &self,
        peer: PeerId,
        peer_heads: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, HandlerError> {
        self.0
            .with(|s| {
                missing_for(
                    s,
                    &DeviceId::from_bytes(peer),
                    &peer_heads,
                    self.0.ready.load(Ordering::SeqCst),
                )
            })
            .map_err(handler_error)
    }

    async fn receive(&self, peer: PeerId, entries: Vec<Vec<u8>>) -> Result<(), HandlerError> {
        let agent = &self.0;
        let (node, removed, received) = agent
            .with(|s| {
                let received = receive(
                    s,
                    &DeviceId::from_bytes(peer),
                    entries,
                    agent.ready.load(Ordering::SeqCst),
                );
                // Earlier vault transactions may have committed even if a later
                // vault or address-book write failed. Always enforce those removals.
                Ok((s.node.clone(), agent.refresh(s), received))
            })
            .map_err(handler_error)?;
        agent.enforce(&node, &removed);
        let added = received.map_err(handler_error)?;
        if added > 0 {
            // Pass news on to the other members.
            agent.sync_now.notify_one();
        }
        Ok(())
    }
}

pub(super) fn hello(s: &Loaded, peer: &DeviceId, addr: Option<Addr>) -> Result<Vec<u8>> {
    let vaults = s
        .vaults
        .iter()
        .filter(|(_, vault)| vault.is_member(peer))
        .map(|(id, vault)| (id.to_string(), hex(&vault.heads().encode())))
        .collect();
    Ok(serde_json::to_vec(&Hello {
        v: 1,
        name: s.meta.device_name.clone(),
        addr,
        peers: s.hints_for(peer),
        vaults,
    })?)
}

pub(super) fn missing_for(
    s: &mut Loaded,
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
pub(super) fn receive(
    s: &mut Loaded,
    peer: &DeviceId,
    entries: Vec<Vec<u8>>,
    ready: bool,
) -> Result<usize> {
    let mut grouped: BTreeMap<VaultId, Vec<Entry>> = BTreeMap::new();
    for bytes in entries {
        let entry = match Entry::decode(&bytes) {
            Ok(entry) => entry,
            Err(error) => {
                warn!(peer = %peer, "undecodable entry: {error}");
                continue;
            }
        };
        if !s.vaults.contains_key(&entry.vault()) {
            continue;
        }
        if entry.log() == Log::Data && !ready {
            continue;
        }
        grouped.entry(entry.vault()).or_default().push(entry);
    }
    let mut added = 0;
    for (id, entries) in grouped {
        added += s.update(id, |vault, _| {
            let mut added = 0;
            for entry in entries {
                if entry.log() == Log::Data && !vault.is_member(peer) {
                    continue;
                }
                match vault.apply(entry) {
                    Ok(true) => added += 1,
                    Ok(false) => {}
                    Err(error) => debug!(peer = %peer, "rejected entry: {error}"),
                }
            }
            Ok(added)
        })?;
    }
    s.peer_mut(peer).last_seen = Some(now());
    s.save_peers()?;
    if added > 0 {
        info!(peer = %peer, entries = added, "received");
    }
    Ok(added)
}

pub(super) fn barrier_complete(members: &HashSet<PeerId>, succeeded: &HashSet<PeerId>) -> bool {
    members.is_subset(succeeded)
}

/// Syncs with every member of every vault, or only of `only`, concurrently.
pub async fn sync_all(agent: &Arc<Agent>, only: Option<VaultId>) -> Result<Vec<PeerSync>> {
    let (node, targets) = agent.with(|s| {
        let peers = match only {
            Some(id) => s
                .vault(&id)
                .members()
                .filter(|member| *member != s.id)
                .map(|member| *member.as_bytes())
                .collect(),
            None => s.peer_set(),
        };
        let targets: Vec<_> = peers
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
        results.push(joined?);
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
/// every known member, then full syncs every [`SYNC_INTERVAL`] and
/// whenever something changed.
pub async fn run(agent: Arc<Agent>) {
    loop {
        match sync_all(&agent, None).await {
            Ok(results) if !agent.ready.load(Ordering::SeqCst) => {
                let succeeded = results
                    .iter()
                    .filter(|p| p.error.is_none())
                    .filter_map(|p| unhex(&p.device.id).ok())
                    .collect();
                // Re-read membership after the round: newly learned members must
                // also complete a round. Failed/time-out attempts never open data.
                let completed = agent
                    .with(|s| {
                        let complete = barrier_complete(&s.peer_set(), &succeeded);
                        if complete {
                            agent.ready.store(true, Ordering::SeqCst);
                        }
                        Ok(complete)
                    })
                    .unwrap_or(false);
                if completed {
                    continue;
                }
            }
            Ok(_) => {}
            Err(error) => warn!("sync failed: {error:#}"),
        }
        tokio::select! {
            _ = tokio::time::sleep(SYNC_INTERVAL) => {}
            _ = agent.sync_now.notified() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::session::Meta;
    use super::*;
    use deadbolt_core::{DeviceSecret, Field, FieldType, Vault};

    #[test]
    fn startup_requires_success_from_current_and_newly_discovered_peers() {
        assert!(!barrier_complete(
            &HashSet::from([[1; 32]]),
            &HashSet::new()
        ));
        assert!(!barrier_complete(
            &HashSet::from([[1; 32], [2; 32]]),
            &HashSet::from([[1; 32]])
        ));
        assert!(barrier_complete(
            &HashSet::from([[1; 32]]),
            &HashSet::from([[1; 32]])
        ));
    }

    #[test]
    fn startup_does_not_accept_data() {
        let dir = tempfile::tempdir().unwrap();
        let secret = DeviceSecret::from_bytes(&[1; 32]);
        let store = deadbolt_store::init_with_params(
            dir.path(),
            b"test",
            *secret.to_bytes(),
            deadbolt_store::KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        let (mut source, genesis) = Vault::create(&secret, "test").unwrap();
        let id = source.id();
        let mut loaded = Loaded {
            store,
            id: secret.device_id(),
            secret,
            meta: Meta::default(),
            vaults: [(id, Vault::from_genesis(genesis).unwrap())]
                .into_iter()
                .collect(),
        };
        let (_, entry) = source
            .create_item(
                &loaded.secret,
                "login",
                None,
                [("password".into(), Field::new(FieldType::Secret, "private"))],
            )
            .unwrap();
        let peer = loaded.id;
        receive(&mut loaded, &peer, vec![entry.encode()], false).unwrap();
        assert!(loaded.vault(&id).items().is_empty());
    }
}
