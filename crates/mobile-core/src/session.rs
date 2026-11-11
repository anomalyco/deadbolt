//! Native storage and transport adapters. Admission and sync decisions live in
//! deadbolt-net::application; signatures, item rules and TOTP live in core.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, Weak},
};

use deadbolt_core::{DeviceId, DeviceSecret, Entry, Vault, VaultId, VaultWrite};
use deadbolt_net::application::{self, Addr, Hint, State};
use deadbolt_net::approval::ApprovalInbox;
use deadbolt_net::{Blob, HandlerError, Node, NodeConfig, PeerAddr, PeerId, SyncHandler};
use deadbolt_store::Unlocked;
use tokio_util::sync::CancellationToken;

use crate::{MobileError, Result};

pub(crate) const PEERS: &str = "mobile/peers";

pub(crate) struct Loaded {
    pub store: Unlocked,
    pub secret: DeviceSecret,
    pub vault: Vault,
    name: String,
    peers: BTreeMap<String, Hint>,
    addr: Option<Addr>,
    ready: bool,
    // Set only by a completed outbound data exchange in the serialized sync round.
    synced_peer: bool,
}

impl Loaded {
    pub fn open(store: Unlocked, name: String) -> Result<Self> {
        let vault = application::storage::load(&store).map_err(|_| MobileError::InvalidVault)?;
        let peers = store
            .meta_get(PEERS)?
            .map(|b| serde_json::from_slice(&b))
            .transpose()
            .map_err(|_| MobileError::InvalidVault)?
            .unwrap_or_default();
        let secret = DeviceSecret::from_bytes(store.device_secret());
        let ready = vault.members().all(|id| id == secret.device_id());
        Ok(Self {
            store,
            secret,
            vault,
            name,
            peers,
            addr: None,
            ready,
            synced_peer: false,
        })
    }

    fn targets(&self) -> Vec<PeerAddr> {
        self.vault
            .members()
            .filter(|id| *id != self.secret.device_id())
            .map(|id| {
                self.peers
                    .get(&id.to_string())
                    .and_then(|hint| hint.addr.clone())
                    .unwrap_or_default()
                    .peer(*id.as_bytes())
            })
            .collect()
    }
}

impl State for Loaded {
    type Error = MobileError;
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
            .filter_map(|id| {
                self.peers
                    .get(&id.to_string())
                    .map(|hint| (id.to_string(), hint.clone()))
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
            return Err(MobileError::InvalidVault);
        }
        self.vault.transact(
            |vault| Ok(change(vault, &self.secret)?),
            |entries| {
                self.store
                    .append_batch(entries.iter().copied().map(Entry::encode))?;
                Ok(())
            },
        )
    }
    fn learn(
        &mut self,
        peer: &DeviceId,
        name: &str,
        addr: Option<Addr>,
        hints: BTreeMap<String, Hint>,
    ) -> Result<()> {
        // Hints are not authority. Keep only members; the direct peer's own
        // address wins over gossip. Membership checks stay in application/core.
        for member in self.vault.members() {
            let id = member.to_string();
            if member != self.device_id()
                && member != *peer
                && let Some(hint) = hints.get(&id)
            {
                self.peers.entry(id).or_insert_with(|| hint.clone());
            }
        }
        if self.vault.is_member(peer) {
            let hint = self.peers.entry(peer.to_string()).or_insert(Hint {
                name: None,
                addr: None,
                addr_seen: 0,
            });
            let name = application::clean_name(name);
            if !name.is_empty() {
                hint.name = Some(name);
            }
            if addr.is_some() {
                hint.addr = addr;
            }
        }
        self.peers
            .retain(|id, _| self.vault.members().any(|member| member.to_string() == *id));
        self.store.meta_set(
            PEERS,
            &serde_json::to_vec(&self.peers).map_err(|_| MobileError::Internal)?,
        )?;
        Ok(())
    }
    fn received(&mut self, _: &DeviceId) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct Handler {
    loaded: Arc<Mutex<Option<Loaded>>>,
    session: Arc<Mutex<Weak<Session>>>,
    cancel: CancellationToken,
}

impl Handler {
    pub(crate) fn stream(
        &self,
        history: application::OutgoingHistory,
    ) -> deadbolt_net::Outgoing<'_> {
        history.outgoing(|history| {
            let slot = self.loaded.lock().map_err(|_| MobileError::Internal)?;
            let s = slot.as_ref().ok_or(MobileError::Locked)?;
            if self.cancel.is_cancelled() {
                return Err(MobileError::Locked.into());
            }
            if !s.vault.is_member(&s.device_id()) {
                return Err(MobileError::InvalidVault.into());
            }
            Ok(history.next(s, s.ready).map_err(MobileError::from)?)
        })
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut Loaded) -> Result<T>) -> Result<T> {
        if self.cancel.is_cancelled() {
            return Err(MobileError::Locked);
        }
        let mut slot = self.loaded.lock().map_err(|_| MobileError::Internal)?;
        let result = f(slot.as_mut().ok_or(MobileError::Locked)?);
        if matches!(result, Err(MobileError::UnconfirmedWrite)) {
            *slot = None;
            self.cancel.cancel();
        }
        drop(slot);
        // A removal may have committed even if a later metadata write failed.
        self.enforce();
        result
    }

    fn enforce(&self) {
        let session = self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upgrade();
        if let Some(session) = session {
            session.node.enforce_membership();
        }
    }

    pub fn clear(&self) {
        self.cancel.cancel();
        *self.loaded.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.enforce();
    }

    fn is_member(&self, peer: &PeerId) -> bool {
        !self.cancel.is_cancelled()
            && self.loaded.lock().ok().is_some_and(|slot| {
                slot.as_ref().is_some_and(|s| {
                    s.vault.is_member(&s.secret.device_id())
                        && s.vault.is_member(&DeviceId::from_bytes(*peer))
                })
            })
    }

    fn can_approve(&self, vault: &str, origin: &PeerId) -> bool {
        !self.cancel.is_cancelled()
            && self.loaded.lock().ok().is_some_and(|slot| {
                slot.as_ref().is_some_and(|s| {
                    s.ready
                        && s.vault.id().to_string() == vault
                        && s.vault.is_member(&s.secret.device_id())
                        && s.vault.is_member(&DeviceId::from_bytes(*origin))
                })
            })
    }
}

fn failure(error: MobileError) -> HandlerError {
    error.to_string().into()
}

impl SyncHandler for Handler {
    type ReceiveState = ();

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
            .with(|s| application::missing_for(s, &DeviceId::from_bytes(peer), &bytes, s.ready))
            .map_err(failure)?;
        Ok(self.stream(history))
    }
    async fn receive(
        &self,
        peer: PeerId,
        entries: Vec<Blob>,
        _: &mut (),
        _: bool,
    ) -> std::result::Result<(), HandlerError> {
        self.with(|s| {
            application::receive(s, &DeviceId::from_bytes(peer), entries, s.ready).map(drop)
        })
        .map_err(failure)
    }
}

impl application::RoundState for Handler {
    type Error = MobileError;
    fn ready(&self) -> Result<bool> {
        self.with(|s| Ok(s.ready))
    }
    fn targets(&self) -> Result<Vec<PeerAddr>> {
        self.with(|s| Ok(s.targets()))
    }
    fn saw(&self, _: PeerId) -> Result<()> {
        self.with(|s| {
            // Membership refresh alone does not confirm a data sync.
            if s.ready {
                s.synced_peer = true;
            }
            Ok(())
        })
    }
    fn publish_ready(&self, addr: Addr) -> Result<()> {
        self.with(|s| {
            s.ready = true;
            s.addr = Some(addr);
            Ok(())
        })
    }
}

pub(crate) struct Session {
    pub handler: Handler,
    pub node: Node,
    pub cancel: CancellationToken,
    pub approvals: ApprovalInbox,
    // Serialize the short signing decision against lock. Neither network I/O
    // nor the platform biometric prompt runs while this mutex is held.
    approval_action: Mutex<()>,
    sync: tokio::sync::Mutex<()>,
}

impl Session {
    pub async fn start(loaded: Loaded, cancel: CancellationToken) -> Result<Arc<Self>> {
        let mut config = NodeConfig::new(*loaded.secret.to_bytes());
        config.portmapper = false;
        Self::start_with_config(loaded, cancel, config).await
    }

    async fn start_with_config(
        loaded: Loaded,
        cancel: CancellationToken,
        mut config: NodeConfig,
    ) -> Result<Arc<Self>> {
        let handler = Handler {
            loaded: Arc::new(Mutex::new(Some(loaded))),
            session: Arc::new(Mutex::new(Weak::new())),
            cancel: cancel.clone(),
        };
        let gate = handler.clone();
        let allowed = handler.clone();
        let approvals = ApprovalInbox::new(move |vault, origin| allowed.can_approve(vault, origin));
        config.approval_inbox = Some(approvals.clone());
        let node = Node::spawn(
            config,
            Arc::new(move |peer: &PeerId| gate.is_member(peer)),
            handler.clone(),
        )
        .await?;
        handler.with(|s| {
            s.addr = Some(Addr::from_peer(node.addr()));
            Ok(())
        })?;
        let session = Arc::new(Self {
            handler,
            node,
            cancel,
            approvals,
            approval_action: Mutex::new(()),
            sync: tokio::sync::Mutex::new(()),
        });
        *session
            .handler
            .session
            .lock()
            .map_err(|_| MobileError::Internal)? = Arc::downgrade(&session);
        Ok(session)
    }

    pub async fn sync(&self) -> Result<()> {
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(MobileError::Cancelled),
            result = async {
                let _round = self.sync.lock().await;
                self.handler.with(|s| {
                    s.synced_peer = false;
                    Ok(())
                })?;
                application::sync_round(&self.node, &self.handler).await?;
                self.handler.with(|s| {
                    if !s.synced_peer && s.vault.members().any(|id| id != s.device_id()) {
                        return Err(MobileError::Network);
                    }
                    Ok(())
                })
            } => result,
        }
    }

    pub fn lock(&self) {
        let _action = self
            .approval_action
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.handler.clear();
        // pending() drops a no-longer-authorized slot and its response sender.
        // Its predicate locks Loaded, so never call it inside Handler::with.
        drop(self.approvals.pending());
    }

    pub fn approval_respond(&self, id: &str, allow: bool, key: &[u8]) -> Result<()> {
        let _action = self
            .approval_action
            .lock()
            .map_err(|_| MobileError::Internal)?;
        let seed = self.handler.with(|s| {
            if allow {
                let key = key.try_into().map_err(|_| MobileError::InvalidRequest)?;
                Ok(s.store.biometric_device_secret(key)?)
            } else {
                Ok(zeroize::Zeroizing::new(*s.secret.to_bytes()))
            }
        })?;
        // Rechecks id, expiry, exact vault, both memberships and readiness.
        // The signing key on Allow came from AEAD unwrap above, not s.secret.
        self.approvals
            .respond(id, allow, &seed)
            .map_err(|_| MobileError::ApprovalUnavailable)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.lock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[tokio::test]
    async fn sync_requires_a_completed_exchange_only_when_there_are_peers() {
        async fn local_session(
            path: &std::path::Path,
            key: &DeviceSecret,
            vault: Vault,
            peers: Value,
        ) -> Arc<Session> {
            crate::tests::fixture(path, key, vault, peers);
            let store = deadbolt_store::unlock(path, b"local-pass").unwrap();
            Session::start_with_config(
                Loaded::open(store, "Fixture".into()).unwrap(),
                CancellationToken::new(),
                NodeConfig::local_only(*key.to_bytes()),
            )
            .await
            .unwrap()
        }

        let a = DeviceSecret::generate();
        let b = DeviceSecret::generate();
        let home = tempfile::tempdir().unwrap();
        let phone = tempfile::tempdir().unwrap();
        let (vault, _) = Vault::create(&a, "sync-test").unwrap();
        let host = local_session(home.path(), &a, vault, json!({})).await;
        host.sync().await.unwrap(); // Sole member: nothing to contact.
        let vault = host
            .handler
            .with(|s| {
                s.update(s.vault.id(), |vault, key| {
                    vault.add(
                        key,
                        b.device_id(),
                        b.join_consent(&vault.id(), &key.device_id()),
                    )?;
                    Ok(())
                })?;
                Ok(s.vault.clone())
            })
            .unwrap();
        // The signed member exists but has no route; loopback nodes have no lookup.
        assert!(matches!(host.sync().await, Err(MobileError::Network)));
        let hint = Hint {
            addr: Some(Addr::from_peer(host.node.addr())),
            name: None,
            addr_seen: 0,
        };
        let id = vault.id();
        let mobile = local_session(
            phone.path(),
            &b,
            vault,
            json!({a.device_id().to_string():hint}),
        )
        .await;
        mobile.sync().await.unwrap();
        assert_eq!(host.handler.with(|s| Ok(s.vault.items().len())).unwrap(), 2);
        // Start a full catch-up. Lock must also stop an already-selected history,
        // not just reject the next connection.
        let hello = json!({
            "v": 1, "name": "Fixture", "addr": null,
            "vaults": {id.to_string():
                data_encoding::HEXLOWER.encode(&deadbolt_core::Heads::default().encode())}
        });
        let mut history = host
            .handler
            .missing_for(
                *b.device_id().as_bytes(),
                serde_json::to_vec(&hello).unwrap(),
            )
            .await
            .unwrap();
        assert!(history.next().unwrap().is_ok());
        // A previous exchange is not evidence for a new round refused by the peer.
        host.lock();
        assert!(history.next().unwrap().is_err());
        assert!(matches!(mobile.sync().await, Err(MobileError::Network)));
        assert_eq!(
            mobile.handler.with(|s| Ok(s.vault.items().len())).unwrap(),
            2
        );
        mobile.node.shutdown().await;
        host.node.shutdown().await;
    }
}
