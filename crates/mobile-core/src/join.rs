//! A fresh real member, not a remote control client. The existing pairing v3
//! listener and application consent/welcome validation do all authentication.
use std::sync::Mutex;

use deadbolt_core::{DeviceId, DeviceSecret, Entry};
use deadbolt_net::application::{self, Addr, Offer, WelcomeReplay, Welcomed};
use deadbolt_net::{
    Blob, HandlerError, Joiner, Node, NodeConfig, PairingCode, PairingContext, PairingOptions,
    PeerId, SyncHandler,
};
use deadbolt_store::KdfParams;

use crate::{
    MobileError, Result,
    session::{Loaded, PEERS},
};

pub(crate) struct Fresh {
    secret: DeviceSecret,
    name: String,
    addr: Addr,
    offer: Mutex<Option<Offer>>,
    welcomed: Mutex<Option<Welcomed>>,
}

pub(crate) struct Listening {
    pub code: String,
    pub node: Node,
    pub listener: deadbolt_net::PairingListener,
    pub fresh: Fresh,
}

pub(crate) async fn listen(name: String) -> Result<Listening> {
    let secret = DeviceSecret::generate();
    let code = PairingCode::generate()?;
    let mut config = NodeConfig::new(*secret.to_bytes());
    config.portmapper = false;
    let node = Node::spawn(config, std::sync::Arc::new(|_: &PeerId| false), NoSync).await?;
    if !node.online(std::time::Duration::from_secs(20)).await {
        return Err(MobileError::Network);
    }
    let listener = node.start_pairing(&code, PairingOptions::default()).await?;
    let fresh = Fresh {
        secret,
        name,
        addr: Addr::from_peer(node.addr()),
        offer: Mutex::new(None),
        welcomed: Mutex::new(None),
    };
    Ok(Listening {
        code: code.to_string(),
        node,
        listener,
        fresh,
    })
}

impl Fresh {
    pub fn persist(self, path: &std::path::Path, passphrase: &[u8]) -> Result<Loaded> {
        let welcomed = self
            .welcomed
            .into_inner()
            .map_err(|_| MobileError::Internal)?
            .ok_or(MobileError::InvalidVault)?;
        let mut peers = welcomed.peers;
        peers.insert(
            welcomed.inviter.to_string(),
            application::Hint {
                name: Some(welcomed.inviter_name),
                addr: welcomed.inviter_addr,
                addr_seen: 0,
            },
        );
        let metadata = serde_json::to_vec(&peers).map_err(|_| MobileError::Internal)?;
        let store = deadbolt_store::init_with_setup(
            path,
            passphrase,
            *self.secret.to_bytes(),
            KdfParams::DEFAULT,
            |store| {
                store.append_batch(welcomed.vault.iter_entries().map(Entry::encode))?;
                store.meta_set(PEERS, &metadata)?;
                Ok(())
            },
        )?;
        Loaded::open(store, self.name)
    }
}

impl Joiner for Fresh {
    type Welcome = WelcomeReplay;

    async fn join(
        &self,
        ctx: &PairingContext,
        bytes: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, HandlerError> {
        let (offer, vault) = application::read_offer(&bytes)?;
        let blob = application::join_blob(
            &self.secret,
            &self.name,
            DeviceId::from_bytes(ctx.remote),
            &vault,
            Some(self.addr.clone()),
        )?;
        *self.offer.lock().map_err(|_| MobileError::Internal)? = Some(offer);
        Ok(blob)
    }
    async fn receive(
        &self,
        ctx: &PairingContext,
        welcome: WelcomeReplay,
    ) -> std::result::Result<(), HandlerError> {
        let offer = self
            .offer
            .lock()
            .map_err(|_| MobileError::Internal)?
            .take()
            .ok_or(MobileError::InvalidVault)?;
        let welcomed = application::verify_welcome(
            &self.secret.device_id(),
            DeviceId::from_bytes(ctx.remote),
            offer,
            welcome,
        )?;
        *self.welcomed.lock().map_err(|_| MobileError::Internal)? = Some(welcomed);
        Ok(())
    }
}

struct NoSync;
impl SyncHandler for NoSync {
    async fn heads(&self, _: PeerId) -> std::result::Result<Vec<u8>, HandlerError> {
        Err("device not set up".into())
    }
    async fn missing_for(
        &self,
        _: PeerId,
        _: Vec<u8>,
    ) -> std::result::Result<deadbolt_net::Outgoing<'_>, HandlerError> {
        Err("device not set up".into())
    }
    async fn receive(&self, _: PeerId, _: Vec<Blob>) -> std::result::Result<(), HandlerError> {
        Err("device not set up".into())
    }
}
