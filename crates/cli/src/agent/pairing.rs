//! Pairing blobs and the [`Joiner`]/[`Inviter`] implementations.
//!
//! ```text
//! offer   = JSON Offer   {vault id, vault name, inviter name + address}
//! join    = JSON JoinBlob {consent signature (bound to the inviter), device name + address}
//! welcome = [JSON WelcomeMeta {hints about the other members}, entry*]   (genesis first)
//! ```
//!
//! Both sides report the confirmation code to the client. With `confirm` the
//! client is asked to accept it; otherwise holding the ticket is the
//! authorization and the code is accepted automatically. The new device reports once it has the offer, so
//! the vault name is shown with the code, and only then signs its consent.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use deadbolt_core::{DeviceId, Entry, Signature, Vault, VaultId};
use deadbolt_net::{HandlerError, Inviter, Joiner, PairingContext, PairingOptions, PairingTicket};
use serde::{Deserialize, Serialize};
use tracing::info;

use super::session::{Addr, Hint, Loaded, hex, short, unhex};
use super::{Agent, Conversation};
use crate::protocol::{DeviceInfo, Event, Reply, VaultInfo};

#[derive(Serialize, Deserialize)]
pub(super) struct Offer {
    v: u32,
    vault: String,
    vault_name: String,
    name: String,
    addr: Option<Addr>,
}

#[derive(Serialize, Deserialize)]
struct JoinBlob {
    v: u32,
    consent: String,
    name: String,
    addr: Option<Addr>,
}

#[derive(Serialize, Deserialize)]
struct WelcomeMeta {
    v: u32,
    peers: BTreeMap<String, Hint>,
}

fn handler_error(error: anyhow::Error) -> HandlerError {
    format!("{error:#}").into()
}

pub(super) fn offer(s: &Loaded, vault: VaultId, addr: Option<Addr>) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&Offer {
        v: 1,
        vault: vault.to_string(),
        vault_name: s.vault(&vault).name().into(),
        name: s.meta.device_name.clone(),
        addr,
    })?)
}

pub(super) fn join_blob(
    s: &Loaded,
    inviter: DeviceId,
    offer: &Offer,
    addr: Option<Addr>,
) -> Result<Vec<u8>> {
    let vault = VaultId::from_bytes(unhex(&offer.vault)?);
    if s.vaults.contains_key(&vault) {
        bail!("this device already holds vault {}", offer.vault_name);
    }
    Ok(serde_json::to_vec(&JoinBlob {
        v: 1,
        consent: hex(s.secret.join_consent(&vault, &inviter).as_bytes()),
        name: s.meta.device_name.clone(),
        addr,
    })?)
}

pub(super) fn welcome(
    s: &mut Loaded,
    vault: VaultId,
    device: DeviceId,
    join: &[u8],
    fallback_addr: Option<Addr>,
) -> Result<(Vec<Vec<u8>>, DeviceInfo)> {
    let join: JoinBlob = serde_json::from_slice(join)?;
    let consent = Signature::from_bytes(unhex(&join.consent)?);
    let held = s.vault(&vault);
    if !held.is_member(&s.id) {
        bail!("this device is no longer a member of {}", held.name());
    }
    if held.is_member(&device) {
        bail!("that device is already a member of {}", held.name());
    }
    s.update(vault, |v, secret| {
        v.add(secret, device, consent).context("adding the device")
    })?;
    s.learn(
        &device,
        Some(&join.name),
        join.addr.or(fallback_addr),
        BTreeMap::new(),
    );
    s.save_peers()?;
    let mut blobs = vec![serde_json::to_vec(&WelcomeMeta {
        v: 1,
        peers: s.hints_for(&device),
    })?];
    blobs.extend(s.vault(&vault).entries().into_iter().map(Entry::encode));
    Ok((blobs, s.device_info(&device, &HashSet::new())))
}

pub(super) fn apply_welcome(
    s: &mut Loaded,
    inviter: DeviceId,
    offer: &Offer,
    welcome: Vec<Vec<u8>>,
) -> Result<VaultInfo> {
    let mut blobs = welcome.into_iter();
    let meta: WelcomeMeta =
        serde_json::from_slice(&blobs.next().ok_or_else(|| anyhow!("empty welcome"))?)?;
    let entries: Vec<Entry> = blobs
        .map(|bytes| Entry::decode(&bytes))
        .collect::<Result<_, _>>()
        .context("decoding welcome")?;
    let vault = Vault::load(entries).context("loading the vault")?;
    if vault.id().to_string() != offer.vault {
        bail!("the welcome is for another vault");
    }
    if !vault.is_member(&s.id) || !vault.is_member(&inviter) {
        bail!("the welcome does not admit this device");
    }
    s.learn(&inviter, Some(&offer.name), offer.addr.clone(), meta.peers);
    let id = vault.id();
    s.add_vault(vault)?;
    Ok(s.vault_info(&id))
}

/// Reports the code; with `confirm`, waits for the client to accept it.
async fn report(conv: &Conversation, event: Event, confirm: bool) -> bool {
    if confirm {
        conv.ask(event).await
    } else {
        conv.event(event).await.is_ok()
    }
}

struct NewDevice<'a> {
    agent: &'a Arc<Agent>,
    conv: &'a Conversation,
    confirm: bool,
    offer: Mutex<Option<Offer>>,
    joined: Mutex<Option<VaultInfo>>,
}

impl Joiner for NewDevice<'_> {
    async fn confirm(&self, _ctx: &PairingContext) -> bool {
        // Reported in `join`, once the vault name is known.
        true
    }

    async fn join(&self, ctx: &PairingContext, offer: Vec<u8>) -> Result<Vec<u8>, HandlerError> {
        let offer: Offer = serde_json::from_slice(&offer)?;
        let inviter_id = DeviceId::from_bytes(ctx.remote);
        let join = self
            .agent
            .with(|s| join_blob(s, inviter_id, &offer, Some(s.own_addr())))
            .map_err(handler_error)?;
        let inviter = DeviceInfo {
            id: hex(&ctx.remote),
            name: Some(super::session::clean_name(&offer.name)),
            this: false,
            connected: true,
            last_seen: None,
        };
        let event = Event::Joining {
            code: ctx.code.to_string(),
            vault: offer.vault_name.clone(),
            inviter,
        };
        if !report(self.conv, event, self.confirm).await {
            return Err("declined".into());
        }
        *self.offer.lock().unwrap_or_else(|e| e.into_inner()) = Some(offer);
        Ok(join)
    }

    async fn receive(
        &self,
        ctx: &PairingContext,
        welcome: Vec<Vec<u8>>,
    ) -> Result<(), HandlerError> {
        let offer = self
            .offer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or("no offer")?;
        let info = self.welcomed(ctx, offer, welcome).map_err(handler_error)?;
        *self.joined.lock().unwrap_or_else(|e| e.into_inner()) = Some(info);
        Ok(())
    }
}

impl NewDevice<'_> {
    fn welcomed(
        &self,
        ctx: &PairingContext,
        offer: Offer,
        welcome: Vec<Vec<u8>>,
    ) -> Result<VaultInfo> {
        let inviter = DeviceId::from_bytes(ctx.remote);
        let (node, removed, info) = self.agent.with(|s| {
            let info = apply_welcome(s, inviter, &offer, welcome)?;
            Ok((s.node.clone(), self.agent.refresh(s), info))
        })?;
        self.agent.enforce(&node, &removed);
        Ok(info)
    }
}

/// `deadbolt join`: show a ticket and wait for an existing device to pair.
pub async fn join(agent: &Arc<Agent>, conv: &Conversation, confirm: bool) -> Result<Reply> {
    let node = agent.with(|s| Ok(s.node.clone()))?;
    let listener = node.start_pairing(PairingOptions::default()).await?;
    conv.event(Event::Ticket {
        ticket: listener.ticket().to_string(),
    })
    .await?;
    let device = NewDevice {
        agent,
        conv,
        confirm,
        offer: Mutex::default(),
        joined: Mutex::default(),
    };
    tokio::select! {
        result = listener.complete(&device) => { result?; }
        _ = conv.closed() => bail!("cancelled"),
    }
    let vault = device
        .joined
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .ok_or_else(|| anyhow!("pairing finished without a vault"))?;
    info!(vault = %vault.name, "joined vault");
    agent.sync_now.notify_one();
    Ok(Reply::Vault { vault })
}

struct ExistingDevice<'a> {
    agent: &'a Arc<Agent>,
    conv: &'a Conversation,
    confirm: bool,
    vault: VaultId,
    ticket_addr: Addr,
    added: Mutex<Option<DeviceInfo>>,
}

impl Inviter for ExistingDevice<'_> {
    async fn confirm(&self, ctx: &PairingContext) -> bool {
        let event = Event::Pairing {
            code: ctx.code.to_string(),
            device: short(&ctx.remote),
        };
        report(self.conv, event, self.confirm).await
    }

    async fn offer(&self, _ctx: &PairingContext) -> Result<Vec<u8>, HandlerError> {
        self.agent
            .with_data(|s| offer(s, self.vault, Some(s.own_addr())))
            .map_err(handler_error)
    }

    async fn welcome(
        &self,
        ctx: &PairingContext,
        join: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, HandlerError> {
        let device = DeviceId::from_bytes(ctx.remote);
        let (node, removed, blobs, info) = self
            .agent
            .with_data(|s| {
                let (blobs, info) =
                    welcome(s, self.vault, device, &join, Some(self.ticket_addr.clone()))?;
                Ok((s.node.clone(), self.agent.refresh(s), blobs, info))
            })
            .map_err(handler_error)?;
        self.agent.enforce(&node, &removed);
        *self.added.lock().unwrap_or_else(|e| e.into_inner()) = Some(info);
        Ok(blobs)
    }
}

/// `deadbolt pair`: admit the device showing `ticket` into a vault.
pub async fn pair(
    agent: &Arc<Agent>,
    conv: &Conversation,
    ticket: String,
    vault: Option<String>,
    confirm: bool,
) -> Result<Reply> {
    let ticket: PairingTicket = ticket.parse()?;
    tokio::select! {
        result = agent.wait_ready() => result?,
        _ = conv.closed() => bail!("cancelled"),
    }
    let (node, vault) = agent.with_data(|s| {
        if ticket.peer_id() == *s.id.as_bytes() {
            bail!("that ticket is from this device");
        }
        let id = s.resolve(vault.as_deref())?;
        if !s.vault(&id).is_member(&s.id) {
            bail!(
                "this device is no longer a member of {}",
                s.vault(&id).name()
            );
        }
        Ok((s.node.clone(), id))
    })?;
    let inviter = ExistingDevice {
        agent,
        conv,
        confirm,
        vault,
        ticket_addr: Addr::from_peer(&ticket.addr()),
        added: Mutex::default(),
    };
    tokio::select! {
        result = node.pair(&ticket, &inviter) => { result?; }
        _ = conv.closed() => bail!("cancelled"),
    }
    let device = inviter
        .added
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .ok_or_else(|| anyhow!("pairing finished without adding the device"))?;
    let vault = agent.with(|s| Ok(s.vault_info(&vault)))?;
    info!(vault = %vault.name, device = %device.id, "paired");
    agent.sync_now.notify_one();
    Ok(Reply::Device { vault, device })
}
