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
use deadbolt_core::{DeviceId, Entry, Signature, Vault, VaultId, valid_name};
use deadbolt_net::{
    Blob, HandlerError, Inviter, Joiner, PairingContext, PairingOptions, PairingTicket,
};
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
    if !valid_name(&offer.vault_name) {
        bail!("invalid vault name");
    }
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
) -> Result<(Vec<Blob>, DeviceInfo)> {
    let join: JoinBlob = serde_json::from_slice(join)?;
    let consent = Signature::from_bytes(unhex(&join.consent)?);
    let held = s.vault(&vault);
    if !held.is_member(&s.id) {
        bail!("this device is no longer a member of {}", held.name());
    }
    if held.was_removed(&device) {
        bail!(
            "that device was removed from {} and can't rejoin it",
            held.name()
        );
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
    let mut blobs = vec![Blob::new(serde_json::to_vec(&WelcomeMeta {
        v: 1,
        peers: s.hints_for(&device),
    })?)];
    blobs.extend(s.vault(&vault).entries().into_iter().map(Entry::encode));
    Ok((blobs, s.device_info(&device, &HashSet::new())))
}

pub(super) fn apply_welcome(
    s: &mut Loaded,
    inviter: DeviceId,
    offer: &Offer,
    welcome: Vec<Blob>,
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
    async fn confirm(&self, ctx: &PairingContext, offer: &[u8]) -> bool {
        let Ok(offer) = serde_json::from_slice::<Offer>(offer) else {
            return false;
        };
        if !valid_name(&offer.vault_name) {
            return false;
        }
        let Ok(vault) = unhex(&offer.vault).map(VaultId::from_bytes) else {
            return false;
        };
        if self
            .agent
            .with(|s| Ok(s.vaults.contains_key(&vault)))
            .unwrap_or(true)
        {
            return false;
        }
        let inviter = DeviceInfo {
            id: hex(&ctx.remote),
            name: Some(super::session::clean_name(&offer.name)),
            this: false,
            connected: true,
            last_seen: None,
        };
        let event = Event::Joining {
            code: ctx.code.to_string(),
            vault: super::session::clean_name(&offer.vault_name),
            inviter,
        };
        report(self.conv, event, self.confirm).await
    }

    async fn join(&self, ctx: &PairingContext, offer: Vec<u8>) -> Result<Vec<u8>, HandlerError> {
        let offer: Offer = serde_json::from_slice(&offer)?;
        let inviter_id = DeviceId::from_bytes(ctx.remote);
        let join = self
            .agent
            .with(|s| join_blob(s, inviter_id, &offer, Some(s.own_addr())))
            .map_err(handler_error)?;
        *self.offer.lock().unwrap_or_else(|e| e.into_inner()) = Some(offer);
        Ok(join)
    }

    async fn receive(&self, ctx: &PairingContext, welcome: Vec<Blob>) -> Result<(), HandlerError> {
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
        welcome: Vec<Blob>,
    ) -> Result<VaultInfo> {
        let inviter = DeviceId::from_bytes(ctx.remote);
        self.agent.with(|s| {
            let info = apply_welcome(s, inviter, &offer, welcome)?;
            self.agent.refresh(s);
            Ok(info)
        })
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
    ) -> Result<Vec<Blob>, HandlerError> {
        let device = DeviceId::from_bytes(ctx.remote);
        let (blobs, info) = self
            .agent
            .with_data(|s| {
                let (blobs, info) =
                    welcome(s, self.vault, device, &join, Some(self.ticket_addr.clone()))?;
                self.agent.refresh(s);
                Ok((blobs, info))
            })
            .map_err(handler_error)?;
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
        let held = s.vault(&id);
        if !held.is_member(&s.id) {
            bail!("this device is no longer a member of {}", held.name());
        }
        let peer = DeviceId::from_bytes(ticket.peer_id());
        if held.was_removed(&peer) {
            bail!(
                "that device was removed from {} and can't rejoin it",
                held.name()
            );
        }
        if held.is_member(&peer) {
            bail!("that device is already a member of {}", held.name());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Message;
    use deadbolt_net::{Error as NetError, Node, NodeConfig, PairingStream, PeerId};
    use deadbolt_store::KdfParams;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::UnixStream;
    use tokio::sync::{mpsc, watch};

    async fn test_agent(dir: &std::path::Path, name: &str) -> Arc<Agent> {
        let kdf = KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        };
        let loaded = Loaded::setup(dir, b"test", name, kdf).unwrap();
        let agent = Agent::new(super::super::tests::test_paths(dir), true, kdf);
        agent.ready.send_replace(true);
        let node = Node::spawn(
            NodeConfig::local_only(*loaded.secret.to_bytes()),
            Arc::new(|_: &PeerId| false),
            super::super::sync::Handler(agent.clone()),
        )
        .await
        .unwrap();
        *agent.session.lock().unwrap() = Some(super::super::session::Session::new(loaded, node));
        agent
    }

    fn test_conv(answer: bool) -> (Conversation, UnixStream) {
        let (server, client) = UnixStream::pair().unwrap();
        let (_, write) = server.into_split();
        let (tx, rx) = mpsc::channel(1);
        tx.try_send(answer).unwrap();
        let conv = Conversation {
            write: tokio::sync::Mutex::new(write),
            answers: tokio::sync::Mutex::new(rx),
            closed: watch::channel(false).1,
        };
        (conv, client)
    }

    async fn read_event(client: UnixStream) -> Event {
        let mut line = String::new();
        BufReader::new(client).read_line(&mut line).await.unwrap();
        match serde_json::from_str::<Message>(&line).unwrap() {
            Message::Event { event } => event,
            other => panic!("expected event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn joiner_confirms_with_offer_and_declining_withholds_consent() {
        for joiner_accepts in [false, true] {
            let a_dir = tempfile::tempdir().unwrap();
            let b_dir = tempfile::tempdir().unwrap();
            let a = test_agent(a_dir.path(), "alpha").await;
            let b = test_agent(b_dir.path(), "beta").await;
            let vault = a.with(|s| s.create_vault("personal")).unwrap();
            let a_id = a.with(|s| Ok(*s.id.as_bytes())).unwrap();
            let b_id = b.with(|s| Ok(*s.id.as_bytes())).unwrap();

            let (a_conv, a_client) = test_conv(true);
            let (b_conv, b_client) = test_conv(joiner_accepts);
            let inviter = ExistingDevice {
                agent: &a,
                conv: &a_conv,
                confirm: true,
                vault,
                ticket_addr: b.with(|s| Ok(s.own_addr())).unwrap(),
                added: Mutex::default(),
            };
            let joiner = NewDevice {
                agent: &b,
                conv: &b_conv,
                confirm: true,
                offer: Mutex::default(),
                joined: Mutex::default(),
            };

            let (left, right) = tokio::io::duplex(64 * 1024);
            let dial = PairingStream::new(a_id, b_id, [7; 32], [9; 32], false);
            let listen = PairingStream::new(b_id, a_id, [7; 32], [9; 32], true);
            let inviter_ref = &inviter;
            let joiner_ref = &joiner;

            let (invited, joined) = tokio::join!(
                async move {
                    let (mut ar, mut at) = tokio::io::split(left);
                    dial.invite(&mut at, &mut ar, 1 << 20, inviter_ref).await
                },
                async move {
                    let (mut br, mut bt) = tokio::io::split(right);
                    listen
                        .prove(&mut br)
                        .await?
                        .complete(&mut bt, &mut br, 1 << 20, joiner_ref)
                        .await
                }
            );

            let Event::Pairing {
                code: a_code,
                device,
            } = read_event(a_client).await
            else {
                panic!("expected Pairing event");
            };
            let Event::Joining {
                code: b_code,
                vault: vault_name,
                inviter: inviter_info,
            } = read_event(b_client).await
            else {
                panic!("expected Joining event");
            };
            assert_eq!(a_code, b_code);
            assert_eq!(device, short(&b_id));
            assert_eq!(vault_name, "personal");
            assert_eq!(inviter_info.name.as_deref(), Some("alpha"));

            if joiner_accepts {
                invited.unwrap();
                joined.unwrap();
                assert!(inviter.added.lock().unwrap().is_some());
                assert!(joiner.joined.lock().unwrap().is_some());
                assert!(b.with(|s| Ok(s.vaults.contains_key(&vault))).unwrap());
            } else {
                assert!(invited.is_err());
                assert!(matches!(joined, Err(NetError::PairingDeclined)));
                assert!(joiner.offer.lock().unwrap().is_none());
                assert!(inviter.added.lock().unwrap().is_none());
                assert!(!b.with(|s| Ok(s.vaults.contains_key(&vault))).unwrap());
                assert_eq!(
                    a.with(|s| Ok(s.vault(&vault).members().count())).unwrap(),
                    1
                );
            }

            a.lock().await;
            b.lock().await;
        }
    }

    #[tokio::test]
    async fn confirm_declines_invalid_offer_and_welcome_refuses_removed_device() {
        struct BadInviter(Vec<u8>);
        impl Inviter for BadInviter {
            async fn confirm(&self, _: &PairingContext) -> bool {
                true
            }
            async fn offer(&self, _: &PairingContext) -> Result<Vec<u8>, HandlerError> {
                Ok(self.0.clone())
            }
            async fn welcome(
                &self,
                _: &PairingContext,
                _: Vec<u8>,
            ) -> Result<Vec<Blob>, HandlerError> {
                unreachable!("joiner must decline before sending join")
            }
        }

        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = test_agent(a_dir.path(), "alpha").await;
        let b = test_agent(b_dir.path(), "beta").await;
        let vault = a.with(|s| s.create_vault("personal")).unwrap();
        let a_id = a.with(|s| Ok(*s.id.as_bytes())).unwrap();
        let b_id = b.with(|s| Ok(*s.id.as_bytes())).unwrap();
        let b_dev = DeviceId::from_bytes(b_id);

        // Admit b into personal so b already holds it.
        let valid_offer = a.with(|s| offer(s, vault, None)).unwrap();
        let parsed_offer: Offer = serde_json::from_slice(&valid_offer).unwrap();
        let join = b
            .with(|s| join_blob(s, DeviceId::from_bytes(a_id), &parsed_offer, None))
            .unwrap();
        let (blobs, _) = a.with(|s| welcome(s, vault, b_dev, &join, None)).unwrap();
        b.with(|s| apply_welcome(s, DeviceId::from_bytes(a_id), &parsed_offer, blobs))
            .unwrap();

        // Remove b on a; a hostile b trying to re-pair into the same vault is
        // refused by `welcome` and receives no entries.
        a.with(|s| s.update(vault, |v, key| Ok(v.remove(key, b_dev)?)))
            .unwrap();
        let err = a
            .with(|s| welcome(s, vault, b_dev, &join, None))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "that device was removed from personal and can't rejoin it"
        );

        // Bad offers (malformed JSON, ANSI/invalid vault name, bad vault id, or
        // an already-held vault) are declined in `NewDevice::confirm` even when
        // `confirm: false`.
        let other = a.with(|s| s.create_vault("work")).unwrap();
        let ansi_offer = serde_json::to_vec(&Offer {
            v: 1,
            vault: other.to_string(),
            vault_name: "work\x1b[31m".into(),
            name: "alpha".into(),
            addr: None,
        })
        .unwrap();
        let bad_id_offer = serde_json::to_vec(&Offer {
            v: 1,
            vault: "not-a-vault-id".into(),
            vault_name: "work".into(),
            name: "alpha".into(),
            addr: None,
        })
        .unwrap();
        for bad in [b"not-json".to_vec(), ansi_offer, bad_id_offer, valid_offer] {
            let (b_conv, _b_client) = test_conv(true);
            let joiner = NewDevice {
                agent: &b,
                conv: &b_conv,
                confirm: false,
                offer: Mutex::default(),
                joined: Mutex::default(),
            };
            let inviter = BadInviter(bad);
            let (left, right) = tokio::io::duplex(64 * 1024);
            let dial = PairingStream::new(a_id, b_id, [7; 32], [9; 32], false);
            let listen = PairingStream::new(b_id, a_id, [7; 32], [9; 32], true);
            let (_, joined) = tokio::join!(
                async move {
                    let (mut ar, mut at) = tokio::io::split(left);
                    dial.invite(&mut at, &mut ar, 1 << 20, &inviter).await
                },
                async move {
                    let (mut br, mut bt) = tokio::io::split(right);
                    listen
                        .prove(&mut br)
                        .await?
                        .complete(&mut bt, &mut br, 1 << 20, &joiner)
                        .await
                }
            );
            assert!(matches!(joined, Err(NetError::PairingDeclined)));
        }

        // Locked agent also declines in `NewDevice::confirm`.
        b.lock().await;
        let work_offer = a.with(|s| offer(s, other, None)).unwrap();
        let (b_conv, _b_client) = test_conv(true);
        let joiner = NewDevice {
            agent: &b,
            conv: &b_conv,
            confirm: false,
            offer: Mutex::default(),
            joined: Mutex::default(),
        };
        let inviter = BadInviter(work_offer);
        let (left, right) = tokio::io::duplex(64 * 1024);
        let dial = PairingStream::new(a_id, b_id, [7; 32], [9; 32], false);
        let listen = PairingStream::new(b_id, a_id, [7; 32], [9; 32], true);
        let (_, joined) = tokio::join!(
            async move {
                let (mut ar, mut at) = tokio::io::split(left);
                dial.invite(&mut at, &mut ar, 1 << 20, &inviter).await
            },
            async move {
                let (mut br, mut bt) = tokio::io::split(right);
                listen
                    .prove(&mut br)
                    .await?
                    .complete(&mut bt, &mut br, 1 << 20, &joiner)
                    .await
            }
        );
        assert!(matches!(joined, Err(NetError::PairingDeclined)));

        a.lock().await;
    }
}
