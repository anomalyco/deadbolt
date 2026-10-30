//! Pairing blobs and the [`Joiner`]/[`Inviter`] implementations.
//!
//! ```text
//! offer   = JSON Offer   {vault id, vault name, inviter name + address}
//! join    = JSON JoinBlob {consent signature (bound to the inviter), device name + address}
//! welcome = [JSON WelcomeMeta {hints about the other members}, entry*]   (genesis first)
//! ```
//!
//! Both run only after the two devices proved the code to each other
//! (`deadbolt_net::pair`). A device that isn't set up joins on a node of its
//! own with a fresh device key, and keeps that key and the vault it received
//! in memory ([`Fresh`]) until the client sends a passphrase; only then is the
//! store created. The inviter commits the `Add` before it sends the welcome, so
//! a join abandoned at the passphrase leaves a member that was never seen,
//! which `devices remove` takes out like any other.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use deadbolt_core::{DeviceId, DeviceSecret, VaultId};
use deadbolt_net::application;
pub(super) use deadbolt_net::application::{Offer, Welcomed};
use deadbolt_net::{
    Blob, HandlerError, Inviter, Joiner, Node, NodeConfig, PairingCode, PairingContext,
    PairingOptions, PeerId, SyncHandler,
};
use deadbolt_store::KdfParams;
use tracing::info;

use super::session::{Addr, Loaded, clean_name};
use super::{Agent, Conversation};
use crate::protocol::{DeviceInfo, Event, Reply, Secret, VaultInfo};

fn handler_error(error: anyhow::Error) -> HandlerError {
    format!("{error:#}").into()
}

pub(super) fn offer(
    s: &Loaded,
    vault: VaultId,
    device: &DeviceId,
    addr: Option<Addr>,
) -> Result<Vec<u8>> {
    Ok(application::offer(s, vault, device, addr)?)
}

pub(super) fn read_offer(offer: &[u8]) -> Result<(Offer, VaultId)> {
    application::read_offer(offer).context("reading the offer")
}

pub(super) fn join_blob(
    secret: &DeviceSecret,
    device_name: &str,
    inviter: DeviceId,
    vault: &VaultId,
    addr: Option<Addr>,
) -> Result<Vec<u8>> {
    Ok(application::join_blob(
        secret,
        device_name,
        inviter,
        vault,
        addr,
    )?)
}

pub(super) fn welcome(
    s: &mut Loaded,
    vault: VaultId,
    device: DeviceId,
    join: &[u8],
    fallback_addr: Option<Addr>,
) -> Result<(Vec<Blob>, DeviceInfo)> {
    let blobs = application::welcome(s, vault, device, join, fallback_addr)?;
    Ok((blobs, s.device_info(&device, &HashSet::new())))
}

fn inviter_info(welcomed: &Welcomed) -> DeviceInfo {
    DeviceInfo {
        id: welcomed.inviter.to_string(),
        name: Some(clean_name(&welcomed.inviter_name)).filter(|n| !n.is_empty()),
        this: false,
        connected: true,
        last_seen: None,
    }
}

pub(super) fn verify_welcome(
    device: &DeviceId,
    inviter: DeviceId,
    offer: Offer,
    welcome: Vec<Blob>,
) -> Result<Welcomed> {
    Ok(application::verify_welcome(
        device, inviter, offer, welcome,
    )?)
}

/// Stores a checked welcome.
pub(super) fn adopt(s: &mut Loaded, welcomed: Welcomed) -> Result<VaultInfo> {
    let Welcomed {
        vault,
        inviter,
        inviter_name,
        inviter_addr,
        peers,
    } = welcomed;
    s.learn(&inviter, Some(&inviter_name), inviter_addr, peers);
    let id = vault.id();
    s.add_vault(vault)?;
    Ok(s.vault_info(&id))
}

#[cfg(test)]
pub(super) fn apply_welcome(
    s: &mut Loaded,
    inviter: DeviceId,
    offer: Offer,
    welcome: Vec<Blob>,
) -> Result<VaultInfo> {
    let welcomed = verify_welcome(&s.id, inviter, offer, welcome)?;
    adopt(s, welcomed)
}

/// A device that joined before it was set up: its key, its name and the
/// vault it received, held in memory until a passphrase arrives. Dropping it
/// discards them.
pub(super) struct Fresh {
    secret: DeviceSecret,
    name: String,
    welcomed: Welcomed,
}

impl Fresh {
    /// Creates the store with this key and stores the vault. Blocking (Argon2).
    pub(super) fn persist(
        self,
        dir: &Path,
        passphrase: &Secret,
        params: KdfParams,
    ) -> Result<(Loaded, VaultInfo)> {
        let mut loaded = Loaded::setup_with(
            dir,
            passphrase.expose().as_bytes(),
            &self.name,
            params,
            self.secret,
        )?;
        let vault = adopt(&mut loaded, self.welcomed)?;
        Ok((loaded, vault))
    }
}

/// The node of a device that isn't set up refuses every sync.
struct NoSync;

impl SyncHandler for NoSync {
    async fn heads(&self, _: PeerId) -> Result<Vec<u8>, HandlerError> {
        Err("this device is not set up".into())
    }
    async fn missing_for(&self, _: PeerId, _: Vec<u8>) -> Result<Vec<Blob>, HandlerError> {
        Err("this device is not set up".into())
    }
    async fn receive(&self, _: PeerId, _: Vec<Blob>) -> Result<(), HandlerError> {
        Err("this device is not set up".into())
    }
}

/// Where the joining device keeps what it gets.
enum Home<'a> {
    /// The unlocked store: the welcome is stored as it arrives.
    Store(&'a Arc<Agent>),
    /// Nothing yet: the device key the node runs on and this device's name.
    Memory(Box<Memory>),
}

struct Memory {
    secret: DeviceSecret,
    name: String,
    addr: Addr,
}

struct NewDevice<'a> {
    home: Home<'a>,
    offer: Mutex<Option<Offer>>,
    welcomed: Mutex<Option<Welcomed>>,
    /// With a store: the vault as stored, and the device that invited this one.
    joined: Mutex<Option<(VaultInfo, DeviceInfo)>>,
}

impl Joiner for NewDevice<'_> {
    async fn join(&self, ctx: &PairingContext, offer: Vec<u8>) -> Result<Vec<u8>, HandlerError> {
        let (offer, vault) = read_offer(&offer).map_err(handler_error)?;
        let inviter = DeviceId::from_bytes(ctx.remote);
        let join = match &self.home {
            Home::Store(agent) => agent.with(|s| {
                if s.contains_vault(&vault) {
                    bail!("this device already holds vault {}", offer.vault_name);
                }
                join_blob(
                    &s.secret,
                    &s.meta.device_name,
                    inviter,
                    &vault,
                    Some(s.own_addr()),
                )
            }),
            Home::Memory(memory) => join_blob(
                &memory.secret,
                &memory.name,
                inviter,
                &vault,
                Some(memory.addr.clone()),
            ),
        }
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
        let device = DeviceId::from_bytes(ctx.local);
        let inviter = DeviceId::from_bytes(ctx.remote);
        let welcomed = verify_welcome(&device, inviter, offer, welcome).map_err(handler_error)?;
        match &self.home {
            Home::Store(agent) => {
                let inviter = inviter_info(&welcomed);
                let vault = agent
                    .with(|s| {
                        let info = adopt(s, welcomed)?;
                        agent.refresh(s);
                        Ok(info)
                    })
                    .map_err(handler_error)?;
                *self.joined.lock().unwrap_or_else(|e| e.into_inner()) = Some((vault, inviter));
            }
            Home::Memory(_) => {
                *self.welcomed.lock().unwrap_or_else(|e| e.into_inner()) = Some(welcomed);
            }
        }
        Ok(())
    }
}

/// What a failed join tells the person at the new device.
fn explain_join(error: deadbolt_net::Error) -> anyhow::Error {
    use deadbolt_net::Error;
    match error {
        Error::PairingExpired => {
            anyhow!("the code expired (codes work for 5 minutes); run `deadbolt join` again")
        }
        Error::PairingCodeMismatch => anyhow!(
            "pairing failed: a device tried a wrong code, so this one no longer works. If that \
             wasn't you, someone may be trying to get in. Run `deadbolt join` again"
        ),
        Error::Remote(message) => anyhow!("the other device refused: {message}"),
        other => other.into(),
    }
}

/// What a failed pair tells the person at the existing device.
fn explain_pair(error: deadbolt_net::Error) -> anyhow::Error {
    use deadbolt_net::Error;
    match error {
        Error::PairingNotFound => anyhow!(
            "no device is waiting for that code: check it, or run `deadbolt join` again on the \
             new device (codes work for 5 minutes)"
        ),
        Error::PairingCodeUsed => anyhow!(
            "pairing failed: that code was already used. If it wasn't you, someone else may \
             have used it: run `deadbolt join` again on the new device"
        ),
        Error::PairingCodeMismatch => {
            anyhow!(
                "pairing failed: the code didn't match; run `deadbolt join` again on the new device"
            )
        }
        Error::OwnCode => {
            anyhow!("that code is from this device; type it on a device that holds the vault")
        }
        Error::Remote(message) => anyhow!("the new device refused: {message}"),
        other => other.into(),
    }
}

async fn fresh_node(agent: &Agent, secret: &DeviceSecret) -> Result<Node> {
    let key = *secret.to_bytes();
    let config = if agent.local_net {
        NodeConfig::local_only(key)
    } else {
        NodeConfig::new(key)
    };
    Ok(Node::spawn(config, Arc::new(|_: &PeerId| false), NoSync).await?)
}

/// `deadbolt join`: show a code and wait for an existing device to pair.
pub async fn join(
    agent: &Arc<Agent>,
    conv: &Conversation,
    device_name: Option<String>,
    passphrase: Option<Secret>,
) -> Result<Reply> {
    let _pairing = agent
        .pairing
        .try_lock()
        .map_err(|_| anyhow!("another pairing is already running on this device"))?;
    let set_up = deadbolt_store::is_initialized(&agent.paths.data);
    // A locked device fails here, before a code shows, so the client can
    // unlock and ask again.
    let (node, home) = if set_up {
        (agent.with(|s| Ok(s.node.clone()))?, None)
    } else {
        if passphrase.as_ref().is_some_and(|p| p.expose().is_empty()) {
            bail!("the passphrase cannot be empty");
        }
        let name = clean_name(&device_name.unwrap_or_else(|| crate::prompt::device_name(None)));
        if name.is_empty() {
            bail!("the device name cannot be empty");
        }
        let secret = DeviceSecret::generate();
        let node = fresh_node(agent, &secret).await?;
        (node.clone(), Some((node, secret, name)))
    };
    let code = PairingCode::generate()?;
    conv.event(Event::Code {
        code: code.to_string(),
    })
    .await?;
    let listener = node.start_pairing(&code, PairingOptions::default()).await?;
    let (fresh_node, home) = match home {
        None => (None, Home::Store(agent)),
        Some((node, secret, name)) => (
            Some(node.clone()),
            Home::Memory(Box::new(Memory {
                secret,
                name,
                addr: Addr::from_peer(node.addr()),
            })),
        ),
    };
    let device = NewDevice {
        home,
        offer: Mutex::default(),
        welcomed: Mutex::default(),
        joined: Mutex::default(),
    };
    let result = tokio::select! {
        result = listener.complete(&device) => result.map_err(explain_join),
        _ = conv.closed() => Err(anyhow!("cancelled")),
    };
    // A device that isn't set up needs its node only to pair.
    if let Some(node) = &fresh_node {
        node.shutdown().await;
    }
    result?;
    let NewDevice {
        home,
        welcomed,
        joined,
        ..
    } = device;
    let vault = match home {
        Home::Store(_) => {
            let (vault, inviter) = joined
                .into_inner()
                .unwrap_or_else(|e| e.into_inner())
                .ok_or_else(|| anyhow!("pairing finished without a vault"))?;
            #[expect(
                clippy::let_underscore_must_use,
                reason = "the vault is stored; the reply reports it even if the event can't go"
            )]
            let _ = conv
                .event(Event::Joined {
                    vault: vault.name.clone(),
                    inviter,
                    passphrase: false,
                })
                .await;
            vault
        }
        Home::Memory(memory) => {
            let Memory { secret, name, .. } = *memory;
            let welcomed = welcomed
                .into_inner()
                .unwrap_or_else(|e| e.into_inner())
                .ok_or_else(|| anyhow!("pairing finished without a vault"))?;
            let event = Event::Joined {
                vault: clean_name(welcomed.vault.name()),
                inviter: inviter_info(&welcomed),
                passphrase: passphrase.is_none(),
            };
            let fresh = Fresh {
                secret,
                name,
                welcomed,
            };
            let passphrase = match passphrase {
                Some(passphrase) => {
                    conv.event(event).await?;
                    passphrase
                }
                None => match conv.ask(event).await {
                    Some(answer) if answer.answer => answer
                        .passphrase
                        .ok_or_else(|| anyhow!("the answer carried no passphrase"))?,
                    _ => bail!("cancelled: nothing was saved on this device"),
                },
            };
            agent.setup_joined(fresh, passphrase).await?
        }
    };
    info!(vault = %vault.name, "joined vault");
    agent.sync_now.notify_one();
    Ok(Reply::Vault { vault })
}

struct ExistingDevice<'a> {
    agent: &'a Arc<Agent>,
    vault: VaultId,
    added: Mutex<Option<DeviceInfo>>,
}

impl Inviter for ExistingDevice<'_> {
    async fn offer(&self, ctx: &PairingContext) -> Result<Vec<u8>, HandlerError> {
        let device = DeviceId::from_bytes(ctx.remote);
        self.agent
            .with_data(|s| offer(s, self.vault, &device, Some(s.own_addr())))
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
                let (blobs, info) = welcome(s, self.vault, device, &join, None)?;
                self.agent.refresh(s);
                Ok((blobs, info))
            })
            .map_err(handler_error)?;
        *self.added.lock().unwrap_or_else(|e| e.into_inner()) = Some(info);
        Ok(blobs)
    }
}

/// `deadbolt pair`: admit the device showing `code` into a vault.
pub async fn pair(
    agent: &Arc<Agent>,
    conv: &Conversation,
    code: String,
    vault: Option<String>,
) -> Result<Reply> {
    let code: PairingCode = code.parse()?;
    let _pairing = agent
        .pairing
        .try_lock()
        .map_err(|_| anyhow!("another pairing is already running on this device"))?;
    tokio::select! {
        result = agent.wait_ready() => result?,
        _ = conv.closed() => bail!("cancelled"),
    }
    let (node, vault) = agent.with_data(|s| {
        let id = s.resolve(vault.as_deref())?;
        let held = s.vault(&id);
        if !held.is_member(&s.id) {
            bail!("this device is no longer a member of {}", held.name());
        }
        Ok((s.node.clone(), id))
    })?;
    let inviter = ExistingDevice {
        agent,
        vault,
        added: Mutex::default(),
    };
    // A debug build's tests look for a missing device only briefly.
    let options = PairingOptions {
        find_timeout: crate::config::test_env("DEADBOLT_TEST_PAIR_FIND_SECS")
            .and_then(|secs| secs.parse().ok())
            .map_or(
                deadbolt_net::DEFAULT_FIND_TIMEOUT,
                std::time::Duration::from_secs,
            ),
        ..PairingOptions::default()
    };
    tokio::select! {
        result = node.pair(&code, options, &inviter) => {
            result.map_err(explain_pair)?;
        }
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
    use deadbolt_net::{Error as NetError, PairingStream};
    use tokio::sync::{mpsc, watch};

    const KDF: KdfParams = KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    async fn test_agent(dir: &std::path::Path, name: &str) -> Arc<Agent> {
        let loaded = Loaded::setup(dir, b"test", name, KDF).unwrap();
        let agent = Agent::new(super::super::tests::test_paths(dir), true, KDF);
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

    fn code() -> PairingCode {
        "violin-garden-tiger-lamp-zoo".parse().unwrap()
    }

    /// Runs the pairing exchange over an in-memory stream.
    async fn exchange(
        inviter: &impl Inviter,
        inviter_id: PeerId,
        joiner: &impl Joiner,
        joiner_id: PeerId,
    ) -> (deadbolt_net::Result<()>, deadbolt_net::Result<()>) {
        let (left, right) = tokio::io::duplex(64 * 1024);
        let dial = PairingStream::new(
            inviter_id,
            joiner_id,
            &code(),
            [5; 32],
            [9; 32],
            false,
            [1; 32],
        );
        let listen = PairingStream::new(
            joiner_id,
            inviter_id,
            &code(),
            [5; 32],
            [9; 32],
            true,
            [2; 32],
        );
        tokio::join!(
            async move {
                let (mut r, mut w) = tokio::io::split(left);
                dial.invite(&mut w, &mut r, 1 << 20, inviter)
                    .await
                    .map(|_| ())
            },
            async move {
                let (mut r, mut w) = tokio::io::split(right);
                listen
                    .prove(&mut w, &mut r)
                    .await?
                    .complete(&mut w, &mut r, 1 << 20, joiner)
                    .await
                    .map(|_| ())
            }
        )
    }

    fn id(agent: &Agent) -> PeerId {
        agent.with(|s| Ok(*s.id.as_bytes())).unwrap()
    }

    #[tokio::test]
    async fn a_set_up_device_joins_and_stores_the_vault() {
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = test_agent(a_dir.path(), "alpha").await;
        let b = test_agent(b_dir.path(), "beta").await;
        let vault = a.with(|s| s.create_vault("personal")).unwrap();
        let inviter = ExistingDevice {
            agent: &a,
            vault,
            added: Mutex::default(),
        };
        let joiner = NewDevice {
            home: Home::Store(&b),
            offer: Mutex::default(),
            welcomed: Mutex::default(),
            joined: Mutex::default(),
        };
        let (invited, joined) = exchange(&inviter, id(&a), &joiner, id(&b)).await;
        invited.unwrap();
        joined.unwrap();
        assert_eq!(
            inviter
                .added
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .name
                .as_deref(),
            Some("beta")
        );
        let (info, by) = joiner.joined.lock().unwrap().take().unwrap();
        assert_eq!(info.name, "personal");
        assert_eq!(by.name.as_deref(), Some("alpha"));
        assert!(b.with(|s| Ok(s.vaults.contains_key(&vault))).unwrap());
        a.lock().await;
        b.lock().await;
    }

    /// Before its passphrase, a new device holds its key and the vault in
    /// memory only: nothing is on disk until `persist`, and dropping the join
    /// leaves nothing behind.
    #[tokio::test]
    async fn a_new_device_keeps_the_vault_in_memory_until_its_passphrase() {
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = test_agent(a_dir.path(), "alpha").await;
        let vault = a.with(|s| s.create_vault("personal")).unwrap();
        for keep in [false, true] {
            let secret = DeviceSecret::generate();
            let b_id = *secret.device_id().as_bytes();
            let inviter = ExistingDevice {
                agent: &a,
                vault,
                added: Mutex::default(),
            };
            let joiner = NewDevice {
                home: Home::Memory(Box::new(Memory {
                    secret,
                    name: "beta".into(),
                    addr: Addr::default(),
                })),
                offer: Mutex::default(),
                welcomed: Mutex::default(),
                joined: Mutex::default(),
            };
            let (invited, joined) = exchange(&inviter, id(&a), &joiner, b_id).await;
            invited.unwrap();
            joined.unwrap();
            let store = b_dir.path().join(if keep { "kept" } else { "dropped" });
            assert!(!store.exists());
            let NewDevice { home, welcomed, .. } = joiner;
            let Home::Memory(memory) = home else {
                unreachable!()
            };
            let Memory { secret, name, .. } = *memory;
            let fresh = Fresh {
                secret,
                name,
                welcomed: welcomed.into_inner().unwrap().unwrap(),
            };
            if keep {
                let (loaded, info) = fresh.persist(&store, &Secret::new("pass"), KDF).unwrap();
                assert_eq!(info.name, "personal");
                assert_eq!(loaded.id.as_bytes(), &b_id);
                drop(loaded);
                let reopened = Loaded::open(&store, b"pass").unwrap();
                assert!(reopened.vaults.contains_key(&vault));
                assert_eq!(reopened.meta.device_name, "beta");
                assert_eq!(
                    reopened
                        .peer(&DeviceId::from_bytes(id(&a)))
                        .unwrap()
                        .name
                        .as_deref(),
                    Some("alpha")
                );
            } else {
                drop(fresh);
                assert!(!store.exists());
                // The inviter admitted it; it shows as never seen until removed.
                let device = DeviceId::from_bytes(b_id);
                assert!(a.with(|s| Ok(s.vault(&vault).is_member(&device))).unwrap());
                a.with(|s| s.update(vault, |v, key| Ok(v.remove(key, device)?)))
                    .unwrap();
            }
        }
        a.lock().await;
    }

    /// A set-up device whose earlier join was admitted but never stored on its
    /// side (it crashed, or was cancelled after the inviter committed) can pair
    /// again; a removed one can't.
    #[tokio::test]
    async fn an_unfinished_join_can_be_retried_but_a_removed_device_cannot_rejoin() {
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = test_agent(a_dir.path(), "alpha").await;
        let b = test_agent(b_dir.path(), "beta").await;
        let vault = a.with(|s| s.create_vault("personal")).unwrap();
        let (a_id, b_id) = (id(&a), id(&b));
        let b_dev = DeviceId::from_bytes(b_id);

        // The inviter commits b's Add, but b never stores the welcome.
        let join = b
            .with(|s| join_blob(&s.secret, "beta", DeviceId::from_bytes(a_id), &vault, None))
            .unwrap();
        a.with(|s| welcome(s, vault, b_dev, &join, None)).unwrap();
        let entries = a.with(|s| Ok(s.vault(&vault).entries().len())).unwrap();

        let inviter = ExistingDevice {
            agent: &a,
            vault,
            added: Mutex::default(),
        };
        let joiner = NewDevice {
            home: Home::Store(&b),
            offer: Mutex::default(),
            welcomed: Mutex::default(),
            joined: Mutex::default(),
        };
        let (invited, joined) = exchange(&inviter, a_id, &joiner, b_id).await;
        invited.unwrap();
        joined.unwrap();
        assert!(b.with(|s| Ok(s.vaults.contains_key(&vault))).unwrap());
        // No second Add.
        assert_eq!(
            a.with(|s| Ok(s.vault(&vault).entries().len())).unwrap(),
            entries
        );

        a.with(|s| s.update(vault, |v, key| Ok(v.remove(key, b_dev)?)))
            .unwrap();
        let err = a
            .with(|s| welcome(s, vault, b_dev, &join, None))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "that device was removed from personal and can't rejoin it"
        );
        let inviter = ExistingDevice {
            agent: &a,
            vault,
            added: Mutex::default(),
        };
        let other = test_agent(tempfile::tempdir().unwrap().path(), "gamma").await;
        let joiner = NewDevice {
            home: Home::Store(&other),
            offer: Mutex::default(),
            welcomed: Mutex::default(),
            joined: Mutex::default(),
        };
        // The removed key pairing again is refused before any offer goes out.
        let (invited, _) = exchange(&inviter, a_id, &joiner, b_id).await;
        assert!(
            matches!(&invited, Err(NetError::Handler(m)) if m.to_string().contains("removed")),
            "{invited:?}"
        );
        a.lock().await;
        b.lock().await;
        other.lock().await;
    }

    #[tokio::test]
    async fn bad_offers_are_refused_before_consent() {
        struct BadInviter(Vec<u8>);
        impl Inviter for BadInviter {
            async fn offer(&self, _: &PairingContext) -> Result<Vec<u8>, HandlerError> {
                Ok(self.0.clone())
            }
            async fn welcome(
                &self,
                _: &PairingContext,
                _: Vec<u8>,
            ) -> Result<Vec<Blob>, HandlerError> {
                unreachable!("the joiner must refuse before sending its consent")
            }
        }

        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = test_agent(a_dir.path(), "alpha").await;
        let b = test_agent(b_dir.path(), "beta").await;
        let held = b.with(|s| s.create_vault("mine")).unwrap();
        let other = a.with(|s| s.create_vault("work")).unwrap();
        let named = |vault: String, name: &str| {
            serde_json::to_vec(&Offer {
                v: 2,
                vault,
                vault_name: name.into(),
                name: "alpha".into(),
                addr: None,
            })
            .unwrap()
        };
        for bad in [
            b"not-json".to_vec(),
            named(other.to_string(), "work\x1b[31m"),
            named("not-a-vault-id".into(), "work"),
            named(held.to_string(), "mine"),
        ] {
            let joiner = NewDevice {
                home: Home::Store(&b),
                offer: Mutex::default(),
                welcomed: Mutex::default(),
                joined: Mutex::default(),
            };
            let (_, joined) = exchange(&BadInviter(bad), id(&a), &joiner, id(&b)).await;
            assert!(matches!(joined, Err(NetError::Handler(_))), "{joined:?}");
        }
        a.lock().await;
        b.lock().await;
    }

    /// The agent's side of a join, through a conversation: the passphrase is
    /// asked for only after pairing, and hanging up then discards everything.
    #[tokio::test]
    async fn a_join_waits_for_its_passphrase_and_hanging_up_discards_it() {
        let dir = tempfile::tempdir().unwrap();
        let agent = Agent::new(super::super::tests::test_paths(dir.path()), true, KDF);
        let (socket, _client) = tokio::net::UnixStream::pair().unwrap();
        let (_, write) = socket.into_split();
        let (closed, closed_rx) = watch::channel(false);
        let (_answers, answers) = mpsc::channel(1);
        let conv = Conversation {
            write: tokio::sync::Mutex::new(write),
            answers: tokio::sync::Mutex::new(answers),
            closed: closed_rx,
        };
        closed.send_replace(true);
        let error = join(&agent, &conv, Some("beta".into()), None)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "cancelled");
        assert!(!deadbolt_store::is_initialized(dir.path()));
    }
}
