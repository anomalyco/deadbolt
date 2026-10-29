//! First-run joining, like the CLI's Fresh: no store until admission and a
//! local passphrase. The worker owns the listener; terminating it cancels join.

use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
    time::Duration,
};

use deadbolt_core::{DeviceId, DeviceSecret, Entry};
use deadbolt_net::application::{self, Addr, Offer, State, Welcomed};
use deadbolt_net::{
    Blob, HandlerError, Joiner, Node, NodeConfig, PairingCode, PairingContext, PairingOptions,
    PeerId, SyncHandler,
};
use deadbolt_store::KdfParams;
use n0_future::task::JoinHandle;
use serde_json::{Value, json};

use crate::{
    Error, Loaded, Result, backend, items_changed, storage_exists, storage_publish, take_secret,
    text,
};

thread_local! {
    static JOIN: RefCell<Joining> = const { RefCell::new(Joining {
        generation: 0,
        phase: Phase::Idle,
        task: None,
    }) };
}

struct Joining {
    generation: u64,
    phase: Phase,
    task: Option<Task>,
}

struct Task(JoinHandle<()>);

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

enum Phase {
    Idle,
    Starting,
    Waiting(String),
    Admitted(Arc<Fresh>),
    Finishing(Arc<Fresh>),
    Failed(String),
}

struct Fresh {
    secret: DeviceSecret,
    welcomed: Welcomed,
}

pub(super) fn require_idle() -> Result<()> {
    JOIN.with(|slot| match slot.borrow().phase {
        Phase::Idle | Phase::Failed(_) => Ok(()),
        _ => Err(Error::Protocol("Finish or cancel the current join first")),
    })
}

pub(super) fn status() -> Value {
    JOIN.with(|slot| match &slot.borrow().phase {
        Phase::Idle => json!({"type":"device-join-status", "phase":"idle"}),
        Phase::Starting => json!({"type":"device-join-status", "phase":"waiting"}),
        Phase::Waiting(code) => {
            json!({"type":"device-join-status", "phase":"waiting", "code":code})
        }
        Phase::Admitted(fresh) | Phase::Finishing(fresh) => {
            json!({"type":"device-join-status", "phase":"admitted", "vault":fresh.welcomed.vault.name()})
        }
        Phase::Failed(message) => {
            json!({"type":"device-join-status", "phase":"failed", "message":message})
        }
    })
}

fn name(body: &Value) -> Result<String> {
    let name = application::clean_name(text(body, "deviceName")?);
    if name.is_empty() {
        return Err(Error::Protocol("A device name is required"));
    }
    Ok(name)
}

// Do not let an old asynchronous completion publish into a newer join.
fn set_phase(generation: u64, phase: Phase) {
    JOIN.with(|slot| {
        let mut join = slot.borrow_mut();
        if join.generation == generation {
            join.phase = phase;
        }
    });
}

pub(super) async fn start(body: &Value) -> Result<Value> {
    require_idle()?;
    if crate::node().is_ok() || crate::state().with(|_| Ok(())).is_ok() {
        return Err(Error::Protocol("This browser already has a vault"));
    }
    let name = name(body)?;
    // Reserve before the first await. Setup requests are also serialized by
    // the offscreen document, but status remains available during setup.
    let generation = JOIN.with(|slot| {
        let mut join = slot.borrow_mut();
        join.generation = join.generation.checked_add(1).ok_or(Error::State)?;
        join.task = None;
        join.phase = Phase::Starting;
        Ok::<_, Error>(join.generation)
    })?;
    let result = listen(name, generation).await;
    if let Err(error) = &result {
        set_phase(generation, Phase::Failed(explain(error)));
    }
    result
}

async fn listen(name: String, generation: u64) -> Result<Value> {
    if storage_exists()
        .await
        .map_err(|_| Error::Protocol("Cannot read browser storage"))?
        .as_bool()
        == Some(true)
    {
        return Err(Error::Protocol(
            "This browser already has a vault; unlock it instead",
        ));
    }
    let secret = DeviceSecret::generate();
    let code = PairingCode::generate()?;
    let mut config = NodeConfig::new(*secret.to_bytes());
    config.portmapper = false;
    let node = Node::spawn(config, Arc::new(|_: &PeerId| false), NoSync).await?;
    if !node.online(Duration::from_secs(20)).await {
        node.shutdown().await;
        return Err(Error::Protocol(
            "Cannot reach an iroh relay; check your connection and try again",
        ));
    }
    let listener = match node.start_pairing(&code, PairingOptions::default()).await {
        Ok(listener) => listener,
        Err(error) => {
            node.shutdown().await;
            return Err(error.into());
        }
    };
    let device = NewDevice {
        secret,
        name,
        addr: Addr::from_peer(node.addr()),
        offer: Mutex::new(None),
        welcomed: Mutex::new(None),
    };
    let code = code.to_string();
    set_phase(generation, Phase::Waiting(code.clone()));
    let task = n0_future::task::spawn(async move {
        let result = listener.complete(&device).await;
        node.shutdown().await;
        let fresh = result.map_err(Error::from).and_then(|_| {
            let welcomed = device
                .welcomed
                .into_inner()
                .map_err(|_| Error::State)?
                .ok_or(Error::Protocol("Pairing finished without a vault"))?;
            Ok(Fresh {
                secret: device.secret,
                welcomed,
            })
        });
        let phase = match fresh {
            Ok(fresh) => Phase::Admitted(Arc::new(fresh)),
            Err(error) => Phase::Failed(explain(&error)),
        };
        set_phase(generation, phase);
    });
    JOIN.with(|slot| slot.borrow_mut().task = Some(Task(task)));
    Ok(json!({"type":"device-join-start", "code":code, "phase":"waiting"}))
}

fn explain(error: &Error) -> String {
    match error {
        Error::Net(deadbolt_net::Error::PairingExpired) =>
            "The code expired (codes work for 5 minutes). Start joining again.".into(),
        Error::Net(deadbolt_net::Error::PairingCodeMismatch) =>
            "A device tried a wrong code, so this code no longer works. If that wasn't you, someone may be trying to get in. Start joining again.".into(),
        Error::Net(deadbolt_net::Error::Remote(message)) =>
            format!("The other device refused: {message}"),
        _ => error.to_string(),
    }
}

pub(super) async fn finish(body: &mut Value) -> Result<Value> {
    let name = name(body)?;
    let passphrase = take_secret(body, "passphrase")?;
    if passphrase.is_empty() {
        return Err(Error::Protocol("The passphrase cannot be empty"));
    }
    let (generation, fresh) = JOIN.with(|slot| {
        let mut join = slot.borrow_mut();
        let Phase::Admitted(fresh) = &join.phase else {
            return Err(Error::Protocol(
                "Wait for admission before setting a passphrase",
            ));
        };
        let fresh = fresh.clone();
        join.phase = Phase::Finishing(fresh.clone());
        Ok((join.generation, fresh))
    })?;
    // Preserve the in-memory welcome for a retry if writing the pending file
    // fails. Once published, failures must be recovered through normal unlock,
    // never by initializing over that store.
    let mut published = false;
    let result = async {
        let store = deadbolt_store::init_with_backend(
            backend(true).await?,
            passphrase.as_bytes(),
            *fresh.secret.to_bytes(),
            KdfParams::DEFAULT,
        )?;
        let entries: Vec<_> = fresh
            .welcomed
            .vault
            .entries()
            .into_iter()
            .map(Entry::encode)
            .collect();
        store.append_batch(entries.iter().map(|entry| entry.as_slice()))?;
        let mut loaded = Loaded::open(store)?;
        loaded
            .store
            .meta_set("extension/device-name", &serde_json::to_vec(&name)?)?;
        loaded.learn(
            &fresh.welcomed.inviter,
            &fresh.welcomed.inviter_name,
            fresh.welcomed.inviter_addr.clone(),
            fresh.welcomed.peers.clone(),
        )?;
        drop(loaded);
        storage_publish()
            .await
            .map_err(|_| Error::Protocol("Cannot publish joined browser storage"))?;
        published = true;
        let store =
            deadbolt_store::unlock_with_backend(backend(false).await?, passphrase.as_bytes())?;
        crate::start(store, None).await?;
        // The vault came in the welcome, but the inviter hasn't heard from
        // this device since: until its first sync it lists it as never seen.
        // Give that sync a moment, so joined means the other device knows.
        n0_future::time::timeout(Duration::from_secs(10), async {
            while !crate::state().with(|s| Ok(s.ready)).unwrap_or(true) {
                n0_future::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_default();
        Ok(())
    }
    .await;
    match result {
        Ok(()) => {
            set_phase(generation, Phase::Idle);
            items_changed();
            Ok(json!({"type":"device-join-finish", "ok":true}))
        }
        Err(error) => {
            let phase = if published {
                Phase::Failed("The vault was saved. Unlock it to continue.".into())
            } else {
                Phase::Admitted(fresh)
            };
            set_phase(generation, phase);
            Err(error)
        }
    }
}

struct NoSync;

impl SyncHandler for NoSync {
    async fn heads(&self, _: PeerId) -> std::result::Result<Vec<u8>, HandlerError> {
        Err("this device is not set up".into())
    }
    async fn missing_for(
        &self,
        _: PeerId,
        _: Vec<u8>,
    ) -> std::result::Result<Vec<Blob>, HandlerError> {
        Err("this device is not set up".into())
    }
    async fn receive(&self, _: PeerId, _: Vec<Blob>) -> std::result::Result<(), HandlerError> {
        Err("this device is not set up".into())
    }
}

struct NewDevice {
    secret: DeviceSecret,
    name: String,
    addr: Addr,
    offer: Mutex<Option<Offer>>,
    welcomed: Mutex<Option<Welcomed>>,
}

impl Joiner for NewDevice {
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
        *self.offer.lock().map_err(|_| Error::State)? = Some(offer);
        Ok(blob)
    }

    async fn receive(
        &self,
        ctx: &PairingContext,
        welcome: Vec<Blob>,
    ) -> std::result::Result<(), HandlerError> {
        let offer = self
            .offer
            .lock()
            .map_err(|_| Error::State)?
            .take()
            .ok_or("no offer")?;
        let welcomed = application::verify_welcome(
            &self.secret.device_id(),
            DeviceId::from_bytes(ctx.remote),
            offer,
            welcome,
        )?;
        *self.welcomed.lock().map_err(|_| Error::State)? = Some(welcomed);
        Ok(())
    }
}
