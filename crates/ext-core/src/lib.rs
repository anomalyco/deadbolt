//! Phase-one standalone device, hosted only in an extension-owned worker.
//! JavaScript routes messages; core owns signatures, membership and secrets.
#![cfg(all(target_family = "wasm", target_os = "unknown"))]

mod wire;

use deadbolt_core::{DataOp, DeviceId, DeviceSecret, Entry, Field, FieldType, Item, ItemId, Vault};
use deadbolt_net::{Node, NodeConfig, PairingOptions, PeerAddr, PeerId};
use deadbolt_store::{KdfParams, OpfsBackend, Unlocked};
use n0_future::time::{Instant, sleep, timeout};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use wasm_bindgen::prelude::*;
use wire::{Addr, Handler};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Error>;

#[wasm_bindgen(inline_js = r#"
export async function storage_exists() {
    const root = await navigator.storage.getDirectory();
    try {
        const file = await root.getFileHandle("vault.redb");
        return (await file.getFile()).size > 0;
    } catch (error) {
        if (error.name === "NotFoundError") return false;
        throw error;
    }
}
async function absent(root) {
    try { await root.getFileHandle("vault.redb"); }
    catch (error) { if (error.name === "NotFoundError") return; throw error; }
    throw new Error("A vault already exists");
}
export async function storage_open(create) {
    const root = await navigator.storage.getDirectory();
    if (create) await absent(root);
    const file = await root.getFileHandle(create ? "vault.redb.pending" : "vault.redb", { create });
    const handle = await file.createSyncAccessHandle();
    // Only a pending initialization can be discarded. The exclusive handle
    // prevents two workers from initializing the pending file concurrently.
    if (create) handle.truncate(0);
    return handle;
}
export async function storage_publish() {
    const root = await navigator.storage.getDirectory();
    await absent(root);
    // Initialization and genesis are durable and the sync handle is closed
    // before the atomic rename makes the vault visible to future unlocks.
    await (await root.getFileHandle("vault.redb.pending")).move("vault.redb");
}
"#)]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn storage_exists() -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(catch)]
    async fn storage_open(create: bool) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(catch)]
    async fn storage_publish() -> std::result::Result<JsValue, JsValue>;
}

async fn backend(create: bool) -> Result<OpfsBackend> {
    let handle = storage_open(create)
        .await
        .map_err(|_| Error::Protocol("Cannot open exclusive browser storage"))?;
    OpfsBackend::new(handle).map_err(|error| Error::Store(error.into()))
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Unlock this extension's vault first")]
    Locked,
    #[error("The device state is unavailable")]
    State,
    #[error("{0}")]
    Protocol(&'static str),
    #[error(transparent)]
    Store(#[from] deadbolt_store::Error),
    #[error(transparent)]
    Core(#[from] deadbolt_core::Error),
    #[error(transparent)]
    Decode(#[from] deadbolt_core::DecodeError),
    #[error(transparent)]
    Net(#[from] deadbolt_net::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

struct Loaded {
    store: Unlocked,
    secret: DeviceSecret,
    vault: Vault,
    peers: BTreeMap<String, Addr>,
    addr: Option<Addr>,
    ready: bool,
}

impl Loaded {
    fn open(store: Unlocked) -> Result<Self> {
        let entries = store
            .iter_all()?
            .map(|bytes| Ok(Entry::decode(&bytes?)?))
            .collect::<Result<Vec<_>>>()?;
        let vault = Vault::load(entries)?;
        let peers = store
            .meta_get("extension/peers")?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?
            .unwrap_or_default();
        let secret = DeviceSecret::from_bytes(store.device_secret());
        let ready = vault.members().all(|peer| peer == secret.device_id());
        Ok(Self {
            store,
            secret,
            vault,
            peers,
            addr: None,
            ready,
        })
    }

    fn commit(&mut self, staged: Vault) -> Result<()> {
        let blobs: Vec<_> = staged
            .missing_for(&self.vault.heads())
            .into_iter()
            .map(Entry::encode)
            .collect();
        self.store
            .append_batch(blobs.iter().map(|blob| blob.as_slice()))?;
        self.vault = staged;
        Ok(())
    }

    fn require_ready(&self) -> Result<()> {
        if !self.ready {
            return Err(Error::Protocol("Startup membership sync is not finished"));
        }
        if !self.vault.is_member(&self.secret.device_id()) {
            return Err(Error::Protocol("This device was removed from the vault"));
        }
        Ok(())
    }

    fn targets(&self) -> Vec<PeerAddr> {
        self.vault
            .members()
            .filter(|id| *id != self.secret.device_id())
            .map(|id| {
                self.peers.get(&id.to_string()).map_or_else(
                    || PeerAddr::from(*id.as_bytes()),
                    |addr| addr.peer(*id.as_bytes()),
                )
            })
            .collect()
    }
}

thread_local! {
    static STATE: Handler = Handler(Arc::new(Mutex::new(None)));
    static NODE: RefCell<Option<Node>> = const { RefCell::new(None) };
}

fn state() -> Handler {
    STATE.with(Clone::clone)
}
fn node() -> Result<Node> {
    NODE.with(|node| node.borrow().clone()).ok_or(Error::Locked)
}

fn enforce_membership() {
    if let Ok(node) = node() {
        node.enforce_membership();
    }
}

fn unhex<const N: usize>(text: &str) -> Result<[u8; N]> {
    data_encoding::HEXLOWER
        .decode(text.as_bytes())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(Error::Protocol("Invalid identifier"))
}

fn text<'a>(body: &'a Value, key: &str) -> Result<&'a str> {
    body.get(key)
        .and_then(Value::as_str)
        .ok_or(Error::Protocol("A required field is missing"))
}

fn take_secret(body: &mut Value, key: &str) -> Result<Zeroizing<String>> {
    match body.get_mut(key).map(Value::take) {
        Some(Value::String(value)) => Ok(Zeroizing::new(value)),
        _ => Err(Error::Protocol("A required field is missing")),
    }
}

async fn start(store: Unlocked) -> Result<()> {
    let loaded = Loaded::open(store)?;
    let mut config = NodeConfig::new(*loaded.secret.to_bytes());
    config.portmapper = false;
    let state = state();
    let membership = state.clone();
    let gate = Arc::new(move |peer: &PeerId| {
        membership
            .with(|s| Ok(s.vault.is_member(&DeviceId::from_bytes(*peer))))
            .unwrap_or(false)
    });
    *state.0.lock().map_err(|_| Error::State)? = Some(loaded);
    let node = match Node::spawn(config, gate, state.clone()).await {
        Ok(node) => node,
        Err(error) => {
            *state.0.lock().map_err(|_| Error::State)? = None;
            return Err(error.into());
        }
    };
    state.with(|s| {
        s.addr = Some(Addr::from_peer(node.addr()));
        Ok(())
    })?;
    NODE.with(|slot| *slot.borrow_mut() = Some(node));
    Ok(())
}

async fn lock() -> Result<Value> {
    let old = NODE.with(|slot| slot.borrow_mut().take());
    *state().0.lock().map_err(|_| Error::State)? = None;
    if let Some(node) = old {
        node.shutdown().await;
    }
    Ok(json!({"type": "device-lock", "ok": true}))
}

/// Startup has the same membership-first barrier and bounded best-effort
/// deadline as the CLI. A dial failure counts as unreachable; an exchange
/// failure does not. Members learned in a round must also be contacted.
async fn sync() -> Result<Value> {
    let node = node()?;
    let state = state();
    let mut ready = state.with(|s| Ok(s.ready))?;
    let mut deadline = Instant::now() + Duration::from_secs(30);
    let mut attempts = BTreeSet::new();
    let mut errors = Vec::new();
    loop {
        let targets = state.with(|s| Ok(s.targets()))?;
        for peer in targets {
            if !ready && attempts.contains(&peer.id) {
                continue;
            }
            let id = peer.id;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let budget = Duration::from_secs(15).min(remaining);
            let until = Instant::now() + budget;
            match timeout(budget, node.connect(peer)).await {
                Ok(Ok(conn)) => {
                    let result =
                        timeout(until.saturating_duration_since(Instant::now()), conn.sync()).await;
                    conn.close();
                    match result {
                        Ok(Ok(_)) | Ok(Err(deadbolt_net::Error::MembershipRejected(_))) => {
                            attempts.insert(id);
                        }
                        Ok(Err(error)) => errors.push(error.to_string()),
                        Err(_) => errors.push("Sync exchange timed out".into()),
                    }
                }
                Ok(Err(error)) => {
                    attempts.insert(id);
                    errors.push(error.to_string());
                }
                Err(_) => {
                    attempts.insert(id);
                    errors.push("Sync dial timed out".into());
                }
            }
        }
        let complete =
            state.with(|s| Ok(s.targets().iter().all(|peer| attempts.contains(&peer.id))))?;
        if ready || complete || Instant::now() >= deadline {
            state.with(|s| {
                s.ready = true;
                s.addr = Some(Addr::from_peer(node.addr()));
                Ok(())
            })?;
            if !ready {
                // As in the CLI, follow membership refresh immediately with a
                // data round rather than waiting for the next browser alarm.
                ready = true;
                attempts.clear();
                deadline = Instant::now() + Duration::from_secs(30);
                continue;
            }
            break;
        }
        sleep(Duration::from_secs(1)).await;
    }
    Ok(json!({"type": "device-sync", "ok": true, "errors": errors}))
}

// The proof deliberately matches the exact origin, rather than broadening a
// credential's scope without the CLI's full PSL policy. Content-script frame
// and gesture checks still run in the shared background autofill implementation.
fn origin(raw: &str) -> Result<String> {
    let url = url::Url::parse(raw).map_err(|_| Error::Protocol("Invalid URL"))?;
    let host = url
        .host_str()
        .ok_or(Error::Protocol("A URL needs a host"))?;
    let local = host == "localhost"
        || host == "127.0.0.1"
        || host.ends_with(".localhost")
        || host.ends_with(".test");
    if url.scheme() != "https" && !(url.scheme() == "http" && local) {
        return Err(Error::Protocol("Not a secure web page"));
    }
    Ok(url.origin().ascii_serialization())
}

fn field(item: &Item, key: &str) -> String {
    item.fields
        .get(key)
        .map(|f| f.value.clone())
        .unwrap_or_default()
}
fn matches(item: &Item, page: &str) -> bool {
    let saved = field(item, "url");
    let saved = if saved.contains("://") {
        saved
    } else {
        format!("https://{saved}")
    };
    !item.deleted && item.kind == "login" && origin(&saved).is_ok_and(|saved| saved == page)
}
fn reference(vault: &Vault, id: ItemId) -> String {
    format!("{}:{id}", vault.id())
}

fn item_ref(vault: &Vault, value: &str) -> Result<ItemId> {
    let (held, item) = value
        .split_once(':')
        .ok_or(Error::Protocol("Invalid login reference"))?;
    if held != vault.id().to_string() {
        return Err(Error::Protocol("Login belongs to another vault"));
    }
    Ok(ItemId::from_bytes(unhex(item)?))
}

fn account(item: &Item, vault: &Vault) -> Value {
    json!({"ref": reference(vault, item.id), "vault": vault.name(), "title": item.name.as_deref().unwrap_or("Login"),
        "username": field(item, "username"), "hasPassword": item.fields.contains_key("password"), "hasTotp": false,
        "urls": [field(item, "url")]})
}

fn login_request(body: &Value) -> Result<Value> {
    let kind = text(body, "type")?;
    let page = origin(text(body, "origin")?)?;
    state().with(|s| {
        let items = s.vault.items();
        match kind {
            "list" => Ok(json!({"type": "list", "site": url::Url::parse(&page).ok().and_then(|u| u.host_str().map(str::to_owned)),
                "accounts": items.iter().filter(|i| matches(i, &page)).map(|i| account(i, &s.vault)).collect::<Vec<_>>()})),
            "fill" => {
                let id = item_ref(&s.vault, text(body, "ref")?)?;
                let item = s.vault.item(&id).filter(|i| matches(i, &page)).ok_or(Error::Protocol("Login does not belong to this origin"))?;
                let wants = body.get("want").and_then(Value::as_array).ok_or(Error::Protocol("Missing requested fields"))?;
                let mut reply = json!({"type": "fill"});
                for key in ["username", "password"] {
                    if wants.iter().any(|w| w.as_str() == Some(key)) && item.fields.contains_key(key) { reply[key] = json!(field(&item, key)); }
                }
                Ok(reply)
            }
            "check" => {
                let password = text(body, "password")?;
                let username = body.get("username").and_then(Value::as_str).unwrap_or_default();
                let matched: Vec<_> = items.iter().filter(|i| matches(i, &page) && field(i, "username") == username).collect();
                let same = matched.iter().any(|i| field(i, "password") == password);
                Ok(json!({"type": "check", "status": if same {"same"} else if matched.is_empty() {"new"} else {"update"},
                    "matches": matched.iter().map(|i| reference(&s.vault, i.id)).collect::<Vec<_>>()}))
            }
            "save" => {
                let input = body.get("entry").ok_or(Error::Protocol("Missing login"))?;
                let url = text(input, "url")?;
                if origin(url)? != page { return Err(Error::Protocol("Login URL does not belong to this origin")); }
                let fields = [
                    ("username".into(), Field::new(FieldType::Text, text(input, "username")?)),
                    ("password".into(), Field::new(FieldType::Secret, text(input, "password")?)),
                    ("url".into(), Field::new(FieldType::Url, url)),
                ];
                let mut staged = s.vault.clone();
                let (id, created) = if let Some(reference) = body.get("ref").and_then(Value::as_str) {
                    let id = item_ref(&s.vault, reference)?;
                    if !s.vault.item(&id).is_some_and(|i| matches(&i, &page)) { return Err(Error::Protocol("Login does not belong to this origin")); }
                    staged.write(&s.secret, fields.into_iter().map(|(name, value)| DataOp::set(id, name, value)).collect())?;
                    (id, false)
                } else {
                    let (id, _) = staged.create_item(&s.secret, "login", Some(text(input, "title")?.into()), fields)?;
                    (id, true)
                };
                s.commit(staged)?;
                Ok(json!({"type": "save", "ref": reference(&s.vault, id), "created": created}))
            }
            // No passkey/card capability is advertised for this proof.
            "passkey-list" => Ok(json!({"type":"passkeys", "rpId": "", "canVerify": false, "passkeys": []})),
            "forms" => Ok(json!({"type":"forms", "identities":[], "cards":[], "canVerify":false})),
            _ => Err(Error::Protocol("This operation is not available in the standalone proof")),
        }
    })
}

async fn dispatch(mut body: Value) -> Result<Value> {
    match text(&body, "type")? {
        "hello" | "device-status" => {
            let status = if state().with(|_| Ok(())).is_ok() {
                "ready"
            } else if storage_exists()
                .await
                .map_err(|_| Error::Protocol("Cannot read browser storage"))?
                .as_bool()
                == Some(true)
            {
                "locked"
            } else {
                "not-set-up"
            };
            Ok(
                json!({"type":"hello", "protocol":3, "version":"standalone-proof", "status":status, "capabilities":[]}),
            )
        }
        "device-create" => {
            if node().is_ok() {
                return Err(Error::Protocol("Lock before creating a device"));
            }
            let passphrase = take_secret(&mut body, "passphrase")?;
            if passphrase.is_empty() {
                return Err(Error::Protocol("The passphrase cannot be empty"));
            }
            let secret = DeviceSecret::generate();
            let (_, genesis) = Vault::create(&secret, text(&body, "name")?)?;
            let store = deadbolt_store::init_with_backend(
                backend(true).await?,
                passphrase.as_bytes(),
                *secret.to_bytes(),
                KdfParams::DEFAULT,
            )?;
            store.append_batch([genesis.encode().as_slice()])?;
            drop(store);
            storage_publish()
                .await
                .map_err(|_| Error::Protocol("Cannot publish initialized browser storage"))?;
            let store =
                deadbolt_store::unlock_with_backend(backend(false).await?, passphrase.as_bytes())?;
            start(store).await?;
            Ok(json!({"type":"device-create", "ok":true}))
        }
        "device-unlock" => {
            if node().is_ok() {
                return Err(Error::Protocol("The vault is already unlocked"));
            }
            let passphrase = take_secret(&mut body, "passphrase")?;
            let store =
                deadbolt_store::unlock_with_backend(backend(false).await?, passphrase.as_bytes())?;
            start(store).await?;
            Ok(json!({"type":"device-unlock", "ok":true}))
        }
        "device-lock" => lock().await,
        "device-sync" => sync().await,
        "device-pair" => {
            if !state().with(|s| Ok(s.ready))? {
                sync().await?;
            }
            state().with(|s| s.require_ready())?;
            let node = node()?;
            if !node.online(Duration::from_secs(20)).await {
                return Err(Error::Protocol("Cannot reach an iroh relay"));
            }
            state().with(|s| {
                s.addr = Some(Addr::from_peer(node.addr()));
                Ok(())
            })?;
            let code = text(&body, "code")?.parse()?;
            node.pair(&code, PairingOptions::default(), &state())
                .await?;
            Ok(json!({"type":"device-pair", "ok":true}))
        }
        _ => login_request(&body),
    }
}

/// Called only through the extension-owned offscreen worker. Never exposed to
/// web pages; privileged commands are sender-gated in the service worker.
#[wasm_bindgen]
pub async fn request(body: JsValue) -> std::result::Result<JsValue, JsValue> {
    let body: Value =
        serde_wasm_bindgen::from_value(body).map_err(|_| JsValue::from_str("Invalid request"))?;
    let reply = match dispatch(body).await {
        Ok(reply) => reply,
        Err(error) => {
            json!({"type":"error", "code": if matches!(error, Error::Locked) {"locked"} else {"failed"}, "message":error.to_string()})
        }
    };
    reply
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|_| JsValue::from_str("Cannot encode reply"))
}
