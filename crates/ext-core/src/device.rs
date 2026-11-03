//! Phase-one standalone device, hosted only in an extension-owned worker.
//! JavaScript routes messages; core owns signatures, membership and secrets.

mod forms;
mod generate;
mod items;
mod join;
mod opfs;
mod passkeys;
mod wire;

use crate::policy::{self, Preset};
use deadbolt_core::autofill::{self, Status, item_name, login_title, otp, urls, value};
use deadbolt_core::site::{Site, page_url};
use deadbolt_core::totp::Totp;
use deadbolt_core::{
    DataOp, DeviceId, DeviceSecret, Entry, Field, FieldType, Item, ItemId, Vault, VaultWrite,
};
use deadbolt_net::{Node, NodeConfig, PairingOptions, PeerAddr, PeerId};
use deadbolt_store::{KdfParams, Unlocked};
use n0_future::task::JoinHandle;
use n0_future::time::{Instant, sleep, timeout};
use opfs::OpfsBackend;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Notify;
use wasm_bindgen::prelude::*;
use wire::{Addr, Handler};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Error>;

#[wasm_bindgen(inline_js = r#"
export function unix_time() { return Math.floor(Date.now() / 1000); }
export function items_changed() { self.postMessage({ change: "items" }); }
export function stop_worker(error) { self.postMessage({ error, fatal: true }); self.close(); }
export function sync_failed() { console.warn("Deadbolt background sync failed; it will retry on the next wake"); }
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
    let handle;
    for (let attempt = 0; ; attempt++) {
        try { handle = await file.createSyncAccessHandle(); break; }
        catch (error) {
            // Terminating the old worker releases its handle asynchronously.
            if (error.name !== "NoModificationAllowedError" || attempt === 3) throw error;
            await new Promise(resolve => setTimeout(resolve, 100));
        }
    }
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
    fn unix_time() -> f64;
    fn items_changed();
    fn stop_worker(error: &str);
    fn sync_failed();
    #[wasm_bindgen(catch)]
    async fn storage_exists() -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(catch)]
    async fn storage_open(create: bool) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(catch)]
    async fn storage_publish() -> std::result::Result<JsValue, JsValue>;
}

async fn backend(create: bool) -> Result<OpfsBackend> {
    let handle = storage_open(create).await.map_err(|_| {
        Error::Protocol("Deadbolt couldn't open its storage in this browser. Try again.")
    })?;
    OpfsBackend::new(handle).map_err(|error| Error::Store(error.into()))
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Deadbolt is locked. Unlock it first.")]
    Locked,
    #[error("Deadbolt hit a problem. Lock it and unlock it again.")]
    State,
    #[error("That passphrase isn't right.")]
    WrongPassphrase,
    #[error("Enter your passphrase to continue.")]
    PassphraseNeeded,
    #[error("That login is for a different site.")]
    DomainMismatch,
    #[error("That item is not in the vault.")]
    NotFound,
    #[error("{0}")]
    Protocol(&'static str),
    #[error(transparent)]
    Store(#[from] deadbolt_store::Error),
    #[error(
        "Deadbolt couldn't confirm a vault change. Unlock it and check whether the change was saved."
    )]
    UnconfirmedWrite(#[source] deadbolt_store::Error),
    #[error(transparent)]
    History(#[from] crate::history::Error),
    #[error(transparent)]
    Core(#[from] deadbolt_core::Error),
    #[error(transparent)]
    Decode(#[from] deadbolt_core::DecodeError),
    #[error(transparent)]
    Net(#[from] deadbolt_net::Error),
    #[error(transparent)]
    Application(#[from] deadbolt_net::application::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Generation(#[from] deadbolt_core::site_password::Error),
    #[error(transparent)]
    Passkey(#[from] deadbolt_core::passkeys::Error),
    #[error(transparent)]
    Item(#[from] deadbolt_core::ItemError),
}

struct Loaded {
    generated: deadbolt_core::site_password::Pending,
    store: Unlocked,
    secret: DeviceSecret,
    vault: Vault,
    peers: BTreeMap<String, Addr>,
    addr: Option<Addr>,
    ready: bool,
    name: String,
    peer_names: BTreeMap<String, String>,
    /// When each other member last completed a sync with this device (unix
    /// seconds), as the CLI's address book keeps it: only direct contact counts.
    seen: BTreeMap<String, u64>,
}

impl Loaded {
    fn open(store: Unlocked) -> Result<Self> {
        let vault = crate::history::load(&store)?;
        let peers = store
            .meta_get("extension/peers")?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let name = store
            .meta_get("extension/device-name")?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_else(|| "Browser".into());
        let peer_names = store
            .meta_get("extension/peer-names")?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let seen = store
            .meta_get("extension/peer-seen")?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let secret = DeviceSecret::from_bytes(store.device_secret());
        let ready = vault.members().all(|peer| peer == secret.device_id());
        Ok(Self {
            generated: Default::default(),
            store,
            secret,
            vault,
            peers,
            addr: None,
            ready,
            name,
            peer_names,
            seen,
        })
    }

    fn write(&mut self, ops: Vec<DataOp>) -> Result<deadbolt_core::Hash> {
        self.mutate(|v, key| Ok(v.write(key, ops)?.hash()))
    }

    fn mutate<T>(
        &mut self,
        change: impl FnOnce(&mut VaultWrite<'_>, &DeviceSecret) -> Result<T>,
    ) -> Result<T> {
        let mut changed = false;
        let result = self.vault.transact(
            |v| change(v, &self.secret),
            |entries| {
                self.store
                    .append_batch(entries.iter().copied().map(Entry::encode))
                    .map_err(|error| match error {
                        deadbolt_store::Error::AppendUncertain(_) => Error::UnconfirmedWrite(error),
                        _ => Error::Store(error),
                    })?;
                changed = true;
                Ok(())
            },
        )?;
        if changed {
            items_changed();
        }
        Ok(result)
    }

    /// `peer` just completed a sync with this device.
    fn saw(&mut self, peer: &DeviceId) -> Result<()> {
        // Only current members appear in devices(). Prune stale timestamps in
        // the next metadata write, never in a second transaction after removal.
        let mut seen = BTreeMap::new();
        for member in self.vault.members() {
            let id = member.to_string();
            let last = if member == *peer {
                Some(unix_time() as u64)
            } else {
                self.seen.get(&id).copied()
            };
            if let Some(last) = last {
                seen.insert(id, last);
            }
        }
        self.store
            .meta_set("extension/peer-seen", &serde_json::to_vec(&seen)?)?;
        self.seen = seen;
        Ok(())
    }

    fn require_ready(&self) -> Result<()> {
        if !self.ready {
            return Err(Error::Protocol(CATCHING_UP));
        }
        if !self.vault.is_member(&self.secret.device_id()) {
            return Err(Error::Protocol(
                "This browser was removed from the vault on another device",
            ));
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

/// Said while the first sync after unlocking hasn't reached every device yet.
const CATCHING_UP: &str =
    "Deadbolt is still catching up with your other devices. Try again in a moment.";
/// Said when this browser can't reach Deadbolt's servers that connect devices.
const OFFLINE: &str =
    "Couldn't reach Deadbolt's sync service. Check your internet connection and try again.";

thread_local! {
    /// The lock preset the service worker last sent (Strict until it does).
    static PRESET: Cell<Preset> = const { Cell::new(Preset::Strict) };
    static STATE: Handler = Handler(Arc::new(Mutex::new(None)));
    static NODE: RefCell<Option<Node>> = const { RefCell::new(None) };
    static SYNC: RefCell<Option<SyncTask>> = const { RefCell::new(None) };
    /// Sync rounds finished since the worker started, for a sync that waits for one.
    static ROUNDS: Cell<u64> = const { Cell::new(0) };
}

struct SyncTask {
    wake: Arc<Notify>,
    task: JoinHandle<()>,
}

impl Drop for SyncTask {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn request_sync() {
    SYNC.with(|slot| {
        if let Some(sync) = slot.borrow().as_ref() {
            sync.wake.notify_one();
        }
    });
}

fn start_sync() {
    let wake = Arc::new(Notify::new());
    let notified = wake.clone();
    let task = n0_future::task::spawn(async move {
        loop {
            notified.notified().await;
            if sync_round().await.is_err() {
                sync_failed();
            }
            ROUNDS.with(|r| r.set(r.get() + 1));
        }
    });
    SYNC.with(|slot| *slot.borrow_mut() = Some(SyncTask { wake, task }));
    request_sync();
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

async fn start(store: Unlocked, device_name: Option<&str>) -> Result<()> {
    let mut loaded = Loaded::open(store)?;
    if let Some(name) = device_name.filter(|name| !name.is_empty() && name.len() <= 200) {
        let name = deadbolt_net::application::clean_name(name);
        if name.is_empty() {
            return Err(Error::Protocol("A device name is required"));
        }
        loaded.name = name;
        loaded
            .store
            .meta_set("extension/device-name", &serde_json::to_vec(&loaded.name)?)?;
    }
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
    start_sync();
    Ok(())
}

/// Startup has the same membership-first barrier and bounded best-effort
/// deadline as the CLI. A dial failure counts as unreachable, except a peer
/// refusing it at its inbound limit; an exchange failure does not. Members
/// learned in a round must also be contacted.
async fn sync_round() -> Result<()> {
    let node = node()?;
    let state = state();
    let mut ready = state.with(|s| Ok(s.ready))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut attempts = BTreeSet::new();
    loop {
        let targets = state.with(|s| {
            Ok(s.targets()
                .into_iter()
                .filter(|peer| ready || !attempts.contains(&peer.id))
                .collect())
        })?;
        let completed = deadbolt_net::application::contact_round(
            targets,
            (!ready).then_some(deadline),
            |peer, budget| {
                let node = &node;
                let state = &state;
                async move {
                    let id = peer.id;
                    let until = Instant::now() + budget;
                    let complete = match timeout(budget, node.connect(peer)).await {
                        Ok(Ok(conn)) => {
                            let result = timeout(
                                until.saturating_duration_since(Instant::now()),
                                conn.sync(),
                            )
                            .await;
                            conn.close();
                            match result {
                                Ok(Ok(_)) => {
                                    // Both sides processed everything: synced.
                                    state.with(|s| s.saw(&DeviceId::from_bytes(id)))?;
                                    true
                                }
                                Ok(Err(deadbolt_net::Error::MembershipRejected(_))) => true,
                                Ok(Err(_)) | Err(_) => false,
                            }
                        }
                        Ok(Err(deadbolt_net::Error::Rejected(_))) => false,
                        Ok(Err(_)) | Err(_) => true,
                    };
                    Ok::<_, Error>(complete)
                }
            },
        )
        .await?;
        attempts.extend(completed);
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
                continue;
            }
            break;
        }
        sleep(Duration::from_secs(1).min(deadline.saturating_duration_since(Instant::now()))).await;
    }
    Ok(())
}

/// Parse the page using the same public-suffix policy as the native daemon.
fn site(raw: &str) -> Result<Site> {
    Site::from_origin(raw).map_err(Error::Protocol)
}

fn origin(raw: &str) -> Result<String> {
    site(raw)?;
    url::Url::parse(raw)
        .map(|url| url.origin().ascii_serialization())
        .map_err(|_| Error::Protocol("That isn't a web address"))
}

fn field(item: &Item, key: &str) -> String {
    value(item, key).unwrap_or_default().to_owned()
}

fn matches(item: &Item, page: &Site) -> bool {
    !item.deleted && item.kind == "login" && page.matches(urls(item))
}

fn find_login(s: &Loaded, body: &Value, page: &Site) -> Result<Item> {
    let item = login(s, body)?;
    if !matches(&item, page) {
        return Err(Error::DomainMismatch);
    }
    Ok(item)
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
    let title = login_title(item);
    let mut account = json!({"ref": reference(vault, item.id), "vault": vault.name(), "title": title,
        "hasPassword": value(item, "password").is_some(), "hasTotp": otp(item).is_some_and(|f| !f.value.is_empty()),
        "urls": urls(item).collect::<Vec<_>>()});
    if let Some(username) = value(item, "username") {
        account["username"] = json!(username);
    }
    if let Some(provider) = value(item, "sign-in-with") {
        let mut sign_in = json!({"provider": provider});
        if let Some(linked) = value(item, "sign-in-account")
            .and_then(|id| unhex(id).ok())
            .map(ItemId::from_bytes)
            .filter(|id| *id != item.id)
            .and_then(|id| vault.item(&id))
            .filter(|i| !i.deleted)
        {
            sign_in["account"] = json!(
                value(&linked, "username")
                    .map(str::to_owned)
                    .unwrap_or_else(|| login_title(&linked))
            );
        }
        account["signIn"] = sign_in;
    }
    account
}

fn list_logins(body: &Value) -> Result<Value> {
    let origin = text(body, "origin")?;
    let page = site(origin)?;
    state().with(|s| {
        let filled: BTreeMap<String, u64> = s
            .store
            .meta_get("extension/filled")?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let mut accounts: Vec<_> = s
            .vault
            .site_logins(&page)
            .map(|i| {
                let mut account = account(&i, &s.vault);
                let urls: Vec<_> = urls(&i).filter(|url| page.matches_url(url)).collect();
                account["urls"] = json!(urls);
                let used = filled.get(&reference(&s.vault, i.id)).copied().unwrap_or(0);
                (autofill::rank(origin, &i, used), account)
            })
            .collect();
        accounts.sort_by(|(ra, a), (rb, b)| {
            ra.cmp(rb)
                .then_with(|| a["ref"].as_str().cmp(&b["ref"].as_str()))
        });
        Ok(json!({"type": "list", "site": page.domain,
            "accounts": accounts.into_iter().map(|(_, account)| account).collect::<Vec<_>>()}))
    })
}

fn fill_login(body: &Value) -> Result<Value> {
    let page = site(text(body, "origin")?)?;
    state().with(|s| {
        let item = find_login(s, body, &page)?;
        let wants = body
            .get("want")
            .and_then(Value::as_array)
            .ok_or(Error::Protocol("Missing requested fields"))?;
        if wants.is_empty()
            || wants.len() > 3
            || wants
                .iter()
                .any(|w| !matches!(w.as_str(), Some("username" | "password" | "totp")))
        {
            return Err(Error::Protocol("Invalid requested fields"));
        }
        let mut reply = json!({"type": "fill"});
        for key in ["username", "password"] {
            if wants.iter().any(|w| w.as_str() == Some(key)) && item.fields.contains_key(key) {
                reply[key] = json!(field(&item, key));
            }
        }
        if wants.iter().any(|w| w.as_str() == Some("totp"))
            && let Some(field) = otp(&item)
        {
            let totp = Totp::parse(&field.value)
                .map_err(|_| Error::Protocol("Invalid one-time password field"))?;
            reply["totp"] = json!(totp.code(unix_time() as u64));
        }
        let mut filled: BTreeMap<String, u64> = s
            .store
            .meta_get("extension/filled")?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        filled.insert(reference(&s.vault, item.id), unix_time() as u64);
        s.store
            .meta_set("extension/filled", &serde_json::to_vec(&filled)?)?;
        Ok(reply)
    })
}

fn check_login(body: &Value) -> Result<Value> {
    let origin = text(body, "origin")?;
    let page = site(origin)?;
    let username = body.get("username").and_then(Value::as_str);
    if username.is_some_and(|u| u.chars().count() > 500) {
        return Err(Error::Protocol("The username is too long"));
    }
    state().with(|s| {
        let password = generate::resolve(&mut s.generated, origin, body)?;
        let (status, ids) = autofill::check(s.vault.site_logins(&page), username, &password);
        let status = match status {
            Status::New => "new",
            Status::Update => "update",
            Status::Same => "same",
        };
        let matches: Vec<_> = ids.into_iter().map(|id| reference(&s.vault, id)).collect();
        Ok(json!({"type": "check", "status": status, "matches": matches}))
    })
}

fn save_login(body: &Value) -> Result<Value> {
    let origin = text(body, "origin")?;
    let page = site(origin)?;
    let input = body.get("entry").ok_or(Error::Protocol("Missing login"))?;
    let url = page_url(text(input, "url")?).map_err(Error::Protocol)?;
    let username = text(input, "username")?.trim();
    let title = text(input, "title")?;
    if url.len() > 2048 || username.chars().count() > 500 {
        return Err(Error::Protocol("The login is too long"));
    }
    if !page.matches_url(url) {
        return Err(Error::DomainMismatch);
    }
    let reply = state().with(|s| {
        let password = generate::resolve(&mut s.generated, origin, input)?;
        let (id, created) = if body.get("ref").is_some() {
            let item = find_login(s, body, &page)?;
            s.write(vec![autofill::password_update(item.id, &password)])?;
            (item.id, false)
        } else {
            let mut fields = vec![
                ("url".into(), Field::new(FieldType::Url, url)),
                ("password".into(), Field::new(FieldType::Secret, &*password)),
            ];
            if !username.is_empty() {
                fields.push(("username".into(), Field::new(FieldType::Text, username)));
            }
            let name = Some(item_name(title)).filter(|t| !t.is_empty() && *t != page.domain);
            let id = s.mutate(|v, key| Ok(v.create_item(key, "login", name, fields)?.0))?;
            (id, true)
        };
        generate::saved(&mut s.generated, input);
        Ok(json!({"type": "save", "ref": reference(&s.vault, id), "created": created}))
    })?;
    request_sync();
    Ok(reply)
}

fn login(s: &Loaded, body: &Value) -> Result<Item> {
    let id = item_ref(&s.vault, text(body, "ref")?)?;
    s.vault
        .item(&id)
        .filter(|i| !i.deleted && i.kind == "login")
        .ok_or(Error::NotFound)
}

/// Checks an explicit passkey PRF or passphrase without holding the live
/// vault during the KDF.
fn reauthenticate(body: &mut Value, required: bool) -> Result<bool> {
    if body.get("prf").is_some() {
        let key = take_prf(body)?;
        return state().with(|s| {
            if !s.store.check_biometric(&key)? {
                return Err(Error::Protocol("Touch ID didn't unlock this vault. Use your passphrase, then reset Touch ID in Settings."));
            }
            Ok(true)
        });
    }
    check_passphrase(body, required)
}

/// Checks an explicit passphrase only, never a passkey.
fn check_passphrase(body: &mut Value, required: bool) -> Result<bool> {
    let passphrase = body.get_mut("passphrase").map(Value::take);
    if required && passphrase.is_none() {
        return Err(Error::PassphraseNeeded);
    }
    let Some(passphrase) = passphrase else {
        return Ok(false);
    };
    let Value::String(passphrase) = passphrase else {
        return Err(Error::Protocol("A required field is missing"));
    };
    let passphrase = Zeroizing::new(passphrase);
    let check = state().with(|s| Ok(s.store.passphrase_check()?))?;
    if !check.matches(passphrase.as_bytes()) {
        return Err(Error::WrongPassphrase);
    }
    Ok(true)
}

/// Domain-separates a passkey's raw PRF output from the store's slot key, so
/// the PRF value itself never keys the store.
const PRF_CONTEXT: &str = "deadbolt ext-core v1 prf unlock";

/// Takes the raw `prf` output and derives the biometric slot key from it.
/// Enrollment, unlock and reauthentication all go through here.
fn take_prf(body: &mut Value) -> Result<Zeroizing<[u8; 32]>> {
    let encoded = take_secret(body, "prf")?;
    let prf = Zeroizing::new(unhex::<32>(&encoded)?);
    Ok(Zeroizing::new(blake3::derive_key(PRF_CONTEXT, &prf[..])))
}

/// Adds a login by hand, or edits one, from the vault page: unlike a page's
/// save it isn't tied to the page's origin. An edit with no password keeps
/// the one it has. `otp` and `notes`, when given, set the one-time password
/// (a TOTP secret or `otpauth://` URI) and the notes; empty, they remove it.
fn edit_login(body: &Value) -> Result<Value> {
    let input = body.get("entry").ok_or(Error::Protocol("Missing login"))?;
    let url = origin(text(input, "url")?)?;
    let title = policy::login_title(text(input, "title")?).map_err(Error::Protocol)?;
    let password = text(input, "password")?;
    let username = text(input, "username")?.trim();
    let favorite = match input.get("favorite") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err(Error::Protocol("favorite is true or false")),
    };
    let tags = items::parse_tags(input.get("tags"))?;
    let reply = state().with(|s| {
        // The core keeps no empty field: a login without a username has none.
        let mut fields = vec![("url".to_owned(), Field::new(FieldType::Url, &url))];
        if !username.is_empty() {
            fields.push(("username".into(), Field::new(FieldType::Text, username)));
        }
        if !password.is_empty() {
            fields.push(("password".into(), Field::new(FieldType::Secret, password)));
        }
        let existing = body.get("ref").map(|_| login(s, body)).transpose()?;
        // Optional fields: absent leaves them, empty removes them.
        let mut removed = Vec::new();
        for key in ["otp", "notes"] {
            match input.get(key) {
                None | Some(Value::Null) => {}
                Some(Value::String(v)) if v.trim().is_empty() => removed.push(key),
                Some(Value::String(v)) => fields.push((
                    key.into(),
                    deadbolt_core::listing::input_field(
                        "login",
                        existing.as_ref(),
                        key,
                        None,
                        v.trim().to_owned(),
                    )?,
                )),
                Some(_) => return Err(Error::Protocol("A login's fields are text")),
            }
        }
        let (id, created) = if let Some(item) = existing {
            let id = item.id;
            let mut ops = vec![DataOp::name(id, Some(title.into()))];
            if username.is_empty() && item.fields.contains_key("username") {
                ops.push(DataOp::remove(id, "username"));
            }
            for key in removed {
                if item.fields.contains_key(key) {
                    ops.push(DataOp::remove(id, key));
                }
            }
            ops.extend(
                fields
                    .into_iter()
                    .map(|(name, value)| DataOp::set(id, name, value)),
            );
            ops.extend(items::tag_ops(&item, favorite, tags.as_deref()));
            s.write(ops)?;
            (id, false)
        } else {
            if password.is_empty() {
                return Err(Error::Protocol("A new login needs a password"));
            }
            let id = s.mutate(|v, key| {
                let (id, _) = v.create_item_with(
                    key,
                    "login",
                    Some(title.into()),
                    fields,
                    favorite.unwrap_or(false),
                    tags.unwrap_or_default(),
                )?;
                Ok(id)
            })?;
            (id, true)
        };
        Ok(json!({"type": "device-save", "ref": reference(&s.vault, id), "created": created}))
    })?;
    request_sync();
    Ok(reply)
}

/// Removes another device from the vault, as `deadbolt devices remove` does.
fn remove_device(body: &Value) -> Result<Value> {
    let target = DeviceId::from_bytes(unhex(text(body, "id")?)?);
    state().with(|s| {
        s.require_ready()?;
        if target == s.secret.device_id() {
            return Err(Error::Protocol(
                "This browser can't remove itself; remove it from another device",
            ));
        }
        if !s.vault.is_member(&target) {
            return Err(Error::Protocol("That device isn't in the vault"));
        }
        s.mutate(|v, key| Ok(v.remove(key, target)?))
    })?;
    enforce_membership();
    request_sync();
    Ok(json!({"type": "device-remove", "ok": true}))
}

fn rename_vault(body: &Value) -> Result<Value> {
    let name = text(body, "name")?.trim();
    state().with(|s| {
        s.require_ready()?;
        if name == s.vault.name() {
            return Ok(());
        }
        s.mutate(|v, key| {
            v.rename(key, name)?;
            Ok(())
        })
    })?;
    request_sync();
    Ok(json!({"type": "device-rename", "ok": true}))
}

/// Asks for a sync round now; with `wait`, answers once one has finished
/// (or after 30 seconds), so "Sync now" can say when it's done.
async fn sync_now(body: &Value) -> Result<Value> {
    node()?;
    let before = ROUNDS.with(Cell::get);
    request_sync();
    if body.get("wait").and_then(Value::as_bool) == Some(true) {
        timeout(Duration::from_secs(30), async {
            while ROUNDS.with(Cell::get) == before {
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_default();
    }
    Ok(json!({"type": "device-sync", "ok": true}))
}

fn devices() -> Result<Value> {
    state().with(|s| {
        Ok(
            json!({"type": "device-devices", "vault": s.vault.name(), "now": unix_time() as u64,
        "devices": s.vault.members().map(|id| {
        let current = id == s.secret.device_id();
        let name = if current { s.name.clone() } else {
            s.peer_names.get(&id.to_string()).cloned().unwrap_or_else(|| id.to_string())
        };
        json!({"id": id.to_string(), "name": name, "current": current, "lastSeen": s.seen.get(&id.to_string())})
    }).collect::<Vec<_>>()}),
        )
    })
}

async fn wait_ready() -> Result<()> {
    request_sync();
    timeout(Duration::from_secs(35), async {
        loop {
            if state().with(|s| Ok(s.ready))? {
                return state().with(|s| s.require_ready());
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| Error::Protocol(CATCHING_UP))?
}

async fn dispatch(mut body: Value) -> Result<Value> {
    // Apply trusted preset changes only after the command succeeds.
    let preset = policy::accepts_preset(text(&body, "type")?)
        .then(|| {
            body.get("preset")
                .and_then(Value::as_str)
                .and_then(Preset::parse)
        })
        .flatten();
    let reply = match text(&body, "type")? {
        "device-preset" => Ok(json!({"type": "device-preset", "ok": true})),
        "device-generate" => generate(&body),
        "hello" | "device-status" => {
            let status = if state().with(|_| Ok(())).is_ok() {
                "ready"
            } else if storage_exists()
                .await
                .map_err(|_| Error::Protocol(STORAGE))?
                .as_bool()
                == Some(true)
            {
                "locked"
            } else {
                "not-set-up"
            };
            Ok(
                json!({"type":"hello", "protocol":3, "version":env!("CARGO_PKG_VERSION"), "status":status, "capabilities":["list", "fill", "check", "save", "generate", "forms", "passkeys"]}),
            )
        }
        "device-create" => {
            join::require_idle()?;
            if node().is_ok() {
                return Err(Error::Protocol("Lock Deadbolt before creating a new vault"));
            }
            let passphrase = take_secret(&mut body, "passphrase")?;
            if passphrase.is_empty() {
                return Err(Error::Protocol("Choose a passphrase"));
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
                .map_err(|_| Error::Protocol(STORAGE))?;
            let store =
                deadbolt_store::unlock_with_backend(backend(false).await?, passphrase.as_bytes())?;
            start(store, body.get("deviceName").and_then(Value::as_str)).await?;
            Ok(json!({"type":"device-create", "ok":true}))
        }
        "device-biometric-info" => {
            let token = if node().is_ok() {
                state().with(|s| Ok(s.store.biometric_token()?))?
            } else if storage_exists()
                .await
                .map_err(|_| Error::Protocol(STORAGE))?
                .as_bool()
                == Some(true)
            {
                deadbolt_store::biometric_token_with_backend(backend(false).await?)?
            } else {
                None
            };
            Ok(
                json!({"type":"device-biometric-info", "token":token.and_then(|t| String::from_utf8(t).ok())}),
            )
        }
        "device-biometric-set" => {
            // Enrolling a new unlock factor requires the passphrase, not just
            // possession of an already-open popup or another cached factor.
            let key = take_prf(&mut body)?;
            check_passphrase(&mut body, true)?;
            let token = text(&body, "token")?;
            if token.len() > 8192 {
                return Err(Error::Protocol("Invalid passkey metadata"));
            }
            state().with(|s| Ok(s.store.set_biometric(&key, token.as_bytes())?))?;
            Ok(json!({"type":"device-biometric-set", "ok":true}))
        }
        "device-biometric-check" => {
            // Lets the extension confirm the passphrase before the passkey
            // ceremony, so a wrong one doesn't waste it; enrolls nothing.
            check_passphrase(&mut body, true)?;
            Ok(json!({"type":"device-biometric-check", "ok":true}))
        }
        "device-biometric-reset" => {
            state().with(|s| Ok(s.store.clear_biometric()?))?;
            Ok(json!({"type":"device-biometric-reset", "ok":true}))
        }
        "device-unlock" => {
            join::require_idle()?;
            if node().is_ok() {
                return Err(Error::Protocol("Deadbolt is already unlocked"));
            }
            let store = if body.get("prf").is_some() {
                let key = take_prf(&mut body)?;
                deadbolt_store::unlock_biometric_with_backend(backend(false).await?, &key)?
            } else {
                let passphrase = take_secret(&mut body, "passphrase")?;
                deadbolt_store::unlock_with_backend(backend(false).await?, passphrase.as_bytes())?
            };
            start(store, body.get("deviceName").and_then(Value::as_str)).await?;
            Ok(json!({"type":"device-unlock", "ok":true}))
        }
        "device-join-start" => join::start(&body).await,
        "device-join-status" => Ok(join::status()),
        "device-join-finish" => join::finish(&mut body).await,
        "device-sync" => sync_now(&body).await,
        "device-passkeys" => passkeys::all(),
        "device-delete" => passkeys::delete(&mut body),
        "device-items" => items::all(),
        "device-item" => items::detail_of(&body),
        "device-secret" => items::secret(&mut body),
        "device-item-save" => items::save(&body),
        "device-item-delete" => items::delete(&mut body),
        "device-kinds" => Ok(items::kinds()),
        "device-save" => edit_login(&body),
        "device-remove" => remove_device(&body),
        "device-rename" => rename_vault(&body),
        "device-devices" => devices(),
        "device-pair" => {
            wait_ready().await?;
            let node = node()?;
            if !node.online(Duration::from_secs(20)).await {
                return Err(Error::Protocol(OFFLINE));
            }
            state().with(|s| {
                s.addr = Some(Addr::from_peer(node.addr()));
                Ok(())
            })?;
            let code = text(&body, "code")?.parse()?;
            node.pair(&code, PairingOptions::default(), &state())
                .await?;
            request_sync();
            items_changed();
            Ok(json!({"type":"device-pair", "ok":true}))
        }
        "generate-check" => generate::check(&body),
        "generate" => generate::generate(&body),
        "generate-keep" => generate::keep(&body),
        "generate-drop" => generate::drop_candidate(&body),
        "forms" => forms::list(&body),
        "fill-form" => forms::fill(&mut body),
        "passkey-list" => passkeys::list(&body),
        "passkey-create" => passkeys::create(&mut body),
        "passkey-get" => passkeys::get(&mut body),
        "passkey-authorize" => passkeys::authorize(&mut body),
        "passkey-finish" => passkeys::finish(&body),
        "list" => list_logins(&body),
        "fill" => fill_login(&body),
        "check" => check_login(&body),
        "save" => save_login(&body),
        _ => Err(Error::Protocol("Deadbolt in the browser can't do this yet")),
    }?;
    if let Some(preset) = preset {
        PRESET.with(|p| p.set(preset));
    }
    Ok(reply)
}

/// Said when this browser's own storage fails under the vault.
const STORAGE: &str = "Deadbolt couldn't read or write its storage in this browser. Try again.";

/// What went wrong, in words for the person using Deadbolt: the messages of
/// the network and storage layers name their internals.
fn plain(error: &Error) -> String {
    use deadbolt_net::Error as Net;
    match error {
        Error::Locked
        | Error::State
        | Error::UnconfirmedWrite(_)
        | Error::WrongPassphrase
        | Error::PassphraseNeeded
        | Error::DomainMismatch
        | Error::NotFound
        | Error::Protocol(_) => error.to_string(),
        Error::Generation(_) | Error::Passkey(_) => error.to_string(),
        Error::History(crate::history::Error::Unavailable { .. } | crate::history::Error::VaultCount(_)) => error.to_string(),
        Error::History(_) => STORAGE.into(),
        Error::Item(error) | Error::Core(deadbolt_core::Error::Item(error)) => {
            sentence(&error.to_string())
        }
        Error::Store(deadbolt_store::Error::WrongPassphrase) => Error::WrongPassphrase.to_string(),
        Error::Store(deadbolt_store::Error::InvalidBiometric) => {
            "That passkey couldn't unlock Deadbolt. Use your passphrase, then set up Touch ID again."
                .into()
        }
        Error::Store(_) | Error::Decode(_) | Error::Json(_) => STORAGE.into(),
        Error::Core(deadbolt_core::Error::MembershipLimit { .. }) => error.to_string(),
        Error::Core(_) | Error::Application(_) => {
            "Deadbolt couldn't make that change to the vault.".into()
        }
        Error::Net(Net::PairingExpired) => {
            "That code expired (codes work for five minutes). Start again.".into()
        }
        Error::Net(Net::PairingCodeMismatch) => {
            "That code didn't match. Check it and start again.".into()
        }
        Error::Net(Net::PairingCodeUsed) => {
            "That code was already used. Start again for a new one.".into()
        }
        Error::Net(Net::PairingNotFound) => {
            "No device is waiting with that code. Check it, or start again on the other device."
                .into()
        }
        Error::Net(Net::OwnCode) => {
            "That code is this browser's own. Enter the code the other device shows.".into()
        }
        Error::Net(Net::InvalidCode(_)) => {
            "That isn't a pairing code. It's five words, like apple-river-stone-lamp-zoo. Update both devices if you have an older four-word code.".into()
        }
        Error::Net(Net::PairingCancelled) => "The pairing was cancelled.".into(),
        Error::Net(Net::Remote(message)) => format!("The other device refused: {message}"),
        Error::Net(
            Net::Timeout | Net::Connect(_) | Net::Closed(_) | Net::Bind(_) | Net::Rendezvous(_),
        ) => OFFLINE.into(),
        Error::Net(_) => "Deadbolt couldn't finish talking to your other device. Try again.".into(),
    }
}

/// An item rule's message as a sentence: "Missing required field number."
fn sentence(message: &str) -> String {
    let mut chars = message.chars();
    let first = chars
        .next()
        .map(|c| c.to_uppercase().collect::<String>())
        .unwrap_or_default();
    format!("{first}{}.", chars.as_str())
}

/// A new password from the core's generator: random letters and digits, with
/// symbols if asked.
fn generate(body: &Value) -> Result<Value> {
    let length = body
        .get("length")
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(deadbolt_core::password::DEFAULT_LENGTH);
    let symbols = body.get("symbols").and_then(Value::as_bool).unwrap_or(true);
    let password = deadbolt_core::password::generate(length, symbols)
        .map_err(|_| Error::Protocol("A password must be 8 to 256 characters"))?;
    Ok(json!({"type": "device-generate", "password": password.as_str()}))
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
            let code = match error {
                Error::Passkey(ref error) => match error {
                    deadbolt_core::passkeys::Error::DomainMismatch(_) => "domain_mismatch",
                    deadbolt_core::passkeys::Error::Exists => "exists",
                    deadbolt_core::passkeys::Error::NotFound => "not_found",
                    _ => "failed",
                },
                Error::Generation(ref error) => match error {
                    deadbolt_core::site_password::Error::Expired => "not_found",
                    deadbolt_core::site_password::Error::Refused(
                        deadbolt_core::password_rules::Refused::Weak,
                    ) => "weak",
                    deadbolt_core::site_password::Error::Origin(_)
                    | deadbolt_core::site_password::Error::RulesTooLong => "bad_request",
                    _ => "failed",
                },
                Error::Locked => "locked",
                Error::PassphraseNeeded => "passphrase_needed",
                Error::DomainMismatch => "domain_mismatch",
                Error::NotFound => "not_found",
                Error::Protocol(_)
                | Error::Item(_)
                | Error::Core(deadbolt_core::Error::Item(_)) => "bad_request",
                Error::WrongPassphrase | Error::Store(deadbolt_store::Error::WrongPassphrase) => {
                    "wrong_passphrase"
                }
                _ => "failed",
            };
            json!({"type":"error", "code": code, "message": plain(&error)})
        }
    };
    reply
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|_| JsValue::from_str("Cannot encode reply"))
}
