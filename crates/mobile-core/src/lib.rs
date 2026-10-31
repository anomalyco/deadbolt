//! Thin native boundary: OS clients own UI, clipboard and biometric gates.
//! Every call is synchronous; run it off the UI thread. `lock` is independent
//! of the network round and cancels all work from the previous generation.
mod join;
mod provider;
mod session;

pub use provider::{MobileCredentialProvider, MobileProviderAuthentication, MobileProviderError};

#[cfg(target_os = "android")]
mod android;

use deadbolt_core::{Item, ItemId, autofill, listing, totp::Totp};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use session::{Loaded, Session};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{runtime::Runtime, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

type Result<T> = std::result::Result<T, MobileError>;

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum MobileError {
    #[error("Unlock Deadbolt first.")]
    Locked,
    #[error("Another setup or unlock is running. Finish or cancel it first.")]
    Busy,
    #[error("The operation was cancelled.")]
    Cancelled,
    #[error("The passphrase or biometric key did not unlock this device.")]
    Authentication,
    #[error("Invalid request.")]
    InvalidRequest,
    #[error("The item or field was not found.")]
    NotFound,
    #[error("This device already has a vault. Unlock it instead.")]
    AlreadyInitialized,
    #[error("The encrypted vault could not be opened or saved. Its files have been retained.")]
    Storage,
    #[error("The vault history is unavailable. Its encrypted entries have been retained.")]
    InvalidVault,
    #[error("A vault write could not be confirmed. Unlock again to reload the saved history.")]
    UnconfirmedWrite,
    #[error("Could not reach the other device. Check the connection and try again.")]
    Network,
    #[error("The pairing code expired. Start pairing again.")]
    PairingExpired,
    #[error("A device tried an incorrect pairing code. Start again with a new code.")]
    PairingCodeMismatch,
    #[error("That approval is no longer available. Ask the other device to try again.")]
    ApprovalUnavailable,
    #[error("Deadbolt could not complete the operation. Lock and unlock it again.")]
    Internal,
}

impl From<deadbolt_store::Error> for MobileError {
    fn from(error: deadbolt_store::Error) -> Self {
        match error {
            deadbolt_store::Error::InUse => Self::Busy,
            deadbolt_store::Error::WrongPassphrase | deadbolt_store::Error::InvalidBiometric => {
                Self::Authentication
            }
            deadbolt_store::Error::AlreadyExists(_) => Self::AlreadyInitialized,
            deadbolt_store::Error::AppendUncertain(_) => Self::UnconfirmedWrite,
            _ => Self::Storage,
        }
    }
}
impl From<deadbolt_net::Error> for MobileError {
    fn from(error: deadbolt_net::Error) -> Self {
        match error {
            deadbolt_net::Error::PairingExpired => Self::PairingExpired,
            deadbolt_net::Error::PairingCodeMismatch => Self::PairingCodeMismatch,
            _ => Self::Network,
        }
    }
}
impl From<deadbolt_net::application::Error> for MobileError {
    fn from(_: deadbolt_net::application::Error) -> Self {
        Self::InvalidVault
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
enum Request {
    Status,
    JoinStart {
        passphrase: Zeroizing<String>,
    },
    JoinStatus,
    JoinCancel,
    Unlock {
        passphrase: Zeroizing<String>,
    },
    Lock,
    Sync,
    Items {
        #[serde(default)]
        query: String,
    },
    Item {
        id: String,
    },
    Secret {
        id: String,
        field: String,
    },
    Code {
        id: String,
    },
}

struct Task<T = ()>(JoinHandle<T>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

enum JoinState {
    Idle,
    Waiting,
    Joined,
    Error(String),
}

struct State {
    cancel: CancellationToken,
    setup: bool,
    session: Option<Arc<Session>>,
    join: JoinState,
    join_task: Option<Task>,
    sync_task: Option<Task>,
    closing: Vec<Task>,
}

impl State {
    fn retire_tasks(&mut self) {
        self.closing.retain(|task| !task.0.is_finished());
        self.closing.extend(self.join_task.take());
        self.closing.extend(self.sync_task.take());
    }
}

struct Device {
    path: PathBuf,
    name: String,
    state: Mutex<State>,
    // File opening/KDF work is serialized independently of lock and network.
    // A cancelled blocking KDF may finish, but cannot publish an unlocked state.
    disk: Arc<Mutex<()>>,
}

#[derive(uniffi::Object)]
pub struct MobileDevice {
    device: Arc<Device>,
    runtime: Option<Runtime>,
}

#[uniffi::export]
impl MobileDevice {
    #[uniffi::constructor]
    pub fn new(path: String, name: String) -> Result<Arc<Self>> {
        let name = deadbolt_net::application::clean_name(&name);
        if path.is_empty() || name.is_empty() {
            return Err(MobileError::InvalidRequest);
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| MobileError::Internal)?;
        Ok(Arc::new(Self {
            device: Arc::new(Device {
                path: path.into(),
                name,
                state: Mutex::new(State {
                    cancel: CancellationToken::new(),
                    setup: false,
                    session: None,
                    join: JoinState::Idle,
                    join_task: None,
                    sync_task: None,
                    closing: Vec::new(),
                }),
                disk: Arc::new(Mutex::new(())),
            }),
            runtime: Some(runtime),
        }))
    }

    /// Successful calls return `{ "ok": true, ... }`; failures throw a typed
    /// MobileError through UniFFI. No `{ok:false}` responses are returned.
    pub fn call(&self, request: String) -> Result<String> {
        let request = Zeroizing::new(request);
        if request.len() > 64 * 1024 {
            return Err(MobileError::InvalidRequest);
        }
        let request: Request =
            serde_json::from_str(&request).map_err(|_| MobileError::InvalidRequest)?;
        let result = match request {
            Request::Lock | Request::JoinCancel => { self.device.lock(); json!({"ok": true}) }
            Request::Status => self.device.status()?,
            Request::JoinStatus => {
                let state = self.device.state.lock().map_err(|_| MobileError::Internal)?;
                match &state.join {
                    JoinState::Waiting => json!({"ok":true,"state":"waiting"}),
                    JoinState::Joined => json!({"ok":true,"state":"joined"}),
                    JoinState::Error(error) => json!({"ok":true,"state":"error","error":error}),
                    JoinState::Idle => json!({"ok":true,"state":"error","error":"No pairing is running."}),
                }
            }
            Request::JoinStart { passphrase } => {
                if passphrase.is_empty() { return Err(MobileError::InvalidRequest); }
                self.runtime()?.block_on(self.device.clone().join(passphrase))?
            }
            Request::Unlock { passphrase } => {
                self.runtime()?.block_on(self.device.clone().unlock(Unlock::Passphrase(passphrase)))?;
                json!({"ok":true})
            }
            Request::Sync => {
                let session = self.device.session()?;
                self.runtime()?.block_on(session.sync())?;
                json!({"ok":true})
            }
            Request::Items { query } => return self.device.session()?.handler.with(|s| items(&s.vault, &query)),
            Request::Item { id } => self.device.session()?.handler.with(|s| {
                let item = find(s, &id)?;
                Ok(json!({"ok":true,"id":id,"title":listing::label(&item),"username":autofill::value(&item,"username").unwrap_or_default(),"url":autofill::value(&item,"url").unwrap_or_default(),"has_password":autofill::value(&item,"password").is_some(),"has_otp":autofill::otp(&item).is_some()}))
            })?,
            Request::Secret { id, field } => return self.device.session()?.handler.with(|s| {
                // This first native surface exposes login passwords only; never
                // turn a field selector into passkey/private-key export.
                let item = find(s, &id)?;
                if item.kind != "login" || field != "password" { return Err(MobileError::InvalidRequest); }
                let value = autofill::value(&item, "password").ok_or(MobileError::NotFound)?;
                #[derive(Serialize)]
                struct Reply<'a> { ok: bool, value: &'a str }
                serde_json::to_string(&Reply { ok: true, value }).map_err(|_| MobileError::Internal)
            }),
            Request::Code { id } => return self.device.session()?.handler.with(|s| {
                let item = find(s, &id)?;
                let field = autofill::otp(&item).ok_or(MobileError::NotFound)?;
                let totp = Totp::parse(&field.value).map_err(|_| MobileError::InvalidRequest)?;
                let time = now()?;
                let code = Zeroizing::new(totp.code(time));
                #[derive(Serialize)]
                struct Reply<'a> { ok: bool, code: &'a str, remaining: u64, period: u64 }
                serde_json::to_string(&Reply { ok:true, code: &code, remaining:totp.valid_until(time)-time, period:totp.period() }).map_err(|_| MobileError::Internal)
            }),
        };
        serde_json::to_string(&result).map_err(|_| MobileError::Internal)
    }

    /// Call off the UI thread when the app enters foreground. On iOS this
    /// runs a normal vault sync while unlocked, without forcing a network
    /// refresh or rebind. It never unlocks the store; a locked device is a no-op.
    /// Lock cancels an in-flight sync.
    pub fn foreground(&self) -> Result<()> {
        #[cfg(target_os = "ios")]
        match self.device.session() {
            Ok(session) => self.runtime()?.block_on(session.sync()),
            Err(MobileError::Locked) => Ok(()),
            Err(error) => Err(error),
        }
        #[cfg(not(target_os = "ios"))]
        Ok(())
    }

    /// Secret-free identity publication for the app, using its existing store
    /// owner. Do not open a provider while the app's session owns redb.
    pub fn credential_identities(&self) -> Result<String> {
        self.device.session()?.handler.with(|s| {
            serde_json::to_string(&provider::identities(&s.vault))
                .map_err(|_| MobileError::Internal)
        })
    }

    /// `key` is a fresh random 32-byte wrapping key protected by the platform's
    /// cryptographic biometric gate. `token` is its opaque public wrapper.
    pub fn biometric_enroll(&self, key: Vec<u8>, token: Vec<u8>) -> Result<()> {
        let key = Zeroizing::new(key);
        let key: &[u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| MobileError::InvalidRequest)?;
        if token.is_empty() || token.len() > 16 * 1024 {
            return Err(MobileError::InvalidRequest);
        }
        self.device
            .session()?
            .handler
            .with(|s| Ok(s.store.set_biometric(key, &token)?))
    }

    pub fn biometric_token(&self) -> Result<Vec<u8>> {
        if let Ok(session) = self.device.session() {
            return session
                .handler
                .with(|s| Ok(s.store.biometric_token()?.unwrap_or_default()));
        }
        let _disk = self.device.disk.lock().map_err(|_| MobileError::Internal)?;
        Ok(deadbolt_store::biometric_token(&self.device.path)?.unwrap_or_default())
    }

    pub fn unlock_biometric(&self, key: Vec<u8>) -> Result<()> {
        let key = Zeroizing::new(key);
        if key.len() != 32 {
            return Err(MobileError::InvalidRequest);
        }
        self.runtime()?
            .block_on(self.device.clone().unlock(Unlock::Biometric(key)))
    }

    /// One pending signed Read, or None while locked/not ready/expired. Fields:
    /// id, origin (hex), expires_at (Unix seconds), vault, item, field, title,
    /// origin_name, caller. Caller describes the verified CLI socket peer;
    /// ancestry and claimed session hints are not a verified initiating app.
    pub fn approval_pending(&self) -> Option<String> {
        let session = self.device.session().ok()?;
        // The inbox's predicate takes the loaded-state mutex itself.
        let pending = session.approvals.pending()?;
        Some(
            json!({
                "id": pending.id,
                "origin": data_encoding::HEXLOWER.encode(&pending.origin),
                "expires_at": pending.expires_at,
                "vault": pending.scope.vault,
                "item": pending.scope.item,
                "field": pending.scope.field,
                "title": pending.scope.title,
                "origin_name": pending.scope.origin_name,
                "caller": pending.scope.caller,
            })
            .to_string(),
        )
    }

    /// Allow requires a fresh OS-gated wrapping key for the displayed request.
    /// Deny needs no biometric key (pass an empty vector). Neither decision
    /// exports a seed or persists a grant.
    pub fn approval_respond(&self, id: String, allow: bool, biometric_key: Vec<u8>) -> Result<()> {
        let key = Zeroizing::new(biometric_key);
        self.device.session()?.approval_respond(&id, allow, &key)
    }
}

impl MobileDevice {
    fn runtime(&self) -> Result<&Runtime> {
        self.runtime.as_ref().ok_or(MobileError::Internal)
    }
}

impl Drop for MobileDevice {
    fn drop(&mut self) {
        self.device.lock();
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

enum Unlock {
    Passphrase(Zeroizing<String>),
    Biometric(Zeroizing<Vec<u8>>),
}

impl Device {
    fn session(&self) -> Result<Arc<Session>> {
        let state = self.state.lock().map_err(|_| MobileError::Internal)?;
        state
            .session
            .as_ref()
            .filter(|s| !s.cancel.is_cancelled())
            .cloned()
            .ok_or(MobileError::Locked)
    }

    fn lock(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.cancel.cancel();
        if let Some(session) = state.session.take() {
            session.lock();
        }
        // Keep ownership while cancelled tasks execute their explicit network
        // shutdown. Aborting them here would skip Node::shutdown entirely.
        state.retire_tasks();
        state.setup = false;
        state.join = JoinState::Idle;
        state.cancel = CancellationToken::new();
    }

    fn status(&self) -> Result<Value> {
        let session = self.session().ok();
        let initialized = deadbolt_store::is_initialized(&self.path);
        let (unlocked, device_id, biometric_ready) = if let Some(session) = session {
            session.handler.with(|s| {
                Ok((
                    true,
                    Some(s.secret.device_id().to_string()),
                    s.store.biometric_token()?.is_some(),
                ))
            })?
        } else {
            // Avoid opening redb while an unlock owns it. Status must not queue
            // behind the KDF, and a setup transition is not biometric-ready.
            let biometric = if initialized {
                self.disk
                    .try_lock()
                    .ok()
                    .and_then(|_guard| deadbolt_store::biometric_token(&self.path).ok().flatten())
                    .is_some()
            } else {
                false
            };
            (false, None, biometric)
        };
        Ok(
            json!({"ok":true,"initialized":initialized,"unlocked":unlocked,"device_id":device_id,"biometric_ready":biometric_ready}),
        )
    }

    fn reserve(&self, joining: bool) -> Result<CancellationToken> {
        let mut state = self.state.lock().map_err(|_| MobileError::Internal)?;
        if state
            .session
            .as_ref()
            .is_some_and(|s| s.cancel.is_cancelled())
        {
            if let Some(session) = state.session.take() {
                session.lock();
            }
            state.retire_tasks();
            state.cancel = CancellationToken::new();
        }
        if state.setup || state.session.is_some() {
            return Err(MobileError::Busy);
        }
        state.setup = true;
        if joining {
            state.join = JoinState::Waiting;
        }
        Ok(state.cancel.clone())
    }

    fn install(&self, session: Arc<Session>, token: &CancellationToken) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| MobileError::Internal)?;
        if token.is_cancelled() {
            session.lock();
            return Err(MobileError::Cancelled);
        }
        state.session = Some(session.clone());
        state.setup = false;
        state.sync_task = Some(Task(tokio::spawn(async move {
            // Startup failure leaves local reads available; manual sync retries.
            let _result = session.sync().await;
            session.cancel.cancelled().await;
            session.lock();
            session.node.shutdown().await;
        })));
        Ok(())
    }

    async fn unlock(self: Arc<Self>, method: Unlock) -> Result<()> {
        let token = self.reserve(false)?;
        let device = self.clone();
        let check = token.clone();
        let result = async {
            let mut task = Task(tokio::task::spawn_blocking(move || {
                let _disk = device.disk.lock().map_err(|_| MobileError::Internal)?;
                if check.is_cancelled() {
                    return Err(MobileError::Cancelled);
                }
                let store = match method {
                    Unlock::Passphrase(pass) => {
                        deadbolt_store::unlock(&device.path, pass.as_bytes())?
                    }
                    Unlock::Biometric(key) => deadbolt_store::unlock_biometric(
                        &device.path,
                        key.as_slice()
                            .try_into()
                            .map_err(|_| MobileError::InvalidRequest)?,
                    )?,
                };
                if check.is_cancelled() {
                    return Err(MobileError::Cancelled);
                }
                Loaded::open(store, device.name.clone())
            }));
            let loaded = (&mut task.0).await.map_err(|_| MobileError::Internal)??;
            let session = Session::start(loaded, token.clone()).await?;
            self.install(session, &token)
        };
        let result = tokio::select! { biased; _ = token.cancelled() => Err(MobileError::Cancelled), result = result => result };
        let mut state = self.state.lock().map_err(|_| MobileError::Internal)?;
        if !token.is_cancelled() {
            state.setup = false;
        }
        result
    }

    async fn join(self: Arc<Self>, passphrase: Zeroizing<String>) -> Result<Value> {
        if deadbolt_store::is_initialized(&self.path) {
            return Err(MobileError::AlreadyInitialized);
        }
        let token = self.reserve(true)?;
        let listening = tokio::select! {
            biased;
            _ = token.cancelled() => Err(MobileError::Cancelled),
            result = join::listen(self.name.clone()) => result,
        };
        let listening = match listening {
            Ok(listening) => listening,
            Err(error) => {
                let mut state = self.state.lock().map_err(|_| MobileError::Internal)?;
                if !token.is_cancelled() {
                    state.setup = false;
                    state.join = JoinState::Error(error.to_string());
                }
                return Err(error);
            }
        };
        let code = listening.code.clone();
        let mut state = self.state.lock().map_err(|_| MobileError::Internal)?;
        if token.is_cancelled() {
            return Err(MobileError::Cancelled);
        }
        let device = self.clone();
        state.join_task = Some(Task(tokio::spawn(async move {
            let node = listening.node.clone();
            let work = async {
                listening.listener.complete(&listening.fresh).await?;
                listening.node.shutdown().await;
                let disk_device = device.clone();
                let check = token.clone();
                let mut task = Task(tokio::task::spawn_blocking(move || {
                    let _disk = disk_device.disk.lock().map_err(|_| MobileError::Internal)?;
                    if check.is_cancelled() {
                        return Err(MobileError::Cancelled);
                    }
                    let loaded = listening
                        .fresh
                        .persist(&disk_device.path, passphrase.as_bytes())?;
                    if check.is_cancelled() {
                        return Err(MobileError::Cancelled);
                    }
                    Ok(loaded)
                }));
                let loaded = (&mut task.0).await.map_err(|_| MobileError::Internal)??;
                let session = Session::start(loaded, token.clone()).await?;
                device.install(session, &token)
            };
            let result: Result<()> = tokio::select! { biased; _ = token.cancelled() => Err(MobileError::Cancelled), result = work => result };
            node.shutdown().await;
            let mut state = device.state.lock().unwrap_or_else(|e| e.into_inner());
            if !token.is_cancelled() {
                state.setup = false;
                state.join = match result {
                    Ok(()) => JoinState::Joined,
                    Err(error) => JoinState::Error(error.to_string()),
                };
            }
        })));
        Ok(json!({"ok":true,"code":code}))
    }
}

fn items(vault: &deadbolt_core::Vault, query: &str) -> Result<String> {
    #[derive(Serialize)]
    struct Row {
        id: String,
        title: String,
        username: String,
        kind: &'static str,
    }
    #[derive(Serialize)]
    struct Reply {
        ok: bool,
        items: Vec<Row>,
    }
    let query = query.trim().to_lowercase();
    let vault_id = vault.id().to_string();
    let mut items: Vec<_> = vault
        .iter_items()
        .filter(|item| item.kind == "login")
        .filter(|item| {
            query.is_empty()
                || listing::searchable(item)
                    .iter()
                    .any(|text| text.to_lowercase().contains(&query))
        })
        .map(|item| Row {
            id: format!(
                "{vault_id}:{}",
                data_encoding::HEXLOWER.encode(item.id.as_bytes())
            ),
            title: listing::label(&item),
            username: autofill::value(&item, "username")
                .unwrap_or_default()
                .to_owned(),
            kind: "login",
        })
        .collect();
    items.sort_unstable_by(|a, b| a.title.cmp(&b.title).then_with(|| a.id.cmp(&b.id)));
    serde_json::to_string(&Reply { ok: true, items }).map_err(|_| MobileError::Internal)
}

fn find(s: &Loaded, id: &str) -> Result<Item> {
    let (vault, item) = id.split_once(':').ok_or(MobileError::InvalidRequest)?;
    if vault != s.vault.id().to_string() {
        return Err(MobileError::NotFound);
    }
    let bytes: [u8; 16] = data_encoding::HEXLOWER
        .decode(item.as_bytes())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(MobileError::InvalidRequest)?;
    s.vault
        .item(&ItemId::from_bytes(bytes))
        .filter(|item| !item.deleted && item.kind == "login")
        .ok_or(MobileError::NotFound)
}

#[expect(
    clippy::disallowed_methods,
    reason = "native composition root supplies wall time only to TOTP"
)]
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| MobileError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadbolt_core::{DeviceSecret, Entry, Field, FieldType, Vault};
    use deadbolt_net::application::{Addr, Hint};
    use deadbolt_net::{Blob, HandlerError, Node, NodeConfig, Outgoing, PeerId, SyncHandler};
    use deadbolt_store::KdfParams;

    const KDF: KdfParams = KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    pub(crate) fn fixture(
        path: &std::path::Path,
        secret: &DeviceSecret,
        mut vault: Vault,
        peers: Value,
    ) -> String {
        let (item, _) = vault
            .create_item(
                secret,
                "login",
                Some("Example Account".into()),
                [
                    ("username".into(), Field::new(FieldType::Text, "alice")),
                    (
                        "password".into(),
                        Field::new(FieldType::Secret, "synthetic-mobile-password"),
                    ),
                    (
                        "url".into(),
                        Field::new(FieldType::Url, "https://example.com"),
                    ),
                    ("otp".into(), Field::new(FieldType::Otp, "JBSWY3DPEHPK3PXP")),
                ],
            )
            .unwrap();
        let entries: Vec<_> = vault.entries().into_iter().map(Entry::encode).collect();
        let peers = serde_json::to_vec(&peers).unwrap();
        let store = deadbolt_store::init_with_setup(
            path,
            b"local-pass",
            *secret.to_bytes(),
            KDF,
            |store| {
                store.append_batch(entries.iter().map(|entry| entry.as_slice()))?;
                store.meta_set(session::PEERS, &peers)?;
                Ok(())
            },
        )
        .unwrap();
        drop(store);
        format!("{}:{item}", vault.id())
    }

    fn call(device: &MobileDevice, value: Value) -> Value {
        serde_json::from_str(&device.call(value.to_string()).unwrap()).unwrap()
    }

    #[test]
    fn local_reads_persist_and_biometrics_require_the_wrapping_key() {
        let dir = tempfile::tempdir().unwrap();
        let secret = DeviceSecret::generate();
        let (vault, _) = Vault::create(&secret, "mobile-test").unwrap();
        let id = fixture(dir.path(), &secret, vault, json!({}));
        let device = MobileDevice::new(dir.path().display().to_string(), "Phone".into()).unwrap();
        assert_eq!(call(&device, json!({"op":"status"}))["unlocked"], false);
        assert!(matches!(
            device.credential_identities(),
            Err(MobileError::Locked)
        ));
        assert!(matches!(
            device.call(json!({"op":"items"}).to_string()),
            Err(MobileError::Locked)
        ));
        assert!(matches!(
            device.call(json!({"op":"unlock","passphrase":"wrong"}).to_string()),
            Err(MobileError::Authentication)
        ));
        // An offline provider can own the real store while the app is locked.
        // Contention must stay retryable and must not publish an app session.
        let provider_store = deadbolt_store::unlock(dir.path(), b"local-pass").unwrap();
        let blocked = device.call(json!({"op":"unlock","passphrase":"local-pass"}).to_string());
        assert!(matches!(blocked, Err(MobileError::Busy)), "{blocked:?}");
        let locked = call(&device, json!({"op":"status"}));
        assert_eq!(locked["unlocked"], false);
        assert!(locked["device_id"].is_null());
        assert!(matches!(
            device.call(json!({"op":"items"}).to_string()),
            Err(MobileError::Locked)
        ));
        assert!(matches!(
            device.credential_identities(),
            Err(MobileError::Locked)
        ));
        drop(provider_store);
        call(&device, json!({"op":"unlock","passphrase":"local-pass"}));
        let identities = device.credential_identities().unwrap();
        assert!(!identities.contains("synthetic-mobile-password"));
        assert!(!identities.contains("JBSWY3DPEHPK3PXP"));
        let identities: Value = serde_json::from_str(&identities).unwrap();
        assert_eq!(identities["passwords"][0]["record_id"], id);
        assert_eq!(identities["one_time_codes"][0]["record_id"], id);
        assert!(matches!(
            deadbolt_store::unlock(dir.path(), b"local-pass"),
            Err(deadbolt_store::Error::InUse)
        ));
        let status = call(&device, json!({"op":"status"}));
        assert_eq!(status["device_id"], secret.device_id().to_string());
        for query in [" ALICE ", "example account", "eXaMpLe AcCoUnT"] {
            assert_eq!(
                call(&device, json!({"op":"items","query":query})),
                json!({"ok": true, "items":[{"id":id, "title":"Example Account", "username":"alice", "kind":"login"}]})
            );
        }
        assert_eq!(
            call(
                &device,
                json!({"op":"items","query":"synthetic-mobile-password"})
            )["items"],
            json!([])
        );
        let detail = call(&device, json!({"op":"item","id":id}));
        assert_eq!(detail["has_password"], true);
        assert!(!detail.to_string().contains("synthetic-mobile-password"));
        assert_eq!(
            call(&device, json!({"op":"secret","id":id,"field":"password"}))["value"],
            "synthetic-mobile-password"
        );
        let code = call(&device, json!({"op":"code","id":id}));
        assert_eq!(code["code"].as_str().unwrap().len(), 6);
        assert!((1..=30).contains(&code["remaining"].as_u64().unwrap()));
        device.biometric_enroll(vec![42; 32], vec![5; 64]).unwrap();
        call(&device, json!({"op":"lock"}));
        assert_eq!(device.biometric_token().unwrap(), vec![5; 64]);
        assert!(matches!(
            device.unlock_biometric(vec![43; 32]),
            Err(MobileError::Authentication)
        ));
        device.unlock_biometric(vec![42; 32]).unwrap();
        assert_eq!(
            call(&device, json!({"op":"items"}))["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        drop(device);
        let device = MobileDevice::new(dir.path().display().to_string(), "Phone".into()).unwrap();
        assert_eq!(call(&device, json!({"op":"status"}))["unlocked"], false);
        call(&device, json!({"op":"unlock","passphrase":"local-pass"}));
        assert_eq!(
            call(&device, json!({"op":"status"}))["device_id"],
            status["device_id"]
        );
    }

    #[test]
    fn lock_cancels_an_established_stalled_sync_without_blocking_reads() {
        #[derive(Clone)]
        struct Stalled(Arc<tokio::sync::Notify>);
        impl SyncHandler for Stalled {
            async fn heads(&self, _: PeerId) -> std::result::Result<Vec<u8>, HandlerError> {
                self.0.notify_one();
                std::future::pending().await
            }
            async fn missing_for(
                &self,
                _: PeerId,
                _: Vec<u8>,
            ) -> std::result::Result<Outgoing<'_>, HandlerError> {
                std::future::pending().await
            }
            async fn receive(
                &self,
                _: PeerId,
                _: Vec<Blob>,
            ) -> std::result::Result<(), HandlerError> {
                std::future::pending().await
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let secret = DeviceSecret::generate();
        let other = DeviceSecret::generate();
        let (mut vault, _) = Vault::create(&secret, "mobile-test").unwrap();
        vault
            .add(
                &secret,
                other.device_id(),
                other.join_consent(&vault.id(), &secret.device_id()),
            )
            .unwrap();
        let device = MobileDevice::new(dir.path().display().to_string(), "Phone".into()).unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let remote = device
            .runtime()
            .unwrap()
            .block_on(Node::spawn(
                NodeConfig::local_only(*other.to_bytes()),
                Arc::new(|_: &PeerId| true),
                Stalled(entered.clone()),
            ))
            .unwrap();
        let hint = Hint {
            name: Some("Stalled".into()),
            addr: Some(Addr::from_peer(remote.addr())),
            addr_seen: 0,
        };
        fixture(
            dir.path(),
            &secret,
            vault,
            json!({other.device_id().to_string():hint}),
        );
        call(&device, json!({"op":"unlock","passphrase":"local-pass"}));
        device
            .runtime()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified()).await
            })
            .unwrap();
        assert_eq!(
            call(&device, json!({"op":"items"}))["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let session = device.device.session().unwrap();
        let start = std::time::Instant::now();
        call(&device, json!({"op":"lock"}));
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
        assert!(session.cancel.is_cancelled());
        assert!(matches!(
            device.runtime().unwrap().block_on(session.sync()),
            Err(MobileError::Cancelled)
        ));
        assert!(matches!(
            session.handler.with(|_| Ok(())),
            Err(MobileError::Locked)
        ));
        // Keep `session` (and its Node) alive: dropping the last Node clone
        // cannot mask a missing explicit shutdown path.
        let closing = std::mem::take(&mut device.device.state.lock().unwrap().closing);
        assert_eq!(closing.len(), 1);
        device.runtime().unwrap().block_on(async {
            for mut task in closing {
                tokio::time::timeout(std::time::Duration::from_secs(5), &mut task.0)
                    .await
                    .unwrap()
                    .unwrap();
            }
        });
        device.runtime().unwrap().block_on(remote.shutdown());
    }

    #[test]
    fn cancelled_setup_cannot_publish_and_failed_setup_stays_uninitialized() {
        let dir = tempfile::tempdir().unwrap();
        let result = deadbolt_store::init_with_setup(dir.path(), b"local", [7; 32], KDF, |_| {
            Err(deadbolt_store::Error::InvalidBiometric)
        });
        assert!(result.is_err());
        assert!(!deadbolt_store::is_initialized(dir.path()));
        let device = MobileDevice::new(dir.path().display().to_string(), "Phone".into()).unwrap();
        let token = device.device.reserve(true).unwrap();
        device.device.lock();
        assert!(token.is_cancelled());
        let newer = device.device.reserve(true).unwrap();
        assert!(!newer.is_cancelled());
        assert!(matches!(
            device.device.reserve(false),
            Err(MobileError::Busy)
        ));
        device.device.lock();
        assert!(!deadbolt_store::is_initialized(dir.path()));
    }

    #[test]
    fn an_unlock_crossing_lock_cannot_restore_the_session() {
        let dir = tempfile::tempdir().unwrap();
        let secret = DeviceSecret::generate();
        let (vault, _) = Vault::create(&secret, "mobile-test").unwrap();
        fixture(dir.path(), &secret, vault, json!({}));
        let device = MobileDevice::new(dir.path().display().to_string(), "Phone".into()).unwrap();
        // Hold the file/KDF lane, not the lifecycle lock: cancellation must not
        // wait for a blocking operation, nor let its late result revive keys.
        let disk = device.device.disk.lock().unwrap();
        let pending = device.clone();
        let thread = std::thread::spawn(move || {
            pending.call(json!({"op":"unlock","passphrase":"local-pass"}).to_string())
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !device.device.state.lock().unwrap().setup {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        call(&device, json!({"op":"lock"}));
        assert!(matches!(
            thread.join().unwrap(),
            Err(MobileError::Cancelled)
        ));
        drop(disk);
        assert_eq!(call(&device, json!({"op":"status"}))["unlocked"], false);
        call(&device, json!({"op":"unlock","passphrase":"local-pass"}));
        assert_eq!(call(&device, json!({"op":"status"}))["unlocked"], true);
        // Completion may win just before lock. Its durable store survives,
        // but neither its published session nor a retained Session can read.
        let session = device.device.session().unwrap();
        call(&device, json!({"op":"lock"}));
        let status = call(&device, json!({"op":"status"}));
        assert_eq!(status["initialized"], true);
        assert_eq!(status["unlocked"], false);
        assert!(matches!(
            session.handler.with(|_| Ok(())),
            Err(MobileError::Locked)
        ));
        assert!(matches!(
            device.call(json!({"op":"items"}).to_string()),
            Err(MobileError::Locked)
        ));
    }

    #[test]
    fn approvals_require_fresh_slot_unwrap_and_lock_revokes_pending() {
        use deadbolt_core::DeviceId;
        use deadbolt_net::application::RoundState;
        use deadbolt_net::approval::ReadScope;

        struct NoSync;
        impl SyncHandler for NoSync {
            async fn heads(&self, _: PeerId) -> std::result::Result<Vec<u8>, HandlerError> {
                Err("synthetic approval-only node".into())
            }
            async fn missing_for(
                &self,
                _: PeerId,
                _: Vec<u8>,
            ) -> std::result::Result<Outgoing<'_>, HandlerError> {
                Err("synthetic approval-only node".into())
            }
            async fn receive(
                &self,
                _: PeerId,
                _: Vec<Blob>,
            ) -> std::result::Result<(), HandlerError> {
                Err("synthetic approval-only node".into())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let origin_key = DeviceSecret::generate();
        let phone_key = DeviceSecret::generate();
        let (mut vault, _) = Vault::create(&origin_key, "approval-fixture").unwrap();
        vault
            .add(
                &origin_key,
                phone_key.device_id(),
                phone_key.join_consent(&vault.id(), &origin_key.device_id()),
            )
            .unwrap();
        let phone = MobileDevice::new(dir.path().display().to_string(), "Phone".into()).unwrap();
        let peer = *phone_key.device_id().as_bytes();
        let origin = phone
            .runtime()
            .unwrap()
            .block_on(Node::spawn(
                NodeConfig::local_only(*origin_key.to_bytes()),
                Arc::new(move |id: &PeerId| *id == peer),
                NoSync,
            ))
            .unwrap();
        let hint = Hint {
            name: Some("Synthetic CLI".into()),
            addr: Some(Addr::from_peer(origin.addr())),
            addr_seen: 0,
        };
        let id = fixture(
            dir.path(),
            &phone_key,
            vault,
            json!({origin_key.device_id().to_string():hint}),
        );
        let (vault, item) = id.split_once(':').unwrap();
        let scope = ReadScope {
            vault: vault.into(),
            item: item.into(),
            field: "password".into(),
            title: "Synthetic account".into(),
            origin_name: "Synthetic CLI".into(),
            caller: "verified CLI peer; unverified ancestry/session hints".into(),
        };
        call(&phone, json!({"op":"unlock","passphrase":"local-pass"}));
        phone.biometric_enroll(vec![42; 32], vec![5; 64]).unwrap();
        let session = phone.device.session().unwrap();
        assert!(!session.handler.ready().unwrap());
        // A transport member cannot submit metadata before startup readiness.
        assert!(
            phone
                .runtime()
                .unwrap()
                .block_on(origin.request_read_approval(session.node.addr(), scope.clone(), || true))
                .is_err()
        );
        assert!(phone.approval_pending().is_none());
        session
            .handler
            .publish_ready(Addr::from_peer(session.node.addr()))
            .unwrap();
        let mut wrong_vault = scope.clone();
        wrong_vault.vault = "01".repeat(32);
        assert!(
            phone
                .runtime()
                .unwrap()
                .block_on(origin.request_read_approval(session.node.addr(), wrong_vault, || true))
                .is_err()
        );

        for attempt in 0..3 {
            let request = origin.request_read_approval(session.node.addr(), scope.clone(), || true);
            let act = async {
                let pending: Value = loop {
                    if let Some(value) = phone.approval_pending() {
                        break serde_json::from_str(&value).unwrap();
                    }
                    tokio::task::yield_now().await;
                };
                assert_eq!(pending["caller"], scope.caller);
                let id = pending["id"].as_str().unwrap().to_owned();
                if attempt == 0 {
                    assert!(matches!(
                        phone.approval_respond(id.clone(), true, vec![43; 32]),
                        Err(MobileError::Authentication)
                    ));
                    assert!(phone.approval_pending().is_some());
                    // Replace only the cached signing key with another current
                    // member. Success must still sign as the phone: only a
                    // fresh biometric-slot unwrap can provide that seed now.
                    session
                        .handler
                        .with(|s| {
                            s.secret = DeviceSecret::from_bytes(&origin_key.to_bytes());
                            Ok(())
                        })
                        .unwrap();
                    phone
                        .approval_respond(id.clone(), true, vec![42; 32])
                        .unwrap();
                    session
                        .handler
                        .with(|s| {
                            s.secret = DeviceSecret::from_bytes(&phone_key.to_bytes());
                            Ok(())
                        })
                        .unwrap();
                    assert!(matches!(
                        phone.approval_respond(id, true, vec![42; 32]),
                        Err(MobileError::ApprovalUnavailable)
                    ));
                } else if attempt == 1 {
                    phone.approval_respond(id, false, Vec::new()).unwrap();
                } else {
                    call(&phone, json!({"op":"lock"}));
                    assert!(matches!(
                        phone.approval_respond(id, true, vec![42; 32]),
                        Err(MobileError::Locked)
                    ));
                    assert!(phone.approval_pending().is_none());
                }
            };
            let (answer, ()) = phone.runtime().unwrap().block_on(async {
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    tokio::join!(request, act)
                })
                .await
                .unwrap()
            });
            if attempt == 0 {
                answer
                    .unwrap()
                    .consume(&scope, phone_key.device_id().as_bytes())
                    .unwrap();
            } else {
                assert!(answer.is_err());
            }
        }
        assert!(
            !session
                .handler
                .with(|s| Ok(s.vault.is_member(&DeviceId::from_bytes(peer))))
                .unwrap_or(false)
        );
        let closing = std::mem::take(&mut phone.device.state.lock().unwrap().closing);
        phone.runtime().unwrap().block_on(async {
            for mut task in closing {
                tokio::time::timeout(std::time::Duration::from_secs(5), &mut task.0)
                    .await
                    .unwrap()
                    .unwrap();
            }
            origin.shutdown().await;
        });
    }

    /// Synthetic-only fixture for the real CLI/mobile integration lanes. No
    /// production command or caller guard changes. Refuses an existing path.
    /// Set DEADBOLT_MOBILE_FIXTURE_DIR to an absolute, absent directory named
    /// deadbolt-mobile-fixture-1000 or deadbolt-mobile-fixture-10000 and set
    /// DEADBOLT_MOBILE_FIXTURE_COUNT to the corresponding count. Local pass:
    /// synthetic-mobile-fixture-passphrase (deliberately public test data).
    #[test]
    #[ignore = "explicit synthetic CLI fixture output directory required"]
    fn seed_synthetic_cli_store() {
        use deadbolt_core::DataOp;
        let path = PathBuf::from(
            std::env::var_os("DEADBOLT_MOBILE_FIXTURE_DIR")
                .expect("set DEADBOLT_MOBILE_FIXTURE_DIR"),
        );
        let count: usize = std::env::var_os("DEADBOLT_MOBILE_FIXTURE_COUNT")
            .expect("set DEADBOLT_MOBILE_FIXTURE_COUNT")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!([1_000, 10_000].contains(&count));
        assert!(
            path.is_absolute() && !path.exists(),
            "fixture directory must be absolute and absent"
        );
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            format!("deadbolt-mobile-fixture-{count}")
        );
        let key = DeviceSecret::generate();
        let (mut vault, _) = Vault::create(&key, "mobile-fixture").unwrap();
        vault
            .create_items(
                &key,
                (0..count).map(|n| {
                    DataOp::create(
                        "login",
                        Some(format!("Synthetic account {n:05}")),
                        [
                            (
                                "username".into(),
                                Field::new(
                                    FieldType::Text,
                                    format!("synthetic-{n:05}@example.test"),
                                ),
                            ),
                            (
                                "password".into(),
                                Field::new(FieldType::Secret, format!("synthetic-password-{n:05}")),
                            ),
                            (
                                "url".into(),
                                Field::new(
                                    FieldType::Url,
                                    format!("https://site-{n:05}.example.test"),
                                ),
                            ),
                            ("otp".into(), Field::new(FieldType::Otp, "JBSWY3DPEHPK3PXP")),
                        ],
                    )
                }),
            )
            .unwrap();
        let entries: Vec<_> = vault.entries().into_iter().map(Entry::encode).collect();
        let default = serde_json::to_vec(&vault.id().to_string()).unwrap();
        let store = deadbolt_store::init_with_setup(
            &path,
            b"synthetic-mobile-fixture-passphrase",
            *key.to_bytes(),
            KdfParams::DEFAULT,
            |store| {
                store.append_batch(entries.iter().map(|entry| entry.as_slice()))?;
                store.meta_set("cli/device-name", br#""Synthetic fixture CLI""#)?;
                store.meta_set("cli/default-vault", &default)?;
                store.meta_set("cli/peers", b"{}")?;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            deadbolt_net::application::storage::load(&store)
                .unwrap()
                .items()
                .len(),
            count
        );
        println!("Created {count} synthetic logins in {}", path.display());
    }

    #[test]
    #[ignore = "uses public pairing rendezvous and relays"]
    fn real_pairing_admits_a_distinct_device_and_syncs_after_restart() {
        use deadbolt_core::DeviceId;
        use deadbolt_net::application::{self, State};
        use deadbolt_net::{Inviter, PairingCode, PairingContext, PairingOptions};

        // The inviter is the exact shared application path used by CLI pair,
        // with a synthetic store. No CLI caller policy is bypassed.
        struct Existing(Arc<Session>);
        impl Inviter for Existing {
            async fn offer(
                &self,
                ctx: &PairingContext,
            ) -> std::result::Result<Vec<u8>, HandlerError> {
                self.0
                    .handler
                    .with(|s| {
                        Ok(application::offer(
                            s,
                            s.vault.id(),
                            &DeviceId::from_bytes(ctx.remote),
                            Some(Addr::from_peer(self.0.node.addr())),
                        )?)
                    })
                    .map_err(|e| e.to_string().into())
            }
            async fn welcome(
                &self,
                ctx: &PairingContext,
                bytes: Vec<u8>,
            ) -> std::result::Result<Outgoing<'_>, HandlerError> {
                let history = self.0.handler.with(|s| {
                    application::welcome(
                        s,
                        s.vault.id(),
                        DeviceId::from_bytes(ctx.remote),
                        &bytes,
                        None,
                    )
                })?;
                Ok(self.0.handler.stream(history))
            }
        }

        let source_dir = tempfile::tempdir().unwrap();
        let phone_dir = tempfile::tempdir().unwrap();
        let secret = DeviceSecret::generate();
        let (vault, _) = Vault::create(&secret, "pairing-fixture").unwrap();
        let id = fixture(source_dir.path(), &secret, vault, json!({}));
        let source = MobileDevice::new(
            source_dir.path().display().to_string(),
            "Existing device".into(),
        )
        .unwrap();
        let phone =
            MobileDevice::new(phone_dir.path().display().to_string(), "Phone".into()).unwrap();
        call(&source, json!({"op":"unlock","passphrase":"local-pass"}));
        let start = call(
            &phone,
            json!({"op":"join-start","passphrase":"separate phone passphrase"}),
        );
        let code: PairingCode = start["code"].as_str().unwrap().parse().unwrap();
        assert_eq!(start["code"].as_str().unwrap().split('-').count(), 5);
        let existing = Existing(source.device.session().unwrap());
        source
            .runtime()
            .unwrap()
            .block_on(
                existing
                    .0
                    .node
                    .pair(&code, PairingOptions::default(), &existing),
            )
            .unwrap();
        let mut pending = phone.device.state.lock().unwrap().join_task.take().unwrap();
        phone.runtime().unwrap().block_on(&mut pending.0).unwrap();
        assert_eq!(call(&phone, json!({"op":"join-status"}))["state"], "joined");
        let phone_id = call(&phone, json!({"op":"status"}))["device_id"].clone();
        assert_ne!(phone_id, secret.device_id().to_string());
        assert_eq!(
            existing
                .0
                .handler
                .with(|s| Ok(s.vault.members().count()))
                .unwrap(),
            2
        );
        assert_eq!(
            call(&phone, json!({"op":"items"}))["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            call(&phone, json!({"op":"secret","id":id,"field":"password"}))["value"],
            "synthetic-mobile-password"
        );
        assert_eq!(
            call(&phone, json!({"op":"code","id":id}))["code"]
                .as_str()
                .unwrap()
                .len(),
            6
        );
        call(&phone, json!({"op":"sync"}));
        phone.foreground().unwrap();
        call(&phone, json!({"op":"lock"}));
        phone.foreground().unwrap();
        assert_eq!(call(&phone, json!({"op":"status"}))["unlocked"], false);
        existing
            .0
            .handler
            .with(|s| {
                s.update(s.vault.id(), |vault, key| {
                    vault.create_item(
                        key,
                        "login",
                        Some("While phone locked".into()),
                        [(
                            "password".into(),
                            Field::new(FieldType::Secret, "synthetic-offline-value"),
                        )],
                    )?;
                    Ok(())
                })
            })
            .unwrap();
        drop(phone);
        let phone =
            MobileDevice::new(phone_dir.path().display().to_string(), "Phone".into()).unwrap();
        assert_eq!(call(&phone, json!({"op":"status"}))["unlocked"], false);
        call(
            &phone,
            json!({"op":"unlock","passphrase":"separate phone passphrase"}),
        );
        call(&phone, json!({"op":"sync"}));
        assert_eq!(
            call(&phone, json!({"op":"items"}))["items"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(call(&phone, json!({"op":"status"}))["device_id"], phone_id);
        call(&phone, json!({"op":"lock"}));
        call(&source, json!({"op":"lock"}));
        let bytes = std::fs::read(phone_dir.path().join(deadbolt_store::DB_FILE)).unwrap();
        assert!(
            !bytes
                .windows(b"synthetic-mobile-password".len())
                .any(|w| w == b"synthetic-mobile-password")
        );
    }
}
