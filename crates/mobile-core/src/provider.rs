//! Offline, request-local credential-provider orchestration. No runtime, Node,
//! socket or retained unlocked state: each call replays the authoritative log.
//! Cancellation revokes publication immediately. Blocking KDF/replay/commit
//! cannot be interrupted mid-call; its local keys/store drop at the next check.
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use deadbolt_core::{
    DeviceSecret, Item, ItemId, Vault, autofill, credential_provider as policy, listing, passkeys,
    webauthn,
};
use deadbolt_net::application::storage;
use deadbolt_store::Unlocked;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, MobileProviderError>;

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum MobileProviderError {
    #[error("The app still has the vault open. Try again after it locks.")]
    InUse,
    #[error("A provider operation is already running for this request.")]
    Busy,
    #[error("This credential request was cancelled or completed.")]
    Cancelled,
    #[error("The passphrase or biometric key did not unlock this device.")]
    Authentication,
    #[error("Invalid credential request.")]
    InvalidRequest,
    #[error("This credential does not match the requested site or relying party.")]
    DomainMismatch,
    #[error("This credential is no longer available.")]
    NotFound,
    #[error("This request needs interactive presentation.")]
    InteractionRequired,
    #[error("This passkey ceremony needs a fresh biometric unlock.")]
    VerificationRequired,
    #[error("An excluded passkey already exists for this relying party.")]
    AlreadyExists,
    #[error("The encrypted vault is unavailable. Its files have been retained.")]
    Storage,
    #[error("The vault history or device membership is unavailable. Its files have been retained.")]
    InvalidVault,
    #[error(
        "The write could not be confirmed. Start a new request to reload the vault; do not retry registration automatically."
    )]
    UnconfirmedWrite,
    #[error("The provider could not complete this request.")]
    Internal,
}

impl From<deadbolt_store::Error> for MobileProviderError {
    fn from(error: deadbolt_store::Error) -> Self {
        match error {
            deadbolt_store::Error::InUse => Self::InUse,
            deadbolt_store::Error::WrongPassphrase | deadbolt_store::Error::InvalidBiometric => {
                Self::Authentication
            }
            deadbolt_store::Error::AppendUncertain(_) => Self::UnconfirmedWrite,
            _ => Self::Storage,
        }
    }
}

impl From<policy::Error> for MobileProviderError {
    fn from(error: policy::Error) -> Self {
        match error {
            policy::Error::UnassociatedApp | policy::Error::InteractionRequired => {
                Self::InteractionRequired
            }
            policy::Error::VerificationUnavailable => Self::VerificationRequired,
            _ => Self::InvalidRequest,
        }
    }
}

impl From<passkeys::Error> for MobileProviderError {
    fn from(error: passkeys::Error) -> Self {
        match error {
            passkeys::Error::DomainMismatch(_) => Self::DomainMismatch,
            passkeys::Error::NotFound | passkeys::Error::Incomplete => Self::NotFound,
            passkeys::Error::Exists => Self::AlreadyExists,
            passkeys::Error::Webauthn(_) => Self::InvalidRequest,
        }
    }
}

/// Key bytes must be released by the OS cryptographic gate for this request,
/// not a cached key gated by a successful LAContext boolean. Rust proves slot
/// decryption, not how or when the host obtained the key. Never log this value.
#[derive(uniffi::Enum)]
pub enum MobileProviderAuthentication {
    Passphrase { value: String },
    Biometric { key: Vec<u8> },
}

enum Authentication {
    Passphrase(Zeroizing<String>),
    Biometric(Zeroizing<Vec<u8>>),
}

impl From<MobileProviderAuthentication> for Authentication {
    fn from(authentication: MobileProviderAuthentication) -> Self {
        match authentication {
            MobileProviderAuthentication::Passphrase { value } => {
                Self::Passphrase(Zeroizing::new(value))
            }
            MobileProviderAuthentication::Biometric { key } => Self::Biometric(Zeroizing::new(key)),
        }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ServiceKind {
    Domain,
    Url,
    App,
}

impl From<ServiceKind> for policy::ServiceKind {
    fn from(kind: ServiceKind) -> Self {
        match kind {
            ServiceKind::Domain => Self::Domain,
            ServiceKind::Url => Self::Url,
            ServiceKind::App => Self::App,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Service {
    kind: ServiceKind,
    identifier: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Verify {
    Required,
    Preferred,
    Discouraged,
}

impl From<Verify> for policy::UserVerification {
    fn from(verify: Verify) -> Self {
        match verify {
            Verify::Required => Self::Required,
            Verify::Preferred => Self::Preferred,
            Verify::Discouraged => Self::Discouraged,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
enum Request {
    Password {
        services: Vec<Service>,
        interactive: bool,
    },
    Otp {
        services: Vec<Service>,
        interactive: bool,
    },
    PasskeyGet {
        rp_id: String,
        allowed_credentials: Vec<String>,
        client_data_hash: String,
        verify: Verify,
        interactive: bool,
    },
    PasskeyCreate {
        rp_id: String,
        client_data_hash: String,
        user_id: String,
        user_name: String,
        #[serde(default)]
        user_display_name: String,
        exclude: Vec<String>,
        verify: Verify,
        interactive: bool,
    },
}

impl Request {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Password { services, .. } | Self::Otp { services, .. } => {
                if services.len() > 64 {
                    return Err(MobileProviderError::InvalidRequest);
                }
                scope(services)?;
            }
            Self::PasskeyGet {
                rp_id,
                allowed_credentials,
                client_data_hash,
                ..
            } => {
                policy::passkey_request(rp_id, allowed_credentials)?;
                webauthn::client_data_hash(client_data_hash)
                    .map_err(|_| MobileProviderError::InvalidRequest)?;
            }
            Self::PasskeyCreate {
                rp_id,
                client_data_hash,
                user_id,
                user_name,
                exclude,
                ..
            } => {
                policy::check_exclude(exclude)?;
                passkeys::check_create_hash(rp_id, client_data_hash, user_id, user_name, exclude)?;
            }
        }
        Ok(())
    }
}

struct Pending {
    id: u64,
    request: Arc<Request>,
    busy: bool,
}
#[derive(Default)]
struct State {
    next: u64,
    pending: Option<Pending>,
}

#[derive(uniffi::Object)]
pub struct MobileCredentialProvider {
    path: PathBuf,
    state: Mutex<State>,
}

#[uniffi::export]
impl MobileCredentialProvider {
    #[uniffi::constructor]
    pub fn new(path: String) -> Arc<Self> {
        Arc::new(Self {
            path: path.into(),
            state: Mutex::new(State::default()),
        })
    }

    /// Bind OS-provided service/RP/hash data before prompting for credentials.
    /// A new request invalidates every old operation, including its late result.
    pub fn begin(&self, request: String) -> Result<u64> {
        // Revoke the old request even when parsing the replacement fails.
        let id = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| MobileProviderError::Internal)?;
            state.pending = None;
            state.next = state
                .next
                .checked_add(1)
                .ok_or(MobileProviderError::Internal)?;
            state.next
        };
        let request = Zeroizing::new(request);
        if request.len() > 64 * 1024 {
            return Err(MobileProviderError::InvalidRequest);
        }
        let request: Request =
            serde_json::from_str(&request).map_err(|_| MobileProviderError::InvalidRequest)?;
        request.validate()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| MobileProviderError::Internal)?;
        if state.next != id {
            return Err(MobileProviderError::Cancelled);
        }
        state.pending = Some(Pending {
            id,
            request: Arc::new(request),
            busy: false,
        });
        Ok(id)
    }

    pub fn cancel(&self, request_id: u64) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Also revoke begin() while it parses outside the lock.
        if state.next == request_id {
            state.pending = None;
            state.next = state.next.saturating_add(1);
        }
    }

    pub fn biometric_token(&self, request_id: u64) -> Result<Vec<u8>> {
        let operation = self.reserve(request_id)?;
        let token = deadbolt_store::biometric_token(&self.path)?
            .ok_or(MobileProviderError::Authentication)?;
        operation.check()?;
        Ok(token)
    }

    /// Returns only picker metadata, never a password, OTP seed or private key.
    /// The store closes before returning; completion reopens and rechecks it.
    pub fn list(
        &self,
        request_id: u64,
        authentication: MobileProviderAuthentication,
    ) -> Result<String> {
        let authentication = Authentication::from(authentication);
        self.run(request_id, authentication, false, |operation, opened| {
            let reply = opened.list(&operation.request)?;
            encode(&reply)
        })
    }

    /// Completes once. Use `vault:item` for fill/assertion, None for registration.
    /// Native code must check its generation again before completing the OS
    /// request: cancellation can occur after this method returns through FFI.
    pub fn complete(
        &self,
        request_id: u64,
        record_id: Option<String>,
        authentication: MobileProviderAuthentication,
    ) -> Result<String> {
        let authentication = Authentication::from(authentication);
        self.run(request_id, authentication, true, |operation, opened| {
            opened.complete(operation, record_id.as_deref())
        })
    }
}

impl MobileCredentialProvider {
    fn reserve(&self, id: u64) -> Result<Operation<'_>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MobileProviderError::Internal)?;
        let pending = state
            .pending
            .as_mut()
            .filter(|p| p.id == id)
            .ok_or(MobileProviderError::Cancelled)?;
        if pending.busy {
            return Err(MobileProviderError::Busy);
        }
        pending.busy = true;
        Ok(Operation {
            owner: self,
            id,
            request: pending.request.clone(),
        })
    }

    fn run(
        &self,
        id: u64,
        authentication: Authentication,
        terminal: bool,
        work: impl FnOnce(&Operation<'_>, &mut Opened) -> Result<Zeroizing<String>>,
    ) -> Result<String> {
        let operation = self.reserve(id)?;
        let result = (|| {
            let mut opened = Opened::open(&self.path, &authentication)?;
            operation.check()?;
            let response = work(&operation, &mut opened);
            // Close before publication, on both success and every error. No
            // derived state is retained, including after an uncertain append.
            drop(opened);
            drop(authentication);
            operation.check()?;
            response
        })();
        if matches!(
            result,
            Err(MobileProviderError::UnconfirmedWrite | MobileProviderError::InvalidVault)
        ) {
            self.cancel(id);
        }
        let mut response = result?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| MobileProviderError::Internal)?;
        if state.pending.as_ref().is_none_or(|p| p.id != id) {
            return Err(MobileProviderError::Cancelled);
        }
        if terminal {
            state.pending = None;
        }
        Ok(std::mem::take(&mut *response))
    }
}

struct Operation<'a> {
    owner: &'a MobileCredentialProvider,
    id: u64,
    request: Arc<Request>,
}
impl Operation<'_> {
    fn check(&self) -> Result<()> {
        let state = self
            .owner
            .state
            .lock()
            .map_err(|_| MobileProviderError::Internal)?;
        if state.pending.as_ref().is_some_and(|p| p.id == self.id) {
            Ok(())
        } else {
            Err(MobileProviderError::Cancelled)
        }
    }
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pending) = state.pending.as_mut().filter(|p| p.id == self.id) {
            pending.busy = false;
        }
    }
}

struct Opened {
    store: Unlocked,
    vault: Vault,
    biometric: bool,
}
impl Opened {
    fn open(path: &std::path::Path, authentication: &Authentication) -> Result<Self> {
        let (store, biometric) = match authentication {
            Authentication::Passphrase(value) => {
                (deadbolt_store::unlock(path, value.as_bytes())?, false)
            }
            Authentication::Biometric(key) => {
                let key: &[u8; 32] = key
                    .as_slice()
                    .try_into()
                    .map_err(|_| MobileProviderError::InvalidRequest)?;
                (deadbolt_store::unlock_biometric(path, key)?, true)
            }
        };
        let vault = storage::load(&store).map_err(|_| MobileProviderError::InvalidVault)?;
        let secret = DeviceSecret::from_bytes(store.device_secret());
        if !vault.is_member(&secret.device_id()) {
            return Err(MobileProviderError::InvalidVault);
        }
        Ok(Self {
            store,
            vault,
            biometric,
        })
    }

    fn item(&self, record: Option<&str>) -> Result<Item> {
        let (vault, item) = record
            .and_then(|r| r.split_once(':'))
            .ok_or(MobileProviderError::InvalidRequest)?;
        if vault != self.vault.id().to_string() {
            return Err(MobileProviderError::NotFound);
        }
        let bytes: [u8; 16] = data_encoding::HEXLOWER
            .decode(item.as_bytes())
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(MobileProviderError::InvalidRequest)?;
        self.vault
            .item(&ItemId::from_bytes(bytes))
            .filter(|i| !i.deleted)
            .ok_or(MobileProviderError::NotFound)
    }

    fn list(&self, request: &Request) -> Result<Value> {
        let mut logins = Vec::new();
        let mut keys = Vec::new();
        let mut unassociated = false;
        match request {
            Request::Password { services, .. } | Request::Otp { services, .. } => {
                let scope = scope(services)?;
                unassociated = scope == policy::Scope::Unassociated;
                let sources = valid_services(services);
                let otp = matches!(request, Request::Otp { .. });
                logins = policy::picker_logins(
                    &scope,
                    self.vault.iter_items().map(|item| (self.vault.id(), item)),
                    |_| 0,
                    otp,
                    |pick| {
                        let service = pick.service.and_then(|i| scope.service(i));
                        let source = pick.service.and_then(|i| sources.get(i));
                        let item = &pick.item;
                        json!({
                            "login": reference(&self.vault, item.id), "vault": self.vault.name(),
                            "title": listing::label(item), "username": autofill::value(item, "username"),
                            "has_password": autofill::value(item, "password").is_some(),
                            "has_otp": autofill::otp(item).is_some_and(|f| !f.value.is_empty()),
                            "urls": autofill::urls(item).filter(|u| service.is_none_or(|s| s.site.matches_url(u))).collect::<Vec<_>>(),
                            "sign_in": null, "service": source,
                        })
                    },
                );
            }
            Request::PasskeyGet {
                rp_id,
                allowed_credentials,
                ..
            } => {
                let rp = policy::passkey_request(rp_id, allowed_credentials)?;
                for item in self.vault.iter_items().filter(|item| {
                    passkeys::matches(item, &rp) && policy::allows(item, allowed_credentials)
                }) {
                    keys.push(json!({"passkey":reference(&self.vault, item.id),"vault":self.vault.name(),
                        "credential_id":autofill::value(&item,"credential-id"),"username":autofill::value(&item,"username"),
                        "created":autofill::value(&item,"created")}));
                }
                keys.sort_by(|a, b| {
                    (a["username"].as_str(), a["passkey"]["item"].as_str())
                        .cmp(&(b["username"].as_str(), b["passkey"]["item"].as_str()))
                });
            }
            Request::PasskeyCreate { .. } => {}
        }
        Ok(Value::Object(serde_json::Map::from_iter([
            ("logins".into(), Value::Array(logins)),
            ("passkeys".into(), Value::Array(keys)),
            ("unassociated".into(), Value::Bool(unassociated)),
            (
                "biometric_enrolled".into(),
                Value::Bool(self.store.biometric_token()?.is_some()),
            ),
        ])))
    }

    fn verified(&self, verify: Verify, interactive: bool) -> Result<bool> {
        if !interactive {
            policy::silent_verification(verify.into(), self.store.biometric_token()?.is_some())?;
            return Ok(false);
        }
        match policy::interactive_verification(verify.into(), self.biometric) {
            policy::Verification::Skip => Ok(false),
            policy::Verification::Verified => Ok(true),
            policy::Verification::Prompt => Err(MobileProviderError::VerificationRequired),
        }
    }

    fn complete(
        &mut self,
        operation: &Operation<'_>,
        record: Option<&str>,
    ) -> Result<Zeroizing<String>> {
        match &*operation.request {
            Request::Password {
                services,
                interactive,
            }
            | Request::Otp {
                services,
                interactive,
            } => {
                let item = self.item(record)?;
                let otp = matches!(&*operation.request, Request::Otp { .. });
                if item.kind != "login" || !policy::usable(&item, otp) {
                    return Err(MobileProviderError::NotFound);
                }
                let scope = scope(services)?;
                // Re-rank just the current selected item with the shared policy:
                // no picker snapshot, caller-supplied site or index is authority.
                let selected = policy::picker_logins(
                    &scope,
                    [(self.vault.id(), item)],
                    |_| 0,
                    otp,
                    |pick| pick,
                )
                .pop()
                .ok_or(MobileProviderError::DomainMismatch)?;
                let sources = valid_services(services);
                let service = selected.service.and_then(|i| sources.get(i));
                let want = if otp {
                    &[policy::Want::Username, policy::Want::Totp][..]
                } else {
                    &[policy::Want::Username, policy::Want::Password][..]
                };
                policy::fill_target(
                    want,
                    service.map(|s| (s.kind.into(), s.identifier.as_str())),
                    *interactive,
                )?;
                operation.check()?;
                let values = policy::login_values(&selected.item, want, unix()?)?;
                #[derive(Serialize)]
                struct Values<'a> {
                    username: Option<&'a str>,
                    password: Option<&'a str>,
                    totp: Option<&'a str>,
                }
                #[derive(Serialize)]
                struct Fill<'a> {
                    values: Values<'a>,
                }
                encode(&Fill {
                    values: Values {
                        username: values.username.as_deref(),
                        password: values.password.as_ref().map(|v| v.as_str()),
                        totp: values.totp.as_ref().map(|v| v.as_str()),
                    },
                })
            }
            Request::PasskeyGet {
                rp_id,
                allowed_credentials,
                client_data_hash,
                verify,
                interactive,
            } => {
                let rp = policy::passkey_request(rp_id, allowed_credentials)?;
                let item = self.item(record)?;
                passkeys::validate(&item, &rp)?;
                if !policy::allows(&item, allowed_credentials) {
                    return Err(MobileProviderError::NotFound);
                }
                let verified = self.verified(*verify, *interactive)?;
                operation.check()?;
                let signed = passkeys::sign_hash(&item, &rp, client_data_hash, verified)?;
                encode(
                    &json!({"credential_id":signed.credential_id,"client_data_hash":signed.client_data_hash,
                    "authenticator_data":signed.authenticator_data,"signature":signed.signature,"user_handle":signed.user_handle,"verified":verified}),
                )
            }
            Request::PasskeyCreate {
                rp_id,
                client_data_hash,
                user_id,
                user_name,
                user_display_name,
                exclude,
                verify,
                interactive,
            } => {
                if record.is_some() {
                    return Err(MobileProviderError::InvalidRequest);
                }
                policy::check_exclude(exclude)?;
                let mut new = passkeys::check_create_hash(
                    rp_id,
                    client_data_hash,
                    user_id,
                    user_name,
                    exclude,
                )?;
                new.display_name = passkeys::user_text(user_display_name);
                passkeys::check_excluded(self.vault.iter_items(), &new.rp_id, &new.exclude)?;
                let verified = self.verified(*verify, *interactive)?;
                operation.check()?;
                let created = time::OffsetDateTime::from_unix_timestamp(
                    i64::try_from(unix()?).map_err(|_| MobileProviderError::Internal)?,
                )
                .map_err(|_| MobileProviderError::Internal)?
                .date()
                .to_string();
                let made = passkeys::register_hash(&new, verified, &created)?;
                let secret = DeviceSecret::from_bytes(self.store.device_secret());
                let mut staged = self.vault.clone();
                let entry = staged
                    .write(&secret, vec![made.create])
                    .map_err(|_| MobileProviderError::InvalidVault)?;
                let record = reference(&self.vault, ItemId::of_create(&entry.hash(), 0));
                operation.check()?;
                // A cancelled call may already have durably written. Never
                // return the credential before commit; never retry on ambiguity.
                storage::commit(&self.store, &mut self.vault, staged)?;
                encode(
                    &json!({"passkey":record,"credential_id":made.credential_id,"client_data_hash":made.client_data_hash,
                    "attestation_object":made.attestation_object,"authenticator_data":made.authenticator_data,
                    "public_key":made.public_key,"verified":verified}),
                )
            }
        }
    }
}

fn scope(services: &[Service]) -> Result<policy::Scope> {
    Ok(policy::scope(
        services
            .iter()
            .map(|s| (s.kind.into(), s.identifier.as_str())),
    )?)
}
fn valid_services(services: &[Service]) -> Vec<&Service> {
    services
        .iter()
        .filter(|s| policy::resolve_service(s.kind.into(), &s.identifier).is_ok())
        .collect()
}
fn reference(vault: &Vault, id: ItemId) -> Value {
    json!({"vault":vault.id().to_string(),"item":id.to_string()})
}
fn encode(value: &impl Serialize) -> Result<Zeroizing<String>> {
    serde_json::to_string(value)
        .map(Zeroizing::new)
        .map_err(|_| MobileProviderError::Internal)
}
fn unix() -> Result<u64> {
    crate::now().map_err(|_| MobileProviderError::Internal)
}

pub(crate) fn identities(vault: &Vault) -> Value {
    let snapshot = policy::identities(vault.iter_items().map(|item| (vault.id(), item)), |_| 0);
    json!({"identities_hash":snapshot.hash,"passwords":snapshot.passwords,"passkeys":snapshot.passkeys,"one_time_codes":snapshot.one_time_codes})
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadbolt_core::{DataOp, Field, FieldType};

    fn passphrase() -> MobileProviderAuthentication {
        MobileProviderAuthentication::Passphrase {
            value: "local-pass".into(),
        }
    }

    fn biometric(byte: u8) -> MobileProviderAuthentication {
        MobileProviderAuthentication::Biometric {
            key: vec![byte; 32],
        }
    }

    fn fixture() -> (tempfile::TempDir, Arc<MobileCredentialProvider>, String) {
        let dir = tempfile::tempdir().unwrap();
        let secret = DeviceSecret::generate();
        let (vault, _) = Vault::create(&secret, "provider-fixture").unwrap();
        let record = crate::tests::fixture(dir.path(), &secret, vault, json!({}));
        let store = deadbolt_store::unlock(dir.path(), b"local-pass").unwrap();
        store
            .set_biometric(&[42; 32], b"synthetic-os-envelope")
            .unwrap();
        drop(store);
        let provider = MobileCredentialProvider::new(dir.path().display().to_string());
        (dir, provider, record)
    }

    fn request(provider: &MobileCredentialProvider, op: &str) -> u64 {
        provider.begin(json!({"op":op,"services":[{"kind":"domain","identifier":"example.com"}],"interactive":true}).to_string()).unwrap()
    }

    fn mutate(dir: &std::path::Path, change: impl FnOnce(&mut Vault, &DeviceSecret)) {
        let store = deadbolt_store::unlock(dir, b"local-pass").unwrap();
        let secret = DeviceSecret::from_bytes(store.device_secret());
        let mut live = storage::load(&store).unwrap();
        let mut staged = live.clone();
        change(&mut staged, &secret);
        storage::commit(&store, &mut live, staged).unwrap();
    }

    fn item_id(record: &str) -> ItemId {
        ItemId::from_bytes(
            data_encoding::HEXLOWER
                .decode(record.split_once(':').unwrap().1.as_bytes())
                .unwrap()
                .try_into()
                .unwrap(),
        )
    }

    fn creation(exclude: Vec<String>, verify: &str) -> String {
        json!({"op":"passkey-create","rp_id":"example.com","client_data_hash":webauthn::b64(&[7;32]),
            "user_id":webauthn::b64(b"alice"),"user_name":"Alice","user_display_name":"Alice Example",
            "exclude":exclude,"verify":verify,"interactive":true}).to_string()
    }

    fn assertion(rp: &str, allowed: Vec<String>, verify: &str) -> String {
        json!({"op":"passkey-get","rp_id":rp,"allowed_credentials":allowed,"client_data_hash":webauthn::b64(&[8;32]),
            "verify":verify,"interactive":true}).to_string()
    }

    #[test]
    fn offline_password_and_otp_replay_close_and_keep_earliest_service() {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let (dir, provider, record) = fixture();
        let id = provider
            .begin(
                json!({"op":"password","services":[
            {"kind":"domain","identifier":"com"},
            {"kind":"url","identifier":"https://example.com/signin"},
            {"kind":"domain","identifier":"example.com"}],"interactive":true})
                .to_string(),
            )
            .unwrap();
        let listed = provider.list(id, passphrase()).unwrap();
        assert!(!listed.contains("synthetic-mobile-password"));
        assert!(!listed.contains("JBSWY3DPEHPK3PXP"));
        let list: Value = serde_json::from_str(&listed).unwrap();
        let (vault_id, item_id) = record.split_once(':').unwrap();
        assert_eq!(
            list,
            json!({
                "logins": [{
                    "login": {"vault": vault_id, "item": item_id},
                    "vault": "provider-fixture", "title": "Example", "username": "alice",
                    "has_password": true, "has_otp": true, "urls": ["https://example.com"],
                    "sign_in": null,
                    "service": {"kind": "url", "identifier": "https://example.com/signin"}
                }],
                "passkeys": [], "unassociated": false, "biometric_enrolled": true
            })
        );
        // list never retains redb, and it never changes the log or needs Tokio.
        let store = deadbolt_store::unlock(dir.path(), b"local-pass").unwrap();
        let before = storage::load(&store).unwrap().heads();
        drop(store);
        let reply: Value = serde_json::from_str(
            &provider
                .complete(id, Some(record.clone()), passphrase())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(reply["values"]["password"], "synthetic-mobile-password");
        assert_eq!(reply["values"]["username"], "alice");
        assert!(reply.get("identities_hash").is_none());
        assert!(matches!(
            provider.complete(id, Some(record.clone()), passphrase()),
            Err(MobileProviderError::Cancelled)
        ));
        let id = request(&provider, "otp");
        let before_time = unix().unwrap();
        let reply: Value =
            serde_json::from_str(&provider.complete(id, Some(record), passphrase()).unwrap())
                .unwrap();
        let totp = deadbolt_core::totp::Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        let code = reply["values"]["totp"].as_str().unwrap();
        assert!(
            [totp.code(before_time), totp.code(unix().unwrap())]
                .iter()
                .any(|v| v == code)
        );
        assert!(reply["values"]["password"].is_null());
        let store = deadbolt_store::unlock(dir.path(), b"local-pass").unwrap();
        let vault = storage::load(&store).unwrap();
        assert_eq!(vault.heads(), before);
        let snapshot = identities(&vault).to_string();
        assert!(!snapshot.contains("synthetic-mobile-password"));
        assert!(!snapshot.contains("JBSWY3DPEHPK3PXP"));
        assert!(tokio::runtime::Handle::try_current().is_err());
    }

    #[test]
    fn current_type_domain_deletion_and_interaction_are_rechecked() {
        let (dir, provider, record) = fixture();
        let id = request(&provider, "password");
        provider.list(id, passphrase()).unwrap();
        mutate(dir.path(), |vault, secret| {
            vault
                .write(
                    secret,
                    vec![DataOp::set(
                        item_id(&record),
                        "url",
                        Field::new(FieldType::Url, "https://different.example"),
                    )],
                )
                .unwrap();
        });
        assert!(matches!(
            provider.complete(id, Some(record.clone()), passphrase()),
            Err(MobileProviderError::DomainMismatch)
        ));
        mutate(dir.path(), |vault, secret| {
            vault
                .write(secret, vec![DataOp::delete(item_id(&record), 1)])
                .unwrap();
        });
        assert!(matches!(
            provider.complete(id, Some(record), passphrase()),
            Err(MobileProviderError::NotFound)
        ));

        let (_dir, provider, record) = fixture();
        let id = provider
            .begin(json!({"op":"password","services":[],"interactive":false}).to_string())
            .unwrap();
        assert!(matches!(
            provider.complete(id, Some(record), passphrase()),
            Err(MobileProviderError::InteractionRequired)
        ));
        assert!(matches!(provider.begin(json!({"op":"password","services":[{"kind":"domain","identifier":"com"}],"interactive":true}).to_string()), Err(MobileProviderError::InvalidRequest)));
        assert!(matches!(
            provider.list(id, passphrase()),
            Err(MobileProviderError::Cancelled)
        ));
    }

    #[test]
    fn contention_wrong_key_and_fresh_request_bound_unwrap() {
        let (dir, provider, record) = fixture();
        let id = request(&provider, "password");
        let app_store = deadbolt_store::unlock(dir.path(), b"local-pass").unwrap();
        assert!(matches!(
            provider.list(id, passphrase()),
            Err(MobileProviderError::InUse)
        ));
        drop(app_store);
        assert!(matches!(
            provider.list(id, biometric(43)),
            Err(MobileProviderError::Authentication)
        ));
        provider.list(id, biometric(42)).unwrap();
        let store = deadbolt_store::unlock(dir.path(), b"local-pass").unwrap();
        store
            .set_biometric(&[43; 32], b"replacement-os-envelope")
            .unwrap();
        drop(store);
        assert!(matches!(
            provider.complete(id, Some(record.clone()), biometric(42)),
            Err(MobileProviderError::Authentication)
        ));
        provider.complete(id, Some(record), biometric(43)).unwrap();
        assert!(matches!(
            provider.list(id, biometric(43)),
            Err(MobileProviderError::Cancelled)
        ));
        assert!(deadbolt_store::unlock(dir.path(), b"local-pass").is_ok());
    }

    #[test]
    fn cancellation_discards_a_prepared_secret_without_reviving_an_old_request() {
        use std::sync::mpsc;
        let (dir, provider, record) = fixture();
        let id = request(&provider, "password");
        let (prepared_tx, prepared_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = provider.clone();
        let thread = std::thread::spawn(move || {
            worker.run(id, passphrase().into(), true, |operation, opened| {
                let response = opened.complete(operation, Some(&record))?;
                prepared_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(response)
            })
        });
        prepared_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert!(matches!(
            provider.list(id, passphrase()),
            Err(MobileProviderError::Busy)
        ));
        provider.cancel(id);
        let next = request(&provider, "password");
        provider.cancel(id); // a late cancellation must not cancel `next`
        release_tx.send(()).unwrap();
        assert!(matches!(
            thread.join().unwrap(),
            Err(MobileProviderError::Cancelled)
        ));
        provider.list(next, passphrase()).unwrap();
        provider.cancel(next);
        assert!(deadbolt_store::unlock(dir.path(), b"local-pass").is_ok());
    }

    #[test]
    fn passkeys_require_current_rp_allowed_list_and_cryptographic_uv() {
        let (dir, provider, _) = fixture();
        let id = provider.begin(creation(vec![], "required")).unwrap();
        assert!(matches!(
            provider.complete(id, None, passphrase()),
            Err(MobileProviderError::VerificationRequired)
        ));
        assert!(matches!(
            provider.complete(id, None, biometric(43)),
            Err(MobileProviderError::Authentication)
        ));
        let made: Value =
            serde_json::from_str(&provider.complete(id, None, biometric(42)).unwrap()).unwrap();
        let record = format!(
            "{}:{}",
            made["passkey"]["vault"].as_str().unwrap(),
            made["passkey"]["item"].as_str().unwrap()
        );
        let credential = made["credential_id"].as_str().unwrap().to_string();
        assert_eq!(made["verified"], true);
        assert_eq!(
            webauthn::unb64(made["authenticator_data"].as_str().unwrap()).unwrap()[32] & 4,
            4
        );
        // Real reopen and signature-validating replay, not just an in-memory
        // item: registration must be durable before returning its credential.
        let store = deadbolt_store::unlock(dir.path(), b"local-pass").unwrap();
        let vault = storage::load(&store).unwrap();
        let saved = vault.item(&item_id(&record)).unwrap();
        assert_eq!(
            autofill::value(&saved, "credential-id"),
            Some(credential.as_str())
        );
        assert!(autofill::value(&saved, "private-key").is_some());
        assert!(matches!(
            passkeys::check_excluded([&saved], "example.com", std::slice::from_ref(&credential)),
            Err(passkeys::Error::Exists)
        ));
        assert!(matches!(
            passkeys::check_excluded(
                std::iter::once(saved.clone()).chain(std::iter::once_with(|| {
                    panic!("an excluded match must stop the stream")
                })),
                "example.com",
                std::slice::from_ref(&credential),
            ),
            Err(passkeys::Error::Exists)
        ));
        let snapshot = identities(&vault).to_string();
        assert!(!snapshot.contains(autofill::value(&saved, "private-key").unwrap()));
        drop(store);

        let id = provider
            .begin(creation(vec![credential.clone()], "required"))
            .unwrap();
        assert!(matches!(
            provider.complete(id, None, biometric(42)),
            Err(MobileProviderError::AlreadyExists)
        ));
        let id = provider
            .begin(assertion("other.example", vec![], "required"))
            .unwrap();
        assert!(matches!(
            provider.complete(id, Some(record.clone()), biometric(42)),
            Err(MobileProviderError::DomainMismatch)
        ));
        let id = provider
            .begin(assertion(
                "example.com",
                vec![webauthn::b64(b"different")],
                "required",
            ))
            .unwrap();
        assert!(matches!(
            provider.complete(id, Some(record.clone()), biometric(42)),
            Err(MobileProviderError::NotFound)
        ));
        let id = provider
            .begin(assertion(
                "example.com",
                vec![credential.clone()],
                "required",
            ))
            .unwrap();
        assert!(matches!(
            provider.complete(id, Some(record.clone()), passphrase()),
            Err(MobileProviderError::VerificationRequired)
        ));
        let signed: Value = serde_json::from_str(
            &provider
                .complete(id, Some(record.clone()), biometric(42))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(signed["credential_id"], credential);
        assert_eq!(signed["client_data_hash"], webauthn::b64(&[8; 32]));
        assert_eq!(signed["verified"], true);
        assert_eq!(
            webauthn::unb64(signed["authenticator_data"].as_str().unwrap()).unwrap()[32] & 4,
            4
        );
        assert!(
            !webauthn::unb64(signed["signature"].as_str().unwrap())
                .unwrap()
                .is_empty()
        );

        let id = provider
            .begin(assertion("example.com", vec![], "discouraged"))
            .unwrap();
        let signed: Value = serde_json::from_str(
            &provider
                .complete(id, Some(record.clone()), passphrase())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(signed["verified"], false);
        assert_eq!(
            webauthn::unb64(signed["authenticator_data"].as_str().unwrap()).unwrap()[32] & 4,
            0
        );
        mutate(dir.path(), |vault, secret| {
            vault
                .write(secret, vec![DataOp::delete(item_id(&record), 2)])
                .unwrap();
        });
        let id = provider
            .begin(assertion("example.com", vec![], "required"))
            .unwrap();
        assert!(matches!(
            provider.complete(id, Some(record), biometric(42)),
            Err(MobileProviderError::NotFound)
        ));
        let mut spoof: Value = serde_json::from_str(&creation(vec![], "required")).unwrap();
        spoof["verified"] = json!(true);
        assert!(matches!(
            provider.begin(spoof.to_string()),
            Err(MobileProviderError::InvalidRequest)
        ));
    }

    #[test]
    fn unconfirmed_write_quarantines_the_request_and_closes_the_store() {
        let (dir, provider, _) = fixture();
        let id = provider.begin(creation(vec![], "required")).unwrap();
        // Test the provider's uncertainty boundary; the store's own fault
        // injection tests cover lost acknowledgements after actual fsync.
        assert!(matches!(
            provider.run(id, biometric(42).into(), true, |_, _| Err(
                MobileProviderError::UnconfirmedWrite
            )),
            Err(MobileProviderError::UnconfirmedWrite)
        ));
        assert!(matches!(
            provider.complete(id, None, biometric(42)),
            Err(MobileProviderError::Cancelled)
        ));
        assert!(deadbolt_store::unlock(dir.path(), b"local-pass").is_ok());
    }

    #[test]
    #[ignore = "explicit previously generated synthetic 1k/10k fixture required"]
    fn measure_synthetic_provider_replay() {
        let path = PathBuf::from(std::env::var_os("DEADBOLT_MOBILE_FIXTURE_DIR").unwrap());
        let count: usize = std::env::var_os("DEADBOLT_MOBILE_FIXTURE_COUNT")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!([1_000, 10_000].contains(&count));
        assert!(path.is_absolute());
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            format!("deadbolt-mobile-fixture-{count}")
        );
        if let Some(mode) = std::env::var_os("DEADBOLT_MOBILE_MEMORY_MODE") {
            // An external sampler reads this process's OS memory counters at
            // each checkpoint, then acknowledges on stdin. Fixture generation
            // happens in a separate process, never in this measured child.
            use std::io::Write;
            let checkpoint = |stage: &str| {
                println!("provider-memory pid={} stage={stage}", std::process::id());
                std::io::stdout().flush().unwrap();
                let mut ack = String::new();
                std::io::stdin().read_line(&mut ack).unwrap();
                assert_eq!(ack.trim(), "continue");
            };
            checkpoint("baseline");
            let provider = MobileCredentialProvider::new(path.display().to_string());
            let request = || {
                provider
                    .begin(json!({"op":"password","services":[],"interactive":true}).to_string())
                    .unwrap()
            };
            let authentication = || MobileProviderAuthentication::Passphrase {
                value: "synthetic-mobile-fixture-passphrase".into(),
            };
            match mode.to_str().unwrap() {
                "phases" => {
                    let store =
                        deadbolt_store::unlock(&path, b"synthetic-mobile-fixture-passphrase")
                            .unwrap();
                    assert_eq!(
                        store.kdf_params().unwrap(),
                        deadbolt_store::KdfParams::DEFAULT
                    );
                    checkpoint("unlocked");
                    let vault = storage::load(&store).unwrap();
                    assert!(
                        vault.is_member(
                            &DeviceSecret::from_bytes(store.device_secret()).device_id()
                        )
                    );
                    checkpoint("replayed");
                    let opened = Opened {
                        store,
                        vault,
                        biometric: false,
                    };
                    let id = request();
                    let operation = provider.reserve(id).unwrap();
                    let list = opened.list(&operation.request).unwrap();
                    assert_eq!(list["logins"].as_array().unwrap().len(), count);
                    let first = &list["logins"][0]["login"];
                    println!(
                        "provider-record {}:{}",
                        first["vault"].as_str().unwrap(),
                        first["item"].as_str().unwrap()
                    );
                    checkpoint("picker_metadata");
                    let response = encode(&list).unwrap();
                    println!("provider-response-bytes {}", response.len());
                    checkpoint("serialized");
                    drop(list);
                    checkpoint("metadata_dropped");
                    drop(opened);
                    checkpoint("store_closed");
                    drop(response);
                    checkpoint("response_dropped");
                }
                mode @ ("list" | "fill" | "cycles") => {
                    let record = std::env::var_os("DEADBOLT_MOBILE_FIXTURE_RECORD")
                        .unwrap()
                        .into_string()
                        .unwrap();
                    let cycles = if mode == "cycles" { 3 } else { 1 };
                    for cycle in 0..cycles {
                        let id = request();
                        if mode != "fill" {
                            let response = provider.list(id, authentication()).unwrap();
                            println!("provider-response-bytes {}", response.len());
                            checkpoint(&format!("list_{cycle}_returned"));
                            drop(response);
                            checkpoint(&format!("list_{cycle}_dropped"));
                        }
                        if mode != "list" {
                            let response = Zeroizing::new(
                                provider
                                    .complete(id, Some(record.clone()), authentication())
                                    .unwrap(),
                            );
                            assert!(response.contains("synthetic-password-"));
                            checkpoint(&format!("fill_{cycle}_returned"));
                            drop(response);
                            checkpoint(&format!("fill_{cycle}_dropped"));
                        }
                    }
                }
                _ => panic!("unknown provider memory measurement mode"),
            }
            checkpoint("finished");
            return;
        }
        let provider = MobileCredentialProvider::new(path.display().to_string());
        let id = provider
            .begin(json!({"op":"password","services":[],"interactive":true}).to_string())
            .unwrap();
        let authentication = || MobileProviderAuthentication::Passphrase {
            value: "synthetic-mobile-fixture-passphrase".into(),
        };
        let start = std::time::Instant::now();
        let list = provider.list(id, authentication()).unwrap();
        let list_ms = start.elapsed().as_millis();
        let list: Value = serde_json::from_str(&list).unwrap();
        assert_eq!(list["logins"].as_array().unwrap().len(), count);
        let first = &list["logins"][0]["login"];
        let record = format!(
            "{}:{}",
            first["vault"].as_str().unwrap(),
            first["item"].as_str().unwrap()
        );
        drop(list);
        let start = std::time::Instant::now();
        let reply = Zeroizing::new(
            provider
                .complete(id, Some(record), authentication())
                .unwrap(),
        );
        let fill_ms = start.elapsed().as_millis();
        assert!(reply.contains("synthetic-password-"));
        println!(
            "synthetic logins={count} full_replay_list_ms={list_ms} full_replay_fill_ms={fill_ms}"
        );
    }
}
