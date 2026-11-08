//! The background daemon: the only process that opens the store. Holds it
//! unlocked, runs the iroh node while unlocked, and serves the control socket.

mod activity;
mod autofill;
pub mod biometric;
mod caller;
mod commands;
mod connection;
mod forms;
mod generate;
mod grants;
mod guesses;
mod health;
mod items;
mod legacy;
mod lifecycle;
mod macos_autofill;
mod mirror;
mod pairing;
mod passkeys;
mod remote_read;
mod secrets;
mod send;
mod session;
#[cfg(test)]
mod sim;
mod ssh_cleanup;
pub(crate) mod ssh_keys;
mod status;
mod sync;
mod system;
#[cfg(test)]
mod tests;
mod updates;
#[cfg(test)]
mod watch_tests;
mod watchers;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use deadbolt_core::DeviceId;
use deadbolt_net::{Membership, Node, NodeConfig, PeerId};
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::client::DaemonError;
use crate::config::Config;
use crate::paths::Paths;
use crate::protocol::ErrorCode;
#[cfg(test)]
use crate::protocol::{CallerInfo, Command, Message, Reply};
use session::{Loaded, Session, clean_name};
use system::SystemEvent;
#[cfg(test)]
use tokio::io::AsyncWriteExt;
use watchers::Watchers;

/// Tests read the control line limit from here; the daemon itself uses it in
/// [`lifecycle`].
#[cfg(test)]
pub(super) use crate::protocol::MAX_LINE;
pub use connection::Conversation;
pub(super) use lifecycle::remove_socket;
pub use lifecycle::serve;

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const BIOMETRIC_CANCEL_COOLDOWN: Duration = Duration::from_secs(2);
const INTERRUPTED: &str = "locked during the sync from 1Password; nothing was written";

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone)]
struct BiometricFlight {
    cancel: Arc<biometric::CancelHandle>,
    rx: watch::Receiver<Option<Result<(), String>>>,
}

#[cfg(test)]
type BiometricUnsealHook = Arc<
    dyn Fn(&biometric::CancelHandle) -> Result<zeroize::Zeroizing<[u8; 32]>, biometric::UnlockError>
        + Send
        + Sync,
>;

pub struct Daemon {
    paths: Paths,
    local_net: bool,
    kdf: deadbolt_store::KdfParams,
    session: Mutex<Option<Session>>,
    /// The membership gate: members of any vault this device holds.
    members: Arc<RwLock<HashSet<PeerId>>>,
    /// Cleared on unlock until membership was synced with reachable peers.
    ready: watch::Sender<bool>,
    sync_now: Notify,
    /// Serializes setup, unlock and lock.
    transition: tokio::sync::Mutex<()>,
    /// Held by the one join or pair running.
    pairing: tokio::sync::Mutex<()>,
    /// Held by the one sync from 1Password running.
    syncing_op: tokio::sync::Mutex<()>,
    /// Bumped by a lock and at shutdown: a sync from 1Password running
    /// kills `op` and writes nothing.
    interrupts: watch::Sender<u64>,
    #[cfg(test)]
    op_program: Mutex<Option<std::path::PathBuf>>,
    /// In-memory metadata of `"biometric.token"`, loaded once at startup and
    /// updated on enrollment/clear/wipe so `status()` never opens `store.redb`.
    biometric_slot: Mutex<Option<biometric::TokenMeta>>,
    /// True once Touch ID has been enrolled for this store (`initial_slot.is_some()`
    /// or enrolled during this daemon's lifetime) and not explicitly turned off,
    /// so `touch_id_reset` distinguishes a wiped/expired slot from a store
    /// where `touch_id = true` was set in `config.toml` before ever enrolling.
    biometric_was_enrolled: AtomicBool,
    /// Coalesces concurrent `UnlockBiometric` requests and lets `Unlock`,
    /// `Lock`, `TouchIdSet`, or `Stop` cancel an in-flight Touch ID prompt.
    biometric_flight: Mutex<Option<BiometricFlight>>,
    /// Short cooldown after a user-cancelled Touch ID prompt so rapid window
    /// focus or summon events do not immediately re-prompt.
    biometric_cooldown_until: Mutex<Option<Instant>>,
    /// The one Touch ID prompt verifying a passkey ceremony, cancelled with
    /// the unlock prompt.
    passkey_prompt: Mutex<Option<Arc<biometric::CancelHandle>>>,
    #[cfg(test)]
    touch_id_available_override: Mutex<Option<bool>>,
    #[cfg(test)]
    biometric_hook: Mutex<Option<BiometricUnsealHook>>,
    idle: Mutex<Idle>,
    /// Requests in progress; the idle timeout waits for them (e.g. pairing).
    busy: AtomicUsize,
    shutdown: Notify,
    watchers: Watchers,
    /// Who connections come from.
    callers: caller::Callers,
    /// Activity not stored yet: entries recorded while locked, and each
    /// caller's count against its limit.
    activity: Mutex<activity::Ledger>,
    /// Each paired agent client's rate limit, by client id.
    agent_rates: Mutex<HashMap<String, crate::browser::host::Bucket>>,
    /// AI callers' `resolve` rate limits, by anchor, and one for them all.
    resolve_rates: Mutex<HashMap<String, crate::browser::host::Bucket>>,
    /// macOS AutoFill extension rate limits for fills and passkey ceremonies.
    autofill_fill_rate: Mutex<Option<crate::browser::host::Bucket>>,
    autofill_passkey_rate: Mutex<Option<crate::browser::host::Bucket>>,
    /// Every passphrase check: one at a time, wrong ones backed off.
    guesses: guesses::Guesses,
    /// Deadbolt Send's endpoint, started by the first send.
    send_server: tokio::sync::Mutex<Option<deadbolt_send::Server>>,
    /// Set as the daemon stops, ending sends and anyone waiting on one.
    stopping: watch::Sender<bool>,
    /// What the background update check last found (`updates`).
    update: Mutex<Option<crate::protocol::UpdateInfo>>,
}

impl Daemon {
    fn new(paths: Paths, local_net: bool, kdf: deadbolt_store::KdfParams) -> Arc<Daemon> {
        let initial_slot = biometric::read_token_meta(&paths.data);
        biometric::spawn_background_refresh();
        Arc::new(Daemon {
            paths,
            local_net,
            kdf,
            session: Mutex::default(),
            members: Arc::default(),
            ready: watch::channel(false).0,
            sync_now: Notify::new(),
            transition: tokio::sync::Mutex::new(()),
            pairing: tokio::sync::Mutex::new(()),
            syncing_op: tokio::sync::Mutex::new(()),
            interrupts: watch::channel(0).0,
            #[cfg(test)]
            op_program: Mutex::default(),
            biometric_was_enrolled: AtomicBool::new(initial_slot.is_some()),
            biometric_slot: Mutex::new(initial_slot),
            biometric_flight: Mutex::default(),
            biometric_cooldown_until: Mutex::default(),
            passkey_prompt: Mutex::default(),
            #[cfg(test)]
            touch_id_available_override: Mutex::default(),
            #[cfg(test)]
            biometric_hook: Mutex::default(),
            idle: Mutex::default(),
            busy: AtomicUsize::new(0),
            shutdown: Notify::new(),
            watchers: Watchers::default(),
            callers: caller::Callers::new(),
            activity: Mutex::default(),
            agent_rates: Mutex::default(),
            resolve_rates: Mutex::default(),
            autofill_fill_rate: Mutex::default(),
            autofill_passkey_rate: Mutex::default(),
            guesses: guesses::Guesses::default(),
            send_server: tokio::sync::Mutex::default(),
            stopping: watch::channel(false).0,
            update: Mutex::default(),
        })
    }

    /// Holds off the idle lock until dropped: for a request waiting on the
    /// user (a Touch ID prompt, a passphrase check).
    fn busy(&self) -> Busy<'_> {
        self.busy.fetch_add(1, Ordering::SeqCst);
        Busy(&self.busy)
    }

    fn interrupt_op(&self) {
        self.interrupts.send_modify(|n| *n += 1);
    }

    fn op(&self) -> mirror::Op {
        #[cfg(test)]
        if let Some(program) = self
            .op_program
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return mirror::Op::at(program);
        }
        mirror::Op::find()
    }

    fn cancel_biometric_prompt(&self) {
        if let Some(flight) = self
            .biometric_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            flight.cancel.cancel();
        }
        if let Some(prompt) = self
            .passkey_prompt
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            prompt.cancel();
        }
    }
}

/// See [`Daemon::busy`].
struct Busy<'a>(&'a AtomicUsize);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.cancel_biometric_prompt();
    }
}

#[derive(Default)]
struct Idle {
    timeout: Option<Duration>,
    deadline: Option<Instant>,
}

/// Whether `error` says the passphrase was wrong.
fn wrong_passphrase(error: &anyhow::Error) -> bool {
    error.chain().any(|e| {
        matches!(
            e.downcast_ref::<deadbolt_store::Error>(),
            Some(deadbolt_store::Error::WrongPassphrase)
        )
    })
}

fn fail(code: ErrorCode, message: impl Into<String>) -> anyhow::Error {
    DaemonError {
        code,
        message: message.into(),
        grant: None,
        passkeys: None,
    }
    .into()
}

impl Daemon {
    /// Locks on each sleep or screen-lock event unless `lock_on_sleep` is off.
    async fn follow_system(self: Arc<Self>, mut events: mpsc::Receiver<SystemEvent>) {
        while let Some(event) = events.recv().await {
            let enabled = match Config::load(&self.paths.config) {
                Ok(config) => config.lock_on_sleep(),
                Err(error) => {
                    warn!("{error:#}; locking anyway");
                    true
                }
            };
            let unlocked = self
                .session
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some();
            if enabled && unlocked {
                info!(?event, "locking");
                self.lock().await;
            }
        }
    }

    async fn setup(
        self: &Arc<Self>,
        passphrase: zeroize::Zeroizing<String>,
        device_name: String,
    ) -> Result<()> {
        self.cancel_biometric_prompt();
        let _transition = self.transition.lock().await;
        self.settle_activity(true);
        *self
            .biometric_cooldown_until
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        if deadbolt_store::is_initialized(&self.paths.data) {
            bail!("this device is already set up");
        }
        let device_name = clean_name(&device_name);
        if device_name.is_empty() {
            bail!("the device name cannot be empty");
        }
        if passphrase.is_empty() {
            bail!("the passphrase cannot be empty");
        }
        let dir = self.paths.data.clone();
        let params = self.kdf;
        let loaded = tokio::task::spawn_blocking(move || {
            Loaded::setup(&dir, passphrase.as_bytes(), &device_name, params)
        })
        .await??;
        self.biometric_was_enrolled.store(false, Ordering::SeqCst);
        *self
            .biometric_slot
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        self.start(loaded, None).await
    }

    /// First run through a join: creates the store with the device key that
    /// joined and stores the vault it received, then unlocks.
    async fn setup_joined(
        self: &Arc<Self>,
        joined: pairing::Fresh,
        passphrase: crate::protocol::Secret,
    ) -> Result<crate::protocol::VaultInfo> {
        self.cancel_biometric_prompt();
        let _transition = self.transition.lock().await;
        self.settle_activity(true);
        *self
            .biometric_cooldown_until
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        if deadbolt_store::is_initialized(&self.paths.data) {
            bail!("this device was set up meanwhile; nothing from the join was saved");
        }
        if passphrase.expose().is_empty() {
            bail!("the passphrase cannot be empty");
        }
        let dir = self.paths.data.clone();
        let params = self.kdf;
        let (loaded, vault) =
            tokio::task::spawn_blocking(move || joined.persist(&dir, &passphrase, params))
                .await??;
        self.biometric_was_enrolled.store(false, Ordering::SeqCst);
        *self
            .biometric_slot
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        self.start(loaded, None).await?;
        Ok(vault)
    }

    /// Unlocks with `passphrase`. While unlocked, it changes the idle
    /// timeout: to a shorter one at once, to a longer one (or never) only if
    /// the passphrase is right. A Touch ID prompt in flight is cancelled only
    /// once the passphrase has opened the store.
    async fn unlock(
        self: &Arc<Self>,
        passphrase: zeroize::Zeroizing<String>,
        timeout_secs: Option<u64>,
    ) -> Result<()> {
        let _transition = self.transition.lock().await;
        self.close_quarantined(&_transition).await;
        self.settle_activity(true);
        *self
            .biometric_cooldown_until
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        let open = self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|s| {
                s.ensure_usable()?;
                Ok::<_, anyhow::Error>(s.store.passphrase_check()?)
            });
        if let Some(check) = open {
            let check = check?;
            if self.with(|_| self.tighten_timeout(timeout_secs))? {
                return Ok(());
            }
            let turn = self.guesses.turn()?;
            let right =
                tokio::task::spawn_blocking(move || check.matches(passphrase.as_bytes())).await?;
            turn.settle(right);
            if !right {
                return Err(deadbolt_store::Error::WrongPassphrase.into());
            }
            return self.with(|_| self.set_timeout(timeout_secs));
        }
        if !deadbolt_store::is_initialized(&self.paths.data) {
            return Err(fail(
                ErrorCode::NotInitialized,
                "this device is not set up; run `deadbolt init` or `deadbolt join`",
            ));
        }
        let dir = self.paths.data.clone();
        let want_touch_id = Config::load(&self.paths.config)
            .map(|c| c.touch_id())
            .unwrap_or(false);
        let enroll_touch_id = want_touch_id && self.refresh_touch_id_available().await;
        let now = session::now();
        let turn = self.guesses.turn()?;
        let opened = tokio::task::spawn_blocking(move || {
            let loaded = Loaded::open(&dir, passphrase.as_bytes())?;
            if enroll_touch_id && let Err(error) = biometric::enroll(&loaded.store, now) {
                warn!("Touch ID enrollment on unlock failed: {error:#}");
            }
            let meta =
                biometric::token_meta(loaded.store.biometric_token().ok().flatten().as_deref());
            Ok::<_, anyhow::Error>((loaded, meta))
        })
        .await?;
        match &opened {
            Ok(_) => turn.settle(true),
            Err(error) if wrong_passphrase(error) => turn.settle(false),
            // Neither right nor wrong (a damaged store, a store in use).
            Err(_) => drop(turn),
        }
        let (loaded, slot_meta) = opened?;
        self.cancel_biometric_prompt();
        if slot_meta.is_some() {
            self.biometric_was_enrolled.store(true, Ordering::SeqCst);
        }
        *self
            .biometric_slot
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = slot_meta;
        self.start(loaded, timeout_secs).await
    }

    /// Unlocks with Touch ID. While unlocked, it changes the idle timeout:
    /// to a shorter one at once, to a longer one (or never) only after a
    /// Touch ID prompt succeeds.
    async fn unlock_biometric(self: &Arc<Self>, timeout_secs: Option<u64>) -> Result<()> {
        self.unlock_biometric_with_reason(timeout_secs, "unlock your Deadbolt vaults")
            .await
            .map(drop)
    }

    /// Like [`Daemon::unlock_biometric`], with a custom `reason` on the Touch ID
    /// sheet. Returns `Ok(true)` only when this call's own Touch ID prompt
    /// unsealed the biometric key (as opposed to returning early while already
    /// unlocked or coalescing onto another caller's prompt).
    pub(super) async fn unlock_biometric_with_reason(
        self: &Arc<Self>,
        timeout_secs: Option<u64>,
        reason: &str,
    ) -> Result<bool> {
        let unlocked = {
            let transition = self.transition.lock().await;
            self.close_quarantined(&transition).await;
            self.session
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
        };
        if unlocked && self.with(|_| self.tighten_timeout(timeout_secs))? {
            return Ok(false);
        }
        if !unlocked && !deadbolt_store::is_initialized(&self.paths.data) {
            return Err(fail(
                ErrorCode::NotInitialized,
                "this device is not set up; run `deadbolt init` or `deadbolt join`",
            ));
        }
        if !Config::load(&self.paths.config)?.touch_id() {
            bail!(
                "Touch ID unlock is not enabled; turn it on in Settings or run `deadbolt touchid on`"
            );
        }
        if let Some(until) = *self
            .biometric_cooldown_until
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            && Instant::now() < until
        {
            bail!("{}", biometric::UnlockError::Cancelled);
        }

        let flight_or_wait = {
            let mut guard = self
                .biometric_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = guard.as_ref() {
                Err(existing.rx.clone())
            } else {
                let cancel = biometric::CancelHandle::new();
                let (tx, rx) = watch::channel(None);
                *guard = Some(BiometricFlight {
                    cancel: cancel.clone(),
                    rx,
                });
                Ok((cancel, tx))
            }
        };

        let (cancel, done_tx) = match flight_or_wait {
            Err(mut rx) => {
                let outcome = rx
                    .wait_for(Option::is_some)
                    .await
                    .ok()
                    .and_then(|v| v.clone())
                    .unwrap_or_else(|| Err(biometric::UnlockError::Cancelled.to_string()));
                // The finger was for the prompt's own request: this one may
                // only shorten the timeout that request set, and never claims
                // `unsealed_here = true` for passkey UV.
                return match outcome {
                    Ok(()) => self
                        .with(|_| self.tighten_timeout(timeout_secs))
                        .map(|_| false),
                    Err(msg) => bail!("{msg}"),
                };
            }
            Ok(pair) => pair,
        };

        struct FlightCleanup<'a> {
            daemon: &'a Daemon,
            cancel: Arc<biometric::CancelHandle>,
            done_tx: Option<watch::Sender<Option<Result<(), String>>>>,
        }
        impl FlightCleanup<'_> {
            fn clear_flight(&self) {
                let mut guard = self
                    .daemon
                    .biometric_flight
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if guard
                    .as_ref()
                    .is_some_and(|f| Arc::ptr_eq(&f.cancel, &self.cancel))
                {
                    *guard = None;
                }
            }
        }
        impl Drop for FlightCleanup<'_> {
            fn drop(&mut self) {
                self.cancel.cancel();
                self.clear_flight();
                if let Some(tx) = self.done_tx.take() {
                    tx.send_replace(Some(Err(biometric::UnlockError::Cancelled.to_string())));
                }
            }
        }

        let mut cleanup = FlightCleanup {
            daemon: self,
            cancel: cancel.clone(),
            done_tx: Some(done_tx),
        };

        let res = self
            .run_biometric_leader(timeout_secs, reason, cancel.clone())
            .await;
        cleanup.clear_flight();
        if let Some(tx) = cleanup.done_tx.take() {
            let broadcast = match &res {
                Ok(_) => Ok(()),
                Err(err) => Err(format!("{err:#}")),
            };
            tx.send_replace(Some(broadcast));
        }
        res
    }

    async fn run_biometric_leader(
        self: &Arc<Self>,
        timeout_secs: Option<u64>,
        reason: &str,
        cancel: Arc<biometric::CancelHandle>,
    ) -> Result<bool> {
        let now = session::now();
        let token = {
            let _transition = self.transition.lock().await;
            self.close_quarantined(&_transition).await;
            let open = self
                .session
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|s| {
                    s.ensure_usable()?;
                    Ok::<_, anyhow::Error>(s.store.biometric_token()?)
                });
            if let Some(token) = open {
                let token = token?;
                // Unlocked: the prompt only verifies a longer timeout.
                if self.with(|_| self.tighten_timeout(timeout_secs))? {
                    return Ok(false);
                }
                let Some(token) = token else {
                    bail!("{}", biometric::UnlockError::NotEnrolled);
                };
                if let Err(err) = biometric::validate_token(&token, true, now) {
                    bail!("{err}");
                }
                token
            } else {
                let dir = self.paths.data.clone();
                let raw =
                    tokio::task::spawn_blocking(move || deadbolt_store::biometric_token(&dir))
                        .await?;
                let token = match raw {
                    Ok(Some(token)) => token,
                    Ok(None) => {
                        *self
                            .biometric_slot
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()) = None;
                        bail!("{}", biometric::UnlockError::NotEnrolled);
                    }
                    Err(ref err) if biometric::is_biometric_slot_error(err) => {
                        let msg = err.to_string();
                        let dir = self.paths.data.clone();
                        drop(
                            tokio::task::spawn_blocking(move || {
                                deadbolt_store::clear_biometric(&dir)
                            })
                            .await,
                        );
                        self.biometric_was_enrolled.store(true, Ordering::SeqCst);
                        *self
                            .biometric_slot
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()) = None;
                        bail!("{}", biometric::UnlockError::Invalidated(msg));
                    }
                    Err(err) => return Err(err.into()),
                };
                if let Err(err) = biometric::validate_token(&token, true, now) {
                    let dir = self.paths.data.clone();
                    let expected = token.clone();
                    drop(
                        tokio::task::spawn_blocking(move || {
                            biometric::clear_biometric_if_matches(&dir, &expected)
                        })
                        .await,
                    );
                    self.biometric_was_enrolled.store(true, Ordering::SeqCst);
                    *self
                        .biometric_slot
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = None;
                    bail!("{err}");
                }
                token
            }
        };

        // Run the interactive Touch ID unseal WITHOUT holding `self.transition`
        // or keeping `store.redb` open, so a concurrent passphrase Unlock or
        // Lock can cancel the prompt immediately and never hits `Error::InUse`.
        let prompt_reason = reason.to_string();
        let unsealed = {
            #[cfg(test)]
            let hook = self
                .biometric_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            #[cfg(test)]
            if let Some(hook) = hook {
                let cancel_for_hook = cancel.clone();
                tokio::task::spawn_blocking(move || hook(&cancel_for_hook)).await?
            } else {
                let cancel_for_unseal = cancel.clone();
                let token_for_unseal = token.clone();
                tokio::task::spawn_blocking(move || {
                    biometric::unseal_token(
                        &token_for_unseal,
                        now,
                        &prompt_reason,
                        &cancel_for_unseal,
                        biometric::PROMPT_TIMEOUT,
                    )
                })
                .await?
            }
            #[cfg(not(test))]
            {
                let cancel_for_unseal = cancel.clone();
                let token_for_unseal = token.clone();
                tokio::task::spawn_blocking(move || {
                    biometric::unseal_token(
                        &token_for_unseal,
                        now,
                        &prompt_reason,
                        &cancel_for_unseal,
                        biometric::PROMPT_TIMEOUT,
                    )
                })
                .await?
            }
        };

        let key = match unsealed {
            Ok(key) => key,
            Err(biometric::UnlockError::Cancelled) => {
                if !cancel.is_cancelled() {
                    *self
                        .biometric_cooldown_until
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) =
                        Some(Instant::now() + BIOMETRIC_CANCEL_COOLDOWN);
                }
                bail!("{}", biometric::UnlockError::Cancelled);
            }
            Err(
                err @ (biometric::UnlockError::Invalidated(_) | biometric::UnlockError::Expired(_)),
            ) => {
                if !cancel.is_cancelled() {
                    let _transition = self.transition.lock().await;
                    if !cancel.is_cancelled()
                        && self
                            .session
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .is_none()
                    {
                        let dir = self.paths.data.clone();
                        let expected = token.clone();
                        let cleared = tokio::task::spawn_blocking(move || {
                            biometric::clear_biometric_if_matches(&dir, &expected)
                        })
                        .await
                        .unwrap_or(false);
                        if cleared {
                            self.biometric_was_enrolled.store(true, Ordering::SeqCst);
                            *self
                                .biometric_slot
                                .lock()
                                .unwrap_or_else(|e| e.into_inner()) = None;
                        }
                    }
                }
                bail!("{err}");
            }
            Err(err) => bail!("{err}"),
        };

        let _transition = self.transition.lock().await;
        self.close_quarantined(&_transition).await;
        if self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            self.with(|_| self.set_timeout(timeout_secs))?;
            return Ok(true);
        }
        if cancel.is_cancelled() {
            bail!("{}", biometric::UnlockError::Cancelled);
        }

        let dir = self.paths.data.clone();
        let expected_token = token;
        let opened = tokio::task::spawn_blocking(move || {
            match deadbolt_store::unlock_biometric(&dir, &key) {
                Ok(store) => {
                    let meta =
                        biometric::token_meta(store.biometric_token().ok().flatten().as_deref());
                    let loaded = Loaded::from_unlocked(store)
                        .map_err(|e| (biometric::UnlockError::from(e), false))?;
                    Ok((loaded, meta))
                }
                Err(ref err) if biometric::is_biometric_slot_error(err) => {
                    let cleared = biometric::clear_biometric_if_matches(&dir, &expected_token);
                    Err((
                        biometric::UnlockError::Invalidated(
                            "biometric key rejected by store header".into(),
                        ),
                        cleared,
                    ))
                }
                Err(err) => Err((biometric::UnlockError::Store(err), false)),
            }
        })
        .await?;

        let (loaded, meta) = match opened {
            Ok(pair) => pair,
            Err((err, cleared)) => {
                if cleared {
                    self.biometric_was_enrolled.store(true, Ordering::SeqCst);
                    *self
                        .biometric_slot
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = None;
                }
                bail!("{err}");
            }
        };

        if meta.is_some() {
            self.biometric_was_enrolled.store(true, Ordering::SeqCst);
        }
        *self
            .biometric_slot
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = meta;
        self.start(loaded, timeout_secs).await?;
        Ok(true)
    }

    async fn set_touch_id(&self, enabled: bool) -> Result<()> {
        self.cancel_biometric_prompt();
        let _transition = self.transition.lock().await;
        self.settle_activity(true);
        *self
            .biometric_cooldown_until
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        if enabled {
            if !self.refresh_touch_id_available().await {
                bail!("Touch ID is not available on this Mac");
            }
            if self
                .session
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_none()
            {
                return Err(if deadbolt_store::is_initialized(&self.paths.data) {
                    fail(ErrorCode::Locked, "locked: run `deadbolt unlock`")
                } else {
                    fail(
                        ErrorCode::NotInitialized,
                        "this device is not set up; run `deadbolt init` or `deadbolt join`",
                    )
                });
            }
            let now = session::now();
            let sealed = tokio::task::spawn_blocking(move || biometric::seal_new(now)).await??;
            self.with(|s| {
                s.store
                    .set_biometric(&sealed.key, &sealed.token)
                    .context("saving Touch ID key slot")?;
                crate::config::set_touch_id(&self.paths.config, true)
                    .context("updating config.toml")
            })?;
            self.biometric_was_enrolled.store(true, Ordering::SeqCst);
            *self
                .biometric_slot
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(sealed.meta);
            Ok(())
        } else {
            crate::config::set_touch_id(&self.paths.config, false)
                .context("updating config.toml")?;
            self.biometric_was_enrolled.store(false, Ordering::SeqCst);
            *self
                .biometric_slot
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = None;
            let clear_open = {
                let guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
                guard.as_ref().map(|s| s.store.clear_biometric())
            };
            match clear_open {
                Some(res) => {
                    res.context("clearing Touch ID key slot")?;
                }
                None if deadbolt_store::is_initialized(&self.paths.data) => {
                    let dir = self.paths.data.clone();
                    tokio::task::spawn_blocking(move || deadbolt_store::clear_biometric(&dir))
                        .await?
                        .context("clearing Touch ID key slot")?;
                }
                None => {}
            }
            Ok(())
        }
    }

    async fn start(self: &Arc<Self>, loaded: Loaded, timeout_secs: Option<u64>) -> Result<()> {
        loaded.ensure_usable()?;
        let secret = *loaded.secret.to_bytes();
        let config = if self.local_net {
            NodeConfig::local_only(secret)
        } else {
            NodeConfig::new(secret)
        };
        let members = self.members.clone();
        let gate: Arc<dyn Membership> = Arc::new(move |id: &[u8; 32]| {
            members
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .contains(id)
        });
        self.ready.send_replace(false);
        let node = Node::spawn(config, gate, sync::Handler(self.clone())).await?;
        let mut session = Session::new(loaded, node);
        self.refresh(&mut session);
        self.ready.send_replace(session.peer_set().is_empty());
        let id: DeviceId = session.id;
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = Some(session);
        self.watchers.unlocked();
        self.settle_activity(false);
        self.set_timeout(timeout_secs)?;
        self.with(|s| {
            s.sync_task = Some(AbortOnDrop(tokio::spawn(sync::run(self.clone()))));
            s.health_task = Some(AbortOnDrop(tokio::spawn(health::run_background(
                self.clone(),
            ))));
            Ok(())
        })?;
        info!(device = %id, "unlocked");
        Ok(())
    }

    async fn lock(&self) {
        self.cancel_biometric_prompt();
        self.interrupt_op();
        let transition = self.transition.lock().await;
        self.close_session(&transition).await;
    }

    /// Only an explicit unlock retires quarantine; all normal reads/retries
    /// continue to fail closed. The transition serializes close with open and
    /// lock, and avoids calling lock() while already holding its mutex.
    async fn close_quarantined(&self, transition: &tokio::sync::MutexGuard<'_, ()>) {
        let quarantined = self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|s| s.append_uncertain);
        if quarantined {
            // Quarantine already cancelled prompts and background work. Do not
            // cancel a new biometric flight that is authenticating recovery.
            self.close_session(transition).await;
        }
    }

    async fn close_session(&self, _transition: &tokio::sync::MutexGuard<'_, ()>) {
        self.settle_activity(true);
        *self
            .biometric_cooldown_until
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        let session = self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        self.members
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.ready.send_replace(false);
        *self.idle.lock().unwrap_or_else(|e| e.into_inner()) = Idle::default();
        if let Some(mut session) = session {
            self.watchers.locked();
            session.health_task.take();
            session.sync_task.take();
            session.node.shutdown().await;
            drop(session);
            info!("locked");
        }
    }
}
