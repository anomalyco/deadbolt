//! macOS AutoFill Credential Provider backend (`docs/macos-autofill.md`).
//!
//! Serves `DeadboltAutoFill.appex` (`pw.deadbolt.app.autofill`) over a
//! dedicated Unix socket (`s`, mode 0600) in the shared Team-ID App Group
//! container (`~/Library/Group Containers/<TEAM_ID>.pw.deadbolt`). The agent
//! remains the only process that opens `store.redb` or holds vault keys.

mod identities;
mod picker;
#[cfg(test)]
mod tests;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use deadbolt_core::totp::Totp;
use deadbolt_core::{Item, ItemId, VaultId, passkeys as shared_passkeys, site as core_site};
use tokio::net::UnixListener;

pub use identities::{identities, identities_hash};
use picker::{MAX_CREDENTIALS, list_for_picker, resolve_service};

use super::autofill::{self, login_ref, otp, value};
use super::items::label;
use super::passkeys;
use super::session::{self, Loaded, unhex};
use super::{Agent, Conversation, ErrorCode, biometric, fail};
use crate::browser::host::Bucket;
use crate::protocol::{
    CallerClass, CallerInfo, Command, Fill, LoginRef, Reply, Secret, SiteValues, Verify,
};
use crate::webauthn;

/// Short filename so `~/Library/Group Containers/<TEAM>.pw.deadbolt/s` stays
/// well within `sockaddr_un.sun_path`'s 104-byte limit on macOS.
pub const SOCKET_NAME: &str = "s";

/// Maximum UTF-8 byte length of a Unix domain socket path on macOS (`104 - 1`).
pub const SUN_PATH_MAX: usize = 103;

const FILL_RATE: (u32, Duration) = (60, Duration::from_millis(250));
const PASSKEY_RATE: (u32, Duration) = (10, Duration::from_secs(1));

/// Which listener accepted a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    Control,
    AutoFill,
}

/// Binds the macOS AutoFill socket inside `container` (`0700`, owned by this
/// user, never a symlink) as `<container>/s` (`0600`).
pub fn bind_in(container: &Path) -> Result<(UnixListener, PathBuf)> {
    deadbolt_client::paths::secure_dir(container)
        .with_context(|| format!("checking {}", container.display()))?;
    let path = container.join(SOCKET_NAME);
    let len = path.as_os_str().as_encoded_bytes().len();
    if len > SUN_PATH_MAX {
        bail!(
            "AutoFill socket path {} is {len} bytes (max {SUN_PATH_MAX})",
            path.display()
        );
    }
    super::remove_socket(&path)?;
    let listener =
        UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting permissions on {}", path.display()))?;
    Ok((listener, path))
}

/// Resolves and binds the default macOS App Group AutoFill socket when this
/// build is signed with an Apple Team ID and the App Group entitlement.
pub async fn bind_default() -> Option<(UnixListener, PathBuf)> {
    if let Some(dir) =
        crate::config::test_env("DEADBOLT_TEST_AUTOFILL_DIR").filter(|s| !s.is_empty())
    {
        return match bind_in(Path::new(&dir)) {
            Ok(bound) => Some(bound),
            Err(error) => {
                tracing::warn!("binding test AutoFill socket in {dir}: {error:#}");
                None
            }
        };
    }
    let group = deadbolt_client::peer::app_group()?;
    let container =
        match tokio::task::spawn_blocking(move || biometric::group_container(&group)).await {
            Ok(Ok(Some(dir))) => dir,
            Ok(Ok(None)) => return None,
            Ok(Err(error)) => {
                tracing::warn!("resolving macOS AutoFill App Group container: {error:#}");
                return None;
            }
            Err(error) => {
                tracing::warn!("joining App Group container probe: {error}");
                return None;
            }
        };
    match bind_in(&container) {
        Ok(bound) => Some(bound),
        Err(error) => {
            tracing::warn!(
                "binding macOS AutoFill socket in {}: {error:#}",
                container.display()
            );
            None
        }
    }
}

/// Whether `command` is one of the dedicated `autofill-*` protocol commands.
pub fn is_autofill_command(command: &Command) -> bool {
    matches!(
        command,
        Command::AutofillStatus
            | Command::AutofillIdentities
            | Command::AutofillList { .. }
            | Command::AutofillFill { .. }
            | Command::AutofillPasskeyGet { .. }
            | Command::AutofillPasskeyCreate { .. }
    )
}

/// Enforces the two-way boundary around `CallerClass::AutoFill` and the App
/// Group socket:
/// - Only `CallerClass::AutoFill` may connect on `SocketKind::AutoFill` or
///   invoke `Command::Autofill*` on any socket.
/// - `CallerClass::AutoFill` may invoke only `Status`, default-timeout `Unlock`
///   and `UnlockBiometric`, and `Command::Autofill*`.
pub fn check_access(socket: SocketKind, caller: &CallerInfo, command: &Command) -> Result<()> {
    if socket == SocketKind::AutoFill && caller.class != CallerClass::AutoFill {
        return Err(fail(
            ErrorCode::Forbidden,
            "only Deadbolt's macOS AutoFill extension may use this socket",
        ));
    }
    if is_autofill_command(command) && caller.class != CallerClass::AutoFill {
        return Err(fail(
            ErrorCode::Forbidden,
            "only Deadbolt's macOS AutoFill extension may run macOS AutoFill commands",
        ));
    }
    if caller.class == CallerClass::AutoFill {
        let allowed = matches!(
            command,
            Command::Status
                | Command::Unlock {
                    timeout_secs: None,
                    ..
                }
                | Command::UnlockBiometric { timeout_secs: None }
                | Command::AutofillStatus
                | Command::AutofillIdentities
                | Command::AutofillList { .. }
                | Command::AutofillFill { .. }
                | Command::AutofillPasskeyGet { .. }
                | Command::AutofillPasskeyCreate { .. }
        );
        if !allowed {
            return Err(fail(
                ErrorCode::Forbidden,
                "macOS AutoFill may not run this command",
            ));
        }
    }
    Ok(())
}

fn find_any_login(s: &Loaded, login: &LoginRef) -> Result<(VaultId, Item)> {
    let not_found = || fail(ErrorCode::NotFound, "no such login");
    let vault = VaultId::from_bytes(unhex(&login.vault).map_err(|_| not_found())?);
    let id = ItemId::from_bytes(unhex(&login.item).map_err(|_| not_found())?);
    let item = s
        .vaults
        .get(&vault)
        .and_then(|v| v.item(&id))
        .filter(|item| !item.deleted && item.kind == "login")
        .ok_or_else(not_found)?;
    Ok((vault, item))
}

fn extract_values(item: &Item, want: &[Fill], now: Duration) -> Result<SiteValues> {
    let mut values = SiteValues::default();
    for fill in want {
        match fill {
            Fill::Username => values.username = value(item, "username").map(str::to_string),
            Fill::Password => values.password = value(item, "password").map(Secret::new),
            Fill::Totp => {
                let Some(field) = otp(item).filter(|f| !f.value.is_empty()) else {
                    continue;
                };
                let totp = Totp::parse(&field.value).map_err(|e| {
                    anyhow!("the one-time password of {} is invalid: {e}", label(item))
                })?;
                values.totp = Some(Secret::new(totp.code(now.as_secs())));
            }
        }
    }
    Ok(values)
}

fn map_passkey_error(error: shared_passkeys::Error) -> anyhow::Error {
    match error {
        shared_passkeys::Error::DomainMismatch(_) => {
            fail(ErrorCode::DomainMismatch, error.to_string())
        }
        shared_passkeys::Error::Exists => fail(ErrorCode::Exists, error.to_string()),
        shared_passkeys::Error::NotFound => fail(ErrorCode::NotFound, error.to_string()),
        _ => error.into(),
    }
}

pub(super) fn is_biometric_cancelled(error: &anyhow::Error) -> bool {
    error.to_string() == biometric::UnlockError::Cancelled.to_string()
        || error.to_string() == "Touch ID was cancelled"
        || error.to_string() == "the request was cancelled"
}

impl Agent {
    fn take_autofill_fill_rate(&self) -> Result<()> {
        let mut bucket = self
            .autofill_fill_rate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if !bucket
            .get_or_insert_with(|| Bucket::new(FILL_RATE, now))
            .take(now)
        {
            return Err(fail(
                ErrorCode::RateLimited,
                "too many AutoFill requests; try again in a moment",
            ));
        }
        Ok(())
    }

    fn take_autofill_passkey_rate(&self) -> Result<()> {
        let mut bucket = self
            .autofill_passkey_rate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if !bucket
            .get_or_insert_with(|| Bucket::new(PASSKEY_RATE, now))
            .take(now)
        {
            return Err(fail(
                ErrorCode::RateLimited,
                "too many passkey requests; try again in a moment",
            ));
        }
        Ok(())
    }

    /// Ensures the store is unlocked before an AutoFill fill or passkey
    /// ceremony. When locked with `interactive == true` and Touch ID ready,
    /// prompts Touch ID once with `reason` (cancelling if `conv` closes) and
    /// returns `Ok(true)` when this call's own Touch ID prompt unsealed the
    /// biometric key.
    async fn ensure_unlocked_for_ceremony(
        self: &Arc<Self>,
        conv: &Conversation,
        interactive: bool,
        reason: &str,
    ) -> Result<bool> {
        if self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Ok(false);
        }
        if !deadbolt_store::is_initialized(&self.paths.data) {
            return Err(fail(
                ErrorCode::NotInitialized,
                "this device is not set up; open Deadbolt to set it up",
            ));
        }
        let st = self.status();
        if !interactive || !st.touch_id_ready {
            return Err(fail(ErrorCode::Locked, "locked: unlock Deadbolt to fill"));
        }
        let outcome = tokio::select! {
            res = self.unlock_biometric_with_reason(None, reason) => res,
            () = conv.closed() => return Err(fail(ErrorCode::Cancelled, "the request was cancelled")),
        };
        match outcome {
            Ok(unsealed_here) => Ok(unsealed_here),
            Err(error) if is_biometric_cancelled(&error) => {
                Err(fail(ErrorCode::Cancelled, error.to_string()))
            }
            Err(error) => Err(error),
        }
    }

    async fn verify_ceremony(
        &self,
        conv: &Conversation,
        verify: Verify,
        reason: &str,
    ) -> Result<bool> {
        match self.verify_user(conv, verify, reason).await {
            Ok(verified) => Ok(verified),
            Err(error) if is_biometric_cancelled(&error) => {
                Err(fail(ErrorCode::Cancelled, error.to_string()))
            }
            Err(error) => Err(error),
        }
    }

    pub(super) async fn macos_autofill(
        self: Arc<Self>,
        command: Command,
        conv: &Conversation,
    ) -> Result<Reply> {
        match command {
            Command::AutofillStatus => {
                let st = self.status();
                let identities_hash = if st.unlocked {
                    self.with(|s| Ok(identities_hash(s))).ok()
                } else {
                    None
                };
                Ok(Reply::AutofillStatus {
                    initialized: st.initialized,
                    unlocked: st.unlocked,
                    touch_id_ready: st.touch_id_ready,
                    touch_id_reset: st.touch_id_reset,
                    can_verify: st.unlocked && self.can_verify(),
                    identities_hash,
                })
            }
            Command::AutofillIdentities => {
                let snap = self.with(|s| Ok(identities(s)))?;
                Ok(Reply::AutofillIdentities {
                    identities_hash: snap.hash,
                    passwords: snap.passwords,
                    passkeys: snap.passkeys,
                    one_time_codes: snap.one_time_codes,
                })
            }
            Command::AutofillList {
                services,
                rp_id,
                allowed_credentials,
                for_otp,
            } => {
                let can_verify = self.can_verify();
                self.with(|s| {
                    list_for_picker(
                        s,
                        &services,
                        rp_id.as_deref(),
                        &allowed_credentials,
                        for_otp,
                        can_verify,
                    )
                })
            }
            Command::AutofillFill {
                service,
                login,
                want,
                interactive,
            } => {
                if want.is_empty() || want.len() > 3 {
                    bail!("autofill-fill wants 1 to 3 fields");
                }
                let resolved = match &service {
                    Some(svc) => Some(resolve_service(svc)?),
                    None => {
                        if !interactive {
                            return Err(fail(
                                ErrorCode::InteractionRequired,
                                "filling into an unassociated app requires confirmation",
                            ));
                        }
                        None
                    }
                };
                self.take_autofill_fill_rate()?;
                let unlock_reason = match &resolved {
                    Some((site, _)) => format!("unlock Deadbolt and fill on {}", site.domain),
                    None => "unlock Deadbolt and fill in an app".to_string(),
                };
                let unlocked_by_touch_id = self
                    .ensure_unlocked_for_ceremony(conv, interactive, &unlock_reason)
                    .await?;

                match resolved {
                    Some((_, origin)) => {
                        let (values, hash) = self.with(|s| {
                            let values = autofill::fill(
                                s,
                                &origin,
                                &login,
                                &want,
                                crate::config::wall_clock(),
                            )?;
                            Ok((values, identities_hash(s)))
                        })?;
                        Ok(Reply::AutofillFill {
                            values,
                            identities_hash: hash,
                        })
                    }
                    None => {
                        let title = self.with(|s| {
                            let (_, item) = find_any_login(s, &login)?;
                            Ok(label(&item))
                        })?;
                        if !unlocked_by_touch_id {
                            let reason = format!("fill {title} in an app");
                            self.verify_ceremony(conv, Verify::Preferred, &reason)
                                .await?;
                        }
                        let now = crate::config::wall_clock();
                        let (values, hash) = self.with(|s| {
                            let (_, item) = find_any_login(s, &login)?;
                            let values = extract_values(&item, &want, now)?;
                            let key = format!("{}:{}", login.vault, login.item);
                            s.set_filled(key, now.as_secs())?;
                            Ok((values, identities_hash(s)))
                        })?;
                        Ok(Reply::AutofillFill {
                            values,
                            identities_hash: hash,
                        })
                    }
                }
            }
            Command::AutofillPasskeyGet {
                rp_id,
                passkey,
                client_data_hash,
                verify,
                interactive,
            } => {
                let rp = core_site::valid_rp_id(&rp_id).map_err(|reason| {
                    fail(ErrorCode::DomainMismatch, format!("{rp_id}: {reason}"))
                })?;
                webauthn::client_data_hash(&client_data_hash).map_err(|e| anyhow!("{e}"))?;
                self.take_autofill_passkey_rate()?;

                if !interactive {
                    self.with(|s| passkeys::find(s, &passkey, &rp).map(drop))?;
                    match verify {
                        Verify::Discouraged => {}
                        Verify::Preferred if !self.can_verify() => {}
                        Verify::Required if !self.can_verify() => {
                            bail!(
                                "this site requires user verification, and Touch ID is off or not set up"
                            );
                        }
                        Verify::Preferred | Verify::Required => {
                            return Err(fail(
                                ErrorCode::InteractionRequired,
                                "Touch ID user verification requires interactive presentation",
                            ));
                        }
                    }
                    let (signed, hash) = self.with(|s| {
                        let (_, item) = passkeys::find(s, &passkey, &rp)?;
                        let signed =
                            shared_passkeys::sign_hash(&item, &rp, &client_data_hash, false)
                                .map_err(map_passkey_error)?;
                        Ok((signed, identities_hash(s)))
                    })?;
                    return Ok(Reply::AutofillPasskeyAssertion {
                        credential_id: signed.credential_id,
                        client_data_hash: signed.client_data_hash,
                        authenticator_data: signed.authenticator_data,
                        signature: signed.signature,
                        user_handle: signed.user_handle,
                        verified: false,
                        identities_hash: hash,
                    });
                }

                let unlock_reason = format!("unlock Deadbolt and sign in to {rp} with a passkey");
                let unlocked_by_touch_id = self
                    .ensure_unlocked_for_ceremony(conv, true, &unlock_reason)
                    .await?;
                self.with(|s| passkeys::find(s, &passkey, &rp).map(drop))?;
                let verified = if verify == Verify::Discouraged {
                    false
                } else if unlocked_by_touch_id {
                    true
                } else {
                    let reason = format!("sign in to {rp} with a passkey");
                    self.verify_ceremony(conv, verify, &reason).await?
                };
                let (signed, hash) = self.with(|s| {
                    let (_, item) = passkeys::find(s, &passkey, &rp)?;
                    let signed =
                        shared_passkeys::sign_hash(&item, &rp, &client_data_hash, verified)
                            .map_err(map_passkey_error)?;
                    Ok((signed, identities_hash(s)))
                })?;
                Ok(Reply::AutofillPasskeyAssertion {
                    credential_id: signed.credential_id,
                    client_data_hash: signed.client_data_hash,
                    authenticator_data: signed.authenticator_data,
                    signature: signed.signature,
                    user_handle: signed.user_handle,
                    verified,
                    identities_hash: hash,
                })
            }
            Command::AutofillPasskeyCreate {
                rp_id,
                client_data_hash,
                user_id,
                user_name,
                user_display_name,
                exclude,
                verify,
                interactive,
            } => {
                if exclude.len() > MAX_CREDENTIALS {
                    bail!("at most {MAX_CREDENTIALS} excluded credentials");
                }
                let mut new = shared_passkeys::check_create_hash(
                    &rp_id,
                    &client_data_hash,
                    &user_id,
                    &user_name,
                    &exclude,
                )
                .map_err(map_passkey_error)?;
                new.display_name = shared_passkeys::user_text(&user_display_name);
                self.take_autofill_passkey_rate()?;

                if !interactive {
                    self.with(|s| {
                        let items: Vec<_> = passkeys::passkeys(s, &new.rp_id)
                            .map(|(_, item)| item)
                            .collect();
                        shared_passkeys::check_excluded(&items, &new.rp_id, &new.exclude)
                            .map_err(map_passkey_error)
                    })?;
                    match verify {
                        Verify::Discouraged => {}
                        Verify::Preferred if !self.can_verify() => {}
                        Verify::Required if !self.can_verify() => {
                            bail!(
                                "this site requires user verification, and Touch ID is off or not set up"
                            );
                        }
                        Verify::Preferred | Verify::Required => {
                            return Err(fail(
                                ErrorCode::InteractionRequired,
                                "Touch ID user verification requires interactive presentation",
                            ));
                        }
                    }
                    let now = i64::try_from(session::now()).unwrap_or(i64::MAX);
                    let (made, passkey, hash) = self.with(|s| {
                        let items: Vec<_> = passkeys::passkeys(s, &new.rp_id)
                            .map(|(_, item)| item)
                            .collect();
                        shared_passkeys::check_excluded(&items, &new.rp_id, &new.exclude)
                            .map_err(map_passkey_error)?;
                        let created = crate::import::onepassword::date(now);
                        let made = shared_passkeys::register_hash(&new, false, &created)
                            .map_err(map_passkey_error)?;
                        let vault = s.resolve(None)?;
                        let entry = s.update(vault, |v, secret| {
                            Ok(v.write(secret, vec![made.create.clone()])?)
                        })?;
                        let passkey = login_ref(&vault, &ItemId::of_create(&entry.hash(), 0));
                        Ok((made, passkey, identities_hash(s)))
                    })?;
                    self.sync_now.notify_one();
                    return Ok(Reply::AutofillPasskeyCreated {
                        passkey,
                        credential_id: made.credential_id,
                        client_data_hash: made.client_data_hash,
                        attestation_object: made.attestation_object,
                        authenticator_data: made.authenticator_data,
                        public_key: made.public_key,
                        verified: false,
                        identities_hash: hash,
                    });
                }

                let unlock_reason = format!("unlock Deadbolt and save a passkey for {}", new.rp_id);
                let unlocked_by_touch_id = self
                    .ensure_unlocked_for_ceremony(conv, true, &unlock_reason)
                    .await?;
                self.with(|s| {
                    let items: Vec<_> = passkeys::passkeys(s, &new.rp_id)
                        .map(|(_, item)| item)
                        .collect();
                    shared_passkeys::check_excluded(&items, &new.rp_id, &new.exclude)
                        .map_err(map_passkey_error)
                })?;
                let verified = if verify == Verify::Discouraged {
                    false
                } else if unlocked_by_touch_id {
                    true
                } else {
                    let reason = format!("save a passkey for {}", new.rp_id);
                    self.verify_ceremony(conv, verify, &reason).await?
                };
                let now = i64::try_from(session::now()).unwrap_or(i64::MAX);
                let (made, passkey, hash) = self.with(|s| {
                    let items: Vec<_> = passkeys::passkeys(s, &new.rp_id)
                        .map(|(_, item)| item)
                        .collect();
                    shared_passkeys::check_excluded(&items, &new.rp_id, &new.exclude)
                        .map_err(map_passkey_error)?;
                    let created = crate::import::onepassword::date(now);
                    let made = shared_passkeys::register_hash(&new, verified, &created)
                        .map_err(map_passkey_error)?;
                    let vault = s.resolve(None)?;
                    let entry = s.update(vault, |v, secret| {
                        Ok(v.write(secret, vec![made.create.clone()])?)
                    })?;
                    let passkey = login_ref(&vault, &ItemId::of_create(&entry.hash(), 0));
                    Ok((made, passkey, identities_hash(s)))
                })?;
                self.sync_now.notify_one();
                Ok(Reply::AutofillPasskeyCreated {
                    passkey,
                    credential_id: made.credential_id,
                    client_data_hash: made.client_data_hash,
                    attestation_object: made.attestation_object,
                    authenticator_data: made.authenticator_data,
                    public_key: made.public_key,
                    verified,
                    identities_hash: hash,
                })
            }
            _ => bail!("not a macOS AutoFill request"),
        }
    }
}
