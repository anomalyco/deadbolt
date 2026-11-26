//! Secure Enclave Touch ID enrollment and unlock for the local store.
//!
//! See `docs/touch-id.md` for the full design. On macOS, a small compiled Swift
//! helper (`deadbolt-enclave`, pinned by SHA-256 at build time) creates a
//! hardware-bound P-256 key inside the Secure Enclave
//! (`CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey`) and seals a random
//! 256-bit `biometric_key` with ECDH + HKDF-SHA256 + AES-256-GCM. The resulting
//! envelope and the AEAD-wrapped key set live in the sealed store.

use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::disk::Zeroizing;
use anyhow::{Result, bail};

/// Re-confirm the vault passphrase at least once every 14 days so the user
/// does not forget their passphrase while relying on Touch ID.
pub const MAX_AGE_SECS: u64 = 14 * 24 * 60 * 60;

/// Maximum time an interactive Touch ID prompt may stay open before the helper
/// is killed and the dialog dismissed.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for non-interactive helper probes (`status`, `seal`).
#[cfg(target_os = "macos")]
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

const AVAILABLE_TTL: Duration = Duration::from_secs(60);
const UNAVAILABLE_TTL: Duration = Duration::from_secs(2);

const MAGIC: &[u8; 4] = b"DBSE";
const VERSION: u8 = 1;
const FLAG_BIOMETRY_CURRENT_SET: u8 = 1 << 0;
const HEADER_LEN: usize = 4 + 1 + 1 + 8;

/// Test-only policy switches for exercising the Secure Enclave headlessly.
#[cfg(all(test, target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealPolicy {
    /// Require `.biometryCurrentSet` in the Secure Enclave key's access control.
    pub require_biometry: bool,
    /// Allow macOS to display the interactive Touch ID prompt during `unseal`.
    pub interactive: bool,
    /// Optional test sleep before unsealing (`--sleep-ms`).
    pub sleep_ms: u32,
}

#[cfg(all(test, target_os = "macos"))]
impl SealPolicy {
    pub const TOUCH_ID: Self = Self {
        require_biometry: true,
        interactive: true,
        sleep_ms: 0,
    };

    pub const HEADLESS_TEST: Self = Self {
        require_biometry: false,
        interactive: false,
        sleep_ms: 0,
    };
}

/// Capabilities reported by `deadbolt-enclave status`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BiometricStatus {
    pub enclave: bool,
    pub biometrics: bool,
}

impl BiometricStatus {
    pub fn is_available(self) -> bool {
        self.enclave && self.biometrics
    }
}

/// Metadata parsed from a `"biometric.token"` header (`"DBSE"`), kept in
/// daemon memory so `status()` never opens the sealed store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenMeta {
    pub flags: u8,
    pub created_at: u64,
}

impl TokenMeta {
    /// Whether this token was enrolled with `.biometryCurrentSet` and is
    /// within the 14-day fresh-passphrase window `[created_at, created_at + MAX_AGE_SECS]`.
    pub fn is_ready(self, now_secs: u64) -> bool {
        (self.flags & FLAG_BIOMETRY_CURRENT_SET != 0)
            && now_secs >= self.created_at
            && now_secs - self.created_at <= MAX_AGE_SECS
    }
}

/// Sealed biometric key + token ready to be written into the sealed store.
pub struct SealedBiometric {
    pub key: Zeroizing<[u8; 32]>,
    pub token: Vec<u8>,
    pub meta: TokenMeta,
}

/// Handle used by the daemon to cancel an in-flight `deadbolt-enclave` prompt
/// (on passphrase `Unlock`, `Lock`, `TouchIdSet`, `Stop`, or `Daemon` drop),
/// immediately killing the helper process and dismissing the Touch ID dialog.
#[derive(Default)]
pub struct CancelHandle {
    cancelled: Mutex<bool>,
    cv: Condvar,
}

impl CancelHandle {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn cancel(&self) {
        let mut guard = self.cancelled.lock().unwrap_or_else(|e| e.into_inner());
        *guard = true;
        self.cv.notify_all();
    }

    pub fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Why a biometric enrollment or unlock attempt did not succeed.
#[derive(Debug)]
pub enum UnlockError {
    NotEnrolled,
    Cancelled,
    Unavailable(String),
    Expired(String),
    Invalidated(String),
    Store(crate::disk::Error),
    Other(anyhow::Error),
}

impl fmt::Display for UnlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnrolled => f.write_str("Touch ID unlock is not enrolled for this store"),
            Self::Cancelled => f.write_str("Touch ID prompt was cancelled"),
            Self::Unavailable(msg) => write!(f, "Touch ID is not available right now: {msg}"),
            Self::Expired(msg) => write!(
                f,
                "Touch ID was reset ({msg}); enter your passphrase to unlock"
            ),
            Self::Invalidated(msg) => write!(
                f,
                "Touch ID was reset ({msg}); enter your passphrase to unlock"
            ),
            Self::Store(err) => err.fmt(f),
            Self::Other(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for UnlockError {}

impl From<crate::disk::Error> for UnlockError {
    fn from(err: crate::disk::Error) -> Self {
        Self::Store(err)
    }
}

impl From<anyhow::Error> for UnlockError {
    fn from(err: anyhow::Error) -> Self {
        Self::Other(err)
    }
}

#[derive(Debug)]
pub struct ParsedToken<'a> {
    pub meta: TokenMeta,
    pub header_aad: &'a [u8],
    pub enclave_blob: &'a [u8],
}

#[cfg(any(target_os = "macos", test))]
fn encode_header(require_biometry: bool, created_at: u64) -> [u8; HEADER_LEN] {
    let flags = if require_biometry {
        FLAG_BIOMETRY_CURRENT_SET
    } else {
        0
    };
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(MAGIC);
    header[4] = VERSION;
    header[5] = flags;
    header[6..14].copy_from_slice(&created_at.to_le_bytes());
    header
}

pub fn parse_token(token: &[u8]) -> Result<ParsedToken<'_>> {
    if token.len() <= HEADER_LEN + 3 {
        bail!("biometric token is truncated");
    }
    if &token[..4] != MAGIC {
        bail!("biometric token has wrong magic");
    }
    let version = token[4];
    if version != VERSION {
        bail!("unsupported biometric token version {version}");
    }
    let flags = token[5];
    let created_at = u64::from_le_bytes([
        token[6], token[7], token[8], token[9], token[10], token[11], token[12], token[13],
    ]);
    Ok(ParsedToken {
        meta: TokenMeta { flags, created_at },
        header_aad: &token[..HEADER_LEN],
        enclave_blob: &token[HEADER_LEN..],
    })
}

/// Parses [`TokenMeta`] from raw `"biometric.token"` bytes.
pub fn token_meta(token: Option<&[u8]>) -> Option<TokenMeta> {
    parse_token(token?).ok().map(|p| p.meta)
}

/// Reads [`TokenMeta`] once from `data_dir` at daemon startup.
pub fn read_token_meta(data_dir: &Path) -> Option<TokenMeta> {
    if !crate::disk::is_initialized(data_dir) {
        return None;
    }
    let token = crate::disk::biometric_token(data_dir).ok().flatten()?;
    token_meta(Some(&token))
}

/// Returns true only when `err` indicates that the biometric header entries
/// (`"biometric.token"` / `"keyset.biometric"`) are invalid or incomplete, not
/// when `open_db` or `Header::read` reports general database corruption.
pub fn is_biometric_slot_error(err: &crate::disk::Error) -> bool {
    match err {
        crate::disk::Error::InvalidBiometric => true,
        crate::disk::Error::Corrupt(msg) => msg.contains("biometric"),
        _ => false,
    }
}

/// Clears the biometric slot in `data_dir` only if `"biometric.token"` still
/// matches `expected_token` (or if the biometric header entry itself is
/// incomplete). Returns whether the slot was cleared.
pub fn clear_biometric_if_matches(data_dir: &Path, expected_token: &[u8]) -> bool {
    match crate::disk::biometric_token(data_dir) {
        Ok(Some(current)) if current == expected_token => {
            crate::disk::clear_biometric(data_dir).unwrap_or(false)
        }
        Err(ref err) if is_biometric_slot_error(err) => {
            crate::disk::clear_biometric(data_dir).unwrap_or(false)
        }
        _ => false,
    }
}

static CACHED_STATUS: Mutex<Option<(BiometricStatus, Instant)>> = Mutex::new(None);
static STATUS_REFRESHING: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "macos")]
static WARNED_HELPER: AtomicBool = AtomicBool::new(false);

/// Returns the cached Touch ID availability without blocking the caller.
///
/// Positive availability is cached for [`AVAILABLE_TTL`] (60 s); negative
/// availability or probe failures are cached for [`UNAVAILABLE_TTL`] (2 s).
/// When the cache is empty or stale, a single background `spawn_blocking`
/// refresh is kicked off so `Daemon::status()` never blocks on a subprocess.
pub fn cached_status() -> BiometricStatus {
    let now = Instant::now();
    let cached = *CACHED_STATUS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((status, at)) = cached {
        let ttl = if status.is_available() {
            AVAILABLE_TTL
        } else {
            UNAVAILABLE_TTL
        };
        if now.saturating_duration_since(at) < ttl {
            return status;
        }
    }
    spawn_background_refresh();
    cached.map(|(status, _)| status).unwrap_or_default()
}

/// Triggers a non-blocking background refresh of [`CACHED_STATUS`] on the
/// current Tokio runtime if no refresh is already running.
pub fn spawn_background_refresh() {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    if STATUS_REFRESHING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    drop(handle.spawn_blocking(|| {
        struct ResetGuard;
        impl Drop for ResetGuard {
            fn drop(&mut self) {
                STATUS_REFRESHING.store(false, Ordering::Release);
            }
        }
        let _guard = ResetGuard;
        refresh_status()
    }));
}

/// Re-probes `deadbolt-enclave status` immediately (blocking) and updates the
/// cache. Probe errors are cached as unavailable for [`UNAVAILABLE_TTL`] and
/// logged at most once until a subsequent probe succeeds.
pub fn refresh_status() -> BiometricStatus {
    #[cfg(target_os = "macos")]
    let status = match macos::status() {
        Ok(status) => {
            WARNED_HELPER.store(false, Ordering::Relaxed);
            status
        }
        Err(err) => {
            if !WARNED_HELPER.swap(true, Ordering::Relaxed) {
                tracing::warn!("Touch ID status probe failed: {err:#}");
            }
            BiometricStatus::default()
        }
    };
    #[cfg(not(target_os = "macos"))]
    let status = BiometricStatus::default();

    *CACHED_STATUS.lock().unwrap_or_else(|e| e.into_inner()) = Some((status, Instant::now()));
    status
}

/// Resolves the shared macOS App Group container directory (`<TEAM_ID>.anomaly.deadbolt`)
/// through `deadbolt-enclave group-container`. Returns `Ok(None)` when the
/// running daemon or helper is not signed with that App Group entitlement (e.g.
/// local ad-hoc builds) or off macOS.
pub fn group_container(group: &str) -> anyhow::Result<Option<std::path::PathBuf>> {
    #[cfg(target_os = "macos")]
    {
        macos::group_container(group)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = group;
        Ok(None)
    }
}

/// Generates a fresh `.biometryCurrentSet` Secure Enclave key and seals a new
/// 256-bit `biometric_key` without touching the sealed store.
pub fn seal_new(now_secs: u64) -> Result<SealedBiometric, UnlockError> {
    seal_inner(true, now_secs)
}

/// Enrolls a fresh `.biometryCurrentSet` Secure Enclave key and writes the
/// biometric slot into `store`.
pub fn enroll(store: &crate::disk::Unlocked, now_secs: u64) -> Result<TokenMeta, UnlockError> {
    let sealed = seal_new(now_secs)?;
    store.set_biometric(&sealed.key, &sealed.token)?;
    Ok(sealed.meta)
}

#[cfg(all(test, target_os = "macos"))]
pub fn enroll_with_policy(
    store: &crate::disk::Unlocked,
    policy: SealPolicy,
    now_secs: u64,
) -> Result<TokenMeta, UnlockError> {
    let sealed = seal_inner(policy.require_biometry, now_secs)?;
    store.set_biometric(&sealed.key, &sealed.token)?;
    Ok(sealed.meta)
}

fn seal_inner(require_biometry: bool, now_secs: u64) -> Result<SealedBiometric, UnlockError> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (require_biometry, now_secs);
        Err(UnlockError::Unavailable(
            "Touch ID is only supported on macOS".into(),
        ))
    }
    #[cfg(target_os = "macos")]
    {
        let key = crate::disk::generate_biometric_key()?;
        let header = encode_header(require_biometry, now_secs);
        let enclave_blob = macos::seal(&key, &header, require_biometry)?;
        let mut token = Vec::with_capacity(header.len() + enclave_blob.len());
        token.extend_from_slice(&header);
        token.extend_from_slice(&enclave_blob);
        let flags = header[5];
        Ok(SealedBiometric {
            key,
            token,
            meta: TokenMeta {
                flags,
                created_at: now_secs,
            },
        })
    }
}

/// Validates the header and age of `token` before invoking `deadbolt-enclave`.
pub fn validate_token(
    token: &[u8],
    require_biometry: bool,
    now_secs: u64,
) -> Result<ParsedToken<'_>, UnlockError> {
    let parsed = parse_token(token).map_err(|e| UnlockError::Invalidated(e.to_string()))?;
    if now_secs < parsed.meta.created_at {
        return Err(UnlockError::Expired(
            "system clock is earlier than Touch ID enrollment time".into(),
        ));
    }
    if now_secs - parsed.meta.created_at > MAX_AGE_SECS {
        return Err(UnlockError::Expired(
            "14-day passphrase confirmation interval elapsed".into(),
        ));
    }
    if require_biometry && (parsed.meta.flags & FLAG_BIOMETRY_CURRENT_SET == 0) {
        return Err(UnlockError::Invalidated(
            "token was not enrolled with biometryCurrentSet".into(),
        ));
    }
    Ok(parsed)
}

/// Unseals the 32-byte `biometric_key` from `token` via `deadbolt-enclave`
/// without holding the sealed store open while the Touch ID prompt is on screen.
pub fn unseal_token(
    token: &[u8],
    now_secs: u64,
    reason: &str,
    cancel: &CancelHandle,
    timeout: Duration,
) -> Result<Zeroizing<[u8; 32]>, UnlockError> {
    unseal_token_inner(token, true, true, 0, now_secs, reason, cancel, timeout)
}

#[expect(
    clippy::too_many_arguments,
    reason = "internal helper shared between production Touch ID unseal and headless Secure Enclave tests"
)]
fn unseal_token_inner(
    token: &[u8],
    require_biometry: bool,
    interactive: bool,
    sleep_ms: u32,
    now_secs: u64,
    reason: &str,
    cancel: &CancelHandle,
    timeout: Duration,
) -> Result<Zeroizing<[u8; 32]>, UnlockError> {
    if cancel.is_cancelled() {
        return Err(UnlockError::Cancelled);
    }
    let parsed = validate_token(token, require_biometry, now_secs)?;

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (
            parsed.header_aad,
            parsed.enclave_blob,
            interactive,
            sleep_ms,
            reason,
            timeout,
        );
        if cancel.is_cancelled() {
            return Err(UnlockError::Cancelled);
        }
        Err(UnlockError::Unavailable(
            "Touch ID is only supported on macOS".into(),
        ))
    }
    #[cfg(target_os = "macos")]
    {
        macos::unseal(
            parsed.header_aad,
            parsed.enclave_blob,
            require_biometry,
            interactive,
            sleep_ms,
            reason,
            cancel,
            timeout,
        )
    }
}

#[cfg(all(test, target_os = "macos"))]
pub fn unlock_with_policy(
    data_dir: &Path,
    policy: SealPolicy,
    now_secs: u64,
    reason: &str,
    cancel: &CancelHandle,
    timeout: Duration,
) -> Result<crate::disk::Unlocked, UnlockError> {
    let token = match crate::disk::biometric_token(data_dir) {
        Ok(Some(token)) => token,
        Ok(None) => return Err(UnlockError::NotEnrolled),
        Err(ref err) if is_biometric_slot_error(err) => {
            drop(crate::disk::clear_biometric(data_dir));
            return Err(UnlockError::Invalidated(err.to_string()));
        }
        Err(err) => return Err(UnlockError::Store(err)),
    };

    let key = match unseal_token_inner(
        &token,
        policy.require_biometry,
        policy.interactive,
        policy.sleep_ms,
        now_secs,
        reason,
        cancel,
        timeout,
    ) {
        Ok(key) => key,
        Err(err @ (UnlockError::Invalidated(_) | UnlockError::Expired(_))) => {
            if !cancel.is_cancelled() {
                clear_biometric_if_matches(data_dir, &token);
            }
            return Err(err);
        }
        Err(err) => return Err(err),
    };

    match crate::disk::unlock_biometric(data_dir, &key) {
        Ok(unlocked) => Ok(unlocked),
        Err(ref err) if is_biometric_slot_error(err) => {
            if !cancel.is_cancelled() {
                clear_biometric_if_matches(data_dir, &token);
            }
            Err(UnlockError::Invalidated(
                "biometric key rejected by store header".into(),
            ))
        }
        Err(err) => Err(UnlockError::Store(err)),
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use crate::disk::Zeroizing;
    use anyhow::{Context, Result, anyhow, bail};

    use super::{BiometricStatus, CancelHandle, PROBE_TIMEOUT, UnlockError};

    const EXIT_CANCELLED: i32 = 10;
    const EXIT_UNAVAILABLE: i32 = 11;
    const EXIT_INVALIDATED: i32 = 12;
    const EXIT_INVALID_INPUT: i32 = 13;

    /// Ensures a spawned `deadbolt-enclave` child process is killed and reaped
    /// on drop (stdin error, timeout, cancellation, or daemon shutdown) so no
    /// zombie process or orphaned Touch ID dialog ever outlives the call.
    struct ChildGuard(Option<Child>);

    impl ChildGuard {
        fn new(child: Child) -> Self {
            Self(Some(child))
        }

        fn wait(&mut self) -> std::io::Result<ExitStatus> {
            let mut child = self
                .0
                .take()
                .ok_or_else(|| std::io::Error::other("child already taken"))?;
            child.wait()
        }

        fn kill_and_reap(&mut self) {
            if let Some(mut child) = self.0.take() {
                drop(child.kill());
                drop(child.wait());
            }
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            self.kill_and_reap();
        }
    }

    /// Resolves the `deadbolt-enclave` helper binary and verifies its pinned
    /// SHA-256 digest before execution.
    ///
    /// In production builds (`cfg(not(test))`), only `deadbolt-enclave` next to
    /// the running `deadbolt` executable (`Deadbolt.app/Contents/Helpers/`) is
    /// accepted; build-machine paths are never consulted.
    pub(super) fn verified_helper_path() -> Result<PathBuf> {
        #[cfg(not(test))]
        let (candidate, expected_sha) = {
            let exe = crate::caller::own_exe().context("locating current executable")?;
            let dir = exe
                .parent()
                .ok_or_else(|| anyhow!("executable has no parent directory"))?;
            (dir.join("deadbolt-enclave"), deadbolt_enclave::SHA256)
        };

        #[cfg(test)]
        let (candidate, expected_sha) = (
            PathBuf::from(deadbolt_enclave::TEST_BIN),
            deadbolt_enclave::TEST_SHA256,
        );

        if let Err(err) = verify_helper_at(&candidate, expected_sha) {
            if !super::WARNED_HELPER.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!("Touch ID helper verification failed: {err:#}");
            }
            return Err(err);
        }
        Ok(candidate)
    }

    pub(super) fn verify_helper_at(path: &Path, expected_hex: &str) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        // ctime (including nanoseconds) is kernel-controlled. Keep the
        // verified fd open too, so its inode cannot be recycled under us.
        type Stamp = (u64, u64, u64, i64, i64, i64, i64);
        static VERIFIED: std::sync::Mutex<Option<(std::fs::File, Stamp, String)>> =
            std::sync::Mutex::new(None);
        let stamp = |m: std::fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.size(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        };
        if expected_hex.len() != 64 {
            bail!("Touch ID helper was not compiled into this build");
        }
        let mut cached = VERIFIED.lock().unwrap_or_else(|e| e.into_inner());
        let meta = std::fs::metadata(path)
            .map_err(|_| anyhow!(deadbolt_client::peer::missing_helper(path)))?;
        if !meta.is_file() {
            bail!(deadbolt_client::peer::missing_helper(path));
        }
        let seen = stamp(meta);
        if cached
            .as_ref()
            .is_some_and(|(_, old, digest)| *old == seen && digest == expected_hex)
        {
            return Ok(());
        }
        let mut file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        if stamp(file.metadata()?) == seen {
            file.read_to_end(&mut bytes)?;
            if deadbolt_enclave::matches_current_arch(&bytes, expected_hex)
                && stamp(file.metadata()?) == seen
                && stamp(std::fs::metadata(path)?) == seen
            {
                *cached = Some((file, seen, expected_hex.into()));
                return Ok(());
            }
        }
        bail!(
            "Touch ID helper at {} failed SHA-256 verification",
            path.display()
        )
    }

    pub fn status() -> Result<BiometricStatus> {
        let child = Command::new(verified_helper_path()?)
            .arg("status")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning deadbolt-enclave status")?;
        let cancel = CancelHandle::default();
        let (exit, stdout, stderr) = wait_with_timeout(child, &cancel, PROBE_TIMEOUT)
            .map_err(|e| anyhow!("deadbolt-enclave status failed: {e}"))?;
        if !exit.success() {
            let stderr = String::from_utf8_lossy(&stderr).trim().to_string();
            bail!("deadbolt-enclave status exited with {exit}: {stderr}");
        }
        let text = String::from_utf8_lossy(&stdout);
        let mut status = BiometricStatus::default();
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("enclave=") {
                status.enclave = v.trim() == "1";
            } else if let Some(v) = line.strip_prefix("biometrics=") {
                status.biometrics = v.trim() == "1";
            }
        }
        Ok(status)
    }

    pub fn group_container(group: &str) -> Result<Option<PathBuf>> {
        let Ok(exe) = crate::caller::own_exe() else {
            return Ok(None);
        };
        let mut cmd = Command::new(verified_helper_path()?);
        cmd.args(["group-container", group]);
        cmd.arg(exe);
        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning deadbolt-enclave group-container")?;
        let cancel = CancelHandle::default();
        let (exit, stdout, stderr) = wait_with_timeout(child, &cancel, PROBE_TIMEOUT)
            .map_err(|e| anyhow!("deadbolt-enclave group-container failed: {e}"))?;
        if exit.success() {
            let path =
                String::from_utf8(stdout).context("App Group container path is not UTF-8")?;
            let path = path.trim();
            if path.is_empty() {
                return Ok(None);
            }
            return Ok(Some(PathBuf::from(path)));
        }
        if exit.code() == Some(EXIT_UNAVAILABLE) {
            return Ok(None);
        }
        let stderr = String::from_utf8_lossy(&stderr).trim().to_string();
        bail!("deadbolt-enclave group-container exited with {exit}: {stderr}")
    }

    pub fn seal(
        key: &[u8; 32],
        header_aad: &[u8],
        require_biometry: bool,
    ) -> Result<Vec<u8>, UnlockError> {
        let mut cmd = Command::new(
            verified_helper_path().map_err(|e| UnlockError::Unavailable(e.to_string()))?,
        );
        cmd.arg("seal");
        #[cfg(test)]
        if !require_biometry {
            cmd.arg("--no-biometry");
        }
        #[cfg(not(test))]
        let _ = require_biometry;

        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning deadbolt-enclave seal")?;

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("opening helper stdin"))?;
            let mut payload = Zeroizing::new(Vec::with_capacity(32 + header_aad.len()));
            payload.extend_from_slice(key);
            payload.extend_from_slice(header_aad);
            if let Err(err) = stdin.write_all(&payload) {
                drop(stdin);
                let _guard = ChildGuard::new(child);
                return Err(UnlockError::Other(
                    anyhow!(err).context("writing key to deadbolt-enclave"),
                ));
            }
        }

        let cancel = CancelHandle::default();
        let (exit, stdout, stderr) = wait_with_timeout(child, &cancel, PROBE_TIMEOUT)?;
        let stderr = String::from_utf8_lossy(&stderr).trim().to_string();
        if !exit.success() {
            return Err(match exit.code() {
                Some(EXIT_CANCELLED) => UnlockError::Cancelled,
                Some(EXIT_UNAVAILABLE) => UnlockError::Unavailable(stderr),
                Some(EXIT_INVALIDATED | EXIT_INVALID_INPUT) => UnlockError::Invalidated(stderr),
                _ => UnlockError::Other(anyhow!("deadbolt-enclave seal failed ({exit}): {stderr}")),
            });
        }
        Ok(stdout)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "internal helper passes policy, timeout, and cancellation to deadbolt-enclave"
    )]
    pub fn unseal(
        header_aad: &[u8],
        enclave_blob: &[u8],
        require_biometry: bool,
        interactive: bool,
        sleep_ms: u32,
        reason: &str,
        cancel: &CancelHandle,
        timeout: Duration,
    ) -> Result<Zeroizing<[u8; 32]>, UnlockError> {
        if enclave_blob.len() < 4 {
            return Err(UnlockError::Invalidated(
                "Secure Enclave payload too short".into(),
            ));
        }
        let aad_len = u16::try_from(header_aad.len())
            .map_err(|_| UnlockError::Invalidated("header AAD too large".into()))?;

        let mut cmd = Command::new(
            verified_helper_path().map_err(|e| UnlockError::Unavailable(e.to_string()))?,
        );
        cmd.arg("unseal");
        if !interactive {
            cmd.arg("--non-interactive");
        }
        #[cfg(test)]
        {
            if !require_biometry {
                cmd.arg("--no-biometry");
            }
            if sleep_ms > 0 {
                cmd.args(["--sleep-ms", &sleep_ms.to_string()]);
            }
        }
        #[cfg(not(test))]
        let _ = (require_biometry, sleep_ms);

        if !reason.is_empty() {
            cmd.args(["--reason", reason]);
        }

        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning deadbolt-enclave unseal")?;

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("missing helper stdin"))?;
            let mut input = Vec::with_capacity(2 + header_aad.len() + enclave_blob.len());
            input.extend_from_slice(&aad_len.to_le_bytes());
            input.extend_from_slice(header_aad);
            input.extend_from_slice(enclave_blob);
            if let Err(err) = stdin.write_all(&input) {
                drop(stdin);
                let _guard = ChildGuard::new(child);
                return Err(UnlockError::Other(
                    anyhow!(err).context("writing token to deadbolt-enclave"),
                ));
            }
        }

        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("missing helper stdout"))?;
        let mut stderr_pipe = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("missing helper stderr"))?;
        let mut guard = ChildGuard::new(child);

        let (tx, rx) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            // Read directly into a fixed zeroizing buffer so plaintext key bytes
            // never land in a reallocating Vec.
            let mut key = Zeroizing::new([0u8; 32]);
            let mut key_filled = 0usize;
            while key_filled < key.len() {
                match stdout.read(&mut key[key_filled..]) {
                    Ok(0) => break,
                    Ok(n) => key_filled += n,
                    Err(err) => {
                        drop(tx.send(Err(anyhow!(err).context("reading deadbolt-enclave stdout"))));
                        return;
                    }
                }
            }
            let mut extra = [0u8; 1];
            let has_extra = stdout.read(&mut extra).unwrap_or(0) > 0;
            let mut stderr_bytes = Vec::new();
            drop(stderr_pipe.read_to_end(&mut stderr_bytes));
            drop(tx.send(Ok((key, key_filled, has_extra, stderr_bytes))));
        });

        let deadline = Instant::now() + timeout;
        let outcome = loop {
            if let Ok(res) = rx.try_recv() {
                break res;
            }
            if cancel.is_cancelled() {
                guard.kill_and_reap();
                drop(reader.join());
                return Err(UnlockError::Cancelled);
            }
            let now = Instant::now();
            if now >= deadline {
                guard.kill_and_reap();
                drop(reader.join());
                return Err(UnlockError::Unavailable("Touch ID prompt timed out".into()));
            }
            let wait_for = (deadline - now).min(Duration::from_millis(25));
            let cguard = cancel.cancelled.lock().unwrap_or_else(|e| e.into_inner());
            if *cguard {
                drop(cguard);
                guard.kill_and_reap();
                drop(reader.join());
                return Err(UnlockError::Cancelled);
            }
            drop(cancel.cv.wait_timeout(cguard, wait_for));
        };

        drop(reader.join());
        let (key, key_filled, has_extra, stderr_bytes) = outcome?;
        let exit_status = guard.wait().context("waiting for deadbolt-enclave")?;
        let stderr = String::from_utf8_lossy(&stderr_bytes).trim().to_string();

        if !exit_status.success() {
            return Err(match exit_status.code() {
                Some(EXIT_CANCELLED) => UnlockError::Cancelled,
                Some(EXIT_UNAVAILABLE) => UnlockError::Unavailable(stderr),
                Some(EXIT_INVALIDATED | EXIT_INVALID_INPUT) => UnlockError::Invalidated(stderr),
                _ => UnlockError::Other(anyhow!(
                    "deadbolt-enclave unseal failed ({exit_status}): {stderr}"
                )),
            });
        }

        if key_filled != 32 || has_extra {
            return Err(UnlockError::Invalidated(format!(
                "unexpected biometric key length (read {key_filled} bytes)"
            )));
        }

        Ok(key)
    }

    fn wait_with_timeout(
        mut child: Child,
        cancel: &CancelHandle,
        timeout: Duration,
    ) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), UnlockError> {
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("missing helper stdout"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("missing helper stderr"))?;
        let mut guard = ChildGuard::new(child);

        let (tx, rx) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let out_res = stdout.read_to_end(&mut out);
            drop(stderr.read_to_end(&mut err));
            drop(tx.send(out_res.map(|_| (out, err))));
        });

        let deadline = Instant::now() + timeout;
        let (out, err) = loop {
            if let Ok(res) = rx.try_recv() {
                break res.context("reading deadbolt-enclave output")?;
            }
            if cancel.is_cancelled() {
                guard.kill_and_reap();
                drop(reader.join());
                return Err(UnlockError::Cancelled);
            }
            let now = Instant::now();
            if now >= deadline {
                guard.kill_and_reap();
                drop(reader.join());
                return Err(UnlockError::Unavailable("Touch ID helper timed out".into()));
            }
            let wait_for = (deadline - now).min(Duration::from_millis(25));
            let cguard = cancel.cancelled.lock().unwrap_or_else(|e| e.into_inner());
            drop(cancel.cv.wait_timeout(cguard, wait_for));
        };
        drop(reader.join());
        let status = guard.wait().context("waiting for deadbolt-enclave")?;
        Ok((status, out, err))
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "macos"))]
mod macos_tests;
