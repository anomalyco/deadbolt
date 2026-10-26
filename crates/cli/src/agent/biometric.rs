//! Secure Enclave Touch ID enrollment and unlock for the local store.
//!
//! See `docs/touch-id.md` for the full design. On macOS, a small compiled Swift
//! helper (`deadbolt-enclave`, pinned by SHA-256 at build time) creates a
//! hardware-bound P-256 key inside the Secure Enclave
//! (`CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey`) and seals a random
//! 256-bit `biometric_key` with ECDH + HKDF-SHA256 + AES-256-GCM. The resulting
//! envelope and the AEAD-wrapped key set live in `store.redb`.

use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use deadbolt_store::Zeroizing;

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
/// agent memory so `status()` never opens `store.redb`.
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

/// Sealed biometric key + token ready to be written into `store.redb`.
pub struct SealedBiometric {
    pub key: Zeroizing<[u8; 32]>,
    pub token: Vec<u8>,
    pub meta: TokenMeta,
}

/// Handle used by the agent to cancel an in-flight `deadbolt-enclave` prompt
/// (on passphrase `Unlock`, `Lock`, `TouchIdSet`, `Stop`, or `Agent` drop),
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
    Store(deadbolt_store::Error),
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

impl From<deadbolt_store::Error> for UnlockError {
    fn from(err: deadbolt_store::Error) -> Self {
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

/// Reads [`TokenMeta`] once from `data_dir` at agent startup.
pub fn read_token_meta(data_dir: &Path) -> Option<TokenMeta> {
    if !deadbolt_store::is_initialized(data_dir) {
        return None;
    }
    let token = deadbolt_store::biometric_token(data_dir).ok().flatten()?;
    token_meta(Some(&token))
}

/// Returns true only when `err` indicates that the biometric header entries
/// (`"biometric.token"` / `"keyset.biometric"`) are invalid or incomplete, not
/// when `open_db` or `Header::read` reports general database corruption.
pub fn is_biometric_slot_error(err: &deadbolt_store::Error) -> bool {
    match err {
        deadbolt_store::Error::InvalidBiometric => true,
        deadbolt_store::Error::Corrupt(msg) => msg.contains("biometric"),
        _ => false,
    }
}

/// Clears the biometric slot in `data_dir` only if `"biometric.token"` still
/// matches `expected_token` (or if the biometric header entry itself is
/// incomplete). Returns whether the slot was cleared.
pub fn clear_biometric_if_matches(data_dir: &Path, expected_token: &[u8]) -> bool {
    match deadbolt_store::biometric_token(data_dir) {
        Ok(Some(current)) if current == expected_token => {
            deadbolt_store::clear_biometric(data_dir).unwrap_or(false)
        }
        Err(ref err) if is_biometric_slot_error(err) => {
            deadbolt_store::clear_biometric(data_dir).unwrap_or(false)
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
/// refresh is kicked off so `Agent::status()` never blocks on a subprocess.
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

/// Generates a fresh `.biometryCurrentSet` Secure Enclave key and seals a new
/// 256-bit `biometric_key` without touching `store.redb`.
pub fn seal_new(now_secs: u64) -> Result<SealedBiometric, UnlockError> {
    seal_inner(true, now_secs)
}

/// Enrolls a fresh `.biometryCurrentSet` Secure Enclave key and writes the
/// biometric slot into `store`.
pub fn enroll(store: &deadbolt_store::Unlocked, now_secs: u64) -> Result<TokenMeta, UnlockError> {
    let sealed = seal_new(now_secs)?;
    store.set_biometric(&sealed.key, &sealed.token)?;
    Ok(sealed.meta)
}

#[cfg(all(test, target_os = "macos"))]
pub fn enroll_with_policy(
    store: &deadbolt_store::Unlocked,
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
        let key = deadbolt_store::generate_biometric_key()?;
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
/// without holding `store.redb` open while the Touch ID prompt is on screen.
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
) -> Result<deadbolt_store::Unlocked, UnlockError> {
    let token = match deadbolt_store::biometric_token(data_dir) {
        Ok(Some(token)) => token,
        Ok(None) => return Err(UnlockError::NotEnrolled),
        Err(ref err) if is_biometric_slot_error(err) => {
            drop(deadbolt_store::clear_biometric(data_dir));
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

    match deadbolt_store::unlock_biometric(data_dir, &key) {
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

    use anyhow::{Context, Result, anyhow, bail};
    use deadbolt_store::Zeroizing;

    use super::{BiometricStatus, CancelHandle, PROBE_TIMEOUT, UnlockError};

    const EXIT_CANCELLED: i32 = 10;
    const EXIT_UNAVAILABLE: i32 = 11;
    const EXIT_INVALIDATED: i32 = 12;
    const EXIT_INVALID_INPUT: i32 = 13;
    const FAT_MAGIC: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];
    const CPU_TYPE_X86_64: u32 = 0x0100_0007;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;

    /// Ensures a spawned `deadbolt-enclave` child process is killed and reaped
    /// on drop (stdin error, timeout, cancellation, or agent shutdown) so no
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

    #[cfg(target_arch = "aarch64")]
    const CURRENT_CPU_TYPE: u32 = CPU_TYPE_ARM64;
    #[cfg(target_arch = "x86_64")]
    const CURRENT_CPU_TYPE: u32 = CPU_TYPE_X86_64;

    /// Resolves the `deadbolt-enclave` helper binary and verifies its pinned
    /// SHA-256 digest before execution.
    ///
    /// In production builds (`cfg(not(test))`), only `deadbolt-enclave` next to
    /// the running `deadbolt` executable (`Deadbolt.app/Contents/Helpers/`) is
    /// accepted; build-machine paths are never consulted.
    fn verified_helper_path() -> Result<PathBuf> {
        #[cfg(not(test))]
        let (candidate, expected_sha) = {
            let exe = std::env::current_exe().context("locating current executable")?;
            let dir = exe
                .parent()
                .ok_or_else(|| anyhow!("executable has no parent directory"))?;
            (
                dir.join("deadbolt-enclave"),
                env!("DEADBOLT_ENCLAVE_SHA256"),
            )
        };

        #[cfg(test)]
        let (candidate, expected_sha) = (
            PathBuf::from(env!("DEADBOLT_ENCLAVE_TEST_BIN")),
            env!("DEADBOLT_ENCLAVE_TEST_SHA256"),
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
        if expected_hex.len() != 64 {
            bail!("Touch ID helper was not compiled into this build");
        }
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading Touch ID helper at {}", path.display()))?;
        if matches_sha256_or_fat_slice(&bytes, expected_hex, CURRENT_CPU_TYPE) {
            return Ok(());
        }
        bail!(
            "Touch ID helper at {} failed SHA-256 verification",
            path.display()
        )
    }

    /// Verifies a thin Mach-O or universal (`lipo -create`) binary against
    /// `expected_hex`.
    ///
    /// Universal binaries must have exactly 2 non-overlapping slices for
    /// `{CPU_TYPE_ARM64, CPU_TYPE_X86_64}`, and the slice for `current_cpu`
    /// must match `expected_hex`.
    pub(super) fn matches_sha256_or_fat_slice(
        bytes: &[u8],
        expected_hex: &str,
        current_cpu: u32,
    ) -> bool {
        if bytes.len() < 4 {
            return false;
        }
        if bytes[..4] != FAT_MAGIC {
            return hex_encode(&sha256(bytes)) == expected_hex;
        }
        let header_end = 8 + 2 * 20;
        if bytes.len() < header_end {
            return false;
        }
        let nfat = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if nfat != 2 {
            return false;
        }
        let Some((cpu0, off0, end0)) = parse_fat_entry(bytes, 8, header_end) else {
            return false;
        };
        let Some((cpu1, off1, end1)) = parse_fat_entry(bytes, 28, header_end) else {
            return false;
        };
        if !(end0 <= off1 || end1 <= off0) {
            return false;
        }
        let valid_pair = (cpu0 == CPU_TYPE_ARM64 && cpu1 == CPU_TYPE_X86_64)
            || (cpu0 == CPU_TYPE_X86_64 && cpu1 == CPU_TYPE_ARM64);
        if !valid_pair {
            return false;
        }
        let slice = if cpu0 == current_cpu {
            &bytes[off0..end0]
        } else if cpu1 == current_cpu {
            &bytes[off1..end1]
        } else {
            return false;
        };
        hex_encode(&sha256(slice)) == expected_hex
    }

    fn parse_fat_entry(
        bytes: &[u8],
        entry: usize,
        min_offset: usize,
    ) -> Option<(u32, usize, usize)> {
        let cputype = u32::from_be_bytes([
            bytes[entry],
            bytes[entry + 1],
            bytes[entry + 2],
            bytes[entry + 3],
        ]);
        let offset = u32::from_be_bytes([
            bytes[entry + 8],
            bytes[entry + 9],
            bytes[entry + 10],
            bytes[entry + 11],
        ]) as usize;
        let size = u32::from_be_bytes([
            bytes[entry + 12],
            bytes[entry + 13],
            bytes[entry + 14],
            bytes[entry + 15],
        ]) as usize;
        let end = offset.checked_add(size)?;
        if offset < min_offset || size == 0 || end > bytes.len() {
            return None;
        }
        Some((cputype, offset, end))
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

    pub(super) fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0f)]));
        }
        out
    }

    /// FIPS 180-4 / RFC 6234 SHA-256.
    pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let bit_len = (data.len() as u64) * 8;
        let mut padded = Vec::with_capacity(data.len() + 72);
        padded.extend_from_slice(data);
        padded.push(0x80);
        while (padded.len() + 8) % 64 != 0 {
            padded.push(0);
        }
        padded.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in padded.as_chunks::<64>().0 {
            let mut w = [0u32; 64];
            for (i, word) in w.iter_mut().take(16).enumerate() {
                let b = i * 4;
                *word = u32::from_be_bytes([chunk[b], chunk[b + 1], chunk[b + 2], chunk[b + 3]]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }

        let mut out = [0u8; 32];
        for (i, word) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_header_roundtrip_and_clock_bounds() {
        let now = 1_700_000_000;
        let header = encode_header(true, now);
        let mut token = header.to_vec();
        token.extend_from_slice(b"payload");

        let meta = token_meta(Some(&token)).unwrap();
        assert!(meta.is_ready(now));
        assert!(meta.is_ready(now + MAX_AGE_SECS));
        assert!(!meta.is_ready(now + MAX_AGE_SECS + 1));
        assert!(!meta.is_ready(now - 1));

        assert!(matches!(
            validate_token(&token, true, now - 1),
            Err(UnlockError::Expired(_))
        ));
        assert!(matches!(
            validate_token(&token, true, now + MAX_AGE_SECS + 1),
            Err(UnlockError::Expired(_))
        ));
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use std::path::PathBuf;
    use tempfile::TempDir;

    use super::*;

    const FAST: deadbolt_store::KdfParams = deadbolt_store::KdfParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };
    const PASS: &[u8] = b"correct horse battery staple";
    const SECRET: [u8; 32] = [0x42; 32];

    #[test]
    fn staged_production_helper_matches_pinned_sha256() {
        let staged = PathBuf::from(env!("DEADBOLT_ENCLAVE_STAGED_BIN"));
        let expected = env!("DEADBOLT_ENCLAVE_SHA256");
        assert_eq!(expected.len(), 64);
        macos::verify_helper_at(&staged, expected).unwrap();
    }

    #[test]
    fn helper_sha256_verification_rejects_tampered_binary() {
        let tmp = TempDir::new().unwrap();
        let fake_helper = tmp.path().join("deadbolt-enclave");
        std::fs::write(&fake_helper, b"#!/bin/sh\necho tampered\n").unwrap();
        assert!(
            macos::verify_helper_at(&fake_helper, env!("DEADBOLT_ENCLAVE_TEST_SHA256")).is_err()
        );
        assert!(macos::verify_helper_at(&fake_helper, "").is_err());
    }

    #[test]
    fn fat_binary_requires_arm64_and_x86_64_and_matches_current_arch() {
        const ARM64: u32 = 0x0100_000c;
        const X86_64: u32 = 0x0100_0007;
        const OTHER: u32 = 0x0000_0007;

        let arm_slice = b"arm64-helper-slice";
        let x86_slice = b"x86_64-helper-slice";
        let arm_sha = macos::hex_encode(&macos::sha256(arm_slice));
        let x86_sha = macos::hex_encode(&macos::sha256(x86_slice));

        fn build_fat(slices: &[(u32, &[u8])]) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
            out.extend_from_slice(&(slices.len() as u32).to_be_bytes());
            let mut offset = 8 + slices.len() * 20;
            for &(cpu, data) in slices {
                out.extend_from_slice(&cpu.to_be_bytes());
                out.extend_from_slice(&0u32.to_be_bytes());
                out.extend_from_slice(&(offset as u32).to_be_bytes());
                out.extend_from_slice(&(data.len() as u32).to_be_bytes());
                out.extend_from_slice(&0u32.to_be_bytes());
                offset += data.len();
            }
            for &(_, data) in slices {
                out.extend_from_slice(data);
            }
            out
        }

        let valid_fat = build_fat(&[(ARM64, arm_slice), (X86_64, x86_slice)]);
        // Current arch matches its own slice and rejects the other arch's hash.
        assert!(macos::matches_sha256_or_fat_slice(
            &valid_fat, &arm_sha, ARM64
        ));
        assert!(!macos::matches_sha256_or_fat_slice(
            &valid_fat, &x86_sha, ARM64
        ));
        assert!(macos::matches_sha256_or_fat_slice(
            &valid_fat, &x86_sha, X86_64
        ));
        assert!(!macos::matches_sha256_or_fat_slice(
            &valid_fat, &arm_sha, X86_64
        ));

        // Fat binary with duplicate arch or wrong arch pair is rejected.
        let dup_arch = build_fat(&[(ARM64, arm_slice), (ARM64, x86_slice)]);
        assert!(!macos::matches_sha256_or_fat_slice(
            &dup_arch, &arm_sha, ARM64
        ));
        let wrong_arch = build_fat(&[(ARM64, arm_slice), (OTHER, x86_slice)]);
        assert!(!macos::matches_sha256_or_fat_slice(
            &wrong_arch,
            &arm_sha,
            ARM64
        ));
        let single_slice_fat = build_fat(&[(ARM64, arm_slice)]);
        assert!(!macos::matches_sha256_or_fat_slice(
            &single_slice_fat,
            &arm_sha,
            ARM64
        ));
    }

    #[test]
    fn secure_enclave_headless_roundtrip_and_invalidation() {
        let cap = refresh_status();
        if !cap.enclave {
            eprintln!("skipping Secure Enclave test: no Secure Enclave on this macOS host");
            return;
        }

        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let now = 1_700_000_000;

        let store = deadbolt_store::init_with_params(dir, PASS, SECRET, FAST).unwrap();
        store.append_batch([&b"vault-entry-1"[..]]).unwrap();
        store.meta_set("vault_id", b"v-touchid").unwrap();
        assert!(store.biometric_token().unwrap().is_none());

        let meta = match enroll_with_policy(&store, SealPolicy::HEADLESS_TEST, now) {
            Ok(meta) => meta,
            Err(UnlockError::Unavailable(msg)) => {
                eprintln!(
                    "skipping Secure Enclave test: Secure Enclave unavailable in this session ({msg})"
                );
                return;
            }
            Err(err) => panic!("unexpected Secure Enclave enrollment failure: {err}"),
        };
        assert_eq!(meta.created_at, now);
        drop(store);

        assert!(read_token_meta(dir).is_some_and(|m| m.created_at == now));

        let cancel = CancelHandle::new();
        // Headless unseal via Secure Enclave ECDH + HKDF + AES-GCM opens the store
        // with no UI prompt.
        let unlocked = unlock_with_policy(
            dir,
            SealPolicy::HEADLESS_TEST,
            now + 60,
            "",
            &cancel,
            PROMPT_TIMEOUT,
        )
        .unwrap();
        assert_eq!(unlocked.device_secret(), &SECRET);
        assert_eq!(
            unlocked
                .meta_get("vault_id")
                .unwrap()
                .as_deref()
                .map(Vec::as_slice),
            Some(&b"v-touchid"[..])
        );
        let entries: Vec<Vec<u8>> = unlocked
            .iter_all()
            .unwrap()
            .map(|r| r.unwrap().to_vec())
            .collect();
        assert_eq!(entries, vec![b"vault-entry-1".to_vec()]);
        drop(unlocked);

        // Requiring `.biometryCurrentSet` against a non-biometric token is rejected
        // and wipes the slot.
        assert!(matches!(
            unlock_with_policy(
                dir,
                SealPolicy::TOUCH_ID,
                now + 60,
                "",
                &cancel,
                PROMPT_TIMEOUT
            ),
            Err(UnlockError::Invalidated(_))
        ));
        assert!(deadbolt_store::biometric_token(dir).unwrap().is_none());

        // Re-enroll and verify 14-day age expiry wipes the slot.
        let store = deadbolt_store::unlock(dir, PASS).unwrap();
        enroll_with_policy(&store, SealPolicy::HEADLESS_TEST, now).unwrap();
        drop(store);
        let expired = now + MAX_AGE_SECS + 1;
        assert!(matches!(
            unlock_with_policy(
                dir,
                SealPolicy::HEADLESS_TEST,
                expired,
                "",
                &cancel,
                PROMPT_TIMEOUT
            ),
            Err(UnlockError::Expired(_))
        ));
        assert!(deadbolt_store::biometric_token(dir).unwrap().is_none());

        // Re-enroll, mutate the recorded biometric stateHash inside the token,
        // and verify that a fingerprint-set stateHash change wipes the slot.
        let store = deadbolt_store::unlock(dir, PASS).unwrap();
        enroll_with_policy(&store, SealPolicy::HEADLESS_TEST, now).unwrap();
        let mut mutated_token = store.biometric_token().unwrap().unwrap();
        mutated_token[HEADER_LEN + 1] ^= 0xff;
        let fresh_key = deadbolt_store::generate_biometric_key().unwrap();
        store.set_biometric(&fresh_key, &mutated_token).unwrap();
        drop(store);
        assert!(matches!(
            unlock_with_policy(
                dir,
                SealPolicy::HEADLESS_TEST,
                now + 60,
                "",
                &cancel,
                PROMPT_TIMEOUT
            ),
            Err(UnlockError::Invalidated(_))
        ));
        assert!(deadbolt_store::biometric_token(dir).unwrap().is_none());
    }

    #[test]
    fn cancel_and_timeout_kill_in_flight_helper_and_preserve_slot() {
        let cap = refresh_status();
        if !cap.enclave {
            eprintln!("skipping Secure Enclave test: no Secure Enclave on this macOS host");
            return;
        }

        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let now = 1_700_000_000;
        let store = deadbolt_store::init_with_params(dir, PASS, SECRET, FAST).unwrap();
        if matches!(
            enroll_with_policy(&store, SealPolicy::HEADLESS_TEST, now),
            Err(UnlockError::Unavailable(_))
        ) {
            return;
        }
        drop(store);

        let slow_policy = SealPolicy {
            require_biometry: false,
            interactive: false,
            sleep_ms: 5_000,
        };

        // 1. Explicit cancellation kills the helper immediately and returns Cancelled.
        let cancel = CancelHandle::new();
        let cancel_clone = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            cancel_clone.cancel();
        });
        let start = Instant::now();
        let err = unlock_with_policy(dir, slow_policy, now + 1, "", &cancel, PROMPT_TIMEOUT)
            .err()
            .unwrap();
        assert!(matches!(err, UnlockError::Cancelled), "got {err:?}");
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(deadbolt_store::biometric_token(dir).unwrap().is_some());

        // 2. Timeout kills the helper and returns Unavailable without wiping the slot.
        let timeout_cancel = CancelHandle::new();
        let start = Instant::now();
        let err = unlock_with_policy(
            dir,
            slow_policy,
            now + 1,
            "",
            &timeout_cancel,
            Duration::from_millis(80),
        )
        .err()
        .unwrap();
        assert!(matches!(err, UnlockError::Unavailable(_)), "got {err:?}");
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(deadbolt_store::biometric_token(dir).unwrap().is_some());
    }

    #[test]
    fn biometry_current_set_never_prompts_when_non_interactive() {
        let cap = refresh_status();
        if !cap.enclave {
            eprintln!("skipping Secure Enclave test: no Secure Enclave on this macOS host");
            return;
        }

        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let now = 1_700_000_000;

        let store = deadbolt_store::init_with_params(dir, PASS, SECRET, FAST).unwrap();
        let policy = SealPolicy {
            require_biometry: true,
            interactive: false,
            sleep_ms: 0,
        };
        let cancel = CancelHandle::new();
        match enroll_with_policy(&store, policy, now) {
            Ok(_) => {
                drop(store);
                let err = unlock_with_policy(dir, policy, now + 1, "", &cancel, PROMPT_TIMEOUT)
                    .err()
                    .unwrap();
                assert!(
                    matches!(err, UnlockError::Unavailable(_)),
                    "expected Unavailable for non-interactive biometric unseal, got {err:?}"
                );
                assert!(deadbolt_store::biometric_token(dir).unwrap().is_some());
            }
            Err(UnlockError::Unavailable(_)) => {
                // On a headless Mac without enrolled fingerprints (e.g. Mac mini or CI VM),
                // `.biometryCurrentSet` fails cleanly with Unavailable (exit 11).
            }
            Err(err) => {
                panic!("unexpected enrollment error on host without Touch ID: {err:?}");
            }
        }
    }
}
