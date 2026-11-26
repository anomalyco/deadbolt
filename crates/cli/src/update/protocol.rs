//! The release protocol: the manifest a channel serves, and the client
//! rules that decide what to do with it (`anomalyco/release`
//! docs/protocol.md, `src/protocol/decide.ts`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Result, bail};
use serde::Deserialize;

/// Deadbolt's application name on the release service.
pub(super) const APP: &str = "deadbolt";

/// Largest safe integer accepted by the release protocol (JS `Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_INTEGER: u64 = (1u64 << 53) - 1;
/// Largest artifact size accepted by the release protocol (8 GiB).
const MAX_ARTIFACT_SIZE: u64 = 8 * 1024 * 1024 * 1024;
const MAX_TARGETS: usize = 64;
const MAX_DISTRIBUTIONS: usize = 32;

/// The release service's name for this build's platform: the static musl
/// build follows its own target, `linux-<arch>-musl`.
pub(super) fn target() -> Result<String> {
    let os = match std::env::consts::OS {
        "macos" => "macos",
        "linux" => "linux",
        os => bail!("no Deadbolt releases for {os}"),
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        arch => bail!("no Deadbolt releases for {arch}"),
    };
    let libc = if cfg!(target_env = "musl") {
        "-musl"
    } else {
        ""
    };
    Ok(format!("{os}-{arch}{libc}"))
}

/// The channel this build was published on; none for builds from source.
pub(crate) fn build_channel() -> Option<&'static str> {
    Some(env!("DEADBOLT_BUILD_CHANNEL")).filter(|c| !c.is_empty())
}

/// This build's version, as the release service names it.
pub(super) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Strict SemVer 2.0.0 without build metadata, matching `anomalyco/release`
/// `src/protocol/semver.ts`. Versions are validated for shape on parse and
/// never ordered: each channel has one current release and installs follow it.
pub(super) fn is_version(text: &str) -> bool {
    if text.is_empty() || text.len() > 128 || !text.is_ascii() {
        return false;
    }
    let (core, prerelease) = match text.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (text, None),
    };
    let valid_num = |s: &str| {
        !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s.len() == 1 || !s.starts_with('0'))
            && s.parse::<u64>().is_ok_and(|n| n <= MAX_SAFE_INTEGER)
    };
    let mut parts = core.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if !valid_num(major) || !valid_num(minor) || !valid_num(patch) {
        return false;
    }
    let Some(pre) = prerelease else {
        return true;
    };
    if pre.is_empty() {
        return false;
    }
    pre.split('.').all(|part| {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return false;
        }
        if part.bytes().all(|b| b.is_ascii_digit()) {
            valid_num(part)
        } else {
            true
        }
    })
}

pub(super) fn is_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 32
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

fn is_target_name(text: &str) -> bool {
    let mut parts = text.split('-');
    let Some(first) = parts.next() else {
        return false;
    };
    if first.is_empty()
        || !first
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return false;
    }
    let mut rest = 0usize;
    for part in parts {
        rest += 1;
        if rest > 3
            || part.is_empty()
            || !part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return false;
        }
    }
    true
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_https_url(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 2048
        && url::Url::parse(text).is_ok_and(|u| u.scheme() == "https")
}

fn is_command(text: &str) -> bool {
    !text.is_empty() && text.len() <= 512 && text.bytes().all(|b| b >= 0x20 && b != 0x7f)
}

// The release protocol, version 1.

#[derive(Debug, Deserialize)]
pub(super) struct Manifest {
    schema: u32,
    app: String,
    /// Grows with every write to the channel (a rollback included).
    pub(super) sequence: u64,
    artifact: String,
    channel: String,
    published_at: String,
    release: Release,
}

impl Manifest {
    /// The release version carried by the manifest.
    pub(super) fn release_version(&self) -> &str {
        &self.release.version
    }

    /// The version the release lists for its npm distribution, when it
    /// carries one: Release is then the source of truth and the registry
    /// isn't asked. Releases written before npm is recorded have none.
    pub(super) fn npm_version(&self) -> Option<&str> {
        self.release
            .distributions
            .iter()
            .find(|distribution| distribution.kind == "npm")
            .and_then(|distribution| distribution.version.as_deref())
    }
}

#[derive(Debug, Deserialize)]
struct Release {
    version: String,
    #[serde(default)]
    notes_url: Option<String>,
    rollout_percent: u8,
    #[serde(default)]
    required: bool,
    targets: BTreeMap<String, Target>,
    distributions: Vec<Distribution>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Target {
    pub(super) url: String,
    pub(super) size: u64,
    pub(super) sha256: String,
}

#[derive(Debug, Deserialize)]
struct Distribution {
    kind: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    command: Option<String>,
}

/// What the running install is, for [`decide`].
#[derive(Debug, Clone)]
pub struct Running<'a> {
    pub version: &'a str,
    pub target: &'a str,
    /// `direct` when this updates itself, else the package manager's kind
    /// or `unknown`.
    pub distribution: &'a str,
    /// 0–99 ([`rollout_bucket`]).
    pub bucket: u8,
    /// SHA-256 of the target file this build was installed from, when known.
    /// For `direct` installs, identifies the running build instead of version text.
    pub sha256: Option<&'a str>,
    /// The channel this build was published on; `None` is the expected one.
    pub channel: Option<&'a str>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Reason {
    Update,
    Required,
    Switch,
}

impl Reason {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Required => "required",
            Self::Switch => "switch",
        }
    }
}

/// The client rules (`src/protocol/decide.ts` in `anomalyco/release`).
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Reject(&'static str),
    None(&'static str),
    Install {
        reason: Reason,
        version: String,
        target: Target,
    },
    Notify {
        reason: Reason,
        version: String,
        distribution: String,
        command: Option<String>,
        notes_url: Option<String>,
    },
}

pub(super) fn parse(text: &str) -> Option<Manifest> {
    let manifest: Manifest = serde_json::from_str(text).ok()?;
    let release = &manifest.release;
    if manifest.schema != 1
        || !is_name(&manifest.app)
        || !is_name(&manifest.artifact)
        || !is_name(&manifest.channel)
        || manifest.sequence > MAX_SAFE_INTEGER
        || manifest.published_at.len() > 2048
        || !is_version(&release.version)
        || release.rollout_percent > 100
        || release
            .notes_url
            .as_deref()
            .is_some_and(|u| !is_https_url(u))
        || release.targets.len() > MAX_TARGETS
        || release.distributions.len() > MAX_DISTRIBUTIONS
    {
        return None;
    }
    for (name, target) in &release.targets {
        if !is_target_name(name)
            || !is_sha256(&target.sha256)
            || target.size > MAX_ARTIFACT_SIZE
            || target.url.is_empty()
            || target.url.len() > 2048
        {
            return None;
        }
    }
    let mut kinds = BTreeSet::new();
    for dist in &release.distributions {
        if !is_name(&dist.kind) || !kinds.insert(dist.kind.as_str()) {
            return None;
        }
        if dist.kind != "direct" {
            if dist.version.as_deref().is_some_and(|v| !is_version(v)) {
                return None;
            }
            if dist.command.as_deref().is_some_and(|c| !is_command(c)) {
                return None;
            }
        }
    }
    Some(manifest)
}

/// Validate identity as well as shape before using a manifest's sequence.
pub(super) fn validated_for(
    app: &str,
    artifact: &str,
    channel: &str,
    text: &str,
) -> Result<Manifest, &'static str> {
    let manifest = parse(text).ok_or("malformed")?;
    if manifest.app != app {
        return Err("wrong_app");
    }
    if manifest.artifact != artifact {
        return Err("wrong_artifact");
    }
    if manifest.channel != channel {
        return Err("wrong_channel");
    }
    Ok(manifest)
}

/// Validate identity for Deadbolt as well as shape before using a manifest's sequence.
pub(super) fn validated(
    artifact: &str,
    channel: &str,
    text: &str,
) -> Result<Manifest, &'static str> {
    validated_for(APP, artifact, channel, text)
}

/// Decides what to do with `text`, the manifest for `app` / `artifact` on
/// `channel`, for the install `running`. Versions are display text, only
/// ever tested for equality (or superseded by `running.sha256` for `direct`
/// installs): an install updates whenever the channel's current release isn't
/// the build it runs.
pub fn decide_for(
    app: &str,
    artifact: &str,
    channel: &str,
    text: &str,
    running: &Running,
) -> Decision {
    let manifest = match validated_for(app, artifact, channel, text) {
        Ok(manifest) => manifest,
        Err(reason) => return Decision::Reject(reason),
    };
    let release = manifest.release;
    let mut candidate = release.version.clone();
    let mut target = None;
    let mut command = None;
    match running.distribution {
        "direct" => match release.targets.get(running.target) {
            Some(found) => target = Some(found.clone()),
            None => return Decision::None("no_target"),
        },
        "unknown" => {}
        kind => match release.distributions.iter().find(|d| d.kind == kind) {
            Some(distribution) => {
                let Some(version) = &distribution.version else {
                    return Decision::None("distribution_pending");
                };
                candidate.clone_from(version);
                command.clone_from(&distribution.command);
            }
            // Releases written before npm was recorded carry no `npm`
            // entry; the registry says what npm serves until it does.
            None if app == APP && kind == "npm" => {}
            None => return Decision::None("distribution_unlisted"),
        },
    }
    let already_running = match (&target, running.sha256) {
        (Some(target), Some(sha256)) => sha256 == target.sha256,
        _ => candidate == running.version,
    };
    if already_running {
        return Decision::None("up_to_date");
    }
    let act = |reason| match target.clone() {
        Some(target) => Decision::Install {
            reason,
            version: candidate.clone(),
            target,
        },
        None => Decision::Notify {
            reason,
            version: candidate.clone(),
            distribution: running.distribution.to_string(),
            command: command.clone(),
            notes_url: release.notes_url.clone(),
        },
    };
    if running.channel.is_some_and(|c| c != channel) {
        return act(Reason::Switch);
    }
    if release.required {
        return act(Reason::Required);
    }
    if running.bucket < release.rollout_percent {
        return act(Reason::Update);
    }
    Decision::None("rollout_deferred")
}

/// [`decide_for`] for Deadbolt (`app = "deadbolt"`).
pub fn decide(artifact: &str, channel: &str, text: &str, running: &Running) -> Decision {
    decide_for(APP, artifact, channel, text, running)
}

/// This install's rollout bucket, 0–99: drawn once from a local random
/// number and kept in `dir` (the state directory), never sent anywhere.
pub(super) fn rollout_bucket(dir: &Path) -> u8 {
    let path = dir.join("rollout-bucket");
    if let Some(bucket) = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| t.trim().parse::<u8>().ok())
        .filter(|b| *b < 100)
    {
        return bucket;
    }
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).ok();
    let bucket = u8::try_from(u32::from_le_bytes(bytes) % 100).unwrap_or(0);
    if std::fs::create_dir_all(dir).is_ok() {
        std::fs::write(&path, format!("{bucket}\n")).ok();
    }
    bucket
}
