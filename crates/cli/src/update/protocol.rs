//! The release protocol: the manifest a channel serves, and the client
//! rules that decide what to do with it (`anomalyco/release`
//! docs/protocol.md, `src/protocol/decide.ts`).

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Result, bail};
use serde::Deserialize;

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

// The release protocol, version 1.

#[derive(Debug, Deserialize)]
pub(super) struct Manifest {
    schema: u32,
    app: String,
    /// Grows with every write to the channel (a rollback included).
    pub(super) sequence: u64,
    artifact: String,
    channel: String,
    release: Release,
}

#[derive(Debug, Deserialize)]
struct Release {
    version: String,
    #[serde(default)]
    notes_url: Option<String>,
    rollout_percent: u8,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    targets: BTreeMap<String, Target>,
    #[serde(default)]
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
    /// The channel this build was published on; `None` is the expected one.
    pub channel: Option<&'a str>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Reason {
    Update,
    Required,
    Switch,
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
        command: Option<String>,
        notes_url: Option<String>,
    },
}

fn parse(text: &str) -> Option<Manifest> {
    let manifest: Manifest = serde_json::from_str(text).ok()?;
    let release = &manifest.release;
    let hex = |s: &str| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    (manifest.schema == 1
        && !release.version.is_empty()
        && release.rollout_percent <= 100
        && release.targets.values().all(|t| hex(&t.sha256)))
    .then_some(manifest)
}

/// Validate identity as well as shape before using a manifest's sequence.
pub(super) fn validated(
    artifact: &str,
    channel: &str,
    text: &str,
) -> Result<Manifest, &'static str> {
    let manifest = parse(text).ok_or("malformed")?;
    if manifest.app != "deadbolt" {
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

/// Decides what to do with `text`, the manifest for `artifact` on
/// `channel`, for the install `running`. Versions are display text, only
/// ever tested for equality: an install updates whenever the channel's
/// current release isn't the build it runs.
pub fn decide(artifact: &str, channel: &str, text: &str, running: &Running) -> Decision {
    let manifest = match validated(artifact, channel, text) {
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
        kind => {
            let Some(distribution) = release.distributions.iter().find(|d| d.kind == kind) else {
                return Decision::None("distribution_unlisted");
            };
            let Some(version) = &distribution.version else {
                return Decision::None("distribution_pending");
            };
            candidate.clone_from(version);
            command.clone_from(&distribution.command);
        }
    }
    if candidate == running.version {
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
