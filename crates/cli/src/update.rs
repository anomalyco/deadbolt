//! `deadbolt update`: updates this Deadbolt from the Anomaly release service
//! (docs/releasing.md, "Updater"), following the service's client rules
//! (`anomalyco/release` docs/protocol.md). What it updates depends on how
//! this binary is installed ([`method`]): Deadbolt.app (the `desktop`
//! artifact) or a standalone CLI (`cli`) replace themselves; npm, pnpm, bun,
//! yarn and Homebrew installs run that manager, pinned to the version it
//! serves; Nix, Cargo and system installs get their manager's command. An
//! unpacked browser extension registered with `deadbolt browser install
//! --extension-dir` is updated too (`extension`).
//!
//! The daemon checks in the background ([`available`]) and only ever says
//! so: nothing is installed unless the user runs `deadbolt update`.
//!
//! Nothing downloaded runs or replaces anything before its size and SHA-256
//! match the manifest and, on macOS, its code signature satisfies what the
//! running install would ([`APP_REQUIREMENT`]). Each replacement is staged
//! beside its destination and renamed into place.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Args;
use data_encoding::HEXLOWER;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::config::{ExtensionBuild, ExtensionDir};
use crate::paths::Paths;
use crate::protocol::UpdateInfo;

/// Where the release service lives.
const SERVICE: &str = "https://anoma.ly/release/";
/// Overrides [`SERVICE`] in debug builds only, and only with a loopback
/// URL, so tests can serve a fake release and no environment can send a
/// release build anywhere else.
const SERVICE_OVERRIDE: &str = "DEADBOLT_RELEASE_URL";
/// The npm registry, which says what npm, pnpm, bun and yarn can install.
const REGISTRY: &str = "https://registry.npmjs.org/";
/// Overrides [`REGISTRY`] as [`SERVICE_OVERRIDE`] does the service.
const REGISTRY_OVERRIDE: &str = "DEADBOLT_NPM_REGISTRY_URL";
/// npm's package, which links to its platform package's `deadbolt`.
const PACKAGE: &str = "@deadbolt/cli";
/// The platform packages `@deadbolt/cli` installs one of.
const PLATFORM_PACKAGES: [&str; 6] = [
    "@deadbolt/cli-linux-x64",
    "@deadbolt/cli-linux-arm64",
    "@deadbolt/cli-linux-x64-musl",
    "@deadbolt/cli-linux-arm64-musl",
    "@deadbolt/cli-darwin-arm64",
    "@deadbolt/cli-darwin-x64",
];
/// What `Deadbolt.app` must satisfy (identifier, team, Developer ID,
/// notarized), the release's `verify-macos` check.
const APP_REQUIREMENT: &str = include_str!("../../app/update-requirement.txt");
/// `deadbolt update --check`'s exit code when an update is available.
const EXIT_AVAILABLE: u8 = 10;
/// The largest manifest read.
const MANIFEST_LIMIT: usize = 1 << 20;

#[derive(Args)]
pub struct UpdateArgs {
    /// Only say whether an update is available: exits 10 if one is, 0 if not.
    #[arg(long)]
    check: bool,
    /// The release channel to follow (default: the one this build was
    /// published on). Builds from source follow none, so need this.
    #[arg(long, value_parser = ["dev", "beta", "stable"])]
    channel: Option<String>,
    /// Switch channels without asking, even on a terminal.
    #[arg(short, long)]
    yes: bool,
    /// Accept a manifest older than one already seen (a lower `sequence`).
    #[arg(long)]
    allow_rollback: bool,
}

/// How the running `deadbolt` is installed, which decides what updating it
/// means.
#[derive(Debug, PartialEq, Eq)]
pub enum Install {
    /// The helper of this Deadbolt.app.
    App(PathBuf),
    /// A Deadbolt.app run from a disk image or under App Translocation,
    /// which can't be replaced.
    Unmovable(PathBuf),
    /// A standalone `deadbolt` (the install script, a tarball, a build) in
    /// this directory.
    Standalone(PathBuf),
    /// Installed by a package manager, which updates it.
    Managed(Manager),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Manager {
    Brew,
    BrewCask,
    Nix,
    Cargo,
    System,
    /// `npm`, `pnpm`, `bun` or `yarn` said it has `@deadbolt/cli` globally:
    /// the command links into its platform package (Deadbolt.app's helper
    /// there, on macOS).
    Npm,
    Pnpm,
    Bun,
    Yarn,
    /// npm's package, but none of those managers said it has it.
    Package,
}

impl Manager {
    /// The release service's distribution kind. npm's packages follow
    /// what the registry serves instead ([`served_by_npm`]).
    fn distribution(self) -> &'static str {
        match self {
            Self::Brew | Self::BrewCask => "brew",
            _ => "unknown",
        }
    }

    /// Whether it installs npm's package, so the registry says what it can
    /// install.
    fn npm(self) -> bool {
        matches!(
            self,
            Self::Npm | Self::Pnpm | Self::Bun | Self::Yarn | Self::Package
        )
    }

    /// Who updates it, for people.
    fn name(self) -> &'static str {
        match self {
            Self::Brew | Self::BrewCask => "Homebrew",
            Self::Nix => "Nix",
            Self::Cargo => "Cargo",
            Self::System => "its package manager",
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Bun => "bun",
            Self::Yarn => "yarn",
            Self::Package => "its JavaScript package manager",
        }
    }

    /// The install method's name in the daemon's check
    /// ([`UpdateInfo`](crate::protocol::UpdateInfo)).
    fn key(self) -> &'static str {
        match self {
            Self::Brew | Self::BrewCask => "brew",
            Self::Nix => "nix",
            Self::Cargo => "cargo",
            Self::System => "system",
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Bun => "bun",
            Self::Yarn => "yarn",
            Self::Package => "package",
        }
    }

    /// What to run by hand when `deadbolt update` doesn't run the manager,
    /// for `channel`.
    fn hint(self, channel: &str) -> String {
        let tag = if channel == "stable" {
            "latest"
        } else {
            channel
        };
        match self {
            Self::Nix => "update it with Nix, which installed it".into(),
            Self::Cargo => "reinstall it with cargo install, which installed it".into(),
            Self::System => "update it with the package manager that installed it".into(),
            Self::Package => format!(
                "reinstall {PACKAGE}@{tag} with the package manager that installed it \
                 (npm i -g, pnpm add -g, bun add -g or yarn global add)"
            ),
            _ => upgrade_command(self, tag).map_or_else(String::new, |c| c.shown),
        }
    }
}

/// The command that installs `version` with a package manager. Always this
/// fixed command, never one from the network.
#[derive(Debug, PartialEq, Eq)]
struct Upgrade {
    /// Looked up with [`find_program`].
    program: &'static str,
    args: Vec<String>,
    /// As people would type it.
    shown: String,
    /// bun never prunes its shared cache, so it gets a fresh one, given
    /// before the package and deleted afterwards (as OpenCode does).
    own_cache: bool,
}

/// [`Upgrade`] for `manager`, pinned to `version`; `None` for the managers
/// `deadbolt update` leaves to the user.
fn upgrade_command(manager: Manager, version: &str) -> Option<Upgrade> {
    let target = format!("{PACKAGE}@{version}");
    let (program, args): (&str, Vec<String>) = match manager {
        Manager::Npm => ("npm", vec!["install".into(), "--global".into(), target]),
        Manager::Pnpm => (
            "pnpm",
            vec![
                "add".into(),
                "--global".into(),
                format!("--allow-build={PACKAGE}"),
                target,
            ],
        ),
        // `--trust` runs the wrapper's postinstall, which links it.
        Manager::Bun => (
            "bun",
            vec![
                "install".into(),
                "--global".into(),
                "--trust".into(),
                target,
            ],
        ),
        Manager::Yarn => ("yarn", vec!["global".into(), "add".into(), target]),
        Manager::Brew => (
            "brew",
            vec!["upgrade".into(), "anomalyco/tap/deadbolt".into()],
        ),
        Manager::BrewCask => (
            "brew",
            vec![
                "upgrade".into(),
                "--cask".into(),
                "anomalyco/tap/deadbolt".into(),
            ],
        ),
        Manager::Nix | Manager::Cargo | Manager::System | Manager::Package => return None,
    };
    Some(Upgrade {
        program,
        shown: std::iter::once(program)
            .chain(args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" "),
        args,
        own_cache: manager == Manager::Bun,
    })
}

/// The install method's name for the daemon's check: the
/// install script's directory (`$DEADBOLT_INSTALL`, else `~/.local/bin`)
/// is `curl`, any other standalone `deadbolt` `standalone`.
pub fn method_key(install: &Install) -> &'static str {
    match install {
        Install::App(_) | Install::Unmovable(_) => "app",
        Install::Standalone(dir) => {
            let script = crate::config::env("DEADBOLT_INSTALL")
                .ok()
                .filter(|d| !d.is_empty())
                .map(PathBuf::from)
                .or_else(|| {
                    crate::config::env("HOME")
                        .ok()
                        .map(|h| PathBuf::from(h).join(".local/bin"))
                });
            let same = script.is_some_and(|s| s.canonicalize().unwrap_or(s) == *dir);
            if same { "curl" } else { "standalone" }
        }
        Install::Managed(manager) => manager.key(),
    }
}

/// How `update` and the notice name an install method ([`method_key`]).
pub fn installed_with(key: &str) -> String {
    match key {
        "app" => "Deadbolt.app".into(),
        "curl" => "installed with the install script".into(),
        "standalone" => "standalone".into(),
        "brew" => "installed with Homebrew".into(),
        "package" => "installed with a JavaScript package manager".into(),
        other => format!("installed with {other}"),
    }
}

/// Where Homebrew keeps casks' records: a Deadbolt.app with one is the cask's.
const CASKROOMS: [&str; 2] = [
    "/opt/homebrew/Caskroom/deadbolt",
    "/usr/local/Caskroom/deadbolt",
];

/// How the `deadbolt` at `exe` (symlinks resolved) is installed, by path
/// alone: npm's package is [`Manager::Package`] until [`method`] asks the
/// managers. `exists` says whether a path exists (Homebrew's cask records).
pub fn classify(exe: &Path, macos: bool, exists: impl Fn(&Path) -> bool) -> Install {
    // Before the bundle: npm's darwin package carries Deadbolt.app.
    if exe.components().any(|c| c.as_os_str() == "node_modules") {
        return Install::Managed(Manager::Package);
    }
    if macos && let Some(bundle) = crate::app::bundle_of(exe) {
        let text = bundle.to_string_lossy();
        if text.starts_with("/Volumes/") || text.contains("/AppTranslocation/") {
            return Install::Unmovable(bundle);
        }
        if CASKROOMS.iter().any(|room| exists(Path::new(room))) {
            return Install::Managed(Manager::BrewCask);
        }
        return Install::App(bundle);
    }
    let text = exe.to_string_lossy();
    if exe.components().any(|c| c.as_os_str() == "Cellar") {
        return Install::Managed(Manager::Brew);
    }
    if text.starts_with("/nix/store/") {
        return Install::Managed(Manager::Nix);
    }
    if text.starts_with("/usr/") && !text.starts_with("/usr/local/") {
        return Install::Managed(Manager::System);
    }
    let dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
    if dir.ends_with(".cargo/bin") {
        return Install::Managed(Manager::Cargo);
    }
    Install::Standalone(dir)
}

/// How the `deadbolt` at `exe` (symlinks resolved) is installed, as
/// OpenCode's updater tells: [`classify`], and for npm's package (one whose
/// `@deadbolt/cli` links to `exe`, [`package_of`]) the first of npm, pnpm,
/// bun and yarn that says it has `@deadbolt/cli` globally, those named in
/// `exe`'s path first.
pub async fn method(exe: &Path) -> Install {
    let install = classify(exe, cfg!(target_os = "macos"), Path::exists);
    if install != Install::Managed(Manager::Package) || package_of(exe).is_none() {
        return install;
    }
    // All at once; a missing manager, a failure or no answer is a no.
    let asks: Vec<_> = manager_order(exe)
        .into_iter()
        .map(|manager| {
            (
                manager,
                tokio::spawn(has_package(manager, exe.to_path_buf())),
            )
        })
        .collect();
    for (manager, ask) in asks {
        if ask.await.unwrap_or(false) {
            return Install::Managed(manager);
        }
    }
    install
}

/// Whether `manager` says it has `@deadbolt/cli` globally.
async fn has_package(manager: Manager, exe: PathBuf) -> bool {
    let (program, args): (&str, &[&str]) = match manager {
        Manager::Npm => ("npm", &["list", "-g", "--depth=0", PACKAGE]),
        Manager::Pnpm => ("pnpm", &["list", "-g", "--depth=0", PACKAGE]),
        Manager::Bun => ("bun", &["pm", "ls", "-g"]),
        _ => ("yarn", &["global", "list"]),
    };
    let Some(program) = find_program(program, &exe) else {
        return false;
    };
    let output = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(Duration::from_secs(15), output).await {
        Ok(Ok(output)) => lists_package(&String::from_utf8_lossy(&output.stdout)),
        _ => false,
    }
}

/// npm, pnpm, bun and yarn, those named in `exe`'s path first (`.bun`,
/// `pnpm`, `yarn`), and bun's `install/global/node_modules` too.
fn manager_order(exe: &Path) -> Vec<Manager> {
    let parts: Vec<String> = exe
        .components()
        .map(|c| {
            let part = c.as_os_str().to_string_lossy().to_lowercase();
            part.trim_start_matches('.').to_string()
        })
        .collect();
    let bun = exe
        .ancestors()
        .any(|dir| dir.ends_with("install/global/node_modules"));
    let mut order = vec![Manager::Npm, Manager::Pnpm, Manager::Bun, Manager::Yarn];
    order.sort_by_key(|m| {
        let named = parts.iter().any(|p| p == m.key()) || (bun && *m == Manager::Bun);
        !named
    });
    order
}

/// Whether a manager's list names `@deadbolt/cli` itself (`@deadbolt/cli@1`,
/// `@deadbolt/cli 1`), not just a platform package.
fn lists_package(text: &str) -> bool {
    text.match_indices(PACKAGE).any(|(at, _)| {
        text[at + PACKAGE.len()..]
            .chars()
            .next()
            .is_none_or(|c| c == '@' || c.is_whitespace() || c == '"')
    })
}

/// The `@deadbolt/cli` package directory whose `deadbolt` is `exe`: `exe`
/// is in `@deadbolt/cli` or one of its platform packages (the directory
/// under `node_modules/@deadbolt/`), and that wrapper's `bin` resolves to
/// `exe`. The wrapper sits beside its platform package, or above it when
/// nested (`cli/node_modules/@deadbolt/…`, or the postinstall's own
/// `cli/platform/node_modules/@deadbolt/…`).
pub fn package_of(exe: &Path) -> Option<PathBuf> {
    let scoped = |dir: &Path| {
        dir.parent().is_some_and(|p| {
            p.file_name().is_some_and(|n| n == "@deadbolt")
                && p.parent()
                    .and_then(Path::file_name)
                    .is_some_and(|n| n == "node_modules")
        })
    };
    let dir = exe.ancestors().skip(1).find(|d| scoped(d))?;
    let name = package_name(dir)?;
    if name != PACKAGE && !PLATFORM_PACKAGES.contains(&name.as_str()) {
        return None;
    }
    let mut wrappers: Vec<PathBuf> = vec![dir.to_path_buf(), dir.with_file_name("cli")];
    wrappers.extend(
        dir.ancestors()
            .skip(1)
            .filter(|d| d.file_name().is_some_and(|n| n == "cli") && scoped(d))
            .map(Path::to_path_buf),
    );
    wrappers.into_iter().find(|w| wrapper_links(w, exe))
}

fn package_json(dir: &Path) -> Option<serde_json::Value> {
    serde_json::from_slice(&std::fs::read(dir.join("package.json")).ok()?).ok()
}

fn package_name(dir: &Path) -> Option<String> {
    Some(package_json(dir)?.get("name")?.as_str()?.to_string())
}

/// Whether `wrapper` is `@deadbolt/cli` and its `deadbolt` bin resolves to
/// `exe`.
fn wrapper_links(wrapper: &Path, exe: &Path) -> bool {
    let Some(json) = package_json(wrapper) else {
        return false;
    };
    if json.get("name").and_then(|n| n.as_str()) != Some(PACKAGE) {
        return false;
    }
    let bin = match json.get("bin") {
        Some(serde_json::Value::String(bin)) => Some(bin.as_str()),
        Some(serde_json::Value::Object(bins)) => bins.get("deadbolt").and_then(|b| b.as_str()),
        _ => None,
    };
    bin.and_then(|bin| wrapper.join(bin).canonicalize().ok())
        .is_some_and(|bin| bin == exe)
}

/// `name`'s executable on PATH; bun also in `$BUN_INSTALL/bin`,
/// `~/.bun/bin` and beside the global install `exe` is in, Homebrew in its
/// usual prefixes, as a program started without a login shell's PATH (the
/// daemon from a launcher) may not find them otherwise.
fn find_program(name: &str, exe: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let mut dirs: Vec<PathBuf> = crate::config::env("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    match name {
        "bun" => {
            dirs.extend(
                exe.ancestors()
                    .find(|d| d.ends_with("install/global/node_modules"))
                    .and_then(|d| d.ancestors().nth(3))
                    .map(|root| root.join("bin")),
            );
            dirs.extend(
                crate::config::env("BUN_INSTALL")
                    .ok()
                    .map(|d| PathBuf::from(d).join("bin")),
            );
            dirs.extend(
                crate::config::env("HOME")
                    .ok()
                    .map(|h| PathBuf::from(h).join(".bun/bin")),
            );
        }
        "brew" => dirs.extend(
            [
                "/opt/homebrew/bin",
                "/usr/local/bin",
                "/home/linuxbrew/.linuxbrew/bin",
            ]
            .map(PathBuf::from),
        ),
        _ => {}
    }
    dirs.into_iter()
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|p| {
            std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

/// The release service's name for this build's platform: the static musl
/// build follows its own target, `linux-<arch>-musl`.
fn target() -> Result<String> {
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
const VERSION: &str = env!("CARGO_PKG_VERSION");

// The release protocol, version 1.

#[derive(Debug, Deserialize)]
struct Manifest {
    schema: u32,
    app: String,
    /// Grows with every write to the channel (a rollback included).
    sequence: u64,
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
    url: String,
    size: u64,
    sha256: String,
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
fn validated(artifact: &str, channel: &str, text: &str) -> Result<Manifest, &'static str> {
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
fn rollout_bucket(dir: &Path) -> u8 {
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

// The release service.

struct Service {
    base: Url,
    registry: Url,
    client: reqwest::Client,
}

impl Service {
    fn new(channel: Option<&str>) -> Result<Self> {
        let env = |name| crate::config::env(name).ok();
        let base = loopback_or(SERVICE, SERVICE_OVERRIDE, env(SERVICE_OVERRIDE).as_deref())?;
        let registry = loopback_or(
            REGISTRY,
            REGISTRY_OVERRIDE,
            env(REGISTRY_OVERRIDE).as_deref(),
        )?;
        // reqwest takes the process's rustls provider; Deadbolt's is ring.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let user_agent = format!("deadbolt/{}/{VERSION}/cli", channel.unwrap_or("source"));
        let client = reqwest::Client::builder()
            .user_agent(user_agent)
            .https_only(base.scheme() == "https" && registry.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(60))
            .build()
            .context("setting up HTTPS")?;
        Ok(Self {
            base,
            registry,
            client,
        })
    }

    fn manifest_url(&self, artifact: &str, channel: &str) -> Result<Url> {
        Ok(self
            .base
            .join(&format!("deadbolt/{artifact}/{channel}.json"))?)
    }

    /// The manifest's URL and text; `None` when the channel has no release
    /// of `artifact`.
    async fn manifest(&self, artifact: &str, channel: &str) -> Result<Option<(Url, String)>> {
        let url = self.manifest_url(artifact, channel)?;
        Ok(self.small(&url).await?.map(|text| (url, text)))
    }

    /// The version npm serves for `channel` (its dist-tag: `latest` for
    /// stable), which is all npm, pnpm, bun and yarn can install.
    async fn npm_version(&self, channel: &str) -> Result<Option<String>> {
        let url = self
            .registry
            .join(&format!("-/package/{PACKAGE}/dist-tags"))?;
        let tag = if channel == "stable" {
            "latest"
        } else {
            channel
        };
        let Some(text) = self.small(&url).await? else {
            return Ok(None);
        };
        let tags: BTreeMap<String, serde_json::Value> =
            serde_json::from_str(&text).with_context(|| format!("reading {url}"))?;
        Ok(tags.get(tag).and_then(|v| v.as_str()).map(str::to_string))
    }

    /// Whether the registry serves `name` at `version`
    /// (`<registry>/<name>/<version>`). Large platform packages show up
    /// minutes after the small `@deadbolt/cli` that needs them.
    async fn npm_has(&self, name: &str, version: &str) -> Result<bool> {
        let url = self.registry.join(&format!("{name}/{version}"))?;
        let Some(text) = self.small(&url).await? else {
            return Ok(false);
        };
        let package: serde_json::Value =
            serde_json::from_str(&text).with_context(|| format!("reading {url}"))?;
        Ok(package.get("version").and_then(|v| v.as_str()) == Some(version))
    }

    /// A small document's text, as manifests are read: `None` on 404.
    async fn small(&self, url: &Url) -> Result<Option<String>> {
        let fetch = async {
            let mut response = self.client.get(url.clone()).send().await?;
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !response.status().is_success() {
                bail!("the service answered {}", response.status());
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                body.extend_from_slice(&chunk);
                if body.len() > MANIFEST_LIMIT {
                    bail!("it is too large for a manifest");
                }
            }
            Ok(Some(String::from_utf8(body).context("it is not UTF-8")?))
        };
        tokio::time::timeout(Duration::from_secs(30), fetch)
            .await
            .with_context(|| format!("no answer from {url}"))?
            .with_context(|| format!("fetching {url}"))
    }

    /// Downloads `target`, listed in the manifest at `manifest`, to `file`,
    /// failing unless its size and SHA-256 are the manifest's.
    async fn download(&self, manifest: &Url, target: &Target, file: &Path) -> Result<()> {
        use std::io::Write;
        let url = file_url(manifest, &target.url)?;
        let fetch = async {
            let mut response = self.client.get(url.clone()).send().await?;
            if !response.status().is_success() {
                bail!("the service answered {}", response.status());
            }
            if response.content_length().is_some_and(|n| n != target.size) {
                bail!("it is not the size the manifest says");
            }
            let mut out = std::fs::File::create(file)
                .with_context(|| format!("creating {}", file.display()))?;
            let mut hash = Sha256::new();
            let mut size = 0u64;
            while let Some(chunk) = response.chunk().await? {
                size += chunk.len() as u64;
                if size > target.size {
                    bail!("it is larger than the manifest says");
                }
                hash.update(&chunk);
                out.write_all(&chunk)?;
            }
            out.sync_all()?;
            if size != target.size {
                bail!(
                    "it is {size} bytes, not the {} the manifest says",
                    target.size
                );
            }
            let sha256 = HEXLOWER.encode(&hash.finalize());
            if sha256 != target.sha256 {
                bail!(
                    "its SHA-256 is {sha256}, not the manifest's {}",
                    target.sha256
                );
            }
            Ok(())
        };
        tokio::time::timeout(Duration::from_secs(30 * 60), fetch)
            .await
            .with_context(|| format!("downloading {url} took too long"))?
            .with_context(|| format!("downloading {url}"))
    }
}

/// A base URL: `default`, or in debug builds `over` (from the variable
/// `var`) on 127.0.0.1 or [::1].
fn loopback_or(default: &str, var: &str, over: Option<&str>) -> Result<Url> {
    let Some(over) = over.filter(|o| cfg!(debug_assertions) && !o.is_empty()) else {
        return Ok(Url::parse(default)?);
    };
    let mut url = Url::parse(over).with_context(|| format!("{var} {over}"))?;
    let loopback = matches!(
        url.host(),
        Some(url::Host::Ipv4(ip)) if ip.is_loopback()
    ) || matches!(url.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback());
    if !loopback || !matches!(url.scheme(), "http" | "https") {
        bail!("{var} must be a URL on 127.0.0.1 or [::1]");
    }
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}

/// A target's file URL, resolved against its manifest's URL: only Deadbolt's
/// files on the service that served the manifest.
fn file_url(manifest: &Url, reference: &str) -> Result<Url> {
    let url = manifest.join(reference)?;
    let files = manifest.join("../files/")?;
    if url.origin() != manifest.origin()
        || !url.path().starts_with(files.path())
        || url.query().is_some()
    {
        bail!("the manifest points outside Deadbolt's releases: {url}");
    }
    Ok(url)
}

// Running the update.

/// For npm's package: npm, pnpm, bun and yarn install only what the
/// registry serves for the channel (`served`, `@deadbolt/cli`'s dist-tag),
/// which trails the release service by minutes, and the wrapper needs this
/// system's platform package at that version too (`platform`: that version
/// when the registry has it), which can trail the wrapper by minutes more.
/// Until both are the release the update is pending, so it's never offered
/// before the manager can install all of it.
fn served_by_npm(decision: Decision, served: Option<&str>, platform: Option<&str>) -> Decision {
    match decision {
        Decision::Notify { ref version, .. }
            if served != Some(version.as_str()) || platform != Some(version.as_str()) =>
        {
            Decision::None("distribution_pending")
        }
        decision => decision,
    }
}

/// The platform package `@deadbolt/cli`'s postinstall links on this system
/// (packaging/npm/postinstall.mjs) for the release service's `target`: on
/// Linux the static `-musl` build only where `static_libc` says so, else the
/// build with the app.
fn platform_package(target: &str, static_libc: impl FnOnce() -> bool) -> String {
    let target = target.replacen("macos-", "darwin-", 1);
    let glibc = target.strip_suffix("-musl").unwrap_or(&target);
    if target.starts_with("linux-") && static_libc() {
        format!("@deadbolt/cli-{glibc}-musl")
    } else {
        format!("@deadbolt/cli-{glibc}")
    }
}

/// Whether the postinstall picks the static build here, as the install
/// script does: musl (Alpine, `/lib/ld-musl-*`, or `ldd --version` says so)
/// or a glibc older than 2.28.
fn static_libc() -> bool {
    let musl_loader = std::fs::read_dir("/lib").is_ok_and(|dir| {
        dir.flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with("ld-musl-"))
    });
    if musl_loader || Path::new("/etc/alpine-release").exists() {
        return true;
    }
    let ldd = Command::new("ldd")
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map(|o| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            )
        })
        .unwrap_or_default();
    static_for(&ldd)
}

/// Whether `ldd --version` said musl or a glibc older than 2.28 (its first
/// line ends in the version: "ldd (GNU libc) 2.36").
fn static_for(ldd: &str) -> bool {
    if ldd.to_lowercase().contains("musl") {
        return true;
    }
    let version = ldd
        .lines()
        .next()
        .and_then(|line| line.trim().rsplit(' ').next())
        .and_then(|v| v.split_once('.'))
        .and_then(|(major, minor)| Some((major.parse::<u32>().ok()?, minor.parse::<u32>().ok()?)));
    version.is_some_and(|v| v < (2, 28))
}

/// The artifact `install` follows, what to call it, and its distribution
/// kind for [`decide`].
fn artifact_of(install: &Install) -> Result<(&'static str, &'static str, &'static str)> {
    Ok(match install {
        Install::App(_) => ("desktop", "Deadbolt.app", "direct"),
        Install::Unmovable(bundle) => bail!(
            "{} runs from a disk image or under App Translocation; \
             move Deadbolt to Applications, open it once, then update",
            bundle.display()
        ),
        Install::Standalone(_) => ("cli", "deadbolt", "direct"),
        Install::Managed(manager @ Manager::BrewCask) => {
            ("desktop", "Deadbolt.app", manager.distribution())
        }
        Install::Managed(manager) => ("cli", "deadbolt", manager.distribution()),
    })
}

/// The channel's manifest for `artifact` and what to do about it, `None`
/// when the channel has none: [`decide`], then for npm's package
/// [`served_by_npm`], for the platform package this system installs
/// ([`platform_package`]).
async fn find(
    service: &Service,
    install: &Install,
    artifact: &str,
    channel: &str,
    running: &Running<'_>,
) -> Result<Option<(Url, String, Decision)>> {
    let Some((url, text)) = service.manifest(artifact, channel).await? else {
        return Ok(None);
    };
    let mut decision = decide(artifact, channel, &text, running);
    if let Install::Managed(manager) = install
        && manager.npm()
        && matches!(decision, Decision::Notify { .. })
    {
        let served = service.npm_version(channel).await?;
        let platform = match &served {
            Some(version) => {
                let name = platform_package(running.target, static_libc);
                service
                    .npm_has(&name, version)
                    .await?
                    .then_some(version.as_str())
            }
            None => None,
        };
        decision = served_by_npm(decision, served.as_deref(), platform);
    }
    Ok(Some((url, text, decision)))
}

/// The daemon's background check: whether this install has an update on
/// `channel` that `deadbolt update` would install (the release service's
/// rules, npm's version for npm's package, Homebrew's for Homebrew). It
/// never downloads or installs anything, nor writes the sequence floors
/// `update` keeps, but it ignores a manifest older than them. `None` for
/// installs it can't update: Nix, Cargo and system packages, and an app
/// that can't be replaced where it is.
pub async fn available(paths: &Paths, channel: &str) -> Result<Option<UpdateInfo>> {
    let exe = crate::app::this_binary()?;
    let install = method(&exe).await;
    if matches!(
        install,
        Install::Unmovable(_) | Install::Managed(Manager::Nix | Manager::Cargo | Manager::System)
    ) {
        return Ok(None);
    }
    let (artifact, _, distribution) = artifact_of(&install)?;
    let state = state_dir(paths);
    let target = target()?;
    let running = Running {
        version: VERSION,
        target: &target,
        distribution,
        bucket: rollout_bucket(&state),
        channel: Some(channel),
    };
    let service = Service::new(Some(channel))?;
    let Some((url, text, decision)) = find(&service, &install, artifact, channel, &running).await?
    else {
        return Ok(None);
    };
    if let Ok(manifest) = validated(artifact, channel, &text) {
        let floor = read_floors(&state)?
            .get(&format!("{artifact}/{channel}"))
            .copied()
            .unwrap_or(0);
        if manifest.sequence < floor {
            bail!(
                "{url} is older than one seen (sequence {} < {floor})",
                manifest.sequence
            );
        }
    }
    Ok(match decision {
        Decision::Reject(reason) => bail!("{url} is not a usable {artifact} manifest ({reason})"),
        Decision::Install { version, .. } | Decision::Notify { version, .. } => Some(UpdateInfo {
            version,
            method: method_key(&install).into(),
        }),
        Decision::None(_) => None,
    })
}

/// The state directory: the log's.
fn state_dir(paths: &Paths) -> PathBuf {
    paths
        .log
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default()
}

pub async fn run(paths: &Paths, args: UpdateArgs) -> Result<ExitCode> {
    let built = build_channel();
    let Some(channel) = args.channel.as_deref().or(built) else {
        bail!(
            "this deadbolt was built from source and follows no release channel; \
             pass --channel dev or --channel stable"
        );
    };
    let exe = crate::app::this_binary()?;
    let install = method(&exe).await;
    let service = Service::new(built)?;
    // Held through the install, so two updates never install at once.
    let state = UpdateState::open(&state_dir(paths))?;
    let bucket = rollout_bucket(&state.dir);
    let target = target()?;
    let shown = match built {
        Some(built) => format!("{VERSION} ({built})"),
        None => format!("{VERSION} (source)"),
    };
    let how = installed_with(method_key(&install));

    let (artifact, what, distribution) = artifact_of(&install)?;
    let running = Running {
        version: VERSION,
        target: &target,
        distribution,
        bucket,
        channel: built,
    };
    let Some((url, text, decision)) = find(&service, &install, artifact, channel, &running).await?
    else {
        bail!("there is no {channel} release of {what} yet");
    };
    let mut available = false;
    if let Decision::Reject(reason) = decision {
        bail!("{url} is not a usable {artifact} manifest ({reason})");
    }
    check_sequence(&state, artifact, channel, &text, args.allow_rollback)?;
    match decision {
        Decision::Reject(reason) => bail!("{url} is not a usable {artifact} manifest ({reason})"),
        Decision::None("up_to_date") => {
            println!("{what} {shown} is up to date on {channel} ({how})");
            if let Install::Managed(manager) = &install
                && upgrade_command(*manager, "").is_none()
            {
                println!("{} updates it: {}", manager.name(), manager.hint(channel));
            }
        }
        Decision::None("rollout_deferred") => println!(
            "{what} {shown}: a new {channel} release is rolling out and hasn't reached this \
             computer yet; try again later"
        ),
        Decision::None("distribution_pending" | "distribution_unlisted") => {
            let manager = match &install {
                Install::Managed(manager) => manager.name(),
                _ => "its package manager",
            };
            println!(
                "{what} {shown} is {manager}'s to update, and {manager} doesn't offer \
                 {channel}'s current release yet; try again later"
            )
        }
        Decision::None(reason) => bail!("{channel} has no {what} for {target} ({reason})"),
        Decision::Notify {
            reason,
            version,
            command,
            notes_url,
        } => {
            let Install::Managed(manager) = install else {
                bail!("unexpected decision for {what}");
            };
            available = true;
            println!("{what} {version} is available on {channel} (this is {shown}, {how})");
            if let Some(notes) = notes_url {
                println!("Release notes: {notes}");
            }
            match upgrade_command(manager, &version) {
                Some(upgrade) if args.check => println!("deadbolt update runs: {}", upgrade.shown),
                Some(upgrade) => {
                    if reason == Reason::Switch {
                        confirm_switch(built.unwrap_or("source"), channel, &version, args.yes)?;
                    } else {
                        confirm_upgrade(&upgrade.shown, args.yes)?;
                    }
                    update_package(paths, manager, &upgrade, &exe, &version).await?;
                }
                None => match command {
                    Some(command) => println!("Update it with: {command}"),
                    None => println!("To update: {}", manager.hint(channel)),
                },
            }
        }
        Decision::Install {
            reason,
            version,
            target,
        } => {
            available = true;
            if args.check {
                match reason {
                    Reason::Switch => {
                        println!("{what} {version} is on {channel} (this is {shown})");
                    }
                    _ => println!("{what} {version} is available on {channel} (this is {shown})"),
                }
            } else {
                if reason == Reason::Switch {
                    confirm_switch(built.unwrap_or("source"), channel, &version, args.yes)?;
                }
                println!("Updating {what} {shown} to {version} ({channel})...");
                match &install {
                    Install::App(bundle) => {
                        refuse_foreign_root(bundle.parent().unwrap_or(bundle))?;
                        update_app(paths, &service, &url, &target, bundle, &version).await?;
                    }
                    Install::Standalone(dir) => {
                        refuse_foreign_root(dir)?;
                        let macos = cfg!(target_os = "macos");
                        update_cli(paths, &service, &url, &target, &exe, dir, built, macos).await?;
                    }
                    _ => bail!("unexpected install for {what}"),
                }
            }
        }
    }
    let extensions = crate::config::Config::load(&paths.config)?.extensions;
    available |= extension(
        &extensions,
        &service,
        &state,
        channel,
        bucket,
        built,
        args.check,
        args.allow_rollback,
    )
    .await?;
    Ok(if args.check && available {
        ExitCode::from(EXIT_AVAILABLE)
    } else {
        ExitCode::SUCCESS
    })
}

/// Running a package manager is asked on a terminal, unless `--yes`.
fn confirm_upgrade(command: &str, yes: bool) -> Result<()> {
    if yes || !crate::prompt::interactive() {
        return Ok(());
    }
    if !crate::prompt::confirm(&format!("Run {command}?"))? {
        bail!("cancelled");
    }
    Ok(())
}

/// The most of a failed manager's output shown.
const OUTPUT_LINES: usize = 12;

/// The last [`OUTPUT_LINES`] non-empty lines of `text`, without terminal
/// escapes.
fn output_tail(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        plain.push(if c == '\r' { '\n' } else { c });
    }
    let lines: Vec<&str> = plain
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty())
        .collect();
    lines[lines.len().saturating_sub(OUTPUT_LINES)..].join("\n")
}

/// What to say when `who` failed to install `version`.
fn upgrade_failure(who: &str, version: &str, detail: &str, shown: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{who} couldn't install deadbolt {version}:\n{detail}\n\n\
         It ran: {shown}\n\
         Fix the problem above, then run `deadbolt update` again, or run that command yourself."
    )
}

/// The command people run for the install `exe` belongs to, which a package
/// manager's update leaves in place: its own link (`~/.bun/bin/deadbolt`,
/// `<prefix>/bin/deadbolt`), else `@deadbolt/cli`'s `bin/deadbolt` in
/// `wrapper`, Homebrew's `<prefix>/bin/deadbolt`, or the cask's app helper.
fn user_link(manager: Manager, exe: &Path, wrapper: Option<&Path>) -> PathBuf {
    match manager {
        Manager::Brew => exe
            .ancestors()
            .find(|d| d.file_name().is_some_and(|n| n == "Cellar"))
            .and_then(Path::parent)
            .map_or_else(|| exe.to_path_buf(), |prefix| prefix.join("bin/deadbolt")),
        Manager::BrewCask => exe.to_path_buf(),
        _ => {
            let link = crate::desktop::launcher_program(exe);
            match wrapper {
                Some(wrapper) if link == exe => wrapper.join("bin/deadbolt"),
                _ => link,
            }
        }
    }
}

/// Updates the install `exe` with its package manager to `version`, then
/// runs the new `deadbolt --version` through the user's link (which lets
/// npm's wrapper link itself where the manager skipped its postinstall)
/// and restarts the daemon on it, locked, if it ran from `exe`.
async fn update_package(
    paths: &Paths,
    manager: Manager,
    upgrade: &Upgrade,
    exe: &Path,
    version: &str,
) -> Result<()> {
    let who = manager.name();
    let Some(program) = find_program(upgrade.program, exe) else {
        bail!(
            "{who} installed deadbolt, but `{}` isn't on PATH; run it yourself: {}",
            upgrade.program,
            upgrade.shown
        );
    };
    let wrapper = package_of(exe);
    let link = user_link(manager, exe, wrapper.as_deref());
    let ours = daemon_runs(paths, |p| p == exe).await;
    let cache = match upgrade.own_cache {
        true => Some(
            tempfile::Builder::new()
                .prefix("deadbolt-update-")
                .tempdir()
                .context("making a cache directory for bun")?,
        ),
        false => None,
    };
    let mut args: Vec<OsString> = upgrade.args.iter().map(OsString::from).collect();
    if let Some(cache) = &cache {
        let at = args.len().saturating_sub(1);
        args.insert(at, cache.path().into());
        args.insert(at, "--cache-dir".into());
    }
    println!("Running {}", upgrade.shown);
    let output = tokio::process::Command::new(&program)
        .args(&args)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output();
    let output = match tokio::time::timeout(Duration::from_secs(10 * 60), output).await {
        Err(_) => {
            return Err(upgrade_failure(
                who,
                version,
                "it was still running after 10 minutes",
                &upgrade.shown,
            ));
        }
        Ok(Err(error)) => {
            return Err(upgrade_failure(
                who,
                version,
                &format!("couldn't run {}: {error}", program.display()),
                &upgrade.shown,
            ));
        }
        Ok(Ok(output)) => output,
    };
    drop(cache);
    if !output.status.success() {
        let detail = [&output.stderr, &output.stdout]
            .into_iter()
            .map(|o| output_tail(&String::from_utf8_lossy(o)))
            .find(|t| !t.is_empty())
            .unwrap_or_else(|| format!("it exited with {} and said nothing", output.status));
        return Err(upgrade_failure(who, version, &detail, &upgrade.shown));
    }
    let said = tokio::process::Command::new(&link)
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output();
    let said = match tokio::time::timeout(Duration::from_secs(120), said).await {
        Ok(Ok(output)) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => String::new(),
    };
    let new = link.canonicalize().unwrap_or_else(|_| link.clone());
    // Whatever is in place now, its daemon comes back.
    if ours && stop_daemon(paths).await {
        restart_daemon(paths, new).await;
    }
    if said.split_whitespace().nth(1) != Some(version) {
        bail!(
            "{who} ran, but {} --version says {:?}, not deadbolt {version}; run {} yourself",
            link.display(),
            said,
            upgrade.shown
        );
    }
    println!("Updated {} to {version} with {who}", link.display());
    Ok(())
}

/// A channel switch is the user's choice: asked on a terminal, else `--yes`.
fn confirm_switch(from: &str, to: &str, version: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !crate::prompt::interactive() {
        bail!("this build is from {from}; pass --yes to switch to {to} {version}");
    }
    if !crate::prompt::confirm(&format!(
        "This build is from {from}. Switch to {to} {version}?"
    ))? {
        bail!("cancelled");
    }
    Ok(())
}

/// A directory beside `dest` to stage its replacement in, on the same
/// volume so it can be renamed into place.
fn stage_beside(dest: &Path) -> Result<tempfile::TempDir> {
    let dir = dest.parent().context("no directory to update in")?;
    tempfile::Builder::new()
        .prefix(".deadbolt-update-")
        .tempdir_in(dir)
        .with_context(|| format!("can't write to {}", dir.display()))
}

/// The code-signing requirement for Deadbolt's `identifier`, from the app's
/// update requirement without `notarized` (bare executables are notarized
/// but can't be stapled, so only the app's ticket can be checked offline).
fn requirement(identifier: &str) -> String {
    APP_REQUIREMENT
        .trim()
        .replace(
            "identifier \"pw.deadbolt.app\"",
            &format!("identifier \"{identifier}\""),
        )
        .trim_end_matches(" and notarized")
        .to_string()
}

// The tools updates use, by absolute path so PATH can't swap them.
const CODESIGN: &str = "/usr/bin/codesign";
const SPCTL: &str = "/usr/sbin/spctl";
const DITTO: &str = "/usr/bin/ditto";
const XATTR: &str = "/usr/bin/xattr";
const OSASCRIPT: &str = "/usr/bin/osascript";
const OPEN: &str = "/usr/bin/open";

/// Whether a standalone `deadbolt`'s replacement must be signed with
/// Deadbolt's Developer ID: always for a release build (one published on a
/// channel) on macOS, decided when it was built, never by what's on disk.
/// Builds from source rely on the checksum alone.
fn signature_required(macos: bool, built: Option<&str>) -> bool {
    macos && built.is_some()
}

/// Whether `path` satisfies `requirement` (`codesign --verify --strict`,
/// with `tool` as codesign). An error if codesign can't run: that is never
/// read as "not signed".
fn satisfies(tool: &str, path: &Path, requirement: &str, deep: bool) -> Result<bool> {
    let mut command = Command::new(tool);
    command.args(["--verify", "--strict", "--all-architectures"]);
    if deep {
        command.arg("--deep");
    }
    let status = command
        .arg(format!("-R={requirement}"))
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("running {tool}"))?;
    Ok(status.success())
}

fn run_tool(command: &mut Command, what: &str) -> Result<()> {
    let output = command
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {what}"))?;
    if !output.status.success() {
        bail!(
            "{what} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Whether root may update: only an install in a root-owned directory, with
/// root's own HOME, so a root shell never writes into a user's files.
fn root_may_update(euid: u32, dir_owner: Option<u32>, home_owner: Option<u32>) -> bool {
    euid != 0 || (dir_owner == Some(0) && home_owner == Some(0))
}

fn refuse_foreign_root(dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let owner = |p: &Path| std::fs::metadata(p).ok().map(|m| m.uid());
    let home = crate::config::env("HOME").ok().map(PathBuf::from);
    let euid = rustix::process::geteuid().as_raw();
    if !root_may_update(euid, owner(dir), home.as_deref().and_then(owner)) {
        bail!(
            "refusing to update {} as root: run `deadbolt update` as the user who owns it",
            dir.display()
        );
    }
    Ok(())
}

/// One CLI update at a time per state directory, through the final replacement,
/// not just the floor write: an older in-flight download must not install last.
/// Keep the lock file in place; locking the atomically replaced JSON would let
/// another process lock a different inode.
struct UpdateState {
    dir: PathBuf,
    lock: std::fs::File,
}

impl UpdateState {
    fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join("update.lock");
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                bail!(
                    "another deadbolt update or browser switch is running; try again when it finishes"
                );
            }
            Err(error) => return Err(error).with_context(|| format!("locking {}", path.display())),
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            lock,
        })
    }
}

impl Drop for UpdateState {
    fn drop(&mut self) {
        // Closing our descriptor alone may leave the lock held by a concurrent
        // fork until exec closes its inherited CLOEXEC descriptor. The update
        // transaction is finished now; unlock the shared description explicitly.
        if let Err(error) = self.lock.unlock() {
            eprintln!(
                "warning: couldn't release {}: {error}",
                self.dir.join("update.lock").display()
            );
        }
    }
}

/// The highest manifest `sequence` seen for each artifact and channel, kept
/// in the state directory, so a replayed older manifest can't take an
/// install back. A real rollback is a new write with a higher sequence
/// (docs/protocol.md, "Operations"), so it passes.
fn check_sequence(
    state: &UpdateState,
    artifact: &str,
    channel: &str,
    text: &str,
    allow_rollback: bool,
) -> Result<()> {
    let sequence = validated(artifact, channel, text)
        .map_err(|reason| anyhow::anyhow!("not a usable {artifact} manifest ({reason})"))?
        .sequence;
    let path = state.dir.join("release-sequences.json");
    let mut seen = read_floors(&state.dir)?;
    let key = format!("{artifact}/{channel}");
    let highest = seen.get(&key).copied().unwrap_or(0);
    if sequence < highest && !allow_rollback {
        bail!(
            "the service sent an older {artifact} manifest for {channel} (sequence {sequence}, \
             but {highest} was seen); pass --allow-rollback to accept it"
        );
    }
    if sequence > highest {
        seen.insert(key, sequence);
        crate::browser::write_atomic(&path, &serde_json::to_string(&seen)?)?;
    }
    Ok(())
}

/// The highest manifest sequences seen, from `release-sequences.json` in
/// `dir`, the state directory.
fn read_floors(dir: &Path) -> Result<BTreeMap<String, u64>> {
    let path = dir.join("release-sequences.json");
    let recovery = || {
        format!(
            "reading {}: cannot use release sequence state; restore this file from a trusted \
             backup (or correct its read permissions). Deleting it loses all remembered \
             replay floors; deadbolt will not delete it automatically",
            path.display()
        )
    };
    Ok(match std::fs::read(&path) {
        Ok(bytes) if bytes.is_empty() => BTreeMap::new(),
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(recovery)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(error) => return Err(error).with_context(recovery),
    })
}

/// Whether the daemon that runs is this `program`, so replacing it should
/// replace the daemon too.
async fn daemon_runs(paths: &Paths, program: impl Fn(&Path) -> bool) -> bool {
    crate::client::running(paths).await.is_some_and(|daemon| {
        daemon.program.is_some_and(|p| {
            let p = PathBuf::from(p.strip_suffix(" (deleted)").unwrap_or(&p));
            program(&p.canonicalize().unwrap_or(p))
        })
    })
}

/// Restarts the daemon from `program` after an update. Not through
/// `ensure_running`: its daemon check wants this process's own binary, which
/// the update just replaced or deleted, so the new daemon would never pass.
async fn restart_daemon(paths: &Paths, program: PathBuf) {
    let launch = deadbolt_client::Launch { program };
    match deadbolt_client::start(paths, &launch).await {
        Ok(_) if deadbolt_store::is_initialized(&paths.data) => {
            println!("Restarted the daemon; the vault is locked until you unlock it.");
        }
        Ok(_) => println!("Restarted the daemon."),
        Err(error) => eprintln!("warning: couldn't restart the daemon: {error}"),
    }
}

/// Stops the daemon before its files are replaced; a failure is a warning.
async fn stop_daemon(paths: &Paths) -> bool {
    match crate::client::stop(paths).await {
        Ok(_) => true,
        Err(error) => {
            eprintln!(
                "warning: couldn't stop the old daemon: {error}; run `deadbolt debug daemon stop`"
            );
            false
        }
    }
}

/// Moves each `(new, dest)` into place, first moving every existing `dest`
/// into `aside`. On any failure every `dest` gets its old file back (or
/// none, if it had none), so the pair never ends half replaced.
fn swap(files: &[(PathBuf, PathBuf)], aside: &Path) -> Result<()> {
    std::fs::create_dir_all(aside)?;
    let mut moved: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
    let restore = |moved: &[(PathBuf, Option<PathBuf>)]| {
        for (dest, old) in moved.iter().rev() {
            match old {
                Some(old) => {
                    std::fs::rename(old, dest).ok();
                }
                None => {
                    std::fs::remove_file(dest).ok();
                }
            }
        }
    };
    for (i, (_, dest)) in files.iter().enumerate() {
        let old = aside.join(i.to_string());
        match std::fs::symlink_metadata(dest) {
            Ok(_) => {
                if let Err(error) = std::fs::rename(dest, &old) {
                    restore(&moved);
                    return Err(error).with_context(|| format!("moving {} aside", dest.display()));
                }
                moved.push((dest.clone(), Some(old)));
            }
            Err(_) => moved.push((dest.clone(), None)),
        }
    }
    for (new, dest) in files {
        if let Err(error) = std::fs::rename(new, dest) {
            restore(&moved);
            return Err(error).with_context(|| format!("replacing {}", dest.display()));
        }
    }
    Ok(())
}

/// The largest file taken from a CLI tarball.
const TAR_FILE_LIMIT: u64 = 256 << 20;

/// Unpacks `deadbolt` and `deadbolt-enclave` from the gzipped tarball
/// `archive` into `out`, and nothing else: no other names, links, devices
/// or paths, so nothing lands outside `out` or keeps the archive's owner.
fn unpack_cli(archive: &Path, out: &Path) -> Result<Vec<PathBuf>> {
    use std::io::Read;
    const NAMES: [&str; 2] = ["deadbolt", "deadbolt-enclave"];
    let octal = |field: &[u8]| -> Result<u64> {
        let text = std::str::from_utf8(field)
            .ok()
            .map(|t| t.trim_matches(|c: char| c == '\0' || c == ' '))
            .context("a malformed tar header")?;
        if text.is_empty() {
            return Ok(0);
        }
        u64::from_str_radix(text, 8).context("a malformed tar header")
    };
    let text = |field: &[u8]| {
        let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
        String::from_utf8_lossy(&field[..end]).into_owned()
    };
    let mut tar = flate2::read::GzDecoder::new(std::fs::File::open(archive)?);
    let mut written = Vec::new();
    let mut next_name: Option<String> = None;
    let mut header = [0u8; 512];
    loop {
        tar.read_exact(&mut header).context("a truncated tarball")?;
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let sum: u64 = header
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u64::from(*b)
                }
            })
            .sum();
        if octal(&header[148..156])? != sum {
            bail!("a tar header with a wrong checksum");
        }
        let size = octal(&header[124..136])?;
        let kind = header[156];
        let mut name = text(&header[0..100]);
        if &header[257..262] == b"ustar" {
            let prefix = text(&header[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        let name = next_name.take().unwrap_or(name);
        let padded = size.div_ceil(512) * 512;
        let mut data = (&mut tar).take(padded);
        match kind {
            // A pax header's `path`, or a GNU long name, names the next entry.
            b'x' | b'L' => {
                if size > 1 << 20 {
                    bail!("an oversized tar header");
                }
                let mut body = vec![0u8; usize::try_from(padded)?];
                data.read_exact(&mut body)?;
                body.truncate(usize::try_from(size)?);
                next_name = if kind == b'L' {
                    Some(text(&body))
                } else {
                    pax_path(&body)
                };
            }
            b'g' | b'5' => {
                std::io::copy(&mut data, &mut std::io::sink())?;
            }
            b'0' | 0 => {
                let name = name.strip_prefix("./").unwrap_or(&name);
                if !NAMES.contains(&name) {
                    // AppleDouble and the like: never written.
                    std::io::copy(&mut data, &mut std::io::sink())?;
                    continue;
                }
                if size > TAR_FILE_LIMIT {
                    bail!("{name} in the release is too large");
                }
                let path = out.join(name);
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .with_context(|| format!("the release has {name} twice"))?;
                std::io::copy(&mut (&mut data).take(size), &mut file)?;
                std::io::copy(&mut data, &mut std::io::sink())?;
                written.push(path);
            }
            other => bail!(
                "the release's tarball holds a link or special file ({:?}, type {})",
                name,
                char::from(other)
            ),
        }
    }
    Ok(written)
}

/// The `path` record of a pax extended header.
fn pax_path(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let mut rest = text;
    while let Some((len, _)) = rest.split_once(' ') {
        let len: usize = len.parse().ok()?;
        let record = rest.get(..len)?;
        rest = &rest[len..];
        let (_, kv) = record.split_once(' ')?;
        if let Some(path) = kv.strip_suffix('\n')?.strip_prefix("path=") {
            return Some(path.to_string());
        }
    }
    None
}

/// Replaces the standalone `exe` (and `deadbolt-enclave` beside it) with the
/// release's tarball.
#[expect(clippy::too_many_arguments, reason = "one call site, all distinct")]
async fn update_cli(
    paths: &Paths,
    service: &Service,
    manifest: &Url,
    target: &Target,
    exe: &Path,
    dir: &Path,
    built: Option<&str>,
    macos: bool,
) -> Result<()> {
    let stage = stage_beside(exe)?;
    let archive = stage.path().join("deadbolt.tar.gz");
    service.download(manifest, target, &archive).await?;
    let unpacked = stage.path().join("unpacked");
    std::fs::create_dir(&unpacked)?;
    unpack_cli(&archive, &unpacked)?;
    let new = unpacked.join("deadbolt");
    if !new.is_file() {
        bail!("the release has no deadbolt");
    }
    let enclave = unpacked.join("deadbolt-enclave");
    let enclave = enclave.is_file().then_some(enclave);
    let installed_enclave = dir.join("deadbolt-enclave");
    // The new deadbolt pins its own helper: never leave the old one beside it.
    if macos && enclave.is_none() && std::fs::symlink_metadata(&installed_enclave).is_ok() {
        bail!(
            "the release has no deadbolt-enclave to replace {}; nothing was changed",
            installed_enclave.display()
        );
    }
    if signature_required(macos, built) {
        if !satisfies(CODESIGN, &new, &requirement("pw.deadbolt.cli"), false)? {
            bail!("the new deadbolt is not signed by Deadbolt's Developer ID; nothing was changed");
        }
        if let Some(enclave) = &enclave
            && !satisfies(
                CODESIGN,
                enclave,
                &requirement("pw.deadbolt.app.enclave"),
                false,
            )?
        {
            bail!(
                "the new deadbolt-enclave is not signed by Deadbolt's Developer ID; nothing was changed"
            );
        }
    }
    let ours = daemon_runs(paths, |p| p == exe).await;
    let mut files = Vec::new();
    for file in std::iter::once(&new).chain(&enclave) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o755))?;
    }
    // The helper first: the new deadbolt pins it, the old one checks before use.
    if let Some(enclave) = &enclave {
        files.push((enclave.clone(), installed_enclave));
    }
    files.push((new, exe.to_path_buf()));
    swap(&files, &stage.path().join("old"))?;
    println!("Updated {}", exe.display());
    if ours && stop_daemon(paths).await {
        restart_daemon(paths, exe.to_path_buf()).await;
    }
    Ok(())
}

/// Whether `target`, a symlink in `parent` (both relative to an archive's
/// root), stays inside `root`, its first component, by path alone.
fn link_inside(parent: &Path, target: &Path) -> bool {
    use std::path::Component;
    let mut depth: Vec<_> = parent.components().collect();
    let Some(root) = depth.first().copied() else {
        return false;
    };
    for part in target.components() {
        match part {
            Component::Normal(_) => depth.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                depth.pop();
                if depth.first() != Some(&root) {
                    return false;
                }
            }
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

/// The most an app zip may unpack to.
const APP_ZIP_LIMIT: u64 = 2 << 30;

/// Checks the app zip before `ditto` unpacks it: only `Deadbolt.app/…` and
/// `__MACOSX/…` (ditto's sequestered resource forks), every symlink inside
/// the bundle, and nothing written through one.
fn check_app_zip(archive: &Path) -> Result<()> {
    use std::io::Read;
    let mut zip = zip::ZipArchive::new(std::fs::File::open(archive)?)?;
    let mut links: Vec<PathBuf> = Vec::new();
    let mut names: Vec<PathBuf> = Vec::new();
    let mut total = 0u64;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry
            .enclosed_name()
            .with_context(|| format!("the app zip has an unsafe path {:?}", entry.name()))?;
        let first = name.components().next().map(|c| c.as_os_str().to_owned());
        let sequestered = first.as_deref() == Some("__MACOSX".as_ref());
        if first.as_deref() != Some("Deadbolt.app".as_ref()) && !sequestered {
            bail!("the app zip holds {} outside Deadbolt.app", name.display());
        }
        total = total.saturating_add(entry.size());
        if total > APP_ZIP_LIMIT {
            bail!("the app zip is too large");
        }
        if entry.is_symlink() {
            let mut target = String::new();
            (&mut entry).take(4096).read_to_string(&mut target)?;
            let parent = name.parent().unwrap_or(Path::new(""));
            if sequestered || !link_inside(parent, Path::new(&target)) {
                bail!("the app zip links {} outside the bundle", name.display());
            }
            links.push(name.clone());
        }
        names.push(name);
    }
    if let Some(name) = names.iter().find(|name| {
        links
            .iter()
            .any(|link| name.starts_with(link) && *name != link)
    }) {
        bail!("the app zip writes {} through a symlink", name.display());
    }
    Ok(())
}

/// After unpacking: every symlink in `bundle` stays inside it.
fn check_bundle_links(bundle: &Path) -> Result<()> {
    let base = bundle.parent().context("no directory")?;
    let mut dirs = vec![bundle.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let meta = std::fs::symlink_metadata(&path)?;
            if meta.is_symlink() {
                let target = std::fs::read_link(&path)?;
                let parent = path.parent().and_then(|p| p.strip_prefix(base).ok());
                if !parent.is_some_and(|p| link_inside(p, &target)) {
                    bail!("{} links outside the bundle", path.display());
                }
            } else if meta.is_dir() {
                dirs.push(path);
            }
        }
    }
    Ok(())
}

/// Replaces `bundle` with the release's Deadbolt.app.
async fn update_app(
    paths: &Paths,
    service: &Service,
    manifest: &Url,
    target: &Target,
    bundle: &Path,
    version: &str,
) -> Result<()> {
    let stage = stage_beside(bundle)?;
    let archive = stage.path().join("Deadbolt.zip");
    service.download(manifest, target, &archive).await?;
    check_app_zip(&archive)?;
    let unpacked = stage.path().join("unpacked");
    run_tool(
        Command::new(DITTO)
            .args(["-x", "-k"])
            .arg(&archive)
            .arg(&unpacked),
        "ditto",
    )?;
    let new = unpacked.join("Deadbolt.app");
    if !new.join("Contents/Helpers/deadbolt").is_file() {
        bail!("the release has no Deadbolt.app");
    }
    check_bundle_links(&new)?;
    let quarantined = Command::new(XATTR)
        .args(["-p", "com.apple.quarantine"])
        .arg(&new)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("running {XATTR}"))?
        .success();
    if !satisfies(CODESIGN, &new, APP_REQUIREMENT.trim(), true)? {
        bail!("the new Deadbolt.app is not signed and notarized as Deadbolt; nothing was changed");
    }
    run_tool(
        Command::new(SPCTL)
            .args(["--assess", "--type", "execute"])
            .arg(&new),
        "Gatekeeper's check of the new Deadbolt.app",
    )?;
    if quarantined {
        run_tool(
            Command::new(XATTR)
                .args(["-dr", "com.apple.quarantine"])
                .arg(&new),
            "xattr",
        )?;
    }

    // Verified: stop the old app and its daemon, then swap.
    let app_ran = quit_app()?;
    stop_daemon(paths).await;
    let old = stage.path().join("old.app");
    let swapped = std::fs::rename(bundle, &old)
        .with_context(|| format!("moving {} aside", bundle.display()))
        .and_then(|()| {
            std::fs::rename(&new, bundle).or_else(|error| {
                std::fs::rename(&old, bundle).ok();
                Err(error).with_context(|| format!("installing {}", bundle.display()))
            })
        });
    // Whichever app is in place now, its daemon comes back.
    restart_daemon(paths, bundle.join("Contents/Helpers/deadbolt")).await;
    let reopen = || {
        if app_ran && let Err(error) = Command::new(OPEN).arg(bundle).status() {
            eprintln!("warning: couldn't reopen {}: {error}", bundle.display());
        }
    };
    if let Err(error) = swapped {
        reopen();
        return Err(error);
    }
    let trashed = trash(&old, &format!("Deadbolt-{VERSION}"));
    println!("Updated {} to {version}", bundle.display());
    match trashed {
        Some(path) => println!("The old app is in the Trash: {}", path.display()),
        None => {
            std::fs::remove_dir_all(&old).ok();
        }
    }
    reopen();
    Ok(())
}

/// Quits Deadbolt.app if it runs, and says whether it did.
fn quit_app() -> Result<bool> {
    let running = Command::new(OSASCRIPT)
        .args(["-e", "application id \"pw.deadbolt.app\" is running"])
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {OSASCRIPT}"))?;
    let running = String::from_utf8_lossy(&running.stdout).trim() == "true";
    if running {
        Command::new(OSASCRIPT)
            .args(["-e", "tell application id \"pw.deadbolt.app\" to quit"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("running {OSASCRIPT}"))?;
    }
    Ok(running)
}

/// Moves `path` to `~/.Trash/<name>.app` (or `<name> 2.app`, …), if it can.
fn trash(path: &Path, name: &str) -> Option<PathBuf> {
    let trash = PathBuf::from(crate::config::env("HOME").ok()?).join(".Trash");
    let dest = (1..100)
        .map(|n| match n {
            1 => trash.join(format!("{name}.app")),
            n => trash.join(format!("{name} {n}.app")),
        })
        .find(|p| !p.exists())?;
    std::fs::rename(path, &dest).ok().map(|()| dest)
}

// Telling people.

/// Remembers the last notice, `<version> <unix seconds>`, in the state
/// directory.
const NOTICE_FILE: &str = "update-notice";
/// How often one version's notice may show.
const NOTICE_EVERY: u64 = 24 * 3600;

/// Whether to tell of `version` at `now`, after the notice `last`
/// ([`NOTICE_FILE`]'s text): another version at once, the same one a day
/// later.
fn notice_due(last: Option<&str>, version: &str, now: u64) -> bool {
    let Some((seen, at)) = last.and_then(|t| t.trim().split_once(' ')) else {
        return true;
    };
    let Ok(at) = at.parse::<u64>() else {
        return true;
    };
    seen != version || at > now || now - at >= NOTICE_EVERY
}

fn notice_line(update: &UpdateInfo) -> String {
    format!(
        "deadbolt {} is out ({}): run deadbolt update",
        update.version,
        installed_with(&update.method)
    )
}

/// Ends a command at a terminal with one line on stderr when the running
/// daemon's check found an update, at most once a day for each version.
/// With no daemon running it says nothing, and never asks the network.
pub async fn notice(paths: &Paths) {
    let status = tokio::time::timeout(Duration::from_secs(1), crate::client::status(paths)).await;
    let Some(update) = status.ok().flatten().and_then(|s| s.update) else {
        return;
    };
    let file = state_dir(paths).join(NOTICE_FILE);
    let now = crate::config::now();
    let last = std::fs::read_to_string(&file).ok();
    if !notice_due(last.as_deref(), &update.version, now) {
        return;
    }
    eprintln!("{}", notice_line(&update));
    std::fs::create_dir_all(state_dir(paths)).ok();
    crate::browser::write_atomic(&file, &format!("{} {now}\n", update.version)).ok();
}

// The browser extension.

/// Written into an extension directory `deadbolt update` installed, listing
/// what it put there, so it only ever replaces its own files.
const EXTENSION_MARKER: &str = ".deadbolt-extension";
/// The most an extension zip may unpack to, and its most entries.
const EXTENSION_LIMIT: u64 = 64 << 20;
const EXTENSION_ENTRIES: usize = 4096;

/// The version an unpacked extension says it is: `version_name`, else
/// `version`.
fn extension_version(dir: &Path) -> Option<String> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).ok()?).ok()?;
    let field = |key: &str| manifest.get(key)?.as_str().map(str::to_string);
    field("version_name").or_else(|| field("version"))
}

/// Whether `dir` may be replaced by Deadbolt's extension: an absolute path
/// that doesn't exist yet, is empty, or holds only what `deadbolt update`
/// installed there (its marker's list).
pub fn extension_dir_ok(dir: &Path) -> bool {
    if !dir.is_absolute() {
        return false;
    }
    let entries = match std::fs::read_dir(dir) {
        Err(error) => return error.kind() == std::io::ErrorKind::NotFound,
        Ok(entries) => entries,
    };
    let Ok(names) = entries
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    if names.is_empty() {
        return true;
    }
    let Ok(marker) = std::fs::read_to_string(dir.join(EXTENSION_MARKER)) else {
        return false;
    };
    let ours: Vec<&str> = marker.lines().collect();
    names
        .iter()
        .all(|name| name == EXTENSION_MARKER || ours.contains(&name.as_str()))
}

/// Unpacks the extension zip `archive` into `out` (absent): regular files
/// and directories only, at most [`EXTENSION_LIMIT`] bytes, then writes the
/// marker listing its top-level entries.
fn unpack_extension(archive: &Path, out: &Path) -> Result<()> {
    use std::io::Read;
    let mut zip = zip::ZipArchive::new(std::fs::File::open(archive)?)?;
    if zip.len() > EXTENSION_ENTRIES {
        bail!("the extension zip has too many files");
    }
    std::fs::create_dir(out)?;
    let mut total = 0u64;
    let mut top = std::collections::BTreeSet::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry
            .enclosed_name()
            .with_context(|| format!("the extension zip has an unsafe path {:?}", entry.name()))?;
        let Some(first) = name.components().next() else {
            continue;
        };
        let first = first.as_os_str().to_string_lossy().into_owned();
        if first == EXTENSION_MARKER {
            bail!("the extension zip holds {EXTENSION_MARKER}");
        }
        top.insert(first);
        let path = out.join(&name);
        if entry.is_symlink() {
            bail!("the extension zip holds a symlink, {}", name.display());
        }
        if entry.is_dir() {
            std::fs::create_dir_all(&path)?;
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("writing {}", path.display()))?;
        let left = EXTENSION_LIMIT - total;
        let copied = std::io::copy(&mut (&mut entry).take(left + 1), &mut file)?;
        total += copied;
        if total > EXTENSION_LIMIT {
            bail!("the extension zip unpacks to more than {EXTENSION_LIMIT} bytes");
        }
    }
    let marker: String = top.iter().map(|name| format!("{name}\n")).collect();
    std::fs::write(out.join(EXTENSION_MARKER), marker)?;
    Ok(())
}

/// Which build an unpacked extension is (`extension/scripts/build.ts`): the
/// native one asks for `nativeMessaging`, the standalone one for `offscreen`
/// (its vault's worker); `None` for anything else.
fn extension_build(dir: &Path) -> Option<ExtensionBuild> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).ok()?).ok()?;
    let permissions = manifest.get("permissions")?.as_array()?;
    let has = |name: &str| permissions.iter().any(|p| p.as_str() == Some(name));
    if has("nativeMessaging") {
        Some(ExtensionBuild::Native)
    } else if has("offscreen") {
        Some(ExtensionBuild::Standalone)
    } else {
        None
    }
}

/// Checks, and unless `check` updates, the extension directories `dirs`
/// (registered with `deadbolt browser install --extension-dir`), each with
/// the build it was registered for (`browser switch` changes it). True when
/// an update is available for any of them. One directory failing doesn't
/// stop the others.
#[expect(clippy::too_many_arguments, reason = "two call sites, all distinct")]
async fn extension(
    dirs: &[ExtensionDir],
    service: &Service,
    state: &UpdateState,
    channel: &str,
    bucket: u8,
    built: Option<&str>,
    check: bool,
    allow_rollback: bool,
) -> Result<bool> {
    if dirs.is_empty() {
        if !check {
            println!(
                "Browser extension: {SERVICE}deadbolt/extension/{channel}/{} (or register \
                 an unpacked copy with `deadbolt browser install --extension-dir <dir>` to \
                 update it here)",
                ExtensionBuild::Native.target()
            );
        }
        return Ok(false);
    }
    let Some((url, text)) = service.manifest("extension", channel).await? else {
        println!("Browser extension: no {channel} release yet");
        return Ok(false);
    };
    check_sequence(state, "extension", channel, &text, allow_rollback)?;
    let mut available = false;
    let mut failed = None;
    for entry in dirs {
        match extension_dir(entry, service, &url, &text, channel, bucket, built, check).await {
            Ok(found) => available |= found,
            Err(error) if dirs.len() > 1 => {
                eprintln!("{}: {error:#}", entry.dir.display());
                failed.get_or_insert(error);
            }
            Err(error) => return Err(error),
        }
    }
    match failed {
        Some(error) => Err(error.context("updating the browser extensions")),
        None => Ok(available),
    }
}

/// [`extension`] for one directory, with the channel's manifest `text` from
/// `url`.
#[expect(clippy::too_many_arguments, reason = "one call site, all distinct")]
async fn extension_dir(
    entry: &ExtensionDir,
    service: &Service,
    url: &Url,
    text: &str,
    channel: &str,
    bucket: u8,
    built: Option<&str>,
    check: bool,
) -> Result<bool> {
    let ExtensionDir { dir, build } = entry;
    let build = *build;
    if !extension_dir_ok(dir) {
        bail!(
            "{} holds files deadbolt didn't install there (or isn't an absolute path); \
             register an empty directory with `deadbolt browser install --extension-dir <dir>`",
            dir.display()
        );
    }
    // The other build in the directory (a switch) is replaced by this
    // channel's release whatever its version, and the user asked for it, so
    // no rollout holds it back.
    let switching = extension_build(dir).is_some_and(|installed| installed != build);
    let current = if switching {
        String::new()
    } else {
        extension_version(dir).unwrap_or_default()
    };
    let running = Running {
        version: &current,
        target: build.target(),
        distribution: "direct",
        bucket: if switching { 0 } else { bucket },
        channel: built,
    };
    let decision = decide("extension", channel, text, &running);
    if let Decision::Reject(reason) = decision {
        bail!("{url} is not a usable extension manifest ({reason})");
    }
    let what = match build {
        ExtensionBuild::Native => "Browser extension",
        ExtensionBuild::Standalone => "Standalone browser extension",
    };
    match decision {
        Decision::Install {
            version, target, ..
        } => {
            if check {
                println!("{what} {version} is available in {}", dir.display());
            } else {
                refuse_foreign_root(dir.parent().unwrap_or(dir))?;
                update_extension(service, url, &target, dir).await?;
                println!(
                    "Updated the {} in {} to {version}; \
                     reload Deadbolt in chrome://extensions",
                    what.to_lowercase(),
                    dir.display()
                );
            }
            Ok(true)
        }
        Decision::None("up_to_date") => {
            println!("{what} {current} is up to date in {}", dir.display());
            Ok(false)
        }
        Decision::None("no_target") => {
            println!("The {channel} release has no {} yet", what.to_lowercase());
            Ok(false)
        }
        _ => Ok(false),
    }
}

/// `deadbolt browser switch`: registers `build` for one extension directory
/// (`dir`, or the only one registered) and puts the channel's release of it
/// there now.
pub async fn switch_extension(
    paths: &Paths,
    build: ExtensionBuild,
    dir: Option<&Path>,
    channel: Option<&str>,
) -> Result<()> {
    let built = build_channel();
    let Some(channel) = channel.or(built) else {
        bail!(
            "this deadbolt was built from source and follows no release channel; \
             pass --channel dev or --channel stable"
        );
    };
    let state = paths
        .log
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let state = UpdateState::open(&state)?;
    let config = crate::config::Config::load(&paths.config)?;
    let dir = match (dir, config.extensions.as_slice()) {
        (Some(dir), _) => {
            let dir = crate::browser::extension_path(dir)?;
            if config.extension(&dir).is_none() {
                bail!(
                    "{} isn't a registered extension directory; run `deadbolt browser \
                     install {}--extension-dir {}` first",
                    dir.display(),
                    if build == ExtensionBuild::Standalone {
                        "--standalone "
                    } else {
                        ""
                    },
                    dir.display()
                );
            }
            dir
        }
        (None, [only]) => only.dir.clone(),
        (None, []) => bail!(
            "no unpacked extension is registered here; run `deadbolt browser install \
             {}--extension-dir <dir>` with a new or empty directory first",
            if build == ExtensionBuild::Standalone {
                "--standalone "
            } else {
                ""
            }
        ),
        (None, several) => bail!(
            "several extension directories are registered; pick one with \
             --extension-dir:\n{}",
            several
                .iter()
                .map(|e| format!("  {} ({})", e.dir.display(), e.build.name()))
                .collect::<Vec<_>>()
                .join("\n")
        ),
    };
    crate::config::set_extension_dir(&paths.config, &dir, build)?;
    let service = Service::new(built)?;
    let bucket = rollout_bucket(&state.dir);
    extension(
        &[ExtensionDir { dir, build }],
        &service,
        &state,
        channel,
        bucket,
        built,
        false,
        false,
    )
    .await?;
    Ok(())
}

/// Replaces `dir` with the release's extension zip, staged beside it.
async fn update_extension(
    service: &Service,
    manifest: &Url,
    target: &Target,
    dir: &Path,
) -> Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let stage = stage_beside(dir)?;
    let archive = stage.path().join("extension.zip");
    service.download(manifest, target, &archive).await?;
    let new = stage.path().join("new");
    unpack_extension(&archive, &new).context("unpacking the extension")?;
    if extension_version(&new).is_none() {
        bail!("the release has no extension manifest");
    }
    let old = stage.path().join("old");
    let had = dir.exists();
    if had {
        std::fs::rename(dir, &old).with_context(|| format!("moving {} aside", dir.display()))?;
    }
    if let Err(error) = std::fs::rename(&new, dir) {
        if had {
            std::fs::rename(&old, dir).ok();
        }
        return Err(error).with_context(|| format!("replacing {}", dir.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
