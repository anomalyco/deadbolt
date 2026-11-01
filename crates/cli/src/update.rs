//! `deadbolt update`: updates this Deadbolt from the Anomaly release service
//! (docs/releasing.md, "Updater"), following the service's client rules
//! (`anomalyco/release` docs/protocol.md). What it updates depends on how
//! this binary is installed ([`classify`]): Deadbolt.app (the `desktop`
//! artifact), a standalone CLI (`cli`), or nothing, for a package manager's
//! install, which gets that manager's command instead. An unpacked browser
//! extension registered with `deadbolt browser install --extension-dir` is
//! updated too (`extension`).
//!
//! Nothing downloaded runs or replaces anything before its size and SHA-256
//! match the manifest and, on macOS, its code signature satisfies what the
//! running install would ([`APP_REQUIREMENT`]). Each replacement is staged
//! beside its destination and renamed into place.

use std::collections::BTreeMap;
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

/// Where the release service lives.
const SERVICE: &str = "https://anoma.ly/release/";
/// Overrides [`SERVICE`] in debug builds only, and only with a loopback
/// URL, so tests can serve a fake release and no environment can send a
/// release build anywhere else.
const SERVICE_OVERRIDE: &str = "DEADBOLT_RELEASE_URL";
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
    /// `npm i -g @deadbolt/cli`: the command links into its platform
    /// package (Deadbolt.app's helper there, on macOS).
    Npm,
    /// `bun add -g @deadbolt/cli`: npm's packages, in bun's global
    /// `install/global/node_modules`.
    Bun,
}

impl Manager {
    /// The release service's distribution kind. npm publishes in the same
    /// release run, right after the service, so the channel's version is
    /// npm's too.
    fn distribution(self) -> &'static str {
        match self {
            Self::Brew | Self::BrewCask => "brew",
            Self::Npm | Self::Bun | Self::Nix | Self::Cargo | Self::System => "unknown",
        }
    }

    /// Who updates it, for people.
    fn name(self) -> &'static str {
        match self {
            Self::Brew | Self::BrewCask => "Homebrew",
            Self::Nix => "Nix",
            Self::Cargo => "Cargo",
            Self::System => "its package manager",
            Self::Npm => "npm",
            Self::Bun => "bun",
        }
    }

    /// What to run when the manifest names no command, for `channel`.
    fn hint(self, channel: &str) -> String {
        let fixed = match self {
            Self::Brew => "brew upgrade anomalyco/tap/deadbolt",
            Self::BrewCask => "brew upgrade --cask anomalyco/tap/deadbolt",
            Self::Nix => "update it with Nix, which installed it",
            Self::Cargo => "reinstall it with cargo install, which installed it",
            Self::System => "update it with the package manager that installed it",
            Self::Npm | Self::Bun => {
                let tag = if channel == "stable" {
                    "latest"
                } else {
                    channel
                };
                let install = if self == Self::Bun {
                    "bun add -g"
                } else {
                    "npm i -g"
                };
                return format!("{install} @deadbolt/cli@{tag}");
            }
        };
        fixed.into()
    }
}

/// Where Homebrew keeps casks' records: a Deadbolt.app with one is the cask's.
const CASKROOMS: [&str; 2] = [
    "/opt/homebrew/Caskroom/deadbolt",
    "/usr/local/Caskroom/deadbolt",
];

/// How the `deadbolt` at `exe` (symlinks resolved) is installed. `exists`
/// says whether a path exists (Homebrew's cask records).
pub fn classify(exe: &Path, macos: bool, exists: impl Fn(&Path) -> bool) -> Install {
    // Before the bundle: npm's darwin package carries Deadbolt.app.
    if exe.components().any(|c| c.as_os_str() == "node_modules") {
        let bun = exe
            .ancestors()
            .any(|dir| dir.ends_with("install/global/node_modules"));
        return Install::Managed(if bun { Manager::Bun } else { Manager::Npm });
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
fn build_channel() -> Option<&'static str> {
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
    client: reqwest::Client,
}

impl Service {
    fn new(channel: Option<&str>) -> Result<Self> {
        let base = service_base(crate::config::env(SERVICE_OVERRIDE).ok().as_deref())?;
        // reqwest takes the process's rustls provider; Deadbolt's is ring.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let agent = format!("deadbolt/{}/{VERSION}/cli", channel.unwrap_or("source"));
        let client = reqwest::Client::builder()
            .user_agent(agent)
            .https_only(base.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(60))
            .build()
            .context("setting up HTTPS")?;
        Ok(Self { base, client })
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
            Ok(Some(
                String::from_utf8(body).context("the manifest is not UTF-8")?,
            ))
        };
        let text = tokio::time::timeout(Duration::from_secs(30), fetch)
            .await
            .with_context(|| format!("no answer from {url}"))?
            .with_context(|| format!("fetching {url}"))?;
        Ok(text.map(|text| (url, text)))
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

/// The service's base URL: [`SERVICE`], or in debug builds an override on
/// 127.0.0.1 or [::1].
fn service_base(over: Option<&str>) -> Result<Url> {
    let Some(over) = over.filter(|o| cfg!(debug_assertions) && !o.is_empty()) else {
        return Ok(Url::parse(SERVICE)?);
    };
    let mut url = Url::parse(over).with_context(|| format!("{SERVICE_OVERRIDE} {over}"))?;
    let loopback = matches!(
        url.host(),
        Some(url::Host::Ipv4(ip)) if ip.is_loopback()
    ) || matches!(url.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback());
    if !loopback || !matches!(url.scheme(), "http" | "https") {
        bail!("{SERVICE_OVERRIDE} must be a URL on 127.0.0.1 or [::1]");
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

pub async fn run(paths: &Paths, args: UpdateArgs) -> Result<ExitCode> {
    let built = build_channel();
    let Some(channel) = args.channel.as_deref().or(built) else {
        bail!(
            "this deadbolt was built from source and follows no release channel; \
             pass --channel dev or --channel stable"
        );
    };
    let exe = crate::app::this_binary()?;
    let install = classify(&exe, cfg!(target_os = "macos"), Path::exists);
    let service = Service::new(built)?;
    let state = paths
        .log
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let state = UpdateState::open(&state)?;
    let bucket = rollout_bucket(&state.dir);
    let target = target()?;
    let shown = match built {
        Some(built) => format!("{VERSION} ({built})"),
        None => format!("{VERSION} (source)"),
    };

    let (artifact, what, distribution) = match &install {
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
    };
    let running = Running {
        version: VERSION,
        target: &target,
        distribution,
        bucket,
        channel: built,
    };
    let Some((url, text)) = service.manifest(artifact, channel).await? else {
        bail!("there is no {channel} release of {what} yet");
    };
    let mut available = false;
    let decision = decide(artifact, channel, &text, &running);
    if let Decision::Reject(reason) = decision {
        bail!("{url} is not a usable {artifact} manifest ({reason})");
    }
    check_sequence(&state, artifact, channel, &text, args.allow_rollback)?;
    match decision {
        Decision::Reject(reason) => bail!("{url} is not a usable {artifact} manifest ({reason})"),
        Decision::None("up_to_date") => {
            println!("{what} {shown} is up to date on {channel}");
            if let Install::Managed(manager) = &install {
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
            version,
            command,
            notes_url,
            ..
        } => {
            let Install::Managed(manager) = install else {
                bail!("unexpected decision for {what}");
            };
            println!("{what} {version} is available on {channel} (this is {shown})");
            match command {
                Some(command) => println!("Update it with: {command}"),
                None => println!("To update: {}", manager.hint(channel)),
            }
            if let Some(notes) = notes_url {
                println!("Release notes: {notes}");
            }
            available = true;
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
    let recovery = || {
        format!(
            "reading {}: cannot use release sequence state; restore this file from a trusted \
             backup (or correct its read permissions). Deleting it loses all remembered \
             replay floors; deadbolt will not delete it automatically",
            path.display()
        )
    };
    let mut seen: BTreeMap<String, u64> = match std::fs::read(&path) {
        Ok(bytes) if bytes.is_empty() => BTreeMap::new(),
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(recovery)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(error) => return Err(error).with_context(recovery),
    };
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

/// Whether the agent that runs is this `program`, so replacing it should
/// replace the agent too.
async fn agent_runs(paths: &Paths, program: impl Fn(&Path) -> bool) -> bool {
    crate::client::running(paths).await.is_some_and(|agent| {
        agent.program.is_some_and(|p| {
            let p = PathBuf::from(p.strip_suffix(" (deleted)").unwrap_or(&p));
            program(&p.canonicalize().unwrap_or(p))
        })
    })
}

/// Restarts the agent from `program` after an update, as `ensure_running`.
async fn restart_agent(paths: &Paths, program: PathBuf) {
    let launch = deadbolt_client::Launch { program };
    match deadbolt_client::ensure_running(paths, &launch).await {
        Ok(status) if status.initialized => {
            println!("Restarted the agent; the vault is locked until you unlock it.");
        }
        Ok(_) => println!("Restarted the agent."),
        Err(error) => eprintln!("warning: couldn't restart the agent: {error}"),
    }
}

/// Stops the agent before its files are replaced; a failure is a warning.
async fn stop_agent(paths: &Paths) -> bool {
    match crate::client::stop(paths).await {
        Ok(_) => true,
        Err(error) => {
            eprintln!("warning: couldn't stop the old agent: {error}; run `deadbolt agent stop`");
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
    let ours = agent_runs(paths, |p| p == exe).await;
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
    if ours && stop_agent(paths).await {
        restart_agent(paths, exe.to_path_buf()).await;
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

    // Verified: stop the old app and its agent, then swap.
    let app_ran = quit_app()?;
    stop_agent(paths).await;
    let old = stage.path().join("old.app");
    let swapped = std::fs::rename(bundle, &old)
        .with_context(|| format!("moving {} aside", bundle.display()))
        .and_then(|()| {
            std::fs::rename(&new, bundle).or_else(|error| {
                std::fs::rename(&old, bundle).ok();
                Err(error).with_context(|| format!("installing {}", bundle.display()))
            })
        });
    // Whichever app is in place now, its agent comes back.
    restart_agent(paths, bundle.join("Contents/Helpers/deadbolt")).await;
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
mod tests {
    use super::*;

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn manifest(rollout: u8, required: bool) -> String {
        serde_json::json!({
            "schema": 1,
            "app": "deadbolt",
            "artifact": "cli",
            "channel": "stable",
            "sequence": 7,
            "published_at": "2026-10-28T00:00:00Z",
            "release": {
                "version": "2.4.0",
                "rollout_percent": rollout,
                "required": required,
                "targets": {
                    "macos-arm64": {
                        "url": format!("/release/deadbolt/files/{SHA}/deadbolt-2.4.0-darwin-arm64.tar.gz"),
                        "size": 1000,
                        "sha256": SHA,
                    }
                },
                "distributions": [
                    { "kind": "direct" },
                    { "kind": "brew", "formula": "anomalyco/tap/deadbolt", "version": "2.3.9",
                      "command": "brew upgrade anomalyco/tap/deadbolt" },
                    { "kind": "aur", "package": "deadbolt-bin" }
                ],
                "revoked_versions": [],
                "future_field": true
            }
        })
        .to_string()
    }

    fn running(version: &'static str, distribution: &'static str, bucket: u8) -> Running<'static> {
        Running {
            version,
            target: "macos-arm64",
            distribution,
            bucket,
            channel: None,
        }
    }

    fn install(reason: Reason) -> Decision {
        Decision::Install {
            reason,
            version: "2.4.0".into(),
            target: Target {
                url: format!("/release/deadbolt/files/{SHA}/deadbolt-2.4.0-darwin-arm64.tar.gz"),
                size: 1000,
                sha256: SHA.into(),
            },
        }
    }

    #[test]
    fn decides_like_the_release_protocol() {
        let text = manifest(25, false);
        let decide = |r: &Running| decide("cli", "stable", &text, r);
        assert_eq!(
            decide(&running("2.3.8", "direct", 24)),
            install(Reason::Update)
        );
        assert_eq!(
            decide(&running("2.3.8", "direct", 25)),
            Decision::None("rollout_deferred")
        );
        // Versions are never ordered: a "newer" build still moves to the release.
        assert_eq!(
            decide(&running("9.0.0", "direct", 0)),
            install(Reason::Update)
        );
        assert_eq!(
            decide(&running("2.4.0", "direct", 0)),
            Decision::None("up_to_date")
        );
        let other = Running {
            target: "linux-riscv",
            ..running("2.3.8", "direct", 0)
        };
        assert_eq!(decide(&other), Decision::None("no_target"));
        let switch = Running {
            channel: Some("dev"),
            ..running("0.0.0-dev-9", "direct", 99)
        };
        assert_eq!(decide(&switch), install(Reason::Switch));
        let required = manifest(0, true);
        assert_eq!(
            super::decide("cli", "stable", &required, &running("2.3.8", "direct", 99)),
            install(Reason::Required)
        );
        // A package manager's install follows what that manager serves.
        assert_eq!(
            decide(&running("2.3.8", "brew", 0)),
            Decision::Notify {
                reason: Reason::Update,
                version: "2.3.9".into(),
                command: Some("brew upgrade anomalyco/tap/deadbolt".into()),
                notes_url: None,
            }
        );
        assert_eq!(
            decide(&running("2.3.9", "brew", 0)),
            Decision::None("up_to_date")
        );
        assert_eq!(
            decide(&running("2.3.8", "aur", 0)),
            Decision::None("distribution_pending")
        );
        assert_eq!(
            decide(&running("2.3.8", "nix", 0)),
            Decision::None("distribution_unlisted")
        );
        assert_eq!(
            decide(&running("2.3.8", "unknown", 0)),
            Decision::Notify {
                reason: Reason::Update,
                version: "2.4.0".into(),
                command: None,
                notes_url: None,
            }
        );
    }

    #[test]
    fn rejects_manifests_that_are_not_this_one() {
        let r = running("2.3.8", "direct", 0);
        let text = manifest(100, false);
        assert_eq!(
            decide("desktop", "stable", &text, &r),
            Decision::Reject("wrong_artifact")
        );
        assert_eq!(
            decide("cli", "dev", &text, &r),
            Decision::Reject("wrong_channel")
        );
        let other = text.replace("\"deadbolt\"", "\"hex\"");
        assert_eq!(
            decide("cli", "stable", &other, &r),
            Decision::Reject("wrong_app")
        );
        for bad in [
            "not json".to_string(),
            text.replace("\"schema\":1", "\"schema\":2"),
            text.replace("\"rollout_percent\":100", "\"rollout_percent\":101"),
            text.replace(SHA, "AAAA"),
            text.replace("\"size\":1000", "\"size\":-1"),
        ] {
            assert_eq!(
                decide("cli", "stable", &bad, &r),
                Decision::Reject("malformed"),
                "{bad}"
            );
        }
    }

    #[test]
    fn keeps_one_rollout_bucket() {
        let dir = tempfile::tempdir().unwrap();
        let first = rollout_bucket(dir.path());
        assert!(first < 100);
        assert_eq!(rollout_bucket(dir.path()), first);
        std::fs::write(dir.path().join("rollout-bucket"), "250\n").unwrap();
        assert!(rollout_bucket(dir.path()) < 100);
        std::fs::write(dir.path().join("rollout-bucket"), "42\n").unwrap();
        assert_eq!(rollout_bucket(dir.path()), 42);
    }

    #[test]
    fn classifies_installs() {
        let none = |_: &Path| false;
        let app = Path::new("/Applications/Deadbolt.app/Contents/Helpers/deadbolt");
        assert_eq!(
            classify(app, true, none),
            Install::App("/Applications/Deadbolt.app".into())
        );
        assert_eq!(
            classify(app, true, |p| p == Path::new(CASKROOMS[0])),
            Install::Managed(Manager::BrewCask)
        );
        assert_eq!(
            classify(
                Path::new("/Volumes/Deadbolt/Deadbolt.app/Contents/Helpers/deadbolt"),
                true,
                none
            ),
            Install::Unmovable("/Volumes/Deadbolt/Deadbolt.app".into())
        );
        assert!(matches!(
            classify(
                Path::new(
                    "/private/var/folders/x/AppTranslocation/ABC/d/Deadbolt.app/Contents/Helpers/deadbolt"
                ),
                true,
                none
            ),
            Install::Unmovable(_)
        ));
        // Off macOS a bundle is just a directory.
        assert_eq!(
            classify(app, false, none),
            Install::Standalone(app.parent().unwrap().into())
        );
        for (path, manager) in [
            (
                "/opt/homebrew/Cellar/deadbolt/0.1.0/bin/deadbolt",
                Manager::Brew,
            ),
            (
                "/home/linuxbrew/.linuxbrew/Cellar/deadbolt/0.1.0/bin/deadbolt",
                Manager::Brew,
            ),
            ("/nix/store/abc-deadbolt/bin/deadbolt", Manager::Nix),
            ("/usr/bin/deadbolt", Manager::System),
            ("/home/me/.cargo/bin/deadbolt", Manager::Cargo),
            (
                "/usr/local/lib/node_modules/@deadbolt/cli-linux-x64/bin/deadbolt",
                Manager::Npm,
            ),
            (
                "/opt/homebrew/lib/node_modules/@deadbolt/cli-darwin-arm64/Deadbolt.app/Contents/Helpers/deadbolt",
                Manager::Npm,
            ),
            (
                "/usr/lib/node_modules/@deadbolt/cli-linux-x64/bin/deadbolt",
                Manager::Npm,
            ),
            (
                "/home/me/.bun/install/global/node_modules/@deadbolt/cli-linux-x64/bin/deadbolt",
                Manager::Bun,
            ),
            (
                "/Users/me/.bun/install/global/node_modules/@deadbolt/cli-darwin-arm64/Deadbolt.app/Contents/Helpers/deadbolt",
                Manager::Bun,
            ),
        ] {
            assert_eq!(
                classify(Path::new(path), true, none),
                Install::Managed(manager),
                "{path}"
            );
        }
        for path in ["/home/me/.local/bin/deadbolt", "/usr/local/bin/deadbolt"] {
            let path = Path::new(path);
            assert_eq!(
                classify(path, true, none),
                Install::Standalone(path.parent().unwrap().into())
            );
        }
    }

    #[test]
    fn only_trusts_the_service_and_its_files() {
        assert_eq!(service_base(None).unwrap().as_str(), SERVICE);
        assert_eq!(service_base(Some("")).unwrap().as_str(), SERVICE);
        if cfg!(debug_assertions) {
            assert_eq!(
                service_base(Some("http://127.0.0.1:8080/r"))
                    .unwrap()
                    .as_str(),
                "http://127.0.0.1:8080/r/"
            );
            assert!(service_base(Some("http://[::1]:1/")).is_ok());
            for bad in [
                "https://evil.example/release/",
                "http://localhost:1/",
                "file:///tmp/",
            ] {
                assert!(service_base(Some(bad)).is_err(), "{bad}");
            }
        }
        let manifest = Url::parse("https://anoma.ly/release/deadbolt/cli/dev.json").unwrap();
        assert_eq!(
            file_url(
                &manifest,
                &format!("/release/deadbolt/files/{SHA}/d.tar.gz")
            )
            .unwrap()
            .as_str(),
            format!("https://anoma.ly/release/deadbolt/files/{SHA}/d.tar.gz")
        );
        for bad in [
            format!("https://evil.example/release/deadbolt/files/{SHA}/d.tar.gz"),
            format!("//evil.example/release/deadbolt/files/{SHA}/d.tar.gz"),
            format!("/release/hex/files/{SHA}/d.tar.gz"),
            "/release/deadbolt/files/../cli/dev.json".to_string(),
            format!("/release/deadbolt/files/{SHA}/d.tar.gz?x=1"),
        ] {
            assert!(file_url(&manifest, &bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn requirements_follow_the_apps() {
        assert!(APP_REQUIREMENT.contains("identifier \"pw.deadbolt.app\""));
        assert!(APP_REQUIREMENT.trim().ends_with(" and notarized"));
        let cli = requirement("pw.deadbolt.cli");
        assert!(cli.contains("identifier \"pw.deadbolt.cli\""), "{cli}");
        assert!(
            cli.contains("certificate leaf[subject.OU] = \"5NZ4Q7NXJ4\""),
            "{cli}"
        );
        assert!(
            !cli.contains("pw.deadbolt.app") && !cli.contains("notarized"),
            "{cli}"
        );
    }

    #[test]
    fn reads_extension_versions_and_guards_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let ext = dir.path().join("ext");
        assert!(!extension_dir_ok(Path::new("relative/ext")));
        assert!(extension_dir_ok(&ext));
        std::fs::create_dir(&ext).unwrap();
        assert!(extension_dir_ok(&ext));
        std::fs::write(
            ext.join("manifest.json"),
            r#"{"name":"Deadbolt","version":"0.0.0.11","version_name":"0.0.0-dev-11"}"#,
        )
        .unwrap();
        assert_eq!(extension_version(&ext).as_deref(), Some("0.0.0-dev-11"));
        assert_eq!(extension_build(&ext), None);
        for (permissions, build) in [
            (r#"["storage","nativeMessaging"]"#, ExtensionBuild::Native),
            (
                r#"["storage","offscreen","alarms"]"#,
                ExtensionBuild::Standalone,
            ),
        ] {
            let manifest = format!(r#"{{"version":"0.0.0.11","permissions":{permissions}}}"#);
            std::fs::write(ext.join("manifest.json"), manifest).unwrap();
            assert_eq!(extension_build(&ext), Some(build));
        }
        // Even a Deadbolt extension isn't replaced unless update put it there.
        assert!(!extension_dir_ok(&ext));
        std::fs::write(ext.join(EXTENSION_MARKER), "manifest.json\n").unwrap();
        assert!(extension_dir_ok(&ext));
        std::fs::write(ext.join("notes.txt"), "mine").unwrap();
        assert!(!extension_dir_ok(&ext));
    }

    fn zip_of(entries: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        for (name, link, body) in entries {
            match link {
                Some(target) => zip.add_symlink(*name, *target, options).unwrap(),
                None if name.ends_with('/') => zip.add_directory(*name, options).unwrap(),
                None => {
                    zip.start_file(*name, options).unwrap();
                    zip.write_all(body).unwrap();
                }
            }
        }
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn unpacks_extensions_without_links_or_bombs() {
        let dir = tempfile::tempdir().unwrap();
        let unpack = |name: &str, bytes: Vec<u8>| {
            let archive = dir.path().join(format!("{name}.zip"));
            std::fs::write(&archive, bytes).unwrap();
            let out = dir.path().join(name);
            unpack_extension(&archive, &out).map(|()| out)
        };
        let out = unpack(
            "good",
            zip_of(&[
                (
                    "manifest.json",
                    None,
                    br#"{"name":"Deadbolt","version":"1.0"}"#,
                ),
                ("icons/", None, b""),
                ("icons/a.png", None, b"png"),
            ]),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(out.join(EXTENSION_MARKER)).unwrap(),
            "icons\nmanifest.json\n"
        );
        assert!(extension_dir_ok(&out));
        assert!(unpack("link", zip_of(&[("evil", Some("/etc/passwd"), b"")])).is_err());
        assert!(unpack("marker", zip_of(&[(EXTENSION_MARKER, None, b"x")])).is_err());
        let big = vec![0u8; usize::try_from(EXTENSION_LIMIT).unwrap() + 1];
        assert!(unpack("bomb", zip_of(&[("big.bin", None, &big)])).is_err());
    }

    #[test]
    fn checks_app_zips_for_escaping_links() {
        let dir = tempfile::tempdir().unwrap();
        let check = |bytes: Vec<u8>| {
            let archive = dir.path().join("app.zip");
            std::fs::write(&archive, bytes).unwrap();
            check_app_zip(&archive)
        };
        let framework = "Deadbolt.app/Contents/Frameworks/F.framework";
        check(zip_of(&[
            ("Deadbolt.app/Contents/Helpers/deadbolt", None, b"bin"),
            (&format!("{framework}/Versions/A/F"), None, b"lib"),
            (&format!("{framework}/Versions/Current"), Some("A"), b""),
            (&format!("{framework}/F"), Some("Versions/Current/F"), b""),
            ("__MACOSX/Deadbolt.app/._x", None, b"fork"),
        ]))
        .unwrap();
        for bad in [
            zip_of(&[("Other.app/x", None, b"")]),
            zip_of(&[("Deadbolt.app/etc", Some("/etc"), b"")]),
            zip_of(&[("Deadbolt.app/up", Some("../../x"), b"")]),
            zip_of(&[("Deadbolt.app/up", Some("../Other.app"), b"")]),
            zip_of(&[
                ("Deadbolt.app/d", Some("Contents"), b""),
                ("Deadbolt.app/d/x", None, b"through the link"),
            ]),
        ] {
            assert!(check(bad).is_err());
        }
        assert!(link_inside(
            Path::new("Deadbolt.app/a/b"),
            Path::new("../../c")
        ));
        assert!(!link_inside(
            Path::new("Deadbolt.app/a"),
            Path::new("../../c")
        ));
    }

    #[test]
    fn signature_checks_are_decided_by_the_build_and_fail_closed() {
        assert!(signature_required(true, Some("dev")));
        assert!(signature_required(true, Some("stable")));
        assert!(!signature_required(true, None));
        assert!(!signature_required(false, Some("stable")));
        // codesign that can't run is an error, never "unsigned".
        let exe = std::env::current_exe().unwrap();
        assert!(satisfies("/nonexistent/codesign", &exe, "anchor apple", false).is_err());
        if cfg!(target_os = "macos") {
            // This test binary is signed ad hoc, not by Deadbolt's Developer ID.
            assert!(!satisfies(CODESIGN, &exe, &requirement("pw.deadbolt.cli"), false).unwrap());
        }
    }

    #[test]
    fn root_updates_only_root_owned_installs() {
        assert!(root_may_update(501, Some(501), Some(501)));
        assert!(root_may_update(0, Some(0), Some(0)));
        assert!(!root_may_update(0, Some(501), Some(0)));
        assert!(!root_may_update(0, Some(0), Some(501)));
        assert!(!root_may_update(0, None, Some(0)));
    }

    #[test]
    fn unreadable_sequence_state_is_not_a_fresh_install() {
        let dir = tempfile::tempdir().unwrap();
        let state = UpdateState::open(dir.path()).unwrap();
        let path = dir.path().join("release-sequences.json");
        for invalid in [
            b"not json".as_slice(),
            b"{\"cli/dev\":\"7\"}",
            b" ",
            b"{\"cli/dev\":7",
        ] {
            std::fs::write(&path, invalid).unwrap();
            for allow in [false, true] {
                let error = check_sequence(&state, "cli", "stable", &manifest(100, false), allow)
                    .unwrap_err();
                let message = format!("{error:#}");
                assert!(message.contains(path.to_str().unwrap()), "{message}");
                assert!(message.contains("trusted backup"), "{message}");
                assert!(
                    message.contains("loses all remembered replay floors"),
                    "{message}"
                );
                assert_eq!(std::fs::read(&path).unwrap(), invalid);
            }
        }
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let zero = manifest(100, false).replace("\"sequence\":7", "\"sequence\":0");
        let error = check_sequence(&state, "cli", "stable", &zero, false).unwrap_err();
        assert!(format!("{error:#}").contains("trusted backup"));
        assert!(path.is_dir());
    }

    #[test]
    fn empty_sequence_state_initializes_like_missing_state() {
        for allow in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let state = UpdateState::open(dir.path()).unwrap();
            let path = dir.path().join("release-sequences.json");
            std::fs::write(&path, "").unwrap();
            let zero = manifest(100, false).replace("\"sequence\":7", "\"sequence\":0");
            check_sequence(&state, "cli", "stable", &zero, allow).unwrap();
            check_sequence(&state, "cli", "stable", &manifest(100, false), allow).unwrap();
            let seen: BTreeMap<String, u64> =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(seen, BTreeMap::from([("cli/stable".into(), 7)]));
            assert!(check_sequence(&state, "cli", "stable", &zero, false).is_err());
        }
    }

    #[test]
    fn sequence_state_stays_locked_until_the_update_finishes() {
        let dir = tempfile::tempdir().unwrap();
        let state = UpdateState::open(dir.path()).unwrap();
        assert!(UpdateState::open(dir.path()).is_err());
        check_sequence(&state, "cli", "stable", &manifest(100, false), false).unwrap();
        // Atomic replacement of the state file must not release the lock.
        assert!(UpdateState::open(dir.path()).is_err());
        // A concurrent process launch can inherit this open file description
        // until exec closes its CLOEXEC descriptor. Hold a duplicate to model
        // that window deterministically, without a fork or timing assumptions.
        let inherited = state.lock.try_clone().unwrap();
        drop(state);
        let state = UpdateState::open(dir.path()).unwrap();
        assert!(UpdateState::open(dir.path()).is_err());
        drop(inherited);
        assert!(UpdateState::open(dir.path()).is_err());
        let older = manifest(100, false).replace("\"sequence\":7", "\"sequence\":6");
        assert!(check_sequence(&state, "cli", "stable", &older, false).is_err());
    }

    #[test]
    fn rejected_manifests_leave_sequence_state_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let state = UpdateState::open(dir.path()).unwrap();
        let good = manifest(100, false);
        check_sequence(&state, "cli", "stable", &good, false).unwrap();
        let path = dir.path().join("release-sequences.json");
        let original = std::fs::read(&path).unwrap();
        let high = good.replace("\"sequence\":7", "\"sequence\":999");
        for invalid in [
            high.replace("\"cli\"", "\"extension\""),
            high.replace("\"stable\"", "\"dev\""),
            high.replace("\"deadbolt\"", "\"other\""),
            high.replace("\"schema\":1", "\"schema\":2"),
            "not json".to_string(),
        ] {
            for allow in [false, true] {
                assert!(check_sequence(&state, "cli", "stable", &invalid, allow).is_err());
                assert_eq!(std::fs::read(&path).unwrap(), original);
            }
        }
    }

    #[test]
    fn refuses_older_manifests_unless_asked() {
        let dir = tempfile::tempdir().unwrap();
        let state = UpdateState::open(&dir.path().join("state")).unwrap();
        let check = |artifact: &str, channel: &str, sequence: u64, allow| {
            let mut text: serde_json::Value = serde_json::from_str(&manifest(100, false)).unwrap();
            text["artifact"] = artifact.into();
            text["channel"] = channel.into();
            text["sequence"] = sequence.into();
            check_sequence(&state, artifact, channel, &text.to_string(), allow)
        };
        check("cli", "dev", 0, false).unwrap();
        check("cli", "dev", 5, false).unwrap();
        check("cli", "dev", 5, false).unwrap();
        check("cli", "dev", 7, false).unwrap();
        assert!(check("cli", "dev", 6, false).is_err());
        // Each artifact and channel is its own.
        check("cli", "stable", 1, false).unwrap();
        check("extension", "dev", 1, false).unwrap();
        check("cli", "dev", 6, true).unwrap();
        assert!(check("cli", "dev", 6, false).is_err());
        let seen: BTreeMap<String, u64> = serde_json::from_slice(
            &std::fs::read(state.dir.join("release-sequences.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            seen,
            BTreeMap::from([
                ("cli/dev".into(), 7),
                ("cli/stable".into(), 1),
                ("extension/dev".into(), 1),
            ])
        );
    }

    #[test]
    fn a_failed_swap_puts_every_old_file_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name);
        for (name, body) in [
            ("deadbolt", "old cli"),
            ("deadbolt-enclave", "old helper"),
            ("new-enclave", "new helper"),
        ] {
            std::fs::write(path(name), body).unwrap();
        }
        // The helper goes in, then the new deadbolt is missing.
        let files = [
            (path("new-enclave"), path("deadbolt-enclave")),
            (path("new-deadbolt"), path("deadbolt")),
        ];
        assert!(swap(&files, &path("aside")).is_err());
        assert_eq!(
            std::fs::read_to_string(path("deadbolt")).unwrap(),
            "old cli"
        );
        assert_eq!(
            std::fs::read_to_string(path("deadbolt-enclave")).unwrap(),
            "old helper"
        );
        // A file that wasn't there before isn't left behind either.
        let files = [
            (path("new-enclave"), path("fresh")),
            (path("new-deadbolt"), path("deadbolt")),
        ];
        std::fs::write(path("new-enclave"), "new helper").ok();
        assert!(swap(&files, &path("aside2")).is_err());
        assert!(!path("fresh").exists());
        assert_eq!(
            std::fs::read_to_string(path("deadbolt")).unwrap(),
            "old cli"
        );
        // And a good swap replaces both.
        std::fs::write(path("new-enclave"), "new helper").unwrap();
        std::fs::write(path("new-deadbolt"), "new cli").unwrap();
        let files = [
            (path("new-enclave"), path("deadbolt-enclave")),
            (path("new-deadbolt"), path("deadbolt")),
        ];
        swap(&files, &path("aside3")).unwrap();
        assert_eq!(
            std::fs::read_to_string(path("deadbolt")).unwrap(),
            "new cli"
        );
        assert_eq!(
            std::fs::read_to_string(path("deadbolt-enclave")).unwrap(),
            "new helper"
        );
    }

    #[test]
    fn unpacks_only_the_cli_from_its_tarball() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("deadbolt"), "cli").unwrap();
        std::fs::write(src.join("deadbolt-enclave"), "helper").unwrap();
        std::fs::write(src.join("README"), "other").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.join("link")).unwrap();
        let tar = |name: &str, files: &[&str]| {
            let archive = dir.path().join(name);
            let status = Command::new("tar")
                .arg("-czf")
                .arg(&archive)
                .arg("-C")
                .arg(&src)
                .args(files)
                .status()
                .unwrap();
            assert!(status.success());
            let out = dir.path().join(format!("{name}.out"));
            std::fs::create_dir(&out).unwrap();
            unpack_cli(&archive, &out).map(|_| out)
        };
        let out = tar("good.tar.gz", &["./deadbolt", "deadbolt-enclave", "README"]).unwrap();
        let mut names: Vec<_> = std::fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["deadbolt", "deadbolt-enclave"]);
        assert_eq!(
            std::fs::read_to_string(out.join("deadbolt")).unwrap(),
            "cli"
        );
        let error = tar("link.tar.gz", &["deadbolt", "link"]).unwrap_err();
        assert!(format!("{error:#}").contains("link"), "{error:#}");
        let long = "a".repeat(150);
        std::fs::write(src.join(&long), "long").unwrap();
        tar("long.tar.gz", &[&long, "deadbolt"]).unwrap();
        assert!(pax_path(b"19 path=deadbolt-x\n").is_some_and(|p| p == "deadbolt-x"));
    }
}
