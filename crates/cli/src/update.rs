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
}

impl Manager {
    /// The release service's distribution kind.
    fn distribution(self) -> &'static str {
        match self {
            Self::Brew | Self::BrewCask => "brew",
            Self::Nix | Self::Cargo | Self::System => "unknown",
        }
    }

    /// What to run when the manifest names no command.
    fn hint(self) -> &'static str {
        match self {
            Self::Brew => "brew upgrade anomalyco/tap/deadbolt",
            Self::BrewCask => "brew upgrade --cask anomalyco/tap/deadbolt",
            Self::Nix => "update it with Nix, which installed it",
            Self::Cargo => "reinstall it with cargo install, which installed it",
            Self::System => "update it with the package manager that installed it",
        }
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

/// The release service's name for this build's platform.
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
    Ok(format!("{os}-{arch}"))
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

/// Decides what to do with `text`, the manifest for `artifact` on
/// `channel`, for the install `running`. Versions are display text, only
/// ever tested for equality: an install updates whenever the channel's
/// current release isn't the build it runs.
pub fn decide(artifact: &str, channel: &str, text: &str, running: &Running) -> Decision {
    let Some(manifest) = parse(text) else {
        return Decision::Reject("malformed");
    };
    if manifest.app != "deadbolt" {
        return Decision::Reject("wrong_app");
    }
    if manifest.artifact != artifact {
        return Decision::Reject("wrong_artifact");
    }
    if manifest.channel != channel {
        return Decision::Reject("wrong_channel");
    }
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
    let bucket = rollout_bucket(&state);
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
    match decide(artifact, channel, &text, &running) {
        Decision::Reject(reason) => bail!("{url} is not a usable {artifact} manifest ({reason})"),
        Decision::None("up_to_date") => println!("{what} {shown} is up to date on {channel}"),
        Decision::None("rollout_deferred") => println!(
            "{what} {shown}: a new {channel} release is rolling out and hasn't reached this \
             computer yet; try again later"
        ),
        Decision::None("distribution_pending" | "distribution_unlisted") => println!(
            "{what} {shown} is Homebrew's to update, and Homebrew doesn't offer {channel}'s \
             current release yet; try again later"
        ),
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
                None => println!("To update: {}", manager.hint()),
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
                        update_app(paths, &service, &url, &target, bundle, &version).await?;
                    }
                    Install::Standalone(dir) => {
                        update_cli(paths, &service, &url, &target, &exe, dir).await?;
                    }
                    _ => bail!("unexpected install for {what}"),
                }
            }
        }
    }
    available |= extension(paths, &service, channel, bucket, built, args.check).await?;
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

/// Whether `path` satisfies `requirement` (`codesign --verify --strict`).
fn satisfies(path: &Path, requirement: &str, deep: bool) -> bool {
    let mut command = Command::new("codesign");
    command.args(["--verify", "--strict", "--all-architectures"]);
    if deep {
        command.arg("--deep");
    }
    command
        .arg(format!("-R={requirement}"))
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
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

/// Replaces the standalone `exe` (and `deadbolt-enclave` beside it) with the
/// release's tarball.
async fn update_cli(
    paths: &Paths,
    service: &Service,
    manifest: &Url,
    target: &Target,
    exe: &Path,
    dir: &Path,
) -> Result<()> {
    let stage = stage_beside(exe)?;
    let archive = stage.path().join("deadbolt.tar.gz");
    service.download(manifest, target, &archive).await?;
    let unpacked = stage.path().join("unpacked");
    std::fs::create_dir(&unpacked)?;
    run_tool(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&unpacked),
        "tar",
    )?;
    let regular = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file());
    let new = unpacked.join("deadbolt");
    if !regular(&new) {
        bail!("the release has no deadbolt");
    }
    let enclave = unpacked.join("deadbolt-enclave");
    let enclave = regular(&enclave).then_some(enclave);
    // A Developer ID-signed deadbolt never gives way to one that isn't.
    if cfg!(target_os = "macos") && satisfies(exe, &requirement("pw.deadbolt.cli"), false) {
        if !satisfies(&new, &requirement("pw.deadbolt.cli"), false) {
            bail!("the new deadbolt is not signed by Deadbolt's Developer ID; nothing was changed");
        }
        if let Some(enclave) = &enclave
            && !satisfies(enclave, &requirement("pw.deadbolt.app.enclave"), false)
        {
            bail!(
                "the new deadbolt-enclave is not signed by Deadbolt's Developer ID; nothing was changed"
            );
        }
    }
    let ours = agent_runs(paths, |p| p == exe).await;
    for file in std::iter::once(&new).chain(&enclave) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o755))?;
    }
    // The helper first: the new deadbolt pins it, the old one checks before use.
    if let Some(enclave) = &enclave {
        let dest = dir.join("deadbolt-enclave");
        std::fs::rename(enclave, &dest).with_context(|| format!("replacing {}", dest.display()))?;
    }
    std::fs::rename(&new, exe).with_context(|| format!("replacing {}", exe.display()))?;
    println!("Updated {}", exe.display());
    if ours {
        if let Err(error) = crate::client::stop(paths).await {
            eprintln!("warning: couldn't stop the old agent: {error}; run `deadbolt agent stop`");
        } else {
            restart_agent(paths, exe.to_path_buf()).await;
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
    let unpacked = stage.path().join("unpacked");
    run_tool(
        Command::new("ditto")
            .args(["-x", "-k"])
            .arg(&archive)
            .arg(&unpacked),
        "ditto",
    )?;
    let new = unpacked.join("Deadbolt.app");
    if !new.join("Contents/Helpers/deadbolt").is_file() {
        bail!("the release has no Deadbolt.app");
    }
    let quarantined = Command::new("xattr")
        .args(["-p", "com.apple.quarantine"])
        .arg(&new)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !satisfies(&new, APP_REQUIREMENT.trim(), true) {
        bail!("the new Deadbolt.app is not signed and notarized as Deadbolt; nothing was changed");
    }
    run_tool(
        Command::new("spctl")
            .args(["--assess", "--type", "execute"])
            .arg(&new),
        "Gatekeeper's check of the new Deadbolt.app",
    )?;
    if quarantined {
        run_tool(
            Command::new("xattr")
                .args(["-dr", "com.apple.quarantine"])
                .arg(&new),
            "xattr",
        )?;
    }

    // Verified: stop the old app and its agent, then swap.
    let app_ran = quit_app();
    crate::client::stop(paths).await.ok();
    let old = stage.path().join("old.app");
    std::fs::rename(bundle, &old).with_context(|| format!("moving {} aside", bundle.display()))?;
    if let Err(error) = std::fs::rename(&new, bundle) {
        std::fs::rename(&old, bundle).ok();
        return Err(error).with_context(|| format!("installing {}", bundle.display()));
    }
    let trashed = trash(&old, &format!("Deadbolt-{VERSION}"));
    println!("Updated {} to {version}", bundle.display());
    match trashed {
        Some(path) => println!("The old app is in the Trash: {}", path.display()),
        None => {
            std::fs::remove_dir_all(&old).ok();
        }
    }
    restart_agent(paths, bundle.join("Contents/Helpers/deadbolt")).await;
    if app_ran {
        Command::new("open").arg(bundle).status().ok();
    }
    Ok(())
}

/// Quits Deadbolt.app if it runs (best effort), and says whether it did.
fn quit_app() -> bool {
    let running = Command::new("osascript")
        .args(["-e", "application id \"pw.deadbolt.app\" is running"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "true");
    if running {
        Command::new("osascript")
            .args(["-e", "tell application id \"pw.deadbolt.app\" to quit"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok();
    }
    running
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

/// The version an unpacked extension says it is: `version_name`, else
/// `version`.
fn extension_version(dir: &Path) -> Option<String> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).ok()?).ok()?;
    let field = |key: &str| manifest.get(key)?.as_str().map(str::to_string);
    field("version_name").or_else(|| field("version"))
}

/// Whether `dir` may be replaced by Deadbolt's extension: absent, empty, or
/// already an unpacked Deadbolt extension.
pub fn extension_dir_ok(dir: &Path) -> bool {
    match std::fs::read_dir(dir) {
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        Ok(mut entries) => {
            entries.next().is_none()
                || std::fs::read(dir.join("manifest.json"))
                    .ok()
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                    .is_some_and(|m| m.get("name").and_then(|n| n.as_str()) == Some("Deadbolt"))
        }
    }
}

/// Checks, and unless `check` updates, the extension directory registered
/// with `deadbolt browser install --extension-dir`. True when an update is
/// available.
async fn extension(
    paths: &Paths,
    service: &Service,
    channel: &str,
    bucket: u8,
    built: Option<&str>,
    check: bool,
) -> Result<bool> {
    let link = format!("{SERVICE}deadbolt/extension/{channel}/chromium");
    let Some(dir) = crate::config::Config::load(&paths.config)?.extension_dir else {
        if !check {
            println!(
                "Browser extension: {link} (or register an unpacked copy with \
                 `deadbolt browser install --extension-dir <dir>` to update it here)"
            );
        }
        return Ok(false);
    };
    if !extension_dir_ok(&dir) {
        bail!(
            "{} is not an unpacked Deadbolt extension; register another with \
             `deadbolt browser install --extension-dir <dir>`",
            dir.display()
        );
    }
    let current = extension_version(&dir).unwrap_or_default();
    let running = Running {
        version: &current,
        target: "chromium",
        distribution: "direct",
        bucket,
        channel: built,
    };
    let Some((url, text)) = service.manifest("extension", channel).await? else {
        println!("Browser extension: no {channel} release yet");
        return Ok(false);
    };
    match decide("extension", channel, &text, &running) {
        Decision::Install {
            version, target, ..
        } => {
            if check {
                println!(
                    "Browser extension {version} is available in {}",
                    dir.display()
                );
            } else {
                update_extension(service, &url, &target, &dir).await?;
                println!(
                    "Updated the browser extension in {} to {version}; \
                     reload Deadbolt in chrome://extensions",
                    dir.display()
                );
            }
            Ok(true)
        }
        Decision::None("up_to_date") => {
            println!("Browser extension {current} is up to date");
            Ok(false)
        }
        Decision::None(_) => Ok(false),
        Decision::Reject(reason) => bail!("{url} is not a usable extension manifest ({reason})"),
        Decision::Notify { .. } => Ok(false),
    }
}

/// Replaces `dir`'s contents with the release's extension zip.
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
    let file = std::fs::File::open(&archive)?;
    zip::ZipArchive::new(file)
        .and_then(|mut zip| zip.extract(&new))
        .context("unpacking the extension")?;
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
        assert!(extension_dir_ok(&ext));
        std::fs::create_dir(&ext).unwrap();
        assert!(extension_dir_ok(&ext));
        std::fs::write(ext.join("notes.txt"), "mine").unwrap();
        assert!(!extension_dir_ok(&ext));
        std::fs::write(
            ext.join("manifest.json"),
            r#"{"name":"Deadbolt","version":"0.0.0.11","version_name":"0.0.0-dev-11"}"#,
        )
        .unwrap();
        assert!(extension_dir_ok(&ext));
        assert_eq!(extension_version(&ext).as_deref(), Some("0.0.0-dev-11"));
        std::fs::write(
            ext.join("manifest.json"),
            r#"{"name":"Other","version":"1.2.3"}"#,
        )
        .unwrap();
        assert!(!extension_dir_ok(&ext));
        assert_eq!(extension_version(&ext).as_deref(), Some("1.2.3"));
    }
}
