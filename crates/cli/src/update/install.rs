//! Running `deadbolt update`: which release this install follows, whether the
//! daemon should announce one, and running the install's own manager to put
//! it in place.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Args;
use url::Url;

use super::extension::extension;
use super::method::{
    Install, Manager, Upgrade, find_program, installed_with, method, method_key, package_of,
    upgrade_command,
};
use super::protocol::{
    Decision, Reason, Running, VERSION, build_channel, decide, rollout_bucket, target, validated,
};
use super::replace::{refuse_foreign_root, update_app, update_cli};
use super::report::build_report;
use super::service::{Manifest, Service};
use super::state::{UpdateState, check_sequence, read_floors};
use crate::paths::Paths;
use crate::protocol::UpdateInfo;

/// `deadbolt update --check`'s exit code when an update is available.
const EXIT_AVAILABLE: u8 = 10;

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
    /// Print the result as JSON on stdout.
    #[arg(long)]
    json: bool,
}

/// For npm's package: npm, pnpm, bun and yarn install only what the
/// registry serves for the channel (`served`, `@deadbolt/cli`'s dist-tag),
/// which trails the release service by minutes, and the wrapper needs this
/// system's platform package at that version too (`platform`: that version
/// when the registry has it), which can trail the wrapper by minutes more.
/// Until both are the release the update is pending, so it's never offered
/// before the manager can install all of it.
pub(super) fn served_by_npm(
    decision: Decision,
    served: Option<&str>,
    platform: Option<&str>,
) -> Decision {
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
pub(super) fn platform_package(target: &str, static_libc: impl FnOnce() -> bool) -> String {
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
pub(super) fn static_for(ldd: &str) -> bool {
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

/// The channel's manifest and what the client rules say to do with it.
pub(super) struct Found {
    url: Url,
    text: String,
    etag: Option<String>,
    decision: Decision,
}

/// A manifest read for `find`: unchanged since the caller's `ETag`, or
/// the channel's manifest and its decision.
pub(super) enum Fetched {
    Unchanged,
    Read(Box<Found>),
}

/// The channel's manifest for `artifact` and what to do about it, `None`
/// when the channel has none: [`decide`], then for npm's package
/// [`served_by_npm`], for the platform package this system installs
/// ([`platform_package`]). Sends `etag` as `If-None-Match` when known.
pub(super) async fn find(
    service: &Service,
    install: &Install,
    artifact: &str,
    channel: &str,
    running: &Running<'_>,
    etag: Option<&str>,
) -> Result<Option<Fetched>> {
    let Some(manifest) = service.manifest(artifact, channel, etag).await? else {
        return Ok(None);
    };
    let Manifest::Found(manifest) = manifest else {
        return Ok(Some(Fetched::Unchanged));
    };
    let (url, text, etag) = (manifest.url, manifest.text, manifest.etag);
    let mut decision = decide(artifact, channel, &text, running);
    if let Install::Managed(manager) = install
        && manager.npm()
        && matches!(decision, Decision::Notify { .. })
    {
        if let Some(version) = npm_from_release(artifact, channel, &text) {
            // Release is the source of truth: no registry request, and the
            // platform package is released with it.
            decision = served_by_npm(decision, Some(&version), Some(&version));
        } else {
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
    }
    Ok(Some(Fetched::Read(Box::new(Found {
        url,
        text,
        etag,
        decision,
    }))))
}

/// The version the manifest lists for npm, if it lists one: Release is the
/// source of truth, and the registry is only asked for releases that
/// don't carry it yet.
pub(super) fn npm_from_release(artifact: &str, channel: &str, text: &str) -> Option<String> {
    validated(artifact, channel, text)
        .ok()?
        .npm_version()
        .map(str::to_string)
}

/// The last `ETag` seen for each `<artifact>/<channel>` manifest, kept
/// by the daemon between polls so an unchanged manifest costs a 304.
pub type Etags = BTreeMap<String, String>;

/// What a background check found. `Unchanged` is a `304 Not Modified`:
/// the manifest is the one the caller last saw, so the answer stands.
#[derive(Debug, PartialEq, Eq)]
pub enum Checked {
    Unchanged,
    Found(Option<UpdateInfo>),
}

/// The daemon's background check: whether this install has an update on
/// `channel` that `deadbolt update` would install (the release service's
/// rules, npm's version for npm's package, Homebrew's for Homebrew). It
/// never downloads or installs anything, nor writes the sequence floors
/// `update` keeps, but it ignores a manifest older than them. `Found(None)`
/// for installs it can't update (Nix, Cargo and system packages, and an app
/// that can't be replaced where it is) and for no update. `etags` carries
/// each manifest's `ETag` between polls.
pub async fn available(paths: &Paths, channel: &str, etags: &mut Etags) -> Result<Checked> {
    let exe = crate::app::this_binary()?;
    let install = method(&exe).await;
    if matches!(
        install,
        Install::Unmovable(_) | Install::Managed(Manager::Nix | Manager::Cargo | Manager::System)
    ) {
        return Ok(Checked::Found(None));
    }
    let (artifact, _, distribution) = artifact_of(&install)?;
    let key = format!("{artifact}/{channel}");
    let state = state_dir(paths);
    let target = target()?;
    let running = Running {
        version: VERSION,
        target: &target,
        distribution,
        bucket: rollout_bucket(&state),
        sha256: None,
        channel: Some(channel),
    };
    let service = Service::new(Some(channel))?;
    let found = etags.get(&key).map(String::as_str);
    let Some(fetched) = find(&service, &install, artifact, channel, &running, found).await? else {
        etags.remove(&key);
        return Ok(Checked::Found(None));
    };
    let Fetched::Read(found) = fetched else {
        return Ok(Checked::Unchanged);
    };
    let Found {
        url,
        text,
        etag,
        decision,
    } = *found;
    match etag {
        Some(etag) => {
            etags.insert(key, etag);
        }
        None => {
            etags.remove(&key);
        }
    }
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
    Ok(Checked::Found(match decision {
        Decision::Reject(reason) => bail!("{url} is not a usable {artifact} manifest ({reason})"),
        Decision::Install { version, .. } | Decision::Notify { version, .. } => Some(UpdateInfo {
            version,
            method: method_key(&install).into(),
        }),
        Decision::None(_) => None,
    }))
}

/// The state directory: the log's.
pub(super) fn state_dir(paths: &Paths) -> PathBuf {
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
        sha256: None,
        channel: built,
    };
    let Some(fetched) = find(&service, &install, artifact, channel, &running, None).await? else {
        bail!("there is no {channel} release of {what} yet");
    };
    let Fetched::Read(found) = fetched else {
        bail!("the service answered 304 to a manifest request without an ETag");
    };
    let Found {
        url,
        text,
        decision,
        ..
    } = *found;
    if let Decision::Reject(reason) = decision {
        bail!("{url} is not a usable {artifact} manifest ({reason})");
    }
    check_sequence(&state, artifact, channel, &text, args.allow_rollback)?;
    let manifest_version = validated(artifact, channel, &text)
        .map(|m| m.release_version().to_string())
        .unwrap_or_default();
    let quiet = args.json;
    let mut available = false;
    match &decision {
        Decision::Reject(reason) => bail!("{url} is not a usable {artifact} manifest ({reason})"),
        Decision::None("up_to_date") if !quiet => {
            println!("{what} {shown} is up to date on {channel} ({how})");
            if let Install::Managed(manager) = &install
                && upgrade_command(*manager, "").is_none()
            {
                println!("{} updates it: {}", manager.name(), manager.hint(channel));
            }
        }
        Decision::None("rollout_deferred") if !quiet => println!(
            "{what} {shown}: a new {channel} release is rolling out and hasn't reached this \
             computer yet; try again later"
        ),
        Decision::None("distribution_pending" | "distribution_unlisted") if !quiet => {
            let manager = match &install {
                Install::Managed(manager) => manager.name(),
                _ => "its package manager",
            };
            println!(
                "{what} {shown} is {manager}'s to update, and {manager} doesn't offer \
                 {channel}'s current release yet; try again later"
            )
        }
        Decision::None(
            "up_to_date" | "rollout_deferred" | "distribution_pending" | "distribution_unlisted",
        ) => {}
        Decision::None(reason) => bail!("{channel} has no {what} for {target} ({reason})"),
        Decision::Notify {
            reason,
            version,
            command,
            notes_url,
            ..
        } => {
            let Install::Managed(manager) = install else {
                bail!("unexpected decision for {what}");
            };
            available = true;
            if !quiet {
                println!("{what} {version} is available on {channel} (this is {shown}, {how})");
                if let Some(notes) = notes_url {
                    println!("Release notes: {notes}");
                }
            }
            match upgrade_command(manager, version) {
                Some(upgrade) if args.check => {
                    if !quiet {
                        println!("deadbolt update runs: {}", upgrade.shown);
                    }
                }
                Some(upgrade) => {
                    if *reason == Reason::Switch {
                        confirm_switch(
                            built.unwrap_or("source"),
                            channel,
                            version,
                            args.yes,
                            quiet,
                        )?;
                    } else {
                        confirm_upgrade(&upgrade.shown, args.yes, quiet)?;
                    }
                    update_package(paths, manager, &upgrade, &exe, version, quiet).await?;
                }
                None if !quiet => match (manager, command) {
                    (Manager::Package, _) | (_, None) => {
                        println!("To update: {}", manager.hint(channel))
                    }
                    (_, Some(command)) => println!("Update it with: {command}"),
                },
                None => {}
            }
        }
        Decision::Install {
            reason,
            version,
            target,
        } => {
            available = true;
            if args.check {
                if !quiet {
                    match reason {
                        Reason::Switch => {
                            println!("{what} {version} is on {channel} (this is {shown})");
                        }
                        _ => {
                            println!("{what} {version} is available on {channel} (this is {shown})")
                        }
                    }
                }
            } else {
                if *reason == Reason::Switch {
                    confirm_switch(built.unwrap_or("source"), channel, version, args.yes, quiet)?;
                }
                if !quiet {
                    println!("Updating {what} {shown} to {version} ({channel})...");
                }
                match &install {
                    Install::App(bundle) => {
                        refuse_foreign_root(bundle.parent().unwrap_or(bundle))?;
                        update_app(paths, &service, &url, target, bundle, version, quiet).await?;
                    }
                    Install::Standalone(dir) => {
                        refuse_foreign_root(dir)?;
                        let macos = cfg!(target_os = "macos");
                        update_cli(
                            paths, &service, &url, target, &exe, dir, built, macos, quiet,
                        )
                        .await?;
                    }
                    _ => bail!("unexpected install for {what}"),
                }
            }
        }
    }
    let extensions = crate::config::Config::load(&paths.config)?.extensions;
    let ext_available = extension(
        &extensions,
        &service,
        &state,
        channel,
        bucket,
        built,
        args.check,
        args.allow_rollback,
        quiet,
    )
    .await?;
    available |= ext_available;
    if args.json {
        let report = build_report(
            VERSION,
            &manifest_version,
            channel,
            &install,
            &decision,
            args.check,
            ext_available,
        );
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(if args.check && available {
        ExitCode::from(EXIT_AVAILABLE)
    } else {
        ExitCode::SUCCESS
    })
}

/// Running a package manager is asked on a terminal, unless `--yes` or `--json`.
fn confirm_upgrade(command: &str, yes: bool, json: bool) -> Result<()> {
    if yes || json || !crate::prompt::interactive() {
        return Ok(());
    }
    if !crate::prompt::confirm(&format!("Run {command}?"))? {
        bail!("cancelled");
    }
    Ok(())
}

/// The most of a failed manager's output shown.
pub(super) const OUTPUT_LINES: usize = 12;

/// The last [`OUTPUT_LINES`] non-empty lines of `text`, without terminal
/// escapes.
pub(super) fn output_tail(text: &str) -> String {
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
pub(super) fn upgrade_failure(
    who: &str,
    version: &str,
    detail: &str,
    shown: &str,
) -> anyhow::Error {
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
pub(super) fn user_link(manager: Manager, exe: &Path, wrapper: Option<&Path>) -> PathBuf {
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
    quiet: bool,
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
    if !quiet {
        println!("Running {}", upgrade.shown);
    }
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
        restart_daemon(paths, new, quiet).await;
    }
    if said.split_whitespace().nth(1) != Some(version) {
        bail!(
            "{who} ran, but {} --version says {:?}, not deadbolt {version}; run {} yourself",
            link.display(),
            said,
            upgrade.shown
        );
    }
    if !quiet {
        println!("Updated {} to {version} with {who}", link.display());
    }
    Ok(())
}

/// A channel switch is the user's choice: asked on a terminal, else `--yes`.
fn confirm_switch(from: &str, to: &str, version: &str, yes: bool, json: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if json || !crate::prompt::interactive() {
        bail!("this build is from {from}; pass --yes to switch to {to} {version}");
    }
    if !crate::prompt::confirm(&format!(
        "This build is from {from}. Switch to {to} {version}?"
    ))? {
        bail!("cancelled");
    }
    Ok(())
}

/// Whether the daemon that runs is this `program`, so replacing it should
/// replace the daemon too.
pub(super) async fn daemon_runs(paths: &Paths, program: impl Fn(&Path) -> bool) -> bool {
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
pub(super) async fn restart_daemon(paths: &Paths, program: PathBuf, quiet: bool) {
    let launch = deadbolt_client::Launch { program };
    match deadbolt_client::start(paths, &launch).await {
        Ok(_) if quiet => {}
        Ok(_) if crate::disk::is_initialized(&paths.data) => {
            println!("Restarted the daemon; the vault is locked until you unlock it.");
        }
        Ok(_) => println!("Restarted the daemon."),
        Err(error) => eprintln!("warning: couldn't restart the daemon: {error}"),
    }
}

/// Stops the daemon before its files are replaced; a failure is a warning.
pub(super) async fn stop_daemon(paths: &Paths) -> bool {
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
