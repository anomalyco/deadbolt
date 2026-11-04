//! The unpacked browser extension `deadbolt update` keeps current, for the
//! directories registered with `deadbolt browser install --extension-dir`.

use std::path::Path;

use anyhow::{Context, Result, bail};
use url::Url;

use super::install::{UpdateState, check_sequence};
use super::protocol::{Decision, Running, Target, build_channel, decide, rollout_bucket};
use super::replace::{refuse_foreign_root, stage_beside};
use super::service::{SERVICE, Service};
use crate::config::{ExtensionBuild, ExtensionDir};
use crate::paths::Paths;

/// Written into an extension directory `deadbolt update` installed, listing
/// what it put there, so it only ever replaces its own files.
pub(super) const EXTENSION_MARKER: &str = ".deadbolt-extension";
/// The most an extension zip may unpack to, and its most entries.
pub(super) const EXTENSION_LIMIT: u64 = 64 << 20;
pub(super) const EXTENSION_ENTRIES: usize = 4096;

/// The version an unpacked extension says it is: `version_name`, else
/// `version`.
pub(super) fn extension_version(dir: &Path) -> Option<String> {
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
pub(super) fn unpack_extension(archive: &Path, out: &Path) -> Result<()> {
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
pub(super) fn extension_build(dir: &Path) -> Option<ExtensionBuild> {
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
pub(super) async fn extension(
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
pub(super) async fn extension_dir(
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
pub(super) async fn update_extension(
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
