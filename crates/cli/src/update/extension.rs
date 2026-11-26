//! The unpacked browser extension `deadbolt update` keeps current, for the
//! directories registered with `deadbolt browser install --extension-dir`.

use std::path::Path;

use anyhow::{Context, Result, bail};
use url::Url;

use super::protocol::{Decision, Running, Target, decide};
use super::replace::{refuse_foreign_root, stage_beside};
use super::service::{Manifest, SERVICE, Service};
use super::state::{UpdateState, check_sequence};
use crate::config::ExtensionDir;

/// The release service target of the `extension` artifact.
const TARGET: &str = "chromium";

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

/// Checks, and unless `check` updates, the extension directories `dirs`
/// (registered with `deadbolt browser install --extension-dir`). True when
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
    quiet: bool,
) -> Result<bool> {
    if dirs.is_empty() {
        if !check && !quiet {
            println!(
                "Browser extension: {SERVICE}deadbolt/extension/{channel}/{} (or register \
                 an unpacked copy with `deadbolt browser install --extension-dir <dir>` to \
                 update it here)",
                TARGET
            );
        }
        return Ok(false);
    }
    let Some(manifest) = service.manifest("extension", channel, None).await? else {
        if !quiet {
            println!("Browser extension: no {channel} release yet");
        }
        return Ok(false);
    };
    let Manifest::Found(manifest) = manifest else {
        bail!("the service answered 304 to a manifest request without an ETag");
    };
    let (url, text) = (manifest.url, manifest.text);
    check_sequence(state, "extension", channel, &text, allow_rollback)?;
    let mut available = false;
    let mut failed = None;
    for entry in dirs {
        match extension_dir(
            entry, service, &url, &text, channel, bucket, built, check, quiet,
        )
        .await
        {
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
    quiet: bool,
) -> Result<bool> {
    let dir = &entry.dir;
    if !extension_dir_ok(dir) {
        bail!(
            "{} holds files deadbolt didn't install there (or isn't an absolute path); \
             register an empty directory with `deadbolt browser install --extension-dir <dir>`",
            dir.display()
        );
    }
    let current = extension_version(dir).unwrap_or_default();
    let running = Running {
        version: &current,
        target: TARGET,
        distribution: "direct",
        bucket,
        sha256: None,
        channel: built,
    };
    let decision = decide("extension", channel, text, &running);
    if let Decision::Reject(reason) = decision {
        bail!("{url} is not a usable extension manifest ({reason})");
    }
    match decision {
        Decision::Install {
            version, target, ..
        } => {
            if check {
                if !quiet {
                    println!(
                        "Browser extension {version} is available in {}",
                        dir.display()
                    );
                }
            } else {
                refuse_foreign_root(dir.parent().unwrap_or(dir))?;
                update_extension(service, url, &target, dir).await?;
                if !quiet {
                    println!(
                        "Updated the browser extension in {} to {version}; \
                         reload Deadbolt in chrome://extensions",
                        dir.display()
                    );
                }
            }
            Ok(true)
        }
        Decision::None("up_to_date") => {
            if !quiet {
                println!(
                    "Browser extension {current} is up to date in {}",
                    dir.display()
                );
            }
            Ok(false)
        }
        Decision::None("no_target") => {
            if !quiet {
                println!("The {channel} release has no browser extension yet");
            }
            Ok(false)
        }
        _ => Ok(false),
    }
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
