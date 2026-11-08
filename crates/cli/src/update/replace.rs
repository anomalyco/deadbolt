//! Replacing what is installed: staging a download beside its destination,
//! checking its signature, unpacking it and moving it into place.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use url::Url;

use super::APP_REQUIREMENT;
use super::install::{daemon_runs, restart_daemon, stop_daemon};
use super::protocol::{Target, VERSION};
use super::service::Service;
use crate::paths::Paths;

/// A directory beside `dest` to stage its replacement in, on the same
/// volume so it can be renamed into place.
pub(super) fn stage_beside(dest: &Path) -> Result<tempfile::TempDir> {
    let dir = dest.parent().context("no directory to update in")?;
    tempfile::Builder::new()
        .prefix(".deadbolt-update-")
        .tempdir_in(dir)
        .with_context(|| format!("can't write to {}", dir.display()))
}

/// The code-signing requirement for Deadbolt's `identifier`, from the app's
/// update requirement without `notarized` (bare executables are notarized
/// but can't be stapled, so only the app's ticket can be checked offline).
pub(super) fn requirement(identifier: &str) -> String {
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
pub(super) const CODESIGN: &str = "/usr/bin/codesign";
const SPCTL: &str = "/usr/sbin/spctl";
const DITTO: &str = "/usr/bin/ditto";
const XATTR: &str = "/usr/bin/xattr";
const OSASCRIPT: &str = "/usr/bin/osascript";
const OPEN: &str = "/usr/bin/open";

/// Whether a standalone `deadbolt`'s replacement must be signed with
/// Deadbolt's Developer ID: always for a release build (one published on a
/// channel) on macOS, decided when it was built, never by what's on disk.
/// Builds from source rely on the checksum alone.
pub(super) fn signature_required(macos: bool, built: Option<&str>) -> bool {
    macos && built.is_some()
}

/// Whether `path` satisfies `requirement` (`codesign --verify --strict`,
/// with `tool` as codesign). An error if codesign can't run: that is never
/// read as "not signed".
pub(super) fn satisfies(tool: &str, path: &Path, requirement: &str, deep: bool) -> Result<bool> {
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
pub(super) fn root_may_update(euid: u32, dir_owner: Option<u32>, home_owner: Option<u32>) -> bool {
    euid != 0 || (dir_owner == Some(0) && home_owner == Some(0))
}

pub(super) fn refuse_foreign_root(dir: &Path) -> Result<()> {
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

/// Moves each `(new, dest)` into place, first moving every existing `dest`
/// into `aside`. On any failure every `dest` gets its old file back (or
/// none, if it had none), so the pair never ends half replaced.
pub(super) fn swap(files: &[(PathBuf, PathBuf)], aside: &Path) -> Result<()> {
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
pub(super) fn unpack_cli(archive: &Path, out: &Path) -> Result<Vec<PathBuf>> {
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
pub(super) fn pax_path(body: &[u8]) -> Option<String> {
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
pub(super) async fn update_cli(
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
pub(super) fn link_inside(parent: &Path, target: &Path) -> bool {
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
pub(super) fn check_app_zip(archive: &Path) -> Result<()> {
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
pub(super) async fn update_app(
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
