//! Deadbolt's browser extension talks to the agent through this binary, run
//! by the browser as a native messaging host (see `docs/autofill.md`).
//!
//! `deadbolt browser install` registers it: a manifest named
//! [`HOST_NAME`] in each browser's `NativeMessagingHosts` directory, whose
//! `path` is this binary and whose only allowed origin is the extension.
//! The browser runs `path` with the extension's origin as its one argument
//! and no way to add others, so `main` reads a first argument of
//! `chrome-extension://…` as `deadbolt browser-host <origin>`: no launcher
//! script to keep in step with the binary.

pub mod host;
mod passkeys;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::ValueEnum;

use crate::config::ExtensionBuild;

/// The native messaging host's name, which the extension connects to.
pub const HOST_NAME: &str = "pw.deadbolt.browser";

/// The extension's id, fixed by the public key in
/// `extension/manifest-key.txt` (the manifest's `key`): the first 128 bits
/// of the SHA-256 of the key's DER, in hex written with the letters `a`–`p`.
pub const EXTENSION_ID: &str = "jhocodkhpifjndffenppfmdkmiolngal";

/// The origin the browser passes for the extension.
pub fn extension_origin() -> String {
    format!("chrome-extension://{EXTENSION_ID}/")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Browser {
    Chrome,
    Brave,
    Arc,
    Edge,
    Chromium,
    Helium,
    /// Every browser above, installed or not.
    All,
}

const BROWSERS: [Browser; 6] = [
    Browser::Chrome,
    Browser::Brave,
    Browser::Arc,
    Browser::Edge,
    Browser::Chromium,
    Browser::Helium,
];

impl Browser {
    fn name(self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Brave => "Brave",
            Self::Arc => "Arc",
            Self::Edge => "Edge",
            Self::Chromium => "Chromium",
            Self::Helium => "Helium",
            Self::All => "all",
        }
    }

    /// The browser's user data directory, where it keeps
    /// `NativeMessagingHosts`, if the platform has the browser.
    fn data_dir(self, macos: bool, home: &Path, config: &Path) -> Option<PathBuf> {
        if macos {
            let support = home.join("Library/Application Support");
            Some(support.join(match self {
                Self::Chrome => "Google/Chrome",
                Self::Brave => "BraveSoftware/Brave-Browser",
                Self::Arc => "Arc/User Data",
                Self::Edge => "Microsoft Edge",
                Self::Chromium => "Chromium",
                Self::Helium => "net.imput.helium",
                Self::All => return None,
            }))
        } else {
            Some(config.join(match self {
                Self::Chrome => "google-chrome",
                Self::Brave => "BraveSoftware/Brave-Browser",
                Self::Edge => "microsoft-edge",
                Self::Chromium => "chromium",
                Self::Helium => "net.imput.helium",
                Self::Arc | Self::All => return None,
            }))
        }
    }
}

/// Where browsers keep their data.
struct Dirs {
    macos: bool,
    home: PathBuf,
    config: PathBuf,
}

impl Dirs {
    fn get() -> Result<Self> {
        Self::from_vars(cfg!(target_os = "macos"), |name| {
            crate::config::env(name).ok()
        })
    }

    /// The directories for an environment given by `vars`.
    fn from_vars(macos: bool, vars: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let var = |name: &str| vars(name).filter(|v| !v.is_empty()).map(PathBuf::from);
        let home = var("HOME").context("HOME is not set")?;
        let config = var("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
        Ok(Self {
            macos,
            home,
            config,
        })
    }

    fn data_dir(&self, browser: Browser) -> Option<PathBuf> {
        browser.data_dir(self.macos, &self.home, &self.config)
    }

    fn manifest(&self, browser: Browser) -> Option<PathBuf> {
        Some(
            self.data_dir(browser)?
                .join("NativeMessagingHosts")
                .join(format!("{HOST_NAME}.json")),
        )
    }
}

fn manifest(program: &Path) -> Result<String> {
    let path = program
        .to_str()
        .context("the path of this binary is not UTF-8")?;
    let manifest = serde_json::json!({
        "name": HOST_NAME,
        "description": "Deadbolt password manager",
        "path": path,
        "type": "stdio",
        "allowed_origins": [extension_origin()],
    });
    Ok(serde_json::to_string_pretty(&manifest)? + "\n")
}

/// Writes `body` to `path` through a synced temporary file in the same
/// directory, then syncs the replacement's directory entry. Existing regular
/// files keep only ordinary rwx bits, never setuid/setgid/sticky bits on the
/// replacement inode; new files use 0666 filtered by the umask.
pub fn write_atomic(path: &Path, body: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    use rustix::io::Errno;

    let dir = path.parent().context("path has no directory")?;
    let name = path.file_name().context("path has no file name")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let permissions = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => Some(std::fs::Permissions::from_mode(
            meta.permissions().mode() & 0o777,
        )),
        Ok(_) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let directory =
        std::fs::File::open(dir).with_context(|| format!("opening {}", dir.display()))?;
    let sync_dir = || {
        // Some filesystems reject fsync on directories with EINVAL or
        // ENOTSUP/EOPNOTSUPP. Only those unsupported-directory cases are
        // skipped; I/O errors (including after rename) must reach the caller.
        directory
            .sync_all()
            .or_else(|error| {
                if Errno::from_io_error(&error).is_some_and(|errno| {
                    [Errno::INVAL, Errno::NOTSUP, Errno::OPNOTSUPP].contains(&errno)
                }) {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .with_context(|| format!("syncing {}", dir.display()))
    };
    let mut temp = tempfile::Builder::new()
        .prefix(&format!(".{}.", name.to_string_lossy()))
        .permissions(
            permissions
                .clone()
                .unwrap_or_else(|| std::fs::Permissions::from_mode(0o666)),
        )
        .tempfile_in(dir)
        .with_context(|| format!("creating a temporary file in {}", dir.display()))?;
    temp.write_all(body.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    if let Some(permissions) = permissions {
        temp.as_file()
            .set_permissions(permissions)
            .with_context(|| format!("setting permissions for {}", path.display()))?;
    }
    temp.as_file()
        .sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    // Persist the pre-rename entries first, and surface directory sync failures
    // before replacing the destination whenever possible.
    sync_dir()?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("writing {}", path.display()))?;
    sync_dir()
}

/// The browsers `chosen` names; none means those installed here.
fn pick(chosen: &[Browser], dirs: &Dirs) -> Result<Vec<Browser>> {
    let available = BROWSERS.into_iter().filter(|b| dirs.data_dir(*b).is_some());
    if chosen.contains(&Browser::All) {
        return Ok(available.collect());
    }
    if chosen.is_empty() {
        let installed: Vec<Browser> = available
            .filter(|b| dirs.data_dir(*b).is_some_and(|d| d.is_dir()))
            .collect();
        if installed.is_empty() {
            bail!("found no Chrome, Brave, Arc, Edge, Chromium or Helium; name one with --browser");
        }
        return Ok(installed);
    }
    for browser in chosen {
        if dirs.data_dir(*browser).is_none() {
            bail!("{} isn't available on this platform", browser.name());
        }
    }
    Ok(BROWSERS
        .into_iter()
        .filter(|b| chosen.contains(b))
        .collect())
}

/// Registers this binary as the native messaging host with `browsers`, and
/// `extension_dir` as the unpacked copy of `build` that `deadbolt update`
/// keeps current.
pub fn install(
    browsers: &[Browser],
    extension_dir: Option<&Path>,
    build: ExtensionBuild,
    config: &Path,
) -> Result<()> {
    match extension_dir {
        Some(dir) => register_extension_dir(dir, build, config)?,
        None if build == ExtensionBuild::Standalone => bail!(
            "--standalone keeps an unpacked copy current: pass --extension-dir <dir> \
             (a new or empty directory), or download it from \
             https://anoma.ly/release/deadbolt/extension/dev/chromium-standalone"
        ),
        None => {}
    }
    let dirs = Dirs::get()?;
    let program = std::env::current_exe().context("finding this binary")?;
    let body = manifest(&program)?;
    for browser in pick(browsers, &dirs)? {
        let Some(path) = dirs.manifest(browser) else {
            continue;
        };
        write_atomic(&path, &body)?;
        println!("{}: wrote {}", browser.name(), path.display());
    }
    println!(
        "The Deadbolt extension ({EXTENSION_ID}) can now reach {}.\n\
         Run this again if you move that binary.",
        program.display()
    );
    Ok(())
}

/// Records `dir` as the unpacked extension `deadbolt update` keeps current:
/// it must not exist yet, be empty, or already hold Deadbolt's extension, as
/// updating replaces everything in it.
fn register_extension_dir(dir: &Path, build: ExtensionBuild, config: &Path) -> Result<()> {
    let dir = extension_path(dir)?;
    if !crate::update::extension_dir_ok(&dir) {
        bail!(
            "{} holds files deadbolt update didn't install; \
             choose an empty or new directory",
            dir.display()
        );
    }
    crate::config::set_extension_dir(config, &dir, build)?;
    println!(
        "`deadbolt update` keeps the {} extension in {} current: run it now to \
         fetch it, then load it unpacked from there (chrome://extensions, \
         Developer mode, Load unpacked)",
        build.name(),
        dir.display()
    );
    Ok(())
}

/// `dir` as an extension directory is registered: absolute, with links
/// resolved (its parent's when it doesn't exist yet), so it's the same path
/// before `deadbolt update` creates it and after.
pub fn extension_path(dir: &Path) -> Result<PathBuf> {
    let dir = std::path::absolute(dir).with_context(|| format!("finding {}", dir.display()))?;
    if let Ok(path) = dir.canonicalize() {
        return Ok(path);
    }
    let resolved = dir
        .parent()
        .zip(dir.file_name())
        .and_then(|(parent, name)| Some(parent.canonicalize().ok()?.join(name)));
    Ok(resolved.unwrap_or(dir))
}

/// Stops `deadbolt update` keeping the unpacked extension in `dir` current,
/// leaving its files and the host's manifests alone.
pub fn unregister_extension_dir(dir: &Path, config: &Path) -> Result<()> {
    let dir = extension_path(dir)?;
    if !crate::config::remove_extension_dir(config, &dir)? {
        bail!(
            "{} isn't a registered extension directory (`deadbolt browser install \
             --extension-dir <dir>` registers one)",
            dir.display()
        );
    }
    println!(
        "`deadbolt update` no longer keeps {} current; remove Deadbolt loaded from \
         there in chrome://extensions, then delete the directory, if you're done with it",
        dir.display()
    );
    Ok(())
}

/// Removes the host's manifest from `browsers` (every browser if none).
pub fn uninstall(browsers: &[Browser]) -> Result<()> {
    let dirs = Dirs::get()?;
    let browsers = if browsers.is_empty() {
        pick(&[Browser::All], &dirs)?
    } else {
        pick(browsers, &dirs)?
    };
    let mut removed = 0;
    for browser in browsers {
        let Some(path) = dirs.manifest(browser) else {
            continue;
        };
        match std::fs::remove_file(&path) {
            Ok(()) => {
                removed += 1;
                println!("{}: removed {}", browser.name(), path.display());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }
    if removed == 0 {
        println!("Deadbolt wasn't registered with any browser.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn atomic_writes_preserve_modes_and_clean_up_failures() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("new/directory");
        let path = dir.join("state.json");
        write_atomic(&path, "first").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first");
        // New files keep the helper's ordinary-file creation mode and umask.
        let ordinary = dir.join("ordinary");
        std::fs::write(&ordinary, "ordinary").unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&path), mode(&ordinary));
        for permissions in [0o600, 0o640, 0o444, 0o750, 0o4600, 0o2640, 0o1444, 0o7750] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(permissions)).unwrap();
            assert_eq!(mode(&path), permissions);
            write_atomic(&path, "replacement").unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement");
            assert_eq!(mode(&path), permissions & 0o777);
            assert_eq!(mode(&path) & 0o7000, 0);
        }
        // A failed rename must leave the destination and no temporary debris.
        let occupied = dir.join("occupied");
        std::fs::create_dir(&occupied).unwrap();
        std::fs::write(occupied.join("keep"), "keep").unwrap();
        assert!(write_atomic(&occupied, "cannot replace a directory").is_err());
        assert_eq!(
            std::fs::read_to_string(occupied.join("keep")).unwrap(),
            "keep"
        );
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["occupied", "ordinary", "state.json"]);
    }

    #[test]
    fn atomic_writes_do_not_follow_temporary_or_destination_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "untouched").unwrap();
        let path = dir.path().join("state.json");
        let old_temp = dir
            .path()
            .join(format!(".state.json.{}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &old_temp).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        write_atomic(&path, "replacement").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement");
        assert!(!std::fs::symlink_metadata(&path).unwrap().is_symlink());
        assert!(std::fs::symlink_metadata(&old_temp).unwrap().is_symlink());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3);
    }

    #[test]
    fn the_extension_id_derives_from_the_committed_key() {
        let key = include_str!("../../../../extension/manifest-key.txt").trim();
        let der = data_encoding::BASE64.decode(key.as_bytes()).unwrap();
        let digest = Sha256::digest(&der);
        let id: String = digest[..16]
            .iter()
            .flat_map(|b| [b >> 4, b & 0xf])
            .map(|n| char::from(b'a' + n))
            .collect();
        assert_eq!(id, EXTENSION_ID);
    }

    #[test]
    fn manifests_go_where_each_platform_looks() {
        let path = |dirs: &Dirs, browser| {
            dirs.manifest(browser)
                .map(|p| p.to_str().unwrap().to_string())
        };
        let file = "NativeMessagingHosts/pw.deadbolt.browser.json";
        for xdg in [None, Some("")] {
            let linux = Dirs::from_vars(false, |name| match name {
                "HOME" => Some("/home/kit".into()),
                "XDG_CONFIG_HOME" => xdg.map(String::from),
                _ => None,
            })
            .unwrap();
            assert_eq!(
                path(&linux, Browser::Chrome).unwrap(),
                format!("/home/kit/.config/google-chrome/{file}")
            );
            assert_eq!(
                path(&linux, Browser::Brave).unwrap(),
                format!("/home/kit/.config/BraveSoftware/Brave-Browser/{file}")
            );
            assert_eq!(path(&linux, Browser::Arc), None);
        }
        let linux = Dirs::from_vars(false, |name| match name {
            "HOME" => Some("/home/kit".into()),
            "XDG_CONFIG_HOME" => Some("/xdg".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(
            path(&linux, Browser::Edge).unwrap(),
            format!("/xdg/microsoft-edge/{file}")
        );
        assert_eq!(
            path(&linux, Browser::Helium).unwrap(),
            format!("/xdg/net.imput.helium/{file}")
        );
        let macos = Dirs::from_vars(true, |name| match name {
            "HOME" => Some("/Users/kit".into()),
            "XDG_CONFIG_HOME" => Some("/xdg".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(
            path(&macos, Browser::Arc).unwrap(),
            format!("/Users/kit/Library/Application Support/Arc/User Data/{file}")
        );
        assert_eq!(
            path(&macos, Browser::Helium).unwrap(),
            format!("/Users/kit/Library/Application Support/net.imput.helium/{file}")
        );
        assert!(Dirs::from_vars(false, |_| None).is_err());
        assert!(Dirs::from_vars(false, |_| Some(String::new())).is_err());
    }

    #[test]
    fn the_manifest_names_this_binary_and_only_the_extension() {
        let body = manifest(Path::new("/opt/deadbolt/bin/deadbolt")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "name": "pw.deadbolt.browser",
                "description": "Deadbolt password manager",
                "path": "/opt/deadbolt/bin/deadbolt",
                "type": "stdio",
                "allowed_origins": ["chrome-extension://jhocodkhpifjndffenppfmdkmiolngal/"],
            })
        );
    }
}
