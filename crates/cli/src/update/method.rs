//! How the running `deadbolt` is installed, and the package manager that
//! updates it.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;

/// Receipt written beside an install by the installer (`site/public/install`),
/// identifying who owns it so `deadbolt update` knows before guessing from
/// paths.
pub(super) const RECEIPT_FILE: &str = "install.json";
/// Largest `install.json` receipt we will read.
const RECEIPT_LIMIT: u64 = 64 * 1024;

/// Parsed `install.json` receipt.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(super) struct InstallReceipt {
    pub(super) app: String,
    pub(super) artifact: String,
    #[serde(default)]
    pub(super) channel: Option<String>,
    pub(super) method: String,
    pub(super) root: String,
}

/// Ownership and permission snapshot for checking receipt trust without root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FileMeta {
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) mode: u32,
    pub(super) is_file: bool,
    pub(super) is_symlink: bool,
    pub(super) len: u64,
}

impl FileMeta {
    fn from_metadata(meta: &std::fs::Metadata) -> Self {
        let kind = meta.file_type();
        Self {
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
            is_file: kind.is_file(),
            is_symlink: kind.is_symlink(),
            len: meta.len(),
        }
    }
}

/// Whether an `install.json` receipt and its directory may be trusted for
/// `method`: the receipt must be a regular, non-symlink, small file that
/// neither group nor others can write; the directory must not be world-writable
/// or writable by another group; and `direct` receipts must be owned by the
/// current user (managed receipts may also be owned by root).
pub(super) fn receipt_trusted(
    method: &str,
    euid: u32,
    egid: u32,
    dir: FileMeta,
    file: FileMeta,
) -> bool {
    if !file.is_file || file.is_symlink || file.len > RECEIPT_LIMIT {
        return false;
    }
    if file.mode & 0o022 != 0 {
        return false;
    }
    if dir.mode & 0o002 != 0 || (dir.mode & 0o020 != 0 && dir.gid != egid) {
        return false;
    }
    let owner_ok = |uid: u32| {
        if method == "direct" {
            uid == euid
        } else {
            uid == euid || uid == 0
        }
    };
    owner_ok(dir.uid) && owner_ok(file.uid)
}

fn same_dir(recorded: &Path, actual: &Path) -> bool {
    if !recorded.is_absolute() {
        return false;
    }
    let Ok(recorded) = recorded.canonicalize() else {
        return false;
    };
    let actual = actual
        .canonicalize()
        .unwrap_or_else(|_| actual.to_path_buf());
    recorded == actual
}

/// Reads and validates an `install.json` receipt for `exe` if a trusted one
/// exists beside the binary (or inside a macOS `Deadbolt.app` bundle). Any
/// missing, corrupt, untrusted, or mismatched receipt returns `None` so the
/// caller falls back to path heuristics.
pub(super) fn read_receipt(exe: &Path, macos: bool) -> Option<Install> {
    let exe_dir = exe.parent()?;
    let bundle = if macos {
        crate::app::bundle_of(exe)
    } else {
        None
    };
    let mut candidates = vec![exe_dir.join(RECEIPT_FILE)];
    if let Some(bundle) = &bundle {
        candidates.push(bundle.join("Contents/Resources").join(RECEIPT_FILE));
        candidates.push(bundle.join(RECEIPT_FILE));
    }
    let euid = rustix::process::geteuid().as_raw();
    let egid = rustix::process::getegid().as_raw();
    for path in candidates {
        let Ok(file_raw) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        let file_meta = FileMeta::from_metadata(&file_raw);
        let receipt_dir = path.parent()?;
        let Ok(dir_raw) = std::fs::metadata(receipt_dir) else {
            return None;
        };
        let dir_meta = FileMeta::from_metadata(&dir_raw);
        if !file_meta.is_file || file_meta.is_symlink || file_meta.len > RECEIPT_LIMIT {
            return None;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            return None;
        };
        let Ok(receipt) = serde_json::from_slice::<InstallReceipt>(&bytes) else {
            return None;
        };
        if receipt.app != super::protocol::APP {
            return None;
        }
        if receipt
            .channel
            .as_deref()
            .is_some_and(|c| !super::protocol::is_name(c))
        {
            return None;
        }
        if !receipt_trusted(&receipt.method, euid, egid, dir_meta, file_meta) {
            return None;
        }
        let expected_root = match receipt.artifact.as_str() {
            "cli" => exe_dir,
            "desktop" => bundle.as_deref()?,
            _ => return None,
        };
        if !same_dir(Path::new(&receipt.root), expected_root) {
            return None;
        }
        return match receipt.method.as_str() {
            "direct" => match receipt.artifact.as_str() {
                "cli" => Some(Install::Standalone(exe_dir.to_path_buf())),
                "desktop" => {
                    let bundle = bundle?;
                    let text = bundle.to_string_lossy();
                    if text.starts_with("/Volumes/") || text.contains("/AppTranslocation/") {
                        Some(Install::Unmovable(bundle))
                    } else {
                        Some(Install::App(bundle))
                    }
                }
                _ => None,
            },
            "homebrew" | "brew" => {
                if receipt.artifact == "desktop" || bundle.is_some() {
                    Some(Install::Managed(Manager::BrewCask))
                } else {
                    Some(Install::Managed(Manager::Brew))
                }
            }
            "brew-cask" | "homebrew-cask" => Some(Install::Managed(Manager::BrewCask)),
            "npm" => Some(Install::Managed(Manager::Npm)),
            "pnpm" => Some(Install::Managed(Manager::Pnpm)),
            "bun" => Some(Install::Managed(Manager::Bun)),
            "yarn" => Some(Install::Managed(Manager::Yarn)),
            "nix" => Some(Install::Managed(Manager::Nix)),
            "cargo" => Some(Install::Managed(Manager::Cargo)),
            "system" | "apt" | "rpm" | "aur" => Some(Install::Managed(Manager::System)),
            _ => None,
        };
    }
    None
}

/// npm's package, which links to its platform package's `deadbolt`.
pub(super) const PACKAGE: &str = "@deadbolt/cli";
/// The platform packages `@deadbolt/cli` installs one of.
pub(super) const PLATFORM_PACKAGES: [&str; 6] = [
    "@deadbolt/cli-linux-x64",
    "@deadbolt/cli-linux-arm64",
    "@deadbolt/cli-linux-x64-musl",
    "@deadbolt/cli-linux-arm64-musl",
    "@deadbolt/cli-darwin-arm64",
    "@deadbolt/cli-darwin-x64",
];
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
    /// The release service's distribution kind. npm's package is `npm`
    /// once the release lists it; a release written before it did carries
    /// no entry, and its build then follows what the registry serves
    /// ([`served_by_npm`]).
    pub(super) fn distribution(self) -> &'static str {
        match self {
            Self::Brew | Self::BrewCask => "brew",
            Self::Npm | Self::Pnpm | Self::Bun | Self::Yarn | Self::Package => "npm",
            _ => "unknown",
        }
    }

    /// Whether it installs npm's package, so the registry says what it can
    /// install.
    pub(super) fn npm(self) -> bool {
        matches!(
            self,
            Self::Npm | Self::Pnpm | Self::Bun | Self::Yarn | Self::Package
        )
    }

    /// Who updates it, for people.
    pub(super) fn name(self) -> &'static str {
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
    pub(super) fn hint(self, channel: &str) -> String {
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
pub(super) struct Upgrade {
    /// Looked up with [`find_program`].
    pub(super) program: &'static str,
    pub(super) args: Vec<String>,
    /// As people would type it.
    pub(super) shown: String,
    /// bun never prunes its shared cache, so it gets a fresh one, given
    /// before the package and deleted afterwards (as OpenCode does).
    pub(super) own_cache: bool,
}

/// [`Upgrade`] for `manager`, pinned to `version`; `None` for the managers
/// `deadbolt update` leaves to the user.
pub(super) fn upgrade_command(manager: Manager, version: &str) -> Option<Upgrade> {
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

/// The install method's name for the daemon's check: a standalone install
/// with a direct `install.json` receipt is `direct`; the install script's
/// directory (`$DEADBOLT_INSTALL`, else `~/.local/bin`) without one is
/// `curl`; any other standalone `deadbolt` is `standalone`.
pub fn method_key(install: &Install) -> &'static str {
    match install {
        Install::App(_) | Install::Unmovable(_) => "app",
        Install::Standalone(dir) => {
            if matches!(
                read_receipt(&dir.join("deadbolt"), false),
                Some(Install::Standalone(_))
            ) {
                return "direct";
            }
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
        "direct" | "curl" => "installed with the install script".into(),
        "standalone" => "standalone".into(),
        "brew" => "installed with Homebrew".into(),
        "package" => "installed with a JavaScript package manager".into(),
        other => format!("installed with {other}"),
    }
}

/// Where Homebrew keeps casks' records: a Deadbolt.app with one is the cask's.
pub(super) const CASKROOMS: [&str; 2] = [
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

/// Checks `install.json` beside `exe` (or inside a macOS `Deadbolt.app`
/// bundle) first, falling back to path heuristics ([`classify`]) when no
/// trusted receipt is present.
pub fn classify_with_receipt(exe: &Path, macos: bool, exists: impl Fn(&Path) -> bool) -> Install {
    if let Some(install) = read_receipt(exe, macos) {
        return install;
    }
    classify(exe, macos, exists)
}

/// How the `deadbolt` at `exe` (symlinks resolved) is installed: checks a
/// trusted `install.json` receipt first, then [`classify`], and for npm's
/// package (one whose `@deadbolt/cli` links to `exe`, [`package_of`]) the
/// first of npm, pnpm, bun and yarn that says it has `@deadbolt/cli`
/// globally, those named in `exe`'s path first.
pub async fn method(exe: &Path) -> Install {
    let install = classify_with_receipt(exe, cfg!(target_os = "macos"), Path::exists);
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
pub(super) async fn has_package(manager: Manager, exe: PathBuf) -> bool {
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
pub(super) fn manager_order(exe: &Path) -> Vec<Manager> {
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
pub(super) fn lists_package(text: &str) -> bool {
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
pub(super) fn find_program(name: &str, exe: &Path) -> Option<PathBuf> {
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
