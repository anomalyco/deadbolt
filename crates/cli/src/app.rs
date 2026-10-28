//! Opening the desktop app: `deadbolt app` from anywhere, and bare
//! `deadbolt` started from outside a terminal (docs/app.md, "One command").
//! The app is its own program, so this binary stays free of GUI libraries.

use std::io::IsTerminal;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// The desktop app's program: beside `deadbolt`, or in `<prefix>/lib/deadbolt/`.
pub const PROGRAM: &str = "deadbolt-ui";
/// Deadbolt.app's bundle identifier.
const BUNDLE_ID: &str = "pw.deadbolt.app";
/// Keeps bare `deadbolt` from ever opening a window (scripts, agents).
const NO_UI: &str = "DEADBOLT_NO_UI";

/// Whether bare `deadbolt` (no arguments) opens the app instead of printing
/// usage: only when none of stdin, stdout and stderr is a terminal, a
/// graphical session exists (always on macOS; a Wayland or X display on
/// Linux), it isn't an SSH session and `DEADBOLT_NO_UI` isn't set.
pub fn bare_opens_app(terminal: bool, macos: bool, var: impl Fn(&str) -> Option<String>) -> bool {
    let set = |name: &str| var(name).is_some_and(|v| !v.is_empty());
    let opted_out = var(NO_UI).is_some_and(|v| !v.is_empty() && v != "0");
    if terminal || opted_out || set("SSH_CONNECTION") {
        return false;
    }
    macos || set("WAYLAND_DISPLAY") || set("DISPLAY")
}

/// Whether this process was started from a terminal.
pub fn from_terminal() -> bool {
    std::io::stdin().is_terminal()
        || std::io::stdout().is_terminal()
        || std::io::stderr().is_terminal()
}

/// What opens the app.
#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    /// The Deadbolt.app this binary is the helper of, through `open`.
    Bundle(PathBuf),
    /// The app's program, run directly.
    Program(PathBuf),
    /// Whichever Deadbolt.app Launch Services knows, through `open -b`.
    BundleId,
}

/// Where the app is for the `deadbolt` at `exe` (symlinks resolved), or
/// the places looked in. In order: the bundle `exe` is the helper of, on
/// macOS; `deadbolt-ui` beside `exe`; `<prefix>/lib/deadbolt/deadbolt-ui`
/// for `<prefix>/bin/deadbolt`; then, on macOS, an installed Deadbolt.app.
pub fn locate(exe: &Path, macos: bool) -> Result<Target, Vec<PathBuf>> {
    if macos && let Some(bundle) = bundle_of(exe) {
        return Ok(Target::Bundle(bundle));
    }
    let mut looked = Vec::new();
    if let Some(dir) = exe.parent() {
        looked.push(dir.join(PROGRAM));
        if dir.file_name().is_some_and(|n| n == "bin")
            && let Some(prefix) = dir.parent()
        {
            looked.push(prefix.join("lib/deadbolt").join(PROGRAM));
        }
    }
    if let Some(program) = looked.iter().find(|p| executable(p)) {
        return Ok(Target::Program(program.clone()));
    }
    if macos {
        return Ok(Target::BundleId);
    }
    Err(looked)
}

/// `X.app` for `X.app/Contents/Helpers/deadbolt`.
fn bundle_of(exe: &Path) -> Option<PathBuf> {
    let helpers = exe.parent()?;
    let contents = helpers.parent()?;
    let bundle = contents.parent()?;
    (helpers.file_name()? == "Helpers"
        && contents.file_name()? == "Contents"
        && bundle.extension()? == "app")
        .then(|| bundle.to_path_buf())
}

fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// This binary's path, symlinks resolved, so a `~/.local/bin/deadbolt`
/// linked into Deadbolt.app still finds its bundle.
pub fn this_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("finding this binary")?;
    Ok(exe.canonicalize().unwrap_or(exe))
}

/// Opens the app and returns once it's launched, detached from this
/// process. Deadbolt.app goes through Launch Services, which brings a
/// running copy to the front; Rune has no single-instance support, so
/// elsewhere a second launch opens a second window.
pub fn open() -> Result<()> {
    let exe = this_binary()?;
    let macos = cfg!(target_os = "macos");
    match locate(&exe, macos) {
        Ok(Target::Bundle(bundle)) => launch_services(Command::new("/usr/bin/open").arg(&bundle))
            .with_context(|| format!("couldn't open {}", bundle.display())),
        Ok(Target::BundleId) => {
            launch_services(Command::new("/usr/bin/open").args(["-b", BUNDLE_ID])).context(
                "couldn't open Deadbolt.app. Install it with `brew install --cask \
                 anomalyco/tap/deadbolt`, or download it from \
                 https://github.com/anomalyco/deadbolt/releases",
            )
        }
        Ok(Target::Program(program)) => {
            let mut command = Command::new(&program);
            // The app runs this `deadbolt` as its agent, not another on PATH.
            if crate::config::env("DEADBOLT_BIN").is_err() {
                command.env("DEADBOLT_BIN", &exe);
            }
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .with_context(|| format!("starting {}", program.display()))?;
            Ok(())
        }
        Err(looked) => {
            let looked: Vec<String> = looked
                .iter()
                .map(|p| format!("  {}", p.display()))
                .collect();
            bail!(
                "Deadbolt's desktop app isn't installed with this deadbolt. Looked for:\n{}\n\
                 Install `{PROGRAM}` there; from a checkout, \
                 `cargo install --locked --path crates/app` puts it beside a \
                 cargo-installed deadbolt.",
                looked.join("\n")
            )
        }
    }
}

/// Runs `open`, which returns once Launch Services has the app started.
fn launch_services(command: &mut Command) -> Result<()> {
    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("running open")?;
    if !status.success() {
        bail!("open exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn env<'a>(vars: &'a [(&str, &str)]) -> impl Fn(&str) -> Option<String> + 'a {
        |name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn bare_deadbolt_opens_the_app_only_outside_a_terminal_with_a_display() {
        let wayland = [("WAYLAND_DISPLAY", "wayland-1")];
        let x11 = [("DISPLAY", ":0")];
        assert!(bare_opens_app(false, false, env(&wayland)));
        assert!(bare_opens_app(false, false, env(&x11)));
        assert!(bare_opens_app(false, true, env(&[])));
        // A terminal on any stream is the CLI.
        assert!(!bare_opens_app(true, false, env(&wayland)));
        assert!(!bare_opens_app(true, true, env(&[])));
        // No graphical session on Linux.
        assert!(!bare_opens_app(false, false, env(&[])));
        assert!(!bare_opens_app(false, false, env(&[("DISPLAY", "")])));
        // SSH, even with a forwarded display.
        let ssh = [("DISPLAY", "localhost:10"), ("SSH_CONNECTION", "1 2 3 4")];
        assert!(!bare_opens_app(false, false, env(&ssh)));
        assert!(!bare_opens_app(false, true, env(&ssh[1..])));
        // The opt-out.
        for value in ["1", "yes"] {
            let vars = [("WAYLAND_DISPLAY", "wayland-1"), (NO_UI, value)];
            assert!(!bare_opens_app(false, false, env(&vars)));
            assert!(!bare_opens_app(false, true, env(&vars[1..])));
        }
        for value in ["", "0"] {
            assert!(bare_opens_app(false, true, env(&[(NO_UI, value)])));
        }
    }

    fn program(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn the_app_is_found_beside_deadbolt_then_under_its_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        let exe = bin.join("deadbolt");
        program(&exe);
        let sibling = bin.join(PROGRAM);
        let lib = dir.path().join("lib/deadbolt").join(PROGRAM);
        assert_eq!(locate(&exe, false), Err(vec![sibling.clone(), lib.clone()]));
        assert_eq!(locate(&exe, true), Ok(Target::BundleId));
        program(&lib);
        assert_eq!(locate(&exe, false), Ok(Target::Program(lib.clone())));
        program(&sibling);
        assert_eq!(locate(&exe, false), Ok(Target::Program(sibling.clone())));
        assert_eq!(locate(&exe, true), Ok(Target::Program(sibling)));
    }

    #[test]
    fn only_an_executable_file_counts_and_only_bin_has_a_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let debug = dir.path().join("target/debug");
        let exe = debug.join("deadbolt");
        program(&exe);
        std::fs::write(debug.join(PROGRAM), "").unwrap();
        program(&dir.path().join("target/lib/deadbolt").join(PROGRAM));
        assert_eq!(locate(&exe, false), Err(vec![debug.join(PROGRAM)]));
    }

    #[test]
    fn the_bundles_helper_opens_its_own_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("Deadbolt.app");
        let exe = bundle.join("Contents/Helpers/deadbolt");
        program(&exe);
        program(&bundle.join("Contents/Helpers").join(PROGRAM));
        assert_eq!(locate(&exe, true), Ok(Target::Bundle(bundle)));
        assert!(
            bundle_of(Path::new(
                "/Applications/Deadbolt/Contents/Helpers/deadbolt"
            ))
            .is_none()
        );
        assert!(
            bundle_of(Path::new(
                "/Applications/Deadbolt.app/Contents/MacOS/Deadbolt"
            ))
            .is_none()
        );
    }
}
