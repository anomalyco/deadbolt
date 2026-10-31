//! Opening the desktop app: `deadbolt app` from anywhere, and bare
//! `deadbolt` started from outside a terminal (docs/app.md, "One command").
//! The app is built into this binary (the `app` feature, on by default; the
//! static musl build leaves it out). It runs in its own process, this binary
//! started again as `deadbolt ui`, a thin client of the agent like any other.
//! A running app is brought forward through the agent (`app-activate`)
//! rather than started again.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::paths::Paths;
use crate::protocol::Reply;

/// The hidden subcommand that runs the app in this process, taking Rune's
/// flags (`--scene`, `--snap`, `--panel`, …). `deadbolt app` starts it
/// detached; development and tests run it directly.
pub const UI: &str = "ui";
/// Deadbolt.app's bundle identifier.
const BUNDLE_ID: &str = "pw.deadbolt.app";
/// Keeps bare `deadbolt` from ever opening a window (scripts, agents).
const NO_UI: &str = "DEADBOLT_NO_UI";
/// The longest `app-activate` may take: the agent holds it while an app
/// another launch is starting gets to its window (`watchers::STARTING`).
const ACTIVATE_TIMEOUT: Duration = Duration::from_secs(10);
/// Whether this build has the app in it.
pub const BUILT_IN: bool = cfg!(feature = "app");
/// What a build without the app says when asked for it.
const NOT_BUILT: &str = "this deadbolt is the static build for servers and containers, \
without the desktop app. On a macOS or glibc Linux desktop, install the build with the \
app: `curl -fsSL https://deadbolt.pw/install | sh`";

/// The token a launcher gave this process for the window it opens:
/// Wayland's `XDG_ACTIVATION_TOKEN`, else X11's `DESKTOP_STARTUP_ID`. A
/// running app needs it for the compositor to let it take focus.
pub fn activation_token(var: impl Fn(&str) -> Option<String>) -> Option<String> {
    ["XDG_ACTIVATION_TOKEN", "DESKTOP_STARTUP_ID"]
        .into_iter()
        .find_map(|name| var(name).filter(|v| !v.is_empty()))
}

/// Whether `app-activate`'s outcome means an app came forward, so none is
/// started: only `activated`. No agent, an agent of another protocol, `no-app`
/// or no answer in time all start one.
fn came_forward<E>(outcome: Result<Result<Reply, E>, tokio::time::error::Elapsed>) -> bool {
    matches!(outcome, Ok(Ok(Reply::Activated)))
}

/// Asks the agent, if one runs, to bring a running app forward with this
/// launch's activation token. False when the caller should start the app.
async fn activate_running(paths: &Paths) -> bool {
    let token = activation_token(|name| crate::config::env(name).ok());
    let command = crate::protocol::Command::AppActivate { token };
    came_forward(
        tokio::time::timeout(ACTIVATE_TIMEOUT, crate::client::simple(paths, command)).await,
    )
}

/// Whether bare `deadbolt` (no arguments) opens the app instead of printing
/// usage: only when none of stdin, stdout and stderr is a terminal, a
/// graphical session exists (always on macOS; a Wayland or X display on
/// Linux), it isn't an SSH session and `DEADBOLT_NO_UI` isn't set.
pub fn bare_opens_app(terminal: bool, macos: bool, var: impl Fn(&str) -> Option<String>) -> bool {
    let opted_out = var(NO_UI).is_some_and(|v| !v.is_empty() && v != "0");
    if terminal || opted_out || set(&var, "SSH_CONNECTION") {
        return false;
    }
    graphical(macos, var)
}

fn set(var: &impl Fn(&str) -> Option<String>, name: &str) -> bool {
    var(name).is_some_and(|v| !v.is_empty())
}

/// Whether there's a graphical session to open a window in: always on
/// macOS; a Wayland or X display elsewhere.
fn graphical(macos: bool, var: impl Fn(&str) -> Option<String>) -> bool {
    macos || set(&var, "WAYLAND_DISPLAY") || set(&var, "DISPLAY")
}

/// Whether this process was started from a terminal.
pub fn from_terminal() -> bool {
    std::io::stdin().is_terminal()
        || std::io::stdout().is_terminal()
        || std::io::stderr().is_terminal()
}

/// The arguments to run the app with in this process, if this process is
/// the app: `deadbolt ui [flags]`, or (macOS) Deadbolt.app's own
/// `Contents/MacOS/Deadbolt` whatever its arguments. That file is this
/// binary too, signed as the app, so it never runs a CLI command: the agent
/// takes it for the app, and a command run through it would carry the
/// app's standing.
pub fn ui_args(args: &[OsString], exe: Option<&Path>, macos: bool) -> Option<Vec<String>> {
    let text = |args: &[OsString]| {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    };
    if macos && exe.is_some_and(|exe| app_bundle_of(exe).is_some()) {
        return Some(text(args.get(1..).unwrap_or_default()));
    }
    (args.get(1).is_some_and(|a| a == UI)).then(|| text(&args[2..]))
}

/// Runs the app in this process until it quits.
pub fn run_ui(argv: Vec<String>) -> ExitCode {
    #[cfg(feature = "app")]
    {
        deadbolt_app::run(
            argv,
            deadbolt_app::Host {
                enclave_sha256: env!("DEADBOLT_ENCLAVE_SHA256"),
            },
        );
        ExitCode::SUCCESS
    }
    #[cfg(not(feature = "app"))]
    {
        let _ = argv;
        eprintln!("error: {NOT_BUILT}");
        ExitCode::FAILURE
    }
}

/// What opens the app.
#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    /// The Deadbolt.app this binary is the helper of, through `open`.
    Bundle(PathBuf),
    /// This binary as `deadbolt ui`, after trying (macOS release builds)
    /// whichever Deadbolt.app Launch Services knows, through `open -b`.
    BuiltIn { bundle_id_first: bool },
    /// No app here: a build without it.
    NotBuilt,
}

/// What opens the app for the `deadbolt` at `exe` (symlinks resolved).
pub fn locate(exe: &Path, macos: bool, built_in: bool, release: bool) -> Target {
    if macos && let Some(bundle) = bundle_of(exe) {
        return Target::Bundle(bundle);
    }
    if built_in {
        Target::BuiltIn {
            bundle_id_first: macos && release,
        }
    } else {
        Target::NotBuilt
    }
}

/// `X.app` for `X.app/Contents/Helpers/deadbolt`.
pub fn bundle_of(exe: &Path) -> Option<PathBuf> {
    bundle_with(exe, "Helpers")
}

/// `X.app` for its own executable, `X.app/Contents/MacOS/<name>`.
fn app_bundle_of(exe: &Path) -> Option<PathBuf> {
    bundle_with(exe, "MacOS")
}

fn bundle_with(exe: &Path, dir: &str) -> Option<PathBuf> {
    let inner = exe.parent()?;
    let contents = inner.parent()?;
    let bundle = contents.parent()?;
    (inner.file_name()? == dir
        && contents.file_name()? == "Contents"
        && bundle.extension()? == "app")
        .then(|| bundle.to_path_buf())
}

/// This binary's path, symlinks resolved, so a `~/.local/bin/deadbolt`
/// linked into Deadbolt.app still finds its bundle.
pub fn this_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("finding this binary")?;
    Ok(exe.canonicalize().unwrap_or(exe))
}

/// Opens the app and returns once it's launched, detached from this
/// process, or once a running one came forward. Deadbolt.app goes through
/// Launch Services, which brings a running copy to the front. The built-in
/// app is asked through the agent first (`app-activate`), and only started
/// when no app answers.
pub async fn open(paths: &Paths) -> Result<()> {
    let exe = this_binary()?;
    let macos = cfg!(target_os = "macos");
    let release = !cfg!(debug_assertions);
    match locate(&exe, macos, BUILT_IN, release) {
        Target::Bundle(bundle) => {
            if let Some(home) = crate::config::env("HOME").ok().filter(|h| !h.is_empty()) {
                link_into_applications(&bundle, Path::new(&home));
            }
            launch_services(Command::new("/usr/bin/open").arg(&bundle))
                .with_context(|| format!("couldn't open {}", bundle.display()))
        }
        Target::BuiltIn { bundle_id_first } => {
            if bundle_id_first
                && launch_services(Command::new("/usr/bin/open").args(["-b", BUNDLE_ID])).is_ok()
            {
                return Ok(());
            }
            if !graphical(macos, |name| crate::config::env(name).ok()) {
                bail!(
                    "there's no graphical session here (neither WAYLAND_DISPLAY nor DISPLAY \
                     is set); `deadbolt app` opens a window on your desktop"
                );
            }
            if activate_running(paths).await {
                return Ok(());
            }
            if !macos {
                crate::desktop::ensure(&exe);
            }
            start(&exe)
        }
        Target::NotBuilt => bail!("{NOT_BUILT}"),
    }
}

/// Starts this binary as the app, in its own process group with no stdio.
/// It inherits the launcher's activation token for its first window (Rune
/// takes it from the environment), and runs this binary as its agent.
fn start(exe: &Path) -> Result<()> {
    // Debug builds only: tests stand a script in for the app.
    let program = cfg!(debug_assertions)
        .then(|| crate::config::env("DEADBOLT_TEST_UI").ok())
        .flatten()
        .filter(|p| !p.is_empty())
        .map_or_else(|| exe.to_path_buf(), PathBuf::from);
    Command::new(&program)
        .arg(UI)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .with_context(|| format!("starting {} {UI}", program.display()))?;
    Ok(())
}

/// Puts a link to `bundle` in `~/Applications`, so Launchpad, Finder and
/// Spotlight's apps list Deadbolt, when it lives somewhere else (an npm
/// install's package) and neither Applications folder has a Deadbolt yet.
/// Best effort: opening the app doesn't wait on it.
fn link_into_applications(bundle: &Path, home: &Path) {
    let Some(link) = applications_link(bundle, home, |p| p.symlink_metadata().is_ok()) else {
        return;
    };
    if let Some(dir) = link.parent()
        && std::fs::create_dir_all(dir).is_ok()
        && std::os::unix::fs::symlink(bundle, &link).is_ok()
    {
        eprintln!("Linked {} to {}", link.display(), bundle.display());
    }
}

/// Where [`link_into_applications`] links `bundle`, if it should.
fn applications_link(
    bundle: &Path,
    home: &Path,
    exists: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let user = home.join("Applications");
    let text = bundle.to_string_lossy();
    let movable = !(text.starts_with("/Volumes/") || text.contains("/AppTranslocation/"));
    let elsewhere = [Path::new("/Applications"), &user]
        .iter()
        .all(|dir| bundle.parent() != Some(dir));
    let link = user.join("Deadbolt.app");
    let taken = exists(&link) || exists(Path::new("/Applications/Deadbolt.app"));
    (movable && elsewhere && !taken).then_some(link)
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

    fn env<'a>(vars: &'a [(&str, &str)]) -> impl Fn(&str) -> Option<String> + 'a {
        |name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn the_launchers_token_is_waylands_else_x11s() {
        assert_eq!(activation_token(env(&[])), None);
        let x11 = [("DESKTOP_STARTUP_ID", "kde-123_TIME456")];
        assert_eq!(
            activation_token(env(&x11)).as_deref(),
            Some("kde-123_TIME456")
        );
        let both = [("DESKTOP_STARTUP_ID", "x"), ("XDG_ACTIVATION_TOKEN", "w")];
        assert_eq!(activation_token(env(&both)).as_deref(), Some("w"));
        let empty = [("XDG_ACTIVATION_TOKEN", ""), ("DESKTOP_STARTUP_ID", "x")];
        assert_eq!(activation_token(env(&empty)).as_deref(), Some("x"));
    }

    #[tokio::test(start_paused = true)]
    async fn only_an_app_that_came_forward_keeps_another_from_starting() {
        let answered = |reply| async move { Ok::<_, ()>(reply) };
        let forward = tokio::time::timeout(ACTIVATE_TIMEOUT, answered(Reply::Activated)).await;
        assert!(came_forward(forward));
        let no_app = tokio::time::timeout(ACTIVATE_TIMEOUT, answered(Reply::NoApp)).await;
        assert!(!came_forward(no_app));
        // No agent, or one that refused the request.
        let failed = tokio::time::timeout(ACTIVATE_TIMEOUT, async { Err::<Reply, _>(()) }).await;
        assert!(!came_forward(failed));
        let stuck = tokio::time::timeout(
            ACTIVATE_TIMEOUT,
            std::future::pending::<Result<Reply, ()>>(),
        );
        assert!(!came_forward(stuck.await));
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

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn only_deadbolt_ui_and_the_bundles_own_executable_run_the_app_here() {
        let cli = Path::new("/home/kit/.local/bin/deadbolt");
        let ui = argv(&["deadbolt", "ui", "--scene", "vault"]);
        assert_eq!(
            ui_args(&ui, Some(cli), false),
            Some(vec!["--scene".into(), "vault".into()])
        );
        assert_eq!(
            ui_args(&argv(&["deadbolt", "ui"]), None, true),
            Some(vec![])
        );
        for other in [&["deadbolt"][..], &["deadbolt", "ls"], &["deadbolt", "app"]] {
            assert_eq!(ui_args(&argv(other), Some(cli), true), None, "{other:?}");
        }
        // Deadbolt.app's own executable is the app whatever it's asked.
        let app = Path::new("/Applications/Deadbolt.app/Contents/MacOS/Deadbolt");
        let ls = argv(&["Deadbolt", "get", "github"]);
        assert_eq!(
            ui_args(&ls, Some(app), true),
            Some(vec!["get".into(), "github".into()])
        );
        assert_eq!(ui_args(&argv(&["Deadbolt"]), Some(app), true), Some(vec![]));
        // Its helper is the CLI.
        let helper = Path::new("/Applications/Deadbolt.app/Contents/Helpers/deadbolt");
        assert_eq!(ui_args(&ls, Some(helper), true), None);
        // Only macOS has bundles.
        assert_eq!(ui_args(&ls, Some(app), false), None);
    }

    #[test]
    fn the_app_is_the_bundle_else_built_in_else_missing() {
        let helper = Path::new("/Applications/Deadbolt.app/Contents/Helpers/deadbolt");
        let bundle = PathBuf::from("/Applications/Deadbolt.app");
        assert_eq!(
            locate(helper, true, true, true),
            Target::Bundle(bundle.clone())
        );
        assert_eq!(locate(helper, true, false, true), Target::Bundle(bundle));
        let cli = Path::new("/usr/local/bin/deadbolt");
        assert_eq!(
            locate(cli, true, true, true),
            Target::BuiltIn {
                bundle_id_first: true
            }
        );
        // A development build opens its own app, not an installed one.
        assert_eq!(
            locate(cli, true, true, false),
            Target::BuiltIn {
                bundle_id_first: false
            }
        );
        assert_eq!(
            locate(cli, false, true, true),
            Target::BuiltIn {
                bundle_id_first: false
            }
        );
        // Linux has no bundles, even shaped like one.
        assert_eq!(
            locate(helper, false, true, true),
            Target::BuiltIn {
                bundle_id_first: false
            }
        );
        assert_eq!(locate(cli, false, false, true), Target::NotBuilt);
    }

    #[test]
    fn the_bundle_is_found_by_its_helpers_shape() {
        assert_eq!(
            bundle_of(Path::new(
                "/Applications/Deadbolt.app/Contents/Helpers/deadbolt"
            )),
            Some(PathBuf::from("/Applications/Deadbolt.app"))
        );
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

    #[test]
    fn an_app_outside_applications_gets_a_link_in_the_users() {
        let home = Path::new("/Users/kit");
        let npm =
            Path::new("/opt/homebrew/lib/node_modules/@deadbolt/cli-darwin-arm64/Deadbolt.app");
        let nothing = |_: &Path| false;
        assert_eq!(
            applications_link(npm, home, nothing),
            Some(PathBuf::from("/Users/kit/Applications/Deadbolt.app"))
        );
        // Either Applications folder already has a Deadbolt (a link included).
        for there in [
            "/Users/kit/Applications/Deadbolt.app",
            "/Applications/Deadbolt.app",
        ] {
            assert_eq!(
                applications_link(npm, home, |p| p == Path::new(there)),
                None
            );
        }
        // Already in one, or somewhere it can't stay.
        for bundle in [
            "/Applications/Deadbolt.app",
            "/Users/kit/Applications/Deadbolt.app",
            "/Volumes/Deadbolt/Deadbolt.app",
            "/private/var/folders/x/AppTranslocation/y/d/Deadbolt.app",
        ] {
            assert_eq!(
                applications_link(Path::new(bundle), home, nothing),
                None,
                "{bundle}"
            );
        }
    }
}
