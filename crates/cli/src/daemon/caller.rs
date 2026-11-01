//! Who is asking (`docs/agent-control.md`): each connection's peer as the
//! kernel names it, its code signature (macOS) or executable (Linux), and the
//! class that rests on them. What the client claims is attached, never used.

use std::collections::HashMap;
use std::io;
use std::path::Path;
#[cfg(any(test, target_os = "macos"))]
use std::path::PathBuf;
use std::sync::Mutex;

use deadbolt_client::peer::{APP_ID, AUTOFILL_ID, CodeSignature, DAEMON_ID, Peer, Process};
use tracing::warn;

use crate::protocol::{CallerClass, CallerInfo, Check, Claim, Signature};

/// Peers remembered, by audit token (pid and pid version).
const CACHE_MAX: usize = 256;

/// AI hosts whose process names make a better label than their path.
const HOSTS: [(&str, &str); 7] = [
    ("opencode", "OpenCode"),
    ("opencode-cli", "OpenCode"),
    ("claude", "Claude Code"),
    ("codex", "Codex"),
    ("cursor-agent", "Cursor"),
    ("gemini", "Gemini CLI"),
    ("aider", "Aider"),
];
const SHELLS: [&str; 7] = ["zsh", "bash", "fish", "sh", "dash", "nu", "tcsh"];

/// The daemon's own binary and its bundle's app and AutoFill extension, which
/// peers are compared to.
pub struct Callers {
    #[cfg(target_os = "macos")]
    exe: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    app: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    autofill: Option<PathBuf>,
    /// Their signatures, read with the first peer.
    #[cfg(target_os = "macos")]
    own: Mutex<Option<Own>>,
    cache: Mutex<HashMap<Peer, CallerInfo>>,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Default)]
struct Own {
    exe: Option<CodeSignature>,
    app: Option<CodeSignature>,
    autofill: Option<CodeSignature>,
}

/// One of Deadbolt's own binaries: where it is (canonical) and its
/// signature on disk.
#[cfg_attr(
    not(any(test, target_os = "macos")),
    allow(dead_code, reason = "only macOS can verify a peer's code")
)]
#[derive(Clone, Copy)]
pub struct Known<'a> {
    pub path: &'a Path,
    pub file: Option<&'a CodeSignature>,
}

/// What a peer's class rests on.
#[cfg_attr(
    not(any(test, target_os = "macos")),
    allow(dead_code, reason = "only macOS can verify a peer's code")
)]
pub enum Evidence<'a> {
    /// The running code's signature, the daemon's own binary, the app's and
    /// the macOS AutoFill extension's, and the Apple team that signed this
    /// build (`None` when ad-hoc).
    Signature {
        code: &'a CodeSignature,
        exe: Option<Known<'a>>,
        app: Option<Known<'a>>,
        autofill: Option<Known<'a>>,
        team: Option<&'a str>,
    },
    /// Nothing verified: on Linux, `/proc` names a peer's executable, but a
    /// process can swap what it runs before the daemon looks.
    None,
}

impl Callers {
    pub fn new() -> Self {
        #[cfg(target_os = "macos")]
        let exe = crate::caller::own_exe().ok();
        Callers {
            #[cfg(target_os = "macos")]
            app: exe.as_deref().and_then(app_beside),
            #[cfg(target_os = "macos")]
            autofill: exe.as_deref().and_then(autofill_beside),
            #[cfg(target_os = "macos")]
            exe,
            #[cfg(target_os = "macos")]
            own: Mutex::default(),
            cache: Mutex::default(),
        }
    }

    #[cfg(test)]
    pub fn cache_for_test(&self, peer: Peer, info: CallerInfo) {
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(peer, info);
    }

    /// How the daemon sees `peer`, claiming `claimed`. Blocking: on macOS it
    /// runs `deadbolt-enclave identify` the first time it sees a process.
    pub fn identify(&self, peer: io::Result<Peer>, claimed: Option<Claim>) -> CallerInfo {
        let mut info = match peer {
            Ok(peer) => self.lookup(peer),
            Err(error) => {
                warn!("reading a peer's credentials: {error}");
                unverified(None, "unknown process")
            }
        };
        info.claimed = claimed.filter(|c| !c.is_empty());
        info
    }

    fn lookup(&self, peer: Peer) -> CallerInfo {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(info) = cache.get(&peer) {
            return info.clone();
        }
        drop(cache);
        let (info, keep) = self.read(peer);
        if keep {
            cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if cache.len() >= CACHE_MAX {
                cache.clear();
            }
            cache.insert(peer, info.clone());
        }
        info
    }

    /// The peer's info, and whether it may be remembered.
    #[cfg(target_os = "macos")]
    fn read(&self, peer: Peer) -> (CallerInfo, bool) {
        let helper = match super::biometric::helper() {
            Ok(helper) => helper,
            Err(error) => {
                warn!("can't identify callers: {error:#}");
                return (unverified(Some(peer), "unverified process"), false);
            }
        };
        let own = self.own.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let files: Vec<PathBuf> = match own {
            Some(_) => Vec::new(),
            None => self
                .exe
                .iter()
                .chain(&self.app)
                .chain(&self.autofill)
                .cloned()
                .collect(),
        };
        let found = match deadbolt_client::peer::identify(&helper, peer.token, &files) {
            Ok(Some(found)) => found,
            Ok(None) => return (unverified(Some(peer), "exited process"), false),
            Err(error) => {
                warn!("identifying a caller: {error}");
                return (unverified(Some(peer), "unverified process"), false);
            }
        };
        let own = own.unwrap_or_else(|| {
            let mut files = found.files.iter().cloned();
            let own = Own {
                exe: self.exe.as_ref().and_then(|_| files.next().flatten()),
                app: self.app.as_ref().and_then(|_| files.next().flatten()),
                autofill: self.autofill.as_ref().and_then(|_| files.next().flatten()),
            };
            *self.own.lock().unwrap_or_else(|e| e.into_inner()) = Some(own.clone());
            own
        });
        let process = found.process.unwrap_or_default();
        fn known<'a>(
            path: &'a Option<PathBuf>,
            file: &'a Option<CodeSignature>,
        ) -> Option<Known<'a>> {
            path.as_deref().map(|path| Known {
                path,
                file: file.as_ref(),
            })
        }
        let evidence = match &found.code {
            Some(code) => Evidence::Signature {
                code,
                exe: known(&self.exe, &own.exe),
                app: known(&self.app, &own.app),
                autofill: known(&self.autofill, &own.autofill),
                team: deadbolt_client::peer::team(),
            },
            None => Evidence::None,
        };
        (info(peer, &evidence, process), true)
    }

    /// Labels only, from `/proc`: never the app or the browser host, so
    /// nothing a Linux peer does is taken on its word.
    #[cfg(target_os = "linux")]
    fn read(&self, peer: Peer) -> (CallerInfo, bool) {
        let process = deadbolt_client::peer::linux::process(peer.pid);
        (from_proc(peer, process), true)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn read(&self, peer: Peer) -> (CallerInfo, bool) {
        (unverified(Some(peer), "unverified process"), false)
    }
}

/// The app of the daemon's own bundle, `Deadbolt.app/Contents/MacOS/Deadbolt`
/// for its `Contents/Helpers/deadbolt`, symlinks resolved. Outside a bundle
/// there is none: `deadbolt ui` there runs the daemon's own code under its own
/// identity, so it's a caller like the CLI.
#[cfg(any(test, target_os = "macos"))]
fn app_beside(exe: &Path) -> Option<PathBuf> {
    let dir = exe.parent()?;
    let contents = dir.parent()?;
    if dir.file_name()? != "Helpers" || contents.file_name()? != "Contents" {
        return None;
    }
    let app = contents.join("MacOS/Deadbolt");
    Some(app.canonicalize().unwrap_or(app))
}

/// The AutoFill extension of the daemon's own bundle,
/// `Deadbolt.app/Contents/PlugIns/DeadboltAutoFill.appex/Contents/MacOS/DeadboltAutoFill`
/// for its `Contents/Helpers/deadbolt`, symlinks resolved.
#[cfg(any(test, target_os = "macos"))]
fn autofill_beside(exe: &Path) -> Option<PathBuf> {
    let dir = exe.parent()?;
    let contents = dir.parent()?;
    if dir.file_name()? != "Helpers" || contents.file_name()? != "Contents" {
        return None;
    }
    let ext = contents.join("PlugIns/DeadboltAutoFill.appex/Contents/MacOS/DeadboltAutoFill");
    Some(ext.canonicalize().unwrap_or(ext))
}

/// Whether `args` run `deadbolt browser-host`, as a browser does.
fn browser_host_args(args: &[String]) -> bool {
    match args {
        [_, mode, ..] if mode == "browser-host" => true,
        [_, origin] => origin.starts_with("chrome-extension://"),
        _ => false,
    }
}

/// The class `evidence` supports. Nothing a client says enters here.
///
/// A Developer ID build knows its own code by team and identifier. An
/// ad-hoc build knows it by path and code hash: the peer runs from the
/// daemon's own binary or its bundle's app, and is the code signed there.
/// The app must run from the daemon's bundle either way: its executable is
/// the whole `deadbolt` binary signed as the app, which runs only the app
/// there, but a copy elsewhere would run CLI commands under its signature.
pub fn classify(evidence: &Evidence, args: &[String]) -> (CallerClass, Check) {
    match evidence {
        Evidence::Signature {
            code,
            exe,
            app,
            autofill,
            team,
        } => {
            let is = |known: &Option<Known>, id: &str| match team {
                Some(_) => code.signed_as(None, *team, id),
                None => known.is_some_and(|known| {
                    code.runs_from(known.path) && code.signed_as(known.file, None, id)
                }),
            };
            let in_bundle = app.is_some_and(|known| code.runs_from(known.path));
            let class = if in_bundle && is(app, APP_ID) {
                CallerClass::App
            } else if is(autofill, AUTOFILL_ID) {
                CallerClass::AutoFill
            } else if is(exe, DAEMON_ID) && browser_host_args(args) {
                CallerClass::BrowserHost
            } else {
                CallerClass::Caller
            };
            (class, Check::Signature)
        }
        Evidence::None => (CallerClass::Caller, Check::None),
    }
}

/// A peer's info from what was read about it, without a claim.
pub fn info(peer: Peer, evidence: &Evidence, process: Process) -> CallerInfo {
    let (class, check) = classify(evidence, &process.args);
    let (program, signature): (Option<String>, Option<Signature>) = match evidence {
        Evidence::Signature { code, .. } => (code.path.clone(), Some(code.signature())),
        Evidence::None => (process.exe.clone(), None),
    };
    let label = label(class, program.as_deref(), &process);
    CallerInfo {
        class,
        check,
        pid: peer.pid,
        pid_version: peer.pid_version,
        uid: Some(peer.uid),
        program,
        signature,
        tty: process.tty,
        started: process.started,
        session_started: process.session_started,
        ancestry: process.ancestry,
        label,
        claimed: None,
    }
}

/// A Linux peer's info from `/proc`: a caller, whatever it runs, labelled
/// as unverified wherever the label shows (whoami, Activity, the app).
#[cfg(any(test, target_os = "linux"))]
fn from_proc(peer: Peer, process: Process) -> CallerInfo {
    let mut info = info(peer, &Evidence::None, process);
    info.check = Check::Unverified;
    info.label = format!("{} · {}", info.label, crate::protocol::UNVERIFIED_LINUX);
    info
}

/// Whether the caller looks like an AI: an AI host (OpenCode, Claude Code…)
/// among its parents, or a claim to be an OpenCode session. A hint, never
/// proof: an AI can start a terminal outside its own tree. So it only ever
/// refuses (pairing agent clients, granting sign-ins), never allows.
pub fn is_ai(info: &CallerInfo) -> bool {
    let host = |name: &str| {
        let name = name.trim_start_matches('-');
        HOSTS
            .iter()
            .any(|(host, _)| host.eq_ignore_ascii_case(name))
    };
    info.ancestry.iter().any(|a| {
        host(&a.name)
            || a.path
                .as_deref()
                .and_then(|p| Path::new(p).file_name())
                .is_some_and(|n| host(&n.to_string_lossy()))
    }) || info
        .claimed
        .as_ref()
        .is_some_and(|c| c.opencode_session.is_some())
}

/// The AI host among `info`'s parents ("OpenCode"), if any.
fn ai_host(info: &CallerInfo) -> Option<&'static str> {
    let host = |name: &str| {
        let name = name.trim_start_matches('-');
        HOSTS
            .iter()
            .find(|(host, _)| host.eq_ignore_ascii_case(name))
            .map(|(_, label)| *label)
    };
    info.ancestry.iter().find_map(|a| {
        host(&a.name).or_else(|| {
            a.path
                .as_deref()
                .and_then(|p| Path::new(p).file_name())
                .and_then(|n| host(&n.to_string_lossy()))
        })
    })
}

/// Why the daemon takes `info` for an AI, and where to go instead: for a
/// refusal, so a person in a terminal inside an AI host knows what to do.
pub fn not_from_here(info: &CallerInfo) -> String {
    let why = match ai_host(info) {
        Some(host) => format!("This shell runs under {host} ({})", info.label),
        None => format!("This shell has OPENCODE_SESSION_ID set ({})", info.label),
    };
    format!("{why}; run it from a terminal outside it, or in the app (see `deadbolt debug whoami`)")
}

/// Nobody in particular: a status asked for without a connection.
pub fn nobody() -> CallerInfo {
    CallerInfo::unverified("nobody")
}

fn unverified(peer: Option<Peer>, label: &str) -> CallerInfo {
    let mut info = CallerInfo::unverified(label);
    if let Some(peer) = peer {
        info.pid = peer.pid;
        info.pid_version = peer.pid_version;
        info.uid = Some(peer.uid);
    }
    info
}

/// "OpenCode › zsh › deadbolt": the nearest AI host or app, the nearest
/// shell, then the program.
fn label(class: CallerClass, program: Option<&str>, process: &Process) -> String {
    let base = |path: &str| {
        Path::new(path)
            .file_name()
            .map_or(path.to_string(), |n| n.to_string_lossy().into_owned())
    };
    let bundle = |path: &str| {
        let (before, _) = path.split_once(".app/")?;
        Some(base(before))
    };
    let host = process.ancestry.iter().find_map(|a| {
        HOSTS
            .iter()
            .find(|(name, _)| a.name == *name)
            .map(|(_, label)| (*label).to_string())
            .or_else(|| a.path.as_deref().and_then(bundle))
    });
    match class {
        CallerClass::App => return "Deadbolt".into(),
        CallerClass::AutoFill => return "macOS AutoFill".into(),
        CallerClass::BrowserHost => {
            return match host {
                Some(browser) => format!("browser host ({browser})"),
                None => "browser host".into(),
            };
        }
        CallerClass::Caller => {}
    }
    let shell = process
        .ancestry
        .iter()
        .map(|a| a.name.trim_start_matches('-'))
        .find(|name| SHELLS.contains(name))
        .map(str::to_string);
    // The app outside a bundle is this binary run as `deadbolt ui` (labels
    // only: a process can rewrite its own arguments).
    let ui = process.args.get(1).is_some_and(|a| a == crate::app::UI);
    let program = program.map(|p| {
        if ui {
            format!("{} ui", base(p))
        } else {
            base(p)
        }
    });
    let mut parts: Vec<String> = Vec::new();
    for part in [host, shell, program].into_iter().flatten() {
        if parts.last() != Some(&part) {
            parts.push(part);
        }
    }
    if parts.is_empty() {
        "unknown process".into()
    } else {
        parts.join(" › ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Ancestor;

    fn peer(pid: u32, version: u32) -> Peer {
        Peer::from_token([501, 501, 20, 501, 20, pid, 100_000, version])
    }

    fn ancestor(pid: u32, name: &str, path: &str) -> Ancestor {
        Ancestor {
            pid,
            name: name.into(),
            path: Some(path.into()),
        }
    }

    /// A pid the kernel hands to a new process is a new caller: the cache is
    /// keyed by the whole audit token, pid version included.
    #[test]
    fn a_reused_pid_is_not_the_same_caller() {
        let callers = Callers::new();
        let first = peer(4242, 7);
        let mut known = unverified(Some(first), "Deadbolt");
        known.class = CallerClass::App;
        callers.cache.lock().unwrap().insert(first, known);
        assert_eq!(callers.lookup(first).class, CallerClass::App);

        let reused = peer(4242, 8);
        let seen = callers.lookup(reused);
        assert_eq!(seen.class, CallerClass::Caller);
        assert_eq!(seen.pid_version, Some(8));
    }

    /// Whatever a client claims, its class comes from its code alone.
    #[test]
    fn an_ai_host_among_the_parents_or_an_opencode_claim_is_an_ai() {
        let mut info = CallerInfo::unverified("zsh › deadbolt");
        info.ancestry = vec![ancestor(10, "zsh", "/bin/zsh")];
        assert!(!is_ai(&info));
        info.ancestry.push(ancestor(
            9,
            "opencode-cli",
            "/Users/k/.opencode/bin/opencode-cli",
        ));
        assert!(is_ai(&info));
        info.ancestry = vec![ancestor(9, "node", "/opt/homebrew/bin/claude")];
        assert!(is_ai(&info));
        info.ancestry = vec![ancestor(10, "-zsh", "/bin/zsh")];
        info.claimed = Some(Claim {
            caller: Some("me".into()),
            opencode_session: None,
        });
        assert!(!is_ai(&info));
        info.claimed = Some(Claim {
            caller: None,
            opencode_session: Some("ses_1".into()),
        });
        assert!(is_ai(&info));
    }

    #[test]
    fn a_claim_never_upgrades_the_class() {
        let callers = Callers::new();
        let someone = peer(4343, 1);
        callers
            .cache
            .lock()
            .unwrap()
            .insert(someone, unverified(Some(someone), "zsh › deadbolt"));
        for name in ["Deadbolt", "Deadbolt.app", "app", "browser-host"] {
            let claim = Claim {
                caller: Some(name.into()),
                opencode_session: Some("ses_1".into()),
            };
            let info = callers.identify(Ok(someone), Some(claim.clone()));
            assert_eq!(info.class, CallerClass::Caller);
            assert_eq!(info.label, "zsh › deadbolt");
            assert_eq!(info.claimed, Some(claim));
        }
    }

    fn at(path: &Path, cdhash: &str, team: Option<&str>, id: &str) -> CodeSignature {
        CodeSignature {
            path: Some(path.display().to_string()),
            signing_id: Some(id.into()),
            team_id: team.map(Into::into),
            cdhash: Some(cdhash.into()),
            valid: true,
        }
    }

    /// An ad-hoc build's app is the code at its own bundle's app path: the
    /// same bytes run from anywhere else are a caller, as is other code
    /// there. The browser host is the daemon's own binary, run as one.
    #[test]
    fn the_app_is_the_code_in_the_daemons_own_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let app_path = root.join("MacOS/Deadbolt");
        let autofill_path =
            root.join("PlugIns/DeadboltAutoFill.appex/Contents/MacOS/DeadboltAutoFill");
        let exe_path = root.join("Helpers/deadbolt");
        let elsewhere = root.join("Copy");
        for path in [&app_path, &autofill_path, &exe_path, &elsewhere] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"").unwrap();
        }
        let app_file = at(&app_path, "a1", None, APP_ID);
        let autofill_file = at(&autofill_path, "af1", None, AUTOFILL_ID);
        let exe_file = at(&exe_path, "e1", None, DAEMON_ID);
        let class_of = |code: CodeSignature, args: &[String]| {
            let evidence = Evidence::Signature {
                code: &code,
                exe: Some(Known {
                    path: &exe_path,
                    file: Some(&exe_file),
                }),
                app: Some(Known {
                    path: &app_path,
                    file: Some(&app_file),
                }),
                autofill: Some(Known {
                    path: &autofill_path,
                    file: Some(&autofill_file),
                }),
                team: None,
            };
            classify(&evidence, args).0
        };
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            class_of(at(&app_path, "a1", None, "x"), &[]),
            CallerClass::App
        );
        assert_eq!(
            class_of(at(&autofill_path, "af1", None, "x"), &[]),
            CallerClass::AutoFill
        );
        assert_eq!(
            class_of(at(&elsewhere, "af1", None, AUTOFILL_ID), &[]),
            CallerClass::Caller
        );
        // A relocated copy of the app, byte for byte, is a caller.
        assert_eq!(
            class_of(at(&elsewhere, "a1", None, APP_ID), &[]),
            CallerClass::Caller
        );
        assert_eq!(
            class_of(at(&app_path, "zz", None, APP_ID), &[]),
            CallerClass::Caller
        );
        let mut forged = at(&app_path, "a1", None, APP_ID);
        forged.valid = false;
        assert_eq!(class_of(forged, &[]), CallerClass::Caller);

        let host = args(&["deadbolt", "chrome-extension://abc/"]);
        assert_eq!(
            class_of(at(&exe_path, "e1", None, "x"), &host),
            CallerClass::BrowserHost
        );
        let mode = args(&["deadbolt", "browser-host", "chrome-extension://abc/"]);
        assert_eq!(
            class_of(at(&exe_path, "e1", None, "x"), &mode),
            CallerClass::BrowserHost
        );
        // The same binary running anything else is a caller, and so is any
        // other code saying it's the browser host.
        let cli = args(&["deadbolt", "get", "github"]);
        assert_eq!(
            class_of(at(&exe_path, "e1", None, "x"), &cli),
            CallerClass::Caller
        );
        assert_eq!(
            class_of(at(&elsewhere, "e1", None, "x"), &host),
            CallerClass::Caller
        );
        assert_eq!(
            classify(&Evidence::None, &host),
            (CallerClass::Caller, Check::None)
        );
    }

    /// A Developer ID build's app is the app its own team signed as
    /// `pw.deadbolt.app`, and nothing ad-hoc, run from the daemon's bundle:
    /// that executable is the whole `deadbolt`, so a copy elsewhere could run
    /// CLI commands under the app's signature.
    #[test]
    fn a_signed_build_knows_its_app_by_team_and_identifier_in_its_bundle() {
        let team = Some("TEAM123456");
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let path = root.join("MacOS/Deadbolt");
        let elsewhere = root.join("Copy");
        for file in [&path, &elsewhere] {
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, b"").unwrap();
        }
        let class_of = |code: CodeSignature, args: &[String]| {
            let evidence = Evidence::Signature {
                code: &code,
                exe: None,
                app: Some(Known {
                    path: &path,
                    file: None,
                }),
                autofill: None,
                team,
            };
            classify(&evidence, args).0
        };
        assert_eq!(
            class_of(at(&path, "a1", team, APP_ID), &[]),
            CallerClass::App
        );
        assert_eq!(
            class_of(at(&elsewhere, "a1", team, APP_ID), &[]),
            CallerClass::Caller
        );
        assert_eq!(
            class_of(at(&elsewhere, "af1", team, AUTOFILL_ID), &[]),
            CallerClass::AutoFill
        );
        assert_eq!(
            class_of(at(&elsewhere, "af1", None, AUTOFILL_ID), &[]),
            CallerClass::Caller
        );
        assert_eq!(
            class_of(at(&path, "a1", None, APP_ID), &[]),
            CallerClass::Caller
        );
        let other = Some("OTHER12345");
        assert_eq!(
            class_of(at(&path, "a1", other, APP_ID), &[]),
            CallerClass::Caller
        );
        assert_eq!(
            class_of(at(&path, "a1", team, DAEMON_ID), &[]),
            CallerClass::Caller
        );
        let host = vec!["deadbolt".into(), "chrome-extension://abc/".into()];
        assert_eq!(
            class_of(at(&elsewhere, "e1", team, DAEMON_ID), &host),
            CallerClass::BrowserHost
        );
        // Without a bundle beside the daemon, nothing is the app.
        let evidence = Evidence::Signature {
            code: &at(&path, "a1", team, APP_ID),
            exe: None,
            app: None,
            autofill: None,
            team,
        };
        assert_eq!(classify(&evidence, &[]).0, CallerClass::Caller);
    }

    /// Linux names a peer's program from `/proc`, which a process can race:
    /// even one running the app's path is a caller, marked unverified.
    #[test]
    fn a_linux_peer_is_an_unverified_caller() {
        let process = Process {
            exe: Some("/usr/lib/deadbolt/deadbolt-ui".into()),
            args: vec!["deadbolt".into(), "chrome-extension://abc/".into()],
            ..Process::default()
        };
        let info = from_proc(peer(77, 1), process);
        assert_eq!(info.class, CallerClass::Caller);
        assert_eq!(info.check, Check::Unverified);
        assert_eq!(
            info.program.as_deref(),
            Some("/usr/lib/deadbolt/deadbolt-ui")
        );
        assert_eq!(info.label, "deadbolt-ui · unverified (Linux)");
        let app = Process {
            exe: Some("/home/kit/.local/bin/deadbolt".into()),
            args: vec!["deadbolt".into(), "ui".into()],
            ..Process::default()
        };
        let info = from_proc(peer(78, 1), app);
        assert_eq!(info.class, CallerClass::Caller);
        assert_eq!(info.label, "deadbolt ui · unverified (Linux)");
    }

    #[test]
    fn labels_name_the_host_and_the_shell() {
        let process = Process {
            ancestry: vec![
                ancestor(10, "-zsh", "/bin/zsh"),
                ancestor(9, "login", "/usr/bin/login"),
                ancestor(
                    8,
                    "ghostty",
                    "/Applications/Ghostty.app/Contents/MacOS/ghostty",
                ),
                ancestor(1, "launchd", "/sbin/launchd"),
            ],
            ..Process::default()
        };
        let label =
            |class, process: &Process| super::label(class, Some("/opt/bin/deadbolt"), process);
        assert_eq!(
            label(CallerClass::Caller, &process),
            "Ghostty › zsh › deadbolt"
        );
        let opencode = Process {
            ancestry: vec![
                ancestor(20, "zsh", "/bin/zsh"),
                ancestor(19, "opencode-cli", "/Users/k/opencode-cli"),
            ],
            ..Process::default()
        };
        assert_eq!(
            label(CallerClass::Caller, &opencode),
            "OpenCode › zsh › deadbolt"
        );
        let brave = Process {
            ancestry: vec![ancestor(
                30,
                "Brave Browser",
                "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            )],
            ..Process::default()
        };
        assert_eq!(
            label(CallerClass::BrowserHost, &brave),
            "browser host (Brave Browser)"
        );
        assert_eq!(label(CallerClass::App, &brave), "Deadbolt");
        assert_eq!(label(CallerClass::AutoFill, &brave), "macOS AutoFill");
    }

    #[test]
    fn the_app_sits_beside_the_daemon() {
        assert_eq!(
            app_beside(Path::new("/A/Deadbolt.app/Contents/Helpers/deadbolt")),
            Some(PathBuf::from("/A/Deadbolt.app/Contents/MacOS/Deadbolt"))
        );
        assert_eq!(
            autofill_beside(Path::new("/A/Deadbolt.app/Contents/Helpers/deadbolt")),
            Some(PathBuf::from(
                "/A/Deadbolt.app/Contents/PlugIns/DeadboltAutoFill.appex/Contents/MacOS/DeadboltAutoFill"
            ))
        );
        assert_eq!(autofill_beside(Path::new("/w/target/debug/deadbolt")), None);
        // Outside a bundle there's no app, development builds included.
        assert_eq!(app_beside(Path::new("/w/target/debug/deadbolt")), None);
    }

    /// The CLI and the app send a passphrase only to a daemon running the
    /// binary they expect, from that very path: the same bytes copied
    /// elsewhere aren't it.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_daemon_check_wants_that_very_binary() {
        let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let helper = super::super::biometric::helper().unwrap();
        let me = crate::caller::own_exe().unwrap();
        deadbolt_client::peer::check(&ours, &helper, &me).unwrap();
        let other = std::fs::canonicalize("/bin/sh").unwrap();
        let refused = deadbolt_client::peer::check(&ours, &helper, &other).unwrap_err();
        assert!(refused.contains("not /bin/sh"), "{refused}");

        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("deadbolt");
        std::fs::copy(&me, &copy).unwrap();
        let refused = deadbolt_client::peer::check(&ours, &helper, &copy).unwrap_err();
        assert!(refused.contains("not "), "a copy is refused: {refused}");

        let gone = dir.path().join("deadbolt-enclave");
        let refused = deadbolt_client::peer::check(&ours, &gone, &me).unwrap_err();
        assert!(
            refused.contains(&format!("{} is missing", gone.display())),
            "{refused}"
        );
    }

    /// The helper looks code up by the whole audit token: once a pid
    /// version is gone, the token names nobody, even if the pid lives on.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_helper_refuses_a_token_from_another_pid_version() {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let me = Peer::of(&ours).unwrap();
        drop(theirs);
        assert_eq!(me.pid, std::process::id());
        let helper = super::super::biometric::helper().unwrap();
        let found = deadbolt_client::peer::identify(&helper, me.token, &[])
            .unwrap()
            .expect("our own token names us");
        let process = found.process.unwrap();
        assert!(found.code.unwrap().cdhash.is_some());
        assert!(!process.args.is_empty());

        let mut token = me.token.unwrap();
        token[7] = token[7].wrapping_add(1);
        assert!(
            deadbolt_client::peer::identify(&helper, Some(token), &[])
                .unwrap()
                .is_none()
        );
    }
}
