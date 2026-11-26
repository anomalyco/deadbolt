//! Who holds the other end of a Unix socket, from the kernel rather than
//! from anything the peer says. macOS gives the audit token
//! (`LOCAL_PEERTOKEN`), by which Security.framework looks the running code's
//! signature up, in process (`peer/macos.rs`). Linux gives `SO_PEERCRED`, and
//! `/proc` the rest.

use std::io;
use std::os::fd::AsFd;
use std::path::Path;

use deadbolt_proto::daemon::{Ancestor, Signature};

pub mod ancestry;
#[cfg(target_os = "macos")]
pub mod macos;

/// A cache hit still has to name living code with that exact pid version.
#[cfg(target_os = "macos")]
pub fn live_token(token: &[u32; 8]) -> bool {
    macos::live_token(token)
}

/// The kernel's word for a socket's peer, taken when it connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Peer {
    pub pid: u32,
    pub uid: u32,
    /// The audit token (macOS), which names the process even after its pid
    /// is reused: Security.framework refuses a token whose process is gone.
    pub token: Option<[u32; 8]>,
    /// The token's pid version (macOS), or the start time in clock ticks
    /// (Linux, read from `/proc` after the fact).
    pub pid_version: Option<u64>,
}

impl Peer {
    #[cfg(target_os = "macos")]
    pub fn of(socket: &impl AsFd) -> io::Result<Peer> {
        let token = deadbolt_os::net::local_peer_token(socket.as_fd())?;
        Ok(Self::from_token(token))
    }

    /// An audit token's fields: euid at 1, pid at 5, pid version at 7.
    pub fn from_token(token: [u32; 8]) -> Peer {
        Peer {
            pid: token[5],
            uid: token[1],
            token: Some(token),
            pid_version: Some(u64::from(token[7])),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn of(socket: &impl AsFd) -> io::Result<Peer> {
        let creds = deadbolt_os::net::peer_credentials(socket.as_fd())?;
        let pid = u32::try_from(creds.pid).map_err(|_| io::Error::other("no peer pid"))?;
        Ok(Peer {
            pid,
            uid: creds.uid,
            token: None,
            pid_version: linux::stat(pid).map(|s| s.start_ticks),
        })
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub fn of(_socket: &impl AsFd) -> io::Result<Peer> {
        Err(io::Error::other("peer credentials are not supported here"))
    }
}

/// The uid of `socket`'s peer, from the kernel. Unlike [`Peer::of`] on
/// macOS (whose audit token is gone once the peer hangs up), it's there for
/// as long as the socket is.
#[cfg(target_os = "macos")]
pub fn uid(socket: &impl AsFd) -> io::Result<u32> {
    deadbolt_os::net::local_peer_uid(socket.as_fd())
}

#[cfg(target_os = "linux")]
pub fn uid(socket: &impl AsFd) -> io::Result<u32> {
    Ok(deadbolt_os::net::peer_credentials(socket.as_fd())?.uid)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn uid(_socket: &impl AsFd) -> io::Result<u32> {
    Err(io::Error::other("peer credentials are not supported here"))
}

/// A code signature as Security.framework read it, from a running process
/// or a file.
#[derive(Debug, Clone, Default)]
pub struct CodeSignature {
    /// The main executable, inside the bundle for an app.
    pub path: Option<String>,
    pub signing_id: Option<String>,
    /// Only when the signature chains to Apple for this team.
    pub team_id: Option<String>,
    /// The code directory hash, lowercase hex.
    pub cdhash: Option<String>,
    pub valid: bool,
}

impl CodeSignature {
    pub fn signature(&self) -> Signature {
        Signature {
            signing_id: self.signing_id.clone(),
            team_id: self.team_id.clone(),
            cdhash: self.cdhash.clone(),
            valid: self.valid,
        }
    }

    /// Whether `self` (a running process) runs from `expected` (canonical)
    /// itself, symlinks resolved, rather than a copy somewhere else.
    pub fn runs_from(&self, expected: &Path) -> bool {
        let running = self.path.as_deref().map(Path::new);
        running.and_then(|p| p.canonicalize().ok()).as_deref() == Some(expected)
    }

    /// Whether `self` (a running process) is Deadbolt's code `id`: signed by
    /// `team` under `id` for a Developer ID build, else (`team` is `None`,
    /// an ad-hoc build) the code directory of `file`, the signature on disk
    /// of the binary it should be. Anything unsigned or invalid never is.
    pub fn signed_as(&self, file: Option<&CodeSignature>, team: Option<&str>, id: &str) -> bool {
        if !self.valid {
            return false;
        }
        match team {
            Some(team) => {
                self.team_id.as_deref() == Some(team) && self.signing_id.as_deref() == Some(id)
            }
            None => file.is_some_and(|file| {
                file.valid && file.cdhash.is_some() && file.cdhash == self.cdhash
            }),
        }
    }
}

/// What the peer's process says about itself, read by pid. Labels only:
/// the process can change its own arguments, and its parents come and go.
#[derive(Debug, Clone, Default)]
pub struct Process {
    pub ppid: Option<u32>,
    /// Unix seconds.
    pub started: Option<u64>,
    pub tty: Option<String>,
    /// When its session (its terminal tab, for a shell) started, Unix seconds.
    pub session_started: Option<u64>,
    pub args: Vec<String>,
    /// Nearest first, up to launchd (or init).
    pub ancestry: Vec<Ancestor>,
    /// Reached init, or an unlisted hidepid boundary.
    pub ancestry_complete: bool,
    /// The executable (Linux; on macOS it's the signature's `path`).
    pub exe: Option<String>,
}

/// The Apple team that signed this build, compiled in (`build.rs`); `None`
/// for an ad-hoc build, whose code is known by path and code hash instead.
pub fn team() -> Option<&'static str> {
    Some(env!("DEADBOLT_TEAM_ID")).filter(|t| !t.is_empty())
}

/// The signing identifier of Deadbolt's daemon (`Contents/Helpers/deadbolt`,
/// and the CLI), as `bundle.sh` and the release (`.github/release/lib.sh`'s
/// `DEADBOLT_CLI_ID`) sign it.
pub const DAEMON_ID: &str = "anomaly.deadbolt.cli";
/// The signing identifier of Deadbolt.app, its bundle identifier.
pub const APP_ID: &str = "anomaly.deadbolt";
/// The signing identifier of Deadbolt's macOS AutoFill extension
/// (`Contents/PlugIns/DeadboltAutoFill.appex`), its bundle identifier.
pub const AUTOFILL_ID: &str = "anomaly.deadbolt.autofill";
/// The suffix of Deadbolt's macOS App Group (`<TEAM_ID>.anomaly.deadbolt`).
pub const APP_GROUP_SUFFIX: &str = "anomaly.deadbolt";

/// The macOS App Group shared with `DeadboltAutoFill.appex`, when this build
/// knows its Apple team (`DEADBOLT_TEAM_ID`).
pub fn app_group() -> Option<String> {
    team().map(|t| format!("{t}.{APP_GROUP_SUFFIX}"))
}

/// Which daemon [`check`] accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepted {
    /// The daemon at `expected` itself, or any daemon off macOS, where
    /// nothing tells.
    Expected,
    /// Another daemon this build's team signed: a Homebrew or npm
    /// `deadbolt`'s, or Deadbolt.app's. It checks its own `deadbolt-enclave`
    /// against its own pin.
    Elsewhere,
}

/// Checks that `socket`'s peer is Deadbolt's daemon, before a passphrase goes
/// to it. `expected` is the daemon this client would run (its own binary, or
/// its bundle's helper).
///
/// On macOS the peer's code is looked up by its audit token and must be
/// Deadbolt's daemon by signature (`daemon_is`): any daemon its team signed,
/// for a Developer ID build, else `expected` itself, not a copy elsewhere.
/// On Linux nothing tells two processes of one user apart, so this checks
/// only that the peer runs as this user; the socket's 0700 directory is what
/// keeps others out.
pub fn check(socket: &impl AsFd, expected: &Path) -> Result<Accepted, String> {
    let peer = Peer::of(socket).map_err(|e| format!("reading the daemon's credentials: {e}"))?;
    if peer.uid != rustix::process::getuid().as_raw() {
        return Err(format!(
            "the daemon (pid {}) runs as another user",
            peer.pid
        ));
    }
    #[cfg(target_os = "macos")]
    {
        let expected = expected
            .canonicalize()
            .map_err(|e| format!("locating {}: {e}", expected.display()))?;
        let Some(code) = peer.token.as_ref().and_then(macos::running) else {
            return Err(format!("the daemon (pid {}) exited", peer.pid));
        };
        let file = macos::file_signature(&expected);
        daemon_is(&code, file.as_ref(), &expected, team()).map_err(|why| {
            format!(
                "the daemon (pid {}) {why}; run `deadbolt debug daemon stop`",
                peer.pid
            )
        })?;
        Ok(if code.runs_from(&expected) {
            Accepted::Expected
        } else {
            Accepted::Elsewhere
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = expected;
        Ok(Accepted::Expected)
    }
}

/// What Deadbolt says when its `deadbolt-enclave` isn't where it belongs.
pub fn missing_helper(helper: &Path) -> String {
    format!(
        "{} is missing: Deadbolt uses it for Touch ID. \
         Reinstall Deadbolt so deadbolt-enclave sits beside deadbolt",
        helper.display()
    )
}

/// Whether running `code` is Deadbolt's daemon. A Developer ID build knows
/// it by `team` and [`DAEMON_ID`] wherever it runs, so a Homebrew or npm
/// `deadbolt` and `/Applications/Deadbolt.app` share one daemon, whichever
/// started it. An ad-hoc build knows it only as the daemon at `expected`
/// (canonical): it runs from that very file, with the code hash of `file`,
/// the signature on disk there.
pub fn daemon_is(
    code: &CodeSignature,
    file: Option<&CodeSignature>,
    expected: &Path,
    team: Option<&str>,
) -> Result<(), String> {
    if team.is_none() && !code.runs_from(expected) {
        let running = code.path.as_deref().unwrap_or("an unknown program");
        return Err(format!("runs {running}, not {}", expected.display()));
    }
    if code.signed_as(file, team, DAEMON_ID) {
        Ok(())
    } else {
        Err(format!("isn't the code signed as {}", expected.display()))
    }
}

#[cfg(target_os = "linux")]
pub mod linux {
    //! `/proc`, for what macOS reads with `proc_pidinfo`.

    use std::{
        fs, io,
        path::{Path, PathBuf},
    };

    pub use super::ancestry::Hidden;
    use super::ancestry::{Facts, collect_ancestry};
    use super::{Ancestor, Process};

    /// `/proc/<pid>/stat`, the fields we use.
    pub struct Stat {
        pub name: String,
        pub ppid: u32,
        pub session: u32,
        pub tty_nr: u32,
        /// Clock ticks after boot.
        pub start_ticks: u64,
    }

    /// A live process's stat, `None` once it is dead. A thread-group leader
    /// that called `pthread_exit` shows `Z` while its other threads run:
    /// the process is alive, keeps its pid, parent and start time, and its
    /// children still name it, so it reads as alive.
    pub fn stat(pid: u32) -> Option<Stat> {
        stat_in(Path::new("/proc"), pid)
    }

    pub(super) fn stat_in(proc: &Path, pid: u32) -> Option<Stat> {
        let text = fs::read_to_string(proc.join(format!("{pid}/stat"))).ok()?;
        let (state, stat) = parse_stat(&text)?;
        match state {
            "X" => None,
            "Z" if !live_thread(proc, pid) => None,
            _ => Some(stat),
        }
    }

    /// Whether any of `pid`'s threads is still running.
    fn live_thread(proc: &Path, pid: u32) -> bool {
        let Ok(tasks) = fs::read_dir(proc.join(format!("{pid}/task"))) else {
            return false;
        };
        tasks.filter_map(Result::ok).any(|task| {
            fs::read_to_string(task.path().join("stat"))
                .ok()
                .and_then(|text| parse_stat(&text).map(|(state, _)| state != "Z" && state != "X"))
                .unwrap_or(false)
        })
    }

    /// A `stat` line's state and fields.
    fn parse_stat(text: &str) -> Option<(&str, Stat)> {
        let open = text.find('(')?;
        let close = text.rfind(')')?;
        let name = text.get(open + 1..close)?.to_string();
        // After the name: state ppid pgrp session tty_nr ... starttime (22nd).
        let rest: Vec<&str> = text.get(close + 1..)?.split_whitespace().collect();
        let state = *rest.first()?;
        Some((
            state,
            Stat {
                name,
                ppid: rest.get(1)?.parse().ok()?,
                session: rest.get(3)?.parse().ok()?,
                tty_nr: rest.get(4)?.parse().ok()?,
                start_ticks: rest.get(19)?.parse().ok()?,
            },
        ))
    }

    pub fn exe(pid: u32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }

    fn boot_time() -> Option<u64> {
        let text = std::fs::read_to_string("/proc/stat").ok()?;
        text.lines()
            .find_map(|line| line.strip_prefix("btime "))
            .and_then(|t| t.trim().parse().ok())
    }

    /// `/proc` reports times in USER_HZ, which is 100 on every Linux.
    fn unix(start_ticks: u64, boot: Option<u64>) -> Option<u64> {
        boot.map(|boot| boot + start_ticks / 100)
    }

    fn tty(tty_nr: u32) -> Option<String> {
        let major = (tty_nr >> 8) & 0xfff;
        let minor = (tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00);
        match major {
            0 => None,
            136..=143 => Some(format!("/dev/pts/{}", (major - 136) * 256 + minor)),
            4 => Some(format!("/dev/tty{minor}")),
            _ => Some(format!("tty {major}:{minor}")),
        }
    }

    /// `/proc/<pid>/cmdline`'s arguments: each ends in a NUL (unless the
    /// process rewrote them), and any of them may be empty.
    pub fn args(raw: &[u8]) -> Vec<String> {
        if raw.is_empty() {
            return Vec::new();
        }
        raw.strip_suffix(&[0])
            .unwrap_or(raw)
            .split(|b| *b == 0)
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect()
    }

    pub(super) fn walk(
        pid: u32,
        next: u32,
        child_start: u64,
        mut parent: impl FnMut(u32) -> Option<(Ancestor, u32, u64)>,
        mut hidden: impl FnMut(u32, u32, u64) -> Option<Hidden>,
    ) -> (Vec<Ancestor>, bool) {
        collect_ancestry(
            pid,
            next,
            (child_start, 0),
            1024,
            |p| {
                let (entry, ppid, start) = parent(p)?;
                Some((
                    entry,
                    Facts {
                        ppid,
                        start: (start, 0),
                    },
                ))
            },
            |p, c, s| hidden(p, c, s.0),
        )
    }

    /// A missing stat is not enough: the pid must still exist, be invisible
    /// on this hidepid mount, and still parent the same child after the scan.
    /// Both EPERM (root sshd) and a successful signal-zero probe (the hidden
    /// user-owned sshd session process) establish existence, not ancestry.
    pub fn hidden_parent(parent: u32, child: u32, child_start: u64) -> Option<Hidden> {
        let pid = rustix::process::Pid::from_raw(parent as i32)?;
        let hidden = matches!(
            rustix::process::test_kill_process(pid),
            Ok(()) | Err(rustix::io::Errno::PERM)
        ) && std::fs::metadata(format!("/proc/{parent}"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            && std::fs::read_to_string("/proc/self/mounts").is_ok_and(|mounts| {
                mounts.lines().any(|line| {
                    let mut fields = line.split_whitespace().skip(1);
                    fields.next() == Some("/proc")
                        && fields.next() == Some("proc")
                        && fields.next().is_some_and(|opts| {
                            opts.split(',')
                                .any(|o| matches!(o, "hidepid=2" | "hidepid=invisible"))
                        })
                })
            });
        if !hidden {
            return None;
        }
        let link = reverse_parent(Path::new("/proc"), parent).ok()?;
        // Don't use the reverse lookup if the original edge went away
        // while enumerating tasks (including a reused child pid).
        stat(child).filter(|s| s.ppid == parent && s.start_ticks == child_start)?;
        Some(link)
    }

    /// Find the visible process that forked a hidden pid. Children belong
    /// to individual threads; looking only at thread-group leaders misses
    /// helpers started on worker threads. An unreadable scan is not proof
    /// of a system boundary.
    pub(super) fn reverse_parent(proc: &Path, hidden: u32) -> io::Result<Hidden> {
        // Explicit probe: ENOENT here can mean CONFIG_PROC_CHILDREN is off.
        fs::File::open(proc.join("thread-self/children"))?;
        for process in fs::read_dir(proc)? {
            let process = process?;
            let Some(pid) = process
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            let tasks = match fs::read_dir(process.path().join("task")) {
                Err(e)
                    if e.kind() == io::ErrorKind::NotFound && !process.path().try_exists()? =>
                {
                    continue;
                }
                result => result?,
            };
            for thread in tasks {
                let path = thread?.path();
                let children = match fs::read_to_string(path.join("children")) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound && !path.try_exists()? => {
                        continue;
                    }
                    result => result?,
                };
                for child in children.split_ascii_whitespace() {
                    if child.parse::<u32>().map_err(io::Error::other)? == hidden {
                        return Ok(Hidden::VisibleParent(pid));
                    }
                }
            }
        }
        Ok(Hidden::SystemBoundary)
    }

    pub fn process(peer: super::Peer) -> Process {
        let pid = peer.pid;
        let Some(me) = stat(pid).filter(|s| Some(s.start_ticks) == peer.pid_version) else {
            return Process::default();
        };
        let boot = boot_time();
        let args = std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|raw| args(&raw))
            .unwrap_or_default();
        let (ancestry, ancestry_complete) = walk(
            pid,
            me.ppid,
            me.start_ticks,
            |next| {
                let parent = stat(next)?;
                Some((
                    Ancestor {
                        pid: next,
                        name: parent.name,
                        path: exe(next).map(|p| p.display().to_string()),
                    },
                    parent.ppid,
                    parent.start_ticks,
                ))
            },
            hidden_parent,
        );
        let exe = exe(pid).map(|p| p.display().to_string());
        // A socket can outlive its connecting process. Don't attribute facts
        // collected by pid to a replacement process or an exited peer.
        if stat(pid).is_none_or(|s| s.start_ticks != me.start_ticks) {
            return Process::default();
        }
        Process {
            ppid: Some(me.ppid),
            started: unix(me.start_ticks, boot),
            tty: tty(me.tty_nr),
            session_started: stat(me.session).and_then(|leader| unix(leader.start_ticks, boot)),
            args,
            ancestry,
            ancestry_complete,
            exe,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{CodeSignature, DAEMON_ID, daemon_is};

    fn sig(cdhash: &str, team: Option<&str>, id: &str, valid: bool) -> CodeSignature {
        CodeSignature {
            path: None,
            signing_id: Some(id.into()),
            team_id: team.map(Into::into),
            cdhash: Some(cdhash.into()),
            valid,
        }
    }

    /// Empty arguments are arguments: none is dropped, so nothing after
    /// them moves up a place.
    #[cfg(target_os = "linux")]
    #[test]
    fn empty_arguments_keep_their_place() {
        assert_eq!(
            super::linux::args(b"\0browser-host\0chrome-extension://x/\0"),
            ["", "browser-host", "chrome-extension://x/"]
        );
        assert_eq!(super::linux::args(b"ls\0\0"), ["ls", ""]);
        assert!(super::linux::args(b"").is_empty());
    }

    /// A leader that exited while another thread runs is a zombie in
    /// `/proc/<pid>/stat` but alive in `/proc/<pid>/task`: it reads as alive,
    /// with its parent and start time. Only when every thread is gone is it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_zombie_leader_with_a_live_thread_is_alive() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path();
        let line = |pid: u32, state: &str| {
            format!(
                "{pid} (we (ird) name) {state} 20 7 7 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 2 0 4242 0 0"
            )
        };
        let write = |path: String, text: String| {
            let path = proc.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        };
        write("30/stat".into(), line(30, "Z"));
        write("30/task/30/stat".into(), line(30, "Z"));
        write("30/task/31/stat".into(), line(31, "S"));
        let alive = super::linux::stat_in(proc, 30).expect("a live thread keeps it alive");
        assert_eq!((alive.ppid, alive.start_ticks), (20, 4242));
        assert_eq!(alive.name, "we (ird) name");

        write("30/task/31/stat".into(), line(31, "X"));
        assert!(
            super::linux::stat_in(proc, 30).is_none(),
            "every thread dead"
        );
        write("40/stat".into(), line(40, "Z"));
        assert!(super::linux::stat_in(proc, 40).is_none(), "no task dir");
        write("50/stat".into(), line(50, "X"));
        write("50/task/51/stat".into(), line(51, "S"));
        assert!(super::linux::stat_in(proc, 50).is_none(), "dead is dead");
        write("60/stat".into(), line(60, "R"));
        assert_eq!(super::linux::stat_in(proc, 60).unwrap().ppid, 20);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_parent_walk_reports_only_chains_that_reach_init_as_complete() {
        let parent = |pid| super::Ancestor {
            pid,
            name: format!("p{pid}"),
            path: None,
        };
        let visible = |p| Some((parent(p), p - 1, u64::from(p)));
        let gone = |_, _, _| None;
        let (deep, complete) = super::linux::walk(36, 35, 36, visible, gone);
        assert!(complete);
        assert_eq!(deep.len(), 35);
        assert_eq!(deep.last().unwrap().pid, 1);
        let until_hidden = |p| if p == 3 { None } else { visible(p) };
        assert!(!super::linux::walk(36, 35, 36, until_hidden, gone).1);
        let (seen, complete) = super::linux::walk(36, 35, 36, until_hidden, |p, c, start| {
            (p == 3 && c == 4 && start == 4).then_some(super::linux::Hidden::SystemBoundary)
        });
        assert!(complete);
        assert_eq!(seen.last().unwrap().pid, 4);
        assert!(!super::linux::walk(36, 35, 36, |p| Some((parent(p), 35, 1)), gone).1);
        assert!(!super::linux::walk(2000, 1999, 2000, visible, gone).1);
        assert!(!super::linux::walk(36, 35, 36, |p| Some((parent(p), 1, 37)), gone).1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hidepid_follows_children_of_non_leader_threads_or_fails_closed() {
        use super::linux::{Hidden, reverse_parent, walk};
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir(root.join("thread-self")).unwrap();
        fs::write(root.join("thread-self/children"), "").unwrap();
        for (tid, children) in [(20, ""), (21, "24 30 ")] {
            let task = root.join(format!("20/task/{tid}"));
            fs::create_dir_all(&task).unwrap();
            fs::write(task.join("children"), children).unwrap();
        }
        let run = || {
            walk(
                40,
                30,
                40,
                |p| match p {
                    20 | 1 => Some((
                        super::Ancestor {
                            pid: p,
                            name: if p == 20 { "zsh" } else { "init" }.into(),
                            path: None,
                        },
                        1,
                        u64::from(p),
                    )),
                    _ => None,
                },
                |h, _, _| reverse_parent(root, h).ok(),
            )
        };
        let (parents, complete) = run();
        assert!(complete);
        assert_eq!(
            parents.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["(hidden)", "zsh", "init"]
        );
        assert!(matches!(
            reverse_parent(root, 300).unwrap(),
            Hidden::SystemBoundary
        ));
        fs::remove_file(root.join("thread-self/children")).unwrap();
        assert!(!run().1, "no children interface is not a system boundary");
    }

    #[test]
    fn code_is_the_files_code_or_the_teams_identifier() {
        let file = sig("aa", None, DAEMON_ID, true);
        assert!(sig("aa", None, "x", true).signed_as(Some(&file), None, DAEMON_ID));
        assert!(!sig("bb", None, DAEMON_ID, true).signed_as(Some(&file), None, DAEMON_ID));
        assert!(!sig("aa", None, DAEMON_ID, false).signed_as(Some(&file), None, DAEMON_ID));
        assert!(!sig("aa", None, DAEMON_ID, true).signed_as(None, None, DAEMON_ID));
        let unsigned = sig("aa", None, DAEMON_ID, false);
        assert!(!sig("aa", None, DAEMON_ID, true).signed_as(Some(&unsigned), None, DAEMON_ID));

        let team = Some("T");
        assert!(sig("bb", team, "anomaly.deadbolt", true).signed_as(
            None,
            team,
            "anomaly.deadbolt"
        ));
        assert!(!sig("bb", team, "anomaly.deadbolt.cli", true).signed_as(
            None,
            team,
            "anomaly.deadbolt"
        ));
        assert!(!sig("bb", Some("U"), "anomaly.deadbolt", true).signed_as(
            None,
            team,
            "anomaly.deadbolt"
        ));
        // A build that knows its team takes no ad-hoc code, even the file's.
        assert!(!sig("aa", None, "anomaly.deadbolt", true).signed_as(
            Some(&file),
            team,
            "anomaly.deadbolt"
        ));
    }

    /// A client takes only the daemon running from the file it expects, by
    /// that file's code hash (ad-hoc) or Deadbolt's team and identifier: a
    /// byte-for-byte copy elsewhere, beside other files, is refused.
    #[test]
    fn the_daemon_is_that_file_not_a_copy() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().canonicalize().unwrap().join("deadbolt");
        let copy = dir.path().canonicalize().unwrap().join("copy");
        std::fs::write(&real, b"").unwrap();
        std::fs::write(&copy, b"").unwrap();
        let running = |path: &Path, team: Option<&str>, id: &str| CodeSignature {
            path: Some(path.display().to_string()),
            signing_id: Some(id.into()),
            team_id: team.map(Into::into),
            cdhash: Some("aa".into()),
            valid: true,
        };
        let file = sig("aa", None, DAEMON_ID, true);

        assert_eq!(
            daemon_is(&running(&real, None, "x"), Some(&file), &real, None),
            Ok(())
        );
        let moved = daemon_is(&running(&copy, None, "x"), Some(&file), &real, None);
        assert!(moved.unwrap_err().contains("not"), "a copy is refused");
        let other = sig("bb", None, DAEMON_ID, true);
        assert!(daemon_is(&running(&real, None, "x"), Some(&other), &real, None).is_err());
        assert!(daemon_is(&running(&real, None, "x"), None, &real, None).is_err());
        let mut forged = running(&real, None, "x");
        forged.valid = false;
        assert!(daemon_is(&forged, Some(&file), &real, None).is_err());
        let nowhere = CodeSignature {
            path: None,
            ..running(&real, None, "x")
        };
        assert!(daemon_is(&nowhere, Some(&file), &real, None).is_err());

        // A Developer ID build wants its own team and the daemon's identifier,
        // whatever the file on disk says.
        let team = Some("TEAM123456");
        assert_eq!(
            daemon_is(&running(&real, team, DAEMON_ID), None, &real, team),
            Ok(())
        );
        assert!(
            daemon_is(
                &running(&real, Some("OTHER12345"), DAEMON_ID),
                None,
                &real,
                team
            )
            .is_err()
        );
        assert!(daemon_is(&running(&real, team, "anomaly.deadbolt"), None, &real, team).is_err());
        assert!(daemon_is(&running(&real, None, DAEMON_ID), Some(&file), &real, team).is_err());
        // ... wherever that daemon runs from.
        assert_eq!(
            daemon_is(&running(&copy, team, DAEMON_ID), None, &real, team),
            Ok(())
        );
    }

    /// The split install: a signed Homebrew or npm `deadbolt` and a signed
    /// `/Applications/Deadbolt.app` each take the daemon the other started.
    /// An ad-hoc build takes only the daemon at the path it expects.
    #[test]
    fn signed_cli_and_app_share_either_daemon() {
        let team = Some("TEAM123456");
        let cli = Path::new("/opt/homebrew/bin/deadbolt");
        let helper = Path::new("/Applications/Deadbolt.app/Contents/Helpers/deadbolt");
        let running = |path: &Path, team: Option<&str>| CodeSignature {
            path: Some(path.display().to_string()),
            signing_id: Some(DAEMON_ID.into()),
            team_id: team.map(Into::into),
            cdhash: Some("aa".into()),
            valid: true,
        };
        // The app reaches the CLI's daemon, and the CLI the app's.
        assert_eq!(daemon_is(&running(cli, team), None, helper, team), Ok(()));
        assert_eq!(daemon_is(&running(helper, team), None, cli, team), Ok(()));
        assert!(daemon_is(&running(cli, Some("OTHER12345")), None, helper, team).is_err());
        // Ad hoc, the path is part of the daemon's identity.
        let file = sig("aa", None, DAEMON_ID, true);
        let refused = daemon_is(&running(cli, None), Some(&file), helper, None).unwrap_err();
        assert!(refused.contains("not "), "{refused}");
    }
}
