//! Who holds the other end of a Unix socket, from the kernel rather than
//! from anything the peer says. macOS gives the audit token
//! (`LOCAL_PEERTOKEN`), and Deadbolt's Swift helper looks the running code's
//! signature up by it (`deadbolt-enclave identify`, `identify.swift` in the
//! CLI). Linux gives `SO_PEERCRED`, and `/proc` the rest.

use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::protocol::{Ancestor, Signature};

const IDENTIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// The kernel's word for a socket's peer, taken when it connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Peer {
    pub pid: u32,
    pub uid: u32,
    /// The audit token (macOS), which names the process even after its pid
    /// is reused: the helper refuses a token whose process is gone.
    pub token: Option<[u32; 8]>,
    /// The token's pid version (macOS), or the start time in clock ticks
    /// (Linux, read from `/proc` after the fact).
    pub pid_version: Option<u64>,
}

impl Peer {
    #[cfg(target_os = "macos")]
    pub fn of(socket: &impl AsFd) -> io::Result<Peer> {
        use nix::sys::socket::{getsockopt, sockopt::LocalPeerToken};
        let token = getsockopt(socket, LocalPeerToken)?.val;
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
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
        let creds = getsockopt(socket, PeerCredentials)?;
        let pid = u32::try_from(creds.pid()).map_err(|_| io::Error::other("no peer pid"))?;
        Ok(Peer {
            pid,
            uid: creds.uid(),
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
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerCred};
    Ok(getsockopt(socket, LocalPeerCred)?.uid())
}

#[cfg(target_os = "linux")]
pub fn uid(socket: &impl AsFd) -> io::Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    Ok(getsockopt(socket, PeerCredentials)?.uid())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn uid(_socket: &impl AsFd) -> io::Result<u32> {
    Err(io::Error::other("peer credentials are not supported here"))
}

/// A code signature as the helper read it, from a running process or a file.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CodeSignature {
    pub path: Option<String>,
    pub signing_id: Option<String>,
    /// Only when the signature chains to Apple for this team.
    pub team_id: Option<String>,
    pub cdhash: Option<String>,
    #[serde(default)]
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
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
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
    /// The executable (Linux; on macOS it's the signature's `path`).
    pub exe: Option<String>,
}

/// `deadbolt-enclave identify`'s answer.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Identified {
    /// The running code, for a token.
    pub code: Option<CodeSignature>,
    pub process: Option<Process>,
    /// One per file asked about, `None` for those that aren't signed code.
    pub files: Vec<Option<CodeSignature>>,
}

/// Runs `helper identify` on `token` (if any) and `files`. `Ok(None)` when
/// the token's process is gone, so the token named nobody alive.
pub fn identify(
    helper: &Path,
    token: Option<[u32; 8]>,
    files: &[PathBuf],
) -> Result<Option<Identified>, String> {
    const GONE: i32 = 15;
    let mut input = serde_json::Map::new();
    if let Some(token) = token {
        input.insert("token".into(), serde_json::json!(token));
    }
    input.insert("files".into(), serde_json::json!(files));
    let input = serde_json::Value::Object(input);
    let mut child = Command::new(helper)
        .arg("identify")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("running {}: {e}", helper.display()))?;
    let written = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("no stdin"))
        .and_then(|mut stdin| stdin.write_all(input.to_string().as_bytes()));
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut err = Vec::new();
        if let Some(stdout) = stdout.as_mut() {
            drop(stdout.read_to_end(&mut out));
        }
        if let Some(stderr) = stderr.as_mut() {
            drop(stderr.read_to_end(&mut err));
        }
        (out, err)
    });
    let deadline = Instant::now() + IDENTIFY_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
            Ok(None) => {
                drop(child.kill());
                drop(child.wait());
                return Err("deadbolt-enclave identify timed out".into());
            }
            Err(e) => return Err(format!("waiting for deadbolt-enclave: {e}")),
        }
    };
    let (out, err) = reader
        .join()
        .map_err(|_| "reading deadbolt-enclave".to_string())?;
    written.map_err(|e| format!("writing to deadbolt-enclave: {e}"))?;
    match status.code() {
        Some(0) => serde_json::from_slice(&out)
            .map(Some)
            .map_err(|e| format!("reading deadbolt-enclave identify: {e}")),
        Some(GONE) => Ok(None),
        _ => Err(format!(
            "deadbolt-enclave identify failed ({status}): {}",
            String::from_utf8_lossy(&err).trim()
        )),
    }
}

/// The Apple team that signed this build, compiled in (`build.rs`); `None`
/// for an ad-hoc build, whose code is known by path and code hash instead.
pub fn team() -> Option<&'static str> {
    Some(env!("DEADBOLT_TEAM_ID")).filter(|t| !t.is_empty())
}

/// The signing identifier of Deadbolt's daemon (`Contents/Helpers/deadbolt`,
/// and the CLI), as `bundle.sh` signs it.
pub const DAEMON_ID: &str = "deadbolt";
/// The signing identifier of Deadbolt.app, its bundle identifier.
pub const APP_ID: &str = "pw.deadbolt.app";
/// The signing identifier of Deadbolt's macOS AutoFill extension
/// (`Contents/PlugIns/DeadboltAutoFill.appex`), its bundle identifier.
pub const AUTOFILL_ID: &str = "pw.deadbolt.app.autofill";
/// The suffix of Deadbolt's macOS App Group (`<TEAM_ID>.pw.deadbolt`).
pub const APP_GROUP_SUFFIX: &str = "pw.deadbolt";

/// The macOS App Group shared with `DeadboltAutoFill.appex`, when this build
/// knows its Apple team (`DEADBOLT_TEAM_ID`).
pub fn app_group() -> Option<String> {
    team().map(|t| format!("{t}.{APP_GROUP_SUFFIX}"))
}

/// Checks that `socket`'s peer is the daemon at `expected` (this client's own
/// binary, or its bundle's helper), before a passphrase goes to it.
///
/// On macOS, `helper` (`deadbolt-enclave`) looks the peer's code up by its
/// audit token: it must run from `expected` itself, not a copy elsewhere, and
/// be Deadbolt's daemon by signature (`daemon_is`). On Linux nothing tells two
/// processes of one user apart, so this checks only that the peer runs as
/// this user; the socket's 0700 directory is what keeps others out.
pub fn check(socket: &impl AsFd, helper: &Path, expected: &Path) -> Result<(), String> {
    let peer = Peer::of(socket).map_err(|e| format!("reading the daemon's credentials: {e}"))?;
    if peer.uid != rustix::process::getuid().as_raw() {
        return Err(format!(
            "the daemon (pid {}) runs as another user",
            peer.pid
        ));
    }
    #[cfg(target_os = "macos")]
    {
        if !helper.is_file() {
            return Err(missing_helper(helper));
        }
        let expected = expected
            .canonicalize()
            .map_err(|e| format!("locating {}: {e}", expected.display()))?;
        let Some(found) = identify(helper, peer.token, std::slice::from_ref(&expected))? else {
            return Err(format!("the daemon (pid {}) exited", peer.pid));
        };
        let code = found.code.unwrap_or_default();
        let file = found.files.into_iter().next().flatten();
        daemon_is(&code, file.as_ref(), &expected, team()).map_err(|why| {
            format!(
                "the daemon (pid {}) {why}; run `deadbolt debug daemon stop`",
                peer.pid
            )
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (helper, expected);
        Ok(())
    }
}

/// What Deadbolt says when its `deadbolt-enclave` isn't where it belongs.
pub fn missing_helper(helper: &Path) -> String {
    format!(
        "{} is missing: Deadbolt uses it to check who it talks to, and for Touch ID. \
         Reinstall Deadbolt so deadbolt-enclave sits beside deadbolt",
        helper.display()
    )
}

/// Whether running `code` is the daemon at `expected` (canonical): it runs
/// from that very file, and is Deadbolt's daemon by signature, by `team` and
/// [`DAEMON_ID`] for a Developer ID build, else by the code hash of `file`,
/// the signature on disk at `expected`.
pub fn daemon_is(
    code: &CodeSignature,
    file: Option<&CodeSignature>,
    expected: &Path,
    team: Option<&str>,
) -> Result<(), String> {
    if !code.runs_from(expected) {
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
    //! `/proc`, for what macOS's helper reads with `proc_pidinfo`.

    use std::path::PathBuf;

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

    pub fn stat(pid: u32) -> Option<Stat> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let open = text.find('(')?;
        let close = text.rfind(')')?;
        let name = text.get(open + 1..close)?.to_string();
        // After the name: state ppid pgrp session tty_nr ... starttime (22nd).
        let rest: Vec<&str> = text.get(close + 1..)?.split_whitespace().collect();
        Some(Stat {
            name,
            ppid: rest.get(1)?.parse().ok()?,
            session: rest.get(3)?.parse().ok()?,
            tty_nr: rest.get(4)?.parse().ok()?,
            start_ticks: rest.get(19)?.parse().ok()?,
        })
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

    pub fn process(pid: u32) -> Process {
        let Some(me) = stat(pid) else {
            return Process::default();
        };
        let boot = boot_time();
        let args = std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|raw| args(&raw))
            .unwrap_or_default();
        let mut ancestry = Vec::new();
        let mut next = me.ppid;
        while next > 0 && ancestry.len() < 32 {
            let Some(parent) = stat(next) else {
                break;
            };
            ancestry.push(Ancestor {
                pid: next,
                name: parent.name,
                path: exe(next).map(|p| p.display().to_string()),
            });
            if next == 1 {
                break;
            }
            next = parent.ppid;
        }
        Process {
            ppid: Some(me.ppid),
            started: unix(me.start_ticks, boot),
            tty: tty(me.tty_nr),
            session_started: stat(me.session).and_then(|leader| unix(leader.start_ticks, boot)),
            args,
            ancestry,
            exe: exe(pid).map(|p| p.display().to_string()),
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

    #[test]
    fn code_is_the_files_code_or_the_teams_identifier() {
        let file = sig("aa", None, "deadbolt", true);
        assert!(sig("aa", None, "x", true).signed_as(Some(&file), None, "deadbolt"));
        assert!(!sig("bb", None, "deadbolt", true).signed_as(Some(&file), None, "deadbolt"));
        assert!(!sig("aa", None, "deadbolt", false).signed_as(Some(&file), None, "deadbolt"));
        assert!(!sig("aa", None, "deadbolt", true).signed_as(None, None, "deadbolt"));
        let unsigned = sig("aa", None, "deadbolt", false);
        assert!(!sig("aa", None, "deadbolt", true).signed_as(Some(&unsigned), None, "deadbolt"));

        let team = Some("T");
        assert!(sig("bb", team, "pw.deadbolt.app", true).signed_as(None, team, "pw.deadbolt.app"));
        assert!(!sig("bb", team, "pw.deadbolt.cli", true).signed_as(None, team, "pw.deadbolt.app"));
        assert!(!sig("bb", Some("U"), "pw.deadbolt.app", true).signed_as(
            None,
            team,
            "pw.deadbolt.app"
        ));
        // A build that knows its team takes no ad-hoc code, even the file's.
        assert!(!sig("aa", None, "pw.deadbolt.app", true).signed_as(
            Some(&file),
            team,
            "pw.deadbolt.app"
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
        assert!(daemon_is(&running(&real, team, "pw.deadbolt.app"), None, &real, team).is_err());
        assert!(daemon_is(&running(&real, None, DAEMON_ID), Some(&file), &real, team).is_err());
        assert!(daemon_is(&running(&copy, team, DAEMON_ID), None, &real, team).is_err());
    }
}
