//! macOS: a peer's running code, looked up by its audit token through
//! Security.framework, and its process facts by pid (`proc_pidinfo`,
//! `sysctl`), in process (`deadbolt-os` holds the calls).
//!
//! The process facts are read by pid first, and the code is looked up by the
//! audit token after, which fails once that pid version is gone. So when
//! [`identify`] answers, the pid still belonged to the token's process
//! throughout: a reused pid can't lend its facts to a dead caller.
//!
//! `team_id` is only reported when it is 10 ASCII letters or digits and the
//! signature chains to Apple's Developer ID roots for that team, so a
//! self-signed certificate naming a team can't claim one. `valid` is
//! `SecCodeCheckValidity` for running code (the kernel's view of its pages
//! and the code directory's signature), and the code directory's signature
//! alone for a file.

use std::collections::HashSet;
use std::path::Path;

use core_foundation::{base::TCFType, data::CFData};
use deadbolt_os::code::{self, Code};
use deadbolt_os::process as sys;
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};

use super::{Ancestor, CodeSignature, Process};

/// The code running as `token`'s process, from the kernel: `None` once
/// that pid version is gone, even if the pid lives on.
fn guest(token: &[u32; 8]) -> Option<SecCode> {
    let bytes = token.map(u32::to_ne_bytes);
    let data = CFData::from_buffer(bytes.as_flattened());
    let mut attrs = GuestAttributes::new();
    attrs.set_audit_token(data.as_concrete_TypeRef());
    SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE).ok()
}

/// Whether `token` still names a living process.
pub fn live_token(token: &[u32; 8]) -> bool {
    guest(token).is_some()
}

/// A peer, as the kernel and its code signature tell it.
#[derive(Debug, Clone, Default)]
pub struct Identified {
    /// The running code.
    pub code: CodeSignature,
    pub process: Process,
}

/// `token`'s process: its facts, then its code. `None` when the token's
/// process is gone, before or while it was read.
pub fn identify(token: [u32; 8]) -> Option<Identified> {
    // Facts by pid first; the token lookup after proves they were this
    // process's.
    let process = process(token[5]);
    let code = running(&token)?;
    Some(Identified { code, process })
}

/// `token`'s running code. `None` when the token's process is gone,
/// before or while it was read.
pub fn running(token: &[u32; 8]) -> Option<CodeSignature> {
    let code = guest(token)?;
    let path = code.path(Flags::NONE).ok().and_then(|url| url.to_path());
    let found = signature(&code, path.as_deref(), true, |requirement| {
        code::running_is_valid(&code, requirement)
    });
    // Again after reading everything: the process may have exited meanwhile.
    guest(token)?;
    Some(found)
}

/// The signature on disk at `path`, its slice for this process's own
/// architecture (the one Deadbolt's binaries run as). `None` for what
/// Security.framework can't read as code.
pub fn file_signature(path: &Path) -> Option<CodeSignature> {
    let file = code::file_code(path)?;
    let at = file.path(Flags::NONE).ok().and_then(|url| url.to_path());
    // The code directory's signature, not every page: the running code's
    // cdhash is compared against this one, and the kernel checks its pages.
    let flags = Flags::DO_NOT_VALIDATE_EXECUTABLE | Flags::DO_NOT_VALIDATE_RESOURCES;
    Some(signature(&file, at.as_deref(), false, |requirement| {
        code::file_is_valid(&file, flags, requirement)
    }))
}

/// What `code`'s signing information says, with `team_id` kept only when
/// `valid` accepts the team's Apple-anchored requirement. `path` is where
/// the code is (the bundle, for an app); its main executable replaces it.
fn signature(
    code: &impl Code,
    path: Option<&Path>,
    dynamic: bool,
    valid: impl Fn(Option<&SecRequirement>) -> bool,
) -> CodeSignature {
    let text = |path: &Path| path.to_string_lossy().into_owned();
    let mut out = CodeSignature {
        path: path.map(text),
        ..CodeSignature::default()
    };
    let Some(info) = code::signing_information(code, dynamic) else {
        return out;
    };
    if let Some(main) = &info.main_executable {
        out.path = Some(text(main));
    }
    out.signing_id = info.identifier;
    out.cdhash = info
        .unique
        .map(|hash| data_encoding::HEXLOWER.encode(&hash));
    out.valid = valid(None);
    if out.valid
        && let Some(team) = info.team_identifier
        && let Some(requirement) = requirement(&team)
        && valid(Some(&requirement))
    {
        out.team_id = Some(team);
    }
    out
}

/// Whether `team` has a team identifier's shape: 10 ASCII letters or
/// digits. Anything else is never put into a requirement's text.
fn is_team_identifier(team: &str) -> bool {
    team.len() == 10 && team.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Signed by Apple's Developer ID for `team`.
fn requirement(team: &str) -> Option<SecRequirement> {
    if !is_team_identifier(team) {
        return None;
    }
    format!("anchor apple generic and certificate leaf[subject.OU] = \"{team}\"")
        .parse()
        .ok()
}

/// A process's BSD info, unless it's a zombie.
fn bsd_info(pid: u32) -> Option<sys::BsdInfo> {
    sys::bsd_info(pid).filter(|info| info.status != sys::ZOMBIE)
}

/// A parent's ppid, name and birth. Full BSD info is restricted for other
/// users' processes (including launchd and login); `KERN_PROC_PID` still
/// gives their ppid and birth time.
fn parent(pid: u32) -> Option<(u32, String, (u64, u64))> {
    if let Some(info) = bsd_info(pid) {
        let name = if info.name.is_empty() {
            info.comm
        } else {
            info.name
        };
        return Some((info.ppid, name, info.start));
    }
    let info = sys::kinfo_proc(pid)?;
    if u32::try_from(info.pid).ok() != Some(pid) || info.stat == sys::ZOMBIE {
        return None;
    }
    Some((u32::try_from(info.ppid).ok()?, info.comm, info.start))
}

/// What `pid` says about itself; empty when it can't be read.
fn process(pid: u32) -> Process {
    let Some(info) = bsd_info(pid) else {
        return Process::default();
    };
    let tty = (info.tdev != u32::MAX)
        .then(|| sys::devname(info.tdev))
        .flatten()
        .map(|name| format!("/dev/{name}"));
    let session_started = rustix::process::Pid::from_raw(pid as i32)
        .and_then(|p| rustix::process::getsid(Some(p)).ok())
        .and_then(|sid| u32::try_from(sid.as_raw_nonzero().get()).ok())
        .and_then(bsd_info)
        .map(|leader| leader.start.0);
    let (ancestry, ancestry_complete) = walk(pid, info.ppid, info.start, parent, sys::path);
    Process {
        ppid: Some(info.ppid),
        started: Some(info.start.0),
        tty,
        session_started,
        args: sys::procargs2(pid)
            .map(|raw| arguments(&raw))
            .unwrap_or_default(),
        ancestry,
        ancestry_complete,
        exe: None,
    }
}

/// The parents of `pid` (whose parent is `next`, born at `birth`), nearest
/// first, up to launchd, and whether they reached it. A parent born after
/// its child isn't its parent: the child was orphaned and the pid reused.
fn walk(
    pid: u32,
    mut next: u32,
    mut birth: (u64, u64),
    mut parent: impl FnMut(u32) -> Option<(u32, String, (u64, u64))>,
    mut path: impl FnMut(u32) -> Option<String>,
) -> (Vec<Ancestor>, bool) {
    let mut ancestry = Vec::new();
    let mut visited = HashSet::from([pid]);
    while next > 0 && ancestry.len() < 1024 && visited.insert(next) {
        let Some((ppid, name, born)) = parent(next) else {
            break;
        };
        if born > birth {
            break;
        }
        ancestry.push(Ancestor {
            pid: next,
            name,
            path: path(next),
        });
        if next == 1 {
            return (ancestry, true);
        }
        next = ppid;
        birth = born;
    }
    (ancestry, pid == 1)
}

/// The arguments in `KERN_PROCARGS2`'s `raw`: argc, the exec path and its
/// NUL, padded with NULs to a multiple of 8 bytes, then argc strings of argv
/// (any of them may be empty), then the environment.
fn arguments(raw: &[u8]) -> Vec<String> {
    let Some(argc) = raw.first_chunk::<4>().map(|b| i32::from_ne_bytes(*b)) else {
        return Vec::new();
    };
    let size = raw.len();
    let mut i = 4;
    while i < size && raw[i] != 0 {
        i += 1;
    }
    // Only the padding is skipped: skipping every NUL would take empty
    // arguments for padding and the environment for arguments.
    let argv = 4 + (i - 4 + 1).div_ceil(8) * 8;
    if argv > size || raw[i..argv].iter().any(|b| *b != 0) {
        return Vec::new();
    }
    i = argv;
    let argc = usize::try_from(argc).unwrap_or(0);
    let mut args = Vec::new();
    while args.len() < argc && i < size {
        let start = i;
        while i < size && raw[i] != 0 {
            i += 1;
        }
        args.push(String::from_utf8_lossy(&raw[start..i]).into_owned());
        i += 1;
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Our own audit token names us: our code, which is our file's, our
    /// arguments and a parent chain up to launchd. Once its pid version is
    /// gone the token names nobody, even though the pid lives on.
    #[test]
    fn a_token_names_its_own_process_version_only() {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let me = super::super::Peer::of(&ours).unwrap();
        drop(theirs);
        assert_eq!(me.pid, std::process::id());
        let token = me.token.unwrap();
        let found = identify(token).expect("our own token names us");
        let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
        assert!(found.code.valid);
        assert_eq!(found.code.path.as_deref(), exe.to_str());
        assert!(found.code.runs_from(&exe));
        let file = file_signature(&exe).unwrap();
        assert!(file.valid);
        assert!(found.code.cdhash.is_some());
        assert_eq!(found.code.cdhash, file.cdhash);
        assert_eq!(found.code.signing_id, file.signing_id);
        // A test binary is signed ad hoc: no team, anchored or not.
        assert_eq!(found.code.team_id, None);

        let process = found.process;
        assert_eq!(process.ppid, Some(std::os::unix::process::parent_id()));
        assert!(process.started.is_some());
        assert!(process.ancestry_complete);
        assert_eq!(process.ancestry.first().unwrap().pid, process.ppid.unwrap());
        let launchd = process.ancestry.last().unwrap();
        assert_eq!((launchd.pid, launchd.name.as_str()), (1, "launchd"));
        assert_eq!(launchd.path.as_deref(), Some("/sbin/launchd"));
        let args: Vec<String> = std::env::args().collect();
        assert_eq!(process.args, args);
        assert!(live_token(&token));

        let mut stale = token;
        stale[7] = stale[7].wrapping_add(1);
        assert!(identify(stale).is_none());
        assert!(running(&stale).is_none());
        assert!(!live_token(&stale));
    }

    /// An Apple platform binary is valid with no team; a file that isn't
    /// code isn't valid code.
    #[test]
    fn files_are_read_as_code() {
        let ls = file_signature(Path::new("/bin/ls")).unwrap();
        assert!(ls.valid);
        assert_eq!(ls.signing_id.as_deref(), Some("com.apple.ls"));
        assert_eq!(ls.team_id, None);
        assert_eq!(ls.path.as_deref(), Some("/bin/ls"));
        assert_eq!(ls.cdhash.map(|h| h.len()), Some(40));

        let dir = tempfile::tempdir().unwrap();
        let text = dir.path().join("notes.txt");
        std::fs::write(&text, "not code").unwrap();
        assert!(file_signature(&text).is_none_or(|s| !s.valid && s.team_id.is_none()));
        assert!(file_signature(&dir.path().join("missing")).is_none());
    }

    #[test]
    fn only_a_team_identifiers_shape_enters_a_requirement() {
        assert!(requirement("TEAM123456").is_some());
        for bad in ["TEAM12345", "TEAM1234567", "TEAM\" or", "TEAM-23456", ""] {
            assert!(requirement(bad).is_none(), "{bad}");
        }
    }

    /// Empty arguments are arguments, and only the exec path's padding is
    /// skipped.
    #[test]
    fn arguments_keep_empty_ones_and_stop_at_argc() {
        let raw = |argc: i32, rest: &[u8]| [&argc.to_ne_bytes()[..], rest].concat();
        // "/bin/x\0" is 7 bytes, padded to 8; then "", "a", then environment.
        let full = raw(2, b"/bin/x\0\0\0a\0HOME=/\0");
        assert_eq!(arguments(&full), ["", "a"]);
        // Exactly 8 bytes of path and NUL pad to 16.
        let padded = raw(1, b"/bin/xyz\0\0\0\0\0\0\0\0arg\0");
        assert_eq!(arguments(&padded), ["arg"]);
        // Padding that isn't NULs, or runs off the end, is no layout we know.
        assert!(arguments(&raw(1, b"/bin/x\0Xarg\0")).is_empty());
        assert!(arguments(&raw(1, b"/bin/x")).is_empty());
        assert!(arguments(&raw(0, b"/bin/x\0\0arg\0")).is_empty());
        assert!(arguments(b"\x01\0").is_empty());
    }

    #[test]
    fn the_parent_walk_needs_launchd_and_older_parents() {
        let named = |ppid: u32, born: u64| Some((ppid, format!("p{ppid}"), (born, 0)));
        let chain = |pid: u32| named(pid - 1, u64::from(pid));
        let no_path = |_| None;
        let (parents, complete) = walk(5, 4, (5, 0), chain, no_path);
        assert!(complete);
        assert_eq!(
            parents.iter().map(|a| a.pid).collect::<Vec<_>>(),
            [4, 3, 2, 1]
        );
        // A parent younger than its child is a reused pid: the walk stops.
        let reused = |pid: u32| named(pid - 1, if pid == 3 { 99 } else { u64::from(pid) });
        let (parents, complete) = walk(5, 4, (5, 0), reused, no_path);
        assert!(!complete);
        assert_eq!(parents.len(), 1);
        // Same second, later microsecond: younger too.
        let later = |pid: u32| Some((pid - 1, String::new(), (5, if pid == 4 { 1 } else { 0 })));
        assert!(walk(5, 4, (5, 0), later, no_path).0.is_empty());
        // An unreadable parent or a loop ends the walk incomplete.
        assert!(!walk(5, 4, (5, 0), |_| None, no_path).1);
        let looped = |pid: u32| named(if pid == 3 { 4 } else { pid - 1 }, 0);
        assert!(!walk(5, 4, (5, 0), looped, no_path).1);
        // launchd itself is complete with no parents.
        assert_eq!(walk(1, 0, (0, 0), chain, no_path), (Vec::new(), true));
    }
}
