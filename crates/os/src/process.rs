//! A process's facts by pid, from `proc_pidinfo`, `proc_pidpath` and
//! `sysctl`, which `libc` declares but nothing wraps. Each answers for
//! whichever process has the pid at that moment; callers that need it to be a
//! particular process confirm that some other way (an audit token).

#![expect(unsafe_code, reason = "libproc and sysctl calls nothing wraps safely")]

use std::ffi::{CStr, c_char, c_int, c_void};
use std::io;

/// `SZOMB`, a zombie's `pbi_status` and `p_stat`.
pub const ZOMBIE: u32 = libc::SZOMB;

/// `struct proc_bsdinfo`, the fields Deadbolt reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BsdInfo {
    pub status: u32,
    pub ppid: u32,
    /// `pbi_comm`: the executable's name, cut to 16 bytes.
    pub comm: String,
    /// `pbi_name`: the longer name, empty when unset.
    pub name: String,
    /// The controlling terminal's device, `u32::MAX` (`NODEV`) for none.
    pub tdev: u32,
    /// Seconds and microseconds since the epoch.
    pub start: (u64, u64),
}

/// `proc_pidinfo(PROC_PIDTBSDINFO)`. Refused for other users' processes
/// (launchd and login among them); [`kinfo_proc`] answers for those.
pub fn bsd_info(pid: u32) -> Option<BsdInfo> {
    let pid = c_int::try_from(pid).ok()?;
    // SAFETY: `proc_bsdinfo` is plain integers and byte arrays, for which
    // all zeroes is a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = c_int::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    // SAFETY: `info` is a writable `proc_bsdinfo` of exactly `size` bytes,
    // the flavor's struct.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&raw mut info).cast::<c_void>(),
            size,
        )
    };
    (written == size).then(|| BsdInfo {
        status: info.pbi_status,
        ppid: info.pbi_ppid,
        comm: text(&info.pbi_comm),
        name: text(&info.pbi_name),
        tdev: info.e_tdev,
        start: (info.pbi_start_tvsec, info.pbi_start_tvusec),
    })
}

/// `struct kinfo_proc` (`sysctl` `KERN_PROC_PID`), the fields Deadbolt
/// reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KinfoProc {
    pub pid: i32,
    pub stat: u32,
    pub ppid: i32,
    /// `p_comm`: the executable's name, cut to 16 bytes.
    pub comm: String,
    /// `p_starttime`, seconds and microseconds since the epoch.
    pub start: (u64, u64),
}

/// `struct kinfo_proc`'s size and the offsets of its fields Deadbolt reads,
/// the same on arm64 and x86_64 (a frozen ABI; the tests check them against
/// the kernel's answer for this process).
const KINFO_PROC_SIZE: usize = 648;
const P_STARTTIME_SEC: usize = 0;
const P_STARTTIME_USEC: usize = 8;
const P_STAT: usize = 36;
const P_PID: usize = 40;
const P_COMM: usize = 243;
const P_COMM_LEN: usize = 17;
const E_PPID: usize = 560;

/// `sysctl` `KERN_PROC_PID`, which answers for any user's process.
pub fn kinfo_proc(pid: u32) -> Option<KinfoProc> {
    let pid = c_int::try_from(pid).ok()?;
    let mut buffer = [0u8; KINFO_PROC_SIZE];
    let size = sysctl(
        &[libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid],
        &mut buffer,
    )
    .ok()?;
    if size != KINFO_PROC_SIZE {
        return None;
    }
    let i32_at = |at: usize| {
        buffer
            .get(at..at + 4)?
            .try_into()
            .ok()
            .map(i32::from_ne_bytes)
    };
    let i64_at = |at: usize| {
        buffer
            .get(at..at + 8)?
            .try_into()
            .ok()
            .map(i64::from_ne_bytes)
    };
    Some(KinfoProc {
        pid: i32_at(P_PID)?,
        stat: u32::from(*buffer.get(P_STAT)?),
        ppid: i32_at(E_PPID)?,
        comm: bytes_text(buffer.get(P_COMM..P_COMM + P_COMM_LEN)?),
        start: (
            u64::try_from(i64_at(P_STARTTIME_SEC)?).ok()?,
            u64::try_from(i32_at(P_STARTTIME_USEC)?).ok()?,
        ),
    })
}

/// `proc_pidpath`: the executable the process runs.
pub fn path(pid: u32) -> Option<String> {
    let pid = c_int::try_from(pid).ok()?;
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let size = u32::try_from(buffer.len()).ok()?;
    // SAFETY: `buffer` is writable for `size` bytes.
    let written = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast::<c_void>(), size) };
    (written > 0).then(|| bytes_text(&buffer))
}

/// `sysctl` `KERN_PROCARGS2`, as the kernel lays it out: `argc`, the exec
/// path, then the arguments and the environment.
pub fn procargs2(pid: u32) -> Option<Vec<u8>> {
    let pid = c_int::try_from(pid).ok()?;
    let mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let size = sysctl(&mib, &mut []).ok()?;
    if size <= 4 {
        return None;
    }
    let mut buffer = vec![0u8; size];
    let size = sysctl(&mib, &mut buffer).ok()?;
    if size <= 4 {
        return None;
    }
    buffer.truncate(size);
    Some(buffer)
}

/// `sysctl(mib)` into `out`, or, with `out` empty, the size it needs.
fn sysctl(mib: &[c_int], out: &mut [u8]) -> io::Result<usize> {
    let mut mib = mib.to_vec();
    let length = u32::try_from(mib.len()).map_err(io::Error::other)?;
    let mut size = out.len();
    let buffer = if out.is_empty() {
        std::ptr::null_mut()
    } else {
        out.as_mut_ptr().cast::<c_void>()
    };
    // SAFETY: `mib` holds `length` names; `buffer` is null (asking for the
    // size) or writable for `size` bytes, and `size` is a valid place for
    // the answer's length. Nothing new is set.
    let status = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            length,
            buffer,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if status == 0 {
        Ok(size)
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe extern "C" {
    /// `devname(3)`'s reentrant form, which `libc` doesn't declare on macOS.
    fn devname_r(dev: libc::dev_t, kind: libc::mode_t, buf: *mut c_char, len: c_int)
    -> *mut c_char;
}

/// The name in `/dev` of the character device `device` (a `dev_t`'s bits,
/// as `proc_bsdinfo.e_tdev` has them), `ttys004` say.
pub fn devname(device: u32) -> Option<String> {
    let mut buffer = [0 as c_char; 256];
    let length = c_int::try_from(buffer.len()).ok()?;
    let device = libc::dev_t::from_ne_bytes(device.to_ne_bytes());
    // SAFETY: `buffer` is writable for `length` bytes; `devname_r` writes a
    // NUL-terminated name into it, or returns null.
    let name = unsafe { devname_r(device, libc::S_IFCHR, buffer.as_mut_ptr(), length) };
    if name.is_null() {
        return None;
    }
    // SAFETY: a non-null answer is `buffer`, now holding a NUL-terminated
    // name; it is copied out before `buffer` goes away.
    let name = unsafe { CStr::from_ptr(name) };
    Some(name.to_string_lossy().into_owned())
}

/// A fixed C string field: its bytes up to the first NUL, as UTF-8 with
/// anything invalid replaced.
fn text(field: &[c_char]) -> String {
    let bytes: Vec<u8> = field.iter().map(|c| c.to_ne_bytes()[0]).collect();
    bytes_text(&bytes)
}

fn bytes_text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hand-kept `kinfo_proc` offsets read this process right.
    #[test]
    fn kinfo_proc_reads_this_process() {
        let me = std::process::id();
        let kinfo = kinfo_proc(me).unwrap();
        let bsd = bsd_info(me).unwrap();
        assert_eq!(kinfo.pid, i32::try_from(me).unwrap());
        assert_eq!(u32::try_from(kinfo.ppid).unwrap(), bsd.ppid);
        // `p_comm` holds 16 bytes of the name, `pbi_comm` 15 and a NUL.
        assert!(!bsd.comm.is_empty() && kinfo.comm.starts_with(&bsd.comm));
        assert_eq!(kinfo.start, bsd.start);
        assert_ne!(kinfo.stat, ZOMBIE);
        assert_eq!(bsd.ppid, std::os::unix::process::parent_id());
    }

    /// launchd belongs to root: its BSD info is refused, its `kinfo_proc`
    /// isn't.
    #[test]
    fn launchd_is_read_through_sysctl() {
        let launchd = kinfo_proc(1).unwrap();
        assert_eq!((launchd.pid, launchd.ppid), (1, 0));
        assert_eq!(launchd.comm, "launchd");
        assert_eq!(path(1).as_deref(), Some("/sbin/launchd"));
    }

    #[test]
    fn this_process_has_its_path_and_arguments() {
        let me = std::process::id();
        let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
        assert_eq!(path(me).as_deref(), exe.to_str());
        let args = procargs2(me).unwrap();
        let argc = i32::from_ne_bytes(args[..4].try_into().unwrap());
        assert_eq!(usize::try_from(argc).unwrap(), std::env::args_os().count());
    }

    #[test]
    fn devname_names_a_character_device() {
        use std::os::unix::fs::MetadataExt;
        let null = std::fs::metadata("/dev/null").unwrap().rdev();
        let null = u32::from_ne_bytes(i32::try_from(null).unwrap().to_ne_bytes());
        assert_eq!(devname(null).as_deref(), Some("null"));
    }

    #[test]
    fn no_process_has_no_facts() {
        assert!(bsd_info(u32::MAX).is_none());
        assert!(kinfo_proc(u32::MAX).is_none());
        assert!(path(u32::MAX).is_none());
    }
}
