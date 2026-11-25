//! Keeping keys out of crash dumps, swap and other processes: process-wide
//! hardening for the daemon ([`harden_process`]) and a key buffer locked in
//! RAM that wipes itself before it's freed ([`LockedSecret`]).
//!
//! Every call is best effort and reports what it managed rather than failing:
//! a container or sandbox may refuse `setrlimit`, `prctl` or `mlock` with
//! `EPERM`, and Deadbolt still runs there, just without that protection.

#![expect(
    unsafe_code,
    reason = "setrlimit, prctl, ptrace, mlock and madvise, and the page-aligned allocation they act on"
)]

use std::alloc::{self, Layout};
use std::ffi::c_void;
use std::fmt;
use std::io;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::OnceLock;

use zeroize::Zeroize;

/// What [`harden_process`] should try beyond what it always does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HardeningOptions {
    /// macOS: refuse debuggers for the rest of the process's life
    /// (`PT_DENY_ATTACH`). A process already under a debugger exits when it
    /// asks, so leave this off in debug builds, tests, and whenever someone
    /// may want to attach.
    pub deny_debugger: bool,
}

/// How one protection went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    /// Not asked for ([`HardeningOptions`]).
    Disabled,
    /// This platform has no such call.
    Unsupported,
    /// The call failed with this `errno`; the process runs without it.
    Failed(i32),
}

impl Outcome {
    fn of(status: libc::c_int) -> Self {
        if status == 0 {
            Self::Applied
        } else {
            Self::Failed(io::Error::last_os_error().raw_os_error().unwrap_or(0))
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Applied => f.write_str("applied"),
            Self::Disabled => f.write_str("off"),
            Self::Unsupported => f.write_str("not on this platform"),
            Self::Failed(errno) => {
                write!(f, "failed: {}", io::Error::from_raw_os_error(*errno))
            }
        }
    }
}

/// What [`harden_process`] did, protection by protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardeningReport {
    /// `RLIMIT_CORE` set to 0 (soft and hard), so a crash writes no core
    /// file holding keys.
    pub core_dumps: Outcome,
    /// Linux: `PR_SET_DUMPABLE` 0, which also keeps same-user processes out
    /// of `/proc/<pid>/mem` and `ptrace`.
    pub dumpable: Outcome,
    /// macOS: `PT_DENY_ATTACH`.
    pub debugger: Outcome,
}

impl HardeningReport {
    /// The protections that were tried and failed, by name.
    pub fn failures(&self) -> impl Iterator<Item = (&'static str, Outcome)> {
        [
            ("core_dumps", self.core_dumps),
            ("dumpable", self.dumpable),
            ("debugger", self.debugger),
        ]
        .into_iter()
        .filter(|(_, outcome)| matches!(outcome, Outcome::Failed(_)))
    }
}

/// Hardens this whole process: no core dumps, and on Linux no same-user
/// `ptrace` or `/proc/<pid>/mem`; with [`HardeningOptions::deny_debugger`],
/// no debugger on macOS. Call it first thing, before any key is in memory.
/// Child processes inherit the core limit, and none of it can be undone.
pub fn harden_process(options: HardeningOptions) -> HardeningReport {
    HardeningReport {
        core_dumps: no_core_dumps(),
        dumpable: not_dumpable(),
        debugger: if options.deny_debugger {
            deny_debugger()
        } else {
            Outcome::Disabled
        },
    }
}

fn no_core_dumps() -> Outcome {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `none` is a valid `rlimit` that outlives the call, which only
    // reads it. Lowering a limit, the hard one included, needs no privilege.
    Outcome::of(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) })
}

#[cfg(target_os = "linux")]
fn not_dumpable() -> Outcome {
    let off: libc::c_ulong = 0;
    // SAFETY: `PR_SET_DUMPABLE` reads one integer argument and touches no
    // memory of ours.
    Outcome::of(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, off, off, off, off) })
}

#[cfg(not(target_os = "linux"))]
fn not_dumpable() -> Outcome {
    Outcome::Unsupported
}

#[cfg(target_os = "macos")]
fn deny_debugger() -> Outcome {
    // SAFETY: `PT_DENY_ATTACH` ignores its pid, address and data arguments
    // and touches no memory of ours.
    Outcome::of(unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) })
}

#[cfg(not(target_os = "macos"))]
fn deny_debugger() -> Outcome {
    Outcome::Unsupported
}

/// The VM page size: `mlock` and `madvise` act on whole pages.
fn page_size() -> usize {
    static PAGE: OnceLock<usize> = OnceLock::new();
    *PAGE.get_or_init(|| {
        // SAFETY: `sysconf` reads a system constant and touches no memory of
        // ours.
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(size)
            .ok()
            .filter(|size| size.is_power_of_two())
            .unwrap_or(4096)
    })
}

/// The bytes to allocate for an `n`-byte secret: whole pages, at least one.
/// `None` if rounding up overflows.
fn alloc_size(n: usize, page: usize) -> Option<usize> {
    n.max(1).checked_next_multiple_of(page)
}

/// `N` secret bytes on the heap, in pages of their own, locked in RAM
/// (`mlock`, so never written to swap) and on Linux left out of core dumps
/// (`MADV_DONTDUMP`). Dropping it zeroes the bytes, then unlocks and frees
/// the pages.
///
/// The handle is a pointer, so moving it never copies the secret. Each
/// secret gets whole pages because locks aren't counted: unlocking one
/// secret on a shared page would unlock its neighbours. Locking is best
/// effort ([`is_locked`](Self::is_locked)): it fails once `RLIMIT_MEMLOCK`
/// is spent, and the secret is still wiped on drop. Not `Clone`;
/// [`try_clone`](Self::try_clone) makes a second locked copy on purpose.
pub struct LockedSecret<const N: usize> {
    bytes: NonNull<[u8; N]>,
    layout: Layout,
    locked: bool,
    undumped: bool,
}

// SAFETY: the pages belong to this handle alone, like a `Box<[u8; N]>`'s
// allocation, and are reached only through `&self` or `&mut self`.
unsafe impl<const N: usize> Send for LockedSecret<N> {}
// SAFETY: `&LockedSecret` only reads the bytes; writing needs `&mut`.
unsafe impl<const N: usize> Sync for LockedSecret<N> {}

impl<const N: usize> LockedSecret<N> {
    /// All zeroes, ready to be filled in place through `DerefMut`.
    pub fn new() -> Self {
        let page = page_size();
        let layout = alloc_size(N, page).and_then(|size| Layout::from_size_align(size, page).ok());
        let Some(layout) = layout else {
            panic!("a {N}-byte secret doesn't fit in memory");
        };
        let size = layout.size();
        // SAFETY: `layout` has a nonzero size.
        let raw = unsafe { alloc::alloc_zeroed(layout) };
        let Some(bytes) = NonNull::new(raw.cast::<[u8; N]>()) else {
            alloc::handle_alloc_error(layout)
        };
        // SAFETY: `raw` is our own live allocation of `size` bytes.
        let locked = unsafe { libc::mlock(raw.cast::<c_void>(), size) } == 0;
        let mut secret = Self {
            bytes,
            layout,
            locked,
            undumped: false,
        };
        secret.undumped = secret.advise_dump(false);
        secret
    }

    /// A locked copy of `bytes`. The caller wipes its own copy.
    pub fn from_bytes(bytes: &[u8; N]) -> Self {
        let mut secret = Self::new();
        secret.copy_from_slice(bytes);
        secret
    }

    /// A second, independently locked copy.
    pub fn try_clone(&self) -> Self {
        Self::from_bytes(self)
    }

    /// Whether `mlock` took: the bytes can't be swapped out.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// `MADV_DONTDUMP` (`dump` false) or `MADV_DODUMP` (`dump` true) on our
    /// pages. Whether it took.
    #[cfg(target_os = "linux")]
    fn advise_dump(&mut self, dump: bool) -> bool {
        let advice = if dump {
            libc::MADV_DODUMP
        } else {
            libc::MADV_DONTDUMP
        };
        let start = self.bytes.as_ptr().cast::<c_void>();
        // SAFETY: `start` is the page-aligned start of our own live
        // allocation of `layout.size()` bytes; the advice only changes what a
        // core dump includes.
        unsafe { libc::madvise(start, self.layout.size(), advice) == 0 }
    }

    #[cfg(not(target_os = "linux"))]
    fn advise_dump(&mut self, _dump: bool) -> bool {
        false
    }
}

impl<const N: usize> Default for LockedSecret<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Deref for LockedSecret<N> {
    type Target = [u8; N];

    fn deref(&self) -> &[u8; N] {
        // SAFETY: `bytes` points to our own live, zero-initialized
        // allocation, aligned and big enough for `[u8; N]`, and `&self` rules
        // out a writer.
        unsafe { self.bytes.as_ref() }
    }
}

impl<const N: usize> DerefMut for LockedSecret<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        // SAFETY: as in `deref`, and `&mut self` makes this the only
        // reference.
        unsafe { self.bytes.as_mut() }
    }
}

impl<const N: usize> AsRef<[u8]> for LockedSecret<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> fmt::Debug for LockedSecret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LockedSecret<{N}>([REDACTED])")
    }
}

impl<const N: usize> Drop for LockedSecret<N> {
    fn drop(&mut self) {
        // Wiped while the pages are still locked and out of dumps.
        self.deref_mut().zeroize();
        #[cfg(test)]
        tests::record_drop(self);
        #[cfg(target_os = "linux")]
        if self.undumped {
            let _redumped: bool = self.advise_dump(true);
        }
        if self.locked {
            let start = self.bytes.as_ptr().cast::<c_void>();
            // SAFETY: `start` and `layout.size()` are the range `new` locked,
            // our own allocation, still live.
            let _status: libc::c_int = unsafe { libc::munlock(start, self.layout.size()) };
        }
        // SAFETY: `bytes` came from `alloc_zeroed` with `layout` and is freed
        // once, here; nothing refers to it after `drop`.
        unsafe { alloc::dealloc(self.bytes.as_ptr().cast::<u8>(), self.layout) };
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::process::Command;

    use super::*;

    thread_local! {
        /// The last secret dropped on this thread: whether its bytes were
        /// all zero just before its pages were unlocked and freed.
        static WIPED: Cell<Option<bool>> = const { Cell::new(None) };
    }

    pub(super) fn record_drop<const N: usize>(secret: &LockedSecret<N>) {
        WIPED.set(Some(secret.iter().all(|byte| *byte == 0)));
    }

    fn core_limit() -> libc::rlimit {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a writable `rlimit` for the call to fill.
        let status = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
        assert_eq!(status, 0, "{}", io::Error::last_os_error());
        limit
    }

    fn memlock_limit() -> libc::rlimit {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a writable `rlimit` for the call to fill.
        let status = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) };
        assert_eq!(status, 0, "{}", io::Error::last_os_error());
        limit
    }

    const CHILD: &str = "DEADBOLT_OS_HARDEN_CHILD";

    /// `harden_process` can't be undone, so it runs in a child: this test
    /// binary again, running only [`hardened_child`].
    #[test]
    fn harden_process_in_a_child() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "mem::tests::hardened_child", "--nocapture"])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success(), "{status}");
    }

    #[test]
    fn hardened_child() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        let report = harden_process(HardeningOptions::default());
        assert_eq!(report.core_dumps, Outcome::Applied);
        let core = core_limit();
        assert_eq!((core.rlim_cur, core.rlim_max), (0, 0));
        assert_eq!(report.debugger, Outcome::Disabled);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(report.dumpable, Outcome::Applied);
            // SAFETY: `PR_GET_DUMPABLE` takes no arguments and touches no
            // memory of ours.
            let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
            assert_eq!(dumpable, 0);
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(report.dumpable, Outcome::Unsupported);
        assert_eq!(report.failures().count(), 0);
    }

    #[test]
    fn a_report_lists_its_failures() {
        let report = HardeningReport {
            core_dumps: Outcome::Applied,
            dumpable: Outcome::Failed(libc::EPERM),
            debugger: Outcome::Disabled,
        };
        let failures: Vec<_> = report.failures().collect();
        assert_eq!(failures, [("dumpable", Outcome::Failed(libc::EPERM))]);
        assert!(failures[0].1.to_string().starts_with("failed: "));
    }

    #[test]
    fn a_secret_holds_its_bytes_on_pages_of_its_own() {
        let mut secret = LockedSecret::<32>::new();
        assert_eq!(*secret, [0; 32]);
        secret.copy_from_slice(&[0xa5; 32]);
        assert_eq!(*secret, [0xa5; 32]);
        assert_eq!(secret.as_ref(), &[0xa5; 32][..]);
        let page = page_size();
        let at = secret.as_ptr() as usize;
        assert_eq!(at % page, 0);
        // Moving the handle leaves the bytes where they are.
        let moved = Box::new(secret);
        assert_eq!(moved.as_ptr() as usize, at);
        let memlock = memlock_limit().rlim_cur;
        if memlock == libc::RLIM_INFINITY || memlock >= (4 * page) as libc::rlim_t {
            assert!(moved.is_locked());
        }
    }

    #[test]
    fn sizes_round_up_to_whole_pages_without_overflow() {
        assert_eq!(alloc_size(0, 4096), Some(4096));
        assert_eq!(alloc_size(32, 4096), Some(4096));
        assert_eq!(alloc_size(4096, 4096), Some(4096));
        assert_eq!(alloc_size(4097, 16384), Some(16384));
        assert_eq!(alloc_size(20_000, 4096), Some(20_480));
        assert_eq!(alloc_size(usize::MAX - 10, 4096), None);
        assert_eq!(alloc_size(usize::MAX, 16384), None);
        assert_eq!(alloc_size(usize::MAX - 4095, 4096), Some(usize::MAX - 4095));
    }

    #[test]
    fn a_clone_is_a_separate_copy() {
        let secret = LockedSecret::from_bytes(&[7; 32]);
        let mut copy = secret.try_clone();
        assert_ne!(copy.as_ptr(), secret.as_ptr());
        copy[0] = 8;
        assert_eq!(secret[0], 7);
        assert_eq!(copy[..2], [8, 7]);
    }

    #[test]
    fn debug_redacts_the_bytes() {
        let secret = LockedSecret::from_bytes(&[0x42; 32]);
        assert_eq!(format!("{secret:?}"), "LockedSecret<32>([REDACTED])");
    }

    #[test]
    fn dropping_wipes_before_freeing() {
        WIPED.set(None);
        drop(LockedSecret::from_bytes(&[0xff; 32]));
        assert_eq!(WIPED.get(), Some(true));
        // More than a page.
        WIPED.set(None);
        drop(LockedSecret::<20_000>::from_bytes(&[0x11; 20_000]));
        assert_eq!(WIPED.get(), Some(true));
    }
}
