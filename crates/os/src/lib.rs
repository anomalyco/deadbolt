//! The few OS calls Deadbolt makes that no dependency wraps safely, each
//! behind a safe function. On macOS: a process's BSD facts, executable and
//! arguments (`proc_pidinfo`, `proc_pidpath`, `sysctl`, `devname_r`), and a
//! code object's signing information (`SecCodeCopySigningInformation`). On
//! Unix: hardening the daemon's process and locking key memory (`mem`), and
//! finding which process in a tree holds a loopback connection (`net`). The
//! rest of the workspace forbids `unsafe`; it stays here, in the modules
//! that need it, with a SAFETY comment on every block. What the process
//! answers mean, and what to trust, is `deadbolt-client`'s (`peer/macos.rs`).

#[cfg(target_os = "macos")]
pub mod code;
#[cfg(unix)]
pub mod mem;
#[cfg(unix)]
pub mod net;
#[cfg(target_os = "macos")]
pub mod process;
