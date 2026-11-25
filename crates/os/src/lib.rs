//! The few macOS calls Deadbolt makes that no dependency wraps safely, each
//! behind a safe function: a process's BSD facts, executable and arguments
//! (`proc_pidinfo`, `proc_pidpath`, `sysctl`, `devname_r`), and a code
//! object's signing information (`SecCodeCopySigningInformation`). The rest
//! of the workspace forbids `unsafe`; it stays here, in the modules that need
//! it, with a SAFETY comment on every block. What the answers mean, and what
//! to trust, is `deadbolt-client`'s (`peer/macos.rs`).

#[cfg(target_os = "macos")]
pub mod code;
#[cfg(target_os = "macos")]
pub mod process;
