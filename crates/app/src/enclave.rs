//! The `deadbolt-enclave` beside the daemon, checked against the SHA-256
//! `crates/enclave` pinned (the same pin `deadbolt` is built with) before the
//! app sends the daemon a passphrase, as `deadbolt` checks it before every
//! use (docs/touch-id.md). A universal helper matches by the slice for
//! this Mac's architecture.

use std::path::Path;

/// Checks `helper` on macOS, the only place the app runs it.
pub fn verify(helper: &Path) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }
    // Kept as data, not folded into the comparison under LTO: the release
    // checks find this pin in the app's bytes (bundle.sh, verify-macos-release.sh).
    let pinned = std::hint::black_box(deadbolt_enclave::SHA256);
    verify_at(helper, pinned, deadbolt_enclave::CURRENT_CPU)
}

fn verify_at(helper: &Path, expected: &str, cpu: u32) -> Result<(), String> {
    if expected.len() != 64 {
        return Err(format!(
            "this build of Deadbolt has no pinned {}, so it can't check its daemon. \
             Reinstall Deadbolt",
            helper.display()
        ));
    }
    if !helper.is_file() {
        return Err(deadbolt_client::peer::missing_helper(helper));
    }
    let bytes = std::fs::read(helper).map_err(|e| format!("reading {}: {e}", helper.display()))?;
    if deadbolt_enclave::matches_sha256_or_fat_slice(&bytes, expected, cpu) {
        Ok(())
    } else {
        Err(format!(
            "{} isn't the one this Deadbolt was built with. Reinstall Deadbolt",
            helper.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use deadbolt_enclave::{CPU_TYPE_ARM64, sha256_hex};

    use super::*;

    #[test]
    fn only_the_pinned_helper_passes() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("deadbolt-enclave");
        let gone = verify_at(&helper, &sha256_hex(b"real"), CPU_TYPE_ARM64).unwrap_err();
        assert!(gone.contains("is missing"), "{gone}");
        std::fs::write(&helper, b"real").unwrap();
        verify_at(&helper, &sha256_hex(b"real"), CPU_TYPE_ARM64).unwrap();
        let unpinned = verify_at(&helper, "", CPU_TYPE_ARM64).unwrap_err();
        assert!(unpinned.contains("no pinned"), "{unpinned}");
        std::fs::write(&helper, b"#!/bin/sh\necho tampered\n").unwrap();
        let tampered = verify_at(&helper, &sha256_hex(b"real"), CPU_TYPE_ARM64).unwrap_err();
        assert!(tampered.contains("Reinstall Deadbolt"), "{tampered}");
    }
}
