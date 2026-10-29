//! The `deadbolt-enclave` beside the agent, checked against the SHA-256 this
//! build pinned (`build.rs`) before the app trusts what it says about the
//! agent, as `deadbolt` checks it before every use (docs/touch-id.md). A
//! universal helper matches by the slice for this Mac's architecture.

use std::path::Path;

use sha2::{Digest, Sha256};

const PINNED: &str = env!("DEADBOLT_ENCLAVE_SHA256");

const FAT_MAGIC: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
#[cfg(target_arch = "aarch64")]
const CURRENT_CPU: u32 = CPU_TYPE_ARM64;
#[cfg(target_arch = "x86_64")]
const CURRENT_CPU: u32 = CPU_TYPE_X86_64;
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const CURRENT_CPU: u32 = 0;

/// Checks `helper` on macOS, the only place the app runs it.
pub fn verify(helper: &Path) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }
    verify_at(helper, PINNED, CURRENT_CPU)
}

fn verify_at(helper: &Path, expected: &str, cpu: u32) -> Result<(), String> {
    if expected.len() != 64 {
        return Err(format!(
            "this build of Deadbolt has no pinned {}, so it can't check its agent. \
             Reinstall Deadbolt (or build it again, after deadbolt-cli)",
            helper.display()
        ));
    }
    if !helper.is_file() {
        return Err(deadbolt_client::peer::missing_helper(helper));
    }
    let bytes = std::fs::read(helper).map_err(|e| format!("reading {}: {e}", helper.display()))?;
    if matches(&bytes, expected, cpu) {
        Ok(())
    } else {
        Err(format!(
            "{} isn't the one this Deadbolt was built with. \
             Reinstall Deadbolt (or build it again, after deadbolt-cli)",
            helper.display()
        ))
    }
}

/// Whether `bytes` (a thin Mach-O, or a universal binary of exactly an arm64
/// and an x86_64 slice that don't overlap) hashes to `expected` for `cpu`.
fn matches(bytes: &[u8], expected: &str, cpu: u32) -> bool {
    if bytes.get(..4) != Some(&FAT_MAGIC[..]) {
        return hex(&Sha256::digest(bytes)) == expected;
    }
    let header_end = 8 + 2 * 20;
    if bytes.len() < header_end || be32(bytes, 4) != Some(2) {
        return false;
    }
    let (Some((cpu0, off0, end0)), Some((cpu1, off1, end1))) = (
        fat_entry(bytes, 8, header_end),
        fat_entry(bytes, 28, header_end),
    ) else {
        return false;
    };
    if !(end0 <= off1 || end1 <= off0) {
        return false;
    }
    let pair = (cpu0 == CPU_TYPE_ARM64 && cpu1 == CPU_TYPE_X86_64)
        || (cpu0 == CPU_TYPE_X86_64 && cpu1 == CPU_TYPE_ARM64);
    if !pair {
        return false;
    }
    let slice = if cpu0 == cpu {
        &bytes[off0..end0]
    } else if cpu1 == cpu {
        &bytes[off1..end1]
    } else {
        return false;
    };
    hex(&Sha256::digest(slice)) == expected
}

/// A `fat_arch` entry's cpu type and slice bounds, which must lie past the
/// header and inside the file.
fn fat_entry(bytes: &[u8], entry: usize, min_offset: usize) -> Option<(u32, usize, usize)> {
    let cpu = be32(bytes, entry)?;
    let offset = usize::try_from(be32(bytes, entry + 8)?).ok()?;
    let size = usize::try_from(be32(bytes, entry + 12)?).ok()?;
    let end = offset.checked_add(size)?;
    (offset >= min_offset && size > 0 && end <= bytes.len()).then_some((cpu, offset, end))
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    let word = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes(word.try_into().ok()?))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(data: &[u8]) -> String {
        hex(&Sha256::digest(data))
    }

    fn fat(slices: &[(u32, &[u8])]) -> Vec<u8> {
        let mut out = FAT_MAGIC.to_vec();
        out.extend_from_slice(&u32::try_from(slices.len()).unwrap().to_be_bytes());
        let mut offset = 8 + slices.len() * 20;
        for &(cpu, data) in slices {
            out.extend_from_slice(&cpu.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&u32::try_from(offset).unwrap().to_be_bytes());
            out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
            offset += data.len();
        }
        for &(_, data) in slices {
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn only_the_pinned_helper_passes() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("deadbolt-enclave");
        let gone = verify_at(&helper, &sha(b"real"), CPU_TYPE_ARM64).unwrap_err();
        assert!(gone.contains("is missing"), "{gone}");
        std::fs::write(&helper, b"real").unwrap();
        verify_at(&helper, &sha(b"real"), CPU_TYPE_ARM64).unwrap();
        let unpinned = verify_at(&helper, "", CPU_TYPE_ARM64).unwrap_err();
        assert!(unpinned.contains("no pinned"), "{unpinned}");
        std::fs::write(&helper, b"#!/bin/sh\necho tampered\n").unwrap();
        let tampered = verify_at(&helper, &sha(b"real"), CPU_TYPE_ARM64).unwrap_err();
        assert!(tampered.contains("Reinstall Deadbolt"), "{tampered}");
    }

    #[test]
    fn a_universal_helper_matches_by_this_macs_slice() {
        let (arm, x86): (&[u8], &[u8]) = (b"arm64 slice", b"x86_64 slice");
        let both = fat(&[(CPU_TYPE_ARM64, arm), (CPU_TYPE_X86_64, x86)]);
        assert!(matches(&both, &sha(arm), CPU_TYPE_ARM64));
        assert!(matches(&both, &sha(x86), CPU_TYPE_X86_64));
        assert!(!matches(&both, &sha(x86), CPU_TYPE_ARM64));
        assert!(!matches(&both, &sha(arm), CPU_TYPE_X86_64));
        for odd in [
            fat(&[(CPU_TYPE_ARM64, arm), (CPU_TYPE_ARM64, x86)]),
            fat(&[(CPU_TYPE_ARM64, arm), (7, x86)]),
            fat(&[(CPU_TYPE_ARM64, arm)]),
            both[..30].to_vec(),
        ] {
            assert!(!matches(&odd, &sha(arm), CPU_TYPE_ARM64));
        }
    }
}
