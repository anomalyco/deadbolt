//! The macOS Touch ID helper, `deadbolt-enclave` (`swift/`), its pin, and its
//! Mach-O SHA-256 verifier.
//! The build script compiles and signs it (or takes the release's signed one
//! from `DEADBOLT_ENCLAVE_PREBUILT`), stages it beside the binaries in Cargo's
//! profile directory, and hashes it. `deadbolt` checks the helper against
//! [`SHA256`] before running it, and `deadbolt-ui` checks the helper beside its
//! daemon before sending a passphrase (daemon identity itself is verified via
//! `deadbolt-os`); both get the same pin from this one build script
//! (docs/touch-id.md). Every value is empty off macOS, or when `swiftc` is
//! missing.

use sha2::{Digest, Sha256};

/// The SHA-256 of the production helper's exact signed bytes.
pub const SHA256: &str = env!("DEADBOLT_ENCLAVE_SHA256");
/// The production helper staged in Cargo's profile directory
/// (`target/<triple?>/<profile>/deadbolt-enclave`).
pub const STAGED_BIN: &str = env!("DEADBOLT_ENCLAVE_STAGED_BIN");
/// A helper built with `-DDEADBOLT_TEST`, for tests.
pub const TEST_BIN: &str = env!("DEADBOLT_ENCLAVE_TEST_BIN");
/// The SHA-256 of [`TEST_BIN`].
pub const TEST_SHA256: &str = env!("DEADBOLT_ENCLAVE_TEST_SHA256");

const FAT_MAGIC: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];
/// Mach-O `CPU_TYPE_X86_64`.
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;
/// Mach-O `CPU_TYPE_ARM64`.
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;

/// Mach-O CPU type for the architecture this binary was compiled for, or `0`
/// off `aarch64` / `x86_64`.
#[cfg(target_arch = "aarch64")]
pub const CURRENT_CPU: u32 = CPU_TYPE_ARM64;
/// Mach-O CPU type for the architecture this binary was compiled for, or `0`
/// off `aarch64` / `x86_64`.
#[cfg(target_arch = "x86_64")]
pub const CURRENT_CPU: u32 = CPU_TYPE_X86_64;
/// Mach-O CPU type for the architecture this binary was compiled for, or `0`
/// off `aarch64` / `x86_64`.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub const CURRENT_CPU: u32 = 0;

/// Lowercase hexadecimal SHA-256 digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

/// Verifies a thin Mach-O or universal (`lipo -create`) binary against
/// `expected_hex` for the architecture this binary was built for.
pub fn matches_current_arch(bytes: &[u8], expected_hex: &str) -> bool {
    matches_sha256_or_fat_slice(bytes, expected_hex, CURRENT_CPU)
}

/// Verifies a thin Mach-O or universal (`lipo -create`) binary against
/// `expected_hex`.
///
/// Universal binaries must have exactly 2 non-overlapping slices for
/// `{CPU_TYPE_ARM64, CPU_TYPE_X86_64}`, and the slice for `current_cpu`
/// must match `expected_hex`.
pub fn matches_sha256_or_fat_slice(bytes: &[u8], expected_hex: &str, current_cpu: u32) -> bool {
    if expected_hex.len() != 64 {
        return false;
    }
    if bytes.get(..4) != Some(&FAT_MAGIC[..]) {
        return sha256_hex(bytes) == expected_hex;
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
    let valid_pair = (cpu0 == CPU_TYPE_ARM64 && cpu1 == CPU_TYPE_X86_64)
        || (cpu0 == CPU_TYPE_X86_64 && cpu1 == CPU_TYPE_ARM64);
    if !valid_pair {
        return false;
    }
    let slice = if cpu0 == current_cpu {
        &bytes[off0..end0]
    } else if cpu1 == current_cpu {
        &bytes[off1..end1]
    } else {
        return false;
    };
    sha256_hex(slice) == expected_hex
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn build_fat(slices: &[(u32, &[u8])]) -> Vec<u8> {
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
    fn thin_and_universal_binaries_verify_their_slice() {
        let (arm, x86): (&[u8], &[u8]) = (b"arm64 slice", b"x86_64 slice");
        let arm_sha = sha256_hex(arm);
        let x86_sha = sha256_hex(x86);

        assert!(matches_sha256_or_fat_slice(arm, &arm_sha, CPU_TYPE_ARM64));
        assert!(!matches_sha256_or_fat_slice(arm, &x86_sha, CPU_TYPE_ARM64));
        assert!(!matches_sha256_or_fat_slice(arm, "", CPU_TYPE_ARM64));

        let both = build_fat(&[(CPU_TYPE_ARM64, arm), (CPU_TYPE_X86_64, x86)]);
        assert!(matches_sha256_or_fat_slice(&both, &arm_sha, CPU_TYPE_ARM64));
        assert!(matches_sha256_or_fat_slice(
            &both,
            &x86_sha,
            CPU_TYPE_X86_64
        ));
        assert!(!matches_sha256_or_fat_slice(
            &both,
            &x86_sha,
            CPU_TYPE_ARM64
        ));
        assert!(!matches_sha256_or_fat_slice(
            &both,
            &arm_sha,
            CPU_TYPE_X86_64
        ));
        assert!(!matches_sha256_or_fat_slice(&both, &arm_sha, 0));

        // Overlapping slices are rejected.
        let mut overlapping = build_fat(&[(CPU_TYPE_ARM64, arm), (CPU_TYPE_X86_64, x86)]);
        let shared_offset = u32::try_from(8 + 2 * 20).unwrap().to_be_bytes();
        overlapping[28 + 8..28 + 12].copy_from_slice(&shared_offset);
        assert!(!matches_sha256_or_fat_slice(
            &overlapping,
            &arm_sha,
            CPU_TYPE_ARM64
        ));

        for odd in [
            build_fat(&[(CPU_TYPE_ARM64, arm), (CPU_TYPE_ARM64, x86)]),
            build_fat(&[(CPU_TYPE_ARM64, arm), (7, x86)]),
            build_fat(&[(CPU_TYPE_ARM64, arm)]),
            both[..30].to_vec(),
        ] {
            assert!(!matches_sha256_or_fat_slice(&odd, &arm_sha, CPU_TYPE_ARM64));
        }
    }

    /// Release builds take `deadbolt-enclave` from `scripts/build-enclave.sh`,
    /// not `build.rs`, so both compile every Swift source in the helper, or a
    /// release ships a helper missing part of it.
    #[test]
    fn the_release_helper_builds_every_swift_source() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let script = std::fs::read_to_string(root.join("scripts/build-enclave.sh")).unwrap();
        let build = std::fs::read_to_string(root.join("build.rs")).unwrap();
        let mut sources: Vec<String> = std::fs::read_dir(root.join("swift"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.ends_with(".swift"))
            .collect();
        sources.sort();
        assert!(!sources.is_empty(), "{sources:?}");
        for name in &sources {
            assert!(
                script.contains(&format!("\"$src/{name}\"")),
                "build-enclave.sh doesn't compile {name}"
            );
            assert!(
                build.contains(&format!("\"swift/{name}\"")),
                "build.rs doesn't compile {name}"
            );
        }
    }
}
