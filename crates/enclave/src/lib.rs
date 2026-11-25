//! The macOS Touch ID helper, `deadbolt-enclave` (`swift/`), and its pin.
//! The build script compiles and signs it (or takes the release's signed one
//! from `DEADBOLT_ENCLAVE_PREBUILT`), stages it beside the binaries in Cargo's
//! profile directory, and hashes it. `deadbolt` checks the helper against
//! [`SHA256`] before running it, and `deadbolt-ui` before trusting what it
//! says about the daemon; both get the same pin from this one build script
//! (docs/touch-id.md). Every value is empty off macOS, or when `swiftc` is
//! missing.

/// The SHA-256 of the production helper's exact signed bytes.
pub const SHA256: &str = env!("DEADBOLT_ENCLAVE_SHA256");
/// The production helper staged in Cargo's profile directory
/// (`target/<triple?>/<profile>/deadbolt-enclave`).
pub const STAGED_BIN: &str = env!("DEADBOLT_ENCLAVE_STAGED_BIN");
/// A helper built with `-DDEADBOLT_TEST`, for tests.
pub const TEST_BIN: &str = env!("DEADBOLT_ENCLAVE_TEST_BIN");
/// The SHA-256 of [`TEST_BIN`].
pub const TEST_SHA256: &str = env!("DEADBOLT_ENCLAVE_TEST_SHA256");

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    /// Release builds take `deadbolt-enclave` from `scripts/build-enclave.sh`,
    /// not `build.rs`, so both compile every Swift source in the helper, or a
    /// release ships a helper missing part of it (caller identity, say).
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
        assert!(sources.len() >= 2, "{sources:?}");
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
