//! Pins the macOS `deadbolt-enclave` this app relies on to tell its agent
//! apart (`DEADBOLT_ENCLAVE_SHA256`, as `deadbolt` pins it; docs/touch-id.md):
//! the release workflow's prebuilt, signed helper (`DEADBOLT_ENCLAVE_PREBUILT`),
//! else the one `crates/cli/build.rs` staged in this Cargo profile directory.
//! Empty when there is none (other platforms, no `swiftc`), and then the app
//! trusts no agent on macOS, as `deadbolt` does.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

#[expect(
    clippy::disallowed_methods,
    reason = "build script reads Cargo's target and the release workflow's helper"
)]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DEADBOLT_ENCLAVE_PREBUILT");
    let pin = if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let prebuilt = std::env::var_os("DEADBOLT_ENCLAVE_PREBUILT")
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from);
        match prebuilt {
            Some(dir) => {
                let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
                let helper = dir.join(arch).join("deadbolt-enclave");
                println!("cargo:rerun-if-changed={}", helper.display());
                // A release build must never quietly ship an unpinned app.
                let bytes = std::fs::read(&helper).unwrap_or_else(|e| {
                    panic!(
                        "DEADBOLT_ENCLAVE_PREBUILT is set, but reading {}: {e}",
                        helper.display()
                    )
                });
                hex(&Sha256::digest(&bytes))
            }
            None => staged().unwrap_or_else(|| {
                println!(
                    "cargo:warning=no deadbolt-enclave staged yet: build deadbolt-cli first, \
                     or build again, for an app that can check its agent"
                );
                String::new()
            }),
        }
    } else {
        String::new()
    };
    println!("cargo:rustc-env=DEADBOLT_ENCLAVE_SHA256={pin}");
}

/// `target/<triple?>/<profile>/deadbolt-enclave`, where `crates/cli/build.rs`
/// copies the helper it pinned into `deadbolt`.
fn staged() -> Option<String> {
    let out = PathBuf::from(std::env::var_os("OUT_DIR")?);
    let helper = out.ancestors().nth(3).map(|p| p.join("deadbolt-enclave"))?;
    println!("cargo:rerun-if-changed={}", helper.display());
    let bytes = std::fs::read(&helper).ok()?;
    Some(hex(&Sha256::digest(&bytes)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
