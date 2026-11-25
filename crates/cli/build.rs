//! Stamps a build id into the binary so the CLI can tell when a running
//! daemon comes from a different build, even if the crate version is the same,
//! and stamps the release channel it was built for (`DEADBOLT_BUILD_CHANNEL`).
//! The Touch ID helper and its pin come from `crates/enclave`.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[expect(
    clippy::disallowed_methods,
    reason = "build-time composition root reads Cargo target env and stamps the binary identity"
)]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-env-changed=DEADBOLT_BUILD_CHANNEL");

    let commit = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let built = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("cargo:rustc-env=DEADBOLT_BUILD={commit}.{built}");

    // The release channel this build is published on (docs/releasing.md);
    // empty for local builds.
    let channel = std::env::var("DEADBOLT_BUILD_CHANNEL").unwrap_or_default();
    assert!(
        matches!(channel.as_str(), "" | "dev" | "beta" | "stable"),
        "DEADBOLT_BUILD_CHANNEL must be dev, beta or stable, not {channel:?}"
    );
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let long_version = if channel.is_empty() {
        version
    } else {
        format!("{version} ({channel})")
    };
    println!("cargo:rustc-env=DEADBOLT_BUILD_CHANNEL={channel}");
    println!("cargo:rustc-env=DEADBOLT_LONG_VERSION={long_version}");
}
