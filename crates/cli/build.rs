//! Stamps a build id into the binary so the CLI can tell when a running
//! agent comes from a different build, even if the crate version is the same.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    #[expect(
        clippy::disallowed_methods,
        reason = "build-time composition root stamps the binary identity"
    )]
    let built = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("cargo:rustc-env=DEADBOLT_BUILD={commit}.{built}");
}
