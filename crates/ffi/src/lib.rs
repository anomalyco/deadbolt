//! Deadbolt for Swift, through UniFFI. `crates/app/scripts/build-autofill.sh`
//! links the static library into `DeadboltAutoFill.appex` and generates its
//! Swift bindings with `bindgen/`, UniFFI's generator at this crate's
//! `uniffi` version.
//!
//! With `client` (the default): the macOS AutoFill extension's side of the
//! App Group socket. One request per connection, line-delimited JSON in
//! [`deadbolt_proto::daemon`]'s schema, with a deadline and a
//! [`CallHandle`] that cancels at once, and the daemon's code checked by
//! [`deadbolt_client::peer::check`] before anything is sent to it. Swift
//! keeps only what needs AppKit or Foundation: finding its bundle and App
//! Group container, and launching the app.

uniffi::setup_scaffolding!();

#[cfg(feature = "client")]
mod autofill;
#[cfg(feature = "client")]
mod call;

#[cfg(feature = "client")]
pub use autofill::*;
#[cfg(feature = "client")]
pub use call::{CallHandle, CallOutcome, autofill_call};

#[cfg(test)]
mod dep_guard_tests {
    use std::path::Path;

    const FORBIDDEN: &[&str] = &[
        "tokio", "zip", "flate2", "tempfile", "reqwest", "hyper", "nix",
    ];

    /// Extracts non-optional dependency names from `[dependencies]` and
    /// target-specific `[target.*.dependencies]` sections of a Cargo.toml.
    fn unconditional_deps(manifest: &str) -> Vec<String> {
        let mut deps = Vec::new();
        let mut in_deps = false;
        for raw in manifest.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                in_deps = line == "[dependencies]"
                    || (line.starts_with("[target.") && line.ends_with(".dependencies]"));
                continue;
            }
            if !in_deps {
                continue;
            }
            let Some((name, rhs)) = line.split_once('=') else {
                continue;
            };
            if rhs.contains("optional = true") || rhs.contains("optional=true") {
                continue;
            }
            deps.push(name.trim().to_owned());
        }
        deps
    }

    /// Keeps `DeadboltAutoFill.appex` lean: `deadbolt-ffi` must disable
    /// `deadbolt-client`'s default `host` feature, and none of the workspace
    /// crates it links may unconditionally pull heavy host dependencies.
    #[test]
    fn autofill_ffi_stays_free_of_host_only_dependencies() {
        let ffi_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let crates_dir = ffi_dir.parent().unwrap();

        let ffi_toml = std::fs::read_to_string(ffi_dir.join("Cargo.toml")).unwrap();
        let client_line = ffi_toml
            .lines()
            .find(|l| l.trim_start().starts_with("deadbolt-client"))
            .expect("deadbolt-ffi depends on deadbolt-client");
        assert!(
            client_line.contains("default-features = false"),
            "deadbolt-ffi must disable deadbolt-client default features: {client_line}"
        );

        for crate_name in ["ffi", "client", "proto", "os"] {
            let manifest =
                std::fs::read_to_string(crates_dir.join(crate_name).join("Cargo.toml")).unwrap();
            let deps = unconditional_deps(&manifest);
            for forbidden in FORBIDDEN {
                assert!(
                    !deps.iter().any(|d| d == forbidden),
                    "crates/{crate_name}/Cargo.toml unconditionally pulls forbidden dep `{forbidden}`"
                );
            }
        }
    }
}
