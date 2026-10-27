//! Stamps a build id into the binary so the CLI can tell when a running
//! agent comes from a different build, even if the crate version is the same,
//! stamps the release channel it was built for (`DEADBOLT_BUILD_CHANNEL`), and
//! compiles the macOS Secure Enclave helper (`deadbolt-enclave`), or takes a
//! prebuilt, already-signed one from `DEADBOLT_ENCLAVE_PREBUILT` (release
//! builds, docs/releasing.md).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[expect(
    clippy::disallowed_methods,
    reason = "build-time composition root reads Cargo target env and stamps the binary identity"
)]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=src/agent/enclave-Info.plist");
    println!("cargo:rerun-if-env-changed=DEADBOLT_APPLE_SIGNING_IDENTITY");
    println!("cargo:rerun-if-env-changed=DEADBOLT_ENCLAVE_PREBUILT");
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

    let prebuilt = std::env::var_os("DEADBOLT_ENCLAVE_PREBUILT")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from);
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        if let Err(reason) = build_macos_enclave_helpers(prebuilt.as_deref()) {
            // A release build must never quietly ship without Touch ID.
            assert!(
                prebuilt.is_none(),
                "DEADBOLT_ENCLAVE_PREBUILT is set, but: {reason}"
            );
            println!("cargo:warning=building without Touch ID helper: {reason}");
            emit_empty_enclave_env();
        }
    } else {
        emit_empty_enclave_env();
    }
}

fn emit_empty_enclave_env() {
    println!("cargo:rustc-env=DEADBOLT_ENCLAVE_SHA256=");
    println!("cargo:rustc-env=DEADBOLT_ENCLAVE_STAGED_BIN=");
    println!("cargo:rustc-env=DEADBOLT_ENCLAVE_TEST_BIN=");
    println!("cargo:rustc-env=DEADBOLT_ENCLAVE_TEST_SHA256=");
}

#[expect(
    clippy::disallowed_methods,
    reason = "build script reads Cargo TARGET env to compile the macOS Secure Enclave helper"
)]
fn build_macos_enclave_helpers(prebuilt: Option<&Path>) -> Result<(), String> {
    let swift_src = PathBuf::from("src/agent/enclave.swift");
    let build_rs = PathBuf::from("build.rs");
    let plist_path = PathBuf::from("src/agent/enclave-Info.plist");
    let out_dir =
        PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| "OUT_DIR is not set".to_string())?);

    let prod_bin = out_dir.join("deadbolt-enclave");
    let test_bin = out_dir.join("deadbolt-enclave-test");

    let target_triple = std::env::var("TARGET").ok().and_then(|target| {
        if target.starts_with("aarch64-") {
            Some("arm64-apple-macosx12.0")
        } else if target.starts_with("x86_64-") {
            Some("x86_64-apple-macosx12.0")
        } else {
            None
        }
    });

    let signing_identity = std::env::var("DEADBOLT_APPLE_SIGNING_IDENTITY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "-");
    // Where the production helper came from: a prebuilt directory or the
    // signing identity. A change rebuilds both helpers.
    let source = match prebuilt {
        Some(dir) => format!("prebuilt:{}", dir.display()),
        None => signing_identity.clone().unwrap_or_else(|| "-".into()),
    };
    let id_stamp = out_dir.join("deadbolt-enclave.signing-identity");
    let prev_identity = std::fs::read_to_string(&id_stamp).ok();
    let identity_changed = prev_identity.as_deref() != Some(source.as_str());

    match prebuilt {
        Some(dir) => copy_prebuilt(dir, &prod_bin)?,
        None => compile_one(
            &swift_src,
            &build_rs,
            &plist_path,
            target_triple,
            signing_identity.as_deref(),
            identity_changed,
            false,
            &prod_bin,
        )?,
    }
    compile_one(
        &swift_src,
        &build_rs,
        &plist_path,
        target_triple,
        None,
        identity_changed,
        true,
        &test_bin,
    )?;
    std::fs::write(&id_stamp, &source).map_err(|e| format!("write {}: {e}", id_stamp.display()))?;

    let prod_bytes =
        std::fs::read(&prod_bin).map_err(|e| format!("read {}: {e}", prod_bin.display()))?;
    let test_bytes =
        std::fs::read(&test_bin).map_err(|e| format!("read {}: {e}", test_bin.display()))?;

    let prod_sha = hex_encode(&sha256(&prod_bytes));
    let test_sha = hex_encode(&sha256(&test_bytes));

    // Copy the production helper next to the compiled `deadbolt` binary in the
    // Cargo profile directory (`target/<triple?>/<profile>/deadbolt-enclave`)
    // so `bundle.sh` and release packaging reuse the exact signed binary that
    // `build.rs` hashed.
    let profile_dir = out_dir
        .ancestors()
        .nth(3)
        .ok_or_else(|| format!("unexpected OUT_DIR layout: {}", out_dir.display()))?;
    let staged = profile_dir.join("deadbolt-enclave");
    std::fs::copy(&prod_bin, &staged)
        .map_err(|e| format!("copy {} to {}: {e}", prod_bin.display(), staged.display()))?;

    println!("cargo:rustc-env=DEADBOLT_ENCLAVE_SHA256={prod_sha}");
    println!(
        "cargo:rustc-env=DEADBOLT_ENCLAVE_STAGED_BIN={}",
        staged.display()
    );
    println!(
        "cargo:rustc-env=DEADBOLT_ENCLAVE_TEST_BIN={}",
        test_bin.display()
    );
    println!("cargo:rustc-env=DEADBOLT_ENCLAVE_TEST_SHA256={test_sha}");
    Ok(())
}

/// Takes the production helper from `<dir>/<target arch>/deadbolt-enclave`
/// (`crates/cli/scripts/build-enclave.sh`, then signed by the release
/// workflow): it must be a thin Mach-O for the target architecture, and its
/// bytes are pinned exactly as they are, signature included.
#[expect(
    clippy::disallowed_methods,
    reason = "build script reads Cargo's target architecture"
)]
fn copy_prebuilt(dir: &Path, out_bin: &Path) -> Result<(), String> {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let cpu: u32 = match arch.as_str() {
        "aarch64" => 0x0100_000c,
        "x86_64" => 0x0100_0007,
        other => return Err(format!("no prebuilt Touch ID helper for {other:?}")),
    };
    let src = dir.join(&arch).join("deadbolt-enclave");
    println!("cargo:rerun-if-changed={}", src.display());
    let bytes = std::fs::read(&src).map_err(|e| format!("read {}: {e}", src.display()))?;
    let thin = bytes.len() >= 8
        && bytes[..4] == [0xcf, 0xfa, 0xed, 0xfe]
        && u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) == cpu;
    if !thin {
        return Err(format!("{} is not a thin {arch} Mach-O", src.display()));
    }
    std::fs::write(out_bin, &bytes).map_err(|e| format!("write {}: {e}", out_bin.display()))
}

#[expect(
    clippy::too_many_arguments,
    reason = "internal helper compiles production and test Secure Enclave binaries"
)]
fn compile_one(
    swift_src: &Path,
    build_rs: &Path,
    plist_path: &Path,
    target_triple: Option<&str>,
    signing_identity: Option<&str>,
    force_rebuild: bool,
    test_mode: bool,
    out_bin: &Path,
) -> Result<(), String> {
    if !force_rebuild
        && let (Ok(bin_meta), Ok(src_meta), Ok(build_meta)) = (
            std::fs::metadata(out_bin),
            std::fs::metadata(swift_src),
            std::fs::metadata(build_rs),
        )
        && let (Ok(bin_t), Ok(src_t), Ok(build_t)) = (
            bin_meta.modified(),
            src_meta.modified(),
            build_meta.modified(),
        )
        && bin_t >= src_t
        && bin_t >= build_t
    {
        return Ok(());
    }

    // crates/cli/scripts/build-enclave.sh compiles the release helper the same
    // way; keep the two in step.
    let mut cmd = Command::new("swiftc");
    cmd.args(["-O", "-parse-as-library"]);
    if let Some(triple) = target_triple {
        cmd.args(["-target", triple]);
    }
    if test_mode {
        cmd.arg("-DDEADBOLT_TEST");
    }
    cmd.arg(swift_src)
        .args([
            "-Xlinker",
            "-sectcreate",
            "-Xlinker",
            "__TEXT",
            "-Xlinker",
            "__info_plist",
            "-Xlinker",
        ])
        .arg(plist_path)
        .arg("-o")
        .arg(out_bin);

    let out = cmd
        .output()
        .map_err(|e| format!("failed to run swiftc: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "swiftc exited with {}: {}",
            out.status,
            stderr.trim()
        ));
    }

    drop(Command::new("strip").arg(out_bin).status());
    let mut sign_cmd = Command::new("codesign");
    sign_cmd.arg("--force");
    if let Some(identity) = signing_identity {
        sign_cmd.args(["--options", "runtime", "--timestamp", "--sign", identity]);
    } else {
        sign_cmd.args(["--sign", "-"]);
    }
    let sign = sign_cmd
        .arg(out_bin)
        .output()
        .map_err(|e| format!("failed to run codesign: {e}"))?;
    if !sign.status.success() {
        let stderr = String::from_utf8_lossy(&sign.stderr);
        return Err(format!(
            "codesign exited with {}: {}",
            sign.status,
            stderr.trim()
        ));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

/// FIPS 180-4 / RFC 6234 SHA-256.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() + 8) % 64 != 0 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let b = i * 4;
            *word = u32::from_be_bytes([chunk[b], chunk[b + 1], chunk[b + 2], chunk[b + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}
