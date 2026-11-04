use std::path::PathBuf;
use tempfile::TempDir;

use super::*;

const FAST: deadbolt_store::KdfParams = deadbolt_store::KdfParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const PASS: &[u8] = b"correct horse battery staple";
const SECRET: [u8; 32] = [0x42; 32];

#[test]
fn staged_production_helper_matches_pinned_sha256() {
    let staged = PathBuf::from(env!("DEADBOLT_ENCLAVE_STAGED_BIN"));
    let expected = env!("DEADBOLT_ENCLAVE_SHA256");
    assert_eq!(expected.len(), 64);
    macos::verify_helper_at(&staged, expected).unwrap();
}

#[test]
fn adhoc_helper_refuses_app_group_without_touching_containermanager() {
    assert_eq!(group_container("5NZ4Q7NXJ4.pw.deadbolt").unwrap(), None);
    assert!(group_container("not-a-team-group").is_err());
}

#[test]
fn helper_sha256_verification_rejects_tampered_binary() {
    let tmp = TempDir::new().unwrap();
    let fake_helper = tmp.path().join("deadbolt-enclave");
    let expected = env!("DEADBOLT_ENCLAVE_TEST_SHA256");
    std::fs::copy(env!("DEADBOLT_ENCLAVE_TEST_BIN"), &fake_helper).unwrap();
    macos::verify_helper_at(&fake_helper, expected).unwrap();
    // Same inode and length, different bytes. A warm digest is not enough.
    std::io::Write::write_all(
        &mut std::fs::OpenOptions::new()
            .write(true)
            .open(&fake_helper)
            .unwrap(),
        b"BAD!",
    )
    .unwrap();
    assert!(macos::verify_helper_at(&fake_helper, expected).is_err());
    std::fs::write(&fake_helper, b"#!/bin/sh\necho tampered\n").unwrap();
    assert!(macos::verify_helper_at(&fake_helper, env!("DEADBOLT_ENCLAVE_TEST_SHA256")).is_err());
    assert!(macos::verify_helper_at(&fake_helper, "").is_err());
}

/// Without its helper, Deadbolt names the file it's missing rather than
/// going on unchecked.
#[test]
fn a_missing_helper_is_named() {
    let tmp = TempDir::new().unwrap();
    let gone = tmp.path().join("deadbolt-enclave");
    let error = macos::verify_helper_at(&gone, env!("DEADBOLT_ENCLAVE_TEST_SHA256"))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(&format!("{} is missing", gone.display())),
        "{error}"
    );
}

#[test]
fn fat_binary_requires_arm64_and_x86_64_and_matches_current_arch() {
    const ARM64: u32 = 0x0100_000c;
    const X86_64: u32 = 0x0100_0007;
    const OTHER: u32 = 0x0000_0007;

    let arm_slice = b"arm64-helper-slice";
    let x86_slice = b"x86_64-helper-slice";
    let arm_sha = macos::hex_encode(&macos::sha256(arm_slice));
    let x86_sha = macos::hex_encode(&macos::sha256(x86_slice));

    fn build_fat(slices: &[(u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        out.extend_from_slice(&(slices.len() as u32).to_be_bytes());
        let mut offset = 8 + slices.len() * 20;
        for &(cpu, data) in slices {
            out.extend_from_slice(&cpu.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&(offset as u32).to_be_bytes());
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
            offset += data.len();
        }
        for &(_, data) in slices {
            out.extend_from_slice(data);
        }
        out
    }

    let valid_fat = build_fat(&[(ARM64, arm_slice), (X86_64, x86_slice)]);
    // Current arch matches its own slice and rejects the other arch's hash.
    assert!(macos::matches_sha256_or_fat_slice(
        &valid_fat, &arm_sha, ARM64
    ));
    assert!(!macos::matches_sha256_or_fat_slice(
        &valid_fat, &x86_sha, ARM64
    ));
    assert!(macos::matches_sha256_or_fat_slice(
        &valid_fat, &x86_sha, X86_64
    ));
    assert!(!macos::matches_sha256_or_fat_slice(
        &valid_fat, &arm_sha, X86_64
    ));

    // Fat binary with duplicate arch or wrong arch pair is rejected.
    let dup_arch = build_fat(&[(ARM64, arm_slice), (ARM64, x86_slice)]);
    assert!(!macos::matches_sha256_or_fat_slice(
        &dup_arch, &arm_sha, ARM64
    ));
    let wrong_arch = build_fat(&[(ARM64, arm_slice), (OTHER, x86_slice)]);
    assert!(!macos::matches_sha256_or_fat_slice(
        &wrong_arch,
        &arm_sha,
        ARM64
    ));
    let single_slice_fat = build_fat(&[(ARM64, arm_slice)]);
    assert!(!macos::matches_sha256_or_fat_slice(
        &single_slice_fat,
        &arm_sha,
        ARM64
    ));
}

#[test]
fn secure_enclave_headless_roundtrip_and_invalidation() {
    let cap = refresh_status();
    if !cap.enclave {
        eprintln!("skipping Secure Enclave test: no Secure Enclave on this macOS host");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let now = 1_700_000_000;

    let store = deadbolt_store::init_with_params(dir, PASS, SECRET, FAST).unwrap();
    store.append_batch([&b"vault-entry-1"[..]]).unwrap();
    store.meta_set("vault_id", b"v-touchid").unwrap();
    assert!(store.biometric_token().unwrap().is_none());

    let meta = match enroll_with_policy(&store, SealPolicy::HEADLESS_TEST, now) {
        Ok(meta) => meta,
        Err(UnlockError::Unavailable(msg)) => {
            eprintln!(
                "skipping Secure Enclave test: Secure Enclave unavailable in this session ({msg})"
            );
            return;
        }
        Err(err) => panic!("unexpected Secure Enclave enrollment failure: {err}"),
    };
    assert_eq!(meta.created_at, now);
    drop(store);

    assert!(read_token_meta(dir).is_some_and(|m| m.created_at == now));

    let cancel = CancelHandle::new();
    // Headless unseal via Secure Enclave ECDH + HKDF + AES-GCM opens the store
    // with no UI prompt.
    let unlocked = unlock_with_policy(
        dir,
        SealPolicy::HEADLESS_TEST,
        now + 60,
        "",
        &cancel,
        PROMPT_TIMEOUT,
    )
    .unwrap();
    assert_eq!(unlocked.device_secret(), &SECRET);
    assert_eq!(
        unlocked
            .meta_get("vault_id")
            .unwrap()
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"v-touchid"[..])
    );
    let entries: Vec<Vec<u8>> = unlocked
        .iter_all()
        .unwrap()
        .map(|r| r.unwrap().to_vec())
        .collect();
    assert_eq!(entries, vec![b"vault-entry-1".to_vec()]);
    drop(unlocked);

    // Requiring `.biometryCurrentSet` against a non-biometric token is rejected
    // and wipes the slot.
    assert!(matches!(
        unlock_with_policy(
            dir,
            SealPolicy::TOUCH_ID,
            now + 60,
            "",
            &cancel,
            PROMPT_TIMEOUT
        ),
        Err(UnlockError::Invalidated(_))
    ));
    assert!(deadbolt_store::biometric_token(dir).unwrap().is_none());

    // Re-enroll and verify 14-day age expiry wipes the slot.
    let store = deadbolt_store::unlock(dir, PASS).unwrap();
    enroll_with_policy(&store, SealPolicy::HEADLESS_TEST, now).unwrap();
    drop(store);
    let expired = now + MAX_AGE_SECS + 1;
    assert!(matches!(
        unlock_with_policy(
            dir,
            SealPolicy::HEADLESS_TEST,
            expired,
            "",
            &cancel,
            PROMPT_TIMEOUT
        ),
        Err(UnlockError::Expired(_))
    ));
    assert!(deadbolt_store::biometric_token(dir).unwrap().is_none());

    // Re-enroll, mutate the recorded biometric stateHash inside the token,
    // and verify that a fingerprint-set stateHash change wipes the slot.
    let store = deadbolt_store::unlock(dir, PASS).unwrap();
    enroll_with_policy(&store, SealPolicy::HEADLESS_TEST, now).unwrap();
    let mut mutated_token = store.biometric_token().unwrap().unwrap();
    mutated_token[HEADER_LEN + 1] ^= 0xff;
    let fresh_key = deadbolt_store::generate_biometric_key().unwrap();
    store.set_biometric(&fresh_key, &mutated_token).unwrap();
    drop(store);
    assert!(matches!(
        unlock_with_policy(
            dir,
            SealPolicy::HEADLESS_TEST,
            now + 60,
            "",
            &cancel,
            PROMPT_TIMEOUT
        ),
        Err(UnlockError::Invalidated(_))
    ));
    assert!(deadbolt_store::biometric_token(dir).unwrap().is_none());
}

#[test]
fn cancel_and_timeout_kill_in_flight_helper_and_preserve_slot() {
    let cap = refresh_status();
    if !cap.enclave {
        eprintln!("skipping Secure Enclave test: no Secure Enclave on this macOS host");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let now = 1_700_000_000;
    let store = deadbolt_store::init_with_params(dir, PASS, SECRET, FAST).unwrap();
    if matches!(
        enroll_with_policy(&store, SealPolicy::HEADLESS_TEST, now),
        Err(UnlockError::Unavailable(_))
    ) {
        return;
    }
    drop(store);

    let slow_policy = SealPolicy {
        require_biometry: false,
        interactive: false,
        sleep_ms: 5_000,
    };

    // 1. Explicit cancellation kills the helper immediately and returns Cancelled.
    let cancel = CancelHandle::new();
    let cancel_clone = cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(80));
        cancel_clone.cancel();
    });
    let start = Instant::now();
    let err = unlock_with_policy(dir, slow_policy, now + 1, "", &cancel, PROMPT_TIMEOUT)
        .err()
        .unwrap();
    assert!(matches!(err, UnlockError::Cancelled), "got {err:?}");
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(deadbolt_store::biometric_token(dir).unwrap().is_some());

    // 2. Timeout kills the helper and returns Unavailable without wiping the slot.
    let timeout_cancel = CancelHandle::new();
    let start = Instant::now();
    let err = unlock_with_policy(
        dir,
        slow_policy,
        now + 1,
        "",
        &timeout_cancel,
        Duration::from_millis(80),
    )
    .err()
    .unwrap();
    assert!(matches!(err, UnlockError::Unavailable(_)), "got {err:?}");
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(deadbolt_store::biometric_token(dir).unwrap().is_some());
}

#[test]
fn biometry_current_set_never_prompts_when_non_interactive() {
    let cap = refresh_status();
    if !cap.enclave {
        eprintln!("skipping Secure Enclave test: no Secure Enclave on this macOS host");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let now = 1_700_000_000;

    let store = deadbolt_store::init_with_params(dir, PASS, SECRET, FAST).unwrap();
    let policy = SealPolicy {
        require_biometry: true,
        interactive: false,
        sleep_ms: 0,
    };
    let cancel = CancelHandle::new();
    match enroll_with_policy(&store, policy, now) {
        Ok(_) => {
            drop(store);
            let err = unlock_with_policy(dir, policy, now + 1, "", &cancel, PROMPT_TIMEOUT)
                .err()
                .unwrap();
            assert!(
                matches!(err, UnlockError::Unavailable(_)),
                "expected Unavailable for non-interactive biometric unseal, got {err:?}"
            );
            assert!(deadbolt_store::biometric_token(dir).unwrap().is_some());
        }
        Err(UnlockError::Unavailable(_)) => {
            // On a headless Mac without enrolled fingerprints (e.g. Mac mini or CI VM),
            // `.biometryCurrentSet` fails cleanly with Unavailable (exit 11).
        }
        Err(err) => {
            panic!("unexpected enrollment error on host without Touch ID: {err:?}");
        }
    }
}
