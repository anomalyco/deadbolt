use std::process::Command;

use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use ssh_key::{LineEnding, PrivateKey, PublicKey, SshSig};

use super::*;

#[test]
fn generates_ed25519_and_p256_keys_and_verifies_signatures() {
    for (kind, prefix) in [
        (KeyKind::Ed25519, "ssh-ed25519 "),
        (KeyKind::EcdsaP256, "ecdsa-sha2-nistp256 "),
    ] {
        let made = generate(kind, Some("alice@laptop")).unwrap();
        assert!(made.public_key.starts_with(prefix), "{}", made.public_key);
        assert!(made.public_key.ends_with(" alice@laptop"));
        assert!(made.fingerprint.starts_with("SHA256:"));
        assert!(
            made.private_key
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );

        let parsed = ParsedKey::parse(&made.private_key, None).unwrap();
        assert_eq!(parsed.fingerprint(), made.fingerprint);
        assert_eq!(parsed.comment().as_deref(), Some("alice@laptop"));

        let sig = parsed.sign_agent(b"ssh-challenge", 0).unwrap();
        verify_signature(parsed.public_key(), b"ssh-challenge", &sig).unwrap();
        assert!(verify_signature(parsed.public_key(), b"tampered", &sig).is_err());
        assert!(
            parsed.sign_agent(b"ssh-challenge", RSA_SHA2_512).is_err(),
            "non-RSA keys reject RSA flags"
        );

        let sshsig_pem = parsed
            .sign_sshsig("git", b"commit payload\x00\xff")
            .unwrap();
        let sshsig = SshSig::from_pem(sshsig_pem.as_bytes()).unwrap();
        parsed
            .public_key()
            .verify("git", b"commit payload\x00\xff", &sshsig)
            .unwrap();
        assert!(
            parsed
                .public_key()
                .verify("file", b"commit payload\x00\xff", &sshsig)
                .is_err()
        );
    }
}

#[test]
fn parses_1password_pkcs8_sec1_and_encrypted_openssh_keys() {
    // 1. Ed25519 in PKCS#8 PEM (how 1Password .1pux and `op` export SSH keys).
    let ed = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let pkcs8_pem = ed.to_pkcs8_pem(der::pem::LineEnding::LF).unwrap();
    let parsed_ed = ParsedKey::parse(&pkcs8_pem, None).unwrap();
    let sig = parsed_ed.sign_agent(b"hello-pkcs8", 0).unwrap();
    verify_signature(parsed_ed.public_key(), b"hello-pkcs8", &sig).unwrap();

    // 2. P-256 in both PKCS#8 PEM and SEC1 (`BEGIN EC PRIVATE KEY`) PEM.
    let sk = p256::SecretKey::from_bytes(&[9u8; 32].into()).unwrap();
    let p256_pkcs8 = sk.to_pkcs8_pem(der::pem::LineEnding::LF).unwrap();
    let p256_sec1 = sk.to_sec1_pem(der::pem::LineEnding::LF).unwrap();
    let k1 = ParsedKey::parse(&p256_pkcs8, None).unwrap();
    let k2 = ParsedKey::parse(&p256_sec1, None).unwrap();
    assert_eq!(k1.public_blob().unwrap(), k2.public_blob().unwrap());
    assert_eq!(k1.fingerprint(), k2.fingerprint());

    // 3. Encrypted OpenSSH key requires and verifies its passphrase, and
    // `normalize_import` strips the file passphrase cleanly.
    let plain = PrivateKey::from_openssh(
        generate(KeyKind::Ed25519, Some("enc@host"))
            .unwrap()
            .private_key
            .as_bytes(),
    )
    .unwrap();
    let encrypted = plain
        .encrypt(&mut SysRng, " passphrase-secret ")
        .unwrap()
        .to_openssh(LineEnding::LF)
        .unwrap();
    assert!(ParsedKey::parse(&encrypted, None).is_err());
    assert!(ParsedKey::parse(&encrypted, Some("passphrase-secret")).is_err());
    let imported = normalize_import(&encrypted, Some(" passphrase-secret "), None).unwrap();
    assert_eq!(imported.comment.as_deref(), Some("enc@host"));
    // Re-encoded key is unencrypted inside the vault.
    let reloaded = ParsedKey::parse(&imported.private_key, None).unwrap();
    assert_eq!(reloaded.fingerprint(), imported.fingerprint);
}

#[test]
fn parses_rsa_openssh_and_pkcs8_signs_sha2_and_refuses_sha1() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_rsa");
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "rsa", "-b", "2048", "-N", "", "-C", "rsa@test"])
        .arg("-f")
        .arg(&key_path)
        .status();
    let Ok(status) = status else {
        return;
    };
    assert!(status.success());

    let openssh_pem = std::fs::read_to_string(&key_path).unwrap();
    let pub_line = std::fs::read_to_string(key_path.with_extension("pub")).unwrap();
    let expected_pub = PublicKey::from_openssh(&pub_line).unwrap();

    let parsed = ParsedKey::parse(&openssh_pem, None).unwrap();
    assert_eq!(
        parsed.public_blob().unwrap(),
        expected_pub.key_data().encode_vec().unwrap()
    );
    assert_eq!(parsed.comment().as_deref(), Some("rsa@test"));

    // Legacy SHA-1 (`flags == 0`) is refused.
    assert!(parsed.sign_agent(b"payload", 0).is_err());

    for flag in [RSA_SHA2_256, RSA_SHA2_512, RSA_SHA2_256 | RSA_SHA2_512] {
        let sig = parsed.sign_agent(b"rsa-payload", flag).unwrap();
        verify_signature(&expected_pub, b"rsa-payload", &sig).unwrap();
        assert!(verify_signature(&expected_pub, b"wrong", &sig).is_err());
    }

    // `SSHSIG` output verifies with real OpenSSH `ssh-keygen -Y verify`.
    let sig_pem = parsed.sign_sshsig("git", b"tree 0000\n").unwrap();
    let sig_path = dir.path().join("commit.sig");
    let allowed = dir.path().join("allowed_signers");
    std::fs::write(&sig_path, &sig_pem).unwrap();
    std::fs::write(
        &allowed,
        format!("alice@example.com namespaces=\"git\" {}", pub_line.trim()),
    )
    .unwrap();
    let mut verify = Command::new("ssh-keygen")
        .args([
            "-Y",
            "verify",
            "-f",
            allowed.to_str().unwrap(),
            "-I",
            "alice@example.com",
            "-n",
            "git",
            "-s",
            sig_path.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(verify.stdin.as_mut().unwrap(), b"tree 0000\n").unwrap();
    let out = verify.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "ssh-keygen -Y verify failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
