use std::process::Command;

use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use ssh_key::{LineEnding, PrivateKey, PublicKey};

use super::*;

#[test]
fn generates_ed25519_and_p256_keys() {
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
        assert_eq!(parsed.public_openssh(None).unwrap(), made.public_key);
    }
}

#[test]
fn parses_1password_pkcs8_sec1_and_encrypted_openssh_keys() {
    // 1. Ed25519 in PKCS#8 PEM (how 1Password .1pux and `op` export SSH keys).
    let ed = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let pkcs8_pem = ed.to_pkcs8_pem(der::pem::LineEnding::LF).unwrap();
    let parsed_ed = ParsedKey::parse(&pkcs8_pem, None).unwrap();
    assert!(
        parsed_ed
            .public_openssh(None)
            .unwrap()
            .starts_with("ssh-ed25519 ")
    );

    // 2. P-256 in both PKCS#8 PEM and SEC1 (`BEGIN EC PRIVATE KEY`) PEM.
    let sk = p256::SecretKey::from_bytes(&[9u8; 32].into()).unwrap();
    let p256_pkcs8 = sk.to_pkcs8_pem(der::pem::LineEnding::LF).unwrap();
    let p256_sec1 = sk.to_sec1_pem(der::pem::LineEnding::LF).unwrap();
    let k1 = ParsedKey::parse(&p256_pkcs8, None).unwrap();
    let k2 = ParsedKey::parse(&p256_sec1, None).unwrap();
    assert_eq!(
        k1.public_openssh(None).unwrap(),
        k2.public_openssh(None).unwrap()
    );
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
fn parses_rsa_openssh_keys() {
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
        parsed.public_openssh(None).unwrap(),
        expected_pub.to_openssh().unwrap()
    );
    assert_eq!(
        parsed.fingerprint(),
        expected_pub.fingerprint(HashAlg::Sha256).to_string()
    );
    assert_eq!(parsed.comment().as_deref(), Some("rsa@test"));
}
