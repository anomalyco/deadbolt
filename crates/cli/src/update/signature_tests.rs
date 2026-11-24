use ed25519_dalek::{Signer, SigningKey};

use super::*;

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// A throwaway key for these tests, never a release key.
fn signer(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(key: &SigningKey) -> String {
    BASE64.encode(key.verifying_key().as_bytes())
}

fn pinned(keys: &[&SigningKey]) -> Keys {
    let text: Vec<String> = keys.iter().map(|k| public(k)).collect();
    Keys::parse(&text.join("\n")).unwrap()
}

fn statement(version: &str, targets: serde_json::Value) -> Vec<u8> {
    serde_json::json!({
        "schema": 1, "app": "deadbolt", "artifact": "cli", "channel": "stable",
        "version": version, "targets": targets,
    })
    .to_string()
    .into_bytes()
}

fn built() -> serde_json::Value {
    serde_json::json!({
        "linux-x64": { "file": "deadbolt-2.4.0-linux-x64.tar.gz", "size": 1000, "sha256": SHA },
        "macos-arm64": { "file": "deadbolt-2.4.0-darwin-arm64.tar.gz", "size": 2000, "sha256": OTHER },
    })
}

/// The signature file the release workflow writes.
fn envelope(key: &SigningKey, statement: &[u8]) -> Vec<u8> {
    serde_json::json!({
        "schema": 1,
        "key": public(key),
        "statement": BASE64.encode(statement),
        "signature": BASE64.encode(&key.sign(statement).to_bytes()),
    })
    .to_string()
    .into_bytes()
}

fn target(file: &str, size: u64, sha256: &str) -> Target {
    Target {
        url: format!("/release/deadbolt/files/{sha256}/{file}"),
        size,
        sha256: sha256.into(),
    }
}

/// The manifest's targets for what [`built`] lists, and its signature.
fn served() -> BTreeMap<String, Target> {
    BTreeMap::from([
        (
            "linux-x64".into(),
            target("deadbolt-2.4.0-linux-x64.tar.gz", 1000, SHA),
        ),
        (
            "macos-arm64".into(),
            target("deadbolt-2.4.0-darwin-arm64.tar.gz", 2000, OTHER),
        ),
        (
            SIGNATURE_TARGET.into(),
            target("deadbolt-2.4.0-cli.update-signature.json", 300, SHA),
        ),
    ])
}

fn check(keys: &Keys, envelope: &[u8], targets: &BTreeMap<String, Target>) -> Result<()> {
    verify(keys, envelope, "cli", "stable", "2.4.0", targets)
}

#[test]
fn accepts_what_the_release_signed() {
    let key = signer(1);
    let signed = envelope(&key, &statement("2.4.0", built()));
    check(&pinned(&[&key]), &signed, &served()).unwrap();
    // During a rotation either pinned key signs.
    let next = signer(2);
    let rotating = pinned(&[&key, &next]);
    check(&rotating, &signed, &served()).unwrap();
    check(
        &rotating,
        &envelope(&next, &statement("2.4.0", built())),
        &served(),
    )
    .unwrap();
}

#[test]
fn refuses_a_tampered_manifest() {
    let key = signer(1);
    let keys = pinned(&[&key]);
    let signed = envelope(&key, &statement("2.4.0", built()));
    let error = |targets: BTreeMap<String, Target>| check(&keys, &signed, &targets).unwrap_err();

    // Another file, with its own (consistent) digest.
    let mut swapped = served();
    swapped.insert(
        "linux-x64".into(),
        target("deadbolt-2.4.0-linux-x64.tar.gz", 1000, OTHER),
    );
    assert!(error(swapped).to_string().contains("aren't the ones"));
    let mut resized = served();
    resized.get_mut("linux-x64").unwrap().size = 999;
    error(resized);
    let mut renamed = served();
    renamed.insert(
        "linux-x64".into(),
        target("deadbolt-2.3.0-linux-x64.tar.gz", 1000, SHA),
    );
    error(renamed);
    // A target the release didn't build, or one missing.
    let mut extra = served();
    extra.insert(
        "linux-arm64".into(),
        target("deadbolt-2.4.0-linux-arm64.tar.gz", 1, SHA),
    );
    error(extra);
    let mut missing = served();
    missing.remove("macos-arm64");
    error(missing);

    // The signed release names another version, artifact or channel.
    let older = verify(&keys, &signed, "cli", "stable", "2.5.0", &served()).unwrap_err();
    assert!(older.to_string().contains("version"), "{older}");
    verify(&keys, &signed, "desktop", "stable", "2.4.0", &served()).unwrap_err();
    verify(&keys, &signed, "cli", "dev", "2.4.0", &served()).unwrap_err();
}

#[test]
fn refuses_a_tampered_or_foreign_signature() {
    let key = signer(1);
    let keys = pinned(&[&key]);
    let mut doc: serde_json::Value =
        serde_json::from_slice(&envelope(&key, &statement("2.4.0", built()))).unwrap();

    // The statement changed after it was signed.
    let mut tampered = doc.clone();
    tampered["statement"] = BASE64.encode(&statement("2.4.1", built())).into();
    let err = check(&keys, tampered.to_string().as_bytes(), &served()).unwrap_err();
    assert!(err.to_string().contains("doesn't match"), "{err}");

    // Signed by a key this build doesn't pin, even one that names itself.
    let stranger = signer(9);
    let foreign = envelope(&stranger, &statement("2.4.0", built()));
    let err = check(&keys, &foreign, &served()).unwrap_err();
    assert!(err.to_string().contains("doesn't trust"), "{err}");
    doc["key"] = public(&stranger).into();
    check(&keys, doc.to_string().as_bytes(), &served()).unwrap_err();

    // Garbage, unknown fields and schemas.
    check(&keys, b"not json", &served()).unwrap_err();
    let mut unknown = doc.clone();
    unknown["key"] = public(&key).into();
    unknown["extra"] = true.into();
    check(&keys, unknown.to_string().as_bytes(), &served()).unwrap_err();
    let mut schema = doc;
    schema["key"] = public(&key).into();
    schema["schema"] = 2.into();
    check(&keys, schema.to_string().as_bytes(), &served()).unwrap_err();
}

#[test]
fn reads_pinned_keys() {
    let keys = Keys::parse("# a comment\n\n  # indented\n").unwrap();
    assert!(keys.is_empty());
    let key = signer(1);
    let keys = Keys::parse(&format!("# current\n{}\n", public(&key))).unwrap();
    assert_eq!(keys.0, [key.verifying_key()]);
    assert!(Keys::parse("not-base64!").is_err());
    assert!(Keys::parse(&BASE64.encode(&[1; 31])).is_err());
    // The compiled-in list always parses.
    Keys::parse(PINNED).unwrap();
}
