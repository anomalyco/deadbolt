//! Protocol conformance tests against the vendored `anomalyco/release`
//! test vectors, plus `install.json` receipt and `--json` report unit tests.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use clap::Parser;
use serde::Deserialize;

use super::install::UpdateArgs;
use super::method::{
    CASKROOMS, FileMeta, Install, Manager, RECEIPT_FILE, classify_with_receipt, method_key,
    read_receipt, receipt_trusted,
};
use super::protocol::{Decision, Reason, Running, Target, decide_for, is_version, parse};
use super::report::build_report;

const DECISIONS_JSON: &str = include_str!("fixtures/decisions.json");
const MANIFESTS_JSON: &str = include_str!("fixtures/manifests.json");
const SEMVER_JSON: &str = include_str!("fixtures/semver.json");

#[derive(Deserialize)]
struct ManifestVectors {
    manifests: BTreeMap<String, ManifestEntry>,
}

#[derive(Deserialize)]
struct ManifestEntry {
    manifest: String,
}

#[derive(Deserialize)]
struct DecisionVectors {
    cases: Vec<DecisionCase>,
}

#[derive(Deserialize)]
struct DecisionCase {
    name: String,
    input: DecisionInput,
    expect: ExpectedDecision,
}

#[derive(Deserialize)]
struct DecisionInput {
    app: String,
    artifact: String,
    channel: String,
    manifest: String,
    install: InstallInput,
}

#[derive(Deserialize)]
struct InstallInput {
    target: String,
    distribution: String,
    rollout_bucket: u8,
    version: String,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    channel: Option<String>,
}

#[derive(Deserialize)]
struct ExpectedDecision {
    action: String,
    reason: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    target: Option<Target>,
    #[serde(default)]
    distribution: Option<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    notes_url: Option<String>,
}

#[derive(Deserialize)]
struct SemverVectors {
    valid: Vec<String>,
    invalid: Vec<String>,
}

fn reason_from_str(reason: &str) -> Reason {
    match reason {
        "update" => Reason::Update,
        "required" => Reason::Required,
        "switch" => Reason::Switch,
        other => panic!("unexpected reason in vector: {other}"),
    }
}

#[test]
fn release_protocol_decision_vectors_all_pass() {
    let manifests: ManifestVectors = serde_json::from_str(MANIFESTS_JSON).unwrap();
    let vectors: DecisionVectors = serde_json::from_str(DECISIONS_JSON).unwrap();
    assert_eq!(vectors.cases.len(), 32);

    for case in &vectors.cases {
        let manifest = &manifests
            .manifests
            .get(&case.input.manifest)
            .unwrap_or_else(|| panic!("missing manifest {:?}", case.input.manifest))
            .manifest;
        let running = Running {
            version: &case.input.install.version,
            target: &case.input.install.target,
            distribution: &case.input.install.distribution,
            bucket: case.input.install.rollout_bucket,
            sha256: case.input.install.sha256.as_deref(),
            channel: case.input.install.channel.as_deref(),
        };
        let actual = decide_for(
            &case.input.app,
            &case.input.artifact,
            &case.input.channel,
            manifest,
            &running,
        );
        let expected = match case.expect.action.as_str() {
            "reject" => Decision::Reject(match case.expect.reason.as_str() {
                "malformed" => "malformed",
                "wrong_app" => "wrong_app",
                "wrong_artifact" => "wrong_artifact",
                "wrong_channel" => "wrong_channel",
                other => panic!("unexpected reject reason {other} in {:?}", case.name),
            }),
            "none" => Decision::None(match case.expect.reason.as_str() {
                "up_to_date" => "up_to_date",
                "rollout_deferred" => "rollout_deferred",
                "no_target" => "no_target",
                "distribution_unlisted" => "distribution_unlisted",
                "distribution_pending" => "distribution_pending",
                other => panic!("unexpected none reason {other} in {:?}", case.name),
            }),
            "install" => Decision::Install {
                reason: reason_from_str(&case.expect.reason),
                version: case.expect.version.clone().unwrap(),
                target: case.expect.target.clone().unwrap(),
            },
            "notify" => Decision::Notify {
                reason: reason_from_str(&case.expect.reason),
                version: case.expect.version.clone().unwrap(),
                distribution: case.expect.distribution.clone().unwrap(),
                command: case.expect.command.clone(),
                notes_url: case.expect.notes_url.clone(),
            },
            other => panic!("unexpected action {other} in {:?}", case.name),
        };
        assert_eq!(actual, expected, "vector failed: {}", case.name);
    }
}

#[test]
fn release_protocol_manifest_vectors_all_pass() {
    let manifests: ManifestVectors = serde_json::from_str(MANIFESTS_JSON).unwrap();
    assert_eq!(manifests.manifests.len(), 9);
    for (name, entry) in &manifests.manifests {
        let should_parse = !matches!(name.as_str(), "malformed" | "not-required");
        assert_eq!(
            parse(&entry.manifest).is_some(),
            should_parse,
            "manifest vector failed: {name}"
        );
    }
}

#[test]
fn release_protocol_semver_vectors_all_pass() {
    let manifests: ManifestVectors = serde_json::from_str(MANIFESTS_JSON).unwrap();
    let base_manifest = &manifests.manifests["base"].manifest;
    let vectors: SemverVectors = serde_json::from_str(SEMVER_JSON).unwrap();
    assert_eq!(vectors.valid.len(), 6);
    assert_eq!(vectors.invalid.len(), 11);

    for version in &vectors.valid {
        assert!(is_version(version), "expected valid semver: {version:?}");
        let mut doc: serde_json::Value = serde_json::from_str(base_manifest).unwrap();
        doc["release"]["version"] = serde_json::Value::String(version.clone());
        assert!(
            parse(&doc.to_string()).is_some(),
            "manifest with valid version {version:?} should parse"
        );
    }
    for version in &vectors.invalid {
        assert!(!is_version(version), "expected invalid semver: {version:?}");
        let mut doc: serde_json::Value = serde_json::from_str(base_manifest).unwrap();
        doc["release"]["version"] = serde_json::Value::String(version.clone());
        assert!(
            parse(&doc.to_string()).is_none(),
            "manifest with invalid version {version:?} must be rejected"
        );
    }
}

fn write_receipt(dir: &Path, body: &str) {
    let path = dir.join(RECEIPT_FILE);
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn install_receipt_direct_wins_over_path_heuristics() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    // Place binary under a path that heuristics would classify as Homebrew Cellar.
    let dir = root.join("Cellar/deadbolt/0.1.0/bin");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let exe = dir.join("deadbolt");
    std::fs::write(&exe, "").unwrap();
    write_receipt(
        &dir,
        &serde_json::json!({
            "app": "deadbolt",
            "artifact": "cli",
            "channel": "stable",
            "method": "direct",
            "root": dir,
        })
        .to_string(),
    );

    let install = classify_with_receipt(&exe, false, |_| false);
    assert_eq!(install, Install::Standalone(dir.clone()));
    assert_eq!(method_key(&install), "direct");
}

#[test]
fn install_receipt_desktop_direct_wins_over_caskroom_and_respects_unmovable() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let bundle = root.join("Deadbolt.app");
    let helpers = bundle.join("Contents/Helpers");
    let resources = bundle.join("Contents/Resources");
    std::fs::create_dir_all(&helpers).unwrap();
    std::fs::create_dir_all(&resources).unwrap();
    std::fs::set_permissions(&resources, std::fs::Permissions::from_mode(0o755)).unwrap();
    let exe = helpers.join("deadbolt");
    std::fs::write(&exe, "").unwrap();
    write_receipt(
        &resources,
        &serde_json::json!({
            "app": "deadbolt",
            "artifact": "desktop",
            "channel": "stable",
            "method": "direct",
            "root": bundle,
        })
        .to_string(),
    );

    // Even if a Homebrew Caskroom exists, a direct receipt wins.
    let install = classify_with_receipt(&exe, true, |p| p == Path::new(CASKROOMS[0]));
    assert_eq!(install, Install::App(bundle));
}

#[test]
fn install_receipt_managed_methods_override_path_heuristics() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    for (method, expected) in [
        ("homebrew", Manager::Brew),
        ("brew", Manager::Brew),
        ("brew-cask", Manager::BrewCask),
        ("npm", Manager::Npm),
        ("pnpm", Manager::Pnpm),
        ("bun", Manager::Bun),
        ("yarn", Manager::Yarn),
        ("nix", Manager::Nix),
        ("cargo", Manager::Cargo),
        ("system", Manager::System),
    ] {
        let dir = root.join(method);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exe = dir.join("deadbolt");
        std::fs::write(&exe, "").unwrap();
        write_receipt(
            &dir,
            &serde_json::json!({
                "app": "deadbolt",
                "artifact": "cli",
                "channel": "stable",
                "method": method,
                "root": dir,
            })
            .to_string(),
        );
        let install = classify_with_receipt(&exe, false, |_| false);
        assert_eq!(install, Install::Managed(expected), "method={method}");
    }
}

#[test]
fn install_receipt_corrupt_mismatched_and_untrusted_fall_back_to_heuristics() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();

    // Helper: create a directory under Cellar so heuristic fallback yields Manager::Brew.
    let make_cellar = |name: &str| {
        let dir = root.join(name).join("Cellar/deadbolt/0.1.0/bin");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exe = dir.join("deadbolt");
        std::fs::write(&exe, "").unwrap();
        (dir, exe)
    };

    // 1. Corrupt JSON falls back.
    let (dir, exe) = make_cellar("corrupt");
    write_receipt(&dir, "{not valid json");
    assert_eq!(read_receipt(&exe, false), None);
    assert_eq!(
        classify_with_receipt(&exe, false, |_| false),
        Install::Managed(Manager::Brew)
    );

    // 2. Mismatched app falls back.
    let (dir, exe) = make_cellar("wrong-app");
    write_receipt(
        &dir,
        &serde_json::json!({
            "app": "other-app",
            "artifact": "cli",
            "channel": "stable",
            "method": "direct",
            "root": dir,
        })
        .to_string(),
    );
    assert_eq!(read_receipt(&exe, false), None);
    assert_eq!(
        classify_with_receipt(&exe, false, |_| false),
        Install::Managed(Manager::Brew)
    );

    // 3. Mismatched root falls back.
    let (dir, exe) = make_cellar("wrong-root");
    write_receipt(
        &dir,
        &serde_json::json!({
            "app": "deadbolt",
            "artifact": "cli",
            "channel": "stable",
            "method": "direct",
            "root": root,
        })
        .to_string(),
    );
    assert_eq!(read_receipt(&exe, false), None);
    assert_eq!(
        classify_with_receipt(&exe, false, |_| false),
        Install::Managed(Manager::Brew)
    );

    // 4. World-writable receipt file is untrusted and falls back.
    let (dir, exe) = make_cellar("world-writable-file");
    write_receipt(
        &dir,
        &serde_json::json!({
            "app": "deadbolt",
            "artifact": "cli",
            "channel": "stable",
            "method": "direct",
            "root": dir,
        })
        .to_string(),
    );
    std::fs::set_permissions(
        dir.join(RECEIPT_FILE),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert_eq!(read_receipt(&exe, false), None);
    assert_eq!(
        classify_with_receipt(&exe, false, |_| false),
        Install::Managed(Manager::Brew)
    );

    // 5. Group-writable receipt file is untrusted and falls back.
    let (dir, exe) = make_cellar("group-writable-file");
    write_receipt(
        &dir,
        &serde_json::json!({
            "app": "deadbolt",
            "artifact": "cli",
            "channel": "stable",
            "method": "direct",
            "root": dir,
        })
        .to_string(),
    );
    std::fs::set_permissions(
        dir.join(RECEIPT_FILE),
        std::fs::Permissions::from_mode(0o664),
    )
    .unwrap();
    assert_eq!(read_receipt(&exe, false), None);

    // 6. World-writable directory is untrusted and falls back.
    let (dir, exe) = make_cellar("world-writable-dir");
    write_receipt(
        &dir,
        &serde_json::json!({
            "app": "deadbolt",
            "artifact": "cli",
            "channel": "stable",
            "method": "direct",
            "root": dir,
        })
        .to_string(),
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(read_receipt(&exe, false), None);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    // 7. Symlink receipt is untrusted and falls back.
    let (dir, exe) = make_cellar("symlink");
    let real = root.join("real-install.json");
    std::fs::write(
        &real,
        serde_json::json!({
            "app": "deadbolt",
            "artifact": "cli",
            "channel": "stable",
            "method": "direct",
            "root": dir,
        })
        .to_string(),
    )
    .unwrap();
    std::os::unix::fs::symlink(&real, dir.join(RECEIPT_FILE)).unwrap();
    assert_eq!(read_receipt(&exe, false), None);
}

#[test]
fn receipt_trust_checks_ownership_and_permissions() {
    let dir = FileMeta {
        uid: 501,
        gid: 20,
        mode: 0o755,
        is_file: false,
        is_symlink: false,
        len: 0,
    };
    let file = FileMeta {
        uid: 501,
        gid: 20,
        mode: 0o644,
        is_file: true,
        is_symlink: false,
        len: 128,
    };
    assert!(receipt_trusted("direct", 501, 20, dir, file));
    // Foreign user cannot spoof a direct or managed receipt.
    assert!(!receipt_trusted(
        "direct",
        501,
        20,
        dir,
        FileMeta { uid: 502, ..file }
    ));
    assert!(!receipt_trusted(
        "npm",
        501,
        20,
        dir,
        FileMeta { uid: 502, ..file }
    ));
    // Root-owned managed receipt is trusted, but root-owned direct receipt is not for a normal user.
    let root_dir = FileMeta { uid: 0, ..dir };
    let root_file = FileMeta { uid: 0, ..file };
    assert!(receipt_trusted("homebrew", 501, 20, root_dir, root_file));
    assert!(!receipt_trusted("direct", 501, 20, root_dir, root_file));
    // Group-writable dir only accepted for the user's own primary group.
    assert!(receipt_trusted(
        "direct",
        501,
        20,
        FileMeta { mode: 0o775, ..dir },
        file
    ));
    assert!(!receipt_trusted(
        "direct",
        501,
        20,
        FileMeta {
            mode: 0o775,
            gid: 99,
            ..dir
        },
        file
    ));
    // Oversized or symlinked receipt files are rejected.
    assert!(!receipt_trusted(
        "direct",
        501,
        20,
        dir,
        FileMeta {
            len: 100_000,
            ..file
        }
    ));
    assert!(!receipt_trusted(
        "direct",
        501,
        20,
        dir,
        FileMeta {
            is_symlink: true,
            ..file
        }
    ));
}

#[derive(Parser)]
struct Wrapper {
    #[command(flatten)]
    args: UpdateArgs,
}

#[test]
fn update_json_report_matches_expected_schema() {
    // CLI flag parsing accepts --check --json.
    let parsed = Wrapper::try_parse_from(["deadbolt", "--check", "--json", "--channel", "dev"]);
    assert!(parsed.is_ok());

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    write_receipt(
        &root,
        &serde_json::json!({
            "app": "deadbolt",
            "artifact": "cli",
            "channel": "stable",
            "method": "direct",
            "root": root,
        })
        .to_string(),
    );
    let direct = Install::Standalone(root);

    // 1. Up to date on --check --json.
    let report = build_report(
        "2.4.0",
        "2.4.0",
        "stable",
        &direct,
        &Decision::None("up_to_date"),
        true,
        false,
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "current": "2.4.0",
            "latest": "2.4.0",
            "channel": "stable",
            "available": false,
            "method": "direct",
            "action": "none",
            "reason": "up_to_date",
        })
    );

    // 2. Direct update available on --check --json vs applied on --json.
    let install_decision = Decision::Install {
        reason: Reason::Update,
        version: "2.5.0".into(),
        target: Target {
            url: "/release/deadbolt/files/a/deadbolt.tar.gz".into(),
            size: 1000,
            sha256: "a".repeat(64),
        },
    };
    let check_report = build_report(
        "2.4.0",
        "2.5.0",
        "stable",
        &direct,
        &install_decision,
        true,
        false,
    );
    assert_eq!(
        serde_json::to_value(&check_report).unwrap(),
        serde_json::json!({
            "current": "2.4.0",
            "latest": "2.5.0",
            "channel": "stable",
            "available": true,
            "method": "direct",
            "action": "install",
            "reason": "update",
        })
    );
    let apply_report = build_report(
        "2.4.0",
        "2.5.0",
        "stable",
        &direct,
        &install_decision,
        false,
        false,
    );
    assert_eq!(apply_report.action, "updated");
    assert!(apply_report.available);

    // 3. Managed notify on --check --json includes command and notes_url.
    let notify = Decision::Notify {
        reason: Reason::Update,
        version: "2.5.0".into(),
        distribution: "brew".into(),
        command: Some("brew upgrade anomalyco/tap/deadbolt".into()),
        notes_url: Some("https://anoma.ly/deadbolt/releases/2.5.0".into()),
    };
    let brew_check = build_report(
        "2.4.0",
        "2.5.0",
        "stable",
        &Install::Managed(Manager::Brew),
        &notify,
        true,
        false,
    );
    assert_eq!(
        serde_json::to_value(&brew_check).unwrap(),
        serde_json::json!({
            "current": "2.4.0",
            "latest": "2.5.0",
            "channel": "stable",
            "available": true,
            "method": "brew",
            "action": "notify",
            "reason": "update",
            "command": "brew upgrade anomalyco/tap/deadbolt",
            "notes_url": "https://anoma.ly/deadbolt/releases/2.5.0",
        })
    );
    let brew_apply = build_report(
        "2.4.0",
        "2.5.0",
        "stable",
        &Install::Managed(Manager::Brew),
        &notify,
        false,
        false,
    );
    assert_eq!(brew_apply.action, "updated");

    // 4. Manual manager stays notify even without --check.
    let nix_apply = build_report(
        "2.4.0",
        "2.5.0",
        "stable",
        &Install::Managed(Manager::Nix),
        &Decision::Notify {
            reason: Reason::Update,
            version: "2.5.0".into(),
            distribution: "unknown".into(),
            command: None,
            notes_url: None,
        },
        false,
        false,
    );
    assert_eq!(nix_apply.action, "notify");
    assert_eq!(nix_apply.method, "nix");
    assert!(
        nix_apply
            .command
            .as_deref()
            .is_some_and(|c| c.contains("Nix"))
    );
}
