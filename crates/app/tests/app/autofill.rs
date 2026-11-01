//! Builds `DeadboltAutoFill.appex` and runs the Swift AutoFill extension test
//! suite (unit, offscreen UI snapshots, socket cancellation, bidirectional
//! `LOCAL_PEERTOKEN` code-signature verification on both daemon and extension,
//! silent fill, interactive passphrase unlock, and searchable picker) against
//! a real `deadbolt` daemon in a staged `Deadbolt.app` bundle.

#![cfg(all(debug_assertions, target_os = "macos"))]

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant};

use deadbolt_client::Paths;
use deadbolt_client::protocol::{
    Command as DaemonCommand, FieldInput, Message, PROTOCOL_VERSION, Request,
};

use crate::support::{PASSPHRASE, deadbolt};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

fn plist_value(plist: &Path, key_path: &str) -> String {
    let out = ProcessCommand::new("/usr/libexec/PlistBuddy")
        .args(["-c", &format!("Print :{key_path}")])
        .arg(plist)
        .output()
        .expect("run PlistBuddy");
    assert!(
        out.status.success(),
        "PlistBuddy Print :{key_path} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

struct AutofillDaemonHarness {
    _home_dir: tempfile::TempDir,
    _sock_dir: tempfile::TempDir,
    app_dir: PathBuf,
    app_bin: PathBuf,
    bin: PathBuf,
    runner: PathBuf,
    control_socket: PathBuf,
    autofill_socket: PathBuf,
    vars: HashMap<&'static str, OsString>,
    daemon_child: Option<Child>,
}

impl AutofillDaemonHarness {
    fn new() -> Self {
        let home_dir = tempfile::Builder::new()
            .prefix("dbaf-home-")
            .tempdir()
            .unwrap();
        let sock_dir = tempfile::Builder::new()
            .prefix("dbaf-")
            .tempdir_in("/tmp")
            .unwrap();
        let autofill_dir = sock_dir.path().join("af");
        fs::create_dir_all(&autofill_dir).unwrap();
        fs::set_permissions(&autofill_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let autofill_socket = autofill_dir.join("s");
        assert!(
            autofill_socket.as_os_str().len() <= 103,
            "AutoFill socket path exceeds sun_path: {}",
            autofill_socket.display()
        );

        // Stage a real `Deadbolt.app` layout so `deadbolt-enclave identify`
        // classifies `Contents/MacOS/Deadbolt` as `CallerClass::App` and
        // `Contents/PlugIns/DeadboltAutoFill.appex` as `CallerClass::AutoFill`
        // by kernel audit token + ad-hoc cdhash, and `PeerCheck.verifyDaemon`
        // verifies `Contents/Helpers/deadbolt`.
        let app_dir = home_dir.path().join("Deadbolt.app");
        let macos_dir = app_dir.join("Contents/MacOS");
        let helpers_dir = app_dir.join("Contents/Helpers");
        let appex_dir = app_dir.join("Contents/PlugIns/DeadboltAutoFill.appex");
        let appex_macos = appex_dir.join("Contents/MacOS");
        fs::create_dir_all(&macos_dir).unwrap();
        fs::create_dir_all(&helpers_dir).unwrap();
        fs::create_dir_all(&appex_macos).unwrap();

        let built_cli = fs::canonicalize(deadbolt()).expect("canonicalize deadbolt binary");
        let built_enclave = built_cli.with_file_name("deadbolt-enclave");
        assert!(
            built_enclave.is_file(),
            "missing deadbolt-enclave beside {}",
            built_cli.display()
        );

        let staged_cli = helpers_dir.join("deadbolt");
        let staged_enclave = helpers_dir.join("deadbolt-enclave");
        fs::copy(&built_cli, &staged_cli).unwrap();
        // Copy `deadbolt-enclave` byte-for-byte without re-signing so its
        // pinned `DEADBOLT_ENCLAVE_SHA256` stays intact.
        fs::copy(&built_enclave, &staged_enclave).unwrap();
        fs::set_permissions(&staged_cli, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&staged_enclave, fs::Permissions::from_mode(0o755)).unwrap();

        let sign_cli = ProcessCommand::new("codesign")
            .args(["--force", "--identifier", "deadbolt", "--sign", "-"])
            .arg(&staged_cli)
            .output()
            .expect("codesign staged deadbolt");
        assert!(
            sign_cli.status.success(),
            "codesign staged deadbolt failed: {}",
            String::from_utf8_lossy(&sign_cli.stderr)
        );

        let app_bin = compile_app_socket_helper(&app_dir, home_dir.path());
        let runner = compile_swift_test_appex(&appex_dir, home_dir.path());

        let sign_app = ProcessCommand::new("codesign")
            .args(["--force", "--identifier", "pw.deadbolt.app", "--sign", "-"])
            .arg(&app_dir)
            .output()
            .expect("sign staged Deadbolt.app bundle");
        assert!(
            sign_app.status.success(),
            "codesign staged Deadbolt.app failed: {}",
            String::from_utf8_lossy(&sign_app.stderr)
        );

        let sub = |name: &str| home_dir.path().join(name).into_os_string();
        let vars = HashMap::from([
            ("DEADBOLT_HOME", sub("home")),
            (
                "XDG_RUNTIME_DIR",
                sock_dir.path().join("run").into_os_string(),
            ),
            ("XDG_STATE_HOME", sub("state")),
            ("XDG_CONFIG_HOME", sub("config")),
            ("DEADBOLT_NET", "local".into()),
            ("DEADBOLT_KDF", "fast".into()),
            ("DEADBOLT_TEST_AUTOFILL_DIR", autofill_dir.into_os_string()),
        ]);
        let paths = Paths::from_vars(|name| vars.get(name).cloned());
        let bin = fs::canonicalize(&staged_cli).unwrap();
        Self {
            _home_dir: home_dir,
            _sock_dir: sock_dir,
            app_dir,
            app_bin,
            bin,
            runner,
            control_socket: paths.socket,
            autofill_socket,
            vars,
            daemon_child: None,
        }
    }

    fn start_daemon(&mut self) {
        let child = ProcessCommand::new(&self.bin)
            .args(["daemon"])
            .envs(&self.vars)
            .env_remove("RUST_LOG")
            .env_remove("OPENCODE_SESSION_ID")
            .env_remove("DEADBOLT_CALLER")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn deadbolt daemon");
        self.daemon_child = Some(child);

        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.autofill_socket.exists() || !self.control_socket.exists() {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for sockets at {} and {} (app_dir={})",
                self.control_socket.display(),
                self.autofill_socket.display(),
                self.app_dir.display()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn send_as_app(&self, command: DaemonCommand) -> Message {
        let mut payload = serde_json::to_string(&Request {
            v: PROTOCOL_VERSION,
            claimed: None,
            command,
        })
        .unwrap();
        payload.push('\n');

        let out = ProcessCommand::new(&self.app_bin)
            .arg(&self.control_socket)
            .arg(&payload)
            .stdin(Stdio::null())
            .output()
            .expect("run staged Deadbolt app socket helper");
        assert!(
            out.status.success(),
            "app socket helper failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let line = String::from_utf8(out.stdout).unwrap();
        let msg: Message = serde_json::from_str(line.trim()).expect("decode control socket reply");
        if let Message::Error { code, message, .. } = &msg {
            panic!("control command failed ({code:?}): {message}");
        }
        msg
    }
}

impl Drop for AutofillDaemonHarness {
    fn drop(&mut self) {
        if self.control_socket.exists() {
            let mut payload = serde_json::to_string(&Request {
                v: PROTOCOL_VERSION,
                claimed: None,
                command: DaemonCommand::Stop,
            })
            .unwrap();
            payload.push('\n');
            drop(
                ProcessCommand::new(&self.app_bin)
                    .arg(&self.control_socket)
                    .arg(&payload)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status(),
            );
        }
        if let Some(mut child) = self.daemon_child.take() {
            drop(child.kill());
            drop(child.wait());
        }
    }
}

fn compile_app_socket_helper(app_dir: &Path, scratch: &Path) -> PathBuf {
    let app_plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>pw.deadbolt.app</string>
<key>CFBundleExecutable</key><string>Deadbolt</string>
<key>CFBundleName</key><string>Deadbolt</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.0.0</string>
<key>CFBundleVersion</key><string>1</string>
</dict></plist>
"#;
    fs::write(app_dir.join("Contents/Info.plist"), app_plist).unwrap();

    let c_src = scratch.join("app_relay.c");
    fs::write(
        &c_src,
        r#"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 3;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, argv[1], sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) return 4;
    size_t len = strlen(argv[2]);
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, argv[2] + off, len - off);
        if (n <= 0) return 5;
        off += (size_t)n;
    }
    char buf[4096];
    while (1) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) return 6;
        if (n == 0) break;
        fwrite(buf, 1, (size_t)n, stdout);
        if (memchr(buf, '\n', (size_t)n) != NULL) break;
    }
    close(fd);
    return 0;
}
"#,
    )
    .unwrap();

    let app_bin = app_dir.join("Contents/MacOS/Deadbolt");
    let cc = ProcessCommand::new("clang")
        .args(["-O2", "-Wall", "-Werror"])
        .arg(&c_src)
        .arg("-o")
        .arg(&app_bin)
        .output()
        .expect("compile staged Deadbolt app helper");
    assert!(
        cc.status.success(),
        "clang failed: {}",
        String::from_utf8_lossy(&cc.stderr)
    );
    fs::set_permissions(&app_bin, fs::Permissions::from_mode(0o755)).unwrap();
    fs::canonicalize(&app_bin).unwrap()
}

fn compile_swift_test_appex(appex_dir: &Path, scratch: &Path) -> PathBuf {
    let root = repo_root();
    let autofill_dir = root.join("crates/app/autofill");
    let proto_swift = scratch.join("ProtocolVersion.swift");
    fs::write(
        &proto_swift,
        format!("public let generatedProtocolVersion: UInt32 = {PROTOCOL_VERSION}\n"),
    )
    .expect("write ProtocolVersion.swift");

    let plist_template =
        fs::read_to_string(autofill_dir.join("Info.plist.in")).expect("read Info.plist.in");
    let plist_rendered = plist_template
        .replace("@VERSION@", "0.0.0")
        .replace("@BUILD@", "1");
    fs::write(appex_dir.join("Contents/Info.plist"), plist_rendered).expect("write Info.plist");

    let runner = appex_dir.join("Contents/MacOS/DeadboltAutoFill");
    let sources = [
        proto_swift,
        autofill_dir.join("Protocol.swift"),
        autofill_dir.join("PeerCheck.swift"),
        autofill_dir.join("SocketClient.swift"),
        autofill_dir.join("IdentitySync.swift"),
        autofill_dir.join("ControllerModel.swift"),
        autofill_dir.join("AutoFillView.swift"),
        autofill_dir.join("CredentialProviderViewController.swift"),
        autofill_dir.join("tests/AutoFillTests.swift"),
    ];

    let triple = if cfg!(target_arch = "aarch64") {
        "arm64-apple-macosx14.0"
    } else {
        "x86_64-apple-macosx14.0"
    };

    let out = ProcessCommand::new("swiftc")
        .args([
            "-O",
            "-swift-version",
            "6",
            "-warnings-as-errors",
            "-module-name",
            "DeadboltAutoFill",
            "-parse-as-library",
            "-target",
            triple,
        ])
        .args(&sources)
        .args([
            "-framework",
            "AppKit",
            "-framework",
            "AuthenticationServices",
            "-framework",
            "Security",
            "-o",
        ])
        .arg(&runner)
        .output()
        .expect("invoke swiftc for AutoFillTests");
    assert!(
        out.status.success(),
        "swiftc failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    fs::set_permissions(&runner, fs::Permissions::from_mode(0o755)).unwrap();

    let sign = ProcessCommand::new("codesign")
        .args([
            "--force",
            "--identifier",
            "pw.deadbolt.app.autofill",
            "--sign",
            "-",
        ])
        .arg(appex_dir)
        .output()
        .expect("ad-hoc sign staged DeadboltAutoFill.appex");
    assert!(
        sign.status.success(),
        "codesign DeadboltAutoFill.appex failed: {}",
        String::from_utf8_lossy(&sign.stderr)
    );
    fs::canonicalize(&runner).unwrap()
}

#[test]
fn autofill_appex_bundle_is_valid() {
    let root = repo_root();
    let tmp = tempfile::Builder::new()
        .prefix("dbaf-bundle-")
        .tempdir()
        .unwrap();
    let appex = tmp.path().join("DeadboltAutoFill.appex");

    let out = ProcessCommand::new("bash")
        .arg(root.join("crates/app/scripts/build-autofill.sh"))
        .arg(&appex)
        .args(["0.2.3", "203"])
        .current_dir(&root)
        .output()
        .expect("run build-autofill.sh");
    assert!(
        out.status.success(),
        "build-autofill.sh failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let plist = appex.join("Contents/Info.plist");
    assert_eq!(
        plist_value(&plist, "CFBundleIdentifier"),
        "pw.deadbolt.app.autofill"
    );
    assert_eq!(plist_value(&plist, "CFBundlePackageType"), "XPC!");
    assert_eq!(plist_value(&plist, "CFBundleShortVersionString"), "0.2.3");
    assert_eq!(plist_value(&plist, "CFBundleVersion"), "203");
    assert_eq!(plist_value(&plist, "LSMinimumSystemVersion"), "14.0");
    assert_eq!(
        plist_value(&plist, "NSExtension:NSExtensionPointIdentifier"),
        "com.apple.authentication-services-credential-provider-ui"
    );
    assert_eq!(
        plist_value(&plist, "NSExtension:NSExtensionPrincipalClass"),
        "DeadboltAutoFill.CredentialProviderViewController"
    );
    assert_eq!(
        plist_value(
            &plist,
            "NSExtension:NSExtensionAttributes:ASCredentialProviderExtensionShowsConfigurationUI"
        ),
        "true"
    );
    assert_eq!(
        plist_value(
            &plist,
            "NSExtension:NSExtensionAttributes:ASCredentialProviderExtensionCapabilities:ProvidesPasswords"
        ),
        "true"
    );

    let bin = appex.join("Contents/MacOS/DeadboltAutoFill");
    let symbols = ProcessCommand::new("nm")
        .arg("-u")
        .arg(&bin)
        .output()
        .expect("nm -u DeadboltAutoFill");
    assert!(symbols.status.success());
    let nm_text = String::from_utf8_lossy(&symbols.stdout);
    assert!(
        nm_text.contains("_NSExtensionMain"),
        "DeadboltAutoFill must link _NSExtensionMain: {nm_text}"
    );

    let verify = ProcessCommand::new("codesign")
        .args(["--verify", "--strict"])
        .arg(&appex)
        .output()
        .expect("codesign --verify DeadboltAutoFill.appex");
    assert!(
        verify.status.success(),
        "codesign verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn autofill_swift_extension_end_to_end() {
    let mut harness = AutofillDaemonHarness::new();
    harness.start_daemon();
    harness.send_as_app(DaemonCommand::Setup {
        passphrase: PASSPHRASE.to_string().into(),
        device_name: "Alex's MacBook Pro".into(),
    });
    harness.send_as_app(DaemonCommand::VaultCreate {
        name: "personal".into(),
    });
    harness.send_as_app(DaemonCommand::ItemNew {
        vault: None,
        kind: "login".into(),
        name: Some("GitHub".into()),
        fields: vec![
            FieldInput {
                name: "username".into(),
                kind: None,
                value: "alex@example.com".into(),
            },
            FieldInput {
                name: "url".into(),
                kind: None,
                value: "https://github.com/login".into(),
            },
            FieldInput {
                name: "password".into(),
                kind: None,
                value: "gh-secret-password-42".into(),
            },
        ],
        favorite: false,
        tags: Vec::new(),
    });
    harness.send_as_app(DaemonCommand::ItemNew {
        vault: None,
        kind: "login".into(),
        name: Some("Linear".into()),
        fields: vec![
            FieldInput {
                name: "username".into(),
                kind: None,
                value: "alex@linear.example".into(),
            },
            FieldInput {
                name: "url".into(),
                kind: None,
                value: "https://linear.app".into(),
            },
            FieldInput {
                name: "password".into(),
                kind: None,
                value: "linear-secret-password-99".into(),
            },
        ],
        favorite: false,
        tags: Vec::new(),
    });

    // Any local process other than `DeadboltAutoFill.appex` connecting to the
    // AutoFill socket is rejected via kernel `LOCAL_PEERTOKEN` inspection.
    {
        let mut rogue = UnixStream::connect(&harness.autofill_socket).expect("connect rogue peer");
        writeln!(
            rogue,
            r#"{{"v":{PROTOCOL_VERSION},"cmd":"autofill-status"}}"#
        )
        .unwrap();
        let mut line = String::new();
        BufReader::new(rogue).read_line(&mut line).unwrap();
        let reply: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(reply["type"], "error", "unexpected reply: {line}");
        assert_eq!(reply["code"], "forbidden", "unexpected reply: {line}");
    }

    // Phase 1: Unlocked end-to-end from staged `DeadboltAutoFill.appex`
    // (unit, socket cancel, snapshots, identity sync, silent fill, domain
    // mismatch refusal, unassociated app picker, PeerCheck).
    let unlocked = ProcessCommand::new(&harness.runner)
        .arg("--live-socket")
        .arg(&harness.autofill_socket)
        .arg("--daemon-bin")
        .arg(&harness.bin)
        .args(["--passphrase", PASSPHRASE])
        .output()
        .expect("run AutoFillTests unlocked phase");
    assert!(
        unlocked.status.success(),
        "AutoFillTests unlocked phase failed:\n{}",
        String::from_utf8_lossy(&unlocked.stderr)
    );

    let stdout = String::from_utf8(unlocked.stdout).unwrap();
    let record_id = stdout
        .lines()
        .find_map(|line| line.strip_prefix("RECORD_ID="))
        .expect("AutoFillTests stdout should print RECORD_ID=")
        .trim()
        .to_string();

    // Phase 2: Lock the daemon and verify silent-fill escalation + passphrase unlock + fill.
    harness.send_as_app(DaemonCommand::Lock);
    let locked = ProcessCommand::new(&harness.runner)
        .arg("--live-socket")
        .arg(&harness.autofill_socket)
        .arg("--daemon-bin")
        .arg(&harness.bin)
        .args(["--passphrase", PASSPHRASE])
        .args(["--locked-record-id", &record_id])
        .output()
        .expect("run AutoFillTests locked phase");
    assert!(
        locked.status.success(),
        "AutoFillTests locked phase failed:\n{}",
        String::from_utf8_lossy(&locked.stderr)
    );
}
