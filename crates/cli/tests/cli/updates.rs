use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::*;

const DEV: &str = "/release/deadbolt/cli/dev.json";
const DIST_TAGS: &str = "/release/-/package/@deadbolt/cli/dist-tags";

/// The `cli` manifest for dev at `version`, `sequence`.
fn manifest(version: &str, sequence: u64) -> Vec<u8> {
    let sha = "a".repeat(64);
    let target = serde_json::json!({
        "url": format!("/release/deadbolt/files/{sha}/cli.bin"), "size": 1, "sha256": sha
    });
    serde_json::json!({
        "schema": 1, "app": "deadbolt", "artifact": "cli", "channel": "dev",
        "sequence": sequence, "published_at": "2026-11-01T00:00:00Z",
        "release": {
            "version": version, "rollout_percent": 100,
            "targets": {
                "macos-arm64": target, "macos-x64": target,
                "linux-arm64": target, "linux-x64": target,
                "linux-arm64-musl": target, "linux-x64-musl": target
            },
            "distributions": [{ "kind": "direct" }]
        }
    })
    .to_string()
    .into_bytes()
}

/// The update the daemon's status reply carries, as the app and the
/// terminal notice read it.
fn update(device: &Device) -> Option<deadbolt_client::protocol::UpdateInfo> {
    let paths = deadbolt_client::Paths::from_vars(|name| match name {
        "DEADBOLT_HOME" => Some(device.path("home").into()),
        "XDG_RUNTIME_DIR" => Some(device.path("run").into()),
        "XDG_STATE_HOME" => Some(device.path("state").into()),
        "XDG_CONFIG_HOME" => Some(device.path("config").into()),
        _ => None,
    });
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime
        .block_on(deadbolt_client::status(&paths))
        .expect("the daemon's status")
        .update
}

/// The update the daemon reports, if it answered at all: the bounded wait
/// an opted-out daemon is watched through, without a fixed sleep.
fn reported_update(device: &Device) -> Option<Option<deadbolt_client::protocol::UpdateInfo>> {
    let paths = deadbolt_client::Paths::from_vars(|name| match name {
        "DEADBOLT_HOME" => Some(device.path("home").into()),
        "XDG_RUNTIME_DIR" => Some(device.path("run").into()),
        "XDG_STATE_HOME" => Some(device.path("state").into()),
        "XDG_CONFIG_HOME" => Some(device.path("config").into()),
        _ => None,
    });
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime
        .block_on(deadbolt_client::status(&paths))
        .map(|status| status.update)
}

#[test]
fn the_daemon_tells_status_and_watchers_when_an_update_is_out() {
    let a = Device::new();
    let files = Arc::new(Mutex::new(HashMap::from([(
        DEV.to_string(),
        manifest(env!("CARGO_PKG_VERSION"), 1),
    )])));
    let base = release_service(files.clone());
    let mut watch = a
        .cmd(&["debug", "watch"])
        .env("DEADBOLT_RELEASE_URL", &base)
        .env("DEADBOLT_UPDATE_CHECK_CHANNEL", "dev")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = watch.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let next = || -> serde_json::Value {
        loop {
            let line = rx.recv_timeout(Duration::from_secs(30)).expect("a change");
            let change: serde_json::Value = serde_json::from_str(&line).unwrap();
            if change != serde_json::json!({"change": "activity"}) {
                return change;
            }
        }
    };
    assert_eq!(next(), serde_json::json!({"change": "watching"}));
    assert_eq!(update(&a), None);

    // A new release: the check (every second here) finds it, and only says so.
    files
        .lock()
        .unwrap()
        .insert(DEV.to_string(), manifest("0.0.0-dev-9999", 2));
    assert_eq!(next(), serde_json::json!({"change": "update"}));
    let found = update(&a).expect("an update");
    assert_eq!(found.version, "0.0.0-dev-9999");
    assert_eq!(found.method, "standalone");
    assert_eq!(a.state(), "not set up");

    // Back to this build (a rollback): nothing to say any more.
    files
        .lock()
        .unwrap()
        .insert(DEV.to_string(), manifest(env!("CARGO_PKG_VERSION"), 3));
    assert_eq!(next(), serde_json::json!({"change": "update"}));
    assert_eq!(update(&a), None);
    a.run(&["debug", "daemon", "stop"]);
    assert!(wait(&mut watch, Duration::from_secs(10)).success());

    // Opted out, the daemon never asks. Wait for it to answer, then watch
    // through a check interval (a second here) without an update.
    let b = Device::new();
    files
        .lock()
        .unwrap()
        .insert(DEV.to_string(), manifest("0.0.0-dev-9999", 4));
    let out = b.output(
        b.cmd(&["debug", "whoami"])
            .env("DEADBOLT_RELEASE_URL", &base)
            .env("DEADBOLT_UPDATE_CHECK_CHANNEL", "dev")
            .env("DEADBOLT_NO_UPDATE_CHECK", "1"),
    );
    assert!(out.status.success());
    let deadline = Instant::now() + Duration::from_secs(10);
    while reported_update(&b).is_none() {
        assert!(Instant::now() < deadline, "the daemon never answered");
        std::thread::sleep(Duration::from_millis(50));
    }
    let watch = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < watch {
        assert_eq!(reported_update(&b), Some(None));
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Copies this deadbolt to `to`, with the `deadbolt-enclave` beside it that
/// a macOS build needs to check its daemon.
fn copy_deadbolt(to: &Path) {
    std::fs::copy(BIN, to).unwrap();
    let enclave = Path::new(BIN).with_file_name("deadbolt-enclave");
    if enclave.exists() {
        std::fs::copy(&enclave, to.with_file_name("deadbolt-enclave")).unwrap();
    }
}

/// A bun global install laid out under `root` (`bun/install/global/…`,
/// linked from `bun/bin/deadbolt`), with a fake `bun` beside that link that
/// lists `@deadbolt/cli`, logs its arguments to `root/bun.log` and on
/// `install` puts a new file in place, as bun does: a stand-in whose
/// `--version` says `deadbolt <installs>` and which otherwise runs a copy of
/// this deadbolt, so its daemon starts. Or it fails, when `fails`. Returns
/// the user's link and the installed `deadbolt`.
fn bun_install(root: &Path, installs: &str, fails: bool) -> (PathBuf, PathBuf) {
    let modules = root.join("bun/install/global/node_modules");
    let package = modules.join("@deadbolt/cli-linux-x64");
    let exe = package.join("bin/deadbolt");
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    // A copy, never a hard link: macOS can name any of an inode's links as
    // a running program's path, so other tests' daemons would seem to run it.
    if !exe.exists() {
        copy_deadbolt(&exe);
    }
    std::fs::write(
        package.join("package.json"),
        r#"{"name":"@deadbolt/cli-linux-x64","version":"0.0.1"}"#,
    )
    .unwrap();
    let wrapper = modules.join("@deadbolt/cli");
    std::fs::create_dir_all(wrapper.join("bin")).unwrap();
    std::fs::write(
        wrapper.join("package.json"),
        r#"{"name":"@deadbolt/cli","bin":{"deadbolt":"./bin/deadbolt"}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "../../cli-linux-x64/bin/deadbolt",
        wrapper.join("bin/deadbolt"),
    )
    .ok();
    let bin = root.join("bun/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let link = bin.join("deadbolt");
    std::os::unix::fs::symlink(wrapper.join("bin/deadbolt"), &link).ok();
    let log = root.join("bun.log");
    let install = if fails {
        "echo 'resolving @deadbolt/cli'; echo 'error: GET https://registry.npmjs.org/@deadbolt%2fcli - 503' >&2; exit 1"
            .to_string()
    } else {
        let copy = root.join("new-deadbolt");
        if !copy.exists() {
            copy_deadbolt(&copy);
        }
        format!(
            "/bin/rm -f '{exe}'; printf '#!/bin/sh\\nif [ \"$1\" = --version ]; then echo \"deadbolt {installs} (dev)\"; exit; fi\\nexec \"{copy}\" \"$@\"\\n' > '{exe}'; /bin/chmod 755 '{exe}'",
            exe = exe.display(),
            copy = copy.display()
        )
    };
    let bun = bin.join("bun");
    std::fs::write(
        &bun,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\ncase \"$1\" in\n  pm) echo '/x node_modules (2 installed)'; echo '├── @deadbolt/cli@0.0.1'; exit 0 ;;\n  install) {install} ;;\nesac\n",
            log = log.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&bun, std::fs::Permissions::from_mode(0o755)).unwrap();
    (link, exe)
}

#[test]
fn update_runs_bun_for_a_bun_install_pinned_to_what_npm_serves() {
    let a = Device::new();
    let files = Arc::new(Mutex::new(HashMap::from([
        (DEV.to_string(), manifest("0.0.0-dev-9999", 1)),
        (DIST_TAGS.to_string(), br#"{"dev":"0.0.1"}"#.to_vec()),
    ])));
    let base = release_service(files.clone());
    let root = a.path("user");
    let (link, exe) = bun_install(&root, "0.0.0-dev-9999", true);
    let empty = a.path("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let update = |args: &[&str]| {
        let mut cmd = a.cmd_of(&link, args);
        cmd.env("DEADBOLT_RELEASE_URL", &base)
            .env("DEADBOLT_NPM_REGISTRY_URL", &base)
            .env("PATH", &empty)
            .env("HOME", &root)
            .env_remove("BUN_INSTALL");
        let out = cmd.output().unwrap();
        eprintln!(
            "$ {args:?}\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    };
    let log = || std::fs::read_to_string(root.join("bun.log")).unwrap_or_default();

    // npm still serves the old build: nothing bun could install yet.
    let out = update(&["update", "--check", "--channel", "dev"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("bun doesn't offer"), "{stdout}");
    assert!(log().contains("pm ls -g"), "{}", log());
    assert!(!log().contains("install"));

    // npm serves the wrapper, but not yet this system's platform package.
    files.lock().unwrap().insert(
        DIST_TAGS.to_string(),
        br#"{"dev":"0.0.0-dev-9999"}"#.to_vec(),
    );
    let out = update(&["update", "--check", "--channel", "dev"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("bun doesn't offer"), "{stdout}");

    for target in [
        "linux-x64",
        "linux-arm64",
        "linux-x64-musl",
        "linux-arm64-musl",
        "darwin-arm64",
        "darwin-x64",
    ] {
        let name = format!("@deadbolt/cli-{target}");
        files.lock().unwrap().insert(
            format!("/release/{name}/0.0.0-dev-9999"),
            serde_json::json!({"name": name, "version": "0.0.0-dev-9999"})
                .to_string()
                .into_bytes(),
        );
    }
    let out = update(&["update", "--check", "--channel", "dev"]);
    assert_eq!(out.status.code(), Some(10));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("installed with bun"), "{stdout}");
    assert!(
        stdout.contains(
            "deadbolt update runs: bun install --global --trust @deadbolt/cli@0.0.0-dev-9999"
        ),
        "{stdout}"
    );
    assert!(!log().contains("install --global"));

    // bun fails: its output's end, the command, and what to do.
    let out = update(&["update", "--channel", "dev", "--yes"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("bun couldn't install deadbolt 0.0.0-dev-9999"),
        "{stderr}"
    );
    assert!(stderr.contains("503"), "{stderr}");
    assert!(
        stderr.contains("It ran: bun install --global --trust @deadbolt/cli@0.0.0-dev-9999"),
        "{stderr}"
    );

    // bun works: the new deadbolt answers through the user's link, and the
    // daemon, which ran the old one, comes back on it. bun deletes the file
    // this `deadbolt update` runs from, which mustn't make the new daemon
    // look like it never started.
    bun_install(&root, "0.0.0-dev-9999", false);
    let pid = |status: &str| {
        status
            .strip_prefix("running pid ")
            .and_then(|l| l.split_whitespace().next())
            .map(str::to_string)
    };
    // Through the link: `debug whoami` starts the daemon (or, on macOS, only
    // passes the new deadbolt's daemon check), then `debug daemon` names it.
    let daemon = || {
        assert!(update(&["debug", "whoami"]).status.success());
        String::from_utf8_lossy(&update(&["debug", "daemon"]).stdout).to_string()
    };
    let before = daemon();
    let old = pid(&before).unwrap_or_else(|| panic!("{before}"));
    let out = update(&["update", "--channel", "dev", "--yes"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stdout.contains("Updated"), "{stdout}");
    assert!(stdout.contains("Restarted the daemon."), "{stdout}");
    assert!(!stderr.contains("warning"), "{stderr}");
    let after = daemon();
    let new = pid(&after).unwrap_or_else(|| panic!("{after}"));
    assert_ne!(new, old, "{after}");
    a.run(&["debug", "daemon", "stop"]);
    let ran = log();
    let install = ran.lines().find(|l| l.starts_with("install")).unwrap();
    let args: Vec<&str> = install.split(' ').collect();
    assert_eq!(args[..4], ["install", "--global", "--trust", "--cache-dir"]);
    assert_eq!(args[5], "@deadbolt/cli@0.0.0-dev-9999");
    assert!(!Path::new(args[4]).exists(), "bun's cache is gone");
    assert!(
        std::fs::read_to_string(&exe)
            .unwrap()
            .contains("0.0.0-dev-9999")
    );
}

#[test]
fn update_check_json_emits_structured_report_and_honors_install_receipt() {
    use std::os::unix::fs::PermissionsExt;

    let a = Device::new();
    let bin = a.path("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let exe = bin.join("deadbolt");
    copy_deadbolt(&exe);
    let root = bin.canonicalize().unwrap();
    let receipt = bin.join("install.json");
    std::fs::write(
        &receipt,
        serde_json::json!({
            "app": "deadbolt",
            "artifact": "cli",
            "channel": "dev",
            "method": "direct",
            "root": root,
        })
        .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&receipt, std::fs::Permissions::from_mode(0o644)).unwrap();

    let files = Arc::new(Mutex::new(HashMap::from([(
        DEV.to_string(),
        manifest(env!("CARGO_PKG_VERSION"), 1),
    )])));
    let base = release_service(files.clone());
    let run_json = |args: &[&str]| {
        let mut cmd = a.cmd_of(&exe, args);
        cmd.env("DEADBOLT_RELEASE_URL", &base);
        a.output(&mut cmd)
    };

    // Up to date: exit 0, clean JSON with method = "direct", available = false, action = "none".
    let out = run_json(&["update", "--check", "--channel", "dev", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(
        report,
        serde_json::json!({
            "current": env!("CARGO_PKG_VERSION"),
            "latest": env!("CARGO_PKG_VERSION"),
            "channel": "dev",
            "available": false,
            "method": "direct",
            "action": "none",
            "reason": "up_to_date",
        })
    );

    // Update available: exit 10, clean JSON with available = true, action = "install".
    files
        .lock()
        .unwrap()
        .insert(DEV.to_string(), manifest("0.0.0-dev-9999", 2));
    let out = run_json(&["update", "--check", "--channel", "dev", "--json"]);
    assert_eq!(out.status.code(), Some(10));
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(
        report,
        serde_json::json!({
            "current": env!("CARGO_PKG_VERSION"),
            "latest": "0.0.0-dev-9999",
            "channel": "dev",
            "available": true,
            "method": "direct",
            "action": "install",
            "reason": "update",
        })
    );
}
