use super::*;

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn manifest(rollout: u8, required: bool) -> String {
    serde_json::json!({
        "schema": 1,
        "app": "deadbolt",
        "artifact": "cli",
        "channel": "stable",
        "sequence": 7,
        "published_at": "2026-10-28T00:00:00Z",
        "release": {
            "version": "2.4.0",
            "rollout_percent": rollout,
            "required": required,
            "targets": {
                "macos-arm64": {
                    "url": format!("/release/deadbolt/files/{SHA}/deadbolt-2.4.0-darwin-arm64.tar.gz"),
                    "size": 1000,
                    "sha256": SHA,
                }
            },
            "distributions": [
                { "kind": "direct" },
                { "kind": "brew", "formula": "anomalyco/tap/deadbolt", "version": "2.3.9",
                  "command": "brew upgrade anomalyco/tap/deadbolt" },
                { "kind": "aur", "package": "deadbolt-bin" }
            ],
            "revoked_versions": [],
            "future_field": true
        }
    })
    .to_string()
}

fn running(version: &'static str, distribution: &'static str, bucket: u8) -> Running<'static> {
    Running {
        version,
        target: "macos-arm64",
        distribution,
        bucket,
        channel: None,
    }
}

fn install(reason: Reason) -> Decision {
    Decision::Install {
        reason,
        version: "2.4.0".into(),
        target: Target {
            url: format!("/release/deadbolt/files/{SHA}/deadbolt-2.4.0-darwin-arm64.tar.gz"),
            size: 1000,
            sha256: SHA.into(),
        },
    }
}

#[test]
fn decides_like_the_release_protocol() {
    let text = manifest(25, false);
    let decide = |r: &Running| decide("cli", "stable", &text, r);
    assert_eq!(
        decide(&running("2.3.8", "direct", 24)),
        install(Reason::Update)
    );
    assert_eq!(
        decide(&running("2.3.8", "direct", 25)),
        Decision::None("rollout_deferred")
    );
    // Versions are never ordered: a "newer" build still moves to the release.
    assert_eq!(
        decide(&running("9.0.0", "direct", 0)),
        install(Reason::Update)
    );
    assert_eq!(
        decide(&running("2.4.0", "direct", 0)),
        Decision::None("up_to_date")
    );
    let other = Running {
        target: "linux-riscv",
        ..running("2.3.8", "direct", 0)
    };
    assert_eq!(decide(&other), Decision::None("no_target"));
    let switch = Running {
        channel: Some("dev"),
        ..running("0.0.0-dev-9", "direct", 99)
    };
    assert_eq!(decide(&switch), install(Reason::Switch));
    let required = manifest(0, true);
    assert_eq!(
        super::decide("cli", "stable", &required, &running("2.3.8", "direct", 99)),
        install(Reason::Required)
    );
    // A package manager's install follows what that manager serves.
    assert_eq!(
        decide(&running("2.3.8", "brew", 0)),
        Decision::Notify {
            reason: Reason::Update,
            version: "2.3.9".into(),
            command: Some("brew upgrade anomalyco/tap/deadbolt".into()),
            notes_url: None,
        }
    );
    assert_eq!(
        decide(&running("2.3.9", "brew", 0)),
        Decision::None("up_to_date")
    );
    assert_eq!(
        decide(&running("2.3.8", "aur", 0)),
        Decision::None("distribution_pending")
    );
    assert_eq!(
        decide(&running("2.3.8", "nix", 0)),
        Decision::None("distribution_unlisted")
    );
    assert_eq!(
        decide(&running("2.3.8", "unknown", 0)),
        Decision::Notify {
            reason: Reason::Update,
            version: "2.4.0".into(),
            command: None,
            notes_url: None,
        }
    );
}

#[test]
fn rejects_manifests_that_are_not_this_one() {
    let r = running("2.3.8", "direct", 0);
    let text = manifest(100, false);
    assert_eq!(
        decide("desktop", "stable", &text, &r),
        Decision::Reject("wrong_artifact")
    );
    assert_eq!(
        decide("cli", "dev", &text, &r),
        Decision::Reject("wrong_channel")
    );
    let other = text.replace("\"deadbolt\"", "\"hex\"");
    assert_eq!(
        decide("cli", "stable", &other, &r),
        Decision::Reject("wrong_app")
    );
    for bad in [
        "not json".to_string(),
        text.replace("\"schema\":1", "\"schema\":2"),
        text.replace("\"rollout_percent\":100", "\"rollout_percent\":101"),
        text.replace(SHA, "AAAA"),
        text.replace("\"size\":1000", "\"size\":-1"),
    ] {
        assert_eq!(
            decide("cli", "stable", &bad, &r),
            Decision::Reject("malformed"),
            "{bad}"
        );
    }
}

#[test]
fn keeps_one_rollout_bucket() {
    let dir = tempfile::tempdir().unwrap();
    let first = rollout_bucket(dir.path());
    assert!(first < 100);
    assert_eq!(rollout_bucket(dir.path()), first);
    std::fs::write(dir.path().join("rollout-bucket"), "250\n").unwrap();
    assert!(rollout_bucket(dir.path()) < 100);
    std::fs::write(dir.path().join("rollout-bucket"), "42\n").unwrap();
    assert_eq!(rollout_bucket(dir.path()), 42);
}

#[test]
fn classifies_installs() {
    let none = |_: &Path| false;
    let app = Path::new("/Applications/Deadbolt.app/Contents/Helpers/deadbolt");
    assert_eq!(
        classify(app, true, none),
        Install::App("/Applications/Deadbolt.app".into())
    );
    assert_eq!(
        classify(app, true, |p| p == Path::new(CASKROOMS[0])),
        Install::Managed(Manager::BrewCask)
    );
    assert_eq!(
        classify(
            Path::new("/Volumes/Deadbolt/Deadbolt.app/Contents/Helpers/deadbolt"),
            true,
            none
        ),
        Install::Unmovable("/Volumes/Deadbolt/Deadbolt.app".into())
    );
    assert!(matches!(
        classify(
            Path::new(
                "/private/var/folders/x/AppTranslocation/ABC/d/Deadbolt.app/Contents/Helpers/deadbolt"
            ),
            true,
            none
        ),
        Install::Unmovable(_)
    ));
    // Off macOS a bundle is just a directory.
    assert_eq!(
        classify(app, false, none),
        Install::Standalone(app.parent().unwrap().into())
    );
    for (path, manager) in [
        (
            "/opt/homebrew/Cellar/deadbolt/0.1.0/bin/deadbolt",
            Manager::Brew,
        ),
        (
            "/home/linuxbrew/.linuxbrew/Cellar/deadbolt/0.1.0/bin/deadbolt",
            Manager::Brew,
        ),
        ("/nix/store/abc-deadbolt/bin/deadbolt", Manager::Nix),
        ("/usr/bin/deadbolt", Manager::System),
        ("/home/me/.cargo/bin/deadbolt", Manager::Cargo),
        (
            "/usr/local/lib/node_modules/@deadbolt/cli-linux-x64/bin/deadbolt",
            Manager::Package,
        ),
        (
            "/opt/homebrew/lib/node_modules/@deadbolt/cli-darwin-arm64/Deadbolt.app/Contents/Helpers/deadbolt",
            Manager::Package,
        ),
        (
            "/usr/lib/node_modules/@deadbolt/cli-linux-x64/bin/deadbolt",
            Manager::Package,
        ),
        (
            "/home/me/.bun/install/global/node_modules/@deadbolt/cli-linux-x64/bin/deadbolt",
            Manager::Package,
        ),
    ] {
        assert_eq!(
            classify(Path::new(path), true, none),
            Install::Managed(manager),
            "{path}"
        );
    }
    for path in ["/home/me/.local/bin/deadbolt", "/usr/local/bin/deadbolt"] {
        let path = Path::new(path);
        assert_eq!(
            classify(path, true, none),
            Install::Standalone(path.parent().unwrap().into())
        );
    }
}

fn service_base(over: Option<&str>) -> Result<Url> {
    loopback_or(SERVICE, SERVICE_OVERRIDE, over)
}

#[test]
fn asks_the_manager_in_the_path_first() {
    use Manager::*;
    let order = |p: &str| manager_order(Path::new(p));
    assert_eq!(
        order("/home/me/.bun/install/global/node_modules/@deadbolt/cli-linux-x64/bin/deadbolt"),
        [Bun, Npm, Pnpm, Yarn]
    );
    assert_eq!(
        order("/opt/bun-root/install/global/node_modules/@deadbolt/cli/bin/deadbolt"),
        [Bun, Npm, Pnpm, Yarn]
    );
    assert_eq!(
        order(
            "/home/me/.local/share/pnpm/global/5/node_modules/@deadbolt/cli-linux-x64/bin/deadbolt"
        ),
        [Pnpm, Npm, Bun, Yarn]
    );
    assert_eq!(
        order("/home/me/.config/yarn/global/node_modules/@deadbolt/cli-linux-x64/bin/deadbolt"),
        [Yarn, Npm, Pnpm, Bun]
    );
    assert_eq!(
        order("/usr/local/lib/node_modules/@deadbolt/cli-linux-x64/bin/deadbolt"),
        [Npm, Pnpm, Bun, Yarn]
    );
}

#[test]
fn reads_whether_a_manager_lists_the_package() {
    for yes in [
        "/usr/lib\n└── @deadbolt/cli@0.0.0-dev-140\n",
        "dependencies:\n@deadbolt/cli 0.0.0-dev-140\n",
        "├── @deadbolt/cli@0.0.0-dev-136\n├── cf@1.0.0\n",
        "info \"@deadbolt/cli@0.0.0-dev-1\" has binaries:\n",
        "@deadbolt/cli",
    ] {
        assert!(lists_package(yes), "{yes}");
    }
    for no in [
        "/usr/lib\n└── (empty)\n",
        "├── @deadbolt/cli-linux-x64@0.0.0-dev-136\n",
        "@deadbolt/client@1.0.0",
        "",
    ] {
        assert!(!lists_package(no), "{no}");
    }
}

/// Lays out `@deadbolt/cli` and a platform package under `modules`,
/// the wrapper's `bin/deadbolt` linked to `exe` (relative to the
/// platform package) as the postinstall links it; returns `exe`.
fn npm_layout(modules: &Path, platform: &str, exe: &str, wrapper: &Path) -> PathBuf {
    let package = modules.join("@deadbolt").join(platform);
    let exe = package.join(exe);
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    std::fs::write(&exe, "").unwrap();
    std::fs::write(
        package.join("package.json"),
        format!(r#"{{"name":"@deadbolt/{platform}","version":"1"}}"#),
    )
    .unwrap();
    std::fs::create_dir_all(wrapper.join("bin")).unwrap();
    std::fs::write(
        wrapper.join("package.json"),
        r#"{"name":"@deadbolt/cli","bin":{"deadbolt":"./bin/deadbolt"}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(&exe, wrapper.join("bin/deadbolt")).unwrap();
    exe.canonicalize().unwrap()
}

#[test]
fn knows_its_own_package_by_the_wrappers_link() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    // Hoisted, as bun and npm install it.
    let modules = root.join("bun/install/global/node_modules");
    let wrapper = modules.join("@deadbolt/cli");
    let exe = npm_layout(&modules, "cli-linux-x64", "bin/deadbolt", &wrapper);
    assert_eq!(package_of(&exe), Some(wrapper.clone()));
    // A Deadbolt.app helper in the darwin package.
    let modules = root.join("brew/lib/node_modules");
    let wrapper = modules.join("@deadbolt/cli");
    let app = "Deadbolt.app/Contents/Helpers/deadbolt";
    let exe = npm_layout(&modules, "cli-darwin-arm64", app, &wrapper);
    assert_eq!(package_of(&exe), Some(wrapper));
    // Nested in the wrapper, where the postinstall installs it itself.
    let wrapper = root.join("npm/lib/node_modules/@deadbolt/cli");
    let nested = wrapper.join("platform/node_modules");
    let exe = npm_layout(&nested, "cli-linux-x64", "bin/deadbolt", &wrapper);
    assert_eq!(package_of(&exe), Some(wrapper));
    // A wrapper that links elsewhere, or another package, isn't ours.
    let modules = root.join("other/node_modules");
    let wrapper = modules.join("@deadbolt/cli");
    let exe = npm_layout(&modules, "cli-linux-x64", "bin/deadbolt", &wrapper);
    let other = modules.join("@deadbolt/cli-linux-x64/bin/other");
    std::fs::write(&other, "").unwrap();
    assert_eq!(package_of(&other), None);
    std::fs::write(
        modules.join("@deadbolt/cli-linux-x64/package.json"),
        r#"{"name":"@evil/cli"}"#,
    )
    .unwrap();
    assert_eq!(package_of(&exe), None);
    assert_eq!(package_of(Path::new("/usr/local/bin/deadbolt")), None);
}

#[test]
fn runs_each_managers_own_command_pinned_to_the_version() {
    let shown = |m| upgrade_command(m, "0.0.0-dev-140").map(|u| u.shown);
    assert_eq!(
        shown(Manager::Npm).unwrap(),
        "npm install --global @deadbolt/cli@0.0.0-dev-140"
    );
    assert_eq!(
        shown(Manager::Pnpm).unwrap(),
        "pnpm add --global --allow-build=@deadbolt/cli @deadbolt/cli@0.0.0-dev-140"
    );
    assert_eq!(
        shown(Manager::Bun).unwrap(),
        "bun install --global --trust @deadbolt/cli@0.0.0-dev-140"
    );
    assert_eq!(
        shown(Manager::Yarn).unwrap(),
        "yarn global add @deadbolt/cli@0.0.0-dev-140"
    );
    assert_eq!(
        shown(Manager::Brew).unwrap(),
        "brew upgrade anomalyco/tap/deadbolt"
    );
    assert_eq!(
        shown(Manager::BrewCask).unwrap(),
        "brew upgrade --cask anomalyco/tap/deadbolt"
    );
    for manual in [
        Manager::Nix,
        Manager::Cargo,
        Manager::System,
        Manager::Package,
    ] {
        assert_eq!(shown(manual), None);
        assert!(!manual.hint("dev").is_empty());
    }
    let bun = upgrade_command(Manager::Bun, "1").unwrap();
    assert!(bun.own_cache && bun.program == "bun");
    assert!(!upgrade_command(Manager::Npm, "1").unwrap().own_cache);
    assert_eq!(
        Manager::Bun.hint("stable"),
        "bun install --global --trust @deadbolt/cli@latest"
    );
    assert!(Manager::Package.hint("dev").contains("@deadbolt/cli@dev"));
}

#[test]
fn npm_installs_only_offer_what_npm_serves() {
    let notify = |version: &str| Decision::Notify {
        reason: Reason::Update,
        version: version.into(),
        command: None,
        notes_url: None,
    };
    let pending = Decision::None("distribution_pending");
    assert_eq!(
        served_by_npm(notify("2"), Some("2"), Some("2")),
        notify("2")
    );
    assert_eq!(served_by_npm(notify("2"), Some("1"), Some("2")), pending);
    assert_eq!(served_by_npm(notify("2"), None, None), pending);
    // The wrapper is out but not yet this system's platform package.
    assert_eq!(served_by_npm(notify("2"), Some("2"), None), pending);
    assert_eq!(
        served_by_npm(Decision::None("up_to_date"), None, None),
        Decision::None("up_to_date")
    );
    // The manifest's rules still hold: npm's version alone offers nothing.
    let text = manifest(0, false);
    let d = decide("cli", "stable", &text, &running("2.3.8", "unknown", 50));
    assert_eq!(
        served_by_npm(d, Some("2.4.0"), Some("2.4.0")),
        Decision::None("rollout_deferred")
    );
}

#[test]
fn waits_for_the_platform_package_the_postinstall_picks() {
    let never = || -> bool { panic!("only Linux asks about libc") };
    assert_eq!(
        platform_package("macos-arm64", never),
        "@deadbolt/cli-darwin-arm64"
    );
    // glibc gets the build with the app, even where the static build runs.
    assert_eq!(
        platform_package("linux-x64-musl", || false),
        "@deadbolt/cli-linux-x64"
    );
    assert_eq!(
        platform_package("linux-arm64", || true),
        "@deadbolt/cli-linux-arm64-musl"
    );
    assert!(!static_for(
        "ldd (Ubuntu GLIBC 2.35-0ubuntu3.8) 2.35\nCopyright (C) 2022"
    ));
    assert!(static_for("ldd (GNU libc) 2.17\n"));
    assert!(static_for("musl libc (x86_64)\nVersion 1.2.5\n"));
    assert!(!static_for(""));
}

/// `@deadbolt/cli` in `dir` as a package manager unpacks it, needing
/// platform packages at `0.0.0-test`, none of which is installed.
fn unpacked_wrapper(dir: &Path) -> PathBuf {
    let wrapper = dir.join("node_modules/@deadbolt/cli");
    std::fs::create_dir_all(wrapper.join("bin")).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/npm");
    for file in ["postinstall.mjs", "bin/deadbolt"] {
        let from = Path::new(file).file_name().unwrap();
        std::fs::copy(root.join(from), wrapper.join(file)).unwrap();
    }
    let dependencies: serde_json::Map<String, serde_json::Value> = PLATFORM_PACKAGES
        .iter()
        .map(|name| (name.to_string(), serde_json::Value::from("0.0.0-test")))
        .collect();
    let package = serde_json::json!({
        "name": PACKAGE,
        "version": "0.0.0-test",
        "optionalDependencies": dependencies,
    });
    std::fs::write(wrapper.join("package.json"), package.to_string()).unwrap();
    wrapper
}

#[test]
fn the_postinstall_never_fails_the_install() {
    use std::os::unix::fs::PermissionsExt;
    let Some(node) = crate::config::env("PATH").ok().and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("node"))
            .find(|node| node.is_file())
    }) else {
        eprintln!("skipped: no node on PATH");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let wrapper = unpacked_wrapper(dir.path());
    // npm doesn't serve the platform package yet.
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(
        bin.join("npm"),
        "#!/bin/sh\necho 'npm error code ETARGET' >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(bin.join("npm"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let node_dir = node.parent().unwrap();
    let system = [Path::new("/usr/bin"), Path::new("/bin")];
    let dirs = [&[bin.as_path(), node_dir][..], &system].concat();
    let path = std::env::join_paths(dirs).unwrap();
    let placeholder = std::fs::read(wrapper.join("bin/deadbolt")).unwrap();
    let kept = || std::fs::read(wrapper.join("bin/deadbolt")).unwrap() == placeholder;

    let out = Command::new(&node)
        .arg(wrapper.join("postinstall.mjs"))
        .env("PATH", &path)
        .env_remove("npm_execpath")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("npm may not serve it yet"), "{stderr}");
    assert!(kept());

    // The placeholder tries again, says why it can't run, and keeps itself.
    let out = Command::new("/bin/sh")
        .arg(wrapper.join("bin/deadbolt"))
        .arg("--version")
        .env("PATH", &path)
        .env_remove("npm_execpath")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("again in a few minutes"), "{stderr}");
    assert!(kept());
}

#[test]
fn tells_of_each_version_at_most_once_a_day() {
    let day = NOTICE_EVERY;
    assert!(notice_due(None, "2", 1000));
    assert!(notice_due(Some("garbage"), "2", 1000));
    assert!(notice_due(Some("2 x"), "2", 1000));
    assert!(!notice_due(Some("2 1000\n"), "2", 1000));
    assert!(!notice_due(Some("2 1000"), "2", 1000 + day - 1));
    assert!(notice_due(Some("2 1000"), "2", 1000 + day));
    assert!(notice_due(Some("1 1000"), "2", 1001));
    // A clock that went back doesn't silence it for good.
    assert!(notice_due(Some("2 5000"), "2", 1000));
    let line = notice_line(&UpdateInfo {
        version: "0.0.0-dev-140".into(),
        method: "bun".into(),
    });
    assert_eq!(
        line,
        "deadbolt 0.0.0-dev-140 is out (installed with bun): run deadbolt update"
    );
    assert_eq!(installed_with("brew"), "installed with Homebrew");
    assert_eq!(installed_with("curl"), "installed with the install script");
}

#[test]
fn shows_the_end_of_a_failed_managers_output() {
    let text: String = (1..=20)
        .map(|n| format!("\x1b[31mline {n}\x1b[0m\r\n\n"))
        .collect();
    let tail = output_tail(&text);
    assert_eq!(tail.lines().count(), OUTPUT_LINES);
    assert!(
        tail.starts_with("line 9") && tail.ends_with("line 20"),
        "{tail}"
    );
    assert_eq!(output_tail("  \n\n"), "");
    let error = upgrade_failure("bun", "2", "boom", "bun install --global --trust x").to_string();
    assert!(error.contains("bun couldn't install deadbolt 2"));
    assert!(error.contains("It ran: bun install --global --trust x"));
    assert!(error.contains("deadbolt update"));
}

#[test]
fn homebrew_updates_are_checked_through_its_link() {
    let exe = Path::new("/opt/homebrew/Cellar/deadbolt/0.1.0/bin/deadbolt");
    assert_eq!(
        user_link(Manager::Brew, exe, None),
        Path::new("/opt/homebrew/bin/deadbolt")
    );
    let app = Path::new("/Applications/Deadbolt.app/Contents/Helpers/deadbolt");
    assert_eq!(user_link(Manager::BrewCask, app, None), app);
    let exe = Path::new("/nowhere/node_modules/@deadbolt/cli-linux-x64/bin/deadbolt");
    let wrapper = Path::new("/nowhere/node_modules/@deadbolt/cli");
    assert_eq!(
        user_link(Manager::Pnpm, exe, Some(wrapper)),
        wrapper.join("bin/deadbolt")
    );
}

#[test]
fn only_trusts_the_service_and_its_files() {
    assert_eq!(service_base(None).unwrap().as_str(), SERVICE);
    assert_eq!(service_base(Some("")).unwrap().as_str(), SERVICE);
    if cfg!(debug_assertions) {
        assert_eq!(
            service_base(Some("http://127.0.0.1:8080/r"))
                .unwrap()
                .as_str(),
            "http://127.0.0.1:8080/r/"
        );
        assert!(service_base(Some("http://[::1]:1/")).is_ok());
        for bad in [
            "https://evil.example/release/",
            "http://localhost:1/",
            "file:///tmp/",
        ] {
            assert!(service_base(Some(bad)).is_err(), "{bad}");
        }
    }
    let manifest = Url::parse("https://anoma.ly/release/deadbolt/cli/dev.json").unwrap();
    assert_eq!(
        file_url(
            &manifest,
            &format!("/release/deadbolt/files/{SHA}/d.tar.gz")
        )
        .unwrap()
        .as_str(),
        format!("https://anoma.ly/release/deadbolt/files/{SHA}/d.tar.gz")
    );
    for bad in [
        format!("https://evil.example/release/deadbolt/files/{SHA}/d.tar.gz"),
        format!("//evil.example/release/deadbolt/files/{SHA}/d.tar.gz"),
        format!("/release/hex/files/{SHA}/d.tar.gz"),
        "/release/deadbolt/files/../cli/dev.json".to_string(),
        format!("/release/deadbolt/files/{SHA}/d.tar.gz?x=1"),
    ] {
        assert!(file_url(&manifest, &bad).is_err(), "{bad}");
    }
}

#[test]
fn requirements_follow_the_apps() {
    assert!(APP_REQUIREMENT.contains("identifier \"pw.deadbolt.app\""));
    assert!(APP_REQUIREMENT.trim().ends_with(" and notarized"));
    let cli = requirement("pw.deadbolt.cli");
    assert!(cli.contains("identifier \"pw.deadbolt.cli\""), "{cli}");
    assert!(
        cli.contains("certificate leaf[subject.OU] = \"5NZ4Q7NXJ4\""),
        "{cli}"
    );
    assert!(
        !cli.contains("pw.deadbolt.app") && !cli.contains("notarized"),
        "{cli}"
    );
}

#[test]
fn reads_extension_versions_and_guards_the_directory() {
    let dir = tempfile::tempdir().unwrap();
    let ext = dir.path().join("ext");
    assert!(!extension_dir_ok(Path::new("relative/ext")));
    assert!(extension_dir_ok(&ext));
    std::fs::create_dir(&ext).unwrap();
    assert!(extension_dir_ok(&ext));
    std::fs::write(
        ext.join("manifest.json"),
        r#"{"name":"Deadbolt","version":"0.0.0.11","version_name":"0.0.0-dev-11"}"#,
    )
    .unwrap();
    assert_eq!(extension_version(&ext).as_deref(), Some("0.0.0-dev-11"));
    assert_eq!(extension_build(&ext), None);
    for (permissions, build) in [
        (r#"["storage","nativeMessaging"]"#, ExtensionBuild::Native),
        (
            r#"["storage","offscreen","alarms"]"#,
            ExtensionBuild::Standalone,
        ),
    ] {
        let manifest = format!(r#"{{"version":"0.0.0.11","permissions":{permissions}}}"#);
        std::fs::write(ext.join("manifest.json"), manifest).unwrap();
        assert_eq!(extension_build(&ext), Some(build));
    }
    // Even a Deadbolt extension isn't replaced unless update put it there.
    assert!(!extension_dir_ok(&ext));
    std::fs::write(ext.join(EXTENSION_MARKER), "manifest.json\n").unwrap();
    assert!(extension_dir_ok(&ext));
    std::fs::write(ext.join("notes.txt"), "mine").unwrap();
    assert!(!extension_dir_ok(&ext));
}

fn zip_of(entries: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    for (name, link, body) in entries {
        match link {
            Some(target) => zip.add_symlink(*name, *target, options).unwrap(),
            None if name.ends_with('/') => zip.add_directory(*name, options).unwrap(),
            None => {
                zip.start_file(*name, options).unwrap();
                zip.write_all(body).unwrap();
            }
        }
    }
    zip.finish().unwrap().into_inner()
}

#[test]
fn unpacks_extensions_without_links_or_bombs() {
    let dir = tempfile::tempdir().unwrap();
    let unpack = |name: &str, bytes: Vec<u8>| {
        let archive = dir.path().join(format!("{name}.zip"));
        std::fs::write(&archive, bytes).unwrap();
        let out = dir.path().join(name);
        unpack_extension(&archive, &out).map(|()| out)
    };
    let out = unpack(
        "good",
        zip_of(&[
            (
                "manifest.json",
                None,
                br#"{"name":"Deadbolt","version":"1.0"}"#,
            ),
            ("icons/", None, b""),
            ("icons/a.png", None, b"png"),
        ]),
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(out.join(EXTENSION_MARKER)).unwrap(),
        "icons\nmanifest.json\n"
    );
    assert!(extension_dir_ok(&out));
    assert!(unpack("link", zip_of(&[("evil", Some("/etc/passwd"), b"")])).is_err());
    assert!(unpack("marker", zip_of(&[(EXTENSION_MARKER, None, b"x")])).is_err());
    let big = vec![0u8; usize::try_from(EXTENSION_LIMIT).unwrap() + 1];
    assert!(unpack("bomb", zip_of(&[("big.bin", None, &big)])).is_err());
}

#[test]
fn checks_app_zips_for_escaping_links() {
    let dir = tempfile::tempdir().unwrap();
    let check = |bytes: Vec<u8>| {
        let archive = dir.path().join("app.zip");
        std::fs::write(&archive, bytes).unwrap();
        check_app_zip(&archive)
    };
    let framework = "Deadbolt.app/Contents/Frameworks/F.framework";
    check(zip_of(&[
        ("Deadbolt.app/Contents/Helpers/deadbolt", None, b"bin"),
        (&format!("{framework}/Versions/A/F"), None, b"lib"),
        (&format!("{framework}/Versions/Current"), Some("A"), b""),
        (&format!("{framework}/F"), Some("Versions/Current/F"), b""),
        ("__MACOSX/Deadbolt.app/._x", None, b"fork"),
    ]))
    .unwrap();
    for bad in [
        zip_of(&[("Other.app/x", None, b"")]),
        zip_of(&[("Deadbolt.app/etc", Some("/etc"), b"")]),
        zip_of(&[("Deadbolt.app/up", Some("../../x"), b"")]),
        zip_of(&[("Deadbolt.app/up", Some("../Other.app"), b"")]),
        zip_of(&[
            ("Deadbolt.app/d", Some("Contents"), b""),
            ("Deadbolt.app/d/x", None, b"through the link"),
        ]),
    ] {
        assert!(check(bad).is_err());
    }
    assert!(link_inside(
        Path::new("Deadbolt.app/a/b"),
        Path::new("../../c")
    ));
    assert!(!link_inside(
        Path::new("Deadbolt.app/a"),
        Path::new("../../c")
    ));
}

#[test]
fn signature_checks_are_decided_by_the_build_and_fail_closed() {
    assert!(signature_required(true, Some("dev")));
    assert!(signature_required(true, Some("stable")));
    assert!(!signature_required(true, None));
    assert!(!signature_required(false, Some("stable")));
    // codesign that can't run is an error, never "unsigned".
    let exe = std::env::current_exe().unwrap();
    assert!(satisfies("/nonexistent/codesign", &exe, "anchor apple", false).is_err());
    if cfg!(target_os = "macos") {
        // This test binary is signed ad hoc, not by Deadbolt's Developer ID.
        assert!(!satisfies(CODESIGN, &exe, &requirement("pw.deadbolt.cli"), false).unwrap());
    }
}

#[test]
fn root_updates_only_root_owned_installs() {
    assert!(root_may_update(501, Some(501), Some(501)));
    assert!(root_may_update(0, Some(0), Some(0)));
    assert!(!root_may_update(0, Some(501), Some(0)));
    assert!(!root_may_update(0, Some(0), Some(501)));
    assert!(!root_may_update(0, None, Some(0)));
}

#[test]
fn unreadable_sequence_state_is_not_a_fresh_install() {
    let dir = tempfile::tempdir().unwrap();
    let state = UpdateState::open(dir.path()).unwrap();
    let path = dir.path().join("release-sequences.json");
    for invalid in [
        b"not json".as_slice(),
        b"{\"cli/dev\":\"7\"}",
        b" ",
        b"{\"cli/dev\":7",
    ] {
        std::fs::write(&path, invalid).unwrap();
        for allow in [false, true] {
            let error =
                check_sequence(&state, "cli", "stable", &manifest(100, false), allow).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains(path.to_str().unwrap()), "{message}");
            assert!(message.contains("trusted backup"), "{message}");
            assert!(
                message.contains("loses all remembered replay floors"),
                "{message}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), invalid);
        }
    }
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let zero = manifest(100, false).replace("\"sequence\":7", "\"sequence\":0");
    let error = check_sequence(&state, "cli", "stable", &zero, false).unwrap_err();
    assert!(format!("{error:#}").contains("trusted backup"));
    assert!(path.is_dir());
}

#[test]
fn empty_sequence_state_initializes_like_missing_state() {
    for allow in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let state = UpdateState::open(dir.path()).unwrap();
        let path = dir.path().join("release-sequences.json");
        std::fs::write(&path, "").unwrap();
        let zero = manifest(100, false).replace("\"sequence\":7", "\"sequence\":0");
        check_sequence(&state, "cli", "stable", &zero, allow).unwrap();
        check_sequence(&state, "cli", "stable", &manifest(100, false), allow).unwrap();
        let seen: BTreeMap<String, u64> =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(seen, BTreeMap::from([("cli/stable".into(), 7)]));
        assert!(check_sequence(&state, "cli", "stable", &zero, false).is_err());
    }
}

#[test]
fn sequence_state_stays_locked_until_the_update_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let state = UpdateState::open(dir.path()).unwrap();
    assert!(UpdateState::open(dir.path()).is_err());
    check_sequence(&state, "cli", "stable", &manifest(100, false), false).unwrap();
    // Atomic replacement of the state file must not release the lock.
    assert!(UpdateState::open(dir.path()).is_err());
    // A concurrent process launch can inherit this open file description
    // until exec closes its CLOEXEC descriptor. Hold a duplicate to model
    // that window deterministically, without a fork or timing assumptions.
    let inherited = state.lock.try_clone().unwrap();
    drop(state);
    let state = UpdateState::open(dir.path()).unwrap();
    assert!(UpdateState::open(dir.path()).is_err());
    drop(inherited);
    assert!(UpdateState::open(dir.path()).is_err());
    let older = manifest(100, false).replace("\"sequence\":7", "\"sequence\":6");
    assert!(check_sequence(&state, "cli", "stable", &older, false).is_err());
}

#[test]
fn rejected_manifests_leave_sequence_state_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let state = UpdateState::open(dir.path()).unwrap();
    let good = manifest(100, false);
    check_sequence(&state, "cli", "stable", &good, false).unwrap();
    let path = dir.path().join("release-sequences.json");
    let original = std::fs::read(&path).unwrap();
    let high = good.replace("\"sequence\":7", "\"sequence\":999");
    for invalid in [
        high.replace("\"cli\"", "\"extension\""),
        high.replace("\"stable\"", "\"dev\""),
        high.replace("\"deadbolt\"", "\"other\""),
        high.replace("\"schema\":1", "\"schema\":2"),
        "not json".to_string(),
    ] {
        for allow in [false, true] {
            assert!(check_sequence(&state, "cli", "stable", &invalid, allow).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
    }
}

#[test]
fn refuses_older_manifests_unless_asked() {
    let dir = tempfile::tempdir().unwrap();
    let state = UpdateState::open(&dir.path().join("state")).unwrap();
    let check = |artifact: &str, channel: &str, sequence: u64, allow| {
        let mut text: serde_json::Value = serde_json::from_str(&manifest(100, false)).unwrap();
        text["artifact"] = artifact.into();
        text["channel"] = channel.into();
        text["sequence"] = sequence.into();
        check_sequence(&state, artifact, channel, &text.to_string(), allow)
    };
    check("cli", "dev", 0, false).unwrap();
    check("cli", "dev", 5, false).unwrap();
    check("cli", "dev", 5, false).unwrap();
    check("cli", "dev", 7, false).unwrap();
    assert!(check("cli", "dev", 6, false).is_err());
    // Each artifact and channel is its own.
    check("cli", "stable", 1, false).unwrap();
    check("extension", "dev", 1, false).unwrap();
    check("cli", "dev", 6, true).unwrap();
    assert!(check("cli", "dev", 6, false).is_err());
    let seen: BTreeMap<String, u64> =
        serde_json::from_slice(&std::fs::read(state.dir.join("release-sequences.json")).unwrap())
            .unwrap();
    assert_eq!(
        seen,
        BTreeMap::from([
            ("cli/dev".into(), 7),
            ("cli/stable".into(), 1),
            ("extension/dev".into(), 1),
        ])
    );
}

#[test]
fn a_failed_swap_puts_every_old_file_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    for (name, body) in [
        ("deadbolt", "old cli"),
        ("deadbolt-enclave", "old helper"),
        ("new-enclave", "new helper"),
    ] {
        std::fs::write(path(name), body).unwrap();
    }
    // The helper goes in, then the new deadbolt is missing.
    let files = [
        (path("new-enclave"), path("deadbolt-enclave")),
        (path("new-deadbolt"), path("deadbolt")),
    ];
    assert!(swap(&files, &path("aside")).is_err());
    assert_eq!(
        std::fs::read_to_string(path("deadbolt")).unwrap(),
        "old cli"
    );
    assert_eq!(
        std::fs::read_to_string(path("deadbolt-enclave")).unwrap(),
        "old helper"
    );
    // A file that wasn't there before isn't left behind either.
    let files = [
        (path("new-enclave"), path("fresh")),
        (path("new-deadbolt"), path("deadbolt")),
    ];
    std::fs::write(path("new-enclave"), "new helper").ok();
    assert!(swap(&files, &path("aside2")).is_err());
    assert!(!path("fresh").exists());
    assert_eq!(
        std::fs::read_to_string(path("deadbolt")).unwrap(),
        "old cli"
    );
    // And a good swap replaces both.
    std::fs::write(path("new-enclave"), "new helper").unwrap();
    std::fs::write(path("new-deadbolt"), "new cli").unwrap();
    let files = [
        (path("new-enclave"), path("deadbolt-enclave")),
        (path("new-deadbolt"), path("deadbolt")),
    ];
    swap(&files, &path("aside3")).unwrap();
    assert_eq!(
        std::fs::read_to_string(path("deadbolt")).unwrap(),
        "new cli"
    );
    assert_eq!(
        std::fs::read_to_string(path("deadbolt-enclave")).unwrap(),
        "new helper"
    );
}

#[test]
fn unpacks_only_the_cli_from_its_tarball() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("deadbolt"), "cli").unwrap();
    std::fs::write(src.join("deadbolt-enclave"), "helper").unwrap();
    std::fs::write(src.join("README"), "other").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", src.join("link")).unwrap();
    let tar = |name: &str, files: &[&str]| {
        let archive = dir.path().join(name);
        let status = Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&src)
            .args(files)
            .status()
            .unwrap();
        assert!(status.success());
        let out = dir.path().join(format!("{name}.out"));
        std::fs::create_dir(&out).unwrap();
        unpack_cli(&archive, &out).map(|_| out)
    };
    let out = tar("good.tar.gz", &["./deadbolt", "deadbolt-enclave", "README"]).unwrap();
    let mut names: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["deadbolt", "deadbolt-enclave"]);
    assert_eq!(
        std::fs::read_to_string(out.join("deadbolt")).unwrap(),
        "cli"
    );
    let error = tar("link.tar.gz", &["deadbolt", "link"]).unwrap_err();
    assert!(format!("{error:#}").contains("link"), "{error:#}");
    let long = "a".repeat(150);
    std::fs::write(src.join(&long), "long").unwrap();
    tar("long.tar.gz", &[&long, "deadbolt"]).unwrap();
    assert!(pax_path(b"19 path=deadbolt-x\n").is_some_and(|p| p == "deadbolt-x"));
}
