//! End-to-end tests: each device is a separate set of directories with its
//! own agent process, networking over localhost only.

// The agent reads the test switches these set (`DEADBOLT_NET`,
// `DEADBOLT_KDF`, `DEADBOLT_TEST_*`) only in a debug build.
#![cfg(test)]
#![cfg(debug_assertions)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_deadbolt");
const PASSPHRASE: &str = "correct horse";

struct Device {
    dir: tempfile::TempDir,
}

impl Device {
    fn new() -> Self {
        Self {
            dir: tempfile::Builder::new().prefix("db").tempdir().unwrap(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn cmd(&self, args: &[&str]) -> Command {
        self.cmd_of(BIN.as_ref(), args)
    }

    /// `cmd` with another copy of deadbolt.
    fn cmd_of(&self, program: &std::path::Path, args: &[&str]) -> Command {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .env("DEADBOLT_HOME", self.path("home"))
            .env("XDG_RUNTIME_DIR", self.path("run"))
            .env("XDG_STATE_HOME", self.path("state"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("DEADBOLT_NET", "local")
            .env("DEADBOLT_KDF", "fast")
            .env("DEADBOLT_PASSPHRASE", PASSPHRASE)
            // Never the real 1Password CLI: a test writes a fake one here.
            .env("DEADBOLT_OP", self.path("op"))
            .env_remove("DEADBOLT_TEST_VERSION")
            .env_remove("DEADBOLT_TEST_PROTOCOL")
            .env_remove("RUST_LOG")
            .stdin(Stdio::null());
        cmd
    }

    fn output(&self, cmd: &mut Command) -> Output {
        let output = cmd.output().unwrap();
        eprintln!(
            "$ {:?}\n{}{}",
            cmd.get_args().collect::<Vec<_>>(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn try_run(&self, args: &[&str]) -> Output {
        self.output(&mut self.cmd(args))
    }

    fn run(&self, args: &[&str]) -> String {
        let output = self.try_run(args);
        assert!(output.status.success(), "deadbolt {args:?} failed");
        String::from_utf8(output.stdout).unwrap()
    }

    /// Runs with `input` on stdin.
    fn try_run_stdin(&self, args: &[&str], input: &str) -> Output {
        self.with_stdin(self.cmd(args), input)
    }

    fn with_stdin(&self, mut cmd: Command, input: &str) -> Output {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        eprintln!(
            "$ {:?} < {input:?}\n{}{}",
            cmd.get_args().collect::<Vec<_>>(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// Fails and returns stderr.
    fn fail(&self, args: &[&str]) -> String {
        let output = self.try_run(args);
        assert!(!output.status.success(), "deadbolt {args:?} succeeded");
        String::from_utf8(output.stderr).unwrap()
    }

    fn agent_pid(&self) -> Option<String> {
        let out = self.try_run(&["agent", "status"]);
        let out = String::from_utf8(out.stdout).unwrap();
        out.strip_prefix("running pid ")
            .map(|rest| rest.split_whitespace().next().unwrap().to_string())
    }

    fn log(&self) -> String {
        let mut log = String::new();
        if let Ok(dirs) = std::fs::read_dir(self.path("state")) {
            for dir in dirs.flatten() {
                if let Ok(text) = std::fs::read_to_string(dir.path().join("agent.log")) {
                    log.push_str(&text);
                }
            }
        }
        log
    }

    /// Device names listed by `devices`.
    fn devices(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .run(&["devices"])
            .lines()
            .map(|line| line.split('\t').next().unwrap().to_string())
            .collect();
        names.sort();
        names
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Err(error) = self.cmd(&["agent", "stop"]).output() {
            eprintln!("test cleanup could not stop agent: {error}");
        }
        if std::thread::panicking() {
            eprintln!(
                "--- agent log {}\n{}",
                self.dir.path().display(),
                self.log()
            );
        }
    }
}

fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn wait(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() > deadline {
            if let Err(error) = child.kill() {
                eprintln!("test cleanup could not kill timed-out process: {error}");
            }
            panic!("process timed out");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `new` runs `deadbolt join`, `inviter` runs `deadbolt pair <ticket>`.
fn pair(inviter: &Device, new: &Device, device_name: &str, vault: Option<&str>) {
    let mut child = new
        .cmd(&["join", "--yes", "--device-name", device_name])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let ticket = rx.recv_timeout(Duration::from_secs(30)).expect("no ticket");
    assert!(ticket.starts_with("DBPAIR"), "{ticket}");
    let mut args = vec!["pair", &ticket];
    if let Some(vault) = vault {
        args.extend(["--vault", vault]);
    }
    let out = inviter.run(&args);
    assert!(
        out.starts_with(&format!("added {device_name} to ")),
        "{out}"
    );
    let status = wait(&mut child, Duration::from_secs(30));
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    eprintln!("join stderr:\n{err}");
    assert!(status.success(), "join failed");
    let joined = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(joined.starts_with("joined vault "), "{joined}");
}

#[test]
fn init_vaults_and_locking() {
    let a = Device::new();
    assert_eq!(
        a.run(&["init", "--device-name", "alpha"]),
        "created vault personal (default)\n"
    );
    assert_eq!(a.run(&["init", "work"]), "created vault work\n");
    assert!(!a.try_run(&["init", "work"]).status.success());
    assert!(!a.try_run(&["init", "Bad Name"]).status.success());

    let ls = a.run(&["vault", "ls"]);
    let lines: Vec<&str> = ls.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("personal\t") && lines[0].ends_with("\tdefault"));
    assert!(lines[1].starts_with("work\t") && lines[1].ends_with("1 device"));

    a.run(&["vault", "default", "work"]);
    a.run(&["vault", "rename", "work", "job"]);
    let ls = a.run(&["vault", "ls"]);
    assert!(ls.contains("job\t") && ls.lines().nth(1).unwrap().ends_with("default"));
    assert_eq!(a.devices(), ["alpha"]);
    assert!(
        a.run(&["devices", "-v", "personal"])
            .contains("this device")
    );

    let status = a.run(&["status"]);
    assert!(status.contains("state\tunlocked\n"), "{status}");
    assert!(status.contains("device\talpha "), "{status}");
    assert!(status.contains("vaults\tpersonal job*\n"), "{status}");

    // Locked: without a terminal, commands fail with exit code 3 instead of
    // unlocking inline, even with DEADBOLT_PASSPHRASE set.
    assert_eq!(a.run(&["lock"]), "locked\n");
    assert!(a.run(&["status"]).contains("state\tlocked\n"));
    let out = a.try_run(&["vault", "ls"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("locked: run `deadbolt unlock`"));
    assert_eq!(a.try_run(&["ls"]).status.code(), Some(3));
    assert!(a.run(&["status"]).contains("state\tlocked\n"));
    a.run(&["unlock"]);
    assert!(a.run(&["vault", "ls"]).contains("personal"));
    assert!(a.run(&["status"]).contains("state\tunlocked\n"));

    // Wrong passphrase.
    a.run(&["lock"]);
    let out = a.output(a.cmd(&["unlock"]).env("DEADBOLT_PASSPHRASE", "wrong"));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("wrong passphrase"));
    assert!(a.run(&["status"]).contains("state\tlocked\n"));

    // Idle timeout.
    a.run(&["unlock", "--timeout", "2s"]);
    assert!(a.run(&["status"]).contains("locks in"));
    eventually("idle lock", || {
        a.run(&["status"]).contains("state\tlocked\n")
    });

    // Config file default.
    std::fs::create_dir_all(a.path("config/deadbolt")).unwrap();
    std::fs::write(
        a.path("config/deadbolt/config.toml"),
        "unlock_timeout = \"1h\"\n",
    )
    .unwrap();
    a.run(&["unlock"]);
    assert!(a.run(&["status"]).contains("locks in 3"));
}

#[test]
fn pairing_membership_and_removal() {
    let a = Device::new();
    let b = Device::new();
    let c = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    a.run(&["init", "other"]);

    pair(&a, &b, "beta", None);
    assert_eq!(a.devices(), ["alpha", "beta"]);
    assert_eq!(b.devices(), ["alpha", "beta"]);
    let ls = b.run(&["vault", "ls"]);
    assert!(
        ls.starts_with("personal\t") && ls.trim_end().ends_with("default"),
        "{ls}"
    );
    assert_eq!(ls.lines().count(), 1, "only the paired vault is shared");

    // b admits c; a learns about c through b.
    pair(&b, &c, "gamma", None);
    assert_eq!(c.devices(), ["alpha", "beta", "gamma"]);
    eventually("a to learn about gamma", || {
        a.run(&["sync"]);
        a.devices() == ["alpha", "beta", "gamma"]
    });
    // c learned a's address from b and can sync with it directly.
    let out = c.run(&["sync"]);
    assert!(out.lines().all(|line| line.contains("\tok ")), "{out}");

    // A rename propagates.
    a.run(&["vault", "rename", "personal", "family"]);
    a.run(&["sync"]);
    eventually("rename to reach c", || {
        c.run(&["sync"]);
        c.run(&["vault", "ls"]).starts_with("family\t")
    });

    // a removes c; b hears about it; c can no longer sync with anyone.
    assert_eq!(
        a.run(&["devices", "remove", "gamma"]),
        "removed gamma from family\n"
    );
    assert_eq!(a.devices(), ["alpha", "beta"]);
    eventually("b to learn about the removal", || {
        a.run(&["sync"]);
        b.devices() == ["alpha", "beta"]
    });
    let out = c.try_run(&["sync"]);
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 2, "{stdout}");
    assert!(
        stdout
            .lines()
            .all(|line| line.contains("error: ") && line.contains("rejected")),
        "{stdout}"
    );
    // b still syncs with a.
    let out = b.run(&["sync"]);
    assert!(out.starts_with("alpha\t") && out.contains("\tok "), "{out}");

    // Re-pairing gamma into family (from which it was removed) is refused before
    // dialing, while pairing that same ticket into a's other vault succeeds.
    let mut child = c
        .cmd(&["join", "--yes", "--device-name", "gamma"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let ticket = rx.recv_timeout(Duration::from_secs(30)).expect("no ticket");
    let err = a.fail(&["pair", &ticket, "--vault", "family"]);
    assert!(
        err.contains("that device was removed from family and can't rejoin it"),
        "{err}"
    );
    let out = a.run(&["pair", &ticket, "--vault", "other"]);
    assert!(out.starts_with("added gamma to other"), "{out}");
    assert!(wait(&mut child, Duration::from_secs(30)).success());
    let joined = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(joined, "joined vault other");
    let out = c.run(&["sync", "--vault", "other"]);
    assert!(out.starts_with("alpha\t") && out.contains("\tok "), "{out}");

    // Restarting the agent keeps everything (store + meta).
    a.run(&["agent", "stop"]);
    a.run(&["unlock"]);
    assert_eq!(a.devices(), ["alpha", "beta"]);
    assert!(a.run(&["vault", "ls"]).contains("other\t"));
}

#[test]
fn second_device_cannot_join_twice_or_pair_unknown_vault() {
    let a = Device::new();
    let b = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    a.run(&["init", "work"]);
    pair(&a, &b, "beta", Some("work"));
    assert_eq!(b.run(&["vault", "ls"]).split('\t').next(), Some("work"));
    // Joining another vault on an existing device.
    pair(&a, &b, "beta", Some("personal"));
    assert_eq!(b.run(&["vault", "ls"]).lines().count(), 2);
    assert!(
        !a.try_run(&["pair", "DBPAIRAAAA", "--vault", "nope"])
            .status
            .success()
    );
}

/// `deadbolt app` beside a stand-in `deadbolt-ui` that records each start
/// and the token it was given. The app's window is a watcher with `app` set.
#[cfg(target_os = "linux")]
#[test]
fn app_comes_forward_through_the_agent_instead_of_starting_again() {
    use deadbolt_client::protocol::Change;
    use std::os::unix::fs::PermissionsExt;

    let a = Device::new();
    let bin = a.path("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let deadbolt = bin.join("deadbolt");
    if std::fs::hard_link(BIN, &deadbolt).is_err() {
        std::fs::copy(BIN, &deadbolt).unwrap();
    }
    let starts = a.path("starts");
    let ui = bin.join("deadbolt-ui");
    std::fs::write(
        &ui,
        format!(
            "#!/bin/sh\necho \"${{XDG_ACTIVATION_TOKEN:-none}}\" >> '{}'\n",
            starts.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&ui, std::fs::Permissions::from_mode(0o755)).unwrap();
    let app = |vars: &[(&str, &str)]| {
        let mut cmd = a.cmd_of(&deadbolt, &["app"]);
        cmd.env_remove("XDG_ACTIVATION_TOKEN")
            .env_remove("DESKTOP_STARTUP_ID")
            .env_remove("DEADBOLT_BIN")
            .envs(vars.iter().copied());
        assert!(a.output(&mut cmd).status.success());
    };
    let started = || {
        std::fs::read_to_string(&starts)
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect::<Vec<_>>()
    };

    // No agent: the app starts, and takes the launcher's token itself.
    app(&[("XDG_ACTIVATION_TOKEN", "one")]);
    eventually("the first start", || started() == ["one"]);
    assert_eq!(a.agent_pid(), None, "opening the app starts no agent");

    // An agent, but no app watching: it starts.
    a.run(&["status"]);
    app(&[("XDG_ACTIVATION_TOKEN", "two")]);
    eventually("the second start", || started() == ["one", "two"]);

    // The app's window watches: later launches bring it forward with their token.
    let paths = deadbolt_client::Paths::from_vars(|name| match name {
        "DEADBOLT_HOME" => Some(a.path("home").into()),
        "XDG_RUNTIME_DIR" => Some(a.path("run").into()),
        "XDG_STATE_HOME" => Some(a.path("state").into()),
        "XDG_CONFIG_HOME" => Some(a.path("config").into()),
        _ => None,
    });
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let next = |watch: &mut deadbolt_client::Watch| {
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), watch.next())
                .await
                .expect("a change in time")
                .unwrap()
        })
    };
    let mut watch = runtime
        .block_on(deadbolt_client::watch(&paths, true))
        .unwrap();
    assert_eq!(next(&mut watch), Some(Change::Watching));
    app(&[("XDG_ACTIVATION_TOKEN", "three")]);
    assert_eq!(
        next(&mut watch),
        Some(Change::Activate {
            token: Some("three".into())
        })
    );
    app(&[("DESKTOP_STARTUP_ID", "x11-startup_TIME42")]);
    assert_eq!(
        next(&mut watch),
        Some(Change::Activate {
            token: Some("x11-startup_TIME42".into())
        })
    );
    app(&[]);
    assert_eq!(next(&mut watch), Some(Change::Activate { token: None }));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(started(), ["one", "two"], "nothing started again");
}

#[test]
fn agent_is_single_instance() {
    let a = Device::new();
    a.run(&["init"]);
    let pid = a.agent_pid().expect("agent running");
    let out = a.try_run(&["agent"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already running"));
    assert_eq!(a.agent_pid(), Some(pid));
    assert_eq!(a.run(&["agent", "stop"]), "stopped\n");
    assert_eq!(a.agent_pid(), None);
    assert_eq!(a.run(&["agent", "stop"]), "not running\n");
}

#[test]
fn whoami_and_activity_name_the_caller_never_values() {
    let a = Device::new();
    a.run(&["init"]);
    let me = a.output(
        a.cmd(&["whoami", "--json"])
            .env("DEADBOLT_CALLER", "Deadbolt")
            .env("OPENCODE_SESSION_ID", "ses_test"),
    );
    assert!(me.status.success());
    let me: serde_json::Value = serde_json::from_slice(&me.stdout).unwrap();
    // Claiming to be the app changes nothing but the claim.
    assert_eq!(me["class"], "caller");
    assert_eq!(me["claimed"]["caller"], "Deadbolt");
    assert_eq!(me["claimed"]["opencode_session"], "ses_test");
    assert_ne!(me["pid"], 0);

    a.run(&[
        "new",
        "login",
        "--name",
        "GitHub",
        "password=hunter2-hunter2",
    ]);
    let out = a.output(
        a.cmd(&["get", "GitHub"])
            .env("DEADBOLT_CALLER", "an AI")
            .env_remove("OPENCODE_SESSION_ID"),
    );
    assert!(out.status.success());
    let activity = a.run(&["activity", "--since", "1h", "--json"]);
    assert!(!activity.contains("hunter2"), "{activity}");
    let entries: Vec<serde_json::Value> = activity
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let get = &entries[0];
    assert_eq!(get["command"], "item-get");
    assert_eq!(get["items"][0]["title"], "GitHub");
    assert_eq!(get["fields"], serde_json::json!(["password"]));
    assert_eq!(get["caller"]["claimed"]["caller"], "an AI");
    assert!(entries.iter().any(|e| e["command"] == "item-new"));
    assert!(
        a.run(&["activity"])
            .contains("\titem-get\tGitHub\tpassword")
    );
}

/// Runs deadbolt with `input` on stdin, reparented away from the test's
/// process tree, as from a person's own terminal: the tests may run under
/// an AI host such as OpenCode, whom the agent refuses pairing and grants.
fn detached(device: &Device, args: &[&str], input: &str) -> (bool, String, String) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static RUNS: AtomicUsize = AtomicUsize::new(0);
    let n = RUNS.fetch_add(1, Ordering::SeqCst);
    let file = |what: &str| device.path(&format!("detached-{n}.{what}"));
    let script = r#"( sleep 0.5; printf %s "$DB_INPUT" | "$0" "$@" >"$DB_OUT" 2>"$DB_ERR"; echo $? >"$DB_CODE.tmp"; mv "$DB_CODE.tmp" "$DB_CODE" ) >/dev/null 2>&1 &"#;
    let mut sh_args = vec!["-c", script, BIN];
    sh_args.extend_from_slice(args);
    let mut cmd = device.cmd_of("/bin/sh".as_ref(), &sh_args);
    cmd.env("DB_INPUT", input)
        .env("DB_OUT", file("out"))
        .env("DB_ERR", file("err"))
        .env("DB_CODE", file("code"))
        .env_remove("OPENCODE_SESSION_ID")
        .env_remove("DEADBOLT_CALLER");
    assert!(cmd.status().unwrap().success());
    eventually("the detached deadbolt", || file("code").exists());
    let read = |what| std::fs::read_to_string(file(what)).unwrap();
    let (out, err) = (read("out"), read("err"));
    eprintln!("$ (detached) {args:?}\n{out}{err}");
    (read("code").trim() == "0", out, err)
}

/// One request to the agent, as an agent client sends it.
fn agent_request(device: &Device, request: serde_json::Value) -> serde_json::Value {
    use std::os::unix::net::UnixStream;
    let paths = deadbolt_client::Paths::from_vars(|name| match name {
        "DEADBOLT_HOME" => Some(device.path("home").into()),
        "XDG_RUNTIME_DIR" => Some(device.path("run").into()),
        "XDG_STATE_HOME" => Some(device.path("state").into()),
        "XDG_CONFIG_HOME" => Some(device.path("config").into()),
        _ => None,
    });
    let mut socket = UnixStream::connect(&paths.socket).unwrap();
    let mut request = request;
    request["v"] = deadbolt_client::protocol::PROTOCOL_VERSION.into();
    socket.write_all(format!("{request}\n").as_bytes()).unwrap();
    let mut reply = String::new();
    socket.read_to_string(&mut reply).unwrap();
    serde_json::from_str(&reply).unwrap()
}

fn agent_error(reply: &serde_json::Value, code: &str) {
    assert_eq!(reply["type"], "error", "{reply}");
    assert_eq!(reply["code"], code, "{reply}");
}

#[test]
fn agents_sign_in_unattended_only_where_allowed() {
    let a = Device::new();
    a.run(&["init"]);
    new(
        &a,
        &[
            "login",
            "--name",
            "GitHub",
            "username=kit",
            "password=hunter2-hunter2",
            "url=github.com",
            &format!("otp={OTP_SECRET}"),
        ],
    );
    let proof = format!("{PASSPHRASE}\n");

    // An AI (here, by its claim) can't pair a client, passphrase or not.
    let out = a.with_stdin(
        {
            let mut cmd = a.cmd(&["--passphrase-stdin", "agents", "add-client", "browse"]);
            cmd.env("OPENCODE_SESSION_ID", "ses_test");
            cmd
        },
        &proof,
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("an AI can't"));

    // The user can, and the token is shown once.
    let (ok, out, _) = detached(
        &a,
        &[
            "--passphrase-stdin",
            "agents",
            "add-client",
            "browse",
            "--json",
        ],
        &proof,
    );
    assert!(ok);
    let paired: serde_json::Value = serde_json::from_str(&out).unwrap();
    let client = serde_json::json!({"id": paired["id"], "token": paired["token"]});
    assert_eq!(paired["token"].as_str().unwrap().len(), 64);
    assert!(
        !a.run(&["agents", "clients", "--json"])
            .contains(paired["token"].as_str().unwrap())
    );
    let logins = |origin: &str| {
        agent_request(
            &a,
            serde_json::json!({"cmd": "agent-logins", "client": client, "origin": origin}),
        )
    };
    let fill = |origin: &str, login: &serde_json::Value, want: &[&str]| {
        agent_request(
            &a,
            serde_json::json!({
                "cmd": "agent-fill", "client": client, "origin": origin,
                "login": login, "want": want,
            }),
        )
    };

    // Nothing allowed yet: the site is named, and nothing is listed.
    let listed = logins("https://github.com");
    assert_eq!(listed["reply"]["granted"], false, "{listed}");
    assert_eq!(listed["reply"]["logins"], serde_json::json!([]));

    // A wrong passphrase allows nothing.
    let (ok, _, err) = detached(
        &a,
        &[
            "--passphrase-stdin",
            "agents",
            "allow",
            "github.com",
            "--fields",
            "username,password",
        ],
        "wrong\n",
    );
    assert!(!ok && err.contains("wrong passphrase"), "{err}");
    let (ok, out, _) = detached(
        &a,
        &[
            "--passphrase-stdin",
            "agents",
            "allow",
            "www.github.com",
            "--fields",
            "username,password",
        ],
        &proof,
    );
    assert!(
        ok && out.contains("github.com\tevery login\tusername,password"),
        "{out}"
    );
    let listed = logins("https://github.com");
    assert_eq!(listed["reply"]["granted"], true, "{listed}");
    let login = &listed["reply"]["logins"][0];
    assert_eq!(login["username"], "kit");
    assert_eq!(login["has_totp"], true);
    let github = login["ref"].clone();
    let values = fill("https://github.com", &github, &["username", "password"]);
    assert_eq!(
        values["reply"]["values"]["password"], "hunter2-hunter2",
        "{values}"
    );
    assert_eq!(values["reply"]["values"]["username"], "kit");

    // The code isn't allowed: not-granted names the site and the login.
    let refused = fill("https://github.com", &github, &["totp"]);
    agent_error(&refused, "not-granted");
    assert_eq!(
        refused["grant"],
        serde_json::json!({"site": "github.com", "login": "kit"})
    );
    // Another site's frame gets nothing.
    agent_error(
        &fill("https://evil.com", &github, &["password"]),
        "not-granted",
    );

    let (ok, _, _) = detached(
        &a,
        &[
            "--passphrase-stdin",
            "agents",
            "allow",
            "github.com",
            "--login",
            "kit",
            "--fields",
            "totp",
            "--expires",
            "1h",
        ],
        &proof,
    );
    assert!(ok);
    let code = fill("https://github.com", &github, &["totp"]);
    let code = code["reply"]["values"]["totp"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()),
        "{code}"
    );
    let grants = a.run(&["agents", "grants"]);
    assert!(
        grants.contains("github.com\tkit\ttotp,passkeys\texpires in "),
        "{grants}"
    );

    // Everything is in Activity, by client, never a value.
    let activity = a.run(&["activity", "--json"]);
    assert!(
        !activity.contains("hunter2") && !activity.contains(&code),
        "{activity}"
    );
    let fills: Vec<serde_json::Value> = activity
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .filter(|e: &serde_json::Value| e["command"] == "agent-fill")
        .collect();
    assert_eq!(fills.len(), 4, "{activity}");
    assert!(fills.iter().all(|e| e["client"] == "browse"));
    assert!(fills.iter().any(|e| e["outcome"] == "refused"));
    assert!(
        fills[0]["items"][0]["title"]
            .as_str()
            .unwrap()
            .starts_with("GitHub (")
    );

    // Revoking the site grant leaves only the code.
    let id = grants
        .lines()
        .find(|l| l.contains("every login"))
        .unwrap()
        .split('\t')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(
        a.run(&["agents", "revoke", &id]).trim(),
        format!("revoked {id}")
    );
    agent_error(
        &fill("https://github.com", &github, &["password"]),
        "not-granted",
    );

    // By default a grant covers every field and passkeys; --all covers every
    // login on every site, but each login still fills only on its own site.
    let (ok, out, _) = detached(
        &a,
        &["--passphrase-stdin", "agents", "allow", "example.org"],
        &proof,
    );
    assert!(
        ok && out.contains("example.org\tevery login\tusername,password,totp,passkeys"),
        "{out}"
    );
    let (ok, out, _) = detached(
        &a,
        &["--passphrase-stdin", "agents", "allow", "--all"],
        &proof,
    );
    assert!(
        ok && out.contains("every site\tevery login\tusername,password,totp,passkeys"),
        "{out}"
    );
    let values = fill("https://github.com", &github, &["password"]);
    assert_eq!(
        values["reply"]["values"]["password"], "hunter2-hunter2",
        "{values}"
    );
    agent_error(
        &fill("https://evil.com", &github, &["password"]),
        "domain-mismatch",
    );
    let activity = a.run(&["activity", "--json"]);
    assert!(activity.contains("\"title\":\"every site\""), "{activity}");

    // Locked, nothing fills.
    a.run(&["lock"]);
    agent_error(&fill("https://github.com", &github, &["totp"]), "locked");
    a.run(&["unlock"]);

    // A removed client is forbidden.
    a.run(&["agents", "remove-client", "browse"]);
    agent_error(&fill("https://github.com", &github, &["totp"]), "forbidden");
    assert_eq!(a.run(&["agents", "grants"]), "");
}

#[test]
fn shares_an_agent_of_another_build() {
    let a = Device::new();
    let old = a.output(a.cmd(&["status"]).env("DEADBOLT_TEST_VERSION", "0.0.0-old"));
    assert!(old.status.success());
    let pid = a.agent_pid().unwrap();
    // Two builds of one protocol, in turns: neither replaces the other's agent.
    for _ in 0..2 {
        let status = a.run(&["status"]);
        assert!(status.contains("state\tnot set up"), "{status}");
        let out = a.output(
            a.cmd(&["status"])
                .env("DEADBOLT_TEST_VERSION", "0.0.0-other"),
        );
        assert!(out.status.success());
    }
    assert_eq!(a.agent_pid().unwrap(), pid);
    let out = a.run(&["agent", "status"]);
    assert!(out.ends_with("version 0.0.0-old\n"), "{out}");
}

#[test]
fn replaces_an_agent_of_an_older_protocol() {
    let a = Device::new();
    let old = a.output(a.cmd(&["status"]).env("DEADBOLT_TEST_PROTOCOL", "1"));
    assert!(old.status.success());
    let old_pid = a.agent_pid().unwrap();

    let status = a.run(&["status"]);
    assert!(status.contains("state\tnot set up"), "{status}");
    let pid = a.agent_pid().unwrap();
    assert_ne!(pid, old_pid);
    a.run(&["status"]);
    assert_eq!(a.agent_pid().unwrap(), pid);
}

#[test]
fn leaves_an_agent_of_a_newer_protocol_running() {
    let a = Device::new();
    let newer = a.output(a.cmd(&["status"]).env(
        "DEADBOLT_TEST_PROTOCOL",
        (deadbolt_client::protocol::PROTOCOL_VERSION + 1).to_string(),
    ));
    assert!(newer.status.success());
    let pid = a.agent_pid().unwrap();

    let error = a.fail(&["status"]);
    for part in [
        "a newer Deadbolt agent is running",
        BIN,
        &format!("pid {pid}"),
        "deadbolt agent stop",
    ] {
        assert!(error.contains(part), "{error}");
    }
    assert_eq!(a.agent_pid().unwrap(), pid);
    // The way out it names works.
    assert_eq!(a.run(&["agent", "stop"]), "stopped\n");
    a.run(&["status"]);
    assert_ne!(a.agent_pid().unwrap(), pid);
}

#[test]
fn passphrase_from_stdin_or_env_only() {
    let a = Device::new();
    let init = |args: &[&str], input: &str| {
        let mut cmd = a.cmd(args);
        cmd.env_remove("DEADBOLT_PASSPHRASE");
        a.with_stdin(cmd, input)
    };
    // No terminal, no env, no flag: an error, never a prompt.
    let out = init(&["init", "--device-name", "alpha"], "");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("DEADBOLT_PASSPHRASE"));

    let out = init(
        &["init", "--device-name", "alpha", "--passphrase-stdin"],
        "from stdin\n",
    );
    assert!(out.status.success());
    a.run(&["lock"]);
    // The env passphrase is not this one.
    assert!(!a.try_run(&["unlock"]).status.success());
    let out = init(&["unlock", "--passphrase-stdin"], "wrong\n");
    assert!(String::from_utf8_lossy(&out.stderr).contains("wrong passphrase"));
    let out = init(&["unlock", "--passphrase-stdin"], "from stdin\n");
    assert!(out.status.success(), "unlock failed");
    assert!(a.run(&["status"]).contains("state\tunlocked\n"));
}

/// The short id `new` prints.
fn new(device: &Device, args: &[&str]) -> String {
    let out = device.run(&[&["new"], args].concat());
    let short = out.trim().to_string();
    assert!(
        short.len() >= 4 && short.bytes().all(|b| b.is_ascii_hexdigit()),
        "{out}"
    );
    short
}

#[test]
fn items() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);

    let github = new(
        &a,
        &[
            "login",
            "username=dax",
            "url=github.com",
            "password=hunter2",
        ],
    );
    let work = new(
        &a,
        &[
            "login",
            "username=dax@work.example",
            "url=https://www.google.com/",
        ],
    );
    new(
        &a,
        &["login", "username=dax.personal@gmail.com", "url=google.com"],
    );

    // Defaults and -f.
    assert_eq!(a.run(&["get", "github"]), "hunter2\n");
    assert_eq!(
        a.run(&["get", "GitHub", "-f", "url"]),
        "https://github.com\n"
    );
    assert_eq!(a.run(&["get", &github, "-f", "username"]), "dax\n");

    // Two Google logins: ambiguous until a username word tells them apart.
    let err = a.fail(&["get", "google"]);
    assert!(err.contains("matches 2 items"), "{err}");
    assert!(err.contains("\tgoogle.com\tdax@work.example"), "{err}");
    assert!(
        err.contains("\tgoogle.com\tdax.personal@gmail.com"),
        "{err}"
    );
    let generated = a.run(&["get", "google", "work"]);
    let generated = generated.trim_end_matches('\n');
    assert_eq!(generated.len(), 24, "{generated}");
    assert!(generated.bytes().all(|b| b.is_ascii_graphic()));
    assert!(generated.bytes().any(|b| !b.is_ascii_alphanumeric()));
    assert_eq!(a.run(&["get", "GOOGLE", "Personal"]).len(), 25);
    // Id prefixes match too.
    assert_eq!(
        a.run(&["get", &work, "-f", "username"]),
        "dax@work.example\n"
    );
    assert!(
        a.fail(&["get", "nothing-like-this"])
            .contains("no item matches")
    );

    // Generated password options.
    new(
        &a,
        &[
            "login",
            "url=short.example",
            "--length",
            "12",
            "--no-symbols",
        ],
    );
    let short = a.run(&["get", "short.example"]);
    assert_eq!(short.trim_end().len(), 12);
    assert!(short.trim_end().bytes().all(|b| b.is_ascii_alphanumeric()));

    // field=- reads stdin (raw, one trailing newline stripped).
    let out = a.try_run_stdin(
        &["new", "login", "url=stdin.example", "password=-"],
        "from stdin\n",
    );
    assert!(out.status.success());
    assert_eq!(a.run(&["get", "stdin"]), "from stdin\n");
    let out = a.try_run_stdin(&["new", "login", "password=-", "notes=-"], "x");
    assert!(String::from_utf8_lossy(&out.stderr).contains("only one field"));

    // Cards: number and expiry normalized; label from brand field or "card".
    new(
        &a,
        &[
            "card",
            "number=4242 4242-4242 4242",
            "expiry=04/27",
            "cvv=123",
            "cardholder=Dax Raad",
        ],
    );
    new(
        &a,
        &[
            "card",
            "number=5555555555554444",
            "brand=Mastercard",
            "--name",
            "Travel",
        ],
    );
    new(&a, &["card", "number=6011000990139424", "brand=Discover"]);
    assert_eq!(a.run(&["get", "4242"]), "4242424242424242\n");
    assert_eq!(a.run(&["get", "4242", "-f", "expiry"]), "2027-04\n");
    let cards = a.run(&["ls", "--type", "card"]);
    let labels: Vec<&str> = cards
        .lines()
        .map(|l| l.split('\t').nth(1).unwrap())
        .collect();
    assert_eq!(
        labels,
        ["card •••• 4242", "Discover •••• 9424", "Travel"],
        "{cards}"
    );
    assert!(cards.contains("\tcard •••• 4242\t04/27\n"), "{cards}");
    assert_eq!(a.run(&["get", "mastercard", "-f", "brand"]), "Mastercard\n");

    // Multi-word search: "dax" matches logins and the cardholder, "4242" the last four.
    assert_eq!(
        a.run(&["get", "dax", "4242", "-f", "cardholder"]),
        "Dax Raad\n"
    );
    assert!(a.fail(&["get", "dax"]).contains("matches 4 items"));
    // Secret values are never searched.
    assert!(a.fail(&["get", "hunter2"]).contains("no item matches"));

    // show masks secrets unless --reveal.
    let show = a.run(&["show", "4242"]);
    assert!(
        show.starts_with("type        card\nlabel       card •••• 4242\nid  "),
        "{show}"
    );
    assert!(show.contains("\nnumber      •••• 4242\n"), "{show}");
    assert!(show.contains("\ncvv         ••••••••\n"), "{show}");
    assert!(show.contains("\nexpiry      2027-04\n"), "{show}");
    assert!(!show.contains("4242424242424242"));
    let show = a.run(&["show", "4242", "--reveal"]);
    assert!(show.contains("\nnumber      4242424242424242\n"), "{show}");
    assert!(show.contains("\ncvv         123\n"), "{show}");

    // Schema rejection.
    for (args, error) in [
        (&["new", "wifi", "password=x"][..], "unknown item type"),
        (&["new", "note"], "needs a name or a field"),
        (&["new", "card", "cvv=123"], "missing required field number"),
        (
            &["new", "card", "number=12ab34567890"],
            "must be 12-19 digits",
        ),
        (
            &["new", "card", "number=4242424242424242", "cvv=12"],
            "must be 3-4 digits",
        ),
        (
            &["new", "card", "number=4242424242424242", "expiry=13/27"],
            "not a month",
        ),
        (
            &["new", "login", "password:text=x"],
            "must be of type secret",
        ),
        (&["new", "login", "x:blob=1"], "unknown field type"),
        (&["new", "login", "Bad=1"], "invalid field name"),
        (&["new", "login", "nope"], "expected field[:type]=value"),
    ] {
        let err = a.fail(args);
        assert!(err.contains(error), "{args:?}: {err}");
    }

    // set / unset / rm.
    assert_eq!(
        a.run(&["set", "github", "password=new2", "--name", "Code"])
            .trim(),
        github
    );
    assert_eq!(a.run(&["get", "code"]), "new2\n");
    assert!(a.run(&["ls", "code"]).contains("\tCode\tdax\n"));
    a.run(&["set", "code", "--name", ""]);
    assert!(a.run(&["ls", "github"]).contains("\tgithub.com\tdax\n"));
    a.run(&["set", "github", "pin:secret=1234", "url=gitlab.com"]);
    assert_eq!(a.run(&["get", "gitlab", "-f", "pin"]), "1234\n");
    assert!(
        a.run(&["show", "gitlab"])
            .contains("\npin       ••••••••\n")
    );
    assert!(a.fail(&["set", "password=x"]).contains("needs a query"));
    assert!(a.fail(&["set", "gitlab"]).contains("nothing to change"));
    a.run(&["unset", "gitlab", "-f", "username"]);
    assert!(
        a.fail(&["get", "gitlab", "-f", "username"])
            .contains("no field username")
    );
    assert!(
        a.fail(&["unset", "4242", "-f", "number"])
            .contains("required")
    );
    // A login needs no password.
    a.run(&["unset", "gitlab", "-f", "password"]);
    assert_eq!(a.run(&["rm", "gitlab"]).trim(), github);
    assert!(a.fail(&["get", "gitlab"]).contains("no item matches"));
    assert_eq!(a.run(&["ls", "--type", "login"]).lines().count(), 4);

    // Everything survives an agent restart.
    a.run(&["agent", "stop"]);
    a.run(&["unlock"]);
    assert_eq!(a.run(&["ls"]).lines().count(), 7);
}

#[test]
fn one_time_codes() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    new(
        &a,
        &[
            "login",
            "url=github.com",
            "password=pw",
            "otp=otpauth://totp/GitHub:dax?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        ],
    );
    new(&a, &["login", "url=gitlab.com", "password=pw"]);

    let code = a.run(&["code", "github"]);
    let code = code.trim_end_matches('\n');
    assert!(
        code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()),
        "{code}"
    );
    // `show` prints the current code with its time left; the secret takes
    // `--reveal` or `get -f otp`.
    let show = a.run(&["show", "github"]);
    let line = show.lines().find(|l| l.starts_with("otp ")).unwrap();
    let (digits, left) = line["otp".len()..].trim().split_once(' ').unwrap();
    assert!(
        digits.len() == 6 && digits.bytes().all(|b| b.is_ascii_digit()),
        "{line}"
    );
    assert!(left.starts_with('(') && left.ends_with("s left)"), "{line}");
    assert!(!show.contains("JBSWY3DPEHPK3PXP"));
    let secret = "otpauth://totp/GitHub:dax?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
    assert!(a.run(&["show", "--reveal", "github"]).contains(secret));
    assert_eq!(a.run(&["get", "-f", "otp", "github"]).trim_end(), secret);
    a.run(&["set", "github", "backup:otp=KRSXG5CTMVRXEZLU"]);
    assert_eq!(
        a.run(&["get", "-f", "backup", "github"]).trim_end(),
        "KRSXG5CTMVRXEZLU"
    );
    assert_eq!(a.run(&["get", "github"]).trim_end(), "pw");
    assert!(
        a.fail(&["code", "gitlab"])
            .contains("gitlab.com has no one-time password")
    );
    let err = a.fail(&["set", "gitlab", "otp=123456"]);
    assert!(
        err.contains("invalid value for otp: the secret is not base32"),
        "{err}"
    );
    a.run(&["set", "gitlab", "otp=jbsw y3dp ehpk 3pxp"]);
    assert_eq!(a.run(&["code", "gitlab"]).trim_end().len(), 6);
}

/// Asking for codes, as a client showing one does every period, doesn't
/// hold the vault open: the idle lock still comes.
#[test]
fn codes_do_not_hold_off_the_idle_lock() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    new(
        &a,
        &[
            "login",
            "url=github.com",
            "password=pw",
            "otp=JBSWY3DPEHPK3PXP",
        ],
    );
    a.run(&["unlock", "--timeout", "2s"]);
    let start = Instant::now();
    while !a.run(&["status"]).contains("state\tlocked\n") {
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "still unlocked while codes are asked for"
        );
        a.try_run(&["code", "github"]);
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[test]
fn concurrent_item_edits_on_two_devices() {
    let a = Device::new();
    let b = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    pair(&a, &b, "beta", None);
    let id = new(&a, &["login", "url=example.com", "password=start"]);
    eventually("b to receive the item", || {
        b.run(&["sync"]);
        b.try_run(&["get", &id]).status.success()
    });

    // Different fields: both survive.
    a.run(&["set", "example", "username=from-a"]);
    b.run(&["set", "example", "notes=from-b"]);
    for device in [&a, &b] {
        eventually("both edits to arrive", || {
            device.run(&["sync"]);
            let show = device.run(&["show", "example"]);
            show.contains("from-a") && show.contains("from-b")
        });
    }

    // Same field: both devices settle on the same one.
    a.run(&["set", "example", "password=from-a"]);
    b.run(&["set", "example", "password=from-b"]);
    eventually("both devices to agree", || {
        a.run(&["sync"]);
        b.run(&["sync"]);
        let (pa, pb) = (a.run(&["get", "example"]), b.run(&["get", "example"]));
        pa == pb && (pa == "from-a\n" || pa == "from-b\n")
    });
}

/// A Bitwarden unencrypted JSON export (web vault: Tools > Export vault).
const BITWARDEN_EXPORT: &str = r#"{
  "encrypted": false,
  "folders": [{ "id": "4f5e2a3b-0c1d-4e2f-9a8b-7c6d5e4f3a2b", "name": "Work" }],
  "items": [
    {
      "passwordHistory": [{ "lastUsedDate": "2024-01-02T03:04:05.000Z", "password": "old-pw-111" }],
      "revisionDate": "2024-05-06T07:08:09.123Z",
      "creationDate": "2023-01-01T00:00:00.000Z",
      "deletedDate": null,
      "id": "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "organizationId": null,
      "folderId": "4f5e2a3b-0c1d-4e2f-9a8b-7c6d5e4f3a2b",
      "type": 1,
      "reprompt": 0,
      "name": "GitHub",
      "notes": "notes-secret-222",
      "favorite": true,
      "fields": [{ "name": "Recovery Code", "value": "recovery-secret-333", "type": 1, "linkedId": null }],
      "login": {
        "fido2Credentials": [],
        "uris": [{ "match": null, "uri": "https://github.com/login" }, { "match": null, "uri": "gh.io" }],
        "username": "dax",
        "password": "github-secret-444",
        "totp": "JBSWY3DPEHPK3PXP"
      },
      "collectionIds": null
    },
    {
      "id": "3b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
      "organizationId": null,
      "folderId": null,
      "type": 3,
      "reprompt": 0,
      "name": null,
      "notes": null,
      "favorite": false,
      "card": {
        "cardholderName": "Dax Raad",
        "brand": "Visa",
        "number": "4242 4242 4242 4242",
        "expMonth": "4",
        "expYear": "2027",
        "code": "555"
      },
      "collectionIds": null
    },
    { "id": "6b1c", "type": 2, "name": "Wifi", "notes": "wifi-secret-666", "favorite": false, "secureNote": { "type": 0 } },
    { "id": "7b1c", "type": 1, "name": "Nopass", "favorite": false, "login": { "username": "x", "password": null } }
  ]
}"#;

#[test]
fn import() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    let file = a.path("export.json");
    std::fs::write(&file, BITWARDEN_EXPORT).unwrap();
    let secrets = [
        "old-pw-111",
        "notes-secret-222",
        "recovery-secret-333",
        "github-secret-444",
        "JBSWY3DPEHPK3PXP",
        "4242",
        "555",
        "wifi-secret-666",
    ];
    let no_secrets = |output: &Output| {
        for text in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(text);
            for secret in secrets {
                assert!(!text.contains(secret), "{secret} leaked: {text}");
            }
        }
    };

    let summary = "4 from Bitwarden (logins 2, cards 1, secure notes 1)\n\
        dropped: 1 favorite, 1 folder, 1 item's password history\n";
    let output = a.try_run(&["import", "--dry-run", file.to_str().unwrap()]);
    assert!(output.status.success());
    no_secrets(&output);
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("dry run: would import {summary}")
    );
    assert_eq!(a.run(&["ls"]), "");

    let output = a.try_run(&["import", file.to_str().unwrap()]);
    assert!(output.status.success());
    no_secrets(&output);
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("imported {summary}")
    );

    let ls = a.run(&["ls"]);
    let lines: Vec<&str> = ls.lines().map(|l| l.split_once('\t').unwrap().1).collect();
    assert_eq!(
        lines,
        ["GitHub\tdax", "Nopass\tx", "Visa •••• 4242\t04/27", "Wifi"]
    );
    assert_eq!(a.run(&["get", "github"]), "github-secret-444\n");
    assert_eq!(a.run(&["get", "wifi"]), "wifi-secret-666\n");
    assert_eq!(
        a.run(&["get", "github", "-f", "recovery-code"]),
        "recovery-secret-333\n"
    );
    assert_eq!(a.run(&["get", "github", "-f", "url-2"]), "https://gh.io\n");
    assert_eq!(a.run(&["get", "visa"]), "4242424242424242\n");
    assert_eq!(a.run(&["get", "visa", "-f", "cvv"]), "555\n");
    let show = a.try_run(&["show", "github"]);
    assert!(show.status.success());
    // Secret fields are masked (notes are not secret; ids are hex, so
    // digit-only values could appear by chance).
    let show = String::from_utf8(show.stdout).unwrap();
    assert!(
        !secrets
            .iter()
            .filter(|s| s.len() > 4 && !s.starts_with("notes"))
            .any(|s| show.contains(s)),
        "{show}"
    );

    // Importing again changes nothing.
    let output = a.try_run(&["import", file.to_str().unwrap()]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.starts_with("imported 0 from Bitwarden (logins 0, cards 0)\nskipped 4 duplicates\n"),
        "{stdout}"
    );
    assert_eq!(a.run(&["ls"]).lines().count(), 4);

    // From stdin, into another vault.
    a.run(&["init", "work"]);
    let output = a.try_run_stdin(&["-v", "work", "import", "-"], BITWARDEN_EXPORT);
    assert!(output.status.success());
    no_secrets(&output);
    assert_eq!(a.run(&["-v", "work", "ls"]).lines().count(), 4);
    assert_eq!(a.run(&["ls"]).lines().count(), 4);

    let encrypted = a.path("encrypted.json");
    std::fs::write(
        &encrypted,
        r#"{"encrypted": true, "passwordProtected": true, "salt": "x", "data": "2.y"}"#,
    )
    .unwrap();
    let err = a.fail(&["import", encrypted.to_str().unwrap()]);
    assert!(
        err.contains("this is an encrypted export; export as unencrypted .json"),
        "{err}"
    );
}

/// A fake 1Password CLI: logs its arguments and stdin, then answers from
/// the files beside it, or fails as `op.mode` says. `item get` gives every
/// item, asked for or not.
const FAKE_OP: &str = r#"#!/bin/sh
dir=$(dirname "$0")
echo "$*" >> "$dir/op.log"
case "$(cat "$dir/op.mode" 2>/dev/null)" in
  signed-out)
    echo '[ERROR] 2024/03/09 16:00:00 You are not currently signed in. Please run `op signin --help` for instructions' >&2
    exit 1 ;;
  dismissed)
    echo '[ERROR] 2024/03/09 16:00:00 authorization prompt dismissed, please try again' >&2
    exit 1 ;;
esac
case "$1 $2" in
  "account list") cat "$dir/op-accounts.json" ;;
  "vault list") echo '[{"id": "v1v1v1v1v1v1v1v1v1v1v1v1v1", "name": "Private"}, {"id": "v2v2v2v2v2v2v2v2v2v2v2v2v2", "name": "Shared"}]' ;;
  "item list") cat "$dir/op-list.json" ;;
  "item get") cat > "$dir/op.stdin"; cat "$dir/op-items.json" ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac
"#;

const OP_ITEMS: &str = include_str!("fixtures/op-items.json");

#[test]
fn sync_from_1password() {
    use std::os::unix::fs::PermissionsExt;

    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    let sync = ["sync", "1password"];
    let secrets = [
        "op-github-pw",
        "op-recovery-111",
        "op-note-secret",
        "op-api-key",
        "op-ssh-pass",
        "JBSWY3DPEHPK3PXP",
        "4242",
    ];
    let no_secrets = |output: &Output| {
        for text in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(text);
            for secret in secrets {
                assert!(!text.contains(secret), "{secret} leaked: {text}");
            }
        }
    };

    let err = a.fail(&sync);
    assert!(
        err.contains("the 1Password CLI (op) is not installed"),
        "{err}"
    );

    let op = a.path("op");
    std::fs::write(&op, FAKE_OP).unwrap();
    std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
    let account = r#"{"url": "https://my.1password.com/", "email": "dax@example.com", "user_uuid": "USERUSERUSERUSERUSERUSERUS", "account_uuid": "AAAABBBBCCCCDDDDEEEEFFFFGG", "shorthand": "my"}"#;
    std::fs::write(a.path("op-accounts.json"), format!("[{account}]")).unwrap();
    std::fs::write(a.path("op-items.json"), OP_ITEMS).unwrap();
    // `op item list` gives no fields, sections or files.
    let listed: Vec<serde_json::Value> = serde_json::Deserializer::from_str(OP_ITEMS)
        .into_iter::<serde_json::Value>()
        .map(|item| {
            let mut item = item.unwrap();
            for key in ["fields", "sections", "files"] {
                item.as_object_mut().unwrap().remove(key);
            }
            item
        })
        .collect();
    std::fs::write(
        a.path("op-list.json"),
        serde_json::to_string(&listed).unwrap(),
    )
    .unwrap();
    let calls = || {
        let calls = std::fs::read_to_string(a.path("op.log")).unwrap_or_default();
        std::fs::remove_file(a.path("op.log")).ok();
        calls
    };
    // The ids of the items the last sync asked `op item get` for.
    let asked = || -> Vec<String> {
        let Ok(stdin) = std::fs::read_to_string(a.path("op.stdin")) else {
            return Vec::new();
        };
        std::fs::remove_file(a.path("op.stdin")).unwrap();
        assert!(!secrets.iter().any(|s| stdin.contains(s)), "{stdin}");
        let listed: Vec<serde_json::Value> = serde_json::from_str(&stdin).unwrap();
        let mut ids: Vec<String> = listed
            .iter()
            .map(|i| i["id"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        ids
    };

    // Not signed in, or access not approved: says what to do.
    std::fs::write(a.path("op.mode"), "signed-out").unwrap();
    let err = a.fail(&sync);
    assert!(err.contains("1Password: not signed in"), "{err}");
    std::fs::write(a.path("op.mode"), "dismissed").unwrap();
    let err = a.fail(&sync);
    assert!(err.contains("approve it"), "{err}");
    std::fs::remove_file(a.path("op.mode")).unwrap();
    calls();

    // Locked: exits 3 before 1Password is asked anything.
    a.run(&["lock"]);
    let output = a.try_run(&sync);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(calls(), "");
    a.run(&["unlock"]);

    let output = a.try_run(&["sync", "1password", "--dry-run"]);
    assert!(output.status.success());
    no_secrets(&output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.starts_with("dry run: 11 would add (0 unchanged, 3 skipped)\n  add     A note\n"),
        "{stdout}"
    );
    assert!(stdout.contains("  skip    Scan (document)\n"), "{stdout}");
    assert_eq!(a.run(&["ls"]), "");
    // Values never go to `op` on argv or stdin.
    let log = calls();
    assert_eq!(
        log,
        "account list --format json\n\
         item list --account AAAABBBBCCCCDDDDEEEEFFFFGG --format json\n\
         item get - --account AAAABBBBCCCCDDDDEEEEFFFFGG --format json\n"
    );
    // Every item but the document and the one of a type unknown here.
    let all = asked();
    assert_eq!(all.len(), listed.len() - 2, "{all:?}");

    let output = a.try_run(&sync);
    assert!(output.status.success());
    no_secrets(&output);
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("11 added (0 unchanged, 3 skipped)\n")
    );
    assert_eq!(a.run(&["ls"]).lines().count(), 11);
    assert_eq!(a.run(&["get", "github"]), "op-github-pw\n");

    asked();

    // Nothing changed: --quiet prints nothing, and only the SSH key that
    // could not be mirrored is asked for again.
    assert_eq!(a.run(&["sync", "1password", "--quiet"]), "");
    assert_eq!(asked(), ["item9"]);

    // Changed here: asked for again, and 1Password's copy wins.
    a.run(&["set", "github", "password=mine"]);
    let out = a.run(&["sync", "1password"]);
    assert!(
        out.starts_with("1 updated (10 unchanged, 3 skipped)\n"),
        "{out}"
    );
    assert_eq!(asked(), ["item1item1item1item1item1a", "item9"]);
    assert_eq!(a.run(&["get", "github"]), "op-github-pw\n");

    // Only some vaults.
    calls();
    let out = a.run(&[
        "sync",
        "op",
        "--op-vault",
        "private",
        "--account",
        "dax@example.com",
    ]);
    assert!(out.starts_with("Up to date (3 unchanged)\n"), "{out}");
    assert!(calls().contains("vault list --account AAAABBBBCCCCDDDDEEEEFFFFGG --format json\n"));
    let err = a.fail(&["sync", "op", "--op-vault", "Nope"]);
    assert!(err.contains("no 1Password vault named \"Nope\""), "{err}");

    // Two accounts: the one mirrored here, else which one must be said.
    let other = r#"{"url": "team.1password.com", "email": "dax@team.example", "user_uuid": "YYYY", "account_uuid": "ZZZZ"}"#;
    std::fs::write(a.path("op-accounts.json"), format!("[{account}, {other}]")).unwrap();
    a.run(&sync);
    a.run(&["init", "work"]);
    let err = a.fail(&["sync", "op", "--vault", "work"]);
    assert!(
        err.contains(
            "2 1Password accounts: choose one with --account (my, dax@team.example on team.1password.com)"
        ),
        "{err}"
    );
    let err = a.fail(&["sync", "op", "--account", "nobody"]);
    assert!(
        err.contains("no 1Password account matches \"nobody\""),
        "{err}"
    );
}

#[test]
fn watch_prints_changes_as_json_lines() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    let vault = a.run(&["vault", "ls"]);
    let short = vault.split('\t').nth(1).unwrap().to_string();
    let mut child = a.cmd(&["watch"]).stdout(Stdio::piped()).spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    // Each command here is also an Activity entry; those come in between.
    let next = || -> serde_json::Value {
        loop {
            let line = rx.recv_timeout(Duration::from_secs(30)).expect("a change");
            let change: serde_json::Value =
                serde_json::from_str(&line).unwrap_or_else(|e| panic!("{line:?} is not JSON: {e}"));
            if change != serde_json::json!({"change": "activity"}) {
                return change;
            }
        }
    };
    assert_eq!(next(), serde_json::json!({"change": "watching"}));

    new(
        &a,
        &["login", "username=dax", "url=github.com", "password=pw"],
    );
    let items = next();
    assert_eq!(items["change"], "items");
    assert!(
        items["vault"].as_str().unwrap().starts_with(&short),
        "{items}"
    );
    a.run(&["lock"]);
    assert_eq!(next(), serde_json::json!({"change": "locked"}));
    a.run(&["unlock"]);
    assert_eq!(next(), serde_json::json!({"change": "unlocked"}));
    a.run(&["agent", "stop"]);
    assert_eq!(next(), serde_json::json!({"change": "stopping"}));
    assert!(wait(&mut child, Duration::from_secs(10)).success());
    assert!(
        rx.recv_timeout(Duration::from_secs(1)).is_err(),
        "the stream ended"
    );
}

const EXTENSION: &str = "chrome-extension://jhocodkhpifjndffenppfmdkmiolngal/";

/// `deadbolt browser-host`, run as a browser runs it: the extension's origin
/// as the only argument, length-prefixed JSON both ways.
struct Host {
    child: Child,
    stdin: std::process::ChildStdin,
    messages: mpsc::Receiver<serde_json::Value>,
    /// `changed` messages that arrived while waiting for a reply.
    pushed: Vec<serde_json::Value>,
    next_id: u64,
}

impl Host {
    fn start(device: &Device) -> Self {
        let mut child = device
            .cmd(&[EXTENSION])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (tx, messages) = mpsc::channel();
        std::thread::spawn(move || {
            loop {
                let mut prefix = [0u8; 4];
                if stdout.read_exact(&mut prefix).is_err() {
                    break;
                }
                let len = u32::from_ne_bytes(prefix) as usize;
                assert!(len <= 1024 * 1024, "a message over the browser's limit");
                let mut body = vec![0u8; len];
                stdout.read_exact(&mut body).unwrap();
                let text = String::from_utf8(body).unwrap();
                eprintln!("host -> {text}");
                if tx.send(serde_json::from_str(&text).unwrap()).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            messages,
            pushed: Vec::new(),
            next_id: 0,
        }
    }

    fn send_raw(&mut self, body: &[u8]) {
        let len = u32::try_from(body.len()).unwrap();
        self.stdin.write_all(&len.to_ne_bytes()).unwrap();
        self.stdin.write_all(body).unwrap();
        self.stdin.flush().unwrap();
    }

    fn recv(&self, timeout: Duration) -> Option<serde_json::Value> {
        self.messages.recv_timeout(timeout).ok()
    }

    /// The next reply, keeping pushes aside.
    fn reply(&mut self) -> serde_json::Value {
        loop {
            let message = self.recv(Duration::from_secs(30)).expect("a reply");
            if message["type"] == "changed" {
                self.pushed.push(message);
            } else {
                return message;
            }
        }
    }

    /// Sends `request` with a fresh id and returns the reply to it.
    fn ask(&mut self, mut request: serde_json::Value) -> serde_json::Value {
        self.next_id += 1;
        let id = format!("r{}", self.next_id);
        request["id"] = id.clone().into();
        self.send_raw(request.to_string().as_bytes());
        let reply = self.reply();
        assert_eq!(reply["id"], id, "{reply}");
        reply
    }

    /// The next `changed` push, from those set aside first.
    fn pushed(&mut self, timeout: Duration) -> Option<serde_json::Value> {
        if !self.pushed.is_empty() {
            return Some(self.pushed.remove(0));
        }
        let message = self.recv(timeout)?;
        assert_eq!(message["type"], "changed", "{message}");
        Some(message)
    }

    /// Hangs up as the browser does, and expects the host to exit cleanly.
    fn close(self) {
        let Self {
            mut child, stdin, ..
        } = self;
        drop(stdin);
        assert!(wait(&mut child, Duration::from_secs(10)).success());
    }
}

fn list(host: &mut Host, origin: &str) -> serde_json::Value {
    let reply = host.ask(serde_json::json!({"type": "list", "origin": origin}));
    assert_eq!(reply["type"], "list", "{reply}");
    reply
}

fn refs(reply: &serde_json::Value) -> Vec<String> {
    reply["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["ref"].as_str().unwrap().to_string())
        .collect()
}

fn assert_error(reply: &serde_json::Value, code: &str) {
    assert_eq!(reply["type"], "error", "{reply}");
    assert_eq!(reply["code"], code, "{reply}");
}

const OTP_SECRET: &str = "JBSWY3DPEHPK3PXP";

#[test]
fn browser_host_lists_and_fills_only_for_the_page_site() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    new(
        &a,
        &[
            "login",
            "username=dax",
            "url=github.com",
            "password=hunter2",
            &format!("otp={OTP_SECRET}"),
        ],
    );
    new(
        &a,
        &[
            "login",
            "username=kit",
            "url=https://gitlab.com",
            "password=gl-pw",
        ],
    );
    new(
        &a,
        &[
            "login",
            "username=evil",
            "url=https://github.com.evil.com",
            "password=evil-pw",
        ],
    );
    let mut host = Host::start(&a);

    let hello = host.ask(serde_json::json!({"type": "hello"}));
    assert_eq!(hello["type"], "hello", "{hello}");
    assert_eq!(hello["status"], "ready");
    assert_eq!(hello["protocol"], 3);
    assert_eq!(
        hello["capabilities"],
        serde_json::json!([
            "list", "fill", "check", "save", "generate", "passkeys", "learn", "forms"
        ])
    );

    // Only the github.com login, on github.com and its subdomains, and no
    // values in the list.
    let github = list(&mut host, "https://github.com");
    assert_eq!(github["site"], "github.com");
    let accounts = github["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1, "{github}");
    assert_eq!(accounts[0]["username"], "dax");
    assert_eq!(accounts[0]["title"], "github.com");
    assert_eq!(accounts[0]["vault"], "personal");
    assert_eq!(accounts[0]["hasPassword"], true);
    assert_eq!(accounts[0]["hasTotp"], true);
    assert_eq!(
        accounts[0]["urls"],
        serde_json::json!(["https://github.com"])
    );
    let text = github.to_string();
    for secret in ["hunter2", OTP_SECRET, "gl-pw", "evil-pw"] {
        assert!(!text.contains(secret), "the list holds {secret}: {text}");
    }
    let github_ref = accounts[0]["ref"].as_str().unwrap().to_string();
    assert_eq!(
        refs(&list(&mut host, "https://gist.github.com:8443")),
        std::slice::from_ref(&github_ref)
    );
    let gitlab_ref = refs(&list(&mut host, "https://gitlab.com")).pop().unwrap();
    assert!(refs(&list(&mut host, "https://evilgithub.com")).is_empty());
    assert_eq!(
        refs(&list(&mut host, "https://github.com.evil.com")).len(),
        1
    );

    let fill = host.ask(serde_json::json!({
        "type": "fill", "origin": "https://github.com", "ref": github_ref,
        "want": ["username", "password", "totp"],
    }));
    assert_eq!(fill["type"], "fill", "{fill}");
    assert_eq!(fill["username"], "dax");
    assert_eq!(fill["password"], "hunter2");
    let totp = fill["totp"].as_str().unwrap();
    assert!(
        totp.len() == 6 && totp.bytes().all(|b| b.is_ascii_digit()),
        "{fill}"
    );
    let only = host.ask(serde_json::json!({
        "type": "fill", "origin": "https://github.com", "ref": github_ref, "want": ["password"],
    }));
    assert_eq!(
        only,
        serde_json::json!({"id": only["id"], "type": "fill", "password": "hunter2"})
    );

    // Another site's login, from this page or a lookalike, is refused.
    for (origin, login) in [
        ("https://github.com", &gitlab_ref),
        ("https://gitlab.com", &github_ref),
        ("https://github.com.evil.com", &github_ref),
        ("https://evilgithub.com", &github_ref),
    ] {
        let reply = host.ask(serde_json::json!({
            "type": "fill", "origin": origin, "ref": login, "want": ["password"],
        }));
        assert_error(&reply, "domain_mismatch");
        assert!(!reply.to_string().contains("pw"), "{reply}");
    }
    let (vault, _) = github_ref.split_once(':').unwrap();
    let missing = format!("{vault}:{}", "0".repeat(32));
    let reply = host.ask(serde_json::json!({
        "type": "fill", "origin": "https://github.com", "ref": missing, "want": ["password"],
    }));
    assert_error(&reply, "not_found");

    // Pages that get nothing: not https, not a site of their own.
    for origin in [
        "http://github.com",
        "https://github.io",
        "github.com",
        "javascript:alert(1)",
        EXTENSION,
    ] {
        let reply = host.ask(serde_json::json!({"type": "list", "origin": origin}));
        assert_error(&reply, "bad_request");
        let reply = host.ask(serde_json::json!({
            "type": "fill", "origin": origin, "ref": github_ref, "want": ["password"],
        }));
        assert_error(&reply, "bad_request");
    }
    let reply = host.ask(serde_json::json!({
        "type": "fill", "origin": "https://github.com", "ref": "1234", "want": ["password"],
    }));
    assert_error(&reply, "bad_request");
    let reply = host.ask(serde_json::json!({
        "type": "fill", "origin": "https://github.com", "ref": github_ref, "want": [],
    }));
    assert_error(&reply, "bad_request");
    let reply = host.ask(serde_json::json!({"type": "unlock", "passphrase": "x"}));
    assert_error(&reply, "bad_request");
    host.close();
}

#[test]
fn browser_host_checks_and_saves_logins() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    new(
        &a,
        &[
            "login",
            "username=Dax",
            "url=github.com",
            "password=hunter2",
        ],
    );
    let mut host = Host::start(&a);
    let github_ref = refs(&list(&mut host, "https://github.com")).pop().unwrap();

    let check = |host: &mut Host, origin: &str, username: &str, password: &str| {
        let reply = host.ask(serde_json::json!({
            "type": "check", "origin": origin, "username": username, "password": password,
        }));
        assert_eq!(reply["type"], "check", "{reply}");
        assert!(!reply.to_string().contains("hunter2"), "{reply}");
        (
            reply["status"].as_str().unwrap().to_string(),
            reply["matches"].clone(),
        )
    };
    let refs_of = |r: &str| serde_json::json!([r]);
    assert_eq!(
        check(&mut host, "https://github.com", " dAX ", "hunter2"),
        ("same".into(), refs_of(&github_ref))
    );
    assert_eq!(
        check(&mut host, "https://github.com", "dax", "hunter3"),
        ("update".into(), refs_of(&github_ref))
    );
    assert_eq!(
        check(&mut host, "https://github.com", "octocat", "hunter2"),
        ("new".into(), serde_json::json!([]))
    );
    // The same login on another site is new there.
    assert_eq!(
        check(&mut host, "https://gitlab.com", "dax", "hunter2"),
        ("new".into(), serde_json::json!([]))
    );
    let reply = host.ask(serde_json::json!({
        "type": "check", "origin": "https://github.com", "username": "dax", "password": "",
    }));
    assert_error(&reply, "bad_request");

    // A new login goes to the default vault.
    let saved = host.ask(serde_json::json!({
        "type": "save", "origin": "https://example.com",
        "entry": {"title": "example.com", "url": "https://example.com/login",
                  "username": "kit", "password": "first-pw"},
    }));
    assert_eq!(saved["type"], "save", "{saved}");
    assert_eq!(saved["created"], true);
    let example_ref = saved["ref"].as_str().unwrap().to_string();
    assert_eq!(
        refs(&list(&mut host, "https://www.example.com")),
        std::slice::from_ref(&example_ref)
    );
    assert_eq!(a.run(&["get", "example"]), "first-pw\n");
    assert_eq!(a.run(&["get", "example", "-f", "username"]), "kit\n");
    assert_eq!(
        check(&mut host, "https://example.com", "kit", "first-pw").0,
        "same"
    );

    // With a ref, only that login's password changes.
    let updated = host.ask(serde_json::json!({
        "type": "save", "origin": "https://example.com", "ref": example_ref,
        "entry": {"title": "example.com", "url": "https://example.com",
                  "username": "kit", "password": "second-pw"},
    }));
    assert_eq!(
        updated,
        serde_json::json!({"id": updated["id"], "type": "save", "ref": example_ref, "created": false})
    );
    assert_eq!(a.run(&["get", "example"]), "second-pw\n");

    // Never another site's login, nor a URL off the page's site.
    let reply = host.ask(serde_json::json!({
        "type": "save", "origin": "https://example.com", "ref": github_ref,
        "entry": {"title": "example.com", "url": "https://example.com",
                  "username": "dax", "password": "stolen"},
    }));
    assert_error(&reply, "domain_mismatch");
    assert_eq!(a.run(&["get", "github"]), "hunter2\n");
    let reply = host.ask(serde_json::json!({
        "type": "save", "origin": "https://example.com",
        "entry": {"title": "github.com", "url": "https://github.com",
                  "username": "dax", "password": "stolen"},
    }));
    assert_error(&reply, "domain_mismatch");
    assert!(
        a.fail(&["get", "github", "dax", "stolen"])
            .contains("no item")
    );
    let reply = host.ask(serde_json::json!({
        "type": "save", "origin": "https://example.com",
        "entry": {"title": "", "url": "https://example.com", "username": "kit", "password": "pw"},
    }));
    assert_error(&reply, "bad_request");

    // Page titles become item names the vault takes.
    let saved = host.ask(serde_json::json!({
        "type": "save", "origin": "https://news.example.net",
        "entry": {"title": "News\t\u{7} —\n Sign in", "url": "https://news.example.net/login",
                  "username": "kit", "password": "news-pw"},
    }));
    assert_eq!(saved["created"], true, "{saved}");
    let news = list(&mut host, "https://news.example.net");
    assert_eq!(news["accounts"][0]["title"], "News — Sign in", "{news}");
    let long = "t".repeat(128);
    let saved = host.ask(serde_json::json!({
        "type": "save", "origin": "https://long.example.dev",
        "entry": {"title": long, "url": "https://long.example.dev", "username": "kit", "password": "pw"},
    }));
    assert_eq!(saved["created"], true, "{saved}");
    let reply = host.ask(serde_json::json!({
        "type": "save", "origin": "https://long.example.dev",
        "entry": {"title": format!("{long}t"), "url": "https://long.example.dev", "username": "kit", "password": "pw"},
    }));
    assert_error(&reply, "bad_request");

    // Only secure pages' URLs are saved, and no spaces.
    for url in [
        "javascript:alert(1)//example.com",
        "data:text/html,example.com",
        "ftp://example.com",
        "http://example.com",
        "example.com",
        "https://example.com/a b",
    ] {
        let reply = host.ask(serde_json::json!({
            "type": "save", "origin": "https://example.com",
            "entry": {"title": "Example", "url": url, "username": "new", "password": "pw"},
        }));
        assert_error(&reply, "bad_request");
    }
    let saved = host.ask(serde_json::json!({
        "type": "save", "origin": "https://trim.example.io",
        "entry": {"title": "Trim", "url": "  https://trim.example.io/login\n",
                  "username": "kit", "password": "pw"},
    }));
    assert_eq!(saved["created"], true, "{saved}");
    assert_eq!(
        list(&mut host, "https://trim.example.io")["accounts"][0]["urls"],
        serde_json::json!(["https://trim.example.io/login"])
    );
    host.close();
}

/// A generated password waits in the agent, for its page's origin only:
/// as a candidate until the extension says it went into the page, then
/// until it's saved. Nothing is saved before, locking forgets it, and rules
/// that allow only weak passwords get none.
#[test]
fn browser_host_generates_passwords_and_holds_them_until_saved() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    let mut host = Host::start(&a);
    let origin = "https://shop.example.com";
    let generate = |host: &mut Host, extra: serde_json::Value| {
        let mut request = serde_json::json!({"type": "generate", "origin": origin});
        request
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        host.ask(request)
    };
    let field = serde_json::json!({"maxLength": 16, "rules": "required: digit; required: [!]; allowed: lower"});
    let checked =
        host.ask(serde_json::json!({"type": "generate-check", "origin": origin, "maxLength": 16}));
    assert_eq!(checked["type"], "generate-check", "{checked}");
    let pin = serde_json::json!({"type": "generate-check", "origin": origin, "maxLength": 6, "allowed": "0123456789"});
    assert_error(&host.ask(pin), "weak");
    assert_error(
        &generate(
            &mut host,
            serde_json::json!({"maxLength": 4, "allowed": "0123456789"}),
        ),
        "weak",
    );
    let made = generate(&mut host, field);
    assert_eq!(made["type"], "generate", "{made}");
    let password = made["password"].as_str().unwrap().to_string();
    let id = made["generated"].as_str().unwrap().to_string();
    assert_eq!(password.len(), 16);
    assert!(
        password
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'!')
    );
    assert!(password.contains('!') && password.bytes().any(|b| b.is_ascii_digit()));
    assert_eq!(a.run(&["ls"]), "", "nothing saved");
    let impossible = generate(
        &mut host,
        serde_json::json!({"minLength": 30, "maxLength": 8}),
    );
    assert_error(&impossible, "failed");

    // A candidate names nothing until it's in the page.
    let check = serde_json::json!({
        "type": "check", "origin": origin, "username": "kit", "generated": id,
    });
    assert_error(&host.ask(check.clone()), "not_found");
    let keep = |host: &mut Host, origin: &str, id: &serde_json::Value| {
        host.ask(serde_json::json!({"type": "generate-keep", "origin": origin, "generated": id}))
    };
    assert_error(
        &keep(&mut host, "https://www.example.com", &made["generated"]),
        "not_found",
    );
    assert_eq!(
        keep(&mut host, origin, &made["generated"])["type"],
        "generate-keep"
    );
    let reply = host.ask(check);
    assert_eq!(reply["status"], "new", "{reply}");
    // A dropped candidate is gone.
    let dropped = generate(&mut host, serde_json::json!({}));
    let reply = host.ask(serde_json::json!({"type": "generate-drop", "origin": origin, "generated": dropped["generated"]}));
    assert_eq!(reply["type"], "generate-drop", "{reply}");
    assert_error(&keep(&mut host, origin, &dropped["generated"]), "not_found");
    let reply = host.ask(serde_json::json!({
        "type": "check", "origin": origin, "username": "kit", "generated": id, "password": "x",
    }));
    assert_error(&reply, "bad_request");
    // Another origin, even on the same site, can't use it.
    let entry = serde_json::json!({"title": "Shop", "url": "https://shop.example.com/join",
                                   "username": "kit", "generated": id});
    let reply = host.ask(serde_json::json!({
        "type": "save", "origin": "https://www.example.com", "entry": entry,
    }));
    assert_error(&reply, "not_found");
    let saved = host.ask(serde_json::json!({"type": "save", "origin": origin, "entry": entry}));
    assert_eq!(saved["created"], true, "{saved}");
    assert_eq!(a.run(&["get", "shop"]), format!("{password}\n"));
    let reply = host.ask(serde_json::json!({"type": "save", "origin": origin, "entry": entry}));
    assert_error(&reply, "not_found");

    let made = generate(&mut host, serde_json::json!({}));
    assert_eq!(made["password"].as_str().unwrap().len(), 20);
    keep(&mut host, origin, &made["generated"]);
    a.run(&["lock"]);
    a.run(&["unlock"]);
    let reply = host.ask(serde_json::json!({
        "type": "check", "origin": origin, "username": "kit", "generated": made["generated"],
    }));
    assert_error(&reply, "not_found");
    host.close();
}

/// Checks guess passwords and fills hand them out: a runaway caller gets
/// a burst, then slows down.
#[test]
fn browser_host_rate_limits_checks_and_fills() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    new(
        &a,
        &[
            "login",
            "username=dax",
            "url=github.com",
            "password=hunter2",
        ],
    );
    let mut host = Host::start(&a);
    let github_ref = refs(&list(&mut host, "https://github.com")).pop().unwrap();
    let check = serde_json::json!({
        "type": "check", "origin": "https://github.com", "username": "dax", "password": "guess",
    });
    let fill = serde_json::json!({
        "type": "fill", "origin": "https://github.com", "ref": github_ref, "want": ["password"],
    });
    for (request, burst) in [(check, 20), (fill, 60)] {
        let mut answered = 0;
        loop {
            let reply = host.ask(request.clone());
            if reply["type"] == "error" {
                assert_error(&reply, "rate_limited");
                break;
            }
            answered += 1;
            assert!(answered < burst * 3, "never limited: {request}");
        }
        assert!(answered >= burst, "limited after {answered}: {request}");
    }
    // Lists aren't limited.
    for _ in 0..100 {
        list(&mut host, "https://github.com");
    }
    host.close();
}

/// The browser hanging up mid-reply ends the host, not a SIGPIPE.
#[test]
fn browser_host_survives_a_closed_pipe() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    let mut child = a
        .cmd(&[EXTENSION])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let mut stdin = child.stdin.take().unwrap();
    let hello = br#"{"id":1,"type":"hello"}"#;
    stdin
        .write_all(&u32::try_from(hello.len()).unwrap().to_ne_bytes())
        .unwrap();
    stdin.write_all(hello).unwrap();
    stdin.flush().unwrap();
    let status = wait(&mut child, Duration::from_secs(30));
    assert!(status.success(), "{status:?}");
    drop(stdin);
}

#[test]
fn browser_host_frames_and_refusals() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    let mut host = Host::start(&a);

    // A message over the limit is skipped whole; the connection carries on.
    let mut big = br#"{"id":"big","type":"list","origin":""#.to_vec();
    big.resize(70_000, b'a');
    big.extend_from_slice(br#""}"#);
    host.send_raw(&big);
    let reply = host.reply();
    assert_error(&reply, "bad_request");
    assert_eq!(reply["id"], serde_json::Value::Null);
    host.send_raw(b"not json");
    let reply = host.reply();
    assert_error(&reply, "bad_request");
    assert_eq!(reply["id"], serde_json::Value::Null);
    host.send_raw(br#"{"type":"hello"}"#);
    assert_error(&host.reply(), "bad_request");
    host.send_raw(br#"{"id":7,"type":"hello"}"#);
    let reply = host.reply();
    assert_eq!(reply["id"], 7);
    assert_eq!(reply["status"], "ready");
    // Many requests on one connection, answered in order.
    for _ in 0..20 {
        let reply = host.ask(serde_json::json!({"type": "list", "origin": "https://github.com"}));
        assert_eq!(reply["accounts"], serde_json::json!([]));
    }
    host.close();

    // Only the Deadbolt extension may run the host.
    for args in [
        &["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"][..],
        &[
            "browser-host",
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
        ],
        &["browser-host", "https://github.com"],
    ] {
        let output = a.try_run(args);
        assert!(!output.status.success(), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("only the Deadbolt extension"),
            "{args:?}"
        );
    }
}

#[test]
fn browser_host_when_locked_or_not_set_up() {
    let fresh = Device::new();
    let mut host = Host::start(&fresh);
    let hello = host.ask(serde_json::json!({"type": "hello"}));
    assert_eq!(hello["status"], "not-set-up", "{hello}");
    let reply = host.ask(serde_json::json!({"type": "list", "origin": "https://github.com"}));
    assert_error(&reply, "locked");
    host.close();

    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    new(
        &a,
        &[
            "login",
            "username=dax",
            "url=github.com",
            "password=hunter2",
        ],
    );
    let mut host = Host::start(&a);
    let github_ref = refs(&list(&mut host, "https://github.com")).pop().unwrap();
    a.run(&["lock"]);
    let hello = host.ask(serde_json::json!({"type": "hello"}));
    assert_eq!(hello["status"], "locked", "{hello}");
    assert_eq!(hello["detail"], "Unlock Deadbolt to fill passwords");
    for request in [
        serde_json::json!({"type": "list", "origin": "https://github.com"}),
        serde_json::json!({"type": "fill", "origin": "https://github.com", "ref": github_ref, "want": ["password"]}),
        serde_json::json!({"type": "check", "origin": "https://github.com", "username": "dax", "password": "x"}),
        serde_json::json!({"type": "save", "origin": "https://github.com",
            "entry": {"title": "github.com", "url": "https://github.com", "username": "dax", "password": "x"}}),
    ] {
        assert_error(&host.ask(request), "locked");
    }
    // A stopped agent is locked too, and the host never starts one but
    // for hello, nor prompts.
    a.run(&["agent", "stop"]);
    assert_error(
        &host.ask(serde_json::json!({"type": "list", "origin": "https://github.com"})),
        "locked",
    );
    assert!(a.agent_pid().is_none());
    host.close();
}

/// The agent hello starts isn't news.
#[test]
fn browser_host_announces_only_agents_that_come_back() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    a.run(&["agent", "stop"]);
    let mut host = Host::start(&a);
    let hello = host.ask(serde_json::json!({"type": "hello"}));
    assert_eq!(hello["status"], "locked", "{hello}");
    // The watcher looks for an agent every 2 s.
    if let Some(message) = host.pushed(Duration::from_secs(5)) {
        panic!("pushed {message}");
    }
    a.run(&["unlock"]);
    assert_eq!(
        host.pushed(Duration::from_secs(30)).unwrap()["change"],
        "unlocked"
    );
    host.close();
}

#[test]
fn browser_host_pushes_changes() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    let mut host = Host::start(&a);
    assert_eq!(
        host.ask(serde_json::json!({"type": "hello"}))["status"],
        "ready"
    );
    // The watch connects on its own; wait until an edit shows up. Edits are
    // all it pushes: no `started` for the agent hello found running.
    let mut n = 0;
    eventually("the host to watch the agent", || {
        n += 1;
        new(
            &a,
            &["login", &format!("url=site{n}.example"), "password=pw"],
        );
        host.pushed(Duration::from_secs(1))
            .is_some_and(|m| m["change"] == "items")
    });
    while let Some(message) = host.pushed(Duration::from_millis(500)) {
        assert_eq!(message["change"], "items", "{message}");
    }

    let change = |host: &mut Host| {
        host.pushed(Duration::from_secs(30)).expect("a change")["change"]
            .as_str()
            .unwrap()
            .to_string()
    };
    a.run(&["lock"]);
    assert_eq!(change(&mut host), "locked");
    a.run(&["unlock"]);
    assert_eq!(change(&mut host), "unlocked");
    a.run(&["agent", "stop"]);
    assert_eq!(change(&mut host), "stopped");
    a.run(&["unlock"]);
    assert_eq!(change(&mut host), "started");
    host.close();
}

/// Listing pages and checking typed logins, as a browser does on every
/// page, doesn't hold the vault open; filling does.
#[test]
fn browser_lookups_do_not_hold_off_the_idle_lock() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    new(
        &a,
        &[
            "login",
            "username=dax",
            "url=github.com",
            "password=hunter2",
        ],
    );
    let mut host = Host::start(&a);
    let github_ref = refs(&list(&mut host, "https://github.com")).pop().unwrap();

    a.run(&["unlock", "--timeout", "2s"]);
    let start = Instant::now();
    loop {
        let reply = host.ask(serde_json::json!({"type": "list", "origin": "https://github.com"}));
        if reply["type"] == "error" {
            assert_error(&reply, "locked");
            break;
        }
        host.ask(serde_json::json!({
            "type": "check", "origin": "https://github.com", "username": "dax", "password": "x",
        }));
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "still unlocked while pages are looked at"
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    a.run(&["unlock", "--timeout", "2s"]);
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(4) {
        let fill = host.ask(serde_json::json!({
            "type": "fill", "origin": "https://github.com", "ref": github_ref, "want": ["password"],
        }));
        assert_eq!(fill["password"], "hunter2", "locked while filling");
        std::thread::sleep(Duration::from_millis(250));
    }
    host.close();
}

#[test]
fn browser_install_registers_the_host() {
    let a = Device::new();
    let home = a.path("user");
    let browsers = |dir: &str| -> Vec<(&'static str, PathBuf)> {
        let base = if cfg!(target_os = "macos") {
            home.join("Library/Application Support")
        } else {
            a.path("config")
        };
        let names: &[(&str, &str)] = if cfg!(target_os = "macos") {
            &[
                ("Chrome", "Google/Chrome"),
                ("Brave", "BraveSoftware/Brave-Browser"),
                ("Arc", "Arc/User Data"),
                ("Edge", "Microsoft Edge"),
                ("Chromium", "Chromium"),
                ("Helium", "net.imput.helium"),
            ]
        } else {
            &[
                ("Chrome", "google-chrome"),
                ("Brave", "BraveSoftware/Brave-Browser"),
                ("Edge", "microsoft-edge"),
                ("Chromium", "chromium"),
                ("Helium", "net.imput.helium"),
            ]
        };
        names
            .iter()
            .map(|(name, path)| (*name, base.join(path).join(dir)))
            .collect()
    };
    let manifests: Vec<(&str, PathBuf)> = browsers("NativeMessagingHosts/pw.deadbolt.browser.json");
    let run = |args: &[&str]| a.output(a.cmd(args).env("HOME", &home));

    // Nothing installed: say so rather than guess.
    let output = run(&["browser", "install"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--browser"));

    // By default, only the browsers that are here.
    let (chrome, chrome_manifest) = &manifests[0];
    std::fs::create_dir_all(chrome_manifest.parent().unwrap().parent().unwrap()).unwrap();
    let output = run(&["browser", "install"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(&format!("{chrome}: wrote {}", chrome_manifest.display())),
        "{stdout}"
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(chrome_manifest).unwrap()).unwrap();
    assert_eq!(manifest["name"], "pw.deadbolt.browser");
    assert_eq!(manifest["type"], "stdio");
    assert_eq!(manifest["allowed_origins"], serde_json::json!([EXTENSION]));
    let path = PathBuf::from(manifest["path"].as_str().unwrap());
    assert!(path.is_absolute());
    assert_eq!(
        std::fs::canonicalize(&path).unwrap(),
        std::fs::canonicalize(BIN).unwrap()
    );
    for (_, other) in &manifests[1..] {
        assert!(!other.exists(), "{}", other.display());
    }

    // Every browser on request, then gone again.
    assert!(
        run(&["browser", "install", "--browser", "all"])
            .status
            .success()
    );
    for (_, manifest) in &manifests {
        assert!(manifest.is_file(), "{}", manifest.display());
    }
    let output = run(&["browser", "uninstall"]);
    assert!(output.status.success());
    for (_, manifest) in &manifests {
        assert!(!manifest.exists(), "{}", manifest.display());
    }
    let output = run(&["browser", "uninstall"]);
    assert!(String::from_utf8_lossy(&output.stdout).contains("wasn't registered"));
}

fn unb64(text: &str) -> Vec<u8> {
    data_encoding::BASE64URL_NOPAD
        .decode(text.as_bytes())
        .unwrap()
}

#[test]
fn browser_host_registers_and_signs_in_with_passkeys() {
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::DecodePublicKey;
    use sha2::Digest;

    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    let mut host = Host::start(&a);
    let challenge = "AAECAwQFBgcICQoLDA0ODw";
    let origin = "https://login.example.com";
    let passkeys = |host: &mut Host, origin: &str, rp: &str| {
        let reply = host.ask(serde_json::json!({
            "type": "passkey-list", "origin": origin, "rpId": rp,
        }));
        assert_eq!(reply["type"], "passkeys", "{reply}");
        reply
    };
    let listed = passkeys(&mut host, origin, "example.com");
    assert_eq!(listed["rpId"], "example.com");
    assert_eq!(listed["canVerify"], false, "no Touch ID here");
    assert_eq!(listed["passkeys"], serde_json::json!([]));

    let create = |uv: &str| {
        serde_json::json!({
            "type": "passkey-create", "origin": origin, "rpId": "example.com",
            "challenge": challenge, "user": {"id": "a2l0", "name": "kit"},
            "exclude": [], "userVerification": uv,
        })
    };
    // Verification required without Touch ID fails before storing anything.
    assert_error(&host.ask(create("required")), "failed");
    assert_eq!(
        passkeys(&mut host, origin, "example.com")["passkeys"],
        serde_json::json!([])
    );

    let made = host.ask(create("preferred"));
    assert_eq!(made["type"], "passkey-created", "{made}");
    assert_eq!(made["verified"], false);
    let client: serde_json::Value =
        serde_json::from_slice(&unb64(made["clientDataJSON"].as_str().unwrap())).unwrap();
    assert_eq!(
        client,
        serde_json::json!({"type": "webauthn.create", "challenge": challenge,
                           "origin": origin, "crossOrigin": false})
    );
    let data = unb64(made["authenticatorData"].as_str().unwrap());
    assert_eq!(&data[..32], sha2::Sha256::digest(b"example.com").as_slice());
    assert_eq!(data[32], 0x59, "UP, BE, BS and AT; no UV");
    assert!(unb64(made["attestationObject"].as_str().unwrap()).starts_with(b"\xa3\x63fmt\x64none"));
    let key =
        p256::ecdsa::VerifyingKey::from_public_key_der(&unb64(made["publicKey"].as_str().unwrap()))
            .unwrap();
    let listed = passkeys(&mut host, "https://example.com", "example.com");
    assert_eq!(listed["passkeys"][0]["ref"], made["ref"]);
    assert_eq!(listed["passkeys"][0]["username"], "kit");
    assert_eq!(listed["passkeys"][0]["credentialId"], made["credentialId"]);

    let get = |origin: &str, rp: &str, uv: &str| {
        serde_json::json!({
            "type": "passkey-get", "origin": origin, "rpId": rp, "ref": made["ref"],
            "challenge": challenge, "userVerification": uv,
        })
    };
    let signed = host.ask(get("https://example.com", "example.com", "discouraged"));
    assert_eq!(signed["type"], "passkey-assertion", "{signed}");
    assert_eq!(signed["userHandle"], "a2l0");
    assert_eq!(signed["credentialId"], made["credentialId"]);
    let client = unb64(signed["clientDataJSON"].as_str().unwrap());
    let mut message = unb64(signed["authenticatorData"].as_str().unwrap());
    assert_eq!(message[32], 0x19);
    message.extend_from_slice(&sha2::Sha256::digest(&client));
    let signature =
        p256::ecdsa::Signature::from_der(&unb64(signed["signature"].as_str().unwrap())).unwrap();
    assert!(key.verify(&message, &signature).is_ok());

    // Opaque frames, other sites and public suffixes get nothing.
    for (origin, rp) in [
        ("null", "example.com"),
        ("https://evil.com", "example.com"),
        ("https://example.com", "com"),
        ("https://alice.github.io", "github.io"),
    ] {
        let reply = host.ask(serde_json::json!({
            "type": "passkey-list", "origin": origin, "rpId": rp,
        }));
        assert_error(&reply, "domain_mismatch");
        assert_error(&host.ask(get(origin, rp, "preferred")), "domain_mismatch");
    }
    assert_error(
        &host.ask(get("https://evil.com", "evil.com", "preferred")),
        "domain_mismatch",
    );
    host.close();

    // The private key never leaves the agent.
    let show = a.run(&["show", "--reveal", "example.com"]);
    assert!(
        show.contains("example.com") && !show.contains("private-key"),
        "{show}"
    );
    assert!(
        !a.try_run(&["get", "example.com", "-f", "private-key"])
            .status
            .success()
    );
}

/// Fetches a send link like the receive page does, over localhost.
fn receive(link: &str) -> Result<deadbolt_send::Bundle, deadbolt_send::Error> {
    let ticket: deadbolt_send::SendTicket = link.trim().parse().unwrap();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let endpoint = deadbolt_send::receiver_endpoint(deadbolt_send::Network::Local)
            .await
            .unwrap();
        let bundle = deadbolt_send::receive(&endpoint, &ticket, |_| {}).await;
        endpoint.close().await;
        bundle
    })
}

fn entry(node: &deadbolt_send::Node) -> &deadbolt_send::Entry {
    match node {
        deadbolt_send::Node::Entry(entry) => entry,
        deadbolt_send::Node::Group(group) => panic!("expected an entry, got {group:?}"),
    }
}

#[test]
fn send_files_secrets_and_items() {
    use deadbolt_send::Node;
    let a = Device::new();
    a.run(&["init"]);
    new(
        &a,
        &[
            "login",
            "username=dax",
            "password=hunter22",
            "url=github.com",
        ],
    );

    // A file, a folder, stdin and an item in one send.
    std::fs::write(a.path("report.txt"), "quarterly").unwrap();
    std::fs::create_dir(a.path("keys")).unwrap();
    std::fs::write(a.path("keys/id.pub"), "ssh-ed25519 AAAA").unwrap();
    let report = a.path("report.txt");
    let keys = a.path("keys");
    let out = a.try_run_stdin(
        &[
            "send",
            report.to_str().unwrap(),
            keys.to_str().unwrap(),
            "-",
            "--item",
            "github.com",
            "--title",
            "for you",
            "--note",
            "rotate after",
            "--yes",
            "--json",
        ],
        "tok_123\n",
    );
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let link = json["link"].as_str().unwrap();
    let id = json["id"].as_str().unwrap();
    assert!(link.starts_with("https://deadbolt.pw/r#"), "{link}");
    assert!(json["expires"].as_u64().unwrap() > 0);

    let bundle = receive(link).unwrap();
    assert_eq!(bundle.title.as_deref(), Some("for you"));
    assert_eq!(bundle.note.as_deref(), Some("rotate after"));
    let [file, Node::Group(folder), stdin, Node::Group(item)] = &bundle.entries[..] else {
        panic!("unexpected bundle {bundle:?}");
    };
    let file = entry(file);
    assert_eq!(
        (file.name.as_str(), file.data.as_slice(), file.sensitive),
        ("report.txt", &b"quarterly"[..], false)
    );
    assert_eq!(folder.name.as_deref(), Some("keys"));
    assert_eq!(entry(&folder.entries[0]).name, "id.pub");
    let stdin = entry(stdin);
    assert_eq!(
        (stdin.data.as_slice(), stdin.sensitive),
        (&b"tok_123"[..], true)
    );
    assert_eq!(item.name.as_deref(), Some("github.com"));
    let password = item
        .entries
        .iter()
        .map(entry)
        .find(|e| e.name == "password")
        .unwrap();
    assert_eq!(
        (password.data.as_slice(), password.sensitive),
        (&b"hunter22"[..], true)
    );

    // Single use: the second open is refused, and the sender sees it picked up.
    assert!(matches!(receive(link), Err(deadbolt_send::Error::Used)));
    let shown = a.run(&["sends", "show", id]);
    assert!(shown.contains("state\tpicked up"), "{shown}");
    assert!(shown.contains("opens\t1 of 1"), "{shown}");
    assert!(a.run(&["sends"]).contains(&format!("{id}\tpicked up")));

    // One field; revoking ends a waiting send with exit code 5.
    let mut waiting = a
        .cmd(&[
            "send",
            "--item",
            "github.com",
            "--field",
            "password",
            "--wait",
            "--ttl",
            "15m",
            "--yes",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(waiting.stdout.take().unwrap())
        .read_line(&mut first)
        .unwrap();
    let pending = a.run(&["sends", "ls", "--json"]);
    let pending: Vec<serde_json::Value> = serde_json::from_str(&pending).unwrap();
    let open = pending.iter().find(|s| s["state"] == "open").unwrap();
    let open_id = open["id"].as_str().unwrap();
    assert_eq!(open["label"], "github.com password");
    assert!(a.run(&["sends", "revoke", open_id]).starts_with("revoked"));
    assert_eq!(wait(&mut waiting, Duration::from_secs(30)).code(), Some(5));
    assert!(matches!(
        receive(&first),
        Err(deadbolt_send::Error::Revoked)
    ));

    assert!(a.fail(&["sends", "show", "zzzz"]).contains("no send"));
}

#[test]
fn send_resolves_inputs_strictly_and_asks_first() {
    let a = Device::new();
    let file = a.path("hello.txt");
    std::fs::write(&file, "hi").unwrap();
    let file = file.to_str().unwrap();

    // A missing path is an error, never a vault search: this device has no vault.
    let err = a.fail(&["send", "./prod.env.typo", "--yes"]);
    assert!(err.contains("./prod.env.typo: no such file"), "{err}");

    // Without --yes there's nothing to confirm on: fail rather than hang.
    let err = a.fail(&["send", file, "--json"]);
    assert!(
        err.contains("--json needs --yes (no prompt possible)"),
        "{err}"
    );
    let err = a.fail(&["send", file]);
    assert!(err.contains("pass --yes"), "{err}");
    let out = a.try_run_stdin(&["send", "-"], "tok_123\n");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("pass --yes"),
        "{out:?}"
    );
    assert!(a.run(&["sends", "ls", "--json"]).trim() == "[]");

    // Vault items: exact name or ID only, with suggestions.
    a.run(&["init"]);
    let stripe = new(&a, &["login", "password=sk_live", "--name", "Stripe"]);
    new(
        &a,
        &["login", "password=sk_test", "--name", "Stripe (test)"],
    );
    new(&a, &["login", "password=one", "--name", "Twin"]);
    new(&a, &["login", "password=two", "--name", "Twin"]);
    let err = a.fail(&["send", "--item", "stripe", "--yes"]);
    assert!(
        err.contains(r#"no item named "stripe". Did you mean: "Stripe", "Stripe (test)"?"#),
        "{err}"
    );
    let err = a.fail(&["send", "--item", "Twin", "--yes"]);
    assert!(err.contains(r#"2 items are named "Twin""#), "{err}");
    let err = a.fail(&["send", "--field", "password", "--item", "Stripe", "--yes"]);
    assert!(err.contains("must follow the --item"), "{err}");

    let link = |args: &[&str]| {
        let out = a.run(&[&["send", "--yes"], args].concat());
        receive(&out).unwrap()
    };
    let bundle = link(&["--item", "Stripe", "--field", "password", file]);
    assert_eq!(entry(&bundle.entries[0]).name, "Stripe password");
    assert_eq!(entry(&bundle.entries[0]).data, b"sk_live");
    assert_eq!(entry(&bundle.entries[1]).data, b"hi");
    let bundle = link(&["--item", &stripe, "--field", "password"]);
    assert_eq!(entry(&bundle.entries[0]).data, b"sk_live");
}

#[test]
fn a_waiting_send_reports_the_pickup() {
    let a = Device::new();
    let file = a.path("hello.txt");
    std::fs::write(&file, "hi").unwrap();
    // Sends need no vault: this device isn't even set up.
    let mut waiting = a
        .cmd(&[
            "send",
            file.to_str().unwrap(),
            "--wait",
            "--opens",
            "2",
            "--yes",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut link = String::new();
    BufReader::new(waiting.stdout.take().unwrap())
        .read_line(&mut link)
        .unwrap();
    receive(&link).unwrap();
    assert!(
        waiting.try_wait().unwrap().is_none(),
        "one of two opens left"
    );
    let bundle = receive(&link).unwrap();
    assert_eq!(entry(&bundle.entries[0]).data, b"hi");
    assert_eq!(wait(&mut waiting, Duration::from_secs(30)).code(), Some(0));
    let mut err = String::new();
    waiting
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(err.contains("picked up"), "{err}");
}

/// Release builds take `deadbolt-enclave` from `scripts/build-enclave.sh`,
/// not `build.rs`, so both compile every Swift source in the helper, or a
/// release ships a helper missing part of it (caller identity, say).
#[test]
fn the_release_helper_builds_every_swift_source() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let script = std::fs::read_to_string(root.join("scripts/build-enclave.sh")).unwrap();
    let build = std::fs::read_to_string(root.join("build.rs")).unwrap();
    let mut sources: Vec<String> = std::fs::read_dir(root.join("src/agent"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".swift"))
        .collect();
    sources.sort();
    assert!(sources.len() >= 2, "{sources:?}");
    for name in &sources {
        assert!(
            script.contains(&format!("\"$src/{name}\"")),
            "build-enclave.sh doesn't compile {name}"
        );
        assert!(
            build.contains(&format!("\"src/agent/{name}\"")),
            "build.rs doesn't compile {name}"
        );
    }
}

/// A release service on 127.0.0.1 for `deadbolt update`: serves whatever
/// `files` holds at each path, one request per connection.
fn release_service(
    files: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/release/", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            reader.read_line(&mut request).ok();
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                line.clear();
            }
            let path = request.split_whitespace().nth(1).unwrap_or("").to_string();
            let body = files.lock().unwrap().get(&path).cloned();
            let (status, body) = match body {
                Some(body) => ("200 OK", body),
                None => ("404 Not Found", b"{}".to_vec()),
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).ok();
            stream.write_all(&body).ok();
        }
    });
    base
}

#[test]
fn update_replaces_a_standalone_deadbolt_only_once_it_checks_out() {
    use sha2::Digest;
    let a = Device::new();
    let bin = a.path("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let exe = bin.join("deadbolt");
    std::fs::copy(BIN, &exe).unwrap();
    let original = std::fs::read(&exe).unwrap();

    // The release: a tarball whose deadbolt is a stand-in script.
    let release = a.path("release");
    std::fs::create_dir_all(&release).unwrap();
    std::fs::write(
        release.join("deadbolt"),
        "#!/bin/sh\necho stand-in deadbolt\n",
    )
    .unwrap();
    let tarball = a.path("deadbolt.tar.gz");
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&tarball)
        .arg("-C")
        .arg(&release)
        .arg("deadbolt")
        .status()
        .unwrap();
    assert!(status.success());
    let tar = std::fs::read(&tarball).unwrap();
    let sha = |bytes: &[u8]| data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(bytes));
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };
    let manifest = |artifact: &str, channel: &str, version: &str, target: &str, size, sha256| {
        let mut targets = serde_json::Map::new();
        targets.insert(
            target.to_string(),
            serde_json::json!({
                "url": format!("/release/deadbolt/files/{sha256}/{artifact}.bin"),
                "size": size,
                "sha256": sha256,
            }),
        );
        serde_json::json!({
            "schema": 1, "app": "deadbolt", "artifact": artifact, "channel": channel,
            "sequence": 1, "published_at": "2026-10-28T00:00:00Z",
            "release": {
                "version": version, "rollout_percent": 100, "targets": targets,
                "distributions": [{ "kind": "direct" }], "revoked_versions": []
            }
        })
        .to_string()
        .into_bytes()
    };
    let target = format!("{os}-{arch}");
    let good = sha(&tar);
    let wrong = sha(b"something else");
    let files = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::from([
        (
            format!("/release/deadbolt/files/{good}/cli.bin"),
            tar.clone(),
        ),
        (
            format!("/release/deadbolt/files/{wrong}/cli.bin"),
            tar.clone(),
        ),
        (
            "/release/deadbolt/cli/beta.json".to_string(),
            manifest(
                "cli",
                "beta",
                "0.0.0-beta.9",
                &target,
                tar.len(),
                wrong.clone(),
            ),
        ),
        (
            "/release/deadbolt/cli/stable.json".to_string(),
            manifest(
                "cli",
                "stable",
                "9.9.9",
                &target,
                tar.len() + 1,
                good.clone(),
            ),
        ),
        (
            "/release/deadbolt/cli/dev.json".to_string(),
            manifest(
                "cli",
                "dev",
                env!("CARGO_PKG_VERSION"),
                &target,
                tar.len(),
                good.clone(),
            ),
        ),
    ])));
    let base = release_service(files.clone());
    let update = |args: &[&str]| {
        let mut cmd = a.cmd_of(&exe, args);
        cmd.env("DEADBOLT_RELEASE_URL", &base);
        a.output(&mut cmd)
    };
    let leftovers = || {
        std::fs::read_dir(&bin)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|name| name != "deadbolt")
            .collect::<Vec<_>>()
    };

    // A build from source follows no channel until told one.
    let output = update(&["update", "--check"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--channel"));

    // The running version is the channel's: nothing to do.
    let output = update(&["update", "--check", "--channel", "dev"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("up to date"));

    // A wrong SHA-256 or size leaves the old binary alone.
    for channel in ["beta", "stable"] {
        let output = update(&["update", "--channel", channel]);
        assert!(!output.status.success(), "{channel}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("SHA-256") || stderr.contains("size"),
            "{stderr}"
        );
        assert!(std::fs::read(&exe).unwrap() == original, "{channel}");
        assert!(leftovers().is_empty(), "{:?}", leftovers());
    }
    // So does a manifest pointing anywhere but the service's files.
    files.lock().unwrap().insert(
        "/release/deadbolt/cli/dev.json".to_string(),
        String::from_utf8(manifest(
            "cli",
            "dev",
            "0.0.0-dev-99",
            &target,
            tar.len(),
            good.clone(),
        ))
        .unwrap()
        .replace(
            "/release/deadbolt/files/",
            "http://198.51.100.1/release/deadbolt/files/",
        )
        .into_bytes(),
    );
    let output = update(&["update", "--channel", "dev"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("outside"));
    assert!(std::fs::read(&exe).unwrap() == original);

    // A replayed older manifest is refused unless asked for.
    let sequenced = |n: u32| {
        String::from_utf8(manifest(
            "cli",
            "dev",
            "0.0.0-dev-99",
            &target,
            tar.len(),
            good.clone(),
        ))
        .unwrap()
        .replace("\"sequence\":1", &format!("\"sequence\":{n}"))
        .into_bytes()
    };
    let serve = |n: u32| {
        files
            .lock()
            .unwrap()
            .insert("/release/deadbolt/cli/dev.json".to_string(), sequenced(n));
    };
    serve(3);
    assert_eq!(
        update(&["update", "--check", "--channel", "dev"])
            .status
            .code(),
        Some(10)
    );
    serve(2);
    let output = update(&["update", "--channel", "dev"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("--allow-rollback"));
    assert!(std::fs::read(&exe).unwrap() == original);
    let output = update(&["update", "--check", "--channel", "dev", "--allow-rollback"]);
    assert_eq!(output.status.code(), Some(10));
    serve(3);

    // On macOS the new deadbolt pins its own helper: a release without one
    // never replaces a deadbolt that has one beside it.
    if cfg!(target_os = "macos") {
        std::fs::write(bin.join("deadbolt-enclave"), "old helper").unwrap();
        let output = update(&["update", "--channel", "dev"]);
        assert!(String::from_utf8_lossy(&output.stderr).contains("deadbolt-enclave"));
        assert!(std::fs::read(&exe).unwrap() == original);
        assert_eq!(
            std::fs::read(bin.join("deadbolt-enclave")).unwrap(),
            b"old helper"
        );
        std::fs::remove_file(bin.join("deadbolt-enclave")).unwrap();
    }

    // A good release, with an unpacked extension registered beside it.
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file("manifest.json", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(br#"{"name":"Deadbolt","version":"0.0.0.99","version_name":"0.0.0-dev-99"}"#)
        .unwrap();
    let extension = zip.finish().unwrap().into_inner();
    let ext_sha = sha(&extension);
    files.lock().unwrap().extend([
        (
            format!("/release/deadbolt/files/{ext_sha}/extension.bin"),
            extension.clone(),
        ),
        (
            "/release/deadbolt/extension/dev.json".to_string(),
            manifest(
                "extension",
                "dev",
                "0.0.0-dev-99",
                "chromium",
                extension.len(),
                ext_sha,
            ),
        ),
    ]);
    let ext = a.path("extension");
    std::fs::create_dir_all(&ext).unwrap();
    std::fs::write(ext.join("mine.txt"), "not an extension").unwrap();
    let output = a.output(
        a.cmd(&[
            "browser",
            "install",
            "--browser",
            "chrome",
            "--extension-dir",
        ])
        .arg(&ext)
        .env("HOME", a.path("user")),
    );
    assert!(
        !output.status.success(),
        "replaced a directory that isn't the extension"
    );
    std::fs::remove_file(ext.join("mine.txt")).unwrap();
    let output = a.output(
        a.cmd(&[
            "browser",
            "install",
            "--browser",
            "chrome",
            "--extension-dir",
        ])
        .arg(&ext)
        .env("HOME", a.path("user")),
    );
    assert!(output.status.success());

    let output = update(&["update", "--check", "--channel", "dev"]);
    assert_eq!(output.status.code(), Some(10));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("0.0.0-dev-99 is available"), "{stdout}");
    assert!(
        stdout.contains("Browser extension 0.0.0-dev-99"),
        "{stdout}"
    );
    assert!(std::fs::read(&exe).unwrap() == original);

    let output = update(&["update", "--channel", "dev"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("chrome://extensions"));
    assert_eq!(
        std::fs::read(&exe).unwrap(),
        b"#!/bin/sh\necho stand-in deadbolt\n"
    );
    let ran = Command::new(&exe).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&ran.stdout), "stand-in deadbolt\n");
    assert!(leftovers().is_empty(), "{:?}", leftovers());
    assert!(
        std::fs::read_to_string(ext.join("manifest.json"))
            .unwrap()
            .contains("0.0.0-dev-99")
    );
    // It knows the files it put there, and nothing else is in the way.
    assert_eq!(
        std::fs::read_to_string(ext.join(".deadbolt-extension")).unwrap(),
        "manifest.json\n"
    );
}

/// The `export.data` of a `.1pux` with an identity and a card, as
/// 1Password 8 writes them.
const FORMS_1PUX: &str = r#"{"accounts": [{"attrs": {"uuid": "USERUSERUSERUSERUSERUSERUS"}, "vaults": [{
  "attrs": {"uuid": "v1v1v1v1v1v1v1v1v1v1v1v1v1", "name": "Private"},
  "items": [
    {"uuid": "ident1ident1ident1ident1id", "state": "active", "categoryUuid": "004",
     "details": {"notesPlain": "", "sections": [
       {"title": "Identification", "name": "name", "fields": [
         {"title": "first name", "id": "firstname", "value": {"string": "Kit"}},
         {"title": "initial", "id": "initial", "value": {"string": "A"}},
         {"title": "last name", "id": "lastname", "value": {"string": "Langton"}},
         {"title": "birth date", "id": "birthdate", "value": {"date": 636249600}},
         {"title": "company", "id": "company", "value": {"string": "Anomaly"}}]},
       {"title": "Address", "name": "address", "fields": [
         {"title": "address", "id": "address", "value": {"address": {"street": "123 Main St\nApt 4", "city": "Brooklyn", "state": "NY", "zip": "11201", "country": "us"}}},
         {"title": "default phone", "id": "defphone", "value": {"phone": "+1 (718) 555-0100"}}]},
       {"title": "Internet Details", "name": "internet", "fields": [
         {"title": "email", "id": "email", "value": {"email": {"email_address": "kit@example.com"}}}]}]},
     "overview": {"title": "Home"}},
    {"uuid": "card1card1card1card1card1c", "state": "active", "categoryUuid": "002",
     "details": {"sections": [{"title": "", "name": "", "fields": [
       {"title": "cardholder name", "id": "cardholder", "value": {"string": "Kit Langton"}},
       {"title": "type", "id": "type", "value": {"creditCardType": "visa"}},
       {"title": "number", "id": "ccnum", "value": {"creditCardNumber": "4242 4242 4242 4242"}},
       {"title": "verification number", "id": "cvv", "value": {"concealed": "737"}},
       {"title": "expiry date", "id": "expiry", "value": {"monthYear": 202808}},
       {"title": "PIN", "id": "pin", "value": {"concealed": "9876"}}]}]},
     "overview": {"title": "Visa"}}
  ]}]}]}"#;

/// A `.1pux` import makes a structured identity and a card; the browser
/// host lists them without values, fills only the fields asked, and
/// Activity records the card fill but not the identity's.
#[test]
fn forms_fill_from_an_imported_identity_and_card() {
    use std::io::Write as _;

    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    let file = a.path("export.1pux");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&file).unwrap());
    zip.start_file("export.data", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(FORMS_1PUX.as_bytes()).unwrap();
    zip.finish().unwrap();
    let output = a.try_run(&["import", file.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.starts_with("imported 2 from 1Password (logins 0, cards 1, identities 1)"),
        "{stdout}"
    );
    let show = a.run(&["show", "home"]);
    for line in [
        "given-name       Kit",
        "additional-name  A",
        "family-name      Langton",
        "organization     Anomaly",
        "phone            +17185550100",
        "address-line1    123 Main St",
        "address-line2    Apt 4",
        "city             Brooklyn",
        "region           NY",
        "postal-code      11201",
        "country          US",
        "birthday         1990-03-01",
    ] {
        assert!(show.contains(line), "{line:?} in\n{show}");
    }

    let mut host = Host::start(&a);
    let origin = "https://shop.example.com";
    let forms = host.ask(serde_json::json!({
        "type": "forms", "origin": origin, "kinds": ["identity", "card"],
    }));
    assert_eq!(forms["type"], "forms", "{forms}");
    assert_eq!(forms["canVerify"], false, "no Touch ID here");
    let identity = &forms["identities"][0];
    assert_eq!(identity["title"], "Home");
    assert_eq!(identity["summary"], "Kit Langton · 123 Main St, Brooklyn");
    let card = &forms["cards"][0];
    assert_eq!(
        (&card["brand"], &card["last4"], &card["expiry"]),
        (&"Visa".into(), &"4242".into(), &"2028-08".into())
    );
    // Refs are hex, so digits could appear by chance: look for the values.
    let listed = forms.to_string();
    assert!(
        !listed.contains("\"737\"") && !listed.contains("4242424242"),
        "{listed}"
    );

    let fill = |host: &mut Host, item: &serde_json::Value, fields: &[&str]| {
        host.ask(serde_json::json!({
            "type": "fill-form", "origin": origin, "ref": item["ref"], "fields": fields,
        }))
    };
    let filled = fill(
        &mut host,
        identity,
        &["given-name", "postal-code", "country"],
    );
    assert_eq!(
        filled["values"],
        serde_json::json!({"given-name": "Kit", "postal-code": "11201", "country": "US"})
    );
    let filled = fill(&mut host, card, &["number", "cvv", "expiry"]);
    assert_eq!(
        filled["values"],
        serde_json::json!({"number": "4242424242424242", "cvv": "737", "expiry": "2028-08"})
    );
    assert_eq!(filled["verified"], false, "the pick is the user's say");
    assert_error(&fill(&mut host, card, &["pin"]), "bad_request");
    // Not on a page autofill takes.
    let refused = host.ask(serde_json::json!({
        "type": "fill-form", "origin": "http://shop.example.com", "ref": card["ref"], "fields": ["number"],
    }));
    assert_error(&refused, "bad_request");
    host.close();

    let activity = a.run(&["activity", "--since", "1h", "--json"]);
    assert!(
        !activity.contains("4242424242") && !activity.contains("737"),
        "{activity}"
    );
    let entries: Vec<serde_json::Value> = activity
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .filter(|e: &serde_json::Value| e["command"].as_str().unwrap().starts_with("form-"))
        .collect();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["command"], "form-fill");
    assert_eq!(entries[0]["items"][0]["title"], format!("Visa · {origin}"));
    assert_eq!(
        entries[0]["fields"],
        serde_json::json!(["cvv", "expiry", "number"])
    );
}
