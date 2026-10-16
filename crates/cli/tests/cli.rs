//! End-to-end tests: each device is a separate set of directories with its
//! own agent process, networking over localhost only.

use std::io::{BufRead, BufReader, Read};
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
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env("DEADBOLT_HOME", self.path("home"))
            .env("XDG_RUNTIME_DIR", self.path("run"))
            .env("XDG_STATE_HOME", self.path("state"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("DEADBOLT_NET", "local")
            .env("DEADBOLT_KDF", "fast")
            .env("DEADBOLT_PASSPHRASE", PASSPHRASE)
            .env("DEADBOLT_TEST_AUTO_CONFIRM", "1")
            .env_remove("DEADBOLT_TEST_VERSION")
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
        let _ = self.cmd(&["agent", "stop"]).output();
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
            let _ = child.kill();
            panic!("process timed out");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `new` runs `deadbolt join`, `inviter` runs `deadbolt pair <ticket>`.
fn pair(inviter: &Device, new: &Device, device_name: &str, vault: Option<&str>) {
    let mut child = new
        .cmd(&["join", "--device-name", device_name])
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

    // Locked: commands unlock inline with DEADBOLT_PASSPHRASE.
    assert_eq!(a.run(&["lock"]), "locked\n");
    assert!(a.run(&["status"]).contains("state\tlocked\n"));
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

    // Restarting the agent keeps everything (store + meta).
    a.run(&["agent", "stop"]);
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
fn replaces_agent_of_another_version() {
    let a = Device::new();
    let old = a.output(a.cmd(&["status"]).env("DEADBOLT_TEST_VERSION", "0.0.0-old"));
    assert!(old.status.success());
    let out = a.output(
        a.cmd(&["agent", "status"])
            .env("DEADBOLT_TEST_VERSION", "0.0.0-old"),
    );
    let out = String::from_utf8(out.stdout).unwrap();
    assert!(out.ends_with("version 0.0.0-old\n"), "{out}");
    let old_pid = a.agent_pid().unwrap();

    let status = a.run(&["status"]);
    assert!(status.contains("state\tnot set up"), "{status}");
    let out = a.run(&["agent", "status"]);
    assert!(
        out.ends_with(&format!("version {}\n", env!("CARGO_PKG_VERSION"))),
        "{out}"
    );
    assert_ne!(a.agent_pid().unwrap(), old_pid);
}
