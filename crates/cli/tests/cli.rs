//! End-to-end tests: each device is a separate set of directories with its
//! own agent process, networking over localhost only.

#![cfg(test)]

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
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env("DEADBOLT_HOME", self.path("home"))
            .env("XDG_RUNTIME_DIR", self.path("run"))
            .env("XDG_STATE_HOME", self.path("state"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("DEADBOLT_NET", "local")
            .env("DEADBOLT_KDF", "fast")
            .env("DEADBOLT_PASSPHRASE", PASSPHRASE)
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
    let newer = a.output(a.cmd(&["status"]).env("DEADBOLT_TEST_PROTOCOL", "5"));
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
    let next = || -> serde_json::Value {
        let line = rx.recv_timeout(Duration::from_secs(30)).expect("a change");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("{line:?} is not JSON: {e}"))
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
