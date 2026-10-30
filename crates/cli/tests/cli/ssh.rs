//! End-to-end SSH agent (`ssh.sock`), `ssh-add`, `ssh-keygen -Y`, `git commit -S`
//! and local unprivileged `sshd` integration tests.

use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use super::{BIN, PASSPHRASE};

struct SshRig {
    dir: tempfile::TempDir,
    approve: &'static str,
    known_hosts: Option<PathBuf>,
}

impl SshRig {
    fn new(approve: &'static str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("d")
            .tempdir_in("/tmp")
            .or_else(|_| tempfile::Builder::new().prefix("d").tempdir())
            .unwrap();
        Self {
            dir,
            approve,
            known_hosts: None,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env("HOME", self.path("u"))
            .env("DEADBOLT_HOME", self.path("h"))
            .env("XDG_RUNTIME_DIR", self.path("r"))
            .env("XDG_STATE_HOME", self.path("s"))
            .env("XDG_CONFIG_HOME", self.path("c"))
            .env("DEADBOLT_NET", "local")
            .env("DEADBOLT_KDF", "fast")
            .env("DEADBOLT_PASSPHRASE", PASSPHRASE)
            .env("DEADBOLT_TEST_SSH_APPROVE", self.approve)
            .env_remove("SSH_CONNECTION")
            .env_remove("SSH_TTY")
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null());
        if let Some(kh) = &self.known_hosts {
            cmd.env("DEADBOLT_KNOWN_HOSTS", kh);
        }
        cmd
    }

    fn try_run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }

    fn run(&self, args: &[&str]) -> String {
        let out = self.try_run(args);
        assert!(
            out.status.success(),
            "deadbolt {args:?} failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn sock(&self) -> PathBuf {
        PathBuf::from(self.run(&["ssh", "sock"]).trim())
    }
}

impl Drop for SshRig {
    fn drop(&mut self) {
        drop(self.cmd(&["agent", "stop"]).output());
    }
}

#[test]
fn ssh_agent_lists_signs_with_openssh_and_signs_git_commits_and_binary_blobs() {
    let rig = SshRig::new("allow");
    fs::create_dir_all(rig.path("u")).unwrap();
    rig.run(&["init", "personal", "--device-name", "laptop"]);

    // 1. `deadbolt ssh new`, `deadbolt new ssh`, and `deadbolt ssh import` (RSA-2048).
    let gh_out = rig.run(&["ssh", "new", "GitHub", "--comment", "alice@github"]);
    let (gh_short, gh_pub) = gh_out.trim().split_once('\t').unwrap();
    assert!(!gh_short.is_empty());
    assert!(gh_pub.starts_with("ssh-ed25519 ") && gh_pub.ends_with(" alice@github"));

    // Default `get` returns `public-key` (never the private key), and `run` refuses `private-key`.
    assert_eq!(rig.run(&["get", "GitHub"]).trim(), gh_pub);
    let refused_run = rig.try_run(&[
        "run",
        "--env",
        "K=deadbolt://personal/GitHub/private-key",
        "--",
        "true",
    ]);
    assert!(
        !refused_run.status.success(),
        "run must refuse SSH private-key"
    );

    let rsa_file = rig.path("imported_rsa");
    assert!(
        Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                "rsa",
                "-b",
                "2048",
                "-N",
                "",
                "-C",
                "legacy@rsa"
            ])
            .arg("-f")
            .arg(&rsa_file)
            .status()
            .unwrap()
            .success()
    );
    let rsa_out = rig.run(&[
        "ssh",
        "import",
        rsa_file.to_str().unwrap(),
        "--name",
        "Legacy RSA",
    ]);
    let (_, rsa_pub) = rsa_out.trim().split_once('\t').unwrap();
    assert!(rsa_pub.starts_with("ssh-rsa "));

    // 2. Enable SSH agent (`ssh.sock`) and verify `ssh-add -L`, `ssh-add -D`, `ssh-keygen -Y sign`.
    rig.run(&["ssh", "on"]);
    assert!(rig.run(&["ssh", "status"]).contains("enabled"));
    let sock = rig.sock();
    assert!(sock.exists());

    let listed = Command::new("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .unwrap();
    assert!(listed.status.success());
    let listed_str = String::from_utf8(listed.stdout).unwrap();
    assert!(listed_str.contains("alice@github"), "{listed_str}");
    assert!(listed_str.contains("legacy@rsa"), "{listed_str}");

    // `ssh-add -D` and `ssh-add <file>` are refused (`SSH_AGENT_FAILURE`).
    assert!(
        !Command::new("ssh-add")
            .arg("-D")
            .env("SSH_AUTH_SOCK", &sock)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        !Command::new("ssh-add")
            .arg(&rsa_file)
            .env("SSH_AUTH_SOCK", &sock)
            .status()
            .unwrap()
            .success()
    );

    // Sign over `ssh.sock` with real `ssh-keygen -Y sign` (both Ed25519 and RSA-2048!).
    let allowed = rig.path("allowed_signers");
    fs::write(
        &allowed,
        format!(
            "alice@example.com namespaces=\"file,git\" {gh_pub}\nalice@example.com namespaces=\"file,git\" {rsa_pub}\n"
        ),
    )
    .unwrap();
    for (i, pub_line) in [gh_pub, rsa_pub].iter().enumerate() {
        let pub_path = rig.path(&format!("k{i}.pub"));
        let msg_path = rig.path(&format!("msg{i}.bin"));
        let binary_payload: Vec<u8> = vec![0x00, 0xff, 0xfe, 0x80, b'h', b'i', i as u8];
        fs::write(&pub_path, format!("{pub_line}\n")).unwrap();
        fs::write(&msg_path, &binary_payload).unwrap();

        let sign_status = Command::new("ssh-keygen")
            .args(["-Y", "sign", "-n", "file", "-U", "-f"])
            .arg(&pub_path)
            .arg(&msg_path)
            .env("SSH_AUTH_SOCK", &sock)
            .status()
            .unwrap();
        assert!(
            sign_status.success(),
            "ssh-keygen -Y sign via ssh.sock #{i}"
        );

        let sig_path = rig.path(&format!("msg{i}.bin.sig"));
        let mut verify = Command::new("ssh-keygen")
            .args([
                "-Y",
                "verify",
                "-f",
                allowed.to_str().unwrap(),
                "-I",
                "alice@example.com",
                "-n",
                "file",
                "-s",
                sig_path.to_str().unwrap(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        verify
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&binary_payload)
            .unwrap();
        assert!(verify.wait_with_output().unwrap().status.success());
    }

    // 3. Direct `deadbolt -Y sign` on non-UTF-8 stdin (`patatt` regression check).
    let gh_pub_file = rig.path("gh.pub");
    fs::write(&gh_pub_file, format!("{gh_pub}\n")).unwrap();
    let non_utf8 = [0xffu8, 0x00, 0xfe, 0x42, 0x99];
    let mut direct = rig.cmd(&[
        "-Y",
        "sign",
        "-n",
        "file",
        "-f",
        gh_pub_file.to_str().unwrap(),
    ]);
    let mut child = direct
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&non_utf8).unwrap();
    let direct_out = child.wait_with_output().unwrap();
    assert!(
        direct_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&direct_out.stderr)
    );
    let direct_sig = rig.path("direct.sig");
    fs::write(&direct_sig, &direct_out.stdout).unwrap();
    let mut verify_direct = Command::new("ssh-keygen")
        .args([
            "-Y",
            "verify",
            "-f",
            allowed.to_str().unwrap(),
            "-I",
            "alice@example.com",
            "-n",
            "file",
            "-s",
            direct_sig.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    verify_direct
        .stdin
        .take()
        .unwrap()
        .write_all(&non_utf8)
        .unwrap();
    assert!(verify_direct.wait().unwrap().success());

    // 4. Real `git commit` and `git tag` signed via `gpg.ssh.program = deadbolt`!
    let repo = rig.path("repo");
    fs::create_dir_all(&repo).unwrap();
    let git = |args: &[&str]| {
        let mut c = Command::new("git");
        c.current_dir(&repo)
            .args(args)
            .env("HOME", rig.path("u"))
            .env("DEADBOLT_HOME", rig.path("h"))
            .env("XDG_RUNTIME_DIR", rig.path("r"))
            .env("XDG_STATE_HOME", rig.path("s"))
            .env("XDG_CONFIG_HOME", rig.path("c"))
            .env("DEADBOLT_NET", "local")
            .env("DEADBOLT_KDF", "fast")
            .env("DEADBOLT_TEST_SSH_APPROVE", "allow")
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_CONNECTION")
            .env_remove("SSH_TTY");
        c.output().unwrap()
    };
    assert!(git(&["init"]).status.success());
    assert!(git(&["config", "user.name", "Alice"]).status.success());
    assert!(
        git(&["config", "user.email", "alice@example.com"])
            .status
            .success()
    );

    let mut cfg_cmd = rig.cmd(&[
        "ssh",
        "git-config",
        "GitHub",
        "--write",
        "--allowed-signers",
        rig.path("repo_signers").to_str().unwrap(),
    ]);
    cfg_cmd.current_dir(&repo);
    assert!(cfg_cmd.output().unwrap().status.success());

    fs::write(repo.join("hello.txt"), "signed by deadbolt\n").unwrap();
    assert!(git(&["add", "hello.txt"]).status.success());
    let committed = git(&["commit", "-m", "feat: signed commit"]);
    assert!(
        committed.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&committed.stderr)
    );
    let verified_commit = git(&["verify-commit", "HEAD"]);
    assert!(
        verified_commit.status.success(),
        "git verify-commit failed: {}\n{}",
        String::from_utf8_lossy(&verified_commit.stdout),
        String::from_utf8_lossy(&verified_commit.stderr)
    );
    let tagged = git(&["tag", "-m", "release v1", "v1.0.0"]);
    assert!(tagged.status.success());
    assert!(git(&["verify-tag", "v1.0.0"]).status.success());

    // Activity records `ssh-sign` entries without leaking private keys.
    let activity = rig.run(&["activity", "--json"]);
    assert!(activity.contains("\"ssh-sign\""), "{activity}");
    assert!(!activity.contains("OPENSSH PRIVATE KEY"), "{activity}");

    // Locking without Touch ID makes `ssh-add -L` empty and `git commit` fail cleanly.
    rig.run(&["lock"]);
    let locked_list = Command::new("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .unwrap();
    assert!(!locked_list.status.success());
    let locked_commit = git(&["commit", "--allow-empty", "-m", "while locked"]);
    assert!(!locked_commit.status.success());
}

#[test]
fn real_ssh_authenticates_against_local_sshd_past_six_key_limit() {
    let sshd_bin = ["/usr/sbin/sshd", "/sbin/sshd"]
        .into_iter()
        .map(Path::new)
        .find(|p| p.is_file());
    let Some(sshd_bin) = sshd_bin else {
        eprintln!("skipping local sshd test: sshd binary not found");
        return;
    };

    let mut rig = SshRig::new("allow");
    fs::create_dir_all(rig.path("u")).unwrap();
    let kh_path = rig.path("known_hosts");
    rig.known_hosts = Some(kh_path.clone());

    // Prepare host key and unprivileged sshd on an ephemeral localhost port.
    let host_key = rig.path("ssh_host_ed25519_key");
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", ""])
            .arg("-f")
            .arg(&host_key)
            .status()
            .unwrap()
            .success()
    );
    let host_pub = fs::read_to_string(host_key.with_extension("pub")).unwrap();

    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    fs::write(
        &kh_path,
        format!("[127.0.0.1]:{port} {}\n", host_pub.trim()),
    )
    .unwrap();

    // Start Deadbolt with 7 SSH keys in the vault; only Key 7 is in `authorized_keys`,
    // and `ssh.toml` scopes keys 1..=6 to `other.example.com` so Key 7 is offered first!
    rig.run(&["init", "personal", "--device-name", "laptop"]);
    let mut ssh_toml = String::new();
    for i in 1..=6 {
        rig.run(&["ssh", "new", &format!("Decoy {i}")]);
        ssh_toml.push_str(&format!(
            "[[ssh-keys]]\nitem = \"Decoy {i}\"\nhosts = [\"other.example.com\"]\n\n"
        ));
    }
    let target_out = rig.run(&["ssh", "new", "Target Key"]);
    let (_, target_pub) = target_out.trim().split_once('\t').unwrap();
    ssh_toml.push_str("[[ssh-keys]]\nitem = \"Target Key\"\nhosts = [\"127.0.0.1\"]\n");

    let cfg_dir = rig.path("c").join("deadbolt");
    fs::create_dir_all(&cfg_dir).unwrap();
    fs::write(cfg_dir.join("ssh.toml"), ssh_toml).unwrap();

    rig.run(&["ssh", "on"]);
    let sock = rig.sock();

    let auth_keys = rig.path("authorized_keys");
    fs::write(&auth_keys, format!("{target_pub}\n")).unwrap();

    let user = Command::new("id")
        .arg("-un")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|| "root".into());

    let pid_file = rig.path("sshd.pid");
    let sshd_cfg = rig.path("sshd_config");
    fs::write(
        &sshd_cfg,
        format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {}\n\
             AuthorizedKeysFile {}\n\
             PidFile {}\n\
             UsePAM no\n\
             StrictModes no\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             PubkeyAuthentication yes\n\
             MaxAuthTries 6\n\
             LogLevel ERROR\n\
             Subsystem sftp internal-sftp\n",
            host_key.display(),
            auth_keys.display(),
            pid_file.display()
        ),
    )
    .unwrap();

    let sshd = match Command::new(sshd_bin)
        .args(["-D", "-f"])
        .arg(&sshd_cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            eprintln!("skipping sshd test (could not spawn sshd: {err})");
            return;
        }
    };

    struct KillChild(std::process::Child);
    impl Drop for KillChild {
        fn drop(&mut self) {
            drop(self.0.kill());
            drop(self.0.wait());
        }
    }
    let mut sshd_guard = KillChild(sshd);

    // Wait until sshd binds the port (or exits early on restricted sandboxes).
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if let Ok(Some(status)) = sshd_guard.0.try_wait() {
            eprintln!("skipping sshd test (unprivileged sshd exited {status})");
            return;
        }
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    let ssh_out = Command::new("ssh")
        .args([
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=no",
            "-o",
            &format!("IdentityAgent={}", sock.display()),
            "-o",
            &format!("UserKnownHostsFile={}", kh_path.display()),
            "-o",
            "StrictHostKeyChecking=yes",
            "-p",
            &port.to_string(),
            &format!("{user}@127.0.0.1"),
            "echo",
            "deadbolt-ssh-ok",
        ])
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .unwrap();
    assert!(
        ssh_out.status.success(),
        "ssh against local sshd failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&ssh_out.stdout),
        String::from_utf8_lossy(&ssh_out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&ssh_out.stdout).trim(),
        "deadbolt-ssh-ok"
    );
}
