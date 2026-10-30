//! `deadbolt ssh` CLI commands and `deadbolt ssh-sign` (`gpg.ssh.program` for
//! Git commit and tag signing, `docs/ssh-agent.md`).

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command as Process, ExitCode, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand, ValueEnum};
use data_encoding::BASE64;
use zeroize::Zeroizing;

use crate::paths::Paths;
use crate::protocol::{Command, FieldInput, Reply, Secret, SshKeyKind};
use crate::{client, config, prompt};

#[derive(Args)]
pub struct SshArgs {
    #[command(subcommand)]
    pub command: Option<SshCommand>,
}

#[derive(Subcommand)]
pub enum SshCommand {
    /// Turn the SSH agent socket on (`ssh.sock`) and print the `~/.ssh/config`
    /// snippet.
    On,
    /// Turn the SSH agent socket off.
    Off,
    /// Show whether the SSH agent is enabled and where its socket lives.
    Status,
    /// Print the SSH agent socket path.
    Sock,
    /// Print `export SSH_AUTH_SOCK=…` for `eval "$(deadbolt ssh env)"`.
    Env,
    /// Generate a new SSH key in Deadbolt and print its short id and public key.
    New {
        /// Optional item title (default: derived from `--comment` or "SSH key").
        name: Option<String>,
        /// Key algorithm (`ed25519` or `p256`).
        #[arg(long = "type", value_enum, default_value_t = KeyTypeArg::Ed25519)]
        kind: KeyTypeArg,
        /// Optional public-key comment (e.g. `alice@laptop`).
        #[arg(short, long)]
        comment: Option<String>,
    },
    /// Import an existing SSH private key file (`~/.ssh/id_ed25519`, RSA, ECDSA)
    /// into Deadbolt.
    Import {
        /// Private key file path (`-` for stdin).
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Optional item title.
        #[arg(long)]
        name: Option<String>,
        /// Optional comment override.
        #[arg(short, long)]
        comment: Option<String>,
    },
    /// Print (or `--write` into Git config and `~/.ssh/allowed_signers`) the
    /// settings to sign Git commits and tags with an SSH key in Deadbolt.
    GitConfig {
        /// Words or short id matching one `ssh` item.
        #[arg(required = true, value_name = "QUERY")]
        query: Vec<String>,
        /// Configure `--global` Git config instead of the current repository.
        #[arg(long)]
        global: bool,
        /// Apply the `git config` settings and update `allowed_signers`.
        #[arg(long)]
        write: bool,
        /// Path to the `allowed_signers` file (default: `~/.ssh/allowed_signers`).
        #[arg(long, value_name = "FILE")]
        allowed_signers: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum KeyTypeArg {
    Ed25519,
    #[value(alias = "ecdsa-p256")]
    P256,
}

impl From<KeyTypeArg> for SshKeyKind {
    fn from(v: KeyTypeArg) -> Self {
        match v {
            KeyTypeArg::Ed25519 => SshKeyKind::Ed25519,
            KeyTypeArg::P256 => SshKeyKind::EcdsaP256,
        }
    }
}

pub fn ssh_config_snippet(sock: &Path) -> String {
    let display = match config::env("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .and_then(|h| sock.strip_prefix(Path::new(&h)).ok())
    {
        Some(rel) => format!("~/{}", rel.display()),
        None => sock.display().to_string(),
    };
    let quoted = if display.contains(' ') {
        format!("\"{display}\"")
    } else {
        display
    };
    format!("Match host * exec \"test -z $SSH_CONNECTION\"\n    IdentityAgent {quoted}")
}

pub async fn run(
    paths: &Paths,
    args: SshArgs,
    vault: Option<String>,
    from_stdin: bool,
) -> Result<()> {
    let sub = args.command.unwrap_or(SshCommand::Status);
    if vault.is_some()
        && matches!(
            sub,
            SshCommand::On
                | SshCommand::Off
                | SshCommand::Status
                | SshCommand::Sock
                | SshCommand::Env
        )
    {
        bail!("--vault does not apply to this command");
    }
    match sub {
        SshCommand::Sock => {
            println!("{}", paths.ssh_client_socket().display());
        }
        SshCommand::Env => {
            let sock = paths.ssh_client_socket();
            let escaped = sock.display().to_string().replace('\'', "'\\''");
            println!("export SSH_AUTH_SOCK='{escaped}'");
        }
        SshCommand::On => {
            client::ensure_running(paths).await?;
            client::simple(paths, Command::SshAgentSet { enabled: true }).await?;
            let sock = paths.ssh_client_socket();
            println!("SSH agent enabled at {}\n", sock.display());
            println!("Add to ~/.ssh/config:\n\n{}", ssh_config_snippet(&sock));
        }
        SshCommand::Off => {
            client::ensure_running(paths).await?;
            client::simple(paths, Command::SshAgentSet { enabled: false }).await?;
            println!("SSH agent disabled");
        }
        SshCommand::Status => {
            let st = client::ensure_running(paths).await?;
            if st.ssh_agent {
                let sock = st
                    .ssh_socket
                    .unwrap_or_else(|| paths.ssh_client_socket().display().to_string());
                println!("ssh\tenabled\t{sock}");
            } else {
                println!("ssh\tdisabled");
            }
        }
        SshCommand::New {
            name,
            kind,
            comment,
        } => {
            client::ensure_running(paths).await?;
            let Reply::SshGenerated {
                private_key,
                public_key,
                fingerprint,
                comment: derived_comment,
            } = crate::request(
                paths,
                Command::SshGenerate {
                    kind: kind.into(),
                    comment,
                },
                from_stdin,
            )
            .await?
            else {
                bail!("unexpected reply");
            };
            let mut fields = vec![
                FieldInput {
                    name: "private-key".into(),
                    kind: None,
                    value: private_key.expose().to_owned(),
                },
                FieldInput {
                    name: "public-key".into(),
                    kind: None,
                    value: public_key.clone(),
                },
                FieldInput {
                    name: "fingerprint".into(),
                    kind: None,
                    value: fingerprint,
                },
            ];
            if let Some(c) = derived_comment {
                fields.push(FieldInput {
                    name: "comment".into(),
                    kind: None,
                    value: c,
                });
            }
            let Reply::Item { item } = crate::request(
                paths,
                Command::ItemNew {
                    vault,
                    kind: "ssh".into(),
                    name,
                    fields,
                    favorite: false,
                    tags: Vec::new(),
                },
                from_stdin,
            )
            .await?
            else {
                bail!("unexpected reply");
            };
            println!("{}\t{public_key}", item.short);
        }
        SshCommand::Import {
            file,
            name,
            comment,
        } => {
            let raw = if file.as_os_str() == "-" {
                if from_stdin {
                    bail!("--passphrase-stdin cannot be used when the key comes from stdin");
                }
                let mut text = Zeroizing::new(String::new());
                std::io::stdin()
                    .lock()
                    .read_to_string(&mut text)
                    .context("reading private key from stdin")?;
                text
            } else {
                Zeroizing::new(
                    fs::read_to_string(&file)
                        .with_context(|| format!("reading {}", file.display()))?,
                )
            };
            client::ensure_running(paths).await?;
            let secret = Secret::new(raw.as_str());
            let inspected = crate::request(
                paths,
                Command::SshInspect {
                    private_key: secret.clone(),
                    passphrase: None,
                    comment: comment.clone(),
                },
                from_stdin,
            )
            .await;
            let generated = match inspected {
                Ok(reply) => reply,
                Err(err) if err.to_string().contains("encrypted") && prompt::interactive() => {
                    let pass = prompt::ask_value("SSH key file passphrase", true)?;
                    crate::request(
                        paths,
                        Command::SshInspect {
                            private_key: secret,
                            passphrase: Some(Secret::new(pass.as_str())),
                            comment,
                        },
                        from_stdin,
                    )
                    .await?
                }
                Err(err) => return Err(err),
            };
            let Reply::SshGenerated {
                private_key,
                public_key,
                fingerprint,
                comment: derived_comment,
            } = generated
            else {
                bail!("unexpected reply");
            };
            let derived_name = name.or_else(|| {
                (file.as_os_str() != "-")
                    .then(|| file.file_stem().map(|s| s.to_string_lossy().into_owned()))
                    .flatten()
            });
            let mut fields = vec![
                FieldInput {
                    name: "private-key".into(),
                    kind: None,
                    value: private_key.expose().to_owned(),
                },
                FieldInput {
                    name: "public-key".into(),
                    kind: None,
                    value: public_key.clone(),
                },
                FieldInput {
                    name: "fingerprint".into(),
                    kind: None,
                    value: fingerprint,
                },
            ];
            if let Some(c) = derived_comment {
                fields.push(FieldInput {
                    name: "comment".into(),
                    kind: None,
                    value: c,
                });
            }
            let Reply::Item { item } = crate::request(
                paths,
                Command::ItemNew {
                    vault,
                    kind: "ssh".into(),
                    name: derived_name,
                    fields,
                    favorite: false,
                    tags: Vec::new(),
                },
                from_stdin,
            )
            .await?
            else {
                bail!("unexpected reply");
            };
            println!("{}\t{public_key}", item.short);
        }
        SshCommand::GitConfig {
            query,
            global,
            write,
            allowed_signers,
        } => {
            client::ensure_running(paths).await?;
            let Reply::Item { item } = crate::request(
                paths,
                Command::ItemGet {
                    vault,
                    query,
                    otp: false,
                    ssh_private: false,
                    files: Vec::new(),
                    deleted: false,
                },
                from_stdin,
            )
            .await?
            else {
                bail!("unexpected reply");
            };
            if item.kind != "ssh" {
                bail!("{} is a {}, not an SSH key", item.label, item.kind);
            }
            let public_key = item
                .fields
                .iter()
                .find(|f| f.name == "public-key")
                .map(|f| f.value.trim().to_owned())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| anyhow!("{} has no public-key field", item.label))?;
            let exe = crate::caller::own_exe().unwrap_or_else(|_| PathBuf::from("deadbolt"));
            let signers_path = allowed_signers
                .or_else(default_allowed_signers)
                .ok_or_else(|| {
                    anyhow!(
                        "could not determine ~/.ssh/allowed_signers; pass --allowed-signers FILE"
                    )
                })?;
            let email = git_user_email().unwrap_or_else(|| "you@example.com".into());

            if write {
                write_allowed_signer(&signers_path, &email, &public_key)?;
                let exe_str = exe.display().to_string();
                let signers_str = signers_path.display().to_string();
                for (k, v) in [
                    ("gpg.format", "ssh"),
                    ("gpg.ssh.program", exe_str.as_str()),
                    ("gpg.ssh.allowedSignersFile", signers_str.as_str()),
                    ("user.signingkey", public_key.as_str()),
                    ("commit.gpgsign", "true"),
                    ("tag.gpgsign", "true"),
                ] {
                    set_git_config(global, k, v)?;
                }
                println!(
                    "configured {} Git commit signing with {} ({})",
                    if global { "global" } else { "repository" },
                    item.label,
                    signers_path.display()
                );
            } else {
                println!(
                    "[gpg]\n\tformat = ssh\n[gpg \"ssh\"]\n\tprogram = {}\n\tallowedSignersFile = {}\n[user]\n\tsigningkey = {public_key}\n[commit]\n\tgpgsign = true\n[tag]\n\tgpgsign = true\n\n# Add to {}:\n# {email} namespaces=\"git\" {public_key}",
                    exe.display(),
                    signers_path.display(),
                    signers_path.display()
                );
            }
        }
    }
    Ok(())
}

/// Implements `gpg.ssh.program` (`ssh-keygen -Y sign|find-principals|verify|check-novalidate`).
pub async fn ssh_sign(
    paths: &Paths,
    raw_args: Vec<OsString>,
    from_stdin: bool,
) -> Result<ExitCode> {
    let parsed = parse_keygen_args(&raw_args)?;
    match parsed.op.as_str() {
        "sign" => run_sign(paths, &raw_args, &parsed, from_stdin).await,
        "find-principals" | "verify" | "check-novalidate" => delegate_ssh_keygen(&raw_args, None),
        other => bail!("unsupported ssh-keygen -Y operation {other:?}"),
    }
}

struct KeygenSignArgs {
    op: String,
    namespace: Option<String>,
    key_file: Option<PathBuf>,
    files: Vec<PathBuf>,
}

fn parse_keygen_args(raw: &[OsString]) -> Result<KeygenSignArgs> {
    let mut op = None;
    let mut namespace = None;
    let mut key_file = None;
    let mut files = Vec::new();
    let mut i = 0usize;
    let mut positional_only = false;

    while i < raw.len() {
        let arg = raw[i]
            .to_str()
            .ok_or_else(|| anyhow!("non-UTF-8 argument to ssh-sign"))?;
        if positional_only {
            files.push(PathBuf::from(&raw[i]));
            i += 1;
            continue;
        }
        if arg == "--" {
            positional_only = true;
            i += 1;
            continue;
        }
        if let Some(rest) = arg.strip_prefix("-Y") {
            if rest.is_empty() {
                i += 1;
                let val = raw
                    .get(i)
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| anyhow!("-Y requires an operation"))?;
                op = Some(val.to_owned());
            } else {
                op = Some(rest.to_owned());
            }
            i += 1;
            continue;
        }
        if let Some(rest) = arg.strip_prefix("-n") {
            if rest.is_empty() {
                i += 1;
                let val = raw
                    .get(i)
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| anyhow!("-n requires a namespace"))?;
                namespace = Some(val.to_owned());
            } else {
                namespace = Some(rest.to_owned());
            }
            i += 1;
            continue;
        }
        if let Some(rest) = arg.strip_prefix("-f") {
            if rest.is_empty() {
                i += 1;
                let val = raw
                    .get(i)
                    .ok_or_else(|| anyhow!("-f requires a key or signers file"))?;
                key_file = Some(PathBuf::from(val));
            } else {
                key_file = Some(PathBuf::from(rest));
            }
            i += 1;
            continue;
        }
        // Flags that take a following argument when not attached (`-s`, `-I`, `-r`, `-O`).
        if matches!(arg, "-s" | "-I" | "-r" | "-O") {
            i += 2;
            continue;
        }
        if arg.starts_with("-s")
            || arg.starts_with("-I")
            || arg.starts_with("-r")
            || arg.starts_with("-O")
            || matches!(arg, "-U" | "-q")
        {
            i += 1;
            continue;
        }
        if arg.starts_with('-') && arg != "-" {
            bail!("unsupported ssh-sign flag {arg}");
        }
        files.push(PathBuf::from(&raw[i]));
        i += 1;
    }

    let op = op.ok_or_else(|| anyhow!("missing -Y <operation>"))?;
    Ok(KeygenSignArgs {
        op,
        namespace,
        key_file,
        files,
    })
}

async fn run_sign(
    paths: &Paths,
    raw_args: &[OsString],
    parsed: &KeygenSignArgs,
    from_stdin: bool,
) -> Result<ExitCode> {
    // When running inside a remote SSH session (`SSH_CONNECTION` or `SSH_TTY`)
    // with a forwarded `SSH_AUTH_SOCK`, delegate to `ssh-keygen -U` over the
    // forwarded socket so Touch ID prompts on the user's local machine.
    let in_remote_ssh = config::env("SSH_CONNECTION").is_ok_and(|v| !v.is_empty())
        || config::env("SSH_TTY").is_ok_and(|v| !v.is_empty());
    if in_remote_ssh
        && let Ok(sock) = config::env("SSH_AUTH_SOCK")
        && !sock.is_empty()
        && Path::new(&sock) != paths.ssh_socket()
        && Path::new(&sock) != paths.ssh_client_socket()
    {
        let mut forwarded_args = Vec::with_capacity(raw_args.len() + 1);
        if !raw_args.iter().any(|a| a == "-U") {
            forwarded_args.push(OsString::from("-U"));
        }
        forwarded_args.extend_from_slice(raw_args);
        return delegate_ssh_keygen(&forwarded_args, Some(&sock));
    }

    let namespace = parsed
        .namespace
        .as_deref()
        .ok_or_else(|| anyhow!("-Y sign requires -n <namespace>"))?;
    let key_file = parsed
        .key_file
        .as_deref()
        .ok_or_else(|| anyhow!("-Y sign requires -f <public_key_file>"))?;
    let public_key = fs::read_to_string(key_file)
        .with_context(|| format!("reading signing public key {}", key_file.display()))?;

    client::ensure_running(paths).await?;

    if parsed.files.is_empty() || (parsed.files.len() == 1 && parsed.files[0].as_os_str() == "-") {
        let mut payload = Vec::new();
        std::io::stdin()
            .lock()
            .read_to_end(&mut payload)
            .context("reading payload to sign from stdin")?;
        let sig = sign_one(paths, &public_key, namespace, &payload, from_stdin).await?;
        let mut out = std::io::stdout().lock();
        out.write_all(sig.as_bytes())?;
        if !sig.ends_with('\n') {
            out.write_all(b"\n")?;
        }
        out.flush()?;
    } else {
        for file in &parsed.files {
            let payload = fs::read(file).with_context(|| format!("reading {}", file.display()))?;
            let sig = sign_one(paths, &public_key, namespace, &payload, from_stdin).await?;
            let mut sig_name = file.as_os_str().to_os_string();
            sig_name.push(".sig");
            let sig_path = PathBuf::from(sig_name);
            let mut body = sig;
            if !body.ends_with('\n') {
                body.push('\n');
            }
            fs::write(&sig_path, body)
                .with_context(|| format!("writing {}", sig_path.display()))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn sign_one(
    paths: &Paths,
    public_key: &str,
    namespace: &str,
    payload: &[u8],
    from_stdin: bool,
) -> Result<String> {
    let command = Command::SshSign {
        public_key: public_key.trim().to_owned(),
        namespace: namespace.to_owned(),
        data: BASE64.encode(payload),
    };
    let Reply::SshSignature { signature } = crate::request(paths, command, from_stdin).await?
    else {
        bail!("unexpected reply to ssh-sign");
    };
    Ok(signature)
}

fn delegate_ssh_keygen(args: &[OsString], ssh_auth_sock: Option<&str>) -> Result<ExitCode> {
    let bin = find_ssh_keygen()?;
    let mut cmd = Process::new(&bin);
    cmd.args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(sock) = ssh_auth_sock {
        cmd.env("SSH_AUTH_SOCK", sock);
    }
    let status = cmd
        .status()
        .with_context(|| format!("running {}", bin.display()))?;
    Ok(ExitCode::from(
        u8::try_from(status.code().unwrap_or(1)).unwrap_or(1),
    ))
}

fn find_ssh_keygen() -> Result<PathBuf> {
    if let Ok(path_var) = config::env("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("ssh-keygen");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    for fallback in ["/usr/bin/ssh-keygen", "/opt/homebrew/bin/ssh-keygen"] {
        let p = PathBuf::from(fallback);
        if p.is_file() {
            return Ok(p);
        }
    }
    bail!("ssh-keygen not found on PATH or in /usr/bin")
}

fn default_allowed_signers() -> Option<PathBuf> {
    let home = config::env("HOME").ok().filter(|h| !h.is_empty())?;
    Some(PathBuf::from(home).join(".ssh").join("allowed_signers"))
}

fn git_user_email() -> Option<String> {
    let out = Process::new("git")
        .args(["config", "--get", "user.email"])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let trimmed = s.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn set_git_config(global: bool, key: &str, value: &str) -> Result<()> {
    let mut cmd = Process::new("git");
    cmd.arg("config");
    if global {
        cmd.arg("--global");
    }
    let status = cmd
        .args([key, value])
        .stdin(Stdio::null())
        .status()
        .context("running git config")?;
    if !status.success() {
        bail!("git config {key} failed ({status})");
    }
    Ok(())
}

fn write_allowed_signer(path: &Path, email: &str, public_key: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    let line = format!("{email} namespaces=\"git\" {}", public_key.trim());
    let existing = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
    };
    if existing.lines().any(|l| l.trim() == line) {
        return Ok(());
    }
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&line);
    updated.push('\n');
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(updated.as_bytes())?;
    Ok(())
}
