//! `deadbolt remote`, `recover`, `recovery rotate` and `status`: a
//! vault's blind store, rebuilding a vault from its kit, handing the kit on,
//! and why a vault is parked.
//!
//! Credentials never come from flags (shell history, `ps`): S3 keys from
//! `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` (`AWS_SESSION_TOKEN`), a
//! WebDAV password from `DEADBOLT_WEBDAV_PASSWORD`, or either from stdin
//! with `--credentials-stdin`. Recovery words come from a hidden prompt or
//! the first line of stdin with `--words-stdin`.

use std::io::BufRead;

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use deadbolt_proto::daemon::{RemoteInfo, RemoteInput, RemoteReport, VaultState};
use zeroize::Zeroizing;

use crate::paths::Paths;
use crate::protocol::{Command, Reply, Secret};
use crate::{client, config, prompt, request};

#[derive(Subcommand)]
pub enum RemoteCommand {
    /// Set the vault's remote.
    #[command(subcommand)]
    Set(SetCommand),
    /// Show the vault's remote (credentials redacted).
    Show {
        #[arg(long)]
        json: bool,
    },
    /// Pull from and push to the remote now, then collect behind its
    /// checkpoints.
    Sync {
        #[arg(long)]
        json: bool,
    },
    /// Forget the vault's remote and its credentials.
    Remove,
}

#[derive(Subcommand)]
pub enum SetCommand {
    /// S3, R2 or MinIO. Keys from AWS_ACCESS_KEY_ID and
    /// AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN), or two lines of stdin.
    S3(S3Args),
    /// A WebDAV collection. The password from DEADBOLT_WEBDAV_PASSWORD, or
    /// stdin; none for an open collection.
    Webdav(WebdavArgs),
}

#[derive(Args)]
pub struct S3Args {
    /// https://<account>.r2.cloudflarestorage.com, https://s3.<region>.amazonaws.com
    #[arg(long)]
    endpoint: String,
    #[arg(long)]
    bucket: String,
    /// `auto` for R2.
    #[arg(long, default_value = "auto")]
    region: String,
    /// A folder in the bucket, ending in `/`.
    #[arg(long, default_value = "")]
    prefix: String,
    /// <endpoint>/<bucket>/<key>, as R2 and MinIO want.
    #[arg(long)]
    path_style: bool,
    /// Read the access key id and secret from the first two lines of stdin.
    #[arg(long)]
    credentials_stdin: bool,
}

#[derive(Args)]
pub struct WebdavArgs {
    /// The collection URL, ending in `/`.
    #[arg(long)]
    url: String,
    #[arg(long)]
    username: Option<String>,
    /// Read the password from the first line of stdin.
    #[arg(long)]
    credentials_stdin: bool,
}

/// `deadbolt recover`.
#[derive(Args)]
pub struct RecoverArgs {
    /// The vault id the recovery kit shows.
    vault_id: String,
    /// Read the 24 words from the first line of stdin.
    #[arg(long)]
    words_stdin: bool,
    #[command(subcommand)]
    remote: SetCommand,
}

#[derive(Subcommand)]
pub enum RecoveryCommand {
    /// Hand the vault's recovery root to a new kit, given the current
    /// words, and print the new words once. The old kit stops working.
    Rotate {
        /// Read the current 24 words from the first line of stdin.
        #[arg(long)]
        words_stdin: bool,
        #[arg(long)]
        json: bool,
    },
}

fn env_secret(names: &[&str]) -> Option<Secret> {
    names
        .iter()
        .find_map(|name| config::env(name).ok())
        .map(Secret::new)
}

fn stdin_lines(n: usize) -> Result<Vec<Zeroizing<String>>> {
    let stdin = std::io::stdin();
    let mut lines = Vec::with_capacity(n);
    for _ in 0..n {
        let mut line = Zeroizing::new(String::new());
        stdin.lock().read_line(&mut line).context("reading stdin")?;
        lines.push(Zeroizing::new(
            line.trim_end_matches(['\r', '\n']).to_owned(),
        ));
    }
    Ok(lines)
}

fn input(command: SetCommand) -> Result<RemoteInput> {
    Ok(match command {
        SetCommand::S3(a) => {
            let (id, secret) = if a.credentials_stdin {
                let lines = stdin_lines(2)?;
                (
                    Secret::new(lines[0].as_str()),
                    Secret::new(lines[1].as_str()),
                )
            } else {
                (
                    env_secret(&["AWS_ACCESS_KEY_ID"])
                        .context("set AWS_ACCESS_KEY_ID, or pass --credentials-stdin")?,
                    env_secret(&["AWS_SECRET_ACCESS_KEY"])
                        .context("set AWS_SECRET_ACCESS_KEY, or pass --credentials-stdin")?,
                )
            };
            RemoteInput::S3 {
                endpoint: a.endpoint,
                bucket: a.bucket,
                region: a.region,
                prefix: a.prefix,
                path_style: a.path_style,
                access_key_id: id,
                secret_access_key: secret,
                session_token: env_secret(&["AWS_SESSION_TOKEN"]),
            }
        }
        SetCommand::Webdav(a) => {
            let password = if a.credentials_stdin {
                Some(Secret::new(stdin_lines(1)?[0].as_str()))
            } else {
                env_secret(&["DEADBOLT_WEBDAV_PASSWORD"])
            };
            RemoteInput::Webdav {
                url: a.url,
                username: a.username,
                password,
            }
        }
    })
}

fn words(from_stdin: bool, label: &str) -> Result<Secret> {
    let text = if from_stdin {
        stdin_lines(1)?.remove(0)
    } else if prompt::interactive() {
        prompt::ask_value(label, true)?
    } else {
        bail!("no terminal to ask for the words: pass --words-stdin");
    };
    let words = text.split_whitespace().collect::<Vec<_>>().join(" ");
    Ok(Secret::new(words))
}

fn show_remote(remote: Option<&RemoteInfo>) {
    let Some(r) = remote else {
        println!("no remote");
        return;
    };
    let mut line = format!("{}\t{}", r.kind, r.url);
    if let Some(bucket) = &r.bucket {
        line.push_str(&format!("\tbucket {bucket}"));
    }
    if !r.prefix.is_empty() {
        line.push_str(&format!("\tprefix {}", r.prefix));
    }
    if let Some(user) = &r.username {
        line.push_str(&format!("\tuser {user}"));
    }
    line.push_str(if r.credentials {
        "\tcredentials set"
    } else {
        "\tno credentials"
    });
    println!("{line}");
}

fn show_report(report: &RemoteReport) {
    println!(
        "pulled {} frames, pushed {} objects, {} proofs, {} checkpoints, collected {}",
        report.pulled, report.pushed, report.proofs, report.checkpoints, report.collected
    );
    for line in &report.anomalies {
        eprintln!("warning: {line}");
    }
}

pub async fn remote(
    paths: &Paths,
    vault: Option<String>,
    command: RemoteCommand,
    from_stdin: bool,
) -> Result<()> {
    client::ensure_running(paths).await?;
    match command {
        RemoteCommand::Set(set) => {
            let command = Command::RemoteSet {
                vault,
                remote: input(set)?,
            };
            let Reply::Remote { remote } = request(paths, command, from_stdin).await? else {
                bail!("unexpected reply");
            };
            show_remote(remote.as_ref());
        }
        RemoteCommand::Show { json } => {
            let Reply::Remote { remote } =
                request(paths, Command::RemoteShow { vault }, from_stdin).await?
            else {
                bail!("unexpected reply");
            };
            if json {
                println!("{}", serde_json::to_string(&remote)?);
            } else {
                show_remote(remote.as_ref());
            }
        }
        RemoteCommand::Sync { json } => {
            let Reply::RemoteSynced { report } =
                request(paths, Command::RemoteSync { vault }, from_stdin).await?
            else {
                bail!("unexpected reply");
            };
            if json {
                println!("{}", serde_json::to_string(&report)?);
            } else {
                show_report(&report);
            }
        }
        RemoteCommand::Remove => {
            request(paths, Command::RemoteRemove { vault }, from_stdin).await?;
            println!("removed the remote");
        }
    }
    Ok(())
}

impl SetCommand {
    /// Whether the credentials come from stdin.
    fn reads_stdin(&self) -> bool {
        match self {
            Self::S3(a) => a.credentials_stdin,
            Self::Webdav(a) => a.credentials_stdin,
        }
    }
}

impl RecoverArgs {
    /// Refuses two things on one stdin: clap can't see the store's
    /// `--credentials-stdin`, which belongs to the subcommand.
    fn check(&self) -> Result<()> {
        if self.words_stdin && self.remote.reads_stdin() {
            bail!(
                "--words-stdin and --credentials-stdin both read stdin: pass the credentials in the environment instead"
            );
        }
        Ok(())
    }
}

pub async fn recover(paths: &Paths, args: RecoverArgs, from_stdin: bool) -> Result<()> {
    args.check()?;
    let remote = input(args.remote)?;
    let words = words(args.words_stdin, "Recovery kit (24 words)")?;
    client::ensure_running(paths).await?;
    let command = Command::Recover {
        vault: args.vault_id,
        words,
        remote,
    };
    let Reply::Vault { vault } = request(paths, command, from_stdin).await? else {
        bail!("unexpected reply");
    };
    println!("recovered {} ({})", vault.name, vault.id);
    eprintln!("Every other device was removed. Rotate the recovery kit: deadbolt recovery rotate");
    Ok(())
}

pub async fn recovery(
    paths: &Paths,
    vault: Option<String>,
    command: RecoveryCommand,
    from_stdin: bool,
) -> Result<()> {
    let RecoveryCommand::Rotate { words_stdin, json } = command;
    let words = words(words_stdin, "Current recovery kit (24 words)")?;
    client::ensure_running(paths).await?;
    let Reply::RecoveryRotated {
        vault,
        recovery_kit,
    } = request(paths, Command::RecoveryRotate { vault, words }, from_stdin).await?
    else {
        bail!("unexpected reply");
    };
    if json {
        let kit = crate::recovery::kit_json(
            &vault.id,
            &vault.name,
            vault.default,
            recovery_kit.expose(),
        )?;
        println!("{}", kit.as_str());
    } else {
        print!(
            "{}",
            crate::recovery::kit_text(&vault.id, recovery_kit.expose()).as_str()
        );
        eprintln!("The old kit no longer opens {}.", vault.name);
    }
    Ok(())
}

fn state_line(state: &VaultState) -> String {
    let mut line = format!(
        "{}\t{}",
        state.vault.name,
        &state.vault.id[..8.min(state.vault.id.len())]
    );
    if state.parked.is_empty() {
        line.push_str("\tok");
    } else {
        line.push_str("\tparked");
    }
    if state.sealed > 0 {
        line.push_str(&format!("\t{} frames waiting for a key", state.sealed));
    }
    if let Some(generation) = state.generation {
        line.push_str(&format!("\tpack gen {generation}"));
    }
    if let Some(remote) = &state.remote {
        line.push_str(&format!("\tremote {}", remote.kind));
    }
    line
}

pub async fn status(
    paths: &Paths,
    vault: Option<String>,
    json: bool,
    from_stdin: bool,
) -> Result<()> {
    let status = client::ensure_running(paths).await?;
    let states = if status.unlocked {
        let Reply::VaultStates { vaults } =
            request(paths, Command::VaultStatus { vault }, from_stdin).await?
        else {
            bail!("unexpected reply");
        };
        vaults
    } else {
        Vec::new()
    };
    if json {
        println!(
            "{}",
            serde_json::json!({ "status": status, "vaults": states })
        );
        return Ok(());
    }
    println!(
        "{}",
        if status.unlocked {
            "unlocked"
        } else {
            "locked"
        }
    );
    for state in &states {
        println!("{}", state_line(state));
        for reason in &state.parked {
            println!("  parked: {}", reason.message);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::RecoverArgs;

    #[derive(Parser)]
    struct Recover {
        #[command(flatten)]
        args: RecoverArgs,
    }

    fn parse(argv: &[&str]) -> RecoverArgs {
        Recover::try_parse_from(["recover"].iter().chain(argv))
            .unwrap()
            .args
    }

    #[test]
    fn the_words_and_the_credentials_never_share_stdin() {
        let both = parse(&[
            "abcd",
            "--words-stdin",
            "webdav",
            "--url",
            "https://dav/",
            "--credentials-stdin",
        ]);
        let error = both.check().unwrap_err().to_string();
        assert!(
            error.contains("--words-stdin and --credentials-stdin"),
            "{error}"
        );
        let s3 = parse(&[
            "abcd",
            "--words-stdin",
            "s3",
            "--endpoint",
            "https://s3",
            "--bucket",
            "b",
            "--credentials-stdin",
        ]);
        assert!(s3.check().is_err());
        assert!(
            parse(&["abcd", "--words-stdin", "webdav", "--url", "https://dav/"])
                .check()
                .is_ok()
        );
        assert!(
            parse(&[
                "abcd",
                "webdav",
                "--url",
                "https://dav/",
                "--credentials-stdin"
            ])
            .check()
            .is_ok()
        );
    }
}
