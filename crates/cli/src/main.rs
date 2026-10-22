#[cfg(not(unix))]
compile_error!("deadbolt currently supports Unix platforms only");

mod agent;
mod client;
mod config;
mod import;
mod items;
mod paths;
mod prompt;
mod protocol;

use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use deadbolt_net::{PairingTicket, QrStyle};

use crate::paths::Paths;
use crate::protocol::{Command, DeviceInfo, ErrorCode, Event, Reply, Status, VaultInfo};

#[derive(Parser)]
#[command(
    name = "deadbolt",
    version,
    about = "A decentralized password manager",
    long_about = "A decentralized password manager.\n\nEverything can be driven with \
flags, env and stdin. The passphrase comes from DEADBOLT_PASSPHRASE or \
--passphrase-stdin. Only when stdin and stderr are terminals does deadbolt ask for \
what is missing; otherwise it fails, with exit code 3 if the store is locked."
)]
struct Cli {
    /// Read the passphrase from the first line of stdin instead of
    /// DEADBOLT_PASSPHRASE (init, join, unlock).
    #[arg(long, global = true)]
    passphrase_stdin: bool,
    /// Vault to act on (default: this device's default vault).
    #[arg(short, long, global = true)]
    vault: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

/// Exit code when the store is locked.
const EXIT_LOCKED: u8 = 3;

#[derive(Subcommand)]
enum Commands {
    /// Set up this device (first run) and create a vault.
    Init {
        /// Vault name.
        #[arg(default_value = "personal")]
        name: String,
        /// This device's name, shown to your other devices (default: hostname).
        #[arg(long)]
        device_name: Option<String>,
    },
    /// Join a vault from one of your other devices: prints a ticket, then
    /// waits until `deadbolt pair <ticket>` runs on a member device.
    Join {
        /// This device's name, shown to your other devices (default: hostname).
        #[arg(long)]
        device_name: Option<String>,
    },
    /// Admit a new device into a vault, using the ticket `deadbolt join` shows.
    Pair {
        ticket: String,
        /// Accept the confirmation code without asking, even on a terminal.
        #[arg(short, long)]
        yes: bool,
    },
    /// List the devices in a vault.
    Devices(DevicesArgs),
    /// Manage vaults.
    #[command(subcommand)]
    Vault(VaultCommand),
    /// Unlock the store.
    Unlock {
        /// Lock again after this long without a deadbolt command (30s, 15m,
        /// 8h, 1d, never). Default: `unlock_timeout` in config.toml, else never.
        #[arg(long)]
        timeout: Option<String>,
    },
    /// Lock the store.
    Lock,
    /// Show the agent, this device, its vaults and peers.
    Status,
    /// Sync now with every device (or only the devices in --vault).
    Sync,
    /// Run the background agent in the foreground, or manage it.
    Agent {
        #[command(subcommand)]
        command: Option<AgentCommand>,
    },
    #[command(flatten)]
    Item(items::ItemCommand),
    /// Import items from another password manager into the vault.
    #[command(subcommand)]
    Import(import::ImportCommand),
}

#[derive(Args)]
struct DevicesArgs {
    #[command(subcommand)]
    command: Option<DevicesCommand>,
}

#[derive(Subcommand)]
enum DevicesCommand {
    /// Remove a device from the vault (by name or id).
    Remove { device: String },
}

#[derive(Subcommand)]
enum VaultCommand {
    /// List vaults.
    Ls,
    /// Rename a vault.
    Rename { old: String, new: String },
    /// Make a vault the default.
    Default { name: String },
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Stop the agent (locks the store).
    Stop,
    /// Show whether the agent is running.
    Status,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let agent = matches!(cli.command, Commands::Agent { command: None });
    // Commands die quietly when piped into `head`. The agent keeps Rust's
    // ignored SIGPIPE: a client hanging up mid-reply must not kill it.
    if !agent {
        sigpipe::reset();
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| if agent { "warn,deadbolt=info" } else { "warn" }.into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            if client::code(&error) == Some(ErrorCode::Locked) {
                ExitCode::from(EXIT_LOCKED)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let paths = Paths::get();
    let from_stdin = cli.passphrase_stdin;
    let vault = cli.vault;
    if vault.is_some()
        && matches!(
            cli.command,
            Commands::Init { .. }
                | Commands::Join { .. }
                | Commands::Unlock { .. }
                | Commands::Lock
                | Commands::Status
                | Commands::Agent { .. }
                | Commands::Vault(_)
        )
    {
        bail!("--vault does not apply to this command");
    }
    match cli.command {
        Commands::Item(command) => {
            client::ensure_running(&paths).await?;
            items::run(&paths, command, vault, from_stdin).await?;
        }
        Commands::Import(command) => {
            client::ensure_running(&paths).await?;
            import::run(&paths, command, vault, from_stdin).await?;
        }
        Commands::Agent { command: None } => agent::serve(paths).await?,
        Commands::Agent {
            command: Some(AgentCommand::Stop),
        } => {
            let stopped = client::stop(&paths).await?;
            println!("{}", if stopped { "stopped" } else { "not running" });
        }
        Commands::Agent {
            command: Some(AgentCommand::Status),
        } => match client::status(&paths).await {
            Some(status) => println!("running pid {} version {}", status.pid, status.version),
            None => {
                println!("not running");
                return Ok(ExitCode::FAILURE);
            }
        },
        Commands::Init { name, device_name } => {
            let status = client::ensure_running(&paths).await?;
            if !status.initialized {
                setup(&paths, device_name, from_stdin).await?;
            }
            let Reply::Vault { vault } =
                request(&paths, Command::VaultCreate { name }, from_stdin).await?
            else {
                bail!("unexpected reply");
            };
            let default = if vault.default { " (default)" } else { "" };
            println!("created vault {}{default}", vault.name);
        }
        Commands::Join { device_name } => {
            let status = client::ensure_running(&paths).await?;
            if !status.initialized {
                setup(&paths, device_name, from_stdin).await?;
            }
            let reply = pairing(&paths, Command::Join { confirm: false }, from_stdin).await?;
            let Reply::Vault { vault } = reply else {
                bail!("unexpected reply");
            };
            println!("joined vault {}", vault.name);
        }
        Commands::Pair { ticket, yes } => {
            client::ensure_running(&paths).await?;
            let confirm = !yes && prompt::interactive();
            let command = Command::Pair {
                ticket,
                vault,
                confirm,
            };
            let reply = pairing(&paths, command, from_stdin).await?;
            let Reply::Device { vault, device } = reply else {
                bail!("unexpected reply");
            };
            println!("added {} to {}", device_name(&device), vault.name);
        }
        Commands::Devices(args) => {
            client::ensure_running(&paths).await?;
            match args.command {
                None => {
                    let reply = request(&paths, Command::Devices { vault }, from_stdin).await?;
                    let Reply::Devices { devices } = reply else {
                        bail!("unexpected reply");
                    };
                    for device in &devices {
                        println!(
                            "{}\t{}\t{}",
                            device_name(device),
                            short(&device.id),
                            presence(device)
                        );
                    }
                }
                Some(DevicesCommand::Remove { device }) => {
                    let command = Command::DeviceRemove { vault, device };
                    let Reply::Device { vault, device } =
                        request(&paths, command, from_stdin).await?
                    else {
                        bail!("unexpected reply");
                    };
                    println!("removed {} from {}", device_name(&device), vault.name);
                }
            }
        }
        Commands::Vault(command) => {
            client::ensure_running(&paths).await?;
            match command {
                VaultCommand::Ls => {
                    let Reply::Vaults { vaults } =
                        request(&paths, Command::VaultList, from_stdin).await?
                    else {
                        bail!("unexpected reply");
                    };
                    for vault in &vaults {
                        println!("{}", vault_line(vault));
                    }
                }
                VaultCommand::Rename { old, new } => {
                    let command = Command::VaultRename {
                        vault: old.clone(),
                        name: new,
                    };
                    let Reply::Vault { vault } = request(&paths, command, from_stdin).await? else {
                        bail!("unexpected reply");
                    };
                    println!("renamed {old} to {}", vault.name);
                }
                VaultCommand::Default { name } => {
                    let command = Command::VaultDefault { vault: name };
                    let Reply::Vault { vault } = request(&paths, command, from_stdin).await? else {
                        bail!("unexpected reply");
                    };
                    println!("default vault {}", vault.name);
                }
            }
        }
        Commands::Unlock { timeout } => {
            let timeout_secs = match timeout {
                Some(text) => Some(config::parse_timeout(&text)?.map_or(0, |d| d.as_secs().max(1))),
                None => None,
            };
            let status = client::ensure_running(&paths).await?;
            if !status.initialized {
                bail!("this device is not set up; run `deadbolt init` or `deadbolt join`");
            }
            if status.unlocked && timeout_secs.is_none() {
                println!("unlocked");
                return Ok(ExitCode::SUCCESS);
            }
            unlock(&paths, timeout_secs, from_stdin).await?;
            println!("unlocked");
        }
        Commands::Lock => {
            client::ensure_running(&paths).await?;
            client::simple(&paths, Command::Lock).await?;
            println!("locked");
        }
        Commands::Status => {
            let status = client::ensure_running(&paths).await?;
            print_status(&status);
        }
        Commands::Sync => {
            client::ensure_running(&paths).await?;
            let Reply::Sync { peers } =
                request(&paths, Command::Sync { vault }, from_stdin).await?
            else {
                bail!("unexpected reply");
            };
            if peers.is_empty() {
                eprintln!("no other devices");
                return Ok(ExitCode::SUCCESS);
            }
            for peer in &peers {
                let result = match &peer.error {
                    None => format!("ok sent {} received {}", peer.sent, peer.received),
                    Some(error) => format!("error: {error}"),
                };
                println!(
                    "{}\t{}\t{result}",
                    device_name(&peer.device),
                    short(&peer.device.id)
                );
            }
            if peers.iter().all(|peer| peer.error.is_some()) {
                return Ok(ExitCode::FAILURE);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn setup(paths: &Paths, device_name: Option<String>, from_stdin: bool) -> Result<()> {
    let passphrase = prompt::passphrase(from_stdin, true)?;
    let device_name = prompt::device_name(device_name);
    client::simple(
        paths,
        Command::Setup {
            passphrase: passphrase.to_string(),
            device_name,
        },
    )
    .await?;
    Ok(())
}

async fn unlock(paths: &Paths, timeout_secs: Option<u64>, from_stdin: bool) -> Result<()> {
    let passphrase = prompt::passphrase(from_stdin, false)?;
    client::simple(
        paths,
        Command::Unlock {
            passphrase: passphrase.to_string(),
            timeout_secs,
        },
    )
    .await?;
    Ok(())
}

/// Sends a request. If the store is locked, unlocks inline when it may
/// prompt; otherwise fails with [`ErrorCode::Locked`].
pub async fn request(paths: &Paths, command: Command, from_stdin: bool) -> Result<Reply> {
    request_with(paths, command, from_stdin, &mut |event| {
        bail!("unexpected event {event:?}")
    })
    .await
}

async fn request_with(
    paths: &Paths,
    command: Command,
    from_stdin: bool,
    on_event: &mut impl FnMut(Event) -> Result<Option<bool>>,
) -> Result<Reply> {
    match client::call(paths, command.clone(), &mut *on_event).await {
        Err(error) if client::code(&error) == Some(ErrorCode::Locked) && prompt::interactive() => {
            unlock(paths, None, from_stdin).await?;
            client::call(paths, command, on_event).await
        }
        result => result,
    }
}

/// Runs a pairing request: the ticket goes to stdout, the QR code and the
/// confirmation code to stderr. The code is asked about only if the request
/// set `confirm`.
async fn pairing(paths: &Paths, command: Command, from_stdin: bool) -> Result<Reply> {
    let confirm =
        |code: &str| prompt::confirm(&format!("confirm code {code} matches the other device?"));
    request_with(paths, command.clone(), from_stdin, &mut |event| {
        let ask = matches!(
            command,
            Command::Join { confirm: true } | Command::Pair { confirm: true, .. }
        );
        Ok(match event {
            Event::Ticket { ticket } => {
                if let Ok(qr) = ticket
                    .parse::<PairingTicket>()
                    .and_then(|t| t.to_qr(QrStyle::LightOnDark))
                {
                    eprintln!("{qr}");
                }
                eprintln!("On a device that is already set up, run: deadbolt pair <ticket>");
                println!("{ticket}");
                eprintln!("waiting...");
                None
            }
            Event::Joining {
                code,
                vault,
                inviter,
            } => {
                eprintln!(
                    "code {code}: joining vault {vault} from {} {}",
                    device_name(&inviter),
                    short(&inviter.id)
                );
                if ask { Some(confirm(&code)?) } else { None }
            }
            Event::Pairing { code, device } => {
                eprintln!("code {code}: adding device {device}");
                if ask { Some(confirm(&code)?) } else { None }
            }
        })
    })
    .await
}

fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}

fn device_name(device: &DeviceInfo) -> &str {
    device.name.as_deref().unwrap_or("-")
}

fn ago(unix: u64) -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
        .saturating_sub(unix);
    match secs {
        0..60 => format!("{secs}s ago"),
        60..3600 => format!("{}m ago", secs / 60),
        3600..86400 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86400),
    }
}

fn presence(device: &DeviceInfo) -> String {
    if device.this {
        return "this device".into();
    }
    if device.connected {
        return "connected".into();
    }
    match device.last_seen {
        Some(seen) => format!("last seen {}", ago(seen)),
        None => "never seen".into(),
    }
}

fn vault_line(vault: &VaultInfo) -> String {
    let mut line = format!(
        "{}\t{}\t{} device{}",
        vault.name,
        short(&vault.id),
        vault.members,
        if vault.members == 1 { "" } else { "s" }
    );
    if vault.default {
        line.push_str("\tdefault");
    }
    if !vault.member {
        line.push_str("\tremoved");
    }
    line
}

fn print_status(status: &Status) {
    println!(
        "agent\trunning pid {} version {}",
        status.pid, status.version
    );
    let state = if !status.initialized {
        "not set up".to_string()
    } else if !status.unlocked {
        "locked".to_string()
    } else if let Some(secs) = status.locks_in_secs {
        format!("unlocked (locks in {secs}s)")
    } else {
        "unlocked".to_string()
    };
    println!("state\t{state}");
    if let Some(device) = &status.device {
        println!("device\t{} {}", device_name(device), short(&device.id));
    }
    if status.unlocked {
        let vaults: Vec<String> = status
            .vaults
            .iter()
            .map(|v| format!("{}{}", v.name, if v.default { "*" } else { "" }))
            .collect();
        println!("vaults\t{}", vaults.join(" "));
        println!("peers\t{}/{} online", status.peers_online, status.peers);
    }
}
