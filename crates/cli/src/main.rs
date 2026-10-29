#[cfg(not(unix))]
compile_error!("deadbolt currently supports Unix platforms only");

mod agent;
mod agents;
mod app;
mod browser;
mod caller;
mod client;
mod config;
mod desktop;
mod import;
mod items;
mod prompt;
mod send;
mod site;
mod update;
mod webauthn;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use deadbolt_client::{export, paths, protocol};
use deadbolt_net::{PairingTicket, QrStyle};

use crate::paths::Paths;
use crate::protocol::{Command, DeviceInfo, ErrorCode, Event, Reply, Status, VaultInfo};

#[derive(Parser)]
#[command(
    name = "deadbolt",
    version,
    long_version = env!("DEADBOLT_LONG_VERSION"),
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
        /// Accept the confirmation code without asking, even on a terminal.
        #[arg(short, long)]
        yes: bool,
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
    /// Sync now with every device (or only the devices in --vault), or
    /// mirror another password manager into --vault.
    Sync {
        #[command(subcommand)]
        command: Option<SyncCommand>,
    },
    /// Print what changes in the agent as JSON lines: lock state, items,
    /// vaults and devices, never values. Ends when the agent stops.
    Watch,
    /// Show how the agent sees this process: its verified program, terminal
    /// and parents, and what it claims (DEADBOLT_CALLER, OPENCODE_SESSION_ID).
    Whoami {
        #[arg(long)]
        json: bool,
    },
    /// List what callers asked the agent for, and what the app showed or
    /// copied, newest first. Names items and fields, never values.
    Activity {
        /// Only entries this recent (30m, 1h, 7d).
        #[arg(long)]
        since: Option<String>,
        /// At most this many entries (default 500).
        #[arg(long)]
        limit: Option<u32>,
        /// One JSON object per line.
        #[arg(long)]
        json: bool,
    },
    /// Let AI agents sign in to sites without asking: pair an agent client
    /// (such as Browse) and allow it logins, site by site. Values never
    /// reach the AI; every fill is in `deadbolt activity`.
    #[command(subcommand)]
    Agents(agents::AgentsCommand),
    /// Run the background agent in the foreground, or manage it.
    Agent {
        #[command(subcommand)]
        command: Option<AgentCommand>,
    },
    /// Enable, disable or check Touch ID unlock on macOS.
    #[command(name = "touchid", visible_alias = "touch-id")]
    TouchId {
        #[command(subcommand)]
        command: Option<TouchIdCommand>,
    },
    #[command(flatten)]
    Item(items::ItemCommand),
    /// Import logins, cards, secure notes, SSH keys and identities from
    /// 1Password, Apple Passwords, Bitwarden or CSV.
    ///
    /// The format is detected from the file. To export:
    ///
    ///   1Password 8: File › Export › (account) › 1PUX (or CSV, logins only)
    ///
    ///   Apple Passwords (macOS 15+): File › Export All Passwords…
    ///   (Safari: File › Export › Passwords…)
    ///
    ///   Bitwarden: Tools › Export vault › .json
    ///
    /// Any other CSV with a password column also works (title, url,
    /// username, password, notes, otpauth). 1Password categories without a
    /// closer type (software licenses, bank accounts, ...) become secure
    /// notes with their fields kept. Documents, other item types, tags,
    /// folders, favorites, attachments and password history are skipped and
    /// counted.
    /// Items already in the vault are skipped, so importing again changes
    /// nothing. Delete the export file afterwards: it is not encrypted.
    #[command(verbatim_doc_comment)]
    Import {
        /// The export file; stdin if omitted or `-`.
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        /// Show what would be imported without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Send files, a secret or vault items through a one-time link that
    /// opens in any browser (deadbolt.pw/r, no Deadbolt needed).
    ///
    /// The link is the key: whoever opens it first gets the contents,
    /// decrypted in their browser. Nothing is uploaded anywhere; the
    /// deadbolt agent on this computer serves the link live until it is
    /// opened, expires (default 1h) or is revoked, and only while it runs.
    ///
    ///   deadbolt send ./report.pdf ./keys/          files and folders
    ///   deadbolt send                               asks for a secret (hidden)
    ///   cat key.pem | deadbolt send -               stdin
    ///   deadbolt send --item "Stripe"               a vault item's fields
    ///   deadbolt send --item Stripe --field secret  one field
    ///
    /// Arguments are files or folders and must exist; vault items are only
    /// ever sent with --item, by exact name or ID. Each --field applies to
    /// the nearest --item before it. Shows what will be sent and asks
    /// first; scripts pass --yes (--json and no terminal require it).
    /// Prints the link; see `deadbolt sends` for what was sent.
    #[command(verbatim_doc_comment)]
    Send(send::SendArgs),
    /// List, show or revoke sends.
    Sends(send::SendsArgs),
    /// Open the desktop app, or bring the running one forward (bare
    /// `deadbolt` does too when started from an app launcher rather than a
    /// terminal; DEADBOLT_NO_UI=1 stops that).
    App,
    /// Add Deadbolt to the Linux app launcher, opening `deadbolt app`.
    #[command(subcommand)]
    Desktop(DesktopCommand),
    /// Connect Deadbolt's browser extension to this computer's Deadbolt.
    #[command(subcommand)]
    Browser(BrowserCommand),
    /// Update this Deadbolt from its release channel: Deadbolt.app when
    /// this is its `deadbolt`, else this standalone `deadbolt`, plus an
    /// unpacked extension registered with `browser install --extension-dir`.
    ///
    /// Downloads are checked against the release's size and SHA-256 and, on
    /// macOS, its code signature before anything is replaced. Installs from
    /// Homebrew or another package manager get its command instead. The agent
    /// restarts on the new build, locked. Works while the vault is locked.
    Update(update::UpdateArgs),
    /// Serve the browser extension at ORIGIN over stdin/stdout. Browsers
    /// run this; `deadbolt browser install` sets it up.
    #[command(hide = true)]
    BrowserHost { origin: String },
}

#[derive(Subcommand)]
enum DesktopCommand {
    /// Write the desktop entry and icon under ~/.local/share (again to update).
    Install,
    /// Remove the desktop entry and icon.
    Uninstall,
}

#[derive(Subcommand)]
enum BrowserCommand {
    /// Let the extension reach Deadbolt in Chrome, Brave, Arc, Edge,
    /// Chromium or Helium (default: those installed here).
    Install {
        #[arg(long, value_enum)]
        browser: Vec<browser::Browser>,
        /// Also keep an unpacked copy of the extension in DIR current with
        /// `deadbolt update` (a new or empty directory; update owns it).
        #[arg(long, value_name = "DIR")]
        extension_dir: Option<PathBuf>,
    },
    /// Stop the extension reaching Deadbolt (default: in every browser).
    Uninstall {
        #[arg(long, value_enum)]
        browser: Vec<browser::Browser>,
    },
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
enum SyncCommand {
    /// Mirror 1Password into --vault with the 1Password CLI (`op`).
    ///
    /// 1Password stays the source of truth: new items are added, changed
    /// ones updated, and ones deleted or archived there deleted here if this
    /// sync added them. Items from a 1Password export imported earlier,
    /// items with the same content and logins with the same username and
    /// URL are taken over; other items here are never touched. Needs the 1Password app's CLI
    /// integration (Settings › Developer), which may ask to approve access.
    /// Exits 3 if deadbolt is locked, before 1Password is asked anything.
    #[command(name = "1password", visible_alias = "op")]
    OnePassword {
        /// The 1Password account (sign-in address, email, shorthand or id);
        /// needed only if the CLI knows several and --vault mirrors none.
        #[arg(long)]
        account: Option<String>,
        /// Mirror only this 1Password vault (by name or id); repeat for
        /// more. Default: every vault in the account.
        #[arg(long = "op-vault", value_name = "NAME")]
        op_vaults: Vec<String>,
        /// Show what would change without writing anything.
        #[arg(long)]
        dry_run: bool,
        /// Print one line, and only if something changed.
        #[arg(short, long)]
        quiet: bool,
    },
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Stop the agent (locks the store).
    Stop,
    /// Show whether the agent is running.
    Status,
}

#[derive(Subcommand)]
enum TouchIdCommand {
    /// Enable Touch ID unlock (unlocks the store first if needed).
    On,
    /// Disable Touch ID unlock and remove the enrolled key slot.
    Off,
    /// Show whether Touch ID unlock is available, enabled and ready.
    Status,
}

fn main() -> ExitCode {
    // A browser runs a native messaging host with the caller's origin as its
    // only argument, which can't name a subcommand.
    let mut args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.len() == 2
        && args[1]
            .to_str()
            .is_some_and(|a| a.starts_with("chrome-extension://"))
    {
        args.insert(1, "browser-host".into());
    }
    // Bare `deadbolt` from an app launcher opens the app; from a terminal,
    // or when the app can't be opened, it prints usage as before.
    if args.len() == 1
        && app::bare_opens_app(app::from_terminal(), cfg!(target_os = "macos"), |name| {
            config::env(name).ok()
        })
        && open_app()
    {
        return ExitCode::SUCCESS;
    }
    let cli = Cli::parse_from(args);
    let agent = matches!(cli.command, Commands::Agent { command: None });
    // Commands die quietly when piped into `head`. The agent and the browser
    // host keep Rust's ignored SIGPIPE: a client hanging up mid-reply must
    // not kill them before they clean up.
    if !agent && !matches!(cli.command, Commands::BrowserHost { .. }) {
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

/// Bare `deadbolt`'s `deadbolt app`, before the CLI's runtime exists.
fn open_app() -> bool {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .is_ok_and(|runtime| runtime.block_on(app::open(&Paths::get())).is_ok())
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
                | Commands::Watch
                | Commands::Whoami { .. }
                | Commands::Activity { .. }
                | Commands::Agent { .. }
                | Commands::Agents(_)
                | Commands::TouchId { .. }
                | Commands::Vault(_)
                | Commands::App
                | Commands::Desktop(_)
                | Commands::Browser(_)
                | Commands::BrowserHost { .. }
                | Commands::Update(_)
                | Commands::Sends(_)
        )
    {
        bail!("--vault does not apply to this command");
    }
    caller::install();
    match cli.command {
        Commands::Send(args) => return send::send(&paths, args, vault, from_stdin).await,
        Commands::Sends(args) => send::sends(&paths, args).await?,
        Commands::Item(command) => {
            client::ensure_running(&paths).await?;
            items::run(&paths, command, vault, from_stdin).await?;
        }
        Commands::Import { file, dry_run } => {
            let export = match file.filter(|f| f.as_os_str() != "-") {
                Some(file) => export::read(&file)?,
                None => {
                    if std::io::stdin().is_terminal() {
                        bail!("pass the export file, or pipe it on stdin");
                    }
                    if from_stdin {
                        bail!("--passphrase-stdin cannot be used when the export comes from stdin");
                    }
                    export::read_from(std::io::stdin().lock())?
                }
            };
            client::ensure_running(&paths).await?;
            let command = Command::Import {
                vault,
                export,
                apply: !dry_run,
            };
            let Reply::Import { report } = request(&paths, command, from_stdin).await? else {
                bail!("unexpected reply");
            };
            for line in report.lines(!dry_run) {
                println!("{line}");
            }
        }
        Commands::Agent { command: None } => agent::serve(paths).await?,
        Commands::Agents(command) => agents::run(&paths, command, from_stdin).await?,
        Commands::App => app::open(&paths).await?,
        Commands::Desktop(DesktopCommand::Install) => desktop::install()?,
        Commands::Desktop(DesktopCommand::Uninstall) => desktop::uninstall()?,
        Commands::Browser(BrowserCommand::Install {
            browser,
            extension_dir,
        }) => browser::install(&browser, extension_dir.as_deref(), &paths.config)?,
        Commands::Update(args) => return update::run(&paths, args).await,
        Commands::Browser(BrowserCommand::Uninstall { browser }) => browser::uninstall(&browser)?,
        Commands::BrowserHost { origin } => browser::host::run(paths, &origin).await?,
        Commands::Agent {
            command: Some(AgentCommand::Stop),
        } => {
            let stopped = client::stop(&paths).await?;
            println!("{}", if stopped { "stopped" } else { "not running" });
        }
        Commands::Agent {
            command: Some(AgentCommand::Status),
        } => match client::running(&paths).await {
            Some(agent) => println!("running pid {} version {}", agent.pid, agent.version),
            None => {
                println!("not running");
                return Ok(ExitCode::FAILURE);
            }
        },
        Commands::TouchId { command } => {
            let status = client::ensure_running(&paths).await?;
            match command.unwrap_or(TouchIdCommand::Status) {
                TouchIdCommand::On => {
                    if !status.initialized {
                        bail!("this device is not set up; run `deadbolt init` or `deadbolt join`");
                    }
                    let Reply::Done =
                        request(&paths, Command::TouchIdSet { enabled: true }, from_stdin).await?
                    else {
                        bail!("unexpected reply");
                    };
                    println!("Touch ID unlock enabled");
                }
                TouchIdCommand::Off => {
                    client::simple(&paths, Command::TouchIdSet { enabled: false }).await?;
                    println!("Touch ID unlock disabled");
                }
                TouchIdCommand::Status => {
                    let state = if !status.touch_id_available {
                        "unavailable"
                    } else if !status.touch_id_enabled {
                        "disabled"
                    } else if !status.initialized {
                        "enabled (not set up)"
                    } else if status.touch_id_ready {
                        "enabled (enrolled)"
                    } else if status.touch_id_reset {
                        "enabled (reset; enter passphrase once)"
                    } else {
                        "enabled (enter passphrase once to finish turning on)"
                    };
                    println!("touchid\t{state}");
                }
            }
        }
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
        Commands::Join { device_name, yes } => {
            let status = client::ensure_running(&paths).await?;
            if !status.initialized {
                setup(&paths, device_name, from_stdin).await?;
            }
            let confirm = !yes && prompt::interactive();
            let reply = pairing(&paths, Command::Join { confirm }, from_stdin).await?;
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
        Commands::Whoami { json } => caller::whoami(&paths, json).await?,
        Commands::Activity { since, limit, json } => {
            caller::activity(&paths, since, limit, json, from_stdin).await?;
        }
        Commands::Watch => {
            client::ensure_running(&paths).await?;
            let mut changes = deadbolt_client::watch(&paths, false).await?;
            while let Some(change) = changes.next().await? {
                println!("{}", serde_json::to_string(&change)?);
            }
        }
        Commands::Sync {
            command:
                Some(SyncCommand::OnePassword {
                    account,
                    op_vaults,
                    dry_run,
                    quiet,
                }),
        } => {
            client::ensure_running(&paths).await?;
            let command = Command::SyncOnePassword {
                vault,
                account,
                op_vaults,
                dry_run,
            };
            let Reply::Mirror { report } = request(&paths, command, from_stdin).await? else {
                bail!("unexpected reply");
            };
            if !quiet {
                for line in report.lines() {
                    println!("{line}");
                }
            } else if report.changed() {
                println!("1Password: {}", report.summary());
            }
        }
        Commands::Sync { command: None } => {
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
            passphrase,
            device_name,
        },
    )
    .await?;
    Ok(())
}

async fn unlock(paths: &Paths, timeout_secs: Option<u64>, from_stdin: bool) -> Result<()> {
    if can_try_touch_id(from_stdin)
        && let Some(status) = client::status(paths).await
        && !status.unlocked
    {
        if status.touch_id_ready {
            match client::simple(paths, Command::UnlockBiometric { timeout_secs }).await {
                Ok(_) => return Ok(()),
                Err(err) => {
                    if std::io::stderr().is_terminal() {
                        if let Some(after) = client::status(paths).await
                            && after.touch_id_reset
                        {
                            eprintln!("Touch ID was reset; enter your passphrase.");
                        } else {
                            let msg = format!("{err:#}");
                            if !msg.contains("cancelled") {
                                eprintln!("{msg}");
                            }
                        }
                    }
                }
            }
        } else if status.touch_id_reset && std::io::stderr().is_terminal() {
            eprintln!("Touch ID was reset; enter your passphrase.");
        } else if status.touch_id_enabled && std::io::stderr().is_terminal() {
            eprintln!("Enter your passphrase once to finish turning on Touch ID.");
        }
    }
    let passphrase = prompt::passphrase(from_stdin, false)?;
    client::simple(
        paths,
        Command::Unlock {
            passphrase,
            timeout_secs,
        },
    )
    .await?;
    Ok(())
}

/// Touch ID is tried on interactive terminals when the user did not supply a
/// passphrase via flags/env and is not connected over SSH.
fn can_try_touch_id(from_stdin: bool) -> bool {
    !from_stdin
        && config::env("DEADBOLT_PASSPHRASE").is_err()
        && config::env("SSH_CONNECTION").is_err()
        && std::io::stdin().is_terminal()
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
    let secs = config::now().saturating_sub(unix);
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
