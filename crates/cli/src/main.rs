#[cfg(not(unix))]
compile_error!("deadbolt currently supports Unix platforms only");

mod agents;
mod app;
mod browser;
mod caller;
mod client;
mod config;
mod daemon;
mod desktop;
mod health;
mod import;
mod items;
mod prompt;
mod secrets;
mod send;
use deadbolt_core::site;
mod update;
use deadbolt_core::webauthn;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use deadbolt_client::{export, paths, protocol};
use deadbolt_net::PairingCode;

use crate::paths::Paths;
use crate::protocol::{
    Answer, Command, DeviceInfo, ErrorCode, Event, Reply, Secret, Status, VaultInfo,
};

#[derive(Parser)]
#[command(
    name = "deadbolt",
    version,
    long_version = env!("DEADBOLT_LONG_VERSION"),
    about = "A decentralized password manager",
    long_about = "A decentralized password manager.\n\nEverything can be driven with \
flags, env and stdin. The passphrase comes from DEADBOLT_PASSPHRASE or \
--passphrase-stdin. Only when stdin and stderr are terminals does deadbolt ask for \
what is missing; otherwise it fails, with exit code 3 if the store is locked and 4 \
if the daemon refused the request."
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
/// Exit code when the daemon refused the request (not granted, forbidden).
const EXIT_DENIED: u8 = 4;

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
    /// Join a vault from one of your other devices: shows a code, then
    /// waits until `deadbolt approve <code>` runs on a device with the vault.
    ///
    /// Codes work once, for 5 minutes. On a device that isn't set up yet,
    /// the passphrase for this device is asked once it has joined (or taken
    /// from DEADBOLT_PASSPHRASE or --passphrase-stdin), and nothing is saved
    /// before then.
    Join {
        /// This device's name, shown to your other devices (default: hostname).
        #[arg(long)]
        device_name: Option<String>,
    },
    /// Approve the device showing a code from `deadbolt join`: adds it to a
    /// vault (the default vault, or --vault).
    Approve {
        /// The code, such as violin-garden-tiger-lamp-zoo.
        #[arg(required = true, num_args = 1.., value_name = "CODE")]
        code: Vec<String>,
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
    /// Sync now with every device (or only the devices in --vault), or
    /// mirror another password manager into --vault.
    Sync {
        #[command(subcommand)]
        command: Option<SyncCommand>,
    },
    /// List what callers asked Deadbolt for, and what the app showed or
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
    /// (such as Browse) and allow it logins, site by site; or let them use
    /// secrets in `deadbolt run` and `inject` (`allow-secrets`). Every use
    /// is in `deadbolt activity`.
    #[command(subcommand)]
    Agents(agents::AgentsCommand),
    /// Run Deadbolt's background daemon in the foreground. Clients start it.
    #[command(hide = true)]
    Daemon,
    /// The daemon under its old name, as an update from an older build
    /// starts it.
    #[command(name = "agent", hide = true)]
    OldDaemon,
    /// Enable, disable or check Touch ID unlock on macOS.
    #[command(name = "touchid", visible_alias = "touch-id")]
    TouchId {
        #[command(subcommand)]
        command: Option<TouchIdCommand>,
    },
    #[command(flatten)]
    Item(items::ItemCommand),
    /// Run a command with secrets in its environment, concealed in its
    /// output.
    ///
    ///   deadbolt run --env GH_TOKEN=deadbolt://personal/GitHub/token -- gh release create v1
    ///   deadbolt run --env-file .env.tpl -- bun run dev
    ///
    /// A reference is deadbolt://[vault/]item/field: the item by its title
    /// or short id (exactly one must match), the vault optional (default:
    /// the default vault). Inherited variables whose value is a reference
    /// are resolved too. The command's stdin passes through, its stdout and
    /// stderr have each value (and its URL and base64 forms) replaced with
    /// <concealed by deadbolt>, signals go on to it, and deadbolt exits with
    /// its code. Masking makes its stdout and stderr pipes: it sees no
    /// terminal (no colors or full-screen UIs; its pager may change), and
    /// output held back as a possible value goes out after 100 ms of quiet.
    /// --no-mask keeps the terminal. Masking stops accidents, not a
    /// command that means to show a value.
    ///
    /// AI agents need `deadbolt agents allow-secrets` first; refused,
    /// deadbolt exits 4.
    #[command(verbatim_doc_comment)]
    Run(secrets::RunArgs),
    /// Fill a template's {{ deadbolt://… }} references and write it 0600.
    ///
    ///   deadbolt inject -i config.tpl -o config.json
    ///
    /// Replaces an existing output file only if `deadbolt inject` wrote it
    /// and it hasn't changed since, or with --force. AI agents need
    /// `deadbolt agents allow-secrets --purpose inject` first, and Touch ID
    /// each time to write to stdout, which is reading the values.
    #[command(verbatim_doc_comment)]
    Inject(secrets::InjectArgs),
    /// Print the value a reference names (deadbolt://[vault/]item/field).
    /// Prefer `deadbolt run` or `inject`: an AI agent reading a value needs
    /// Touch ID every time, and is refused without it.
    Read(secrets::ReadArgs),
    /// Import logins, cards, secure notes, SSH keys, identities, API
    /// credentials, documents and the rest from 1Password, Apple Passwords,
    /// Bitwarden or CSV.
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
    /// username, password, notes, otpauth). 1Password categories map to
    /// their types (API credentials, databases, servers, Wi-Fi, software
    /// licenses, bank accounts, documents, passports, driver's licenses,
    /// memberships, crypto wallets, social security numbers); the others
    /// become secure notes with their fields kept. A .1pux's documents and
    /// attachments come along, up to 10 MiB each. Other item types, tags,
    /// folders, favorites and password history are skipped and counted.
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
    /// Deadbolt daemon on this computer serves the link live until it is
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
    /// Prints the link.
    ///
    ///   deadbolt send ls                            what was sent
    ///   deadbolt send show <id>                     one send and its opens
    ///   deadbolt send revoke <id>                   stop a link working
    ///
    /// A first argument of ls, show or revoke is the subcommand, never a
    /// path: send a file named ls as ./ls.
    #[command(verbatim_doc_comment)]
    Send(send::SendArgs),
    /// Audit saved passwords for weak, reused, and breached credentials, and
    /// sites supporting authenticator codes or passkeys.
    Health(health::HealthArgs),
    /// Open the desktop app, or bring the running one forward (bare
    /// `deadbolt` does too when started from an app launcher rather than a
    /// terminal; DEADBOLT_NO_UI=1 stops that). On Linux its first opening
    /// adds Deadbolt to the app launcher.
    App,
    /// Add Deadbolt to the Linux app launcher, opening `deadbolt app`, or
    /// take it out.
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
    /// Homebrew or another package manager get its command instead. The daemon
    /// restarts on the new build, locked. Works while the vault is locked.
    Update(update::UpdateArgs),
    /// Diagnostics: how the daemon sees you, its live change stream, the
    /// daemon itself.
    #[command(subcommand)]
    Debug(DebugCommand),
    /// Serve the browser extension at ORIGIN over stdin/stdout. Browsers
    /// run this; `deadbolt browser install` sets it up.
    #[command(hide = true)]
    BrowserHost { origin: String },
}

#[derive(Subcommand)]
enum DebugCommand {
    /// Show how the daemon sees this process: its verified program, terminal
    /// and parents, and what it claims (DEADBOLT_CALLER, OPENCODE_SESSION_ID).
    Whoami {
        #[arg(long)]
        json: bool,
    },
    /// Print what changes in the daemon as JSON lines: lock state, items,
    /// vaults and devices, never values. Ends when the daemon stops.
    Watch,
    /// Show whether the background daemon is running and locked, or stop it.
    Daemon {
        #[command(subcommand)]
        command: Option<DaemonCommand>,
    },
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
        /// Each directory registered this way is kept current with its own
        /// build.
        #[arg(long, value_name = "DIR")]
        extension_dir: Option<PathBuf>,
        /// Keep the standalone build in DIR instead: its own vault in the
        /// browser, which pairs with this computer's Deadbolt as a device.
        #[arg(long, requires = "extension_dir")]
        standalone: bool,
    },
    /// Put the other build of the extension in a directory registered with
    /// `browser install --extension-dir`, then reload Deadbolt in
    /// chrome://extensions. Both builds have the same id, so the profile
    /// keeps its place for it; each keeps its own settings.
    #[command(group(clap::ArgGroup::new("build").required(true).args(["standalone", "native"])))]
    Switch {
        /// The standalone build: its own vault in the browser.
        #[arg(long)]
        standalone: bool,
        /// The native build: fills from this computer's Deadbolt.
        #[arg(long)]
        native: bool,
        /// The release channel to fetch it from (default: this build's).
        #[arg(long, value_parser = ["dev", "beta", "stable"])]
        channel: Option<String>,
        /// The registered directory to switch (needed when there are
        /// several).
        #[arg(long, value_name = "DIR")]
        extension_dir: Option<PathBuf>,
    },
    /// Stop the extension reaching Deadbolt (default: in every browser).
    Uninstall {
        #[arg(long, value_enum, conflicts_with = "extension_dir")]
        browser: Vec<browser::Browser>,
        /// Only stop `deadbolt update` keeping DIR current, leaving its
        /// files and the browsers' registration alone.
        #[arg(long, value_name = "DIR")]
        extension_dir: Option<PathBuf>,
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
enum DaemonCommand {
    /// Show whether the daemon is running, and whether it's locked.
    Status,
    /// Stop the daemon (locks the store).
    Stop,
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
    let mut args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    // Deadbolt.app's own executable and `deadbolt ui` are the app itself.
    let exe = app::this_binary().ok();
    if let Some(argv) = app::ui_args(&args, exe.as_deref(), cfg!(target_os = "macos")) {
        return app::run_ui(argv);
    }
    // A browser runs a native messaging host with the caller's origin as its
    // only argument, which can't name a subcommand.
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
        && app::BUILT_IN
        && app::bare_opens_app(app::from_terminal(), cfg!(target_os = "macos"), |name| {
            config::env(name).ok()
        })
        && open_app()
    {
        return ExitCode::SUCCESS;
    }
    let json = args.iter().any(|a| a == "--json");
    let cli = Cli::parse_from(args);
    let daemon = matches!(cli.command, Commands::Daemon | Commands::OldDaemon);
    // The daemon's update notice: only to a person at a terminal.
    let notice = !json && notices_updates(&cli.command) && prompt::interactive();
    // Commands die quietly when piped into `head`. The daemon and the browser
    // host keep Rust's ignored SIGPIPE: a client hanging up mid-reply must
    // not kill them before they clean up.
    if !daemon && !matches!(cli.command, Commands::BrowserHost { .. }) {
        sigpipe::reset();
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| if daemon { "warn,deadbolt=info" } else { "warn" }.into()),
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
    let result = runtime.block_on(async {
        let result = run(cli).await;
        if notice {
            update::notice(&Paths::get()).await;
        }
        result
    });
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            match client::code(&error) {
                Some(ErrorCode::Locked) => ExitCode::from(EXIT_LOCKED),
                Some(ErrorCode::Forbidden | ErrorCode::NotGranted) => ExitCode::from(EXIT_DENIED),
                _ => ExitCode::FAILURE,
            }
        }
    }
}

/// Whether `command` may end with the daemon's update notice: not the
/// daemon, hosts and helpers other programs run, `update` (which says it
/// itself), `debug watch`, the app, or `run`, whose output is its program's.
fn notices_updates(command: &Commands) -> bool {
    !matches!(
        command,
        Commands::Daemon
            | Commands::OldDaemon
            | Commands::BrowserHost { .. }
            | Commands::Update(_)
            | Commands::Debug(DebugCommand::Watch)
            | Commands::App
            | Commands::Run(_)
    )
}

/// The extension build `--standalone` picks (else the native one).
fn extension_build(standalone: bool) -> config::ExtensionBuild {
    if standalone {
        config::ExtensionBuild::Standalone
    } else {
        config::ExtensionBuild::Native
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
        && (matches!(
            cli.command,
            Commands::Init { .. }
                | Commands::Join { .. }
                | Commands::Unlock { .. }
                | Commands::Lock
                | Commands::Debug(_)
                | Commands::Activity { .. }
                | Commands::Daemon
                | Commands::OldDaemon
                | Commands::TouchId { .. }
                | Commands::Run(_)
                | Commands::Inject(_)
                | Commands::Read(_)
                | Commands::Vault(_)
                | Commands::App
                | Commands::Desktop(_)
                | Commands::Browser(_)
                | Commands::BrowserHost { .. }
                | Commands::Update(_)
        ) || matches!(&cli.command, Commands::Send(args) if args.manages()))
    {
        bail!("--vault does not apply to this command");
    }
    caller::install();
    match cli.command {
        Commands::Send(args) => return send::send(&paths, args, vault, from_stdin).await,
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
                export: export.text,
                files: export.files,
                apply: !dry_run,
            };
            let Reply::Import { report } = request(&paths, command, from_stdin).await? else {
                bail!("unexpected reply");
            };
            for line in report.lines(!dry_run) {
                println!("{line}");
            }
        }
        Commands::Daemon => daemon::serve(paths, false).await?,
        Commands::OldDaemon => daemon::serve(paths, true).await?,
        Commands::Agents(command) => agents::run(&paths, command, vault, from_stdin).await?,
        Commands::Run(args) => return secrets::run(&paths, args, from_stdin).await,
        Commands::Inject(args) => secrets::inject(&paths, args, from_stdin).await?,
        Commands::Read(args) => secrets::read(&paths, args, from_stdin).await?,
        Commands::Health(args) => return health::run(&paths, vault, from_stdin, args).await,
        Commands::App => app::open(&paths).await?,
        Commands::Desktop(DesktopCommand::Install) => desktop::install()?,
        Commands::Desktop(DesktopCommand::Uninstall) => desktop::uninstall()?,
        Commands::Browser(BrowserCommand::Install {
            browser,
            extension_dir,
            standalone,
        }) => browser::install(
            &browser,
            extension_dir.as_deref(),
            extension_build(standalone),
            &paths.config,
        )?,
        Commands::Browser(BrowserCommand::Switch {
            standalone,
            native: _,
            channel,
            extension_dir,
        }) => {
            update::switch_extension(
                &paths,
                extension_build(standalone),
                extension_dir.as_deref(),
                channel.as_deref(),
            )
            .await?
        }
        Commands::Update(args) => return update::run(&paths, args).await,
        Commands::Browser(BrowserCommand::Uninstall {
            browser,
            extension_dir: None,
        }) => browser::uninstall(&browser)?,
        Commands::Browser(BrowserCommand::Uninstall {
            browser: _,
            extension_dir: Some(dir),
        }) => browser::unregister_extension_dir(&dir, &paths.config)?,
        Commands::BrowserHost { origin } => browser::host::run(paths, &origin).await?,
        Commands::Debug(DebugCommand::Daemon {
            command: Some(DaemonCommand::Stop),
        }) => {
            let stopped = client::stop(&paths).await?;
            println!("{}", if stopped { "stopped" } else { "not running" });
        }
        Commands::Debug(DebugCommand::Daemon {
            command: None | Some(DaemonCommand::Status),
        }) => match client::running(&paths).await {
            Some(daemon) => {
                println!("running pid {} version {}", daemon.pid, daemon.version);
                if let Some(status) = client::status(&paths).await {
                    println!("{}", lock_state(&status));
                }
            }
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
        Commands::Join { device_name } => {
            let status = client::ensure_running(&paths).await?;
            // A new device gets its passphrase last, once it has joined. One
            // supplied up front goes with the request; without one and without
            // a terminal to ask on, fail before a code is spent.
            let passphrase = if status.initialized {
                None
            } else {
                let supplied = prompt::supplied_passphrase(from_stdin)?;
                if supplied.is_none() && !prompt::interactive() {
                    bail!(
                        "a passphrase is needed for this device: set DEADBOLT_PASSPHRASE or pass --passphrase-stdin"
                    );
                }
                supplied.map(|p| Secret::new(p.as_str()))
            };
            let command = Command::Join {
                device_name: Some(prompt::device_name(device_name)),
                passphrase,
            };
            let Reply::Vault { .. } = join(&paths, command, from_stdin).await? else {
                bail!("unexpected reply");
            };
        }
        Commands::Approve { code } => {
            let code = code.join(" ");
            code.parse::<PairingCode>()?;
            client::ensure_running(&paths).await?;
            let vault = match vault {
                Some(vault) => Some(vault),
                None => choose_vault(&paths, from_stdin).await?,
            };
            let reply = request(&paths, Command::Pair { code, vault }, from_stdin).await?;
            let Reply::Device { vault, device } = reply else {
                bail!("unexpected reply");
            };
            println!("✓ added \"{}\" to {}", device_name(&device), vault.name);
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
        Commands::Debug(DebugCommand::Whoami { json }) => caller::whoami(&paths, json).await?,
        Commands::Activity { since, limit, json } => {
            caller::activity(&paths, since, limit, json, from_stdin).await?;
        }
        Commands::Debug(DebugCommand::Watch) => {
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
    on_event: &mut impl FnMut(Event) -> Result<Option<Answer>>,
) -> Result<Reply> {
    match client::call(paths, command.clone(), &mut *on_event).await {
        Err(error) if client::code(&error) == Some(ErrorCode::Locked) && prompt::interactive() => {
            unlock(paths, None, from_stdin).await?;
            client::call(paths, command, on_event).await
        }
        result => result,
    }
}

/// Runs `join`: the code and the outcome go to stdout, what to do with the
/// code to stderr. A device that isn't set up is asked for its passphrase
/// once it has joined, unless the request carries one.
async fn join(paths: &Paths, command: Command, from_stdin: bool) -> Result<Reply> {
    request_with(paths, command, from_stdin, &mut |event| {
        Ok(match event {
            Event::Code { code } => {
                println!("Code: {code}");
                eprintln!("On a device with your vault, run: deadbolt approve {code}");
                eprintln!("waiting…");
                None
            }
            Event::Joined {
                vault,
                inviter,
                passphrase,
            } => {
                println!("✓ joined \"{vault}\" from {}", device_name(&inviter));
                if passphrase {
                    let passphrase = prompt::new_passphrase("Passphrase for this device", "Again")?;
                    Some(Answer::passphrase(Secret::new(passphrase.as_str())))
                } else {
                    None
                }
            }
        })
    })
    .await
}

/// The vault `approve` adds to when `--vault` isn't given: the only one, else
/// asked on a terminal (the default first), else an error.
async fn choose_vault(paths: &Paths, from_stdin: bool) -> Result<Option<String>> {
    let Reply::Vaults { vaults } = request(paths, Command::VaultList, from_stdin).await? else {
        bail!("unexpected reply");
    };
    let mut vaults: Vec<VaultInfo> = vaults.into_iter().filter(|v| v.member).collect();
    if vaults.len() < 2 {
        return Ok(None);
    }
    vaults.sort_by_key(|v| !v.default);
    let names: Vec<&str> = vaults.iter().map(|v| v.name.as_str()).collect();
    if !prompt::interactive() {
        bail!(
            "this device holds several vaults ({}); choose one with --vault",
            names.join(", ")
        );
    }
    prompt::choose("Add to which vault?", &names).map(Some)
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
    let mut line = format!("{}\t{}", vault.name, short(&vault.id));
    if vault.error.is_none() {
        line.push_str(&format!(
            "\t{} device{}",
            vault.members,
            if vault.members == 1 { "" } else { "s" }
        ));
    }
    if vault.default {
        line.push_str("\tdefault");
    }
    if let Some(error) = &vault.error {
        line.push_str(&format!("\tunavailable: {error}"));
    } else if !vault.member {
        line.push_str("\tremoved");
    }
    line
}

fn lock_state(status: &Status) -> String {
    if !status.initialized {
        "not set up".into()
    } else if !status.unlocked {
        "locked".into()
    } else if let Some(secs) = status.locks_in_secs {
        format!("unlocked (locks in {secs}s)")
    } else {
        "unlocked".into()
    }
}
