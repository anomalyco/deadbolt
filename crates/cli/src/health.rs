//! `deadbolt health`: password health audit, dismissal management, and opt-in
//! breach-check settings.

use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::{Args, Subcommand};

use crate::config::{Config, set_breach_checks};
use crate::paths::Paths;
use crate::protocol::{Command, Finding, FindingKind, HealthReport, ItemHealth, Reply};

#[derive(Args)]
pub struct HealthArgs {
    #[command(subcommand)]
    pub command: Option<HealthCommand>,
    /// Include two-factor and passkey upgrade opportunities alongside risks.
    #[arg(long)]
    pub all: bool,
    /// Show only these comma-separated kinds (`breached`, `site-breach`,
    /// `reused`, `weak`, `2fa`, `passkeys`, `ignored`).
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,
    /// Query Have I Been Pwned's padded k-anonymity range API for this run.
    #[arg(long)]
    pub online: bool,
    /// Inspect every unlocked vault on this device instead of only `--vault`.
    #[arg(long)]
    pub all_vaults: bool,
    /// Print the report as JSON (never contains secret values or hashes).
    #[arg(long)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum HealthCommand {
    /// Silence a finding (`weak`, `reused`, `breached`, `site-breach`, `2fa`,
    /// `passkey`) on an item. Password findings re-arm automatically if the
    /// item's password changes.
    Ignore {
        /// Item title, host, username, or id prefix (must match one item).
        item: String,
        /// Finding kind to ignore (`weak`, `reused`, `breached`, `site-breach`,
        /// `2fa`, `passkey`).
        kind: String,
    },
    /// Restore a previously ignored finding on an item.
    Unignore { item: String, kind: String },
    /// Enable, disable, or check opt-in Have I Been Pwned breach checks.
    Breaches {
        #[arg(value_parser = ["on", "off", "status"])]
        action: Option<String>,
    },
}

fn parse_kind(raw: &str) -> Result<FindingKind> {
    FindingKind::parse(&raw.trim().to_ascii_lowercase()).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown finding kind {raw:?} (expected breached, site-breach, reused, weak, 2fa, or passkey)"
        )
    })
}

pub async fn run(
    paths: &Paths,
    vault: Option<String>,
    passphrase_stdin: bool,
    args: HealthArgs,
) -> Result<ExitCode> {
    match args.command {
        Some(HealthCommand::Ignore { item, kind }) => {
            let kind = parse_kind(&kind)?;
            let query: Vec<String> = item.split_whitespace().map(String::from).collect();
            let cmd = Command::HealthIgnore {
                vault,
                query,
                kind,
                ignored: true,
            };
            let Reply::Health { .. } = crate::request(paths, cmd, passphrase_stdin).await? else {
                bail!("unexpected reply");
            };
            println!("ignored {} warning on {item}", kind.as_str());
            Ok(ExitCode::SUCCESS)
        }
        Some(HealthCommand::Unignore { item, kind }) => {
            let kind = parse_kind(&kind)?;
            let query: Vec<String> = item.split_whitespace().map(String::from).collect();
            let cmd = Command::HealthIgnore {
                vault,
                query,
                kind,
                ignored: false,
            };
            let Reply::Health { .. } = crate::request(paths, cmd, passphrase_stdin).await? else {
                bail!("unexpected reply");
            };
            println!("restored {} warning on {item}", kind.as_str());
            Ok(ExitCode::SUCCESS)
        }
        Some(HealthCommand::Breaches { action }) => match action.as_deref().unwrap_or("status") {
            "status" => {
                let enabled = Config::load(&paths.config)?.breach_checks();
                println!(
                    "breach checks: {}",
                    if enabled {
                        "on (5-char SHA-1 prefixes via api.pwnedpasswords.com with padding)"
                    } else {
                        "off (offline checks only)"
                    }
                );
                Ok(ExitCode::SUCCESS)
            }
            mode @ ("on" | "off") => {
                let enabled = mode == "on";
                if deadbolt_client::status(paths)
                    .await
                    .is_some_and(|st| st.unlocked)
                {
                    let cmd = Command::BreachChecksSet { enabled };
                    let _ = crate::request(paths, cmd, passphrase_stdin).await?;
                } else {
                    set_breach_checks(&paths.config, enabled)?;
                }
                println!("breach checks: {mode}");
                Ok(ExitCode::SUCCESS)
            }
            _ => unreachable!(),
        },
        None => {
            let target = if args.all_vaults {
                Some("*".to_owned())
            } else {
                vault
            };
            let cmd = Command::Health {
                vault: target,
                online: args.online,
            };
            let Reply::Health { mut report } = crate::request(paths, cmd, passphrase_stdin).await?
            else {
                bail!("unexpected reply");
            };
            let show_ignored = args.only.iter().any(|k| k == "ignored");
            let filter_kinds: Vec<FindingKind> = args
                .only
                .iter()
                .filter(|k| k.as_str() != "ignored")
                .map(|k| parse_kind(k))
                .collect::<Result<_>>()?;

            filter_report(&mut report, args.all, &filter_kinds, show_ignored);

            if args.json {
                println!("{}", serde_json::to_string(&report)?);
            } else {
                print_report(&report, args.all || !filter_kinds.is_empty(), show_ignored);
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn filter_report(
    report: &mut HealthReport,
    include_upgrades: bool,
    only: &[FindingKind],
    show_ignored: bool,
) {
    let keep_finding = |f: &Finding| {
        if !only.is_empty() {
            only.contains(&f.kind())
        } else if include_upgrades {
            true
        } else {
            f.kind().is_risk()
        }
    };
    report.items.retain_mut(|item| {
        if show_ignored && only.is_empty() {
            item.findings.clear();
            !item.ignored.is_empty()
        } else {
            item.findings.retain(keep_finding);
            if !show_ignored {
                item.ignored.clear();
            }
            !item.findings.is_empty() || (show_ignored && !item.ignored.is_empty())
        }
    });
}

fn print_report(report: &HealthReport, show_upgrades: bool, show_ignored: bool) {
    let c = &report.counts;
    let mut parts = Vec::new();
    if c.breached > 0 {
        parts.push(format!("{} breached", c.breached));
    }
    if c.site_breach > 0 {
        parts.push(format!("{} site breach", c.site_breach));
    }
    if c.reused > 0 {
        parts.push(format!("{} reused", c.reused));
    }
    if c.weak > 0 {
        parts.push(format!("{} weak", c.weak));
    }
    if show_upgrades {
        if c.missing_two_factor > 0 {
            parts.push(format!("{} missing 2FA", c.missing_two_factor));
        }
        if c.passkeys_available > 0 {
            parts.push(format!("{} passkey available", c.passkeys_available));
        }
    }
    if show_ignored && c.ignored > 0 {
        parts.push(format!("{} ignored", c.ignored));
    }

    if parts.is_empty() && report.items.is_empty() {
        println!("no password health issues found");
        return;
    }
    println!("{}", parts.join(", "));
    for item in &report.items {
        print_item(item, show_ignored);
    }
}

fn print_item(item: &ItemHealth, show_ignored: bool) {
    let who = match &item.detail {
        Some(d) => format!("{} ({d})", item.label),
        None => item.label.clone(),
    };
    let short = &item.id[..item.id.len().min(8)];
    for f in &item.findings {
        println!(
            "  {short}  {:<11}  {who} · {}",
            f.kind().as_str(),
            f.summary()
        );
    }
    if show_ignored {
        for f in &item.ignored {
            println!(
                "  {short}  {:<11}  {who} · {} (ignored)",
                f.kind().as_str(),
                f.summary()
            );
        }
    }
}
