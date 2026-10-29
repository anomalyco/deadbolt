//! `deadbolt agents`: the agent clients (such as Browse's relay) that may
//! sign AI agents in to sites unattended, the standing grants saying where
//! (`docs/agent-control.md`, "Standing grants"), and the grants letting AI
//! agents use secrets in commands (`deadbolt run`, `inject`).

use std::io::IsTerminal;

use anyhow::{Result, anyhow, bail};
use clap::Subcommand;
use zeroize::Zeroizing;

use crate::paths::Paths;
use crate::protocol::{
    AgentClientInfo, AgentGrantInfo, Command, ErrorCode, Fill, Purpose, Reply, SecretGrantInfo,
};
use crate::{client, config, prompt, request};

#[derive(Subcommand)]
pub enum AgentsCommand {
    /// Pair an agent client, such as Browse (`opencode-browser deadbolt
    /// connect` runs this). Asks for Touch ID or your passphrase; refused
    /// to AI agents. Prints its id and token, shown only now.
    AddClient {
        name: String,
        /// One JSON object: {"id", "name", "token"}.
        #[arg(long)]
        json: bool,
    },
    /// List the paired agent clients.
    Clients {
        #[arg(long)]
        json: bool,
    },
    /// Unpair an agent client (by id or name) and drop its grants.
    RemoveClient { client: String },
    /// Let an agent client sign in to SITE (a domain, or an exact origin
    /// such as https://app.example.com), or with --all to every site,
    /// without asking: usernames, passwords, one-time codes and passkeys
    /// unless narrowed. A login still fills only on the site of its URLs.
    /// Asks for Touch ID or your passphrase; refused to AI agents.
    Allow {
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        site: Option<String>,
        /// Every login on every site.
        #[arg(long, conflicts_with = "login")]
        all: bool,
        /// Only this login (its id, username or title), else every login
        /// for the site.
        #[arg(long)]
        login: Option<String>,
        /// What it may fill: username, password, totp, comma separated, or
        /// none (default: all three).
        #[arg(long)]
        fields: Option<String>,
        /// Don't sign in with the site's passkeys (by default it may, with
        /// user presence and never verification).
        #[arg(long)]
        no_passkeys: bool,
        /// Expire after this long (30m, 8h, 30d; default never).
        #[arg(long)]
        expires: Option<String>,
        /// The agent client (id or name); needed when several are paired.
        #[arg(long)]
        client: Option<String>,
    },
    /// Let AI agents use ITEMs (titles or short ids, in --vault) in
    /// `deadbolt run` and `deadbolt inject` without asking. Never `deadbolt
    /// read`: an AI reading a value needs Touch ID each time. Asks for
    /// Touch ID or your passphrase; refused to AI agents.
    AllowSecrets {
        #[arg(required = true, value_name = "ITEM")]
        items: Vec<String>,
        /// Only these fields, comma separated (default: every field).
        #[arg(long)]
        fields: Option<String>,
        /// What for: run, inject; repeat for both (default: both).
        #[arg(long, value_enum)]
        purpose: Vec<GrantPurpose>,
        /// Expire after this long (30m, 8h, 30d; default never).
        #[arg(long)]
        expires: Option<String>,
    },
    /// List the standing grants: sign-ins and secrets.
    Grants {
        #[arg(long)]
        json: bool,
    },
    /// Remove a standing grant (either kind) by id.
    Revoke { id: String },
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum GrantPurpose {
    Run,
    Inject,
}

pub async fn run(
    paths: &Paths,
    command: AgentsCommand,
    vault: Option<String>,
    from_stdin: bool,
) -> Result<()> {
    if vault.is_some() && !matches!(command, AgentsCommand::AllowSecrets { .. }) {
        bail!("--vault does not apply to this command");
    }
    client::ensure_running(paths).await?;
    match command {
        AgentsCommand::AddClient { name, json } => {
            let reply = with_proof(paths, from_stdin, |passphrase| Command::AgentClientAdd {
                name: name.clone(),
                passphrase,
            })
            .await?;
            let Reply::AgentClientAdded { client, token } = reply else {
                bail!("unexpected reply");
            };
            if json {
                let out = serde_json::json!({
                    "id": client.id, "name": client.name, "token": token.expose(),
                });
                println!("{out}");
            } else {
                println!("paired agent client {} ({})", client.name, client.id);
                println!("token\t{}", token.expose());
                eprintln!("The token is shown only now. Anyone with it can use what you allow.");
            }
        }
        AgentsCommand::Clients { json } => {
            for client in clients(paths, from_stdin).await? {
                if json {
                    println!("{}", serde_json::to_string(&client)?);
                } else {
                    let used = client.last_used.map_or_else(
                        || "never used".into(),
                        |t| format!("used {}", crate::ago(t)),
                    );
                    println!(
                        "{}\t{}\tpaired {}\t{used}",
                        client.id,
                        client.name,
                        crate::ago(client.created)
                    );
                }
            }
        }
        AgentsCommand::RemoveClient { client } => {
            let id = client_id(paths, Some(&client), from_stdin).await?;
            let command = Command::AgentClientRemove { id: id.clone() };
            request(paths, command, from_stdin).await?;
            println!("removed agent client {id}");
        }
        AgentsCommand::Allow {
            site,
            all,
            login,
            fields,
            no_passkeys,
            expires,
            client,
        } => {
            let site = if all { None } else { site };
            let passkeys = !no_passkeys;
            let client_id = client_id(paths, client.as_deref(), from_stdin).await?;
            let fields = parse_fields(fields.as_deref())?;
            let expires_at = match expires {
                Some(text) => config::parse_timeout(&text)?.map(|d| config::now() + d.as_secs()),
                None => None,
            };
            let reply = with_proof(paths, from_stdin, |passphrase| Command::AgentGrantSet {
                client_id: client_id.clone(),
                site: site.clone(),
                login: login.clone(),
                fields: fields.clone(),
                passkeys,
                expires_at,
                passphrase,
            })
            .await?;
            let Reply::AgentGrant { grant } = reply else {
                bail!("unexpected reply");
            };
            println!("allowed\t{}", grant_line(&grant));
        }
        AgentsCommand::AllowSecrets {
            items,
            fields,
            purpose,
            expires,
        } => {
            let fields: Vec<String> = match fields {
                Some(text) => text.split(',').map(|f| f.trim().to_string()).collect(),
                None => Vec::new(),
            };
            let purposes: Vec<Purpose> = if purpose.is_empty() {
                vec![Purpose::Run, Purpose::Inject]
            } else {
                purpose
                    .iter()
                    .map(|p| match p {
                        GrantPurpose::Run => Purpose::Run,
                        GrantPurpose::Inject => Purpose::Inject,
                    })
                    .collect()
            };
            let expires_at = match expires {
                Some(text) => config::parse_timeout(&text)?.map(|d| config::now() + d.as_secs()),
                None => None,
            };
            let reply = with_proof(paths, from_stdin, |passphrase| Command::SecretGrantSet {
                vault: vault.clone(),
                items: items.clone(),
                fields: fields.clone(),
                purposes: purposes.clone(),
                expires_at,
                passphrase,
            })
            .await?;
            let Reply::SecretGrants { grants } = reply else {
                bail!("unexpected reply");
            };
            for grant in &grants {
                println!("allowed\t{}", secret_grant_line(grant));
            }
        }
        AgentsCommand::Grants { json } => {
            let Reply::AgentGrants { grants } =
                request(paths, Command::AgentGrantList, from_stdin).await?
            else {
                bail!("unexpected reply");
            };
            let Reply::SecretGrants { grants: secrets } =
                request(paths, Command::SecretGrantList, from_stdin).await?
            else {
                bail!("unexpected reply");
            };
            for grant in &grants {
                if json {
                    println!("{}", serde_json::to_string(grant)?);
                } else {
                    println!("{}", grant_line(grant));
                }
            }
            for grant in &secrets {
                if json {
                    println!("{}", serde_json::to_string(grant)?);
                } else {
                    println!("{}", secret_grant_line(grant));
                }
            }
        }
        AgentsCommand::Revoke { id } => {
            let command = Command::AgentGrantRemove { id: id.clone() };
            request(paths, command, from_stdin).await?;
            println!("revoked {id}");
        }
    }
    Ok(())
}

/// Sends a request that needs the user: with the passphrase from stdin
/// (`--passphrase-stdin`), else with Touch ID raised by the agent when it is
/// on, else with the passphrase typed on the terminal. Never
/// `DEADBOLT_PASSPHRASE`: an AI's shell inherits it.
async fn with_proof(
    paths: &Paths,
    from_stdin: bool,
    command: impl Fn(Option<Zeroizing<String>>) -> Command,
) -> Result<Reply> {
    if from_stdin {
        let passphrase = prompt::passphrase(true, false)?;
        return request(paths, command(Some(passphrase)), false).await;
    }
    let terminal = || -> Result<Zeroizing<String>> {
        if !std::io::stderr().is_terminal() {
            bail!("this needs your passphrase on a terminal, or --passphrase-stdin");
        }
        let passphrase = Zeroizing::new(rpassword::prompt_password("passphrase: ")?);
        if passphrase.is_empty() {
            bail!("the passphrase cannot be empty");
        }
        Ok(passphrase)
    };
    let status = client::ensure_running(paths).await?;
    if status.touch_id_available && status.touch_id_enabled {
        match request(paths, command(None), false).await {
            Err(error)
                if client::code(&error) == Some(ErrorCode::Failed)
                    && format!("{error:#}").contains("needs your passphrase") => {}
            result => return result,
        }
    }
    request(paths, command(Some(terminal()?)), false).await
}

async fn clients(paths: &Paths, from_stdin: bool) -> Result<Vec<AgentClientInfo>> {
    let Reply::AgentClients { clients } =
        request(paths, Command::AgentClientList, from_stdin).await?
    else {
        bail!("unexpected reply");
    };
    Ok(clients)
}

/// The client `query` names (an id, a unique id prefix or a name), else the
/// only one paired.
async fn client_id(paths: &Paths, query: Option<&str>, from_stdin: bool) -> Result<String> {
    let all = clients(paths, from_stdin).await?;
    let found: Vec<&AgentClientInfo> = match query {
        Some(query) => {
            let lower = query.trim().to_lowercase();
            let by_id: Vec<&AgentClientInfo> = all
                .iter()
                .filter(|c| c.id == lower || (lower.len() >= 4 && c.id.starts_with(&lower)))
                .collect();
            if by_id.is_empty() {
                all.iter()
                    .filter(|c| c.name.to_lowercase() == lower)
                    .collect()
            } else {
                by_id
            }
        }
        None => all.iter().collect(),
    };
    match (found.as_slice(), query) {
        ([client], _) => Ok(client.id.clone()),
        ([], Some(query)) => bail!("no agent client {query}; see `deadbolt agents clients`"),
        ([], None) => {
            bail!("no agent client is paired; pair one with `deadbolt agents add-client`")
        }
        (_, _) => bail!("several agent clients match: pass --client with an id"),
    }
}

fn parse_fields(text: Option<&str>) -> Result<Vec<Fill>> {
    let Some(text) = text else {
        return Ok(vec![Fill::Username, Fill::Password, Fill::Totp]);
    };
    if text.trim() == "none" {
        return Ok(Vec::new());
    }
    text.split(',')
        .map(|f| match f.trim() {
            "username" => Ok(Fill::Username),
            "password" => Ok(Fill::Password),
            "totp" | "otp" | "code" => Ok(Fill::Totp),
            other => Err(anyhow!(
                "unknown field '{other}' (username, password, totp or none)"
            )),
        })
        .collect()
}

fn fill_name(fill: Fill) -> &'static str {
    match fill {
        Fill::Username => "username",
        Fill::Password => "password",
        Fill::Totp => "totp",
    }
}

/// "a1b2…  browse  github.com  kit  username,password,passkeys  expires in 29d".
fn grant_line(grant: &AgentGrantInfo) -> String {
    let mut what: Vec<&str> = grant.fields.iter().map(|f| fill_name(*f)).collect();
    if grant.passkeys {
        what.push("passkeys");
    }
    let expires = expiry(grant.expires_at, grant.expired);
    format!(
        "{}\t{}\t{}\t{}\t{}\t{expires}",
        grant.id,
        grant.client_name.as_deref().unwrap_or(&grant.client_id),
        grant.site.as_deref().unwrap_or("every site"),
        grant.login_label.as_deref().unwrap_or("every login"),
        what.join(",")
    )
}

/// "expires in 29d", "expired", "never expires".
fn expiry(expires_at: Option<u64>, expired: bool) -> String {
    match expires_at {
        _ if expired => "expired".to_string(),
        Some(at) => {
            let left = at.saturating_sub(config::now());
            match left {
                0..3600 => format!("expires in {}m", left.div_ceil(60)),
                3600..86400 => format!("expires in {}h", left / 3600),
                _ => format!("expires in {}d", left / 86400),
            }
        }
        None => "never expires".into(),
    }
}

/// "c3d4…  AI agents  personal › GitHub  token  run,inject  never expires".
fn secret_grant_line(grant: &SecretGrantInfo) -> String {
    let fields = if grant.fields.is_empty() {
        "every field".to_string()
    } else {
        grant.fields.join(",")
    };
    let purposes: Vec<&str> = grant.purposes.iter().map(|p| p.as_str()).collect();
    format!(
        "{}\tAI agents\t{} › {}\t{fields}\t{}\t{}",
        grant.id,
        grant.vault,
        grant.title,
        purposes.join(","),
        expiry(grant.expires_at, grant.expired)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_parse_strictly() {
        assert_eq!(
            parse_fields(None).unwrap(),
            [Fill::Username, Fill::Password, Fill::Totp]
        );
        assert_eq!(
            parse_fields(Some("password, otp")).unwrap(),
            [Fill::Password, Fill::Totp]
        );
        assert!(parse_fields(Some("none")).unwrap().is_empty());
        assert!(parse_fields(Some("passwd")).is_err());
    }
}
