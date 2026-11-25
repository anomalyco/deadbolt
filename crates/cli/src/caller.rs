//! Who this CLI is to the daemon (`deadbolt debug whoami`), what callers did
//! (`deadbolt activity`), and the check every command starts with: that the
//! daemon is this binary before a passphrase goes to it.

use std::path::PathBuf;

use anyhow::{Result, bail};
use deadbolt_client::peer;

use crate::config;
use crate::paths::Paths;
use crate::protocol::{ActivityEntry, CallerInfo, Check, Command, Outcome, Reply, Signature};

/// Checks the daemon before sending it a passphrase.
pub fn install() {
    deadbolt_client::set_daemon_check(Box::new(|socket| {
        let exe = own_exe().map_err(|e| format!("locating this binary: {e}"))?;
        peer::check(&socket, &exe).map(drop)
    }));
}

/// This binary, with symlinks resolved: the installed command links to the
/// app bundle's helper.
pub fn own_exe() -> std::io::Result<PathBuf> {
    std::env::current_exe().and_then(std::fs::canonicalize)
}

pub async fn whoami(paths: &Paths, json: bool) -> Result<()> {
    let status = crate::client::ensure_running(paths).await?;
    let caller = status.caller;
    if json {
        println!("{}", serde_json::to_string_pretty(&caller)?);
        return Ok(());
    }
    for (key, value) in whoami_lines(&caller) {
        println!("{key}\t{value}");
    }
    Ok(())
}

fn whoami_lines(caller: &CallerInfo) -> Vec<(&'static str, String)> {
    let mut lines = vec![
        ("caller", caller.label.clone()),
        ("class", kebab(&caller.class)),
        ("identified", caller.identified.to_string()),
        (
            "reason",
            caller.reason.clone().unwrap_or_else(|| {
                if caller.identified {
                    "live peer"
                } else {
                    "no identification recorded"
                }
                .into()
            }),
        ),
        ("checked", check(caller.check).into()),
        ("pid", caller.pid.to_string()),
    ];
    if let Some(program) = &caller.program {
        lines.push(("program", program.clone()));
    }
    if let Some(signature) = &caller.signature {
        lines.push(("signature", signed(signature)));
    }
    if let Some(tty) = &caller.tty {
        lines.push(("tty", tty.clone()));
    }
    if !caller.ancestry.is_empty() {
        let names: Vec<&str> = caller.ancestry.iter().map(|a| a.name.as_str()).collect();
        lines.push(("parents", names.join(" ‹ ")));
    }
    lines
}

fn check(check: Check) -> &'static str {
    match check {
        Check::Signature => "code signature",
        Check::Unverified => crate::protocol::UNVERIFIED_LINUX,
        Check::None => "nothing",
    }
}

fn signed(signature: &Signature) -> String {
    let mut parts = Vec::new();
    if !signature.valid {
        parts.push("invalid".to_string());
    }
    match &signature.team_id {
        Some(team) => parts.push(format!("team {team}")),
        None => parts.push("ad-hoc or unanchored".into()),
    }
    if let Some(id) = &signature.signing_id {
        parts.push(id.clone());
    }
    if let Some(cdhash) = &signature.cdhash {
        parts.push(format!("cdhash {}", cdhash.get(..12).unwrap_or(cdhash)));
    }
    parts.join(", ")
}

/// A serde enum's name, as the protocol spells it.
fn kebab(value: &impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// `deadbolt activity` lists this many entries unless told otherwise.
const DEFAULT_LIMIT: u32 = 500;
/// The most the daemon sends in one `ActivityList`.
const PAGE: u32 = 1_000;

pub async fn activity(
    paths: &Paths,
    since: Option<String>,
    limit: Option<u32>,
    json: bool,
    from_stdin: bool,
) -> Result<()> {
    let since = match since {
        Some(text) => match config::parse_timeout(&text)? {
            Some(age) => Some(config::now().saturating_sub(age.as_secs())),
            None => bail!("--since takes a duration, like 1h or 7d"),
        },
        None => None,
    };
    crate::client::ensure_running(paths).await?;
    // The daemon sends at most a page at a time; more go back by id.
    let mut left = limit.unwrap_or(DEFAULT_LIMIT);
    let mut before = None;
    while left > 0 {
        let page = left.min(PAGE);
        let command = Command::ActivityList {
            since,
            limit: Some(page),
            before,
        };
        let Reply::Activity { entries } = crate::request(paths, command, from_stdin).await? else {
            bail!("unexpected reply");
        };
        for entry in &entries {
            if json {
                println!("{}", serde_json::to_string(entry)?);
            } else {
                println!("{}", activity_line(entry));
            }
        }
        left -= entries.len().min(left as usize) as u32;
        match entries.last() {
            Some(last) if entries.len() == page as usize => before = Some(last.id),
            _ => break,
        }
    }
    Ok(())
}

fn activity_line(entry: &ActivityEntry) -> String {
    let items: Vec<String> = entry
        .items
        .iter()
        .map(|item| match &item.vault {
            Some(vault) => format!("{vault}/{}", item.title),
            None => item.title.clone(),
        })
        .collect();
    let outcome = match entry.outcome {
        Outcome::Allowed => "",
        Outcome::Locked => "\tlocked",
        Outcome::Refused => "\trefused",
        Outcome::Failed => "\tfailed",
    };
    let more = match entry.more {
        0 => String::new(),
        n => format!("\t{n} more"),
    };
    format!(
        "{}\t{}\t{}\t{}\t{}{outcome}{more}",
        crate::ago(entry.time),
        entry.caller.label,
        entry.command,
        items.join(", "),
        entry.fields.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ActivityItem, CallerClass, Tier};

    fn caller() -> CallerInfo {
        CallerInfo {
            identified: true,
            reason: None,
            class: CallerClass::Caller,
            check: Check::Signature,
            pid: 42,
            pid_version: Some(3),
            uid: Some(501),
            program: Some("/opt/bin/deadbolt".into()),
            signature: None,
            tty: Some("/dev/ttys004".into()),
            started: None,
            session_started: None,
            ancestry: Vec::new(),
            label: "Ghostty › zsh › deadbolt".into(),
        }
    }

    #[test]
    fn whoami_names_the_caller_and_its_class() {
        let lines = whoami_lines(&caller());
        assert_eq!(lines[0], ("caller", "Ghostty › zsh › deadbolt".into()));
        assert_eq!(lines[1], ("class", "caller".into()));
        assert!(lines.contains(&("reason", "live peer".into())));
    }

    #[test]
    fn an_activity_line_names_items_and_fields() {
        let entry = ActivityEntry {
            id: 1,
            time: config::now(),
            caller: caller(),
            tier: Tier::Read,
            command: "item-get".into(),
            items: vec![ActivityItem {
                vault: Some("personal".into()),
                id: Some("i1".into()),
                title: "GitHub".into(),
            }],
            fields: vec!["username".into(), "password".into()],
            outcome: Outcome::Locked,
            more: 0,
        };
        assert_eq!(
            activity_line(&entry),
            "0s ago\tGhostty › zsh › deadbolt\titem-get\tpersonal/GitHub\tusername,password\tlocked"
        );
        let folded = ActivityEntry {
            command: "more-past-limit".into(),
            items: Vec::new(),
            fields: Vec::new(),
            outcome: Outcome::Allowed,
            more: 25,
            ..entry
        };
        assert_eq!(
            activity_line(&folded),
            "0s ago\tGhostty › zsh › deadbolt\tmore-past-limit\t\t\t25 more"
        );
    }
}
