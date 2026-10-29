//! Settings' Agents: the agent clients (such as Browse) that may sign AI
//! agents in to sites without asking, and the standing grants saying where,
//! each with Revoke. Pairing and allowing happen in a terminal (`deadbolt
//! agents`), with Touch ID or the passphrase; here they only narrow.

use deadbolt_client::Paths;
use deadbolt_client::protocol::{AgentClientInfo, AgentGrantInfo, Command, Fill, Reply};
use rune::{El, Tx, col, row, text};
use rune_kit::Kit;

use crate::agent::{Done, Failure, Job};
use crate::model::App;

/// What Revoke removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revoke {
    Client(String),
    Grant(String),
}

/// Clients and grants, as the agent lists them.
pub type Listing = (Vec<AgentClientInfo>, Vec<AgentGrantInfo>);

#[derive(Default)]
pub struct Agents {
    pub open: bool,
    pub loading: bool,
    pub clients: Vec<AgentClientInfo>,
    pub grants: Vec<AgentGrantInfo>,
    pub error: Option<String>,
    /// The list asked for: a reply to an earlier ask is dropped.
    seq: u64,
}

impl Agents {
    /// Closes the list, and drops the reply to an ask on its way.
    pub(crate) fn forget(&mut self) {
        self.seq += 1;
        *self = Agents {
            seq: self.seq,
            ..Agents::default()
        };
    }
}

impl App {
    pub fn toggle_agents(&mut self) {
        if self.agents.open {
            self.agents.forget();
        } else {
            self.agents.open = true;
            self.load_agents();
        }
    }

    fn load_agents(&mut self) {
        self.send_agents(None);
    }

    /// Something changed in the agent (pairing and grants are Activity
    /// entries): an open list asks again.
    pub(crate) fn on_agents_changed(&mut self) {
        if self.agents.open {
            self.load_agents();
        }
    }

    pub fn revoke_agent(&mut self, revoke: Revoke) {
        self.send_agents(Some(revoke));
    }

    fn send_agents(&mut self, revoke: Option<Revoke>) {
        self.agents.seq += 1;
        self.agents.loading = true;
        self.agent.send(Job::Agents {
            seq: self.agents.seq,
            revoke,
        });
    }

    pub(crate) fn on_agents(&mut self, seq: u64, result: Result<Listing, Failure>, tx: &mut Tx) {
        if !self.agents.open || seq != self.agents.seq {
            return;
        }
        self.agents.loading = false;
        match result {
            Ok((clients, grants)) => {
                self.agents.clients = clients;
                self.agents.grants = grants;
                self.agents.error = None;
            }
            Err(failure) if failure.locked() => {
                self.agents.forget();
                self.on_locked(tx);
            }
            Err(failure) => self.agents.error = Some(failure.message),
        }
    }
}

pub(crate) async fn run(paths: &Paths, seq: u64, revoke: Option<Revoke>) -> Done {
    let result: Result<Listing, Failure> = async {
        match revoke {
            Some(Revoke::Client(id)) => {
                deadbolt_client::simple(paths, Command::AgentClientRemove { id }).await?;
            }
            Some(Revoke::Grant(id)) => {
                deadbolt_client::simple(paths, Command::AgentGrantRemove { id }).await?;
            }
            None => {}
        }
        let clients = crate::agent::call(paths, Command::AgentClientList, |r| match r {
            Reply::AgentClients { clients } => Some(clients),
            _ => None,
        })
        .await?;
        let grants = crate::agent::call(paths, Command::AgentGrantList, |r| match r {
            Reply::AgentGrants { grants } => Some(grants),
            _ => None,
        })
        .await?;
        Ok((clients, grants))
    }
    .await;
    Done::Agents { seq, result }
}

fn fill_name(fill: &Fill) -> &'static str {
    match fill {
        Fill::Username => "username",
        Fill::Password => "password",
        Fill::Totp => "one-time code",
    }
}

/// "github.com · kit · username, password, passkeys · browse".
pub fn grant_line(grant: &AgentGrantInfo) -> String {
    let client = grant.client_name.as_deref().unwrap_or(&grant.client_id);
    let mut parts = match &grant.site {
        None => vec!["All logins".to_owned(), client.to_owned()],
        Some(site) => {
            let mut what: Vec<&str> = grant.fields.iter().map(fill_name).collect();
            if grant.passkeys {
                what.push("passkeys");
            }
            vec![
                site.clone(),
                grant
                    .login_label
                    .as_deref()
                    .unwrap_or("every login")
                    .to_owned(),
                what.join(", "),
                client.to_owned(),
            ]
        }
    };
    if grant.expired {
        parts.push("expired".into());
    }
    parts.join(" · ")
}

/// Settings' Agents row: its Show or Hide button, and once open, the
/// clients and grants under the row.
pub fn setting(s: &App, k: &Kit) -> (El, Option<El>) {
    let a = &s.agents;
    let button = crate::settings::button(if a.open { "Hide" } else { "Show" })
        .on_press(|s: &mut App| s.toggle_agents())
        .build(k)
        .key("agents-button");
    if !a.open {
        return (button, None);
    }
    let quiet = |key: &str, words: String, ink| {
        text(words)
            .key(key.to_owned())
            .font(k.ty.small)
            .color(ink)
            .wrap()
            .w_full()
    };
    let entry = |key: String, words: String, revoke: Revoke| {
        row()
            .key(key.clone())
            .w_full()
            // The buttons line up with the row's own.
            .pr(28.0)
            .gap(12.0)
            .center_y()
            .child(
                text(words)
                    .key("words")
                    .font(k.ty.small)
                    .color(k.c.text_base)
                    .wrap()
                    .grow(1.0)
                    .shrink()
                    .min_w(0.0),
            )
            .child(
                crate::settings::button("Revoke")
                    .on_press(move |s: &mut App| s.revoke_agent(revoke.clone()))
                    .build(k)
                    .key(format!("{key}-revoke")),
            )
    };
    let list = if let Some(error) = &a.error {
        quiet("agents-error", error.clone(), k.c.danger.fg)
    } else if a.clients.is_empty() {
        let empty = if a.loading {
            "Loading…".to_string()
        } else {
            "No agent clients. Pair one in Terminal with deadbolt agents add-client.".to_string()
        };
        quiet("agents-empty", empty, k.c.text_muted)
    } else {
        let mut rows: Vec<El> = a
            .clients
            .iter()
            .map(|c| {
                entry(
                    format!("agent-client-{}", c.id),
                    format!("{} · paired agent client", c.name),
                    Revoke::Client(c.id.clone()),
                )
            })
            .collect();
        if a.grants.is_empty() {
            rows.push(quiet(
                "grants-empty",
                "Nothing allowed yet. Allow a site in Terminal with deadbolt agents allow.".into(),
                k.c.text_muted,
            ));
        }
        rows.extend(a.grants.iter().map(|g| {
            entry(
                format!("agent-grant-{}", g.id),
                grant_line(g),
                Revoke::Grant(g.id.clone()),
            )
        }));
        col().key("agents-list").w_full().gap(6.0).children(rows)
    };
    (
        button,
        Some(col().key("agents").w_full().pb(12.0).child(list)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_line_says_where_what_and_who() {
        let grant = AgentGrantInfo {
            id: "g1".into(),
            client_id: "c1".into(),
            client_name: Some("browse".into()),
            site: Some("github.com".into()),
            login: None,
            login_label: Some("kit".into()),
            fields: vec![Fill::Username, Fill::Password],
            passkeys: true,
            created: 0,
            expires_at: None,
            expired: false,
        };
        assert_eq!(
            grant_line(&grant),
            "github.com · kit · username, password, passkeys · browse"
        );
        let site_wide = AgentGrantInfo {
            login_label: None,
            client_name: None,
            passkeys: false,
            expired: true,
            ..grant
        };
        assert_eq!(
            grant_line(&site_wide),
            "github.com · every login · username, password · c1 · expired"
        );
        let all = AgentGrantInfo {
            site: None,
            client_name: Some("browse".into()),
            expired: false,
            ..site_wide
        };
        assert_eq!(grant_line(&all), "All logins · browse");
    }
}
