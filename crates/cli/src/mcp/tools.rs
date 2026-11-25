//! The tools `deadbolt mcp` offers: daemon and vault status, vault and item
//! listings, a credential health summary and `deadbolt run --broker`
//! commands. Each asks the daemon only for what carries no values; [`ask`]
//! refuses anything else before it is sent.

use serde_json::{Map, Value, json};

use super::RpcError;
use crate::client;
use crate::paths::Paths;
use crate::protocol::{Command, ErrorCode, ItemInfo, Reference, Reply, VaultInfo, noun};
use deadbolt_core::item::schema;
use deadbolt_core::listing::primary_field;

/// One tool as `tools/list` shows it.
struct Spec {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    /// Each argument: its name, JSON type and description.
    arguments: &'static [(&'static str, &'static str, &'static str)],
    required: &'static [&'static str],
}

const VAULT: (&str, &str, &str) = (
    "vault",
    "string",
    "Vault name or id (default: this device's default vault).",
);

/// Every tool. None returns a secret value: the schema test in `tests.rs`
/// holds each one to that.
const TOOLS: [Spec; 5] = [
    Spec {
        name: "deadbolt_status",
        title: "Deadbolt status",
        description: "Whether Deadbolt's daemon is running and the store locked, its version, \
how many vaults it holds and this device's name. Works while locked. Never returns secret values.",
        arguments: &[],
        required: &[],
    },
    Spec {
        name: "deadbolt_list_vaults",
        title: "List vaults",
        description: "The vaults on this device: name, id, how many devices share each, and \
which is the default. Needs the store unlocked. Never returns secret values.",
        arguments: &[],
        required: &[],
    },
    Spec {
        name: "deadbolt_list_items",
        title: "List items",
        description: "Items in a vault: id, title, type, tags, the username or other \
non-secret detail, the names of the item type's fields, and a deadbolt:// reference to \
its main field for deadbolt run and deadbolt_broker_hint. Field values are never returned. \
Needs the store unlocked.",
        arguments: &[
            VAULT,
            (
                "query",
                "string",
                "Words that must all match an item's title, username or site.",
            ),
            (
                "kind",
                "string",
                "Only items of this type: login, api, ssh, note, card, database, server…",
            ),
            ("tag", "string", "Only items with this tag."),
            ("limit", "integer", "At most this many items (default 200)."),
        ],
        required: &[],
    },
    Spec {
        name: "deadbolt_health_summary",
        title: "Credential health",
        description: "Counts of weak, reused and breached items, and each flagged item by \
title and id with what was found. Offline checks only. Never returns secret values or hashes. \
Needs the store unlocked.",
        arguments: &[
            (
                "vault",
                "string",
                "Vault name or id, or \"*\" for every vault (default: the default vault).",
            ),
            (
                "include_upgrades",
                "boolean",
                "Also list sites that support authenticator codes or passkeys.",
            ),
        ],
        required: &[],
    },
    Spec {
        name: "deadbolt_broker_hint",
        title: "Broker command",
        description: "A deadbolt run --broker command that lets a program call an HTTP API \
with a vault credential it never holds: the program gets a placeholder and a local URL, and \
Deadbolt's broker adds the real credential on the way out. Give the item and a known service \
(openai, anthropic) or the API's https upstream URL. Ask the person to run the command; never \
ask them for the credential itself.",
        arguments: &[
            ("item", "string", "The item's title or short id."),
            VAULT,
            (
                "field",
                "string",
                "The item's field to send (default: the item type's main field).",
            ),
            (
                "service",
                "string",
                "A known API: openai or anthropic. Sets the upstream and variables.",
            ),
            (
                "upstream",
                "string",
                "The API's base URL, https (for a service Deadbolt doesn't know).",
            ),
            (
                "env",
                "string",
                "The variable the program takes its API key from.",
            ),
            (
                "base_env",
                "string",
                "The variable the program takes the API's base URL from.",
            ),
            (
                "header",
                "string",
                "Send the credential bare in this header instead of Authorization: Bearer.",
            ),
            ("command", "string", "The program to run, after --."),
        ],
        required: &["item"],
    },
];

/// The daemon commands a tool may send: none of them carries a value back.
pub(super) fn value_free(command: &Command) -> bool {
    matches!(
        command,
        Command::Status
            | Command::VaultList
            | Command::ItemList { deleted: false, .. }
            | Command::Health { online: false, .. }
    )
}

/// `tools/list`'s tools.
pub(super) fn list() -> Vec<Value> {
    TOOLS
        .iter()
        .map(|spec| {
            let properties: Map<String, Value> = spec
                .arguments
                .iter()
                .map(|(name, kind, description)| {
                    (
                        (*name).to_string(),
                        json!({ "type": kind, "description": description }),
                    )
                })
                .collect();
            json!({
                "name": spec.name,
                "title": spec.title,
                "description": spec.description,
                "inputSchema": {
                    "type": "object",
                    "properties": properties,
                    "required": spec.required,
                    "additionalProperties": false,
                },
                "annotations": {
                    "title": spec.title,
                    "readOnlyHint": true,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": false,
                },
            })
        })
        .collect()
}

/// Why a tool call failed: bad arguments (a JSON-RPC error), or the daemon
/// (a tool result with `isError`, so the agent can tell the person).
pub(super) enum Failure {
    Params(String),
    Daemon { code: &'static str, message: String },
}

impl From<RpcError> for Failure {
    fn from(error: RpcError) -> Self {
        Failure::Params(error.message)
    }
}

/// Runs tool `name`. An unknown tool or bad arguments are a JSON-RPC error.
pub(super) async fn call(paths: &Paths, name: &str, arguments: &Value) -> Result<Value, RpcError> {
    let Some(spec) = TOOLS.iter().find(|spec| spec.name == name) else {
        return Err(RpcError::invalid_params(format!("no tool {name:?}")));
    };
    let args = Args::check(spec, arguments)?;
    let outcome = match spec.name {
        "deadbolt_status" => status(paths).await,
        "deadbolt_list_vaults" => vaults(paths).await,
        "deadbolt_list_items" => items(paths, &args).await,
        "deadbolt_health_summary" => health(paths, &args).await,
        "deadbolt_broker_hint" => super::hint::broker_hint(paths, &args).await,
        _ => unreachable!("every tool has a handler"),
    };
    let (structured, is_error) = match outcome {
        Ok(value) => (value, false),
        Err(Failure::Params(message)) => return Err(RpcError::invalid_params(message)),
        Err(Failure::Daemon { code, message }) => {
            (json!({ "error": code, "message": message }), true)
        }
    };
    let text = serde_json::to_string_pretty(&structured).unwrap_or_default();
    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": structured,
        "isError": is_error,
    }))
}

/// A call's arguments, checked against its tool's schema.
pub(super) struct Args<'a>(&'a Map<String, Value>);

impl<'a> Args<'a> {
    fn check(spec: &Spec, arguments: &'a Value) -> Result<Self, RpcError> {
        let Some(map) = arguments.as_object() else {
            return Err(RpcError::invalid_params("arguments must be an object"));
        };
        for (key, value) in map {
            let Some((_, kind, _)) = spec.arguments.iter().find(|(name, ..)| name == key) else {
                return Err(RpcError::invalid_params(format!(
                    "{} takes no argument {key:?}",
                    spec.name
                )));
            };
            let ok = match *kind {
                "string" => value.is_string(),
                "boolean" => value.is_boolean(),
                "integer" => value.as_u64().is_some(),
                _ => false,
            };
            if !ok && !value.is_null() {
                return Err(RpcError::invalid_params(format!("{key} must be a {kind}")));
            }
        }
        for required in spec.required {
            if map.get(*required).and_then(Value::as_str).is_none() {
                return Err(RpcError::invalid_params(format!(
                    "{} needs {required}",
                    spec.name
                )));
            }
        }
        Ok(Self(map))
    }

    /// A string argument, `None` when absent or blank.
    pub(super) fn string(&self, key: &str) -> Option<String> {
        self.0
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
    }

    fn flag(&self, key: &str) -> bool {
        self.0.get(key).and_then(Value::as_bool).unwrap_or(false)
    }

    fn number(&self, key: &str) -> Option<u64> {
        self.0.get(key).and_then(Value::as_u64)
    }
}

/// Sends a value-free `command` to the running daemon, never starting it.
pub(super) async fn ask(paths: &Paths, command: Command) -> Result<Reply, Failure> {
    if !value_free(&command) {
        return Err(Failure::Daemon {
            code: "forbidden",
            message: format!("deadbolt mcp never sends {}", command.name()),
        });
    }
    client::call(paths, command, |event| {
        Err(anyhow::anyhow!("unexpected event {event:?}"))
    })
    .await
    .map_err(daemon_failure)
}

fn daemon_failure(error: anyhow::Error) -> Failure {
    let (code, message) = match client::code(&error) {
        Some(ErrorCode::Locked) => (
            "locked",
            "The store is locked. Ask the person to run `deadbolt unlock`, then try again.".into(),
        ),
        Some(ErrorCode::NotInitialized) => (
            "not-set-up",
            "Deadbolt isn't set up on this device. Ask the person to run `deadbolt init`.".into(),
        ),
        Some(code) => (code.name(), format!("{error:#}")),
        None if error
            .downcast_ref::<deadbolt_client::Error>()
            .is_some_and(|e| matches!(e, deadbolt_client::Error::Connect(_))) =>
        {
            (
                "not-running",
                "Deadbolt's daemon isn't running. Ask the person to run `deadbolt unlock`, \
then try again."
                    .into(),
            )
        }
        None => ("failed", format!("{error:#}")),
    };
    Failure::Daemon { code, message }
}

fn unexpected() -> Failure {
    Failure::Daemon {
        code: "failed",
        message: "unexpected reply from the daemon".into(),
    }
}

async fn status(paths: &Paths) -> Result<Value, Failure> {
    let Some(status) = client::status(paths).await else {
        let running = client::running(paths).await;
        return Ok(json!({
            "running": running.is_some(),
            "state": if running.is_some() { "incompatible" } else { "stopped" },
            "version": client::version(),
            "daemon_version": running.map(|d| d.version),
            "hint": "Ask the person to run `deadbolt unlock`, which starts the daemon.",
        }));
    };
    let state = if !status.initialized {
        "not set up"
    } else if status.unlocked {
        "unlocked"
    } else {
        "locked"
    };
    Ok(json!({
        "running": true,
        "state": state,
        "initialized": status.initialized,
        "unlocked": status.unlocked,
        "locks_in_secs": status.locks_in_secs,
        "version": client::version(),
        "daemon_version": status.version,
        "vault_count": status.unlocked.then_some(status.vaults.len()),
        "default_vault": status.vaults.iter().find(|v| v.default).map(|v| &v.name),
        "device": status.device.as_ref().map(|d| json!({
            "name": d.name,
            "id": short(&d.id),
        })),
        "devices": status.peers,
        "devices_online": status.peers_online,
        "touch_id_ready": status.touch_id_ready,
        "update_available": status.update.as_ref().map(|u| &u.version),
    }))
}

pub(super) async fn vault_list(paths: &Paths) -> Result<Vec<VaultInfo>, Failure> {
    let Reply::Vaults { vaults } = ask(paths, Command::VaultList).await? else {
        return Err(unexpected());
    };
    Ok(vaults)
}

async fn vaults(paths: &Paths) -> Result<Value, Failure> {
    let vaults = vault_list(paths).await?;
    let vaults: Vec<Value> = vaults
        .iter()
        .map(|v| {
            json!({
                "name": v.name,
                "id": v.id,
                "default": v.default,
                "devices": v.members,
                "member": v.member,
                "unavailable": v.error,
            })
        })
        .collect();
    Ok(json!({ "vaults": vaults }))
}

/// The vault a reference should name: `vault` (a name or id) by its name,
/// else the default vault's name; `None` to leave it out.
pub(super) async fn reference_vault(paths: &Paths, vault: Option<&str>) -> Option<String> {
    let vaults = vault_list(paths).await.ok()?;
    let found = match vault {
        Some(asked) => vaults
            .iter()
            .find(|v| v.name == asked || v.id == asked)
            .or_else(|| vaults.iter().find(|v| v.id.starts_with(asked))),
        None => vaults.iter().find(|v| v.default),
    };
    let name = found.map_or_else(|| vault.map(String::from), |v| Some(v.name.clone()))?;
    // A comma would end a --route value: name such a vault by id.
    Some(match found {
        Some(v) if name.contains(',') => v.id.clone(),
        _ => name,
    })
}

/// Lists items (`ItemList` carries no field values).
pub(super) async fn item_list(
    paths: &Paths,
    vault: Option<String>,
    query: &str,
    kind: Option<String>,
    tag: Option<String>,
) -> Result<Vec<ItemInfo>, Failure> {
    let command = Command::ItemList {
        vault,
        query: query.split_whitespace().map(String::from).collect(),
        kind,
        deleted: false,
        tags: tag.into_iter().collect(),
        favorites: false,
    };
    let Reply::Items { items } = ask(paths, command).await? else {
        return Err(unexpected());
    };
    Ok(items)
}

const DEFAULT_LIMIT: u64 = 200;

async fn items(paths: &Paths, args: &Args<'_>) -> Result<Value, Failure> {
    let vault = args.string("vault");
    let items = item_list(
        paths,
        vault.clone(),
        &args.string("query").unwrap_or_default(),
        args.string("kind"),
        args.string("tag"),
    )
    .await?;
    let in_vault = reference_vault(paths, vault.as_deref()).await;
    let limit =
        usize::try_from(args.number("limit").unwrap_or(DEFAULT_LIMIT)).unwrap_or(usize::MAX);
    let listed: Vec<Value> = items
        .iter()
        .take(limit)
        .map(|item| {
            let name = reference_name(item, &items);
            json!({
                "id": item.id,
                "short": item.short,
                "title": item.label,
                "kind": item.kind,
                "type": noun(&item.kind, 1),
                "detail": item.detail,
                "tags": item.tags,
                "favorite": item.favorite,
                "fields": schema(&item.kind)
                    .map(|s| s.fields.iter().map(|f| f.name).collect::<Vec<_>>())
                    .unwrap_or_default(),
                "reference": primary_field(&item.kind).map(|field| reference(in_vault.as_deref(), name, field)),
            })
        })
        .collect();
    Ok(json!({
        "vault": in_vault,
        "count": items.len(),
        "truncated": items.len() > listed.len(),
        "items": listed,
        "note": "fields lists the item type's field names; an item may lack some or have \
    others. A reference is deadbolt://vault/item/field.",
    }))
}

/// How a reference names `item`: its title, unless another of `items` has
/// the same one or a comma would end a --route value, then its short id.
pub(super) fn reference_name<'a>(item: &'a ItemInfo, items: &[ItemInfo]) -> &'a str {
    let shared = items
        .iter()
        .filter(|other| other.label.eq_ignore_ascii_case(&item.label))
        .count()
        > 1;
    if shared || item.label.contains(',') {
        &item.short
    } else {
        &item.label
    }
}

pub(super) fn reference(vault: Option<&str>, item: &str, field: &str) -> String {
    Reference {
        vault: vault.map(String::from),
        item: item.into(),
        field: field.into(),
    }
    .to_string()
}

async fn health(paths: &Paths, args: &Args<'_>) -> Result<Value, Failure> {
    let command = Command::Health {
        vault: args.string("vault"),
        online: false,
    };
    let Reply::Health { report } = ask(paths, command).await? else {
        return Err(unexpected());
    };
    let upgrades = args.flag("include_upgrades");
    let items: Vec<Value> = report
        .items
        .iter()
        .filter_map(|item| {
            let findings: Vec<Value> = item
                .findings
                .iter()
                .filter(|f| upgrades || f.kind().is_risk())
                .map(|f| json!({ "kind": f.kind().as_str(), "summary": f.summary() }))
                .collect();
            (!findings.is_empty()).then(|| {
                json!({
                    "id": item.id,
                    "short": short(&item.id),
                    "title": item.label,
                    "vault": item.vault_name,
                    "kind": item.kind,
                    "detail": item.detail,
                    "site": item.site_url,
                    "risk": item.risk,
                    "findings": findings,
                })
            })
        })
        .collect();
    Ok(json!({
        "counts": report.counts,
        "breach_checks_enabled": report.breach_checks_enabled,
        "items": items,
    }))
}

fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}
