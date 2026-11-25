//! `deadbolt mcp`: a Model Context Protocol server on stdin and stdout for
//! AI coding agents, that never hands out a secret value.
//!
//! JSON-RPC 2.0, one message per line (MCP's stdio transport): `initialize`,
//! `ping`, `tools/list` and `tools/call`, with notifications such as
//! `notifications/initialized` accepted and left unanswered. Its tools
//! ([`tools`]) ask the daemon only what carries no values (`status`,
//! `vault-list`, `item-list`, `health`), never `item-get`, `item-code` or
//! `resolve`, so no value ever reaches this process to leak. An agent that
//! needs a credential gets a `deadbolt run --broker` command to hand to the
//! person, which keeps the value out of the agent's process too
//! (docs/broker.md).
//!
//! It never starts the daemon or unlocks the store: a locked or stopped
//! daemon is a tool result saying so.

mod hint;
mod tools;

#[cfg(test)]
mod tests;

use anyhow::Result;
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::paths::Paths;

/// The protocol revisions this server speaks, newest first. A client asking
/// for another gets the newest.
const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// What the server tells the agent when it connects.
const INSTRUCTIONS: &str = "Deadbolt is the person's password manager. These tools show \
vault and item metadata, never values. When a command needs a credential, call \
deadbolt_broker_hint and ask the person to run the command it gives: deadbolt's broker \
then supplies the credential to that command without you seeing it. Never ask the \
person to paste a secret.";

/// A JSON-RPC error: its code and message.
#[derive(Debug)]
struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: INVALID_PARAMS,
            message: message.into(),
        }
    }
}

/// Serves MCP on this process's stdin and stdout until stdin closes.
pub async fn run(paths: &Paths) -> Result<()> {
    serve(
        paths,
        BufReader::new(tokio::io::stdin()),
        tokio::io::stdout(),
    )
    .await
}

/// Serves MCP on `reader` and `writer` until `reader` ends.
pub async fn serve(
    paths: &Paths,
    reader: impl AsyncBufRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
) -> Result<()> {
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(reply) = answer(paths, &line).await {
            let mut out = serde_json::to_vec(&reply)?;
            out.push(b'\n');
            writer.write_all(&out).await?;
            writer.flush().await?;
        }
    }
    Ok(())
}

/// The reply to one line, or `None` for a notification or a client's
/// response.
async fn answer(paths: &Paths, line: &str) -> Option<Value> {
    let Ok(message) = serde_json::from_str::<Value>(line) else {
        return Some(failure(Value::Null, PARSE_ERROR, "parse error"));
    };
    let Some(message) = message.as_object() else {
        return Some(failure(
            Value::Null,
            INVALID_REQUEST,
            "expected one JSON-RPC 2.0 request object",
        ));
    };
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str);
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Some(failure(
            id.unwrap_or(Value::Null),
            INVALID_REQUEST,
            "expected jsonrpc \"2.0\"",
        ));
    }
    let Some(method) = method else {
        // A response to a request of ours (we make none) needs no answer.
        if message.contains_key("result") || message.contains_key("error") {
            return None;
        }
        return Some(failure(
            id.unwrap_or(Value::Null),
            INVALID_REQUEST,
            "expected a method",
        ));
    };
    // Notifications (`notifications/initialized`, `notifications/cancelled`)
    // are never answered.
    let id = id?;
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
    Some(match dispatch(paths, method, &params).await {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => failure(id, error.code, &error.message),
    })
}

async fn dispatch(paths: &Paths, method: &str, params: &Value) -> Result<Value, RpcError> {
    match method {
        "initialize" => Ok(initialize(params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools::list() })),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::invalid_params("tools/call needs a tool name"))?;
            let arguments = match params.get("arguments") {
                None | Some(Value::Null) => json!({}),
                Some(arguments @ Value::Object(_)) => arguments.clone(),
                Some(_) => return Err(RpcError::invalid_params("arguments must be an object")),
            };
            tools::call(paths, name, &arguments).await
        }
        _ => Err(RpcError {
            code: METHOD_NOT_FOUND,
            message: format!("no method {method:?}"),
        }),
    }
}

fn initialize(params: &Value) -> Value {
    let asked = params.get("protocolVersion").and_then(Value::as_str);
    let version = PROTOCOL_VERSIONS
        .iter()
        .find(|v| Some(**v) == asked)
        .unwrap_or(&PROTOCOL_VERSIONS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": {
            "name": "deadbolt",
            "title": "Deadbolt",
            "version": crate::client::version(),
        },
        "instructions": INSTRUCTIONS,
    })
}

fn failure(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}
