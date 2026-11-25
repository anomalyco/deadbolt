//! `deadbolt mcp`'s protocol and its read-free tool surface. A live daemon
//! with real values is `tests/cli/mcp.rs`.

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::tools::{self, value_free};
use super::*;
use crate::protocol::Command;

/// Words no tool may offer: a tool that reads, reveals or exports values.
const FORBIDDEN: [&str; 9] = [
    "get_secret",
    "read",
    "reveal",
    "decrypt",
    "totp",
    "export",
    "password",
    "otp",
    "copy",
];

/// Paths whose daemon isn't running.
fn nowhere(dir: &std::path::Path) -> Paths {
    Paths {
        data: dir.join("data"),
        config: dir.join("config"),
        socket: dir.join("socket"),
        lock: dir.join("lock"),
        log: dir.join("log"),
    }
}

/// Sends `lines` to a server and returns its replies.
async fn exchange(paths: &Paths, lines: &[Value]) -> Vec<Value> {
    let (client, server) = tokio::io::duplex(1 << 20);
    let (server_read, server_write) = tokio::io::split(server);
    let (client_read, mut client_write) = tokio::io::split(client);
    let serving = tokio::spawn({
        let paths = paths.clone();
        async move { serve(&paths, BufReader::new(server_read), server_write).await }
    });
    for line in lines {
        let mut bytes = serde_json::to_vec(line).unwrap();
        bytes.push(b'\n');
        client_write.write_all(&bytes).await.unwrap();
    }
    client_write.write_all(b"not json\n").await.unwrap();
    client_write.shutdown().await.unwrap();
    serving.await.unwrap().unwrap();
    let mut replies: Vec<Value> = Vec::new();
    let mut reader = BufReader::new(client_read).lines();
    while let Some(line) = reader.next_line().await.unwrap() {
        replies.push(serde_json::from_str(&line).unwrap());
    }
    // The trailing parse error marks the end.
    let last = replies.pop().unwrap();
    assert_eq!(last["error"]["code"], PARSE_ERROR, "{last}");
    replies
}

fn request(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn words(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|w| !w.is_empty())
        .map(String::from)
        .collect()
}

#[test]
fn every_tool_is_read_only_and_offers_no_values() {
    let tools = tools::list();
    assert_eq!(tools.len(), 5);
    for tool in &tools {
        let name = tool["name"].as_str().unwrap();
        let annotations = &tool["annotations"];
        assert_eq!(annotations["readOnlyHint"], true, "{name}");
        assert_eq!(annotations["destructiveHint"], false, "{name}");
        assert_eq!(annotations["openWorldHint"], false, "{name}");
        assert!(name.starts_with("deadbolt_"), "{name}");
        // What the agent reads: the name, title, description and arguments.
        let mut offered = vec![
            name.to_string(),
            tool["title"].as_str().unwrap().into(),
            tool["description"].as_str().unwrap().into(),
        ];
        for (argument, schema) in tool["inputSchema"]["properties"].as_object().unwrap() {
            offered.push(argument.clone());
            offered.push(schema["description"].as_str().unwrap().into());
        }
        for text in &offered {
            for word in words(text) {
                for forbidden in FORBIDDEN {
                    assert!(
                        !word.starts_with(forbidden) && !word.contains("secret_"),
                        "{name} offers {word:?} in {text:?}"
                    );
                }
            }
        }
        assert_eq!(tool["inputSchema"]["additionalProperties"], false, "{name}");
    }
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "deadbolt_status",
            "deadbolt_list_vaults",
            "deadbolt_list_items",
            "deadbolt_health_summary",
            "deadbolt_broker_hint",
        ]
    );
}

#[test]
fn only_value_free_commands_reach_the_daemon() {
    assert!(value_free(&Command::Status));
    assert!(value_free(&Command::VaultList));
    let list = |deleted| Command::ItemList {
        vault: None,
        query: Vec::new(),
        kind: None,
        deleted,
        tags: Vec::new(),
        favorites: false,
    };
    assert!(value_free(&list(false)));
    assert!(!value_free(&list(true)), "deleted items stay out");
    assert!(value_free(&Command::Health {
        vault: None,
        online: false
    }));
    assert!(
        !value_free(&Command::Health {
            vault: None,
            online: true
        }),
        "never sends hash prefixes out"
    );
    for refused in [
        Command::ItemGet {
            vault: None,
            query: vec!["x".into()],
            otp: true,
            ssh_private: true,
            files: Vec::new(),
            deleted: false,
        },
        Command::ItemCode {
            vault: None,
            query: vec!["x".into()],
        },
        Command::Resolve {
            refs: vec!["deadbolt://x/y".into()],
            purpose: crate::protocol::Purpose::Read,
        },
        Command::Lock,
        Command::Stop,
    ] {
        assert!(!value_free(&refused), "{refused:?}");
    }
}

#[tokio::test]
async fn speaks_json_rpc_and_refuses_unknown_tools() {
    let dir = tempfile::tempdir().unwrap();
    let paths = nowhere(dir.path());
    let replies = exchange(
        &paths,
        &[
            request(1, "initialize", json!({"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}})),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            request(2, "ping", json!({})),
            request(3, "tools/list", json!({})),
            request(4, "tools/call", json!({"name": "deadbolt_get_secret", "arguments": {}})),
            request(5, "tools/call", json!({"name": "deadbolt_list_items", "arguments": {"reveal": true}})),
            request(6, "tools/call", json!({"name": "deadbolt_list_items", "arguments": {"limit": "all"}})),
            request(7, "tools/call", json!({"name": "deadbolt_broker_hint", "arguments": {}})),
            request(8, "resources/read", json!({"uri": "deadbolt://x/y"})),
            json!({"jsonrpc": "1.0", "id": 9, "method": "ping"}),
            request(10, "tools/call", json!({"arguments": {}})),
        ],
    )
    .await;
    // The notification has no reply.
    let ids: Vec<u64> = replies.iter().map(|r| r["id"].as_u64().unwrap()).collect();
    assert_eq!(ids, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    let init = &replies[0]["result"];
    assert_eq!(init["protocolVersion"], "2025-03-26");
    assert_eq!(init["serverInfo"]["name"], "deadbolt");
    assert!(init["capabilities"]["tools"].is_object());
    assert!(init["capabilities"].get("resources").is_none());
    assert_eq!(replies[1]["result"], json!({}));
    assert_eq!(replies[2]["result"]["tools"], json!(tools::list()));
    for reply in &replies[3..7] {
        assert_eq!(reply["error"]["code"], INVALID_PARAMS, "{reply}");
        assert!(reply.get("result").is_none(), "{reply}");
    }
    assert_eq!(replies[7]["error"]["code"], METHOD_NOT_FOUND);
    assert_eq!(replies[8]["error"]["code"], INVALID_REQUEST);
    assert_eq!(replies[9]["error"]["code"], INVALID_PARAMS);
}

#[tokio::test]
async fn a_stopped_daemon_is_a_tool_result() {
    let dir = tempfile::tempdir().unwrap();
    let paths = nowhere(dir.path());
    let names: Vec<String> = tools::list()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    let calls: Vec<Value> = names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let arguments = if name == "deadbolt_broker_hint" {
                json!({"item": "OpenAI", "service": "openai"})
            } else {
                json!({})
            };
            request(
                i as u64,
                "tools/call",
                json!({"name": name, "arguments": arguments}),
            )
        })
        .collect();
    let replies = exchange(&paths, &calls).await;
    assert_eq!(replies.len(), names.len());
    for (name, reply) in names.iter().zip(&replies) {
        let result = &reply["result"];
        let structured = &result["structuredContent"];
        assert_eq!(
            serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap(),
            *structured,
            "{name}"
        );
        match name.as_str() {
            "deadbolt_status" => {
                assert_eq!(result["isError"], false);
                assert_eq!(structured["running"], false);
                assert_eq!(structured["state"], "stopped");
            }
            "deadbolt_broker_hint" => {
                // Still a command, built from what was asked.
                assert_eq!(result["isError"], false, "{reply}");
                let command = structured["command"].as_str().unwrap();
                assert!(
                    command.starts_with("deadbolt run --broker --route 'openai=https://api.openai.com/v1,bearer=deadbolt://OpenAI/credential,env=OPENAI_API_KEY,base-env=OPENAI_BASE_URL' -- "),
                    "{command}"
                );
                assert!(!structured["warnings"].as_array().unwrap().is_empty());
            }
            _ => {
                assert_eq!(result["isError"], true, "{name}: {reply}");
                assert_eq!(structured["error"], "not-running", "{name}");
            }
        }
    }
}
