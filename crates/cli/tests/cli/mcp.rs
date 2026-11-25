//! `deadbolt mcp` against a real daemon holding real values: every tool it
//! lists, unlocked and locked, and not one value in anything it writes.

use serde_json::{Value, json};

use super::*;

const PASSWORD: &str = "SUPER-SECRET-NEVER-LEAK-98765";
const NOTE: &str = "NOTE-SECRET-XYZ";
const OTP_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const API_KEY: &str = "sk-live-API-KEY-NEVER-LEAK-4242";

/// Runs `deadbolt mcp` with `requests` on stdin, one per line; returns its
/// raw stdout and stderr and the replies.
fn mcp(device: &Device, requests: &[Value]) -> (String, String, Vec<Value>) {
    let input: String = requests.iter().map(|r| format!("{r}\n")).collect();
    let out = device.with_stdin(device.cmd(&["mcp"]), &input);
    assert!(out.status.success(), "deadbolt mcp failed");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    let replies = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (stdout, stderr, replies)
}

fn request(id: usize, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn assert_no_values(what: &str, text: &str) {
    for value in [PASSWORD, NOTE, OTP_SECRET, API_KEY, "hunter2-reused"] {
        assert!(!text.contains(value), "{what} leaks {value:?}:\n{text}");
    }
}

/// Every call to make of each tool: at least one per tool `tools/list`
/// offers, so a new tool fails here until it is covered.
fn calls(tools: &[Value]) -> Vec<(String, Value)> {
    let mut calls = Vec::new();
    for tool in tools {
        let name = tool["name"].as_str().unwrap();
        let arguments: Vec<Value> = match name {
            "deadbolt_status" | "deadbolt_list_vaults" => vec![json!({})],
            "deadbolt_list_items" => vec![
                json!({}),
                json!({"query": "github"}),
                json!({"vault": "personal", "kind": "note"}),
                json!({"kind": "api", "limit": 1}),
            ],
            "deadbolt_health_summary" => {
                vec![json!({}), json!({"vault": "*", "include_upgrades": true})]
            }
            "deadbolt_broker_hint" => vec![
                json!({"item": "OpenAI", "service": "openai", "command": "python app.py"}),
                json!({"item": "GitHub", "upstream": "https://api.github.com", "field": "password"}),
                json!({"item": "Plans", "upstream": "https://api.example.com", "header": "x-api-key"}),
            ],
            other => panic!("no calls for tool {other}: add them here"),
        };
        calls.extend(arguments.into_iter().map(|a| (name.to_string(), a)));
    }
    calls
}

fn call_all(device: &Device) -> (Vec<(String, Value)>, Vec<Value>) {
    let (stdout, stderr, replies) = mcp(
        device,
        &[
            request(
                0,
                "initialize",
                json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}),
            ),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            request(1, "tools/list", json!({})),
        ],
    );
    assert_no_values("tools/list", &format!("{stdout}{stderr}"));
    assert_eq!(replies.len(), 2, "{stdout}");
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "deadbolt");
    let tools = replies[1]["result"]["tools"].as_array().unwrap();
    assert!(tools.len() >= 5);
    let calls = calls(tools);
    let requests: Vec<Value> = calls
        .iter()
        .enumerate()
        .map(|(i, (name, arguments))| {
            request(
                i,
                "tools/call",
                json!({"name": name, "arguments": arguments}),
            )
        })
        .collect();
    let (stdout, stderr, replies) = mcp(device, &requests);
    assert_no_values("tools/call", &format!("{stdout}{stderr}"));
    assert_eq!(replies.len(), calls.len(), "{stdout}");
    for (i, reply) in replies.iter().enumerate() {
        assert_eq!(reply["id"], i, "{reply}");
        assert!(reply["result"]["structuredContent"].is_object(), "{reply}");
    }
    (calls, replies)
}

fn result<'a>(calls: &[(String, Value)], replies: &'a [Value], name: &str, n: usize) -> &'a Value {
    let i = calls
        .iter()
        .enumerate()
        .filter(|(_, (tool, _))| tool == name)
        .nth(n)
        .unwrap()
        .0;
    &replies[i]["result"]
}

#[test]
fn mcp_tools_show_metadata_and_never_a_value() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    a.run(&[
        "new",
        "login",
        "--name",
        "GitHub",
        "username=alex",
        "url=https://github.com",
        &format!("password={PASSWORD}"),
        &format!("otp=otpauth://totp/GitHub:alex?secret={OTP_SECRET}"),
    ]);
    a.run(&["new", "note", "--name", "Plans", &format!("notes={NOTE}")]);
    a.run(&[
        "new",
        "api",
        "--name",
        "OpenAI",
        &format!("credential={API_KEY}"),
    ]);
    // Two weak logins sharing a password, for the health summary.
    for site in ["one.example", "two.example"] {
        a.run(&[
            "new",
            "login",
            "--name",
            site,
            "username=sam",
            &format!("url=https://{site}"),
            "password=hunter2-reused",
        ]);
    }

    let (calls, replies) = call_all(&a);
    for reply in &replies {
        assert_eq!(reply["result"]["isError"], false, "{reply}");
    }
    let status = &result(&calls, &replies, "deadbolt_status", 0)["structuredContent"];
    assert_eq!(status["state"], "unlocked", "{status}");
    assert_eq!(status["vault_count"], 1);
    assert_eq!(status["device"]["name"], "alpha");

    let vaults = &result(&calls, &replies, "deadbolt_list_vaults", 0)["structuredContent"];
    assert_eq!(vaults["vaults"][0]["name"], "personal", "{vaults}");

    let items = &result(&calls, &replies, "deadbolt_list_items", 0)["structuredContent"];
    assert_eq!(items["count"], 5, "{items}");
    let github = &result(&calls, &replies, "deadbolt_list_items", 1)["structuredContent"]["items"];
    assert_eq!(github.as_array().unwrap().len(), 1, "{github}");
    assert_eq!(github[0]["title"], "GitHub");
    assert_eq!(github[0]["detail"], "alex");
    assert_eq!(
        github[0]["reference"],
        "deadbolt://personal/GitHub/password"
    );
    let fields = github[0]["fields"].as_array().unwrap();
    assert!(fields.contains(&json!("password")) && fields.contains(&json!("otp")));
    let notes = &result(&calls, &replies, "deadbolt_list_items", 2)["structuredContent"];
    assert_eq!(
        notes["items"][0]["reference"],
        "deadbolt://personal/Plans/notes"
    );
    let limited = &result(&calls, &replies, "deadbolt_list_items", 3)["structuredContent"];
    assert_eq!(limited["items"].as_array().unwrap().len(), 1, "{limited}");

    let health = &result(&calls, &replies, "deadbolt_health_summary", 0)["structuredContent"];
    assert!(
        health["counts"]["reused"].as_u64().unwrap() >= 2,
        "{health}"
    );
    let flagged: Vec<&str> = health["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap())
        .collect();
    assert!(flagged.contains(&"one.example"), "{health}");

    let openai = &result(&calls, &replies, "deadbolt_broker_hint", 0)["structuredContent"];
    assert_eq!(
        openai["command"],
        "deadbolt run --broker --route 'openai=https://api.openai.com/v1,bearer=deadbolt://personal/OpenAI/credential,env=OPENAI_API_KEY,base-env=OPENAI_BASE_URL' -- python app.py",
        "{openai}"
    );
    assert_eq!(openai["item"]["title"], "OpenAI");
    assert_eq!(openai["warnings"], json!([]));
    let github = &result(&calls, &replies, "deadbolt_broker_hint", 1)["structuredContent"];
    assert_eq!(
        github["route"],
        "github=https://api.github.com,bearer=deadbolt://personal/GitHub/password,env=GITHUB_API_KEY,base-env=GITHUB_BASE_URL",
        "{github}"
    );
    let plans = &result(&calls, &replies, "deadbolt_broker_hint", 2)["structuredContent"];
    assert_eq!(
        plans["reference"], "deadbolt://personal/Plans/notes",
        "{plans}"
    );
    assert!(
        plans["route"]
            .as_str()
            .unwrap()
            .ends_with(",header=x-api-key")
    );

    // Locked: every tool answers, saying so, and the daemon stays up.
    a.run(&["lock"]);
    let (calls, replies) = call_all(&a);
    for ((name, _), reply) in calls.iter().zip(&replies) {
        let result = &reply["result"];
        let structured = &result["structuredContent"];
        match name.as_str() {
            "deadbolt_status" => {
                assert_eq!(result["isError"], false);
                assert_eq!(structured["state"], "locked", "{structured}");
                assert_eq!(structured["vault_count"], Value::Null);
            }
            "deadbolt_broker_hint" => {
                assert_eq!(result["isError"], false, "{reply}");
                assert!(
                    structured["command"]
                        .as_str()
                        .unwrap()
                        .starts_with("deadbolt run --broker --route '")
                );
                assert!(
                    structured["warnings"][0]
                        .as_str()
                        .unwrap()
                        .contains("locked"),
                    "{structured}"
                );
            }
            _ => {
                assert_eq!(result["isError"], true, "{name}: {reply}");
                assert_eq!(structured["error"], "locked", "{name}: {structured}");
            }
        }
    }
    assert_eq!(a.state(), "locked");
}
