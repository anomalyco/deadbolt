//! `deadbolt_broker_hint`: the `deadbolt run --broker` command that gives a
//! program an API credential it never holds (docs/broker.md). The route it
//! builds is checked by the same parser `deadbolt run` uses.

use serde_json::{Value, json};

use super::tools::{Args, Failure, item_list, reference, reference_name, reference_vault};
use crate::broker::launch::RouteSpec;
use crate::paths::Paths;
use crate::protocol::ItemInfo;
use deadbolt_core::listing::primary_field;

/// An API whose route Deadbolt knows.
struct Service {
    name: &'static str,
    upstream: &'static str,
    env: &'static str,
    base_env: &'static str,
    header: Option<&'static str>,
}

const SERVICES: [Service; 2] = [
    Service {
        name: "openai",
        upstream: "https://api.openai.com/v1",
        env: "OPENAI_API_KEY",
        base_env: "OPENAI_BASE_URL",
        header: None,
    },
    Service {
        name: "anthropic",
        upstream: "https://api.anthropic.com",
        env: "ANTHROPIC_API_KEY",
        base_env: "ANTHROPIC_BASE_URL",
        header: Some("x-api-key"),
    },
];

pub(super) async fn broker_hint(paths: &Paths, args: &Args<'_>) -> Result<Value, Failure> {
    let asked = args.string("item").unwrap_or_default();
    let vault = args.string("vault");
    let service = match args.string("service") {
        Some(name) => Some(
            SERVICES
                .iter()
                .find(|s| s.name.eq_ignore_ascii_case(&name))
                .ok_or_else(|| {
                    Failure::Params(format!(
                        "no service {name:?}: give openai or anthropic, or upstream with the API's https URL"
                    ))
                })?,
        ),
        None => None,
    };
    let upstream = match (args.string("upstream"), service) {
        (Some(upstream), _) => upstream,
        (None, Some(service)) => service.upstream.to_string(),
        (None, None) => {
            return Err(Failure::Params(
                "give service (openai or anthropic) or upstream (the API's https URL)".into(),
            ));
        }
    };
    let alias = match service {
        Some(service) => service.name.to_string(),
        None => alias(&upstream),
    };
    let upper = alias.to_ascii_uppercase().replace('-', "_");
    let env = args
        .string("env")
        .or_else(|| service.map(|s| s.env.to_string()))
        .unwrap_or_else(|| format!("{upper}_API_KEY"));
    let base_env = args
        .string("base_env")
        .or_else(|| service.map(|s| s.base_env.to_string()))
        .unwrap_or_else(|| format!("{upper}_BASE_URL"));
    let header = args
        .string("header")
        .or_else(|| service.and_then(|s| s.header.map(String::from)));
    for (key, name) in [("env", &env), ("base_env", &base_env)] {
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(Failure::Params(format!("{key} must be a variable name")));
        }
    }
    if header
        .as_ref()
        .is_some_and(|h| !h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    {
        return Err(Failure::Params("header must be a header name".into()));
    }

    // Which item: checked against the vault's listing when the daemon can
    // say, else taken as given.
    let mut warnings = Vec::new();
    let mut candidates = Vec::new();
    let found = match item_list(paths, vault.clone(), &asked, None, None).await {
        Ok(items) => {
            let picked = pick(&asked, &items);
            if picked.is_none() {
                if items.is_empty() {
                    warnings.push(format!("no item matches {asked:?}"));
                } else {
                    warnings.push(format!(
                        "{} items match {asked:?}: give one's short id as item",
                        items.len()
                    ));
                    candidates = items.iter().take(20).map(summary).collect();
                }
            }
            picked.map(|item| {
                (
                    summary(item),
                    reference_name(item, &items).to_string(),
                    item.kind.clone(),
                )
            })
        }
        Err(Failure::Daemon { message, .. }) => {
            warnings.push(format!("couldn't check the item: {message}"));
            None
        }
        Err(params) => return Err(params),
    };
    let (item, name, kind) = match found {
        Some((item, name, kind)) => (Some(item), name, Some(kind)),
        None => (None, asked.clone(), None),
    };
    let field = args
        .string("field")
        .or_else(|| kind.as_deref().and_then(primary_field).map(String::from))
        .unwrap_or_else(|| "credential".into());
    let in_vault = reference_vault(paths, vault.as_deref()).await.or(vault);
    let reference = reference(in_vault.as_deref(), &name, &field);

    let mut route = format!("{alias}={upstream},bearer={reference},env={env},base-env={base_env}");
    if let Some(header) = &header {
        route.push_str(&format!(",header={header}"));
    }
    RouteSpec::parse(&route).map_err(|e| Failure::Params(format!("{e:#}")))?;
    let program = args.string("command").unwrap_or_else(|| "<command>".into());
    let command = format!(
        "deadbolt run --broker --route {} -- {program}",
        quote(&route)
    );
    Ok(json!({
        "command": command,
        "route": route,
        "reference": reference,
        "env": env,
        "base_env": base_env,
        "item": item,
        "candidates": candidates,
        "warnings": warnings,
        "how": format!(
            "Ask the person to run this command. The program gets a placeholder in ${env} and \
    the broker's local URL in ${base_env}, and must send its requests there; the broker adds the \
    real credential, which never enters the program's environment or this conversation."
        ),
    }))
}

/// The one item `asked` names among `items`: by id, short id or title, else
/// the only match.
fn pick<'a>(asked: &str, items: &'a [ItemInfo]) -> Option<&'a ItemInfo> {
    let exact: Vec<&ItemInfo> = items
        .iter()
        .filter(|i| i.id == asked || i.short == asked || i.label.eq_ignore_ascii_case(asked))
        .collect();
    match (exact.as_slice(), items) {
        ([one], _) => Some(one),
        ([], [only]) => Some(only),
        _ => None,
    }
}

fn summary(item: &ItemInfo) -> Value {
    json!({
        "id": item.id,
        "short": item.short,
        "title": item.label,
        "kind": item.kind,
        "detail": item.detail,
    })
}

/// A route alias from an upstream URL's host: `api.example.com` is
/// `example`.
fn alias(upstream: &str) -> String {
    let host = upstream
        .split_once("://")
        .map_or(upstream, |(_, rest)| rest)
        .split(['/', ':', '?'])
        .next()
        .unwrap_or_default();
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let label = match labels.as_slice() {
        [.., name, "co" | "com", _cc] => name,
        [.., name, _tld] => name,
        [only] => only,
        _ => "api",
    };
    let alias: String = label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect::<String>()
        .to_ascii_lowercase();
    if alias.is_empty() {
        "api".into()
    } else {
        alias
    }
}

/// `text` in single quotes for a POSIX shell.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_name_the_host() {
        assert_eq!(alias("https://api.example.com/v1"), "example");
        assert_eq!(alias("https://api.example.co.uk"), "example");
        assert_eq!(alias("http://localhost:8080/x"), "localhost");
        assert_eq!(alias("https://"), "api");
    }

    #[test]
    fn quotes_for_a_shell() {
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), r"'it'\''s'");
    }
}
