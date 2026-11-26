//! The viewer runs inside a mobile extension's memory budget: nothing heavy
//! may reach it. Walks `Cargo.lock` from `deadbolt-viewer`, which lists every
//! dependency any feature could enable, so this over-approximates the real
//! tree (`cargo tree -p deadbolt-viewer`) and never under-reports.

use std::collections::{BTreeMap, BTreeSet};

const LOCK: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"));

const BANNED: [&str; 9] = [
    "argon2",
    "tokio",
    "iroh",
    "reqwest",
    "hyper",
    "redb",
    "rune",
    "wgpu",
    "deadbolt-net",
];

fn graph() -> BTreeMap<String, Vec<String>> {
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for package in LOCK.split("[[package]]").skip(1) {
        let mut name = None;
        let mut deps = Vec::new();
        let mut in_deps = false;
        for line in package.lines() {
            let line = line.trim();
            if let Some(value) = line.strip_prefix("name = ") {
                name = Some(value.trim_matches('"').to_owned());
            } else if line == "dependencies = [" {
                in_deps = true;
            } else if in_deps && line == "]" {
                in_deps = false;
            } else if in_deps {
                let dep = line.trim_end_matches(',').trim_matches('"');
                deps.push(dep.split(' ').next().unwrap_or(dep).to_owned());
            }
        }
        graph.entry(name.unwrap()).or_default().extend(deps);
    }
    graph
}

#[test]
fn nothing_heavy_reaches_the_viewer() {
    let graph = graph();
    let mut seen = BTreeSet::new();
    let mut todo = vec!["deadbolt-viewer".to_owned()];
    while let Some(name) = todo.pop() {
        if seen.insert(name.clone()) {
            todo.extend(graph.get(&name).into_iter().flatten().cloned());
        }
    }
    assert!(seen.contains("deadbolt-pack") && seen.contains("deadbolt-core"));
    let banned: Vec<&String> = seen
        .iter()
        .filter(|name| {
            BANNED.iter().any(|b| {
                name.as_str() == *b
                    || name.starts_with(&format!("{b}-"))
                    || name.starts_with(&format!("{b}_"))
            })
        })
        .collect();
    assert!(banned.is_empty(), "the viewer reaches {banned:?}");
}
