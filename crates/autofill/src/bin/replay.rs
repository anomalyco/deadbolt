//! Replays snapshot JSON files through the engine, for the corpus.
//!
//!   replay <dir> [--trace]
//!
//! Reads every `*.json` in `<dir>` (sorted by name) and writes one JSON line
//! per file to stdout: `{"file", "frames": [...]}` or `{"file", "error"}`.
//! Traces are left out unless `--trace` is given.

use std::io::Write;
use std::process::ExitCode;

use deadbolt_autofill::{Engine, Snapshot};
use serde_json::json;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let trace = args.iter().any(|a| a == "--trace");
    let Some(dir) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("usage: replay <dir> [--trace]");
        return ExitCode::from(2);
    };
    let engine = match Engine::embedded() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("rules: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut files: Vec<std::path::PathBuf> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect(),
        Err(e) => {
            eprintln!("{dir}: {e}");
            return ExitCode::FAILURE;
        }
    };
    files.sort();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for path in files {
        let file = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let line = match std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|s| Snapshot::from_json(&s).map_err(|e| e.to_string()))
        {
            Ok(snapshot) => {
                let mut analysis = engine.analyze(&snapshot);
                if !trace {
                    for frame in &mut analysis.frames {
                        frame.fields.iter_mut().for_each(|f| f.trace.clear());
                        frame.groups.iter_mut().for_each(|g| g.trace.clear());
                    }
                }
                json!({ "file": file, "frames": analysis.frames })
            }
            Err(error) => json!({ "file": file, "error": error }),
        };
        if let Err(e) = writeln!(out, "{line}") {
            eprintln!("write: {e}");
            return ExitCode::FAILURE;
        }
    }
    if let Err(e) = out.flush() {
        eprintln!("write: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
