//! Writes the browser protocol's TypeScript bindings to the path given, or
//! to `extension/src/gen/proto.ts` from the current directory:
//! `cargo run -p deadbolt-proto --bin gen-ts -- extension/src/gen/proto.ts`
//! (`bun run gen:proto`).

use std::path::PathBuf;
use std::process::ExitCode;

use deadbolt_proto::typescript;

fn main() -> ExitCode {
    let path = std::env::args_os()
        .nth(1)
        .map_or_else(|| PathBuf::from(typescript::PATH), PathBuf::from);
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty())
        && let Err(error) = std::fs::create_dir_all(dir)
    {
        eprintln!("gen-ts: creating {}: {error}", dir.display());
        return ExitCode::FAILURE;
    }
    match std::fs::write(&path, typescript::bindings()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gen-ts: writing {}: {error}", path.display());
            ExitCode::FAILURE
        }
    }
}
