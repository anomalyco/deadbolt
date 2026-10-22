# Deadbolt

An alpha, local-first password manager in Rust. No compatibility shims: change
internal APIs directly and update their callers.

- `crates/core`: signed vault log, membership and item rules.
- `crates/store`: encrypted redb persistence and passphrase derivation.
- `crates/net`: iroh transport, membership gates, sync and pairing.
- `crates/cli`: commands, background agent, control socket and deterministic simulator.
- `docs/`: design and simulation reference. `site/`: project site.

## Commands

`bun run check` runs formatting, Clippy (warnings are errors), workspace tests and
`cargo deny check`. Install stable Rust with rustfmt/Clippy and cargo-deny first.
CI runs the same steps, with cargo-deny in its own job and Rust on Linux and macOS.

On Kit's Mac Studio, route Cargo builds and tests through HiveMind:
`hivemind run --kind cargo -- cargo +stable test --workspace --locked -j 2`.
The complete gate can run as `hivemind run --kind cargo -- bun run check`.
Run formatting locally with `export PATH=$HOME/.cargo/bin:$PATH` and
`cargo +stable fmt --all`. Use stable explicitly and start with two build jobs.

See `docs/simulation.md` before changing sync or pairing. Simulation controls:
`DEADBOLT_SIM_SEED`, `DEADBOLT_SIM_SEEDS`, `DEADBOLT_SIM_TRACE`,
`DEADBOLT_SIM_TIMING`. Membership tests use `DEADBOLT_MEMBERSHIP_CASES` and
`DEADBOLT_MEMBERSHIP_DEPTH`; other property tests use `PROPTEST_CASES`.
Put `env NAME=value` after HiveMind's `--` to reach the worker.
CLI integration tests use `DEADBOLT_NET=local` and `DEADBOLT_KDF=fast`.

## Shipping

Branch from `main`, make focused commits, and open a PR. Kit merges; do not enable
auto-merge. Coordinate shared-file changes with other active worktrees.
Site deployment is `cd site && bun run deploy`. **Ask first:** it replaces Dax's
live page. Rust changes do not require a site deploy.
