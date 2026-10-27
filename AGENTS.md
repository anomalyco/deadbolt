# Deadbolt

An alpha, local-first password manager in Rust. No compatibility shims: change
internal APIs directly and update their callers.

- `crates/core`: signed vault log, membership and item rules.
- `crates/store`: encrypted redb persistence and passphrase derivation.
- `crates/net`: iroh transport, membership gates, sync and pairing.
- `crates/cli`: commands, background agent, control socket and deterministic simulator.
- `crates/send`: Deadbolt Send links, sealing and delivery (native and wasm32); `crates/send-web`: its browser build for the site's `/r`.
- `extension/`: the Chromium MV3 extension (TypeScript, `bun build`), talking to `deadbolt browser-host`.
- `docs/`: design and simulation reference. `site/`: project site.

## Commands

`bun run check` runs the extension's typecheck, tests and build, then formatting,
Clippy (warnings are errors), workspace tests and `cargo deny check`. Install
stable Rust with rustfmt/Clippy and cargo-deny first. CI runs the same steps, with
cargo-deny and the extension in their own jobs and Rust on Linux and macOS.

See `docs/simulation.md` before changing sync or pairing. Simulation controls:
`DEADBOLT_SIM_SEED`, `DEADBOLT_SIM_SEEDS`, `DEADBOLT_SIM_TRACE`,
`DEADBOLT_SIM_TIMING`. Membership tests use `DEADBOLT_MEMBERSHIP_CASES` and
`DEADBOLT_MEMBERSHIP_DEPTH`; other property tests use `PROPTEST_CASES`.
CLI integration tests use `DEADBOLT_NET=local` and `DEADBOLT_KDF=fast`.

## Rune

`crates/app` pins Rune to an exact rev on its `dev` branch. At the start of each
work round, unless mid-release, bump every Rune `rev` in `crates/app/Cargo.toml` to the
head of Rune `dev` and run `cargo update -p rune -p rune-kit -p rune-theme-opencode`. Read the
`CHANGELOG.md` "## dev" entries since the old pin first, and adapt to anything
marked breaking. Run the app tests and compare `crates/app/scripts/snap.sh` stills
before and after. If a bump breaks on Rune's side, report it to Rune rather than
working around it.

## Shipping

Branch from `main`, make focused commits, and open a PR. Kit merges; do not enable
auto-merge. Coordinate shared-file changes with other active worktrees.
Site deployment is `cd site && bun run deploy`. **Ask first:** it replaces Dax's
live page. Rust changes do not require a site deploy.
