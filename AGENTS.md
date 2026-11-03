<!-- tallow -->
# Deadbolt

An alpha, local-first password manager in Rust. No compatibility shims: change
internal APIs directly and update their callers.

- `crates/core`: signed vault log, membership and item rules.
- `crates/store`: encrypted redb persistence and passphrase derivation.
- `crates/net`: iroh transport, membership gates, sync and pairing.
- `crates/cli`: commands, background daemon, control socket, deterministic simulator and `deadbolt update` (`src/update.rs`, docs/releasing.md "Updater").
- `crates/app`: the Rune desktop app, a library built into `deadbolt` behind deadbolt-cli's default `app` feature (the static musl build turns it off); `deadbolt app` opens it, `deadbolt ui` runs it with Rune's flags (docs/app.md).
- `crates/autofill`: the autofill engine: field and form classification from a value-free page snapshot, clue tables in `rules/*.toml` (not yet used by the extension).
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
CLI integration tests use `DEADBOLT_NET=local` and `DEADBOLT_KDF=fast`, which
only debug builds read (so they don't run under `--release`).

Each crate has at most one integration-test binary, since every binary links
the whole crate and its dependencies. Add integration tests as modules of it
(`tests/<crate>/`, declared in its `main.rs`; cli and send have a lone
`tests/<crate>.rs`), never as a new top-level file in `tests/` (app and net
set `autotests = false`, so it would never run). Run one module with a
filter: `cargo test -p deadbolt-app --test app panel::`.

## Rune

`crates/app` pins Rune to an exact rev on its `dev` branch. At the start of each
work round, unless mid-release, bump every Rune `rev` in `crates/app/Cargo.toml` to the
head of Rune `dev` and run `cargo update -p rune -p rune-kit -p rune-theme-opencode`. Read the
`CHANGELOG.md` "## dev" entries since the old pin first, and adapt to anything
marked breaking. Run the app tests and compare `crates/app/scripts/snap.sh` stills
before and after. If a bump breaks on Rune's side, report it to Rune rather than
working around it.

## Shipping

Branch from `dev`, make focused commits, and open a PR against `dev`. Every push to
`dev` publishes a dev build (runs queue, never cancel); `production` is
fast-forwarded from `dev` to release stable (`docs/releasing.md`). `.github/release/`
and `.github/workflows/release.yml` are the release security boundary. Coordinate
shared-file changes with other active worktrees, and remove your worktree
(`git worktree remove`) once your PR merges.
Site deployment is `cd site && bun run deploy`. **Ask first:** it replaces Dax's
live page. Rust changes do not require a site deploy.
