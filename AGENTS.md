<!-- tallow -->
# Deadbolt

An alpha, local-first password manager in Rust. No compatibility shims: change
internal APIs directly and update their callers.

- `crates/core`: v2 signed `DBF2` frame log, `X25519Wrap` clean-tip epochs and back-links, recovery-lineage membership resolver (`class = 0` 24-word recovery root), fraud proofs, delta clocks, item rules, password health, and autofill/form/tag rules (pure, `wasm32`-clean).
- `crates/proto`: wire schemas, pure data: the daemon control protocol (`daemon`) and the extension's native messaging (`browser`). `bun run gen:proto` writes the browser types to `extension/src/gen/proto.ts`; CI fails when it's stale.
- `crates/os`: safe wrappers for the few OS calls no dependency wraps (BSD process facts and arguments, code signing info, process hardening, and locked key memory); the one crate where `unsafe` is allowed.
- `crates/pack`: v2 on-disk storage — append-only framed logs (`members.log`, `wal-<n>.log`), immutable checkpoint packs (`gen-<n>.pack`), alternating sealed local state (`local-<m>.sealed`) with a two-phase rollback anchor, and W1–W6 crash rules over a create/append/delete-only `Blocks` trait (`wasm32`-clean).
- `crates/remote`: blind HTTP remote sync — four-verb `ObjStore` (S3/R2 SigV4 and WebDAV), canonical object names, push/pull planner, rollback/withholding/self-rollback detection, and store-backed Send (pure core is `wasm32`-clean; `reqwest` transport behind the default `http` feature).
- `crates/send`: Deadbolt Send links, sealing and delivery over iroh or the vault's remote store (native and `wasm32`).
- `crates/send-web`: browser WebAssembly receiver of `deadbolt-send` for the site's `/r`.
- `crates/engine`: the sans-IO vault engine (`deadbolt-engine`): unlocked vaults, capability tokens (`CapTable`), and the item, autofill, form, passkey, secret, SSH key and Activity rules the daemon serves them by. Storage (`VaultStore`) and time (`Clock`) come from the host, and CI clippies it for `wasm32-unknown-unknown` (`bun run check:wasm`), so no tokio, sockets, filesystem, env or OS code goes in it.
- `crates/net`: iroh transport, membership gates, device-to-device sync and SPAKE2 pairing.
- `crates/client`: daemon file locations, peer verification, and the client that starts and talks to the daemon over `deadbolt-proto`.
- `crates/enclave`: the macOS Touch ID helper (`deadbolt-enclave`, Swift), its SHA-256 pin, and the shared Mach-O slice verifier used by both `deadbolt` and `deadbolt-ui` (docs/touch-id.md).
- `crates/ffi`: Deadbolt for Swift through UniFFI (`deadbolt-ffi`). Its `client` feature is the macOS AutoFill extension's daemon client: socket, protocol and the daemon's code check. `crates/app/scripts/build-autofill.sh` links it into `DeadboltAutoFill.appex` (`crates/app/autofill/*.swift`) and generates the Swift bindings with `crates/ffi/bindgen`, UniFFI's generator in its own workspace and lockfile.
- `crates/viewer`: zero-KDF, read-only `gen-<n>.pack` reader for mobile AutoFill extensions using pack-scoped keys (never `K_e` or `D_sign`) and sealing offline saves to `outbox/` (no `argon2`, `tokio`, `iroh` or network).
- `crates/app`: the Rune desktop app, its own binary `deadbolt-ui` (`src/main.rs`; Deadbolt.app's `Contents/MacOS/Deadbolt`). `deadbolt` is always headless and never links it; `deadbolt app` finds and opens `deadbolt-ui`, `deadbolt ui` runs it with Rune's flags (docs/app.md).
- `crates/cli`: commands, background daemon (`src/daemon/`: the engine's host, `deadbolt-pack` storage in `src/disk/`, socket, taint/capability enforcement, sync, pairing, Touch ID and breach checks), `deadbolt broker` (docs/broker.md), `deadbolt mcp`, deterministic simulator and `deadbolt update` (`src/update.rs`, docs/releasing.md "Updater").
- `extension/`: the Chromium MV3 extension (TypeScript, `bun build`), talking to `deadbolt browser-host`.
- `docs/`: design and simulation reference. `site/`: project site.

## Commands

`bun run check` runs the extension's typecheck, tests and build, then formatting,
Clippy (warnings are errors), workspace tests, `cargo deny check` and
`cargo machete` (unused dependencies; a false positive goes in that crate's
`[package.metadata.cargo-machete]` ignored list). Install stable Rust with
rustfmt/Clippy, cargo-deny and cargo-machete first. CI runs the same steps, with
cargo-deny, cargo-machete and the extension in their own jobs and Rust on Linux
and macOS.

For code shape and file sizes, `bash scripts/file-size.sh` checks tracked
`.rs` and `.swift` files under `crates/`, `.ts` files under `extension/src`,
and `.ts`/`.tsx` files under `site/src` (inline `#[cfg(test)]` items and test
files excluded from production counts), and runs in `bun run check` and CI.
It warns above 800 non-test lines and fails above 1,500 unless
`scripts/file-size-exceptions.txt` lists `<path> <ceiling>`; warns on test
files over 1,000 lines; fails on prefix families (`x.rs`/`x/` + 2+ `x_*.rs` or
3+ `x_*.rs`, and the same for `.ts`/`.tsx` with `-` or `_`); and warns above
40 or fails above 60 non-test sources in a folder. `--update-exceptions`
rewrites the size exception list to current sizes, only lowering ceilings
unless given `--allow-raise`; `--warn-only` always exits 0.

See `docs/simulation.md` before changing sync or pairing. Simulation controls:
`DEADBOLT_SIM_SEED`, `DEADBOLT_SIM_SEEDS`, `DEADBOLT_SIM_TRACE`,
`DEADBOLT_SIM_TIMING`. Membership tests use `DEADBOLT_MEMBERSHIP_CASES` and
`DEADBOLT_MEMBERSHIP_DEPTH`; other property tests use `PROPTEST_CASES`.
CLI integration tests use `DEADBOLT_NET=local` and `DEADBOLT_KDF=fast`, which
only debug builds read (so they don't run under `--release`).

Extension tests and investigations use throwaway browser profiles only. Never
open, read or copy anything from a person's real browser profile (prefs,
passkey settings, cookies, storage), even to check a setting; ask them instead.

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
Site deployment is `cd site && bun run deploy`. **Ask first:** it replaces the
live site. Rust changes do not require a site deploy.
