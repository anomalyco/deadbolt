# Releasing Deadbolt

One run of the **Release** workflow (`.github/workflows/release.yml`) builds,
signs, verifies, and publishes the CLI, `Deadbolt.app` and the browser
extension from one commit to the Anomaly release service (`anomalyco/release`,
`https://anoma.ly/release`). It is Hex's release pipeline, which follows
OpenCode's.

## Branches and channels

Work lands on `dev` (pull requests target it). `production` holds what was
released and moves only by fast-forward from `dev`.

| Channel | Runs on | Version | Publishes |
| --- | --- | --- | --- |
| `dev` | every push to `dev` (not docs/site/Markdown-only); dispatch from `dev` | `0.0.0-dev-<run>` (`.<attempt>` on a full rerun) | release service `dev` channel |
| `check` | dispatch (`channel: check`) from `dev` or `production` | as `dev` from `dev`, as `stable` from `production` | nothing: builds, signs and verifies only |
| `stable` | push to `production`, push of tag `v<version>`, dispatch from `production` | `[workspace.package] version` | release service `stable`, GitHub release `v<version>` (Latest), Homebrew |

A newer push to `dev` cancels a dev run in progress; other channels queue.
`.github/release/plan.sh` decides all of this from the event and ref. Versions
are display text: each channel has one current release, and installs follow it.
Release builds stamp the version into `Cargo.toml` (`scripts/set-crate-version.sh`,
never committed) and the channel into the binary (`DEADBOLT_BUILD_CHANNEL`,
shown by `deadbolt --version`, e.g. `deadbolt 0.0.0-dev-42 (dev)`), for a future
updater.

## The pipeline

```text
Release (push dev | production | v*, or workflow_dispatch: channel)
├─ plan               plan.sh: channel, version, tag, notes                               [build]
├─ build-linux-*      deadbolt-<v>-linux-{x64,arm64}.tar.gz (musl, static)                [build]
├─ build-extension    deadbolt-extension-<v>.zip (manifest version stamped)                [build]
├─ build-enclave      deadbolt-enclave for arm64 + x86_64, ad hoc                           [build]
├─ sign-enclave       Developer ID-signs the two helpers; decides "signed"                  [release]
├─ build-macos        deadbolt pinned to those helpers; universal Deadbolt.app (ad hoc);
│                     deadbolt-<v>-darwin-{arm64,x64}.tar.gz                                [build]
├─ sign-macos         sign-macos.sh: CLI + app inside-out, notarize, staple, zip + DMG       [release]
├─ verify-macos       Gatekeeper, staple, update requirement, Touch ID pin, launch            [build]
├─ publish            OIDC: cli, desktop, extension to the release service; provenance      [release]
├─ github             stable: tag v<v>, GitHub release with every file + SHA256SUMS        [contents: write]
├─ homebrew-stage     stable: render formula + cask, brew style/audit/install/test          [build]
├─ homebrew           stable: push deadbolt.rb and Casks/deadbolt.rb to the tap             [release]
└─ record-brew        OIDC: the tap serves <v> (cli and desktop distributions)                [release]
```

- **Build jobs** (`[build]`) run repository code (cargo, `build.rs`, swiftc,
  bun, brew) with no environment, secret or id-token, and make unsigned files.
  Release builds use no cache.
- **Sign and publish jobs** (`[release]`) run in the `release` environment,
  check out only `.github/release/` (sparse), and run only those scripts and
  SHA-pinned actions on artifacts they treat as data. They never build,
  install dependencies, or run repository code or the artifacts.
- **Artifacts** each carry a `SHA256SUMS`; the job that made one reports that
  manifest's digest as an output, and every job that downloads it checks the
  digest and every file (`.github/release/upload`, `download`,
  `verify-artifacts.sh`). `assemble.sh` accepts only this version's release
  file names.

`.github/workflows/release.yml` and `.github/release/` are the security
boundary. Protect `.github/` with CODEOWNERS and a ruleset on `dev` and
`production` (pull requests with code-owner review), as Hex does.

### macOS and the Touch ID helper

`deadbolt` pins the exact bytes, signature included, of the `deadbolt-enclave`
it ships with (`DEADBOLT_ENCLAVE_SHA256`, [touch-id.md](touch-id.md)), so the
helper is signed before `deadbolt` is compiled: `build-enclave` →
`sign-enclave` → `build-macos` (`DEADBOLT_ENCLAVE_PREBUILT`) → `sign-macos`,
which signs `deadbolt` and the app around the helper and fails if the helper's
bytes change. `verify-macos` checks every architecture slice's pin.

- The app is **universal** (arm64 + x86_64, macOS 12+, like `bundle.sh
  --universal`): one signing and notarization, one DMG and one cask for every
  Mac, at about twice the size. The service lists the same files under both
  `macos-arm64` and `macos-x64`, so an updater looks up its own target as
  Hex's does.
- Code identities: `pw.deadbolt.app` (the app), `pw.deadbolt.cli` (`deadbolt`,
  in the app and the tarballs), `pw.deadbolt.app.enclave` (the helper), all
  Developer ID team `5NZ4Q7NXJ4` with the hardened runtime and a secure
  timestamp. `sign-macos.sh` refuses any Mach-O in the app other than
  `Contents/MacOS/Deadbolt`, `Contents/Helpers/deadbolt` and
  `Contents/Helpers/deadbolt-enclave`.
- The CLI tarballs hold `deadbolt` and `deadbolt-enclave`; both are notarized
  (bare executables cannot be stapled). The app and DMG are notarized and
  stapled. `crates/app/update-requirement.txt` is what an updater must require
  of a new `Deadbolt.app` (identifier, team, Developer ID, notarized).
- **Without the Apple values** `dev` and `check` go on unsigned: the macOS CLI
  tarballs carry the ad-hoc helper and `deadbolt`, and no app is built into
  the release. `stable` fails.

## The release service

`.github/release/registry-deadbolt.json` is Deadbolt's entry for
`anomalyco/release` (`registry/deadbolt.json`, listed in `registry/index.ts`):
repository `anomalyco/deadbolt` (id 1421127274, owner 66570915), workflow
`.github/workflows/release.yml`, environment `release`:

```text
refs/heads/production, refs/tags/v*   channels stable, beta
refs/heads/dev                        channel  dev
```

Deadbolt has three artifacts, each with a manifest at
`https://anoma.ly/release/deadbolt/<artifact>/<channel>.json`:

| Artifact | Targets | File |
| --- | --- | --- |
| `cli` | `macos-arm64`, `macos-x64`, `linux-x64`, `linux-arm64` | `deadbolt-<v>-{darwin,linux}-<arch>.tar.gz` |
| `desktop` | `macos-arm64`, `macos-x64` | `Deadbolt-<v>-macos-universal.zip` (root `Deadbolt.app`, for an updater) |
| | `macos-arm64-dmg`, `macos-x64-dmg` | `Deadbolt-<v>-macos-universal.dmg` |
| `extension` | `chromium` | `deadbolt-extension-<v>.zip` (unpacked MV3 build with its fixed key) |

`publish` uploads each file with its SHA-256, posts each release, then
downloads every published URL and compares it with the local bytes
(`release-service.sh`); rerunning a publish that already went through is
safe. Distributions: `cli` lists `brew` (formula `anomalyco/tap/deadbolt`),
`desktop` lists `brew` (cask `anomalyco/tap/deadbolt`); each gains a version
only after the tap serves it (`record-brew`). `site/public/install` reads the
`cli` manifest for `${DEADBOLT_CHANNEL:-stable}` and checks size and SHA-256;
`DEADBOLT_VERSION` installs a pinned stable version from its GitHub release.
Auto-update is not built yet; the desktop manifest follows Hex's updater
protocol so one can be added.

## Homebrew

Both live in `anomalyco/homebrew-tap`, rendered from `packaging/homebrew/` by
`scripts/release-homebrew.sh` from the stable manifests:

- **Formula** `deadbolt.rb` (tap root, `brew install anomalyco/tap/deadbolt`):
  the CLI tarballs from the release service; installs `deadbolt`, and on macOS
  `deadbolt-enclave` beside it.
- **Cask** `Casks/deadbolt.rb` (`brew install --cask anomalyco/tap/deadbolt`):
  the DMG, plus `binary` linking `Contents/Helpers/deadbolt` as `deadbolt`, so
  the command is always the same build as the agent the app starts (the app
  treats that link as its own). The formula and the cask both own
  `bin/deadbolt`, so brew installs only one of them; Homebrew's cask
  `conflicts_with formula:` is not functional, so it is left out. `zap`
  removes the vault (`~/.local/share/deadbolt`), config, state, the browser
  native messaging manifests and the app's preferences.

## Secrets and settings (`release` environment)

- macOS: secret `APPLE_SIGNING_CERTIFICATE` (base64 `.p12` with the Developer
  ID Application identity for team `5NZ4Q7NXJ4`), optional secret
  `APPLE_SIGNING_CERTIFICATE_PASSWORD`, secret `APPLE_NOTARY_KEY` (App Store
  Connect API `.p8`), variables `APPLE_NOTARY_KEY_ID` and
  `APPLE_NOTARY_ISSUER_ID`. `macos-credentials.sh` imports them into a
  throwaway keychain and prints nothing secret.
- Homebrew: secret `HOMEBREW_TAP_KEY`, a write deploy key on
  `anomalyco/homebrew-tap`. Keep it in the environment, not the repository.
- The environment has no required reviewer (every push to `dev` publishes);
  its deployment policy admits `dev`, `production` and `v*` tags.
- Publishing needs no secret: the service authorizes the `publish` and
  `record-brew` jobs by their OIDC token.

## Cutting a stable release

1. On `dev`, set `[workspace.package] version` in `Cargo.toml` (and run
   `cargo update -w` for `Cargo.lock`) and add `docs/releases/<version>.md`.
2. Let the push publish its dev build and try it
   (`curl -fsSL https://deadbolt.pw/install | DEADBOLT_CHANNEL=dev sh`).
3. `git push origin <commit>:production` (fast-forward only). The push runs
   the stable release. Push to `production` or the tag, not both. `plan`
   refuses a version that is already tagged elsewhere, already current, or
   has no notes.
4. If a later job fails, use **Re-run failed jobs**; a full rerun stops at
   `plan` once the version is published.

A push to `production` that only changes `docs/`, `site/` or Markdown starts
no release (`paths-ignore` applies to every branch). Deploy the site
separately (`cd site && bun run deploy`, with Dax's approval).

## Follow-ups

- `deadbolt browser install` writes its own executable as the native messaging
  host. After installing or updating the app, the host should point at
  `/Applications/Deadbolt.app/Contents/Helpers/deadbolt` (or the cask's link),
  not at a moved or replaced binary.
- An in-app updater (`desktop` manifest, `update-requirement.txt`) and a
  Chrome Web Store listing for the extension.
