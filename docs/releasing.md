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

Releases never cancel each other, as in Hex: the running one finishes, and of
the pushes that land meanwhile only the newest waits (GitHub replaces an older
pending run), so a busy `dev` still publishes, about once per release run.
`.github/release/plan.sh` decides all of this from the event and ref. Versions
are display text: each channel has one current release, and installs follow it.
Release builds stamp the version into `Cargo.toml` (`scripts/set-crate-version.sh`,
never committed) and the channel into the binary (`DEADBOLT_BUILD_CHANNEL`,
shown by `deadbolt --version`, e.g. `deadbolt 0.0.0-dev-42 (dev)`), which
`deadbolt update` follows ([Updater](#updater)).

## The pipeline

```text
Release (push dev | production | v*, or workflow_dispatch: channel)
├─ plan               plan.sh: channel, version, tag, notes                               [build]
├─ build-linux-*      deadbolt-<v>-linux-{x64,arm64}.tar.gz (glibc 2.28+, app built in)  [build]
├─ build-linux-*-musl deadbolt-<v>-linux-{x64,arm64}-musl.tar.gz (static, no app)         [build]
├─ build-extension    deadbolt-extension-<v>.zip (manifest version stamped)                [build]
├─ build-extension-standalone
│                     deadbolt-extension-standalone-<v>.zip (wasm vault; the only job
│                     with the wasm32 target and wasm-bindgen-cli)                         [build]
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

### Linux

Two builds of `deadbolt` per architecture:

- **glibc, with the app** (`linux-x64`, `linux-arm64`): built in
  `quay.io/pypa/manylinux_2_28` (AlmaLinux 8, glibc 2.28), pinned by tag and
  digest, so it runs on glibc 2.28 and later (Debian 10, Ubuntu 18.10,
  RHEL 8 and newer). The runner's own Ubuntu 24.04 would require glibc 2.39,
  as Hex's builds do; 2.28 is the manylinux baseline Python wheels use. Rune
  loads Wayland, X11 and the GPU drivers when a window opens, so the job fails
  unless every `NEEDED` library is glibc's (libc, libm, libdl, libpthread,
  the loader) or libgcc_s, and no symbol needs a glibc newer than 2.28. It then runs `--version`,
  `--help`, `status`, `agent status`, `init`, `new`, `ls` and `app` (which
  must say there's no graphical session) in AlmaLinux 8 minimal, which has no display and no
  desktop libraries.
- **musl, static, without the app** (`linux-x64-musl`, `linux-arm64-musl`):
  `--no-default-features`, for Alpine, containers and glibc older than 2.28.
  The job checks it's static and that `deadbolt app` says the app isn't in it.

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
- `Contents/MacOS/Deadbolt` and `Contents/Helpers/deadbolt` are the same
  `deadbolt` (the app built in), built once and signed twice, so the agent
  tells the app from the CLI ([app.md](app.md#one-bundle-one-agent)).
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
| `cli` | `macos-arm64`, `macos-x64`, `linux-x64`, `linux-arm64` (glibc, app built in) | `deadbolt-<v>-{darwin,linux}-<arch>.tar.gz` |
| | `linux-x64-musl`, `linux-arm64-musl` (static, no app) | `deadbolt-<v>-linux-<arch>-musl.tar.gz` |
| `desktop` | `macos-arm64`, `macos-x64` | `Deadbolt-<v>-macos-universal.zip` (root `Deadbolt.app`, for an updater) |
| | `macos-arm64-dmg`, `macos-x64-dmg` | `Deadbolt-<v>-macos-universal.dmg` |
| `extension` | `chromium` | `deadbolt-extension-<v>.zip` (unpacked MV3 build with its fixed key) |
| | `chromium-standalone` | `deadbolt-extension-standalone-<v>.zip` (the standalone build, same key and id) |

`publish` uploads each file with its SHA-256, posts each release, then
downloads every published URL and compares it with the local bytes
(`release-service.sh`); rerunning a publish that already went through is
safe. Distributions: `cli` lists `brew` (formula `anomalyco/tap/deadbolt`),
`desktop` lists `brew` (cask `anomalyco/tap/deadbolt`); each gains a version
only after the tap serves it (`record-brew`). `site/public/install` reads the
`cli` manifest for `${DEADBOLT_CHANNEL:-stable}` and checks size and SHA-256.
On Linux it installs the glibc build unless the system is musl (`/lib/ld-musl-*`,
or `ldd --version` says musl) or its glibc is older than 2.28, which get the
`-musl` build (`DEADBOLT_LIBC=gnu|musl` overrides);
`DEADBOLT_VERSION` installs a pinned stable version from its GitHub release.

## Updater

`deadbolt update [--check] [--channel dev|beta|stable] [--yes] [--allow-rollback]`
(`crates/cli/src/update.rs`) follows the release service's client rules
(`anomalyco/release` `docs/protocol.md`, `src/protocol/decide.ts`): versions
are display text, tested only for equality, so an install updates whenever its
channel's current release isn't the build it runs, a rollback included.

- **Channel:** the build's (`DEADBOLT_BUILD_CHANNEL`). Builds from source have
  none and need `--channel`. Another channel than the build's is a switch: it
  asks on a terminal, else needs `--yes`, and ignores the rollout.
- **Rollout:** `required` installs at once; otherwise the install's bucket
  (0–99, drawn once from a local random number and kept in
  `$XDG_STATE_HOME/deadbolt/rollout-bucket`, never sent) must be under
  `rollout_percent`.
- **What it updates** depends on where the running `deadbolt` is, symlinks
  resolved:
  - `Deadbolt.app/Contents/Helpers/deadbolt` (or `~/.local/bin/deadbolt`
    linked to it): the `desktop` artifact's `macos-arm64`/`macos-x64` zip.
    Before `ditto -x -k` unpacks it, every entry must be under
    `Deadbolt.app/` (or ditto's `__MACOSX/`), with no symlink pointing out of
    the bundle and nothing written through one, at most 2 GiB; after, every
    symlink in the bundle is checked again. It must pass
    `codesign --verify --deep --strict` against
    `crates/app/update-requirement.txt` (compiled in) and
    `spctl --assess --type execute`; then the app is quit, the agent stopped,
    the old bundle renamed aside within its directory and moved to
    `~/.Trash/Deadbolt-<old version>.app`, the new one renamed into place,
    quarantine cleared if present, and the agent restarted from whichever
    bundle is in place, even if the swap failed and the old one was put back
    (the vault comes back locked). An app on a disk image or under App
    Translocation is refused, and one whose cask record exists
    (`<brew prefix>/Caskroom/deadbolt`) gets the manifest's
    `brew upgrade --cask` instead.
  - Anything else (the install script, a tarball, a build): the `cli`
    artifact's tarball for this OS and architecture (`linux-<arch>-musl` for
    the static build), read in-process: only
    regular files named `deadbolt` and `deadbolt-enclave` are written, never
    links, devices, other names or owners, into the 0700 staging directory
    beside the install. On macOS a release without `deadbolt-enclave` doesn't
    replace a `deadbolt` that has one beside it (the new one pins its own
    helper). The running files are moved into the stage, the new pair renamed
    in, and on any failure both old files come back. If the running agent is
    this binary it is stopped and started again from the new one.
  - A path under Homebrew's `Cellar`, `/nix/store`, `/usr` (not `/usr/local`)
    or `~/.cargo/bin` belongs to that package manager: `update` prints the
    manifest's `command` (or a hint) and changes nothing.
- **Signatures:** a release build (published on a channel) on macOS always
  requires its replacement to satisfy the update requirement with identifier
  `pw.deadbolt.cli` (and `pw.deadbolt.app.enclave` for the helper), without
  `notarized`, as bare executables aren't stapled. That's fixed when it's
  built: nothing on disk turns it off, so an unsigned dev build can't update
  itself until dev builds are signed. Only builds from source rely on the
  checksum alone, as the install script does. `codesign`, `spctl`, `ditto`,
  `xattr`, `osascript` and `open` run from `/usr/bin` (`/usr/sbin/spctl`), and
  one that can't run is an error, never "unsigned".
- **Older manifests:** the highest `sequence` seen for each artifact and
  channel is kept in `$XDG_STATE_HOME/deadbolt/release-sequences.json`, and a
  lower one is refused unless `--allow-rollback`, which never lowers the
  remembered maximum. Only manifests with valid shape and matching app,
  artifact and channel can advance it. A missing or zero-byte state file
  starts empty; unreadable or nonempty malformed state stops the update,
  even with `--allow-rollback`, rather than discarding trusted floors. The
  error names the exact path: restore it from a trusted backup, or correct
  its read permissions. Deleting it loses all remembered replay floors;
  Deadbolt never deletes it automatically. A persistent
  `update.lock` in the same state directory gives `update` (including
  `--check`) and `browser switch` exclusive access for the whole transaction,
  through installation. A competing invocation fails and must be retried
  after the first finishes; separate state directories are not coordinated.
  A real rollback is a new write with a higher sequence, so installs still
  follow it. The protocol's
  `revoked_versions` is always `[]` and clients ignore it, so `update` does
  too.
- **Root:** as euid 0, `update` only changes an install in a root-owned
  directory with a root-owned `HOME`.
- **Extension:** `deadbolt browser install [--standalone] --extension-dir <dir>`
  records an absolute path and the build it gets (`native` or `standalone`) as
  an `[[extensions]]` entry in `config.toml`; the directory must be new or
  empty. Several can be registered (say the native build for one profile and
  the standalone one for another); registering one again changes its build,
  and `deadbolt browser uninstall --extension-dir <dir>` unregisters it,
  leaving its files. An older config's single `extension_dir` and
  `extension_build` are read as one entry and rewritten the next time the
  config changes. For each directory, `update` compares its `manifest.json` `version_name` with the
  `extension` manifest and replaces the directory from that build's zip
  (`chromium`, or `chromium-standalone`)
  (regular files and directories only, at most 64 MiB and 4096 entries,
  staged beside it and renamed into place), writing `.deadbolt-extension`
  with the names it installed. It never replaces a directory holding anything
  else. Then it says to reload Deadbolt in `chrome://extensions`. Without a
  registered directory it prints the channel's download link.
  `deadbolt browser switch --standalone|--native [--channel] [--extension-dir <dir>]`
  changes one directory's build (the only one, or `<dir>` when there are
  several) and fetches it at once: a directory holding the other build
  (told apart by its manifest's `nativeMessaging` or `offscreen` permission)
  takes the channel's release whatever its version, with no rollout hold,
  since the user asked. Both builds have the same id, so reloading the
  extension switches the profile ([extension-device.md](extension-device.md#installing-and-updating-the-standalone-build)).
  The standalone build's settings read the channel's feed themselves (a
  release build knows its channel; a build from source checks nothing) and
  say when a newer build is out, with this command and the download link.
  Deadbolt.app doesn't update extensions.
- **Checks:** manifests come only from `https://anoma.ly/release` (no
  redirects, 30 s, at most 1 MiB); file URLs are resolved against the manifest
  URL and must stay under its origin's `/release/deadbolt/files/`; a download
  stops past the manifest's size and must match its size and SHA-256 before
  it's unpacked, run or moved. Nothing needs the vault, so it works locked.
  `--check` prints what's available and exits 10 if anything is, else 0.
  Requests send `User-Agent: deadbolt/<build channel or source>/<version>/cli`.
- **Tests** point it at a fake service with `DEADBOLT_RELEASE_URL`, which only
  debug builds read and only for a URL on 127.0.0.1 or [::1].
- It doesn't require the protocol's `install.json` receipt: `update` is a
  command the user runs on the install in front of them, and package-manager
  paths are refused instead.

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
  host. After installing the app, the host should point at
  `/Applications/Deadbolt.app/Contents/Helpers/deadbolt` (or the cask's link),
  not at a moved binary (`deadbolt update` replaces files in place, so the
  path stays valid).
- Update offers in the app itself (it can run `deadbolt update`, which updates
  a registered extension directory too), periodic checks, and a Chrome Web
  Store listing for the extension.
