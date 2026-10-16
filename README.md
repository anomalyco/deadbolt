# deadbolt

A decentralized password manager, in Rust. Your devices sync directly with each other over [iroh](https://www.iroh.computer); a new device joins only by pairing from one you already have. No accounts, no servers of our own.

Status: design. No code yet.

## Install

```sh
curl -fsSL https://deadbolt.pw/install | sh
```

```sh
brew install anomalyco/tap/deadbolt
```

Or download a tarball from [GitHub releases](https://github.com/anomalyco/deadbolt/releases) (macOS and Linux, x64 and arm64). The install script verifies the tarball against the release's `SHA256SUMS`; set `DEADBOLT_VERSION` to pin a version and `DEADBOLT_INSTALL` to change the directory (default `~/.local/bin`).

## Docs

- [`docs/design.md`](docs/design.md) — **the current v1 design** (two keys, signed membership, per-device encrypted logs, QR pairing).
- `docs/research/` — prior art
  - [`01-inkandswitch.md`](docs/research/01-inkandswitch.md) — Keyhive, BeeKEM, Beelay/Subduction, Automerge
  - [`02-rust-sync-stacks.md`](docs/research/02-rust-sync-stacks.md) — iroh, p2panda, Willow, Loro/Automerge/yrs
  - [`03-mailbox-pairing-keys.md`](docs/research/03-mailbox-pairing-keys.md) — mailboxes (Nostr, S3, folders), pairing, how other password managers handle keys and recovery
- `docs/history/` — how we got here: the v0 proposal, the no-infrastructure (Nostr mailbox) revision, and two adversarial critiques of them. Superseded by `docs/design.md`; kept for the reasoning. These docs reference the research files by bare filename.

## Site

[`site/index.html`](site/index.html) is a mock marketing page in the style of opentunnel.xyz — a single static file (fonts are Anton and IBM Plex Mono, OFL; licences in `site/fonts/`). Copy and product details on it are placeholders.

![deadbolt](site/screenshots/above-the-fold.png)
