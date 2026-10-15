# Deadbolt research 02 — Rust sync, transport, and CRDT building blocks

*Researched 2026-10-15. Primary sources only. "(inference)" = my reasoning, not a sourced fact. "(unverified)" = not confirmed from a primary source in this pass.*

## TL;DR

- **Transport: use iroh 1.x.** It is stable (1.0.0 shipped 2026-06-15; 1.3.0 is current), dual-licensed MIT/Apache, and the wire format and API are now frozen. It gives dial-by-public-key QUIC, hole punching, relay fallback, pkarr/DNS/mDNS address lookup, and connection-level allowlisting hooks. It is the right base for "every device talks to every device."
- **Do not build the vault on iroh-docs.** It is maintained but pre-1.0 (0.101), moves slowly, and has two open sync/timestamp bugs. Its write capability *is* a shared namespace secret, so a device cannot be revoked. Its keys, author IDs, and timestamps travel in plaintext. Learn from its range-based set reconciliation; don't adopt it.
- **iroh-willow is effectively dead:** it is pinned to iroh 0.34 and has had no code commits in 2026. **Willow's Rust stack (`willow25`) covers only the data model, Meadowcap, storage, and the drop format.** Confidential Sync design is paused. Treat Willow as a design reference, not a v1 dependency.
- **p2panda** is the closest off-the-shelf "E2EE local-first on iroh" framework. Group key agreement (`p2panda-encryption`, `p2panda-spaces`) is still pre-1.0 and **unaudited**, and group control messages are unencrypted. Learn from it, and possibly reuse it later.
- **Ink & Switch Keyhive + Subduction** are the most on-target designs for "E2EE + capabilities + encrypted-blob sync server." Subduction ships an iroh transport. Both are explicitly marked "do not use in production." Watch them for the personal data store (PDS) phase.
- **CRDT:** **Loro** (MIT, 1.x, shallow snapshots for history trimming and redaction) or **Automerge** (MIT; the Rust crate is still 0.x at 0.12, compressed runtime). Both export opaque update bytes you can encrypt. yrs is fine but text-centric. cr-sqlite is dormant.
- **Recommended v1:** iroh 1.x + iroh-tickets + an mDNS lookup crate. Add a **small custom Deadbolt sync protocol** on its own ALPN that syncs **encrypted, signed per-device op logs**; vault state is LWW per item (Loro map *or* a hand-rolled register). Pair devices with a QR or ticket plus a PAKE. Admit only paired endpoint IDs through endpoint hooks, and self-host the relay and DNS. The mailbox is a separate iroh endpoint that stores ciphertext logs. Details in §7.

---

## 1. iroh (n0-computer)

### Status and stability

- **1.0.0 released 2026-06-15** ("Dial keys, not IPs") after more than 65 versions. Since then: 1.0.1–1.0.3 (Jun–Jul), 1.1.0 (2026-08-25), 1.2.0 (2026-09-09/11), and **1.3.0 (2026-09-28, latest)**. Sources: https://www.iroh.computer/blog/v1 · https://github.com/n0-computer/iroh/releases
- "Iroh 1.0 just means that the wire format and API are stable" (n0, 2026-07-09): https://www.iroh.computer/blog/the-road-to-iroh-1-0
- Support policy: a major release gets 1 year of full support, then maintenance until year 3. Minor releases get 3 months of full support. https://docs.iroh.computer/about/release-policy
- Public relays: v1.0 runs "until End of Life." v0.35 relays shut down 2026-12-31. https://www.iroh.computer/blog/v1
- iroh now runs on **noq**, n0's multipath fork of quinn: https://www.iroh.computer/blog/the-road-to-iroh-1-0
- License: MIT OR Apache-2.0: https://github.com/n0-computer/iroh. The repo is very active (pushes on 2026-10-15; about 12.7k stars per the GitHub API).

### Identity and endpoint model

- Each endpoint is identified by an **Ed25519 public key (EndpointId, formerly NodeId)**. TLS 1.3 uses raw public keys (RFC 7250). Other key algorithms were explicitly rejected for 1.0. https://www.iroh.computer/blog/the-road-to-iroh-1-0
- Optional **post-quantum key exchange** exists in 1.0. **PQ signatures do not**, because the EndpointId *is* the public key. Same source, plus the "post quantum key exchange examples" entry in the rc.0 notes: https://github.com/n0-computer/iroh/releases/tag/v1.0.0-rc.0
- Protocols are multiplexed by **ALPN**, one QUIC connection per ALPN. The ALPN appears in the plaintext ClientHello; ECH is "might" for the future. https://www.iroh.computer/blog/the-road-to-iroh-1-0
- **Endpoint hooks** can reject connections after the handshake based on remote EndpointId and ALPN, before any application data flows. This is the natural place to enforce "paired devices only." https://docs.iroh.computer/connecting/endpoint-hooks

### Hole punching

- Tailscale-style NAT traversal, now built on QUIC multipath. "Roughly 9 out of 10 networking conditions allow a direct connection." https://docs.iroh.computer/concepts/relays · https://docs.iroh.computer/concepts/nat-traversal
- Browsers (Wasm) are **relay-only**: no UDP. https://docs.iroh.computer/languages/wasm-browser
  - Doc inconsistency: the FAQ elsewhere says "iroh doesn't run in the browser": https://docs.iroh.computer/about/faq

### Relays: what they see and store

- Relays are **stateless**. They hold no application data, only forward E2E-encrypted QUIC. https://docs.iroh.computer/concepts/relays
- **They see:** "the identities of the devices connected to it, which pairs are exchanging traffic, when, and how much," plus IP addresses. They do *not* learn when a pair goes direct. https://docs.iroh.computer/concepts/security-privacy
- **No store-and-forward.** A relay cannot serve as the mailbox (inference from "stateless"). The mailbox must be a separate service.
- Self-hosting is supported via the open-source `iroh-relay` binary. **Bearer-token access control** shipped in 1.0.0, and allowlists or a shared password are available. https://github.com/n0-computer/iroh/releases/tag/v1.0.0 · https://docs.iroh.computer/concepts/security-privacy
- n0 says public relays are for dev and testing; production should use paid Shared/Dedicated relays or self-hosting. https://docs.iroh.computer/concepts/relays
- "Relay-only mode," which would hide IPs from peers, is listed as *upcoming*: https://docs.iroh.computer/concepts/security-privacy

### Discovery ("address lookup" in 1.x)

- **Default:** each endpoint publishes a signed pkarr record (public key + home relay; internal IPs filtered out) to `dns.iroh.link`, resolved over DNS or HTTPS. https://docs.iroh.computer/concepts/address-lookup · https://docs.iroh.computer/concepts/security-privacy
  - Privacy note for Deadbolt (inference): a public record per device makes device IDs resolvable by anyone who knows them. Self-host `iroh-dns-server` or skip publishing.
- **Mainline DHT** lookup via `iroh-mainline-address-lookup` (0.6.0, 2026-09-28): https://docs.iroh.computer/connecting/dht-address-lookup
- **mDNS / LAN** is opt-in in 1.x through two crates:
  - `iroh-mdns-address-lookup` (swarm-discovery, adaptive announcement rate)
  - `iroh-mdns-peer-lookup` (standard DNS-SD, faster first connect; suited to mobile)
  - Source: https://docs.iroh.computer/connecting/local-address-lookup
- **Tickets** (`iroh-tickets` 1.0.0) bundle EndpointId + relay URL + direct addresses + app data, and are QR-friendly. n0 recommends caching EndpointIds rather than tickets for long-lived peers. https://docs.iroh.computer/concepts/tickets
- Custom transports exist: Tor, Nym, and BLE (docs index): https://docs.iroh.computer/llms.txt

### Protocol crates

**iroh-blobs** — 0.103.x, active (last commit 2026-10-08)
- BLAKE3 verified streaming, content-addressed transfer. Built on iroh 1.
- n0's 2024 plan said blobs would reach 1.0 "around the same time as iroh"; it hasn't yet.
- **Reuse:** for large attachments or backups as ciphertext blobs.
- Sources: https://github.com/n0-computer/iroh-blobs · https://www.iroh.computer/blog/road-to-1-0

**iroh-gossip** — 0.101.0, active (fixes on 2026-10-14/15)
- HyParView + PlumTree epidemic broadcast per topic.
- **Reuse (optional):** for "new head" notifications. With fewer than about 10 personal devices, direct pushes are simpler (inference).
- Source: https://github.com/n0-computer/iroh-gossip

**iroh-docs** — 0.101.0 on crates.io (published 2026-06-15)
- Last commit 2026-08-19. Two bugs filed 2026-09-09 and 2026-10-09 are still open.
- n0 said in 2025 it was "not yet ready for a 1.0" and would keep getting minor releases. It is still listed in the docs, and **I found no deprecation notice** — it is maintained at low priority (inference). Sources:
  - https://www.iroh.computer/blog/iroh-0-35-prepping-for-1-0
  - https://docs.iroh.computer/protocols/documents
  - #120 and #121: https://github.com/n0-computer/iroh-docs/issues
- Data model: entries keyed by (namespace, author, key) → (BLAKE3 hash, size, timestamp). Sync uses range-based set reconciliation; storage is redb; it depends on blobs + gossip.
- The **namespace secret key is the write capability**. Sharing a `DocTicket` in write mode hands out that secret, so there is no per-device revocation.
- Source: https://github.com/n0-computer/iroh-docs
- **Learn from, don't use for the vault.**

**iroh-willow** — dormant
- Cargo.toml pins iroh 0.34 and iroh-blobs from a git branch.
- Since 2026-02 the only commits are dependabot CI bumps.
- Source: https://github.com/n0-computer/iroh-willow
- **Ignore.**

**iroh-automerge / iroh-automerge-repo** — examples, labelled "experimental"
- https://docs.iroh.computer/concepts/protocols · https://github.com/n0-computer/iroh-examples

### Pairing and ticket precedents

- **sendme** and **dumbpipe** are ticket-based. sendme still dials with a ticket rather than an ID only. https://www.iroh.computer/blog/the-road-to-iroh-1-0
- **Delta Chat's "second device" transfer** was iroh's original production use case: a resumable single-blob backup to a newly provisioned device. This is the closest real-world precedent for pairing. Same source.
- I found no n0 example of authenticated pairing (PAKE or short code). Deadbolt has to design it (inference).

### Verdict

- **Reuse directly:** `iroh`, `iroh-tickets`, an mDNS lookup crate, `iroh-relay` (self-hosted), `iroh-dns-server` (self-hosted), and optionally `iroh-blobs`.
- **Maturity risk:** low for core iroh. Medium for blobs and gossip, which are pre-1.0 and still have breaking minors.

---

## 2. p2panda

**What it is**
- A modular Rust stack for "privacy-respecting and secure local-first applications," described as "broadcast-only at its heart."
- Crates: `p2panda`, `-net`, `-discovery`, `-sync`, `-blobs`, `-core`, `-store`, `-stream`, `-spaces`, `-encryption`, `-auth`.
- License: MIT OR Apache-2.0.
- Source: https://github.com/p2panda/p2panda

**Use of iroh**
- `p2panda-net` depends on iroh 1.3.0, iroh-gossip 0.101, and iroh-mdns-address-lookup 0.6.
- Unreleased work adds a connection/sync `Authoriser` (allow/block lists) and mDNS network IDs.
- Sources: https://github.com/p2panda/p2panda/blob/main/p2panda-net/Cargo.toml · https://github.com/p2panda/p2panda/blob/main/CHANGELOG.md

**Data and sync**
- Signed, append-only per-author logs of "operations." The header encoding was stabilised in v0.7.0 (2026-07-07).
- `p2panda-sync` provides local-first log sync, and topic-based "confidential" discovery.
- Sources: https://github.com/p2panda/p2panda/releases/tag/v0.7.0 · https://github.com/p2panda/p2panda

**Encryption (`p2panda-encryption` 0.7.1)**
- **Data Encryption:** one symmetric group key, reused until rotated (for example on member removal). Old keys are kept so late joiners can read history; forward secrecy is optional, by deleting keys.
- **Message Encryption:** a per-member Double-Ratchet-style chain with per-message keys (forward secrecy).
- Key agreement: 2SM from the DCGKA paper (Weidner, Kleppmann et al., 2020), X3DH pre-key bundles for first contact, then HPKE rounds. Updates are O(n).
- **Not audited**, and **group control messages are unencrypted** (membership metadata is visible). Not PQ-secure.
- "Cannot recommend … for high-risk use-cases."
- Source: https://github.com/p2panda/p2panda/blob/main/p2panda-encryption/README.md
- The 2025 blog mentioned a pending Radically Open Security audit; the README still says unaudited. https://p2panda.org/2025/02/24/group-encryption.html

**Access control and groups**
- `p2panda-auth`: decentralised group management with per-member permissions; an "authorisation CRDT."
- `p2panda-spaces`: combines auth + Data Encryption, with nested groups for **multi-device profiles**. This is exactly Deadbolt's "my devices" group.
- Sources: https://docs.rs/crate/p2panda-spaces/latest · https://github.com/p2panda/p2panda/issues/774

**Maturity**
- v0.7.1 (2026-08-21).
- The README states "APIs are not yet considered stable." The team calls spaces/multi-device integration the "last big feature" before v1.
- Low download counts (p2panda-net about 10k total).
- Sources: https://github.com/p2panda/p2panda/releases · crates.io API

**Verdict**
- **Learn from:**
  - the Data-vs-Message encryption split (Deadbolt wants *Data Encryption* semantics: new devices read history, removal triggers rotation);
  - multi-device groups as nested groups;
  - per-author signed logs;
  - the connection authoriser pattern.
- **Possible reuse later:** `p2panda-encryption`/`-spaces` once v1 ships and an audit lands.
- **Risk:** medium-high for a password manager today (unaudited, API churn).

---

## 3. Willow, Meadowcap, Willow'25, willow-rs, Earthstar

**Data model**
- Namespaces → subspaces (author or device keys) → hierarchical paths.
- **Prefix-based destructive deletion**: newer entries overwrite older ones at the same or descendant paths. It "actually delete[s] stuff."
- Payloads are content-addressed.
- Source: https://willowprotocol.org/

**Meadowcap**
- Capabilities with delegation, owned and communal namespaces. Status: **Final**.
- Source: https://willowprotocol.org/more/changes/index.html

**Willow'25**
- Recommended parameters: Ed25519, WILLIAM3 hash (from Bab), ChaCha20-Poly1305.
- Handshake: Noise-XX-like `Nose_XX_ED25519_ChaChaPoly_WILLIAM3`.
- Set fingerprints: hashes summed mod 2^256.
- Status: **Proposal**.
- Source: https://willowprotocol.org/specs/willow25/

**Sync**
- **Confidential Sync** (formerly WGPS): private interest overlap, 3D range-based set reconciliation, LCMUX.
  - Demoted to **Proposal**. The page says "Design on this specification are paused, we are focussing on the Willow Transport Protocol first."
  - Sources: https://willowprotocol.org/specs/confidential-sync/ · https://willowprotocol.org/more/changes/index.html
- **Willow Transfer Protocol (WTP)**: new, request/response, supports region-based set reconciliation. **Capabilities and requests are sent in plaintext metadata.** Status: "Proposal (as of 16.10.2026)" — the page's own date, oddly one day ahead of today.
  - Source: https://willowprotocol.org/specs/wtp/
- **Drop Format** (formerly sideloading): encrypted single-file bundles for sneakernet. Status: Candidate. https://willowprotocol.org/more/changes/index.html

**E2EE story**
- "Willow has no built-in mechanisms for encrypting data." An informative spec explains how to encrypt payloads and paths.
- **Timestamps must stay plaintext** (needed for joins), and payload length and digest leak unless padded.
- Source: https://willowprotocol.org/specs/e2e/

**Rust implementation**
- The GitHub `earthstar-project/willow-rs` repo is **archived** and moved to Codeberg `worm-blossom/willow_rs`. https://github.com/earthstar-project/willow-rs · https://codeberg.org/worm-blossom/willow_rs
- The `willow25` crate is at 0.7.9 (2026-08-27), with about 1.9k downloads total.
- The older generic crates `willow_data_model` and `meadowcap` are **deprecated**.
- Implemented: Data Model, Meadowcap, storage (fjall-based), and the drop format (a default feature). **No sync protocol yet.**
- Sources: https://crates.io/crates/willow25 · https://docs.rs/crate/willow25/latest/source/CHANGELOG.md · https://willowprotocol.org/rust/

**Earthstar**
- TypeScript, LGPL-3.0. Last release 11.0.0-beta.2 (2024-05). Last push 2025-04.
- Source: https://github.com/earthstar-project/earthstar
- **Not relevant** for a Rust build.

**Verdict**
- **Learn from:**
  - path-prefix deletion (great for "really delete this secret");
  - Meadowcap's capability shape;
  - the E2EE metadata analysis;
  - 3D range-based set reconciliation;
  - the Drop Format as a model for encrypted export and restore bundles.
- **Don't depend on it for v1:** the sync spec is in flux, and the only Rust sync implementation (iroh-willow) is dead.
- **License:** MIT OR Apache-2.0.

---

## 4. CRDT libraries

### Automerge (Rust core)

- **Crate:** `automerge` **0.12.0** (2026-09-16). The Rust crate is still 0.x while JS is 3.5. A Rust `1.0.0-beta` line existed in 2025 but the 0.x line continued. MIT. Very active. Sources: crates.io API · https://github.com/automerge/automerge
- **Data types:** JSON-like nested maps and lists, text, counters. Full history with git-like change hashes and `*_at(heads)` time travel. https://docs.rs/automerge/latest/automerge/
- **Size and performance:** Automerge 3 / Rust 0.7 keeps the columnar compressed format *at runtime*. Memory dropped more than 10x; Automerge's Moby Dick example went from 700 MB to 1.3 MB. https://automerge.org/blog/automerge-3/ · https://github.com/automerge/automerge/blob/main/rust/CHANGELOG.md
- **History and GC:** history is kept forever. There is no shallow/trim equivalent that I found (unverified). An experimental `bundle` API compacts a subset of changes. Same changelog.
- **Encrypted-sync friendliness:**
  - Changes are discrete byte chunks with hashes and dependencies, so you can encrypt each change or bundle.
  - The built-in sync protocol exchanges heads and change hashes and needs plaintext docs on both ends. A ciphertext-only server can't run it (inference).
  - Ink & Switch's answer is Subduction/Sedimentree (§5).
- **Ecosystem:** `samod` (Rust automerge-repo, 0.15) · iroh-automerge examples.

### Loro

- **Crate:** `loro` **1.16.2** (2026-09); npm `loro-crdt` 1.16.4 (2026-09-30). MIT. Very active, about 6.2k stars. Sources: https://github.com/loro-dev/loro · crates.io API
- **Data types:**
  - Map (LWW), List, **MovableList**, Text and rich text (Fugue), **movable Tree**, Counter.
  - Version vectors and frontiers, time travel, fork/merge, Eg-Walker.
  - Sources: https://github.com/loro-dev/loro · https://loro.dev/llms.txt
- **History and GC:**
  - **Shallow snapshots** work like a git shallow clone: they drop history before a frontier. Loro claims "typically 70–90% smaller."
  - They can also be used to **redact** deleted sensitive content from history — very relevant for a password manager.
  - Limitation: "Peers can only sync if they have versions after the shallow snapshot point."
  - Source: https://loro.dev/docs/concepts/shallow_snapshots
- **Encrypted-sync friendliness:**
  - Export modes Updates (since a version vector), Snapshot, and Shallow produce opaque byte blobs, so each update batch can be encrypted.
  - Import tolerates out-of-order input ("pending operations").
  - Sources: https://loro.dev/llms.txt · https://loro.dev/docs/concepts/import_status (listed in the docs nav)
- **Maturity:** 1.x since the 1.0 announcement (https://loro.dev/blog/v1.0). Smaller team than Automerge (inference).

### yrs (Yjs Rust port)

- **Crate:** `yrs` **0.28.0** (2026-09-17). MIT. About 4.1M downloads. https://github.com/y-crdt/y-crdt
- **Data types:** Text, Array, Map, XML; heavily optimised for text editing.
- **History and GC:** GC of deleted content is **on by default** (`skip_gc: false`). Without explicit snapshots there is no per-version history. https://github.com/y-crdt/y-crdt/blob/main/yrs/src/doc.rs
- **Encrypted sync:** updates are opaque binary diffs computed from a state vector, so they are encryptable. It is a wire-compatible ecosystem with Yjs.
- **Fit:** fine for collaborative text. Less natural for a structured personal data store than Loro or Automerge (inference).

### cr-sqlite (vlcn-io)

- SQLite extension with CRDT columns (MIT).
- **Last release v0.16.3 (2024-01)**. 2026 commits are only build and packaging fixes.
- Sources: https://github.com/vlcn-io/cr-sqlite · https://api.github.com/repos/vlcn-io/cr-sqlite/commits
- **Dormant**, and its sync model is row-change based. Not recommended.

### Quick comparison

| | Automerge | Loro | yrs |
|---|---|---|---|
| Rust version | 0.12 (0.x) | 1.16 | 0.28 |
| Structured personal data | good | **best** (tree, movable list, map) | ok |
| History trimming / redaction | no (bundle is experimental) | **shallow snapshot** | GC deletes content |
| Opaque update export | yes (changes) | yes (updates since VV) | yes (updates since SV) |
| Ciphertext-only server sync | via Subduction (pre-alpha) | DIY | DIY |
| License | MIT | MIT | MIT |

---

## 5. Other relevant projects

**Keyhive** (Ink & Switch) — `keyhive_core` 0.7.0 (2026-10-13)
- Capability-based delegation, signing, and encryption for local-first apps.
- BeeKEM, a concurrent TreeKEM variant for continuous group key agreement.
- Pre-alpha: "DO NOT use this release in production". Unaudited; the nonce and key-commitment construction has not been independently reviewed.
- Apache-2.0.
- Sources: https://github.com/inkandswitch/keyhive · https://www.inkandswitch.com/keyhive/notebook/
- **Learn from:** the threat model and BeeKEM design.

**Subduction** (Ink & Switch, successor to Beelay) — `subduction_core` 0.19.0 (2026-10-07)
- P2P sync for hash-linked data. "Efficient synchronization of encrypted, partitioned data … without requiring decryption."
- **Sedimentree** partitions history into hash-depth strata, so peers can diff on metadata alone.
- Transports: **iroh**, WebSocket, and HTTP long-poll. Has Keyhive policy integration. MIT OR Apache-2.0.
- "Very unstable API … DO NOT use for production."
- Source: https://github.com/inkandswitch/subduction
- **The closest prior art for Deadbolt's ciphertext mailbox.**

**OpenMLS / mls-rs**
- Standard MLS (RFC 9420) group key agreement in Rust: `openmls` 0.9.1 (2026-10-07), `mls-rs` 0.56.0 (2026-08-19). crates.io API · https://github.com/openmls/openmls · https://github.com/awslabs/mls-rs
- MLS assumes an ordered delivery service. That is awkward in pure P2P, which is why p2panda chose DCGKA/2SM (https://p2panda.org/2025/02/24/group-encryption.html).
- For a *single user's* handful of devices, a simple "vault key + HPKE wrap per device + rotate on removal" scheme is likely enough (inference).

**Veilid** — `veilid-core` 0.5.7 (2026-07-19)
- Rust, MPL-2.0. Its own DHT and private routing network.
- Sources: https://gitlab.com/veilid/veilid · crates.io API
- Overlaps with iroh rather than complementing it, and has a different networking model. **Skip** unless strong anonymity becomes a goal.

**Jazz 2.0** (garden-co)
- Now a Rust-heavy codebase ("groove" engine), MIT.
- "Jazz 2.0 alpha," positioned as a local-first relational DB with "our global storage cloud."
- Source: https://github.com/garden-co/jazz
- Cloud-centric and alpha: not a fit. Classic Jazz's E2EE group model may be worth reading (unverified for 2.0).

**Ditto** — closed-source commercial. Excluded.

**Earthstar** — see §3: TypeScript, dormant.

---

## 6. Design notes: syncing opaque ciphertext

1. **Keep encryption outside the CRDT.** Encrypt each update batch from Loro/Automerge (or each op) with the vault key using an AEAD.
   - Wrap it in a signed envelope: `(device_id, seq, prev_hash, key_epoch, ciphertext)`.
   - Peers and the mailbox reconcile on envelope metadata (device_id, seq, hash), never on content.
   - This is the p2panda per-author log pattern and the Subduction premise (inference).
2. **Use per-device append-only logs plus version vectors** instead of iroh-docs-style wall-clock LWW.
   - iroh-docs issue #120 shows the timestamp skew trap: https://github.com/n0-computer/iroh-docs/issues/120
   - Syncing "give me device D's log from seq N" is trivial and works identically device↔device and device↔mailbox (inference).
3. **Compaction:** periodically re-snapshot (Loro shallow snapshot) under the current key epoch and publish a "checkpoint" envelope.
   - Old ciphertext can then be dropped. This is also how a revoked device's key epoch ages out.
   - Caveat: peers behind the snapshot point must re-bootstrap (Loro's documented limit).
4. **Metadata exposure checklist** (from Willow E2EE, iroh security docs, and the p2panda README):
   - endpoint IDs and pairs visible to the relay;
   - pkarr records public;
   - ALPN string in ClientHello;
   - envelope sizes (pad them);
   - timing.

---

## 7. Recommendations

### Deadbolt v1 (password vault, P2P sync, pairing-only onboarding)

**Transport**
- `iroh` 1.x with a pinned minor.
- **Self-hosted `iroh-relay`** with bearer/allowlist auth, plus a **self-hosted `iroh-dns-server`** — or skip pkarr publishing and rely on cached addresses + mDNS + relay.
- `iroh-mdns-peer-lookup` for fast LAN pairing on mobile.

**Access control**
- An endpoint hook rejects any EndpointId not in the paired-device set, which is itself a signed, replicated record.
- Custom ALPN `deadbolt/sync/1`.

**Pairing**
- The existing device shows a QR code containing an `iroh-tickets`-style ticket (EndpointId + relay + one-time pairing secret), or a short code verified with a **PAKE** (inference: n0 has no example).
- After the new device authenticates, the old device HPKE-wraps the vault key to the new device's static key and adds it to the device set.

**Crypto**
- One vault key per epoch. Rotate on device removal — the p2panda "Data Encryption" semantics, not a ratchet.
- AEAD-encrypt every op batch and sign envelopes with a per-device key.
- Don't adopt `p2panda-encryption` or Keyhive yet (both unaudited).

**Data**
- Vault items as LWW registers keyed by item UUID, with tombstones.
- Either a **Loro** `Map` (for its shallow-snapshot redaction) or a hand-rolled register map. The CRDT surface needed is tiny (inference).
- Avoid iroh-docs.

**Attachments**
- Optional `iroh-blobs` for ciphertext blobs.

**Mailbox (v1.x)**
- A separate always-on iroh endpoint that accepts envelopes from paired devices, keyed by (device_id, seq), and serves them back.
- Model it on Subduction/Willow drop-format ideas, but keep it a ~few-hundred-line custom service until Subduction stabilises (inference).

**Trade-offs**
- Building a small custom protocol is maximum control and minimum attack surface, at the cost of owning sync correctness.
- iroh core is the only third-party networking dependency with a stability promise.

### Later: general personal data store with full CRDT replication

**Path A — recommended default:** keep the v1 envelope/log protocol and swap the payload CRDT to **Loro** documents per collection.
- Loro brings rich types (tree, movable list, text), version control, and shallow-snapshot GC.
- The mailbox and pairing code stay unchanged.

**Path B — re-evaluate in 2027:** move to **Automerge + Keyhive + Subduction (iroh transport)** once they leave pre-alpha and get audits.
- This would give standardised E2EE capability-based sharing (sharing with *other people*, not just your own devices) and a ciphertext-sync server off the shelf.
- Risk: three pre-1.0 Ink & Switch components moving together.

**Path C:** adopt **p2panda** (spaces + auth + sync on iroh) after its v1 and audit, if multi-user groups become core.
- Trade-off: framework lock-in to p2panda's operation and log format.

**Watch Willow** for:
- path/prefix deletion semantics;
- Meadowcap-style delegation for fine-grained sharing;
- drop-format-style encrypted backups.

Re-check once WTP or Confidential Sync stabilise and a Rust sync implementation exists.

### Maturity and license summary

| Component | Version (date) | Risk | License | Use |
|---|---|---|---|---|
| iroh | 1.3.0 (2026-09-28) | low | MIT/Apache | **reuse** |
| iroh-tickets | 1.0.0 (2026-06-15) | low | MIT/Apache | reuse |
| iroh-mdns-*-lookup | 0.6.0 (2026-09-28) | med | MIT/Apache (unverified per crate) | reuse |
| iroh-blobs | 0.103.1 (2026-10-06) | med | MIT/Apache | reuse (attachments) |
| iroh-gossip | 0.101.0 (2026-06-15) | med | MIT/Apache | optional |
| iroh-docs | 0.101.0 (2026-06-15) | med-high | MIT/Apache | learn only |
| iroh-willow | stale on iroh 0.34 | dead | MIT/Apache | ignore |
| p2panda (*) | 0.7.1 (2026-08-21) | high | MIT/Apache | learn / later |
| willow25 | 0.7.9 (2026-08-27) | high (no sync) | MIT/Apache | learn |
| Loro | 1.16.x (2026-09) | low-med | MIT | **reuse** |
| Automerge (Rust) | 0.12.0 (2026-09-16) | low-med | MIT | alternative |
| yrs | 0.28.0 (2026-09-17) | low | MIT | text only |
| cr-sqlite | 0.16.3 (2024-01) | dormant | MIT | skip |
| Keyhive / Subduction | 0.7.0 / 0.19.0 (2026-10) | very high | Apache / MIT-Apache | watch |

## Open questions and uncertainty

- **iroh-docs status:** I found no official deprecation; "de-prioritised" is my inference from release cadence and open bugs. Ask n0 directly if this matters.
- **Delta Chat's current pairing flow:** not re-verified against its source.
- **Loro shallow-snapshot redaction guarantees:** whether it removes deleted data from *all* encodings, including previously exported updates held by other peers. Obviously not for copies already exported — needs a design-level answer.
- **Automerge history trimming:** I didn't confirm whether the Rust 0.12 line added it.
- **Subduction's encrypted-mode security properties:** read `design/security` before borrowing from it.
