# Deadbolt research 03: ciphertext mailbox, pairing and device membership, password-manager key design

- **Date:** 2026-10-15
- **Scope:** read-only research from primary sources (specs, vendor whitepapers, official docs, peer-reviewed papers). No code was written or published.
- **Context:** Deadbolt is a decentralised password manager written in Rust. Devices sync the vault directly to each other (probably over iroh). New devices join only by pairing with an existing device; there are no accounts. A store-and-forward "mailbox" that holds only ciphertext comes later, and the design should grow into a general personal data store with CRDT replication.
- **Confidence labels:** **[verified]** means a cited primary source states it. **[inference]** means it is my reasoning from the cited material. **[uncertain]** means it was not fully verified or may be stale.

---

## TL;DR

1. **Use dumb storage as the mailbox. Public social protocols are a poor fit.** For v1, define a small `BlobMailbox` trait (put-if-absent, compare-and-swap on a small "head" object, get, list, delete) and implement it over **S3-compatible storage** and **a local or synced folder** (KeePassXC/Syncthing pattern). Next, add a **headless always-on Deadbolt "storage peer"** reachable over iroh (on a NAS, VPS or Raspberry Pi). It holds ciphertext but no keys, similar to Keyhive's E2EE relays. Treat **Nostr and Blossom** as an optional zero-setup transport for small control messages and wake-ups, not as durable storage.
2. **Do not use the following as the mailbox:** AT Protocol repos (public and archival; the new "spaces" provide access control without encryption and are alpha), Pkarr or the Mainline DHT (1000-byte limit, records expire within hours), or IPFS (content stays only while someone pins it, CIDs are public, and deletion is never guaranteed).
3. **Pairing:** use a **QR code carrying a high-entropy one-time secret plus an iroh ticket**. Signal and WhatsApp work the same way. Require a local unlock on the sponsor device and an explicit "Add device X?" confirmation. Offer a **short-code PAKE fallback** (CPace, which is in the RFC Editor queue, or SPAKE2, RFC 9382) for devices without a camera.
4. **Membership:** keep a **signed, causally ordered membership log** (a CRDT). Every device has its own identity key, and existing members sponsor new devices (like iCloud Keychain). Removing a device triggers an **epoch key rotation**, with keys wrapped to each remaining device using HPKE. Personal device groups are small (n < ~20), so the O(n) cost is fine. **Do not adopt MLS for v1**, because TreeKEM/MLS assumes something totally orders commits. For later multi-user sharing, evaluate DCGKA (`p2panda-encryption`) or Keyhive/BeeKEM once they mature.
5. **Key hierarchy:** device key → vault epoch key (KEK) → per-item key → content. Bind all metadata (vault ID, item ID, epoch, schema version) into AEAD associated data. Never accept a public key that the membership log has not authenticated. Never let synced data choose the KDF or cipher parameters. The 2026 ETH Zurich and USI malicious-server analysis found exactly these mistakes in Bitwarden, LastPass, Dashlane and 1Password.
6. **Recovery:** make a **Recovery Kit mandatory** at vault creation: a 256-bit secret printed as words or a QR code. The kit is itself a **member of the membership log**, so recovering means "act as the paper device and admit a new device." The kit also deterministically derives the mailbox locator. A passphrase add-on (two secrets, 1Password-style) and social recovery (Shamir/SLIP-39 shares) are later options. There is no server-side HSM, so never offer a password-only recovery.

---

## A. Infrastructure that could serve as a ciphertext mailbox

### What a mailbox must do (requirements)

- **R1: Holds only opaque ciphertext**, with object names and sizes that reveal as little as possible.
- **R2: Durability.** It must survive weeks or months while all devices are offline, which is the restore case.
- **R3: Atomic "head" update.** Concurrent writers must not clobber each other: either compare-and-swap, or append-only writes with unique names.
- **R4: Integrity and freshness are checked client-side.** Assume the mailbox can drop, reorder, replay or roll back data. KeeShare's docs admit that signatures cannot detect rollback to an older signed version ([KeePassXC KeeShare doc](https://github.com/keepassxreboot/keepassxc/blob/develop/docs/topics/KeeShare.adoc)) **[verified]**.
- **R5: Deletion and compaction** are possible after devices have caught up.
- **R6: A Rust client** exists, and cost is low, ideally zero, for vaults of a few MB.

### Comparison

| Option | Opaque blobs? | Size limits | Durability | Metadata exposed | Atomicity | Cost | Rust client | Verdict |
|---|---|---|---|---|---|---|---|---|
| **S3-compatible (R2, B2, S3, MinIO)** | Yes | Effectively unlimited | High, contractual | Bucket owner sees object names, sizes, times and IPs | `If-None-Match` / `If-Match` conditional PUT | R2 free tier: 10 GB-month | `object_store`, `opendal`, aws-sdk **[uncertain: not re-verified]** | **v1** |
| **Folder / WebDAV / Syncthing / Nextcloud / Git** | Yes | Unlimited | As good as the user's setup | Provider sees file names, sizes, times | Mostly none (WebDAV LOCK optional); Git can push with lease | Free, user-owned | `opendal` (WebDAV, fs), `gix` **[uncertain]** | **v1 (power users)** |
| **Headless Deadbolt peer over iroh** | Yes | Unlimited | As good as the host | Only the host sees ciphertext and timing | Defined by our own protocol | User's hardware or VPS | iroh (native) | **v1.5** |
| **Nostr relays (NIP-44/59/78)** | Yes (base64 in `content`) | Per relay: 64 KB–512 KB per message in published examples | **No guarantee**; relays may drop gift wraps | Relay sees pubkeys, `p` tags, kind, size, IP; `created_at` is public | Replaceable/addressable "latest wins" only | Free or about 4k–19k sats | `nostr-sdk` (alpha) | **Later: control plane only** |
| **Blossom blob servers** | Yes | Per server (`413` if too large) | Advisory; may send a `Sunset` header | sha256 is public; list endpoint optional | Content-addressed, so immutable | Free or paid | `nostr-blossom` | **Later: bulk under Nostr** |
| **AT Protocol PDS** | Public repo: yes, but public and archival. Spaces: alpha, not E2EE | n/a | Good, but the data is rebroadcast | Everything public in the repo; in spaces the PDS reads plaintext | n/a | Free | `atrium` **[uncertain]** | **No** |
| **Pubky homeserver** | `/pub` is public; `/priv` has access control without encryption | 100 MiB declared | Operator-dependent | Operator sees everything except encrypted content | WebDAV locks | Free or self-hosted | Rust SDK | **Maybe later** |
| **Pkarr / Mainline DHT** | Only ≤1000-byte signed DNS packets | 1000 B | Hours, must republish | Public key, record contents | Signed and sequenced | Free | `pkarr` | **Discovery only** |
| **IPFS + pinning** | Yes | Large | Only while pinned | CIDs public and announced to the DHT | None (CIDs immutable) | Pinning fees | Kubo HTTP API **[uncertain]** | **No** |

### A.1 Nostr

- **Event kinds and replacement** **[verified]** ([NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)):
  - Regular events are "expected to be stored."
  - Replaceable events (10000–19999, 0, 3) keep only the latest per (pubkey, kind).
  - Addressable events (30000–39999) keep only the latest per (kind, pubkey, `d` tag).
  - Ephemeral events (20000–29999) are "not expected to be stored."
- **Retention:** no protocol-level durability guarantee. NIP-59 says outright that "relays may choose not to store gift wrapped events" ([NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md)) **[verified]**. Any mailbox on Nostr needs replication to several relays and must tolerate loss **[inference]**.
- **Size limits are per relay**, advertised through NIP-11 `limitation.max_message_length` and `max_content_length`. The spec's examples include 16,384 B, `nostr.wine` at 524,288 B and `nostr.land` at 65,535 B ([NIP-11](https://github.com/nostr-protocol/nips/blob/master/11.md)) **[verified, values are examples and may be stale]**. Design for ≤ ~32 KB per event **[inference]**.
- **App data:** NIP-78 defines kind `30078` (addressable, `d` tag) and kind `78` for "personal private data… users use Nostr relays as their personal database." Relays SHOULD require NIP-42 AUTH and serve these events only to the author ([NIP-78](https://github.com/nostr-protocol/nips/blob/master/78.md)) **[verified]**. This fits well as a "latest signed head / snapshot pointer per device."
- **NIP-44 v2** encryption uses secp256k1 ECDH, HKDF, ChaCha20, HMAC-SHA256 and power-of-two padding, and was audited by Cure53 in December 2023. Its stated limitations: no forward secrecy, no post-compromise security, no post-quantum security, visible `created_at`, IP leaks to relays, and partial length hiding ([NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md)) **[verified]**. Deadbolt should encrypt with its own vault keys and use Nostr only as an envelope **[inference]**.
- **NIP-59 gift wrap.** The rumor is unsigned. The seal (kind 13) is signed by the author and encrypted to the recipient. The wrap (kind 1059) is signed by a one-time key and carries the recipient's `p` tag. Timestamps should be randomised. Relays SHOULD use AUTH and serve 1059 events only to the tagged recipient. Kind 21059 is an ephemeral wrap ([NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md)) **[verified]**. The **recipient pubkey stays visible** to the relay **[verified]**, so use per-device, per-vault Nostr keys derived from vault secrets rather than a public identity **[inference]**.
- **NIP-17** (private DMs over 44+59) recommends 1–3 inbox relays listed in kind 10050. It notes that each recipient needs a separate wrap and that the scheme suits groups of ≤10 ([NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md)) **[verified]**. A personal device set falls within that range **[inference]**.
- **Paid relays** publish fees in NIP-11. Examples: `nostr.wine` admission 18,888,000 msats (~18.9k sats); `nostr.land` 4,000,000 msats (4k sats) per 30 days ([NIP-11](https://github.com/nostr-protocol/nips/blob/master/11.md)) **[verified as spec examples; current prices uncertain]**. Paid relays give a better chance of retention but still no SLA **[inference]**.
- **Blossom:** HTTP `GET/HEAD /<sha256>`, `PUT /upload`, optional `DELETE` and `/list/<pubkey>` (BUD-12). The server MUST NOT modify blobs and may return `413` for oversize uploads. `Sunset` headers are advisory only ([Blossom README](https://github.com/hzrd149/blossom), [BUD-01](https://github.com/hzrd149/blossom/blob/master/buds/01.md), [BUD-02](https://github.com/hzrd149/blossom/blob/master/buds/02.md)) **[verified]**. Content addressing gives integrity; encrypt before upload **[inference]**.
- **Rust:** the `rust-nostr` repo now lives at `nostrdevkit/nostr` (Nostr Dev Kit). It includes `nostr`, `nostr-sdk`, `nostr-blossom` and database backends, and supports NIPs 17, 42, 44, 59, 62, 77 (negentropy) and 78. The libraries are marked **"ALPHA… API will change in breaking ways"** ([nostrdevkit/nostr](https://github.com/nostrdevkit/nostr)) **[verified]**.

### A.2 AT Protocol (PDS)

- The atproto repo and sync protocol are for **public broadcast data**: signed, archival, rebroadcastable ([proposal 0016](https://github.com/bluesky-social/proposals/blob/main/0016-permissioned-data/README.md)) **[verified]**. Storing vault ciphertext there publishes it permanently to relays and AppViews ("harvest now, decrypt later") **[inference]**.
- **Private data work:** "permissioned data" was renamed **atproto spaces**, and the alpha opened on 2026-08-20. It is explicitly "ALPHA SOFTWARE DO NOT USE IT IN PRODUCTION," with launch targeted "later this year" ([atproto blog](https://atproto.com/blog/atproto-spaces-alpha)) **[verified]**.
- Spaces provide **"access control, not confidentiality. They are not end-to-end encrypted"**. PDSes and authorised apps read plaintext ([proposal 0016](https://github.com/bluesky-social/proposals/blob/main/0016-permissioned-data/README.md)) **[verified]**.
- A WordPress integrator noted that **revocation is coarse**: it "only bites at credential renewal… apps keep whatever they've already synced" ([Atmosphere forum](https://discourse.atmosphere.community/t/permissioned-data-proposal-discussion/946)) **[verified, third-party analysis]**.
- **Verdict:** skip for now. Spaces might later act as a sync transport for a social or sharing layer, carrying Deadbolt ciphertext **[inference]**.

### A.3 Pkarr / Mainline DHT

- Pkarr publishes Ed25519-signed DNS packets to the Mainline DHT (BEP44). Records are **ephemeral ("the DHT drops records after hours; republish periodically")** and limited to **1000 bytes**: "PKARR is for discovery, not storage" ([pkarr README](https://github.com/pubky/pkarr)) **[verified]**.
- **iroh** uses Pkarr for address lookup. By default it publishes signed records to n0's `iroh-dns-server` (`dns.iroh.link`) and resolves them over DNS. DHT publishing is opt-in. By default only the home relay URL is published, not IP addresses. The public servers are rate-limited with "no guaranteed uptime," and production users can self-host ([iroh docs: address lookup](https://docs.iroh.computer/concepts/discovery), [DNS lookup](https://docs.iroh.computer/connecting/dns-address-lookup), [PkarrPublisher](https://docs.rs/iroh/latest/iroh/address_lookup/pkarr/struct.PkarrPublisher.html)) **[verified]**.
- **Use in Deadbolt:** device discovery only, which iroh already provides. One option: a recovery-derived Pkarr key could publish a **pointer** ("this vault's mailbox is at s3://… / storage peer X") so that a Recovery Kit alone can find the mailbox **[inference]**.
- **Pubky homeserver** (built on Pkarr) is a per-key HTTP data store. `/pub` is public. `/priv` is "access control, not encryption: Homeserver administrators can still read and write." Apps must encrypt client-side, and access patterns and sizes stay visible ([Pubky security model](https://pubky.org/security-model/)). One Pubky page says "current implementations only support public, unencrypted data" ([Pubky homeserver](https://pubky.org/explore/pubky-protocol/homeserver/)), so the docs conflict **[uncertain]**. Rust SDK and WebDAV-style locks are available ([Pubky SDK](https://pubky.org/sdk/)). It is a plausible later "BYO homeserver" backend **[inference]**.

### A.4 IPFS / pinning

- Unpinned data is garbage-collected. "IPFS guarantees that any content on the network is discoverable, [but] doesn't guarantee that any content is persistently available"; persistence needs a pinning service or Filecoin ([IPFS persistence](https://docs.ipfs.tech/concepts/persistence/)) **[verified]**.
- The Pinning Service API spec is **frozen and archived** ([IPFS pinning services](https://docs.ipfs.tech/how-to/work-with-pinning-services/)) **[verified]**.
- Nodes announce CIDs to the network ([lifecycle](https://docs.ipfs.tech/concepts/lifecycle/)) **[verified]**. Deletion depends on every pinner, so it is unenforceable **[inference]**.
- **Verdict:** no. It adds a pinning vendor dependency while offering neither confidentiality nor deletion.

### A.5 Dumb storage: S3, WebDAV, folders, Git

- **KeePassXC model:** one encrypted KDBX file is synced by any provider ("Dropbox, Google Drive, OneDrive, Nextcloud, Syncthing"). Conflict copies are resolved by **Merge** (matching UUID plus modified time, older version kept in history, deletions recorded so entries don't reappear). The docs recommend storage with version history and warn that remote sync is **not atomic** ([KeePassXC user guide](https://keepassxc.org/docs/KeePassXC_UserGuide), [DatabaseOperations](https://github.com/keepassxreboot/keepassxc/blob/develop/docs/topics/DatabaseOperations.adoc)) **[verified]**.
- **Lesson:** "whole-file overwrite plus merge-on-conflict" works for a single-user vault but scales poorly to a CRDT data store. Prefer **immutable, uniquely named, content-addressed chunks plus small per-device head objects** **[inference]**.
- **S3 conditional writes:** `If-None-Match: *` (create-once) and `If-Match: <ETag>` (compare-and-swap) on PutObject and CompleteMultipartUpload. Failures return `412`, races can return `409` ([AWS docs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html), [AWS announcement 2024-11-25](https://aws.amazon.com/about-aws/whats-new/2024/11/amazon-s3-functionality-conditional-writes/)) **[verified]**.
- **Cloudflare R2:** evaluates these atomically, "at most one request succeeds," and is strongly consistent for read-after-write and listing ([R2 consistency](https://developers.cloudflare.com/r2/reference/consistency/)). Its free tier is 10 GB-month, 1M Class A and 10M Class B operations, with free egress ([R2 pricing](https://developers.cloudflare.com/r2/pricing/)) **[verified]**. A password vault fits inside the free tier **[inference]**.
- **Not every S3-compatible implementation supports conditional writes [uncertain].** Probe at setup and fall back to append-only unique keys, which give per-device logs with no shared mutable object **[inference]**.

### A.6 Proposed mailbox object layout (design sketch, [inference])

```
<prefix = HKDF(mailbox_root, "deadbolt/mailbox/v1")>/
  heads/<H(device_id)>            # signed, encrypted {device seq, version vector, snapshot ref}; CAS by owner only
  chunks/<blake3(ciphertext)>     # immutable, encrypted, padded CRDT ops/snapshots (create-once)
  inbox/<H(recipient)>/<rand>     # sealed key-wraps / pairing / membership ops for a device
```

- **Object names** are keyed hashes, so the provider cannot link them to vault structure. Pad chunks to size buckets.
- **Freshness:** each head is signed by its device and carries a monotonic counter. Every device remembers the highest counter seen per peer and shows "last synced from X: date," so rollback or withholding becomes visible.
- **The same layout maps onto** a folder, WebDAV, S3, a storage peer over iroh (blobs), or Nostr plus Blossom (heads as kind 30078 or gift-wrapped events, chunks on Blossom).

---

## B. Pairing and device membership

### B.1 Pairing primitives

- **Magic-wormhole:** the rendezvous ("mailbox") server allocates nameplates. Clients run SPAKE2 over the server, which relays only encrypted messages after the PAKE. Bulk data uses a separate "transit" (direct TCP or relay) ([server protocol](https://magic-wormhole.readthedocs.io/en/latest/server-protocol.html), [Rust docs](https://docs.rs/magic-wormhole/latest/magic_wormhole/)) **[verified]**.
  - The default code is **16 bits**: "an attacker gets a 1-in-65536 chance" per use, with one online guess ([welcome docs](https://magic-wormhole.readthedocs.io/en/latest/welcome.html)) **[verified]**.
  - The Rust crate uses `spake2` (Ed25519 group, symmetric mode) and is licensed **EUPL-1.2** ([crates.io](https://crates.io/crates/magic-wormhole), [key.rs](https://docs.rs/magic-wormhole/latest/src/magic_wormhole/core/key.rs.html)) **[verified]**. The licence needs review.
  - Default public server: `ws://relay.magic-wormhole.io:4000/v1` ([rendezvous.rs](https://docs.rs/magic-wormhole/latest/src/magic_wormhole/core/rendezvous.rs.html)) **[verified]**.
- **SPAKE2 crate (RustCrypto/PAKEs):** "have not yet received any formal cryptographic and security reviews… no efforts… erasing secrets from the memory. USE AT YOUR OWN RISK" ([README](https://github.com/RustCrypto/PAKEs)) **[verified]**. SPAKE2 is RFC 9382 ([crypto-lab summary of RFC 9382/9383](https://systemslibrarian.github.io/crypto-lab-spake-gate/)) **[verified via secondary source]**.
- **CPace** was CFRG's selected balanced PAKE. `draft-irtf-cfrg-cpace-21` was **sent to the RFC Editor on 2026-07-15** and was "Awaiting First editor" as of 2026-10-07. The draft now **mandates party identifiers**, or an equivalent transcript-uniqueness mechanism, after a UKS discussion during last call ([datatracker](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/), [history](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/history/)) **[verified]**. No well-known audited Rust CPace crate was found **[uncertain]**.
- **Key point [inference]:** a PAKE is only needed when the human carries a *low-entropy* code. A QR code can carry 256 bits, and then a plain authenticated key exchange plus HMAC key confirmation is enough. Signal and WhatsApp both do this (below).

### B.2 How real systems authorise a new device

**Signal linked devices** **[verified]** ([Signal blog 2025-01-27](https://signal.org/blog/a-synchronized-start-for-linked-devices/), [support](https://support.signal.org/hc/en-us/articles/360007320551-Linked-Devices)):
- The new device creates a temporary provisioning address and a Curve25519 keypair, then shows both in a QR code.
- The primary device requires biometric or device unlock, scans the code, and sends a **provisioning message encrypted to that key**. It contains shared keys, account information and a **one-time linking token**.
- History is moved as an archive encrypted with a **one-time AES-256 key** carried inside the provisioning message. The archive is uploaded temporarily.
- Since August 2026, Android phones and tablets and iPhones can also be linked devices ([Signal blog 2026-08-04](https://signal.org/blog/linked-devices-and-android-tablets/)).

**WhatsApp multi-device** **[verified]** ([Meta engineering 2021](https://engineering.fb.com/2021/07/14/security/whatsapp-multi-device/), [Albrecht/Dowling/Jones, EUROCRYPT 2025](https://eprint.iacr.org/2025/794.pdf)):
- Each device has its own identity key, and the primary device is the root of trust.
- The QR code carries the companion's identity key and a **Linking Secret Key**, which is never sent to the server. The primary creates an **Account Signature** over the companion key and the companion creates a **Device Signature** over the primary key; this mutual signing prevents forced adoption. The primary signs the **device list**, and the linking payload is HMAC'd with the linking secret.
- Alternative: an 8-character alphanumeric code bootstraps an encrypted ECDH exchange.
- Revocation means re-signing the device list without the removed device. **Device lists expire after 35 days**, so a revocation is enforced within 35 days even if the server withholds the new list.

**Apple iCloud Keychain** **[verified]** ([Secure keychain syncing](https://support.apple.com/guide/security/secure-keychain-syncing-sec0a319b35f/web)):
- Each device creates a **syncing identity** (P-384) and **signs its own list of trusted peers**, stored in CloudKit. The lists can't be modified without the owning device's private key.
- A new device joins by being **sponsored** by an existing device, which signs the updated circle and issues a **voucher**, or by keychain recovery.
- Items are encrypted so that only circle devices can decrypt. Concurrent edits are resolved by picking one ("eventual consistency").

**Apple recovery** **[verified]**:
- Escrow recovery runs through **HSM clusters**. They verify the iCloud security code with SRP, allow **10 attempts and then destroy the record**, and Apple destroyed the admin cards that could change the firmware ([Escrow security](https://support.apple.com/guide/security/escrow-security-for-icloud-keychain-sec3e341e75d/web)).
- With **Advanced Data Protection**, the user must set up a **recovery contact or recovery key** before enabling it, because Apple holds no keys ([Apple iCloud data security](https://support.apple.com/en-us/102651)).
- Passwords and Keychain are end-to-end encrypted even without ADP (same source).

**Matrix cross-signing** **[verified]** ([spec E2EE module](https://github.com/matrix-org/matrix-spec/blob/main/content/client-server-api/modules/end_to_end_encryption.md), [MSC1756](https://github.com/matrix-org/matrix-doc/blob/master/proposals/1756-cross-signing.md)):
- Each user has three Ed25519 keys: a master key (identity), a self-signing key (signs own devices) and a user-signing key (signs other users' master keys).
- The private parts can be stored server-side, encrypted under a recovery key (SSSS), or shared between devices.
- Verification uses SAS (emoji or decimal) or QR codes. One QR mode covers "self-verifying where the current device does not yet trust the master key."
- Splitting the keys means a compromised self-signing or user-signing key can be replaced without changing the master key.
- Clients can exclude unsigned devices from key sharing ("exclude insecure devices," MSC4153) ([matrix-js-sdk docs](https://matrix-org-matrix-js-sdk.mintlify.app/guides/cross-signing)) **[verified, secondary docs]**.

**MLS (RFC 9420) / OpenMLS** **[verified]**:
- OpenMLS implements RFC 9420/9750. The latest releases are 0.9.1 and 0.8.2 (2026-10-07), the latter fixing a high-severity unbounded-recursion advisory ([crates.io](https://crates.io/crates/openmls), [GHSA-gc79-23g3-8g52](https://github.com/openmls/openmls/security/advisories/GHSA-gc79-23g3-8g52)).
- An SRLabs audit funded by the Sovereign Tech Agency found 8 issues (1 high); 7 were fixed in 0.8.1 and 0.7.3 ([phnx blog](https://blog.phnx.im/openmls-independent-security-audit/), [SRLabs report](https://blog.openmls.tech/SRL-OpenMLS_security_assurance_assessment.pdf)).
- OpenMLS **does not provide a delivery service or an authentication service**; applications bring their own (SRLabs report).
- **TreeKEM "depends on a central server to create a total order of operations, and to pick winners among concurrent operations"** ([Ink & Switch, Keyhive notebook 02](https://www.inkandswitch.com/keyhive/notebook/02/)).

**Decentralised CGKA built for local-first systems** **[verified]**:
- **`p2panda-encryption` (Rust, 0.7.1):** DCGKA from Weidner, Kleppmann et al., with the group-membership CRDT made robust to concurrent add and remove. No central coordinator is needed. It has a "Data Encryption" scheme (symmetric group key rotated on removal, giving PCS) and a "Message Encryption" scheme (double ratchet), uses 2SM key agreement with O(n) healing, and is suitable for about 128 members ([docs.rs](https://docs.rs/p2panda-encryption/latest/p2panda_encryption/), [p2panda blog](https://p2panda.org/2025/02/24/group-encryption.html)). An audit by Radically Open Security was "pending" in February 2025; the outcome was not verified **[uncertain]**.
- **Keyhive (Ink & Switch):** convergent capabilities, a group-management CRDT with coordination-free revocation, and **BeeKEM**, a concurrent TreeKEM variant using only X25519/ChaCha/BLAKE3. It is **pre-alpha and unaudited** ([GitHub](https://github.com/inkandswitch/keyhive), [design](https://github.com/inkandswitch/keyhive/tree/main/design)). Its sync layer, Subduction (which replaces Beelay), syncs E2EE chunks through relays that cannot decrypt them.

### B.3 Lessons for Deadbolt ([inference] unless cited)

- **Per-device keys everywhere** (Signal, WhatsApp, Apple, Matrix): never copy one device's private identity to another. Revoking a device then means removing one key.
- **Mutual signatures at link time** (WhatsApp) stop a malicious peer from forcing a device into, or out of, a vault.
- **Local user presence on the sponsor** (Signal and WhatsApp require biometrics or device unlock before scanning) defends against someone who briefly holds an unlocked phone.
- **Bound the effect of withheld revocations** with expiring signed membership heads (WhatsApp: 35 days). In P2P, the equivalent is: a device that hasn't seen a fresh head from any peer within N days shows a warning, and devices refuse to *send new keys* to anyone not in the latest head they know.
- **Removal does not erase what a device already saw.** Rotation protects future data only (WhatsApp, Signal and MLS all provide PCS for future messages). For a password manager this means flagging "passwords this device could read; consider rotating."
- **Avoid single-root fragility:** WhatsApp's primary device is a single point of failure, and changing it resets the identity (Albrecht et al.). Matrix uses an offline-capable master key. Apple uses peer-signed lists. For Deadbolt, a peer-signed membership log plus a paper "recovery member" avoids needing a primary device.

---

## C. How existing password managers handle E2EE and devices

| Product | Root secret(s) | Key hierarchy | New device | Sharing | Recovery |
|---|---|---|---|---|---|
| **1Password** | Account password + 128-bit Secret Key (2SKD) | AUK → personal keyset (private key) → vault keys → items (overview and details encrypted separately) | Enter password plus Secret Key (add-device QR carries the Secret Key) | Vault key wrapped to member public keys | Emergency Kit; family or team recovery |
| **Bitwarden** | Master password (PBKDF2; Argon2id option **[uncertain]**) → user key | User key → per-item "cipher key" → content; RSA keys for orgs | Log in; or "trusted devices": device key plus device RSA key wrap the user key | Org symmetric key wrapped with RSA | Emergency access (time delay), org account recovery |
| **Proton Pass** | Account password (bcrypt) → user key | User key → vault key (32 B) → item key (32 B), AES-256-GCM | Log in | Vault or item keys to recipient address keys (OpenPGP) | Proton account recovery |
| **KeePassXC** | Password ± key file ± YubiKey → Argon2id | Single KDBX file key | Copy the file | KeeShare containers | User's own backups |
| **Apple Passwords / iCloud Keychain** | Device passcodes + iCloud security code | Per-device syncing identities | Sponsored pairing or HSM escrow | Shared groups **[not researched]** | HSM escrow (10 tries); ADP recovery contact or key |
| **P2P (PearPass, Passphere, Myki)** | Local | Local | QR / P2P | Varies | Varies |

**Details and sources** **[verified]**:
- **1Password:** the AUK is derived from the password via PBKDF2, XORed with HKDF(Secret Key). A separate SRP-x authenticator is derived with a different salt. The server never sees anything crackable. Vault keys are wrapped to users' public keys. The add-device link carries the Secret Key ([white paper, deeper look at keys](https://agilebits.github.io/security-design/deepKeys.html), [white paper PDF](https://1passwordstatic.com/files/security/1password-white-paper.pdf)).
- **Bitwarden:** per-item 64-byte cipher keys are wrapped by the user or org key, and rotating the user key re-wraps the cipher keys. Trusted devices keep a local device key that wraps a device RSA private key, which unwraps the user key ([Bitwarden whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/), [trusted devices](https://bitwarden.com/help/about-trusted-devices/)). The SDK now enforces a **KEK/CEK hierarchy where a CEK is "freshly generated… never reused"** and rotation re-wraps only small keys ([bitwarden_crypto key_hierarchy](https://sdk-api-docs.bitwarden.com/bitwarden_crypto/safe/key_hierarchy/index.html)).
- **Proton Pass:** item keys allow sharing a single item without sharing the vault key (least privilege). The vault key is "encrypted and signed with your user key" ([Proton Pass security model](https://proton.me/blog/proton-pass-security-model)).
- **KeePassXC:** merge semantics as in §A.5. Argon2id is recommended. Docs advise syncing the key file separately from the database ([KeePassXC docs/FAQ](https://keepassxc.org/docs/)).
- **P2P managers:** Myki (local storage, P2P sync) was discontinued in April 2022 after JumpCloud acquired it ([Wikipedia](https://en.wikipedia.org/wiki/Myki_(password_manager))). Tether's **PearPass** (December 2025, P2P on Pears/Holepunch) is now marked "**paused from active development**" ([pass.pears.com](https://pass.pears.com/), [Tether press](https://tether.io/news/tether-launches-pearpass-a-peer-to-peer-password-manager-to-eliminate-cloud-breach-risks/)). Passphere uses QR-initiated PeerJS sync ([passphere.app](https://passphere.app/)). **Lesson [inference]:** P2P password managers have struggled to survive as products. Restore and onboarding UX, plus an exportable format, matter more than the novelty of P2P.

### C.1 The 2026 malicious-server analysis

Scarlata, Torrisi, Backendal and Paterson, USENIX Security 2026; full version on ePrint 2026/058 ([USENIX](https://www.usenix.org/conference/usenixsecurity26/presentation/scarlata), [ePrint](https://eprint.iacr.org/2026/058), [zkae.io](https://zkae.io/)) **[verified]**:

- They found **12 attacks on Bitwarden, 7 on LastPass, 6 on Dashlane and 6 on 1Password**. Most of them recover passwords.
- **Anti-patterns:**
  1. Key escrow and recovery features using **unauthenticated public keys**.
  2. **Integrity only per field, not per vault**, which allows cut-and-paste and field swapping.
  3. **No cryptographic binding between data and metadata.**
  4. **Backwards-compatibility downgrades**, such as Dashlane accepting CBC without a MAC, or a server-forged setting that drops PBKDF2 iterations from 200,000 to 1.
  5. Assuming public-key ciphertexts authenticate their origin. In 1Password, RSA-OAEP lacks sender authentication, so a malicious server can swap in vaults it controls.
- **Relevance to Deadbolt [inference]:** in a P2P system, *any peer or mailbox* plays the "malicious server." The same rules apply:
  - authenticate every public key through the membership log;
  - use AEAD with associated data covering vault ID, item ID, field path, epoch and schema version;
  - sign or authenticate all key wraps (HPKE Auth mode, or sign the wrap);
  - never let synced data choose the KDF or cipher;
  - have no legacy decrypt paths, and pin a ciphersuite per epoch.

### C.2 Passkeys and interoperability

- **FIDO Credential Exchange Format (CXF) 1.0** is a Proposed Standard (2025-08-14; errata 2026-03-09). Passkeys are exported as a PKCS#8 private key plus `rpId`, `credentialId` and `userHandle`. **Passkeys with a non-zero signature counter MUST be excluded**, and importers set the counter to 0 ([CXF](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html)) **[verified]**.
- **CXP** (the transfer protocol) is still a Working Draft. The latest public version (2024-10-03) uses HPKE ([CXP WD](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html), [FIDO download page](https://fidoalliance.org/download-credential-exchange-specifications/)) **[verified]**.
- **Recommendation [inference]:** model Deadbolt items so they round-trip to CXF. Store passkeys as synced keys with counter 0, which suits multi-device sync since counters can't be kept consistent across replicas. Expose CXF import and export to avoid lock-in, a lesson from the P2P products that shut down.

---

## D. Recommendations for Deadbolt

### D.1 Keys and identities (v1)

```
Recovery secret (256-bit, paper/QR)  ──HKDF──► recovery member keys (Ed25519 sign, X25519 KEM)
                                      └─HKDF──► mailbox locator / mailbox namespace key
Device (per install)                   device signing key (Ed25519), device KEM key (X25519/HPKE)
                                       iroh EndpointId (transport) — certified by device signing key
Vault "space"                          vault_id; membership log (signed ops, causal DAG)
  epoch e                              Vault Epoch Key VEK_e (KEK) — HPKE-wrapped to every member incl. recovery member
    item i                             Item Key IK_i (CEK→ or KEK for attachments) wrapped by VEK_e
      content                          XChaCha20-Poly1305 / AES-256-GCM, AAD = (vault_id, item_id, field/blob id, epoch, schema_ver)
```

- **Keep the device signing key separate from the iroh node key [inference].** The transport ID can then be rotated, and the membership log does not depend on iroh internals.
- **Per-item keys** follow Bitwarden, Proton and the Bitwarden SDK. They allow cheap epoch rotation, which only re-wraps item keys, and future single-item sharing.
- **Wraps are sender-authenticated:** HPKE Auth/AuthPSK mode, or an Ed25519 signature over the wrap, bound to the vault ID and epoch (ETH lesson).
- **Ciphersuite is fixed per epoch and recorded in signed membership ops.** Clients reject unknown or weaker suites and never downgrade (ETH lesson).

### D.2 Pairing protocol (v1)

**Primary flow: QR code shown on the existing device (the sponsor).**
1. The sponsor unlocks locally (biometric or passcode), then shows a QR code containing `{v, iroh_ticket(EndpointId+relay), pairing_secret (32 B, one-time, ~2 min TTL), vault_hint}`.
2. The applicant scans it and connects over iroh. QUIC/TLS authenticates the sponsor's endpoint key.
3. Both sides compute `K = HKDF(pairing_secret, transcript(EndpointIds, ephemeral DH))` and exchange HMAC key confirmation. This proves possession of the QR secret, so no PAKE is needed (Signal and WhatsApp model).
4. The applicant sends its device public keys and name. The sponsor shows "Add **Pixel 9 (Deadbolt 1.0)**?" and the user confirms.
5. The sponsor appends a signed `Add(device)` op. The applicant countersigns (WhatsApp-style mutual signature). The sponsor sends the membership log and current `VEK_e` wrapped to the applicant, and then CRDT sync begins.

**Reverse QR** (the applicant shows, the sponsor scans) is better when the sponsor is a phone and the applicant a desktop, which matches Signal's direction.

**No-camera fallback:** a short code (for example 3 words, or 8 alphanumeric characters) with a PAKE, allowing a single attempt and a short TTL.
- **Same LAN:** rendezvous via iroh local (mDNS-like) discovery ([iroh docs](https://docs.iroh.computer/concepts/discovery)).
- **Remote options:** (a) magic-wormhole's mailbox protocol (public server or self-hosted; the crate is EUPL-1.2 and `spake2` is unaudited); (b) a Nostr ephemeral event (kind 2xxxx) keyed by `H(nameplate)` carrying PAKE messages.
- **PAKE choice:** prefer CPace once an implementation with test vectors exists, since the RFC is imminent. Otherwise use SPAKE2 (RFC 9382). Either way, get a crypto review before shipping **[inference]**.

### D.3 Membership and revocation model

- **Membership log** is an append-only DAG of signed ops: `Genesis`, `Add(dev, role)`, `Remove(dev)`, `Rotate(epoch)`, `Rename`. It is a CRDT with deterministic resolution.
  - Roles: `admin` (can add and remove), `member` (read/write data), `recovery` (admin, paper).
  - **Ops authored by a device that are concurrent with, or after, its removal are invalid.** Mutual concurrent removal resolves deterministically, for example both are removed and the user is told. This is the hard part; see Keyhive's "coordination-free revocation" ([Keyhive notebook](https://www.inkandswitch.com/keyhive/notebook/)) and p2panda's concurrent-safe group CRDT ([p2panda-encryption](https://docs.rs/crate/p2panda-encryption/latest)) **[inference + cited prior art]**.
  - **Option:** reuse `p2panda-encryption`'s group-membership and DCGKA "data scheme" rather than writing our own, depending on its audit status **[uncertain]**.
- **On removal:** a new `VEK_{e+1}` is wrapped to the remaining members and the recovery member. New writes use e+1. Old items stay under their item keys, re-wrapped lazily. The UI lists the secrets the removed device could read and nudges the user to rotate them (removal cannot un-reveal).
- **Withheld-revocation bound:** each admin device re-signs a `Head(membership_hash, time)` at least every N days (WhatsApp uses 35). A device that hasn't seen a fresh head shows a "possibly out of date" warning, and no device ships keys to members missing from its latest head **[inference]**.
- **Lost device:** remove it from any remaining device, or from the Recovery Kit.
- **Why not MLS in v1 [inference]:**
  - Personal device counts are small, so pairwise HPKE wraps (O(n)) are cheap.
  - MLS needs a total order of commits, which a P2P system lacks.
  - Per-message forward secrecy is not valuable for a vault where every device must read the full history anyway.
  - Revisit for *multi-user* shared vaults: if there is an always-on coordinator, consider MLS (OpenMLS, audited 2026); if not, consider DCGKA or BeeKEM.

### D.4 Mailbox plan

- **v1 (ship):** use a `BlobMailbox` trait with the §A.6 layout. Backends:
  - **S3-compatible**, using conditional writes when available and probed at setup; R2's free tier covers typical vaults.
  - **Folder** (which covers Syncthing, Nextcloud, Dropbox and iCloud Drive folders), written append-only with unique names so file-sync tools never conflict.
  - Every device both writes to and reads from the mailbox. P2P over iroh stays the primary path.
- **v1.5:** a **headless storage peer**, i.e. the Deadbolt daemon in `--storage-only` mode on a NAS or VPS. It has no vault keys and is admitted by a signed `AddStoragePeer` op, giving it permission to *store*, not read. It keeps chunks and heads and answers iroh sync requests. This mirrors Keyhive's relays syncing E2EE chunks ([Keyhive](https://www.inkandswitch.com/project/keyhive/)) **[inference]**.
- **v2 (optional zero-setup):** Nostr plus Blossom.
  - Heads as kind 30078 or 1059-wrapped events on 2–3 AUTH-enforcing, ideally paid relays, using per-vault derived Nostr keys rather than a public npub.
  - Chunks on 2+ Blossom servers.
  - Treat everything as best-effort and periodically republish.
- **Skip:** AT Protocol (revisit spaces after GA only as a transport), IPFS, and storing data on the DHT.

### D.5 Recovery design

- **Mandatory Recovery Kit at vault creation**, matching ADP (recovery key or contact required), 1Password's Emergency Kit and Signal's 64-character recovery key ([Apple](https://support.apple.com/en-us/102651), [1Password](https://1passwordstatic.com/files/security/1password-white-paper.pdf), [Signal Secure Backups](https://signal.org/blog/introducing-secure-backups/)):
  - **Contents:** a 256-bit secret (BIP39-style 24 words or a Signal-style 64-character string) plus a QR version, and optionally the vault ID and mailbox hints.
  - **The kit is a member** (role `recovery`). Every epoch key is also wrapped to it. To restore on a fresh device: enter the kit, derive the recovery member keys and mailbox locator, fetch heads and chunks from the mailbox (or any reachable peer), then the "recovery member" signs `Add(new device)` and optionally `Remove(lost devices)`, followed by a rotation.
  - **Verify on setup** (ask for 2–3 words back), since Signal and Apple both stress that losing the key means losing the data.
  - **Kit rotation:** re-issue it with `Remove(recovery_old)` and `Add(recovery_new)`.
- **Optional kit plus passphrase (two secrets):** wrap the kit's secret under Argon2id(passphrase) XOR HKDF(kit), 1Password-style ([1Password 2SKD](https://agilebits.github.io/security-design/deepKeys.html)). A stolen paper kit alone is then not enough, at the cost of a second thing to forget.
- **Never offer password-only recovery against the mailbox.** Without an HSM rate-limiter (Apple's 10-attempt cluster) the mailbox ciphertext is offline-crackable **[inference from Apple escrow doc]**.
- **Later: social recovery.** Split the recovery secret with Shamir, using SLIP-0039 mnemonic shares (spec at github.com/satoshilabs/slips, slip-0039.md) **[uncertain: SLIP-39 not re-fetched for this doc]**. Give shares to trusted contacts as encrypted shares or printouts, for example 3-of-5.
  - **Time-delayed emergency access** of the Bitwarden kind ([Bitwarden whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)) needs a party that enforces the delay. A storage peer could enforce it only weakly, so treat it as a non-goal unless a storage peer exists **[inference]**.

### D.6 Trade-offs and open questions

- **Recovery Kit as a full admin member:** convenient, but a stolen kit gives full takeover. Mitigations: the optional passphrase; making kit use visible (it emits a signed op that every device shows prominently); an "alert on recovery use" banner.
- **Nostr metadata:** even with gift wraps, relays see recipient keys, sizes and timing (NIP-44 and NIP-59 limitations). Per-vault keys and padding reduce linkability but don't hide activity.
- **S3 operator metadata:** the bucket owner (the user, if they bring their own credentials) sees object counts, sizes and access IPs. Keyed names and padding help.
- **Concurrent membership edits:** the semantics need formal specification and testing (model-check the CRDT, for example with `stateright` or TLA+) **[inference]**.
- **Open:** PAKE crate choice and audit; whether to depend on `p2panda-encryption`, and its audit status; licence implications of the EUPL magic-wormhole crate; mapping Deadbolt items to CXF.

---

## Sources (primary unless noted)

- Nostr: [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md), [NIP-11](https://github.com/nostr-protocol/nips/blob/master/11.md), [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md), [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md), [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md), [NIP-78](https://github.com/nostr-protocol/nips/blob/master/78.md), [Blossom](https://github.com/hzrd149/blossom), [nostrdevkit/nostr (rust-nostr)](https://github.com/nostrdevkit/nostr)
- AT Protocol: [proposal 0016 (spaces)](https://github.com/bluesky-social/proposals/blob/main/0016-permissioned-data/README.md), [spaces alpha blog 2026-08-20](https://atproto.com/blog/atproto-spaces-alpha), [Spring 2026 roadmap](https://atproto.com/blog/2026-spring-roadmap), [dholms diary 7](https://dholms.leaflet.pub/3mqtqvjidqs2p)
- Pkarr/iroh/Pubky: [pkarr](https://github.com/pubky/pkarr), [iroh address lookup](https://docs.iroh.computer/concepts/discovery), [iroh DNS](https://docs.iroh.computer/connecting/dns-address-lookup), [Pubky security model](https://pubky.org/security-model/), [Pubky API](https://pubky.org/explore/pubky-protocol/api/)
- IPFS: [persistence](https://docs.ipfs.tech/concepts/persistence/), [pinning services](https://docs.ipfs.tech/how-to/work-with-pinning-services/)
- Storage: [S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html), [R2 consistency](https://developers.cloudflare.com/r2/reference/consistency/), [R2 pricing](https://developers.cloudflare.com/r2/pricing/), [KeePassXC guide](https://keepassxc.org/docs/KeePassXC_UserGuide)
- Pairing: [magic-wormhole docs](https://magic-wormhole.readthedocs.io/en/latest/server-protocol.html), [magic-wormhole.rs](https://crates.io/crates/magic-wormhole), [RustCrypto PAKEs](https://github.com/RustCrypto/PAKEs), [CPace draft-21](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/)
- Devices: [Signal linked devices](https://signal.org/blog/a-synchronized-start-for-linked-devices/), [Signal Secure Backups](https://signal.org/blog/introducing-secure-backups/), [WhatsApp multi-device](https://engineering.fb.com/2021/07/14/security/whatsapp-multi-device/), [WhatsApp formal analysis](https://eprint.iacr.org/2025/794.pdf), [Apple keychain syncing](https://support.apple.com/guide/security/secure-keychain-syncing-sec0a319b35f/web), [Apple escrow](https://support.apple.com/guide/security/escrow-security-for-icloud-keychain-sec3e341e75d/web), [Apple iCloud data security/ADP](https://support.apple.com/en-us/102651), [Matrix E2EE spec](https://github.com/matrix-org/matrix-spec/blob/main/content/client-server-api/modules/end_to_end_encryption.md)
- Group keys: [OpenMLS](https://crates.io/crates/openmls), [OpenMLS audit](https://blog.phnx.im/openmls-independent-security-audit/), [p2panda-encryption](https://docs.rs/p2panda-encryption/latest/p2panda_encryption/), [Keyhive](https://github.com/inkandswitch/keyhive), [BeeKEM notebook](https://www.inkandswitch.com/keyhive/notebook/02/)
- Password managers: [1Password white paper](https://1passwordstatic.com/files/security/1password-white-paper.pdf), [Bitwarden whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/), [Bitwarden key hierarchy](https://sdk-api-docs.bitwarden.com/bitwarden_crypto/safe/key_hierarchy/index.html), [Proton Pass model](https://proton.me/blog/proton-pass-security-model), [ZKAE paper](https://eprint.iacr.org/2026/058), [FIDO CXF](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html), [FIDO CXP WD](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html)
