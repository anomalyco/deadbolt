# Deadbolt Revision 1 (`04b-revision-no-infra.md`) — Hostile Critique

Reviewed: 2026-10-15. Target: `04b-revision-no-infra.md` (read alongside `04-proposal.md` and `05-critique.md`). Claims verified against NIP-01, NIP-42, NIP-78 (including the Sept 2026 `AUTH` update), Blossom BUD-01/02/11/12, live Blossom server policies (`blossom.band`, `blossom.primal.net`, `24242.io`), and `docs.iroh.computer`.

---

## 1. Verdict

**The "devices are the source of truth; mailbox is a lossy cache with a repair loop" principle is the right way to go serverless, but the concrete Nostr/Blossom/iroh mechanics in `04b` will fail in production on day one.** Specifically: deriving the Nostr mailbox key from the *epoch key* makes Recovery Kit restore mathematically impossible after a single epoch rotation; sharing one Nostr signing key across devices on replaceable `kind: 30078` events lets a compromised device or a skewed repair loop clobber honest heads; major public Blossom servers reject `application/octet-stream` ciphertexts with HTTP `415`; ephemeral `kind: 2xxxx` PAKE messages vanish if the second device subscribes 500ms late; and `iroh` cannot hole-punch across NATs without a relay. Fix the epoch-discovery anchor, replace overwritable heads with append-only/per-device signed events, drop Blossom for normal vault snapshots, and keep all five non-mailbox P0 crypto fixes from `05-critique.md`.

---

## 2. How the "No-Infra" Constraint Changes `05-critique.md`

`04b` only supersedes §6 (Transports) and parts of §5 (Recovery) of `04-proposal.md`. Here is how each `05-critique.md` finding stands:

| `05-critique.md` Finding | Status Under `04b` (No Infra / Lossy Nostr Mailbox) |
|---|---|
| **CF-1:** HLC LWW future-dating / BFT CRDT violation | **UNCHANGED & MORE URGENT.** Still fatal. Public relays make injecting back-dated/future-dated segments from a compromised device trivial; causal parent ordering + whiteout watermarks + conflict-preserving item history remain mandatory. |
| **CF-2:** Persistent per-item keys + epoch chaining break PCS & "true delete" | **UNCHANGED.** Still fatal. Every edit still needs a fresh `CEK`, and epoch chaining must still break at snapshots. (Note: on public Nostr relays you cannot force relays to delete old events, which makes *not* chaining old epoch keys into new snapshots even more important if a device is later compromised.) |
| **CF-3:** Circular AEAD AAD (`segment ID` in AAD) & no XChaCha20-Poly1305 key commitment | **UNCHANGED.** Still fatal and unimplementable as written. |
| **CF-4:** Recovery Kit deriving mailbox credentials & per-device mailbox auth | **CHANGES SIGNIFICANTLY (see CF-N1 & CF-N2 below).** Unlike AWS/Cloudflare IAM keys, Nostr `secp256k1` keys *are* client-generated, so a Recovery Kit *can* deterministically derive a Nostr keypair without pre-registration. Conversely, because public Nostr relays do not evaluate Deadbolt's membership DAG, **per-device write revocation at the relay is impossible inside a shared keypair**. `04b` tries to solve this by deriving the mailbox key from the *epoch key*, which accidentally breaks Recovery Kit restore and offline device catch-up (CF-N1). |
| **CF-5:** Pairing endpoint-hook deadlock, QR-hijack race, missing mutual signature | **UNCHANGED** for QR pairing; **WORSE** for remote short-code PAKE over Nostr ephemeral events (see CF-N4). |
| **CF-6:** Hardware Enclave curve mismatch (P-256 vs Ed25519/X25519) & Local Unlock Key (`LUK`) | **UNCHANGED.** Still fatal on stolen/locked devices. |
| **Mailbox CAS (`05-critique.md` §3.9):** | **RESOLVED IN PRINCIPLE, BROKEN IN Nostr MECHANICS.** Dropping CAS in favor of single-writer logs + repair loop is right, but `04b`'s use of a shared `mailbox_key` on NIP-78 `kind: 30078` reintroduces cross-device head clobbering (CF-N2). |

---

## 3. Critical Flaws in `04b-revision-no-infra.md`

### CF-N1: The Epoch-Derived Mailbox Key Catch-22 (Breaks Recovery Kit Restore and Offline Device Catch-Up)
- **Where:** `04b` line 11 (*"Each vault derives, per epoch, a mailbox key (Nostr keypair) and a locator tag from the epoch key"*) and line 31 (*"recovery kit derives the mailbox key/locators → fetch newest snapshot + heads"*).
- **Why it sinks the design:**
  1. **Recovery Kit restore is impossible after epoch 0:** The printed Recovery Kit is a static 256-bit secret created at epoch 0. When a device is removed later, the vault rotates to epoch `e` with a fresh random `VEK_e`. Per line 11, epoch `e`'s `mailbox_key_e` and `locator_e` are derived from `VEK_e` (so relays cannot link epochs). When the user loses all devices and enters the Recovery Kit on a fresh install, **the Recovery Kit only knows its own secret—it does not know `VEK_e`!** The HPKE wrap of `VEK_e` for the Recovery Kit is stored inside epoch `e`'s events under `mailbox_key_e` / `locator_e`, which the Recovery Kit cannot query (or NIP-42 `AUTH` for!) without already knowing `VEK_e`. And because relays are lossy and the repair loop (line 17) only repairs the *latest* heads/snapshot, epoch 0 is gone.
  2. **Long-offline devices get stranded across multi-epoch rotations:** If Laptop C is offline while the vault rotates `epoch 1 → 2 → 3`, active devices are now repairing epoch 3 under `mailbox_key_3`. When lossy relays drop epoch 1 and epoch 2 events, Laptop C (which only has `VEK_1`) can only derive `mailbox_key_1` and is permanently marooned.
- **Concrete failure scenario:** User creates a vault (epoch 0), prints the Recovery Kit, pairs a second phone, later removes an old tablet (rotating to epoch 1, `VEK_1`), and 3 months later loses their remaining devices. They enter the 24-word Recovery Kit into a new laptop. The laptop derives `mailbox_key_0`, queries the relays, finds nothing (relays pruned old epoch 0 events; active devices only repaired `mailbox_key_1`), and the user loses their entire vault despite every relay still holding the live epoch 1 snapshot.
- **Fix:**
  - Introduce a **Root Bootstrap / Directory Channel** keyed by `K_bootstrap = HKDF(recovery_kit_secret, "deadbolt/bootstrap/v1")` (or `HKDF(vault_genesis_secret, ...)` stored on the Recovery Kit and all member devices):
  - Whenever a new epoch `e` is created, publish an encrypted **Epoch Directory record** containing `{epoch: e, wraps: [HPKE_Auth(member_i_x25519, VEK_e), HPKE_Auth(recovery_x25519, VEK_e)], current_relays}` and include **the latest Epoch Directory record** in the repair loop!
  - Now a recovering user (or an offline device returning after 5 epoch rotations) queries the bootstrap locator, unwraps the latest `VEK_e` using its X25519 key, derives `mailbox_key_e`, and fetches the live epoch `e` snapshot and heads. (To prevent a removed device—which knows `K_bootstrap`—from overwriting the bootstrap directory on relays, see CF-N2!)

### CF-N2: Shared `mailbox_key` + Addressable `kind: 30078` Allows Head Destruction by Removed Devices and Clock-Skewed Repair Loops
- **Where:** `04b` lines 11–18 (*"Each vault derives, per epoch, a mailbox key... Head: addressable kind 30078 (NIP-78), `d` = H(locator ‖ device ID)... Relay keeps only the newest... Spam/forgery: anyone can post with the locator; devices ignore anything not signed by a current member inside the ciphertext."*).
- **Why it sinks the design:**
  1. **Relays replace `kind: 30078` based on the OUTER signature (`mailbox_key`) and OUTER `created_at`—never the inner device signature!** Per NIP-01, a relay keeps **only one** event per `(pubkey, kind=30078, d)`. Because every device in epoch `e` shares the same outer Nostr `mailbox_key`, any device holding `mailbox_key` can publish a `kind: 30078` event for `d = H(locator ‖ victim_device)` with `created_at = now + 600` containing garbage ciphertext. **The relay immediately deletes the honest device's real head event** and replaces it with the garbage event. Other devices fetch the garbage event, reject its inner signature (per line 18), and **now have zero heads/snapshot pointers!**
  2. **The Repair Loop clobbers newer heads with older heads under clock skew:** Suppose Device A publishes `head(seq=10)` at `t=1000` and then `head(seq=11)` at `t=1002`. Device B (whose system clock is 5 seconds fast, `t=1006`, and which only has `seq=10` so far) sees that Relay 3 is missing A's head and re-signs/re-publishes A's `seq=10` head with `created_at = 1006` (or relays sync via negentropy). Because `1006 > 1002`, **Device B's repair of `seq=10` overwrites `seq=11` on the relays!** Conversely, if Device B re-broadcasts A's raw original JSON event (`created_at = 1000`) two days later, relays reject it with `["OK", ..., false, "invalid: event creation date is too far off from the current time"]` (NIP-01).
  3. **NIP-01 1-second timestamp collision:** `created_at` is an integer unix timestamp in seconds. If a device updates its `kind: 30078` head twice in the same second (`seq=5` then `seq=6`), NIP-01 mandates keeping whichever event has the *lexicographically lowest `id` hash*—silently dropping `seq=6` 50% of the time!
- **Concrete attack/failure scenario:**
  - *Attack:* Device B is compromised. Before (or right as) Device A removes Device B, Device B publishes `kind: 30078` events under `mailbox_key_e` (and under `K_bootstrap` if `K_bootstrap` used `kind: 30078`!) with `created_at = now + 10 min` and random noise as `content` for every device's `d` tag across all relays. All honest head and snapshot pointers are wiped from every relay for the next 10 minutes; a background loop on B repeats this indefinitely for `K_bootstrap`.
  - *Failure:* User edits two passwords in 800ms on Laptop A (`seq=10` and `seq=11` share `created_at`). Half the relays keep `seq=10` and drop `seq=11` because `id(seq=10) < id(seq=11)`.
- **Fix:**
  1. **Enforce strictly monotonic `created_at` per `(pubkey, d)`:** Never emit a replaceable/addressable Nostr event with `created_at <= last_emitted_created_at`; set `created_at = max(unix_now(), last_created_at + 1)`.
  2. **Do not use a shared Nostr signing key on overwritable `kind: 30078` slots where a compromised peer holds the key:**
     - Either (a) make Heads and Epoch Directory records **regular events (`kind: 78` per NIP-78)** queried with `{"kinds": [78], "authors": [mailbox_pubkey], "#d": [d_tag], "limit": 10}` so a bogus write **cannot overwrite** the valid event on the relay (clients fetch the recent N events, verify the inner Ed25519 signature, and pick the highest valid `seq`/`epoch`!), **OR**
     - (b) have each device sign its `kind: 30078` head using an **epoch-blinded per-device `secp256k1` key** derived from that device's own private key (announced inside the encrypted membership log), so no other device can ever forge an outer signature for Device A's `(pubkey, 30078, d)` slot! (Use `(a)` for the Bootstrap Directory and Snapshot pointers so any honest device can repair them without enabling overwrite attacks.)

### CF-N3: Major Public Blossom Servers Reject Arbitrary Ciphertext (`415 Unsupported Media Type`) and Are Unnecessary for Vault Snapshots
- **Where:** `04b` lines 10, 15 (*"Snapshot: chunks on Blossom (content-addressed, encrypted), pointer in a head-like addressable event"*).
- **Why it sinks the design (verified against live Blossom servers):**
  1. **Public Blossom servers are media CDNs, not generic binary stores:**
     - **`blossom.band` and `blossom.nostr.build`** (the largest free Blossom hosts) restrict free uploads to **images, audio, and video only** (up to 20 MiB); even paid tiers only add PDF, SVG, and ZIP. Uploading `application/octet-stream` fails with `415 Unsupported Media Type`.
     - **`blossom.primal.net`** returns a misleading `200 OK` to `HEAD /upload` preflights and then rejects `PUT /upload` of `application/octet-stream` with `415 Unsupported Media Type`.
     - **`24242.io`** auto-deletes blobs after 60 days and enforces *"First person to upload an object owns it"* (affecting `DELETE`).
  2. **Vault snapshots are tiny and do not need Blossom:** A compressed password vault of 1,000 items is **~50–150 KB** (~65–200 KB base64)—that is **3 to 8 Nostr `kind: 78` events**! Adding Blossom for v1 vault snapshots introduces a second network protocol, a second failure mode (where the Nostr pointer survives but the Blossom server rejected or evicted the chunk), and `415` rejections on the most popular public servers.
- **Concrete failure scenario:** Deadbolt v1 ships configured with `blossom.primal.net` and `blossom.band`. Every snapshot upload fails with HTTP `415 Unsupported Media Type` (or gets corrupted if disguised with a fake `.png`/`.mp4` header on a server that runs media validation/transcoding). Snapshots are never stored, so recovery and compaction fail across the board.
- **Fix:**
  - **Store v1 vault snapshots directly on Nostr relays as a small manifest (`kind: 78`) pointing to 1–N chunked `kind: 78` events (≤ 22 KB raw / ~30 KB base64 each).**
  - Reserve Blossom strictly as an **optional attachment store for large binary files (> 256 KB)** on servers explicitly verified to accept `application/octet-stream` (e.g., `nostr.download`, `24242.io`, or user-configured Blossom/S3).

### CF-N4: Ephemeral Nostr Events (`kind: 2xxxx`) Drop PAKE Handshakes on Normal Human Timing and Expose Single-Attempt Codes to Public Bot Sniping
- **Where:** `04b` line 28 (*"Remote short-code: PAKE messages exchanged as ephemeral Nostr events (kind 2xxxx) keyed by H(code nameplate) — no magic-wormhole server needed."*).
- **Why it sinks the design:**
  1. **Ephemeral events (`20000 <= kind < 30000`) are never stored by relays (`NIP-01`):** If Device A sends PAKE Message 1 even **100ms before** Device B finishes opening WebSocket connections and sending `["REQ", sub_id, {"kinds": [2xxxx], "#d": [H(nameplate)]}]` to the relay, the relay drops Message 1 on the floor (NIP-01: `mute: no one was listening to your ephemeral event and it wasn't handled in any way, it was ignored`). Unlike Magic Wormhole's rendezvous server—which buffers the nameplate message for a few minutes until the peer connects—Nostr ephemeral events have **zero buffering**.
  2. **Public relay bot griefing / dictionary attacks:** Anyone subscribed to `{"kinds": [2xxxx]}` on major public relays sees every active `H(nameplate)` tag in real time the instant Message 1 appears, and can immediately reply with a garbage Message 2 to burn the "single attempt" (`04-proposal.md` §4 line 57: *"single attempt"*)—a 100% reliable global DoS on all remote pairings—or run an automated online guess against every pairing session.
- **Concrete failure scenario:** User generates a pairing code on Desktop A (`427-maple-river`) and types it into Phone B 6 seconds later. Desktop A published PAKE Message 1 as `kind: 24200` at `t=0s`; Phone B subscribed at `t=6s`. Phone B never receives Message 1 and hangs until timeout. If Desktop A retries, a script watching `kind: 24200` on `nos.lol` injects a bogus responder packet in 20ms, aborting the single-attempt PAKE.
- **Fix:**
  1. **Use short-lived regular events (`kind: 78`) with a NIP-40 expiration tag (`["expiration", "<now + 180>"]`), or have the initiator re-broadcast PAKE Message 1 every 2 seconds until Message 2 arrives.**
  2. **Split the short code into `(nameplate, pake_secret)` where `pake_secret` has ≥ 50 bits of entropy (e.g., 4 diceware words)**, and derive **both** the deterministic subset of rendezvous relays and an outer **channel signing key (`K_pair_chan = HKDF(pake_secret, "deadbolt/pair-outer/v1")`)** from the code! If every pairing event must be outer-signed by `K_pair_chan` (or carry a proof of knowledge of a half-secret), a passive bot on a public relay cannot inject a fake Message 2 to grief the session without already knowing the code, while CPace still protects against active MITM if the user makes a typo or uses a shorter secret.

### CF-N5: `iroh` Cannot Hole-Punch Across NATs Without a Relay (Breaking Option c), and n0's Paid Shared Relays Cannot Authenticate Serverless Clients (Breaking Option b)
- **Where:** `04b` lines 22–23 (*"Options: (a) ship with n0 public relays and accept the risk, (b) pay n0 (their infra, not ours), (c) make iroh optional and fall back to Nostr-only sync when no direct path exists... Recommend (c) as the floor and (a/b) as the fast path."*).
- **Why it sinks the design (verified against `docs.iroh.computer`):**
  1. **Without a relay, `iroh` cannot hole-punch across NATs at all:** Per `docs.iroh.computer/concepts/nat-traversal` (*"1. Initial Contact Through a Relay: Both peers first connect to a shared relay server. The relay acts as a meeting point where peers can coordinate before a direct path is established"*), `iroh` does **not** coordinate UDP hole-punching over Nostr or DHT; it requires both endpoints to exchange reflexive UDP addresses and synchronize simultaneous outbound packets *through an iroh relay*. Without an iroh relay, "direct QUIC" only works on the **same LAN (mDNS)** or when a device has a publicly routable IPv6 / port-forwarded IPv4!
  2. **Option (b) (n0 paid Shared Relays) requires a project-wide root secret:** Per `docs.iroh.computer/concepts/relays` (*"Authentication"*), n0's Shared and Dedicated relays authenticate endpoints using tokens signed locally by a **single project-wide root API key** (*"separately issued per-endpoint credentials are not implemented"*). With no Deadbolt backend server to mint short-lived tokens, you would have to embed your paid n0 project root API key inside the open-source client binary—where anyone can extract it, abuse your paid quota, or force you to revoke the key (breaking all deployed clients).
- **Concrete failure scenario:** You ship Option (b) by embedding your n0 Pro API key in the binary; someone extracts it in 10 minutes, runs `sendme` traffic through it, and you revoke the key, breaking iroh relay access for every Deadbolt user. Or you disable relays in Option (c), and two devices on different networks (phone on 5G, laptop on home Wi-Fi) can **never** establish an iroh connection, falling back 100% of the time to polling Nostr relays.
- **Fix:**
  1. **Be honest about the architecture:** When devices are not on the same LAN, if you don't run a relay and don't use n0's public relays, **Nostr IS the sync transport** (not just a fallback cache), and `iroh` is strictly a **same-LAN (`iroh-mdns-peer-lookup`) + opportunistic public-relay fast path**.
  2. For `iroh` over the internet without Deadbolt servers: use **n0 public relays (`presets::N0` with DNS publishing disabled)** as the default zero-infra opportunistic fast path, allow users to configure a custom `iroh-relay` URL, and if you later pay n0 without running a token server, use a **Dedicated relay with dashboard authentication toggled OFF** (which n0 explicitly supports: *"Turning authentication off from the dashboard tells the relay to admit any endpoint without a token"*).

---

## 4. Significant Issues in `04b` (Verified Protocol & Relay Realities)

1. **NIP-78 (`kind: 30078` / `kind: 78`) + Sept 2026 NIP-42 `AUTH` interaction with rotating `mailbox_key`s:**
   - **Verified spec fact:** In September 2026, NIP-78 was updated to state that relays `SHOULD` require NIP-42 `AUTH` before accepting or serving `kind: 78` and `kind: 30078`, and `SHOULD` only serve them to a client authenticated *as the event's author pubkey*.
   - **Two consequences `04b` missed:**
     - First, **every reader must possess the outer `mailbox_key` *private* key** (not just the public key or locator tag) to pass NIP-42 `AUTH` when reading `kind: 78` / `kind: 30078` from spec-compliant relays.
     - Second, on **paid/allowlisted Nostr relays** (which use NIP-42 `AUTH` to check whether your `npub` paid for admission), **rotating `mailbox_key` on every epoch breaks relay admission** (`["OK", ..., false, "restricted: not allowed to write"]`) because the relay only whitelisted the user's static paid `npub`! If a user configures a paid relay, Deadbolt must support authenticating NIP-42 with a user-supplied relay `npub` while keeping the event author / encryption keys separate (note: NIP-78's owner-only read rule requires the NIP-42 `AUTH` pubkey to match the event's `pubkey`!).

2. **Tag-indexing rules in NIP-01 (`#d` vs custom locator tags) and redundant locator tags:**
   - **Verified spec fact (`NIP-01`):** Relays **only index single-letter tags (`a`–`z`, `A`–`Z`)** for filter queries (`#d`, `#t`, `#x`, etc.).
   - In `04b` lines 11–14, each vault already derives a unique per-epoch **mailbox key (`pubkey`)** *and* tags events with a **locator**. If `mailbox_key` is already unique per `(vault, epoch)`, querying `{"authors": [mailbox_pubkey], "kinds": [78, 30078]}` already isolates that vault and epoch! Adding a plaintext locator tag is redundant unless aligned to a single-letter tag (`["d", "<id>"]`) to distinguish sub-streams (`#d: ["seg"]`, `#d: ["head:<H(dev)>"]`, `#d: ["snap"]`).

3. **Base64 encoding inflation breaks the "≤ ~32 KB" segment limit on real relays:**
   - `04b` line 13 says: *"encrypted segment payload (≤ ~32 KB; split larger)"*.
   - Nostr `content` is a JSON UTF-8 string (`NIP-01`). Base64-encoding 32 KB of binary ciphertext produces **43.7 KB of ASCII**, plus ~1 KB of JSON envelope (`id`, `pubkey`, `sig`, `tags`), totaling **~45 KB**. Many public relays enforce `max_message_length: 32768` (32 KB) or `16384` (16 KB) (`03-mailbox-pairing-keys.md` §A.1 line 54).
   - **Fix:** Cap raw binary segment chunks at **16 KB** (which becomes ~22 KB base64, safely below a 32 KB wire limit, or split further if a relay advertises `max_message_length: 16384` via NIP-11).

4. **Repair loop write-amplification and non-deterministic outer `event.id`s:**
   - `04b` line 17 says: *"on every sync, a device checks each relay for the latest heads/snapshot and re-publishes what's missing."*
   - If Device A creates a segment and signs the outer Nostr event at `created_at = 1000`, and later Device B notices Relay 4 is missing that segment and *re-signs* a new outer Nostr wrapper at `created_at = 2000`, the new wrapper has a **different `created_at` and therefore a different Nostr `event.id` (`sha256`)**! Now Relay 1 has `event.id = X` and Relay 4 has `event.id = Y` for the exact same segment, defeating Nostr event-ID deduplication and causing devices to download duplicate segments from every relay!
   - **Fix:** Make the outer Nostr event wrapper **100% deterministic per segment** (or store and re-broadcast the author's original signed Nostr `EVENT` JSON verbatim, falling back to re-wrapping only if a relay rejects the old `created_at` timestamp, and include `["d", "<segment_blake3_hash>"]` so devices check missing segments by `d`-tag hash before downloading `content`!).

5. **Lossy mailbox vs. local segment compaction hazard:**
   - In `04-proposal.md` §3 line 51, once a device writes or ingests a snapshot, it drops older segments. In `04b` line 8, relays can drop the snapshot at any time.
   - If devices dropped their old segments after a snapshot, and the relays subsequently lose that snapshot, no device can re-publish the old segments!
   - **Fix:** Every device must be able to **re-export a fresh signed snapshot from its current local database at any time** (and must retain its local copy of the latest signed snapshot + any post-snapshot segments) so the repair loop can always heal a total relay wipe.

6. **Drop `pkarr` on the Mainline DHT (`04b` line 24):**
   - `04b` line 24 suggests *"pkarr on the Mainline DHT (iroh supports it) or a Nostr addressable event carrying current node addresses."*
   - Do **not** use the BitTorrent Mainline DHT: it publishes every device's `EndpointId` and home relay URL in plaintext to millions of untrusted DHT nodes and adds multi-second lookup latency (`docs.iroh.computer/connecting/dht-address-lookup`). You already have Nostr: put each device's encrypted current `EndpointAddr` (LAN IP:port + relay URL) **inside its encrypted Nostr `Head` event**. That gives sub-second lookup and hides `EndpointId`s and relay URLs from everyone outside the vault.

---

## 5. Prioritized Changes Before v1 (Combining `05-critique.md` + `06-critique-no-infra.md`)

1. **[P0 — Recovery & Epoch Discovery (`CF-N1`)] Add a Root Bootstrap Directory channel derived from the Recovery Kit:**
   - Derive `K_bootstrap = HKDF(recovery_kit_secret, "deadbolt/bootstrap/v1")`. On every epoch rotation, publish an encrypted **Epoch Directory event (`kind: 78`)** under `K_bootstrap` containing `VEK_e` HPKE-wrapped to each active member and to the `tier 0` Recovery Kit, and keep the latest directory event alive via the repair loop. Without this, Recovery Kit restore and multi-epoch offline catch-up are dead after epoch 0.
2. **[P0 — Nostr Event Model (`CF-N2`, `CF-N3`)] Use `kind: 78` (append-only regular events) with `#d` tags instead of shared-key `kind: 30078` and Blossom for vault snapshots:**
   - Do not let multiple devices share a signing key on overwritable `kind: 30078` events (where one compromised device or clock-skewed repair loop wipes honest heads). Use `kind: 78` with single-letter `["d", ...]` tags for segments, snapshot chunks (≤ 16 KB binary / ~22 KB base64 each), and bootstrap directory records so relays cannot be tricked into overwriting valid state and snapshots don't hit Blossom `415 Unsupported Media Type` rejections.
3. **[P0 — Core Crypto & CRDT (`05-critique.md` `CF-1`, `CF-2`, `CF-3`)] Keep all three core crypto/CRDT fixes from `05-critique.md`:**
   - Causal parent ordering + `RemoveDevice` whiteout watermarks + conflict-preserving item history (no raw HLC LWW); fresh `CEK` per edit + unchained snapshot epochs (no reused item keys across epochs); and non-circular AEAD AAD + BLAKE3 key commitment for XChaCha20-Poly1305.
4. **[P0 — Pairing & Transports (`CF-N4`, `CF-N5`, `05-critique.md` `CF-5`)] Fix Nostr PAKE buffering/bot-protection and `iroh` discovery:**
   - For remote short-code pairing, use `kind: 78` with NIP-40 expiration + 2s initiator re-transmit (not unbuffered `kind: 2xxxx`), outer-sign pairing packets with a key derived from a ≥50-bit code (CPace on `curve25519-dalek` `ristretto255`), require mutual `DeviceBind` signatures, and put encrypted `iroh` `EndpointAddr`s inside Nostr `Head` events (disable `dns.iroh.link` and Mainline DHT).
5. **[P0 — Local Device Security (`05-critique.md` `CF-6`)] Decouple `iroh` `EndpointId` from the vault signing key and protect local state with Hardware P-256 + `Argon2id`:**
   - Keep `EndpointId` separate from the device's Ed25519 vault key, wrap the local DB and keys under a Local Unlock Key (`LUK`) gated by a hardware P-256 enclave key (Secure Enclave/TPM/StrongBox) + `Argon2id(master_passphrase)`, and ship an encrypted local backup file export on day 1 as the ultimate hedge against total public-relay loss.
