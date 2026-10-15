# Deadbolt v0 — Hostile Design Critique

Reviewed: 2026-10-15. Target: `04-proposal.md` against `01-inkandswitch.md`, `02-rust-sync-stacks.md`, `03-mailbox-pairing-keys.md`.

---

## 1. Verdict

**Do not build v0 as written.** While the high-level shape (iroh 1.x transport, per-device signed logs, no accounts, O(n) HPKE epoch wraps instead of MLS) is the right starting point, the cryptographic and replication internals contain **six critical flaws** that break Post-Compromise Security, allow trivial vault poisoning by a removed device, make the AEAD construction unimplementable as written, and contradict hardware enclave capabilities. Fix the key hierarchy, causal ordering, recovery authority tier, and mailbox authentication before writing code.

---

## 2. Critical Flaws (Security or Correctness Bugs That Sink It)

### CF-1: HLC-based LWW without causal validation allows a compromised/removed device to permanently overwrite the vault ("Future-Dating" / BFT CRDT violation)
- **Where:** §1 (lines 35–38), §3 (line 48: *"LWW by (hybrid logical clock, device ID)"*).
- **Why it sinks the design:** An HLC embeds an unverified physical wall-clock timestamp asserted by the authoring device. In a P2P/mailbox system with no trusted clock authority, a compromised device (or a removed device back-dating an op under an epoch key `VEK_e` it already holds) can sign operations with `HLC = (2099-01-01, 0, device_id)` or `u64::MAX`. Because conflict resolution compares `(HLC, device_id)`, those poisoned ops beat every honest edit the user makes for the next 73 years, and merging that HLC drags honest devices' local HLC clocks into the far future or causes integer overflow. Worse, content ops do not cite membership heads (`before(u)` in Kleppmann's PaPoC 2022 BFT CRDT paper, `01-inkandswitch.md` §6), so replicas cannot deterministically decide whether an op was written while its author was still authorized.
- **Concrete attack scenario:** Laptop B is stolen. The user removes Laptop B on Phone A (advancing to epoch 2) and rotates their banking password on Phone A at `HLC = 2026-10-15T12:00:00Z`. Laptop B (which still has `VEK_1` and mailbox access) writes a segment under epoch 1 setting the banking item's password to an attacker-controlled credential (or a tombstone) with `HLC = 2099-01-01T00:00:00Z` and uploads it to the mailbox. Phone A syncs from the mailbox, validates B's signature under epoch 1, compares `2099 > 2026`, and **silently overwrites the newly rotated banking password with the attacker's epoch-1 payload**.
- **Fix:**
  1. **Order item edits causally, never by raw HLC.** Each item op must reference the `op_id`s (hashes) of the item state it overwrites. One edit supersedes another iff it is in its causal future.
  2. **Causal dominance of epochs:** Any edit written in epoch `e+1` (where `e+1` causally follows `RemoveDevice(B)`) strictly dominates any concurrent op written by `B` in epoch `e` or earlier, regardless of timestamps.
  3. **Whiteout watermark in `RemoveDevice`:** `RemoveDevice(B, last_valid_head_of_B)` must record the latest `(seq, segment_hash)` from `B` known to the remover (`01-inkandswitch.md` §3.4a). Any segment from `B` not in the causal past of `last_valid_head_of_B` is dropped ("whiteout").
  4. **Never silently drop concurrent edits to credentials:** When two honest devices make genuinely concurrent edits to an item, break ties deterministically by `(clamped_hlc, op_hash)` for the active field, **and** append the losing field value into the item's `history` / `conflicts` list so a generated password or TOTP seed is never lost. Reject any op whose HLC exceeds `local_now + MAX_DRIFT` (e.g., 10 minutes) at live ingest.

### CF-2: Persistent "per-item keys" break Post-Compromise Security (PCS) on password rotation and contradict the "true delete" claim
- **Where:** §2 (lines 41–43).
- **Why it sinks the design:** The proposal puts a persistent **per-item key (`IK_i`)** under the vault epoch key (`VEK_e`) and claims two things:
  1. Removing a device rotates `VEK_e → VEK_{e+1}` to protect new edits, while the user rotates real passwords (§Threat model line 19).
  2. Deleting an item drops its `IK_i` from future snapshots, making lingering mailbox segments unreadable ("true delete").
  **Both claims fail:**
  - **PCS failure on existing items:** If `IK_i` is a persistent per-item key that gets re-wrapped under `VEK_{e+1}` when the epoch rotates (as described in `03-mailbox-pairing-keys.md` §D.3 line 258), then **the removed device already cached `IK_i` during epoch `e`!** When the user edits item `i` in epoch `e+1` to rotate their compromised password, encrypting the new password under `IK_i` lets the removed device decrypt the newly rotated password directly from the mailbox or relay without needing `VEK_{e+1}`.
  - **"True delete" failure on lingering segments:** For peers to decrypt incremental segments before a snapshot is created, each segment must either carry `Wrap(VEK_e, IK_i)` or derive the op key from `VEK_e`. Because §2 line 42 states that *"epoch keys are chained (each new epoch key also wraps the previous one)"*, every current device holds `VEK_e` forever. Therefore, any lingering segment in the mailbox still has its wrapped `IK_i` right next to it and can be unwrapped with `VEK_e` forever—dropping `IK_i` from a later snapshot deletes nothing from the old segment.
- **Concrete attack scenario:**
  1. Phone B is stolen and removed (`epoch 1 → epoch 2`). Deadbolt prompts the user on Laptop A to change their GitHub password. Laptop A updates the GitHub item under `IK_github` (wrapped under `VEK_2`) and pushes the segment to the S3 mailbox. Phone B downloads the segment from S3 and decrypts the new GitHub password using its cached `IK_github` from epoch 1.
  2. The user deletes a cryptocurrency seed item, waits for all devices to write a snapshot, and later has a device compromised. Because `VEK_2` chains `VEK_1` and the old segment still sits in S3 (or on a backup), the attacker unwraps `VEK_1`, unwraps `IK_seed` from the old segment header, and decrypts the "truly deleted" seed.
- **Fix:**
  1. **Never reuse a content encryption key (`CEK`) across edits.** Every item write generates a fresh random 256-bit `CEK` (wrapped by the current `VEK_e`), or derives a one-time op key from `VEK_e` + random salt (`03-mailbox-pairing-keys.md` §C line 185: Bitwarden SDK rule *"a CEK is freshly generated… never reused"*).
  2. **Break the epoch chain at snapshots:** When a compacted snapshot is written at epoch `e`, re-wrap only the *live* item CEKs under `VEK_e` and **do not chain `VEK_{e-1}` inside `VEK_e`**. Once all active member devices acknowledge the snapshot frontier, delete pre-snapshot segments from the mailbox and zeroize `VEK_{0..e-1}` locally. Only then is lingering ciphertext actually unreadable.

### CF-3: Circular AEAD Associated Data (`segment ID = BLAKE3(ciphertext)` inside AAD) and missing key commitment in XChaCha20-Poly1305
- **Where:** §2 (line 44), §3 (line 49).
- **Why it sinks the design:**
  1. **Cryptographic circularity:** §2 specifies `associated data = vault ID ‖ epoch ‖ item ID ‖ schema version ‖ segment ID`. §3 defines `Segment ID = BLAKE3 of ciphertext`. **You cannot pass `BLAKE3(ciphertext)` as the AEAD `AAD` input when producing `ciphertext`!** An implementer forced to resolve this will drop `segment ID` from the AAD, leaving item ciphertexts unbound to their enclosing segment, author device, sequence number, and causal parents.
  2. **Missing author/sequence/op-type binding in AAD:** Because all devices in epoch `e` share `VEK_e`, omitting `author_device_id`, `segment_seq`, `op_index`, `parent_op_ids`, and `record_type` from the AEAD AAD allows a compromised device to strip an honest device's outer signature, transplant or replay an old item ciphertext into a new segment, or swap wrapped keys between items.
  3. **No Key Commitment:** XChaCha20-Poly1305 is **not key-committing** (`01-inkandswitch.md` §1 line 47, §3.7 Threat T7). A malicious device can craft a single item ciphertext `C` and wrap two different keys `K_1, K_2` in the HPKE/wrapped-key table such that Device A and Device B both verify the same segment hash and Poly1305 tag, but decrypt two different passwords—permanently breaking replica convergence.
- **Concrete attack scenario:** A compromised device publishes a segment containing an item ciphertext `C` and per-recipient or per-epoch key wraps `K_1` and `K_2` constructed via a Poly1305 multi-key collision. Phone A decrypts the bank password as `correct-horse`, while Laptop C decrypts the exact same item version as `attacker-password`. Both devices report the same segment hash and believe they are in sync.
- **Fix:**
  1. Bind pre-encryption coordinates into the AEAD AAD: `AAD = "deadbolt/item/v1" ‖ vault_id ‖ epoch ‖ author_device_id ‖ segment_seq ‖ op_index ‖ causal_parents_hash ‖ item_id ‖ op_kind ‖ schema_version`.
  2. Define `segment_id = BLAKE3(canonical_segment_header ‖ op_ciphertexts)` and sign `"deadbolt/seg-sig/v1" ‖ segment_id` with the author's Ed25519 key.
  3. Enforce **key commitment**: for every AEAD encryption under key `K`, compute `key_commit = BLAKE3::derive_key("deadbolt/key-commit/v1", K)` and include `key_commit` inside the signed segment header (and inside the AAD), or derive `K` deterministically from a committed seed so the recipient recomputes and verifies `key_commit` before accepting the plaintext.

### CF-4: Deriving mailbox credentials from the Recovery Kit is impossible for S3/R2 and prevents revoking a removed device's mailbox access
- **Where:** §5 (line 61: *"The kit secret also derives the mailbox location/credentials"*).
- **Why it sinks the design:**
  1. **Cloud credentials are provider-issued, not client-derived:** AWS S3 and Cloudflare R2 `AccessKeyId` / `SecretAccessKey` values are generated by AWS/Cloudflare IAM when a bucket token is created—they **cannot** be deterministically derived via HKDF from a 256-bit Recovery Kit generated offline at vault creation (§5 line 60).
  2. **Permanent mailbox access for revoked devices:** Every active device must hold the mailbox credentials to run `put_segment` and `put_head` during normal sync. If mailbox credentials are static and derived from the printed Recovery Kit, **removing a compromised device (`RemoveDevice`) cannot revoke its mailbox access** without invalidating the user's printed paper Recovery Kit!
- **Concrete attack scenario:**
  - *Failure 1 (Total data loss on restore):* User creates a vault on day 1, prints the Mandatory Recovery Kit, and configures an R2 bucket on day 10. On day 60, the user loses their phone and laptop, buys a new laptop, and enters the 24-word Recovery Kit. The new laptop derives a 32-byte key that has nothing to do with their R2 endpoint URL or Cloudflare S3 credentials. Restore fails completely.
  - *Failure 2 (Unrevocable attacker):* Laptop B is compromised and removed from the vault. Because mailbox credentials are static (tied to the Recovery Kit), Laptop B retains full write/delete access to the mailbox, continuously scraping new segments, corrupting heads, or exhausting storage quotas.
- **Fix:**
  1. **For the Deadbolt storage peer (`iroh`):** Authenticate every connection with the **connecting device's own Ed25519 key** verified against the signed membership log (which the storage peer stores and verifies without decryption keys, matching Keyhive/Subduction's `Relay` capability in `01-inkandswitch.md` §3.2 & §4.2). The Recovery Kit's Ed25519 public key is in the membership log as the `Recovery` root principal, so it can authenticate to the storage peer during disaster recovery, while `RemoveDevice(B)` immediately cuts off `B` at the storage peer.
  2. **For BYO S3/R2:** Either (a) require the user to save/print the S3 credentials alongside the kit when configuring S3, or (b) publish an **encrypted mailbox bootstrap blob** (containing the S3 endpoint + read/write credentials encrypted under `HKDF(kit_secret, "deadbolt/mailbox-bootstrap/v1")`) to a deterministic location (or a Pkarr DNS TXT record signed by a key derived from `kit_secret`, as noted in `03-mailbox-pairing-keys.md` §A.3 line 75) and rotate the S3 credentials whenever a device is removed.

### CF-5: Pairing flow has an endpoint-hook deadlock, a QR-hijack MITM race, and no mutual signature (forced adoption)
- **Where:** §4 (lines 54–56), §6 (line 66).
- **Why it sinks the design:**
  1. **Endpoint-hook deadlock:** §6 says *"endpoint admits only NodeIds in the current membership."* In §4, the new device dials the existing device over iroh **before** `AddDevice` is signed. Its `EndpointId` is not in the membership log, so the endpoint hook rejects the pairing connection before the HMAC runs.
  2. **QR-hijack race (applicant public key is not in the QR):** In §4, the *existing* device shows the QR (`NodeAddr + secret + vault ID`) and the *new* device scans it and sends its public keys + device name. Because the QR does not contain the new device's public key, anyone who sees the QR (a shoulder-surfer, webcam, screen share, or malware) can race the legitimate device, compute the valid HMAC using the QR secret, and send `device_name = "iPhone 17"`. The existing device shows `"Add iPhone 17, <fingerprint>?"`. Humans click "Confirm" when the device name matches; they do not manually read 64-character hex fingerprints across two screens. (In Signal, `03-mailbox-pairing-keys.md` §B.2, the **new device** shows the QR containing its own public key and the existing device scans it, which cryptographically pins the new device's public key with zero fingerprint comparison!)
  3. **No mutual signature or KEM proof-of-possession:** The new device sends its Ed25519 + X25519 public keys without signing the X25519 key or counter-signing the `AddDevice` transcript. Without mutual signatures (`03-mailbox-pairing-keys.md` §B.2 WhatsApp `Account Signature` + `Device Signature`, §C.1 Scarlata et al. 2026 attack #5), an attacker can induct a victim device into an attacker-controlled vault (so passwords the user creates next sync straight to the attacker) or swap the X25519 KEM key for an unauthenticated public key (Scarlata et al. attack #1).
- **Concrete attack scenario:** A user pairs their phone to their laptop on a train or during a video call. An observer captures the QR code on the laptop screen and connects 100ms before the phone, claiming the name `"iPhone"` and presenting attacker keys. The user taps "Confirm" on the laptop, wrapping `VEK_e` and streaming the entire vault snapshot to the attacker.
- **Fix:**
  1. **Expose a separate `deadbolt/pair/1` ALPN** that is enabled *only* while the pairing modal is open (max 2 minutes), accepts **at most one connection**, and immediately closes and invalidates the one-time secret on the first failed HMAC or completed handshake. Keep `deadbolt/sync/1` strictly restricted to current membership `EndpointId`s.
  2. **Prefer New-Device-Shows-QR** (applicant displays QR containing `applicant_ed25519 ‖ applicant_x25519 ‖ pairing_secret ‖ relay_hint`; sponsor scans). When the sponsor must display the QR (camera-less desktop applicant), derive a 6-digit **Short Authentication String (SAS)** from the TLS exporter + both public keys (`HKDF(secret, tls_exporter ‖ sponsor_pub ‖ applicant_ed25519 ‖ applicant_x25519)`) and require the user to type the 6 digits shown on the applicant into the sponsor (not a Yes/No button on a self-reported device name).
  3. **Require mutual signatures:** The applicant signs `DeviceBind(vault_id, sponsor_id, applicant_ed25519, applicant_x25519, epoch)` with `applicant_ed25519` (proving possession of both keys and consenting to join `vault_id`), and `AddDevice` embeds that signature inside the membership log.

### CF-6: Hardware keystore claim is impossible as specified (Secure Enclave / TPM / StrongBox do not support Ed25519 or X25519, and iroh requires raw private key bytes in RAM)
- **Where:** §1 (line 33: *"Each device: Ed25519 identity key = its iroh NodeId; X25519 key for HPKE wraps. Private keys in OS keystore / Secure Enclave where available."*).
- **Why it sinks the design:**
  1. **Curve incompatibility with hardware enclaves:** Apple Secure Enclave, Android StrongBox, and Windows TPM 2.0 platform crypto providers **only support NIST P-256** (and RSA on some TPMs) for non-exportable hardware keys—**never Ed25519 and never X25519**.
  2. **iroh requires raw key bytes:** `iroh::Endpoint::builder().secret_key(...)` requires the raw 32-byte Ed25519 secret key in process memory to run QUIC/TLS 1.3 (RFC 7250). It cannot delegate signing to an opaque hardware handle.
  3. **Coupling transport identity to vault identity:** Making the vault's Ed25519 signing key equal to the `iroh` transport key directly violates `03-mailbox-pairing-keys.md` §D.1 (line 231) and forces the vault signing key to stay decrypted in RAM whenever the networking stack is listening.
- **Concrete attack scenario:** On macOS/Windows/Linux, because Secure Enclave/TPM cannot hold Ed25519/X25519, the implementation stores the raw 32-byte keys as generic secret blobs in the OS login keychain. The user's laptop is stolen while asleep (logged in, screen locked or unlocked via weak OS login) or hit by a local infostealer; the attacker reads the exportable X25519 key from the keychain, unwraps `VEK_e`, and decrypts the local vault database offline with zero rate-limiting.
- **Fix:**
  1. **Separate keys:** Give each device (a) an `iroh` transport key (`EndpointId`), (b) a Vault Signing key (`Ed25519`, which signs a delegation certificate over the current `EndpointId`), and (c) an HPKE decryption key (`X25519`).
  2. **Hardware-backed P-256 + Argon2id local envelope (`LUK`):** Encrypt the local vault database and the device's `Ed25519`/`X25519`/`VEK` secret bytes at rest under a **Local Unlock Key (`LUK`)**. Protect `LUK` with a **non-exportable P-256 key in Secure Enclave / StrongBox / TPM** (via ECIES/ECDH gated by biometric/passcode user presence, which gets silicon-enforced attempt rate limiting) combined with `Argon2id(master_passphrase)`. Zeroize `LUK`, `Ed25519`, `X25519`, and `VEK` from RAM when the vault locks.

---

## 3. Significant Issues (Design Choices That Will Hurt Later)

1. **Replication model (per-device sequential logs break on OS backup restore and snapshot gaps):**
   - Assuming each device's log is strictly linear (`device_id → seq`) fails as soon as a phone or laptop is restored from an iCloud/Time Machine backup and reuses `seq = 42` for a different segment hash, causing a permanent fork.
   - Once Device A compacts segments `1..50` into a snapshot at vector clock `{A: 50, B: 30}` and drops segments `1..50`, a peer at `{A: 40, B: 35}` can no longer fetch `A: 41..50`. It must ingest A's snapshot *without* losing `B: 31..35` by replaying `B: 31..35` on top of the snapshot.
   - Membership sync and data sync are not ordered in §3: a peer **must** sync and validate the membership DAG up to epoch `e` *before* accepting or decrypting data segments from epoch `e`.

2. **LWW map choice (self-contradictory granularity, silent password destruction, and painful v2 Loro migration):**
   - §3 line 48 contradicts itself in two sentences: first it defines the map value as an *"encrypted item blob"* keyed by item ID (whole-item LWW), then claims *"LWW per field is the expected behaviour"*. Whole-item LWW means editing a note or adding a TOTP key on Device A while rotating the password on Device B **destroys either the new password or the TOTP key**.
   - Overwriting a password in place without an embedded `password_history` array loses the old password if a website's "Change Password" form errors out after Deadbolt saves the new one.
   - Hand-rolling a custom binary CRDT in v1 and switching to Loro in v2 (§7) creates a permanent v1→v2 wire/storage migration burden. Either use Loro 1.16 now (`02-rust-sync-stacks.md` §4: MIT, 1.x, built-in LWW Map + MovableList + ShallowSnapshot) or make the v1 item format a per-field causal map with automatic conflict-history preservation.

3. **Epoch chaining (defeats compaction and leaks all history):**
   - Chaining `VEK_{e+1} → VEK_e → … → VEK_0` forever (§2 line 42) is unnecessary once a snapshot re-encrypts live state under `VEK_{e+1}`. Keeping the chain forever prevents cryptographic erasure of old segments and forces every newly paired device to receive keys for the entire historical log back to vault genesis.

4. **Snapshot/compaction & "true delete" claims (resurrection bugs and missing GC coordination):**
   - §3 line 51 says *"Deleted items vanish from snapshots."* If Device A deletes Item X, writes a snapshot *without* a tombstone for X, and Device C (which was offline and still holds Item X from before the deletion) later syncs, **Item X will resurrect** unless either (a) snapshots retain compact tombstones `(item_id, deleted_at_op_hash)` until *every* active member device has acknowledged a frontier past the deletion, or (b) any state from before the snapshot's vector clock is strictly masked by the snapshot's frontier.
   - No garbage-collection protocol is specified: without each device advertising its `acked_snapshot_frontier` in its signed head, no device can safely delete old segments from the mailbox without stranding an offline device (`01-inkandswitch.md` §2 PushPin lesson).

5. **Membership conflict rules (incomplete cascade, Recovery Kit revocation, and 2-device bricking):**
   - §1 leaves mutual concurrent removal (`A removes B` || `B removes A`) unresolved and considers *"both removed"*. In a 2-device vault, "both removed" **permanently bricks all active devices**.
   - Worse, because §5 models the Recovery Kit as just *"a member device in the membership log"*, a single compromised device can sign `RemoveDevice(recovery_kit)` and lock the user out of their printed recovery sheet! The Recovery Kit must be a **Root tier (`tier 0`)** that no device (`tier 1`) is allowed to remove (`01-inkandswitch.md` §3.4b Keyline "Root role", §7.3).
   - Re-adding a previously removed device ID is not forbidden in §1; in causal graphs, re-adding the same key revives its old delegations (`01-inkandswitch.md` §3.4b). Removed device keys must be permanently burned.

6. **Expiring heads (misapplied WhatsApp rule drops offline spare devices):**
   - §1 line 39 says: *"Signed membership heads expire (e.g. 30 days)... nobody wraps new keys to a device not in the latest head they know."*
   - In WhatsApp (`03-mailbox-pairing-keys.md` §B.2), the *primary phone* re-signs the device list every 35 days so Meta's server cannot serve a stale list forever. In Deadbolt, there is no primary phone: if a user leaves their spare travel laptop powered off in a drawer for 31 days, it still belongs in the latest membership head! If instead you require every device to sign a heartbeat every 30 days to receive new key wraps, a laptop in a drawer for 31 days gets silently cut off from future epochs.
   - What should expire after 30 days is **a peer's trust in a silent mailbox/relay view**: if a device has not seen a newly signed membership head from *any* admin/device in 30 days, warn the user; never stop wrapping epoch keys to a member device that hasn't been explicitly removed by a `RemoveDevice` op.

7. **Recovery kit as a member (stateless paper device sequence collision & physical theft risk):**
   - A "paper device" has no persistent disk state. If the user recovers once in 2026 (`seq = 1`) and recovers again in 2027, a naive paper device will emit `seq = 1` again with a different hash, breaking per-device log invariants unless recovery first reads the membership DAG and derives a unique recovery epoch/nonce or immediately rotates the Recovery Kit.
   - A stolen paper kit with no passphrase gives silent, complete vault compromise (`03-mailbox-pairing-keys.md` §D.5, §D.6). Support an optional 2SKD mode (`Argon2id(passphrase) XOR HKDF(kit_secret)`), and require every device's UI to display a persistent high-priority alert whenever the Recovery Kit signs an operation.

8. **Pairing protocol details (stale iroh 0.x names, missing LAN mDNS, missing remote PAKE rendezvous):**
   - §1 and §4 use `NodeId` and `NodeAddr`, which are **iroh 0.x API names** (`02-rust-sync-stacks.md` §1: iroh 1.x uses `EndpointId` and `EndpointAddr`).
   - §4 line 57 proposes *"short numeric/word code + PAKE (CPace or SPAKE2), single attempt"* for camera-less devices, but omits **how the two devices discover each other's 256-bit `EndpointId` / `EndpointAddr` from a short code**. A 256-bit `EndpointId` cannot fit in a 4-word code! On a LAN, mDNS (`iroh-mdns-peer-lookup`) can advertise `H(nameplate)`; across NATs/subnets, a rendezvous channel (e.g., the configured mailbox/relay) is required (`03-mailbox-pairing-keys.md` §D.2).

9. **Mailbox trait & heads CAS (shared-head vs per-device-head confusion, broken on Folder backends, missing `delete_segment`):**
   - §6 defines `Mailbox` with `put_head` *using compare-and-swap (CAS)*, and claims the `Folder` backend (*"works with any sync tool / NAS / USB"*) implements it. **Syncthing, Dropbox, iCloud Drive, and Nextcloud do not have distributed Compare-And-Swap** (`03-mailbox-pairing-keys.md` §A.5)—concurrent writes produce `.sync-conflict` files!
   - Furthermore, since logs are per-device (§3), each device writes **its own head** (`heads/<H(device_id)>`, `03-mailbox-pairing-keys.md` §A.6), so different devices never race on the same head object anyway! On Folder backends, write immutable files `heads/<H(device_id)>/<seq>_<hash>` and clean up older head files so no file is ever mutated in place.
   - The `Mailbox` trait in §6 (`put_segment`, `list_heads`, `get_segment`, `put_head`) **omits `delete_segment`**, making mailbox compaction and "true delete" (§2, §3) impossible to execute against the trait.

10. **Metadata leakage (unpadded segment sizes, plaintext membership graph, default pkarr leaks):**
    - Without padding segments to power-of-two or fixed size buckets (`01-inkandswitch.md` §4.3; `02-rust-sync-stacks.md` §6; `03-mailbox-pairing-keys.md` §A.6), every single-password add/edit leaks its exact byte length and timing to S3/R2, folder sync providers, or the storage peer.
    - Unless object keys under the mailbox are keyed hashes (`HMAC(mailbox_ns_key, ...)`), the bucket operator sees device IDs and head structures.
    - `iroh` publishes signed pkarr records to `dns.iroh.link` by default (`02-rust-sync-stacks.md` §1 line 52). Unless explicitly disabled in `Endpoint::builder()`, every device's `EndpointId` and home relay URL are published to n0's public DNS server.

11. **iroh relay trust & the "token/allowlist" contradiction:**
    - §6 says *"Self-host relay (token/allowlist) and DNS discovery server"*, while §Goals says *"No accounts."* How does a brand-new user or un-paired device obtain a valid bearer token or get its `EndpointId` onto Deadbolt's self-hosted relay allowlist without an account/registration server? And if a static bearer token is shipped inside the open-source client binary, anyone can extract it with `strings`.
    - A central Deadbolt-operated relay + DNS server sees every user's `EndpointId`s, IP addresses, connection times, and device-to-device graph (`02-rust-sync-stacks.md` §1 line 44).
    - Once devices share a mailbox, each device should encrypt its current `EndpointAddr` (direct IP:port candidates + relay URL) inside its mailbox head, eliminating the need for any DNS/pkarr discovery server after initial pairing.

12. **Local unlock with no rate limiter:**
    - Leaving master passphrase vs OS biometrics as an open question (§Open questions #6) misses that **CLI and Linux desktop targets (`§Architecture: cli / sdk / ui`) often have no biometric hardware or hardware enclave at all**, while macOS/iOS/Android/Windows hardware enclaves *do* provide hardware-enforced rate limits. You need both: a mandatory memory-hard `Argon2id` master passphrase KDF at rest **plus** hardware-enclave (P-256 Secure Enclave / TPM / StrongBox) key wrapping where available.

---

## 4. Where the Proposal Misreads or Overstates the Research

1. **Conflates `iroh` transport key with the device identity key:**
   - *Proposal (§1 line 33):* `"Each device: Ed25519 identity key = its iroh NodeId"`.
   - *Research (`03-mailbox-pairing-keys.md` §D.1 line 231):* Explicitly warns: **"Keep the device signing key separate from the iroh node key. The transport ID can then be rotated, and the membership log does not depend on iroh internals."**
2. **Uses obsolete iroh 0.x terminology and omits required iroh 1.x LAN discovery crates:**
   - *Proposal (§1, §4, §6):* Uses `NodeId` and `NodeAddr`, and omits mDNS and tickets.
   - *Research (`02-rust-sync-stacks.md` §1 lines 30, 55–59, §7 line 341):* Notes that iroh 1.0 renamed `NodeId` to `EndpointId` and made LAN discovery opt-in via `iroh-mdns-peer-lookup` / `iroh-mdns-address-lookup`.
3. **Claims persistent per-item keys + chained epoch keys give PCS and "true delete":**
   - *Proposal (§2 lines 41–43):* Claims chaining epoch keys keeps old segments readable while dropping per-item keys from snapshots makes lingering mailbox bytes unreadable.
   - *Research (`03-mailbox-pairing-keys.md` §C line 185 & `01-inkandswitch.md` §7.3 lines 430–433):* Bitwarden's modern SDK requires fresh, never-reused CEKs per edit (`03-mailbox-pairing-keys.md` §C), and `01-inkandswitch.md` §7.3 notes that deleting history requires either key shredding *without* retaining old keys in the chain or full re-genesis once all devices ack.
4. **Ignores XChaCha20-Poly1305's lack of key commitment:**
   - *Proposal (§2 line 44):* Uses plain `XChaCha20-Poly1305` for multi-device/wrapped-key encryption.
   - *Research (`01-inkandswitch.md` §1 line 47, §3.7 lines 245–248):* Explicitly flags that XChaCha20-Poly1305 requires a key-committing construction to prevent multi-key collision attacks (Threat T7).
5. **Puts CAS `put_head` into the `Mailbox` trait and claims `Folder` backends support it:**
   - *Proposal (§6 lines 67–69):* Defines `Mailbox` with `put_head` (compare-and-swap) implemented over `Folder (works with any sync tool / NAS / USB)`.
   - *Research (`03-mailbox-pairing-keys.md` §A.5 lines 87–91 & Table line 37):* Explicitly states that Folder / Syncthing / Dropbox sync is **not atomic** and lacks CAS, requiring per-device head files and append-only unique file names.
6. **Overstates Recovery Kit derivation of mailbox credentials:**
   - *Proposal (§5 line 61):* `"The kit secret also derives the mailbox location/credentials"`.
   - *Research (`03-mailbox-pairing-keys.md` §A.3 line 75, §D.1 line 221):* Stated that the kit derives a *mailbox namespace key* or signs a *Pkarr pointer record* that points to the mailbox URL—not that third-party S3 credentials can be mathematically derived from a pre-printed seed.
7. **Drops Keyline's Root-tier authority separation for the Recovery Kit:**
   - *Proposal (§1, §5):* Makes the Recovery Kit an ordinary peer member in the membership log and leaves mutual concurrent device removal open.
   - *Research (`01-inkandswitch.md` §3.4b line 179, §7.3 lines 438–443):* Explicitly warns that peer-level mutual revocation can **permanently brick** the graph and recommends keeping an offline **recovery key as the sole root admin (`Root > Device`)**.
8. **Ignores the wall-clock/HLC LWW warning:**
   - *Proposal (§3 line 48):* Uses HLC LWW over encrypted item blobs.
   - *Research (`02-rust-sync-stacks.md` §6 lines 319–320 & `01-inkandswitch.md` §6 lines 380–383):* Explicitly warns against timestamp-based LWW (`iroh-docs` #120 trap) and requires causal-past (`before(u)`) validation for BFT CRDTs.

---

## 5. What's Over-Engineered for v1 vs. What's Missing

### Over-engineered for v1 (Cut or Simplify)
1. **Persistent per-item keys + infinite epoch-key chaining (§2):** Multi-user single-item sharing is an explicit v1 non-goal (§Non-goals line 11). Replace persistent item keys + chained epoch keys with: **per-segment/per-op keys under `VEK_e`**, and on `RemoveDevice` (`epoch e → e+1`), have the remover immediately write a **compacted snapshot encrypted under `VEK_{e+1}`** (with no chain to `VEK_e`). Once all active devices ack the snapshot, delete pre-snapshot segments and shred `VEK_e`.
2. **Peer-to-peer multi-admin revocation DAG without a Root tier (§1):** Don't invent an unverified concurrent admin-revocation graph. Give the **Recovery Kit `tier 0` (Root)** authority and give devices deterministic **seniority rank** (`tier 1`, ordered by sponsorship depth + `AddDevice` hash) so concurrent removals always resolve deterministically without bricking the vault.
3. **Self-hosting a custom token-gated `iroh-dns-server` for device discovery (§6):** Once devices are paired, they already share a mailbox (or direct LAN mDNS + cached addresses). Each device can write its encrypted current `EndpointAddr` inside its mailbox head, making a public or custom DNS discovery server completely redundant after pairing.

### Missing from v1 (Must Add Before Building)
1. **Local storage & encryption-at-rest architecture:** Specify the local store (`SQLite` or `redb`), how the Local Unlock Key (`LUK`) is derived (`Argon2id` + OS hardware P-256 enclave wrap), auto-lock timers, memory zeroization (`zeroize` crate), and OS core-dump/swap protections.
2. **Concrete Vault Item Schema & Conflict/Password History:** Define the item fields (CXF-compatible login, passkey with `signCount = 0`, TOTP, SSH key, secure note, custom fields) and include a bounded `history: Vec<HistoricalField>` array inside each item so overwritten or LWW-losing passwords/TOTPs are always recoverable by the user.
3. **Compacted Tombstones & Snapshot GC Watermarks:** Snapshots must retain lightweight tombstones `(item_id, deleted_at_op_hash)` until all member devices' `acked_frontier` pass the deletion, preventing offline peers from resurrecting deleted items.
4. **Compromised-Password Rotation Tracker:** To deliver on §Threat model line 19 (*"prompt the user to rotate the real passwords it could see"*), each item must record the `last_password_change_epoch` so Deadbolt can concretely list every item whose current password was readable by a removed device's epoch.
5. **Import / Export & Encrypted Backup Bundle:** A password manager with no 1Password/Bitwarden/CSV/CXF import and no single-file encrypted export is DOA for user adoption (`03-mailbox-pairing-keys.md` §C line 188).
6. **Wire limits & DoS bounds on `deadbolt/sync/1`:** Maximum segment size (e.g., 4 MiB; larger attachments go to content-addressed `iroh-blobs`/chunks), max DAG depth, and bounded pre-verification buffering.

---

## 6. Answers to the 6 Open Questions

1. **Concurrent mutual removal and "remove vs sponsor" races — exact rules, and what the UI says:**
   - **Never remove both devices** (that bricks a 2-device vault).
   - Assign every principal a total order `Seniority = (role_tier, sponsor_depth, blake3(add_op))`, where `RecoveryKit = tier 0` (cannot be removed by any `tier 1` device; can only be rotated by a signature from the current `RecoveryKit`) and `Device = tier 1`.
   - **Mutual removal rule:** When `Remove(B) by A` and `Remove(A) by B` are causally concurrent, the signer with the strictly smaller `Seniority` tuple wins; the loser's `Remove` op (and any ops it signed concurrently or afterward) is invalidated.
   - **Remove vs sponsor rule:** An op `u` signed by `X` is valid iff `X` is an active member in the state materialized from `u.parents` **and** no valid `Remove(X)` is concurrent with or causally precedes `u`. This transitively invalidates `B → Add(C) → Add(D)` whenever `Remove(B)` is concurrent with `Add(C)`.
   - **Permanent burn:** A removed `DeviceId` can never be re-added.
   - **UI:** On surviving devices, display a blocking security alert naming the revoked device(s), any cascaded sponsored devices, and the list of items whose passwords need rotation. On the removed device, switch to an offline read-only "Removed from Vault" state (never auto-wipe local data, so if a stolen senior device revoked an honest junior device, the user can still use their `tier 0` Recovery Kit to revoke the stolen senior device and re-onboard).

2. **Do we need an external timestamp/witness to stop a compromised-then-removed device from back-dating ops?**
   - **No external witness is needed for v1.**
   - Include `last_known_head_of_B: (seq, hash)` inside `RemoveDevice(B)`. Any segment from `B` not in the causal past of `last_known_head_of_B` is rejected (whiteout) unless another honest device had already referenced it in its own signed causal history *before* `RemoveDevice(B)`.
   - Because item ordering is causal (CF-1) and epoch `e+1` causally follows `RemoveDevice(B)`, a back-dated epoch-`e` op from `B` can never overwrite a post-removal epoch-`e+1` edit. Any back-dated concurrent edit from `B` against pre-removal state is shunted into the item's `conflict_history` array rather than silently replacing the active credential.

3. **Epoch-key chaining gives every current member all history — fine for one person; wrong for future multi-user sharing. When do we switch models?**
   - **Drop infinite epoch-key chaining now in v1.** Once a compacted snapshot is written under `VEK_e` and acknowledged by all active devices, drop `VEK_{0..e-1}` and delete pre-snapshot segments so "true delete" actually works.
   - **For multi-user sharing later, never share a personal vault's epoch chain.** Model each shared collection/folder as a **separate vault/space** with its own genesis, membership log, and epoch keys (the 1Password / Proton Pass / Keyhive Document model). Sharing an item copies or moves its current state into the shared vault's key hierarchy with zero exposure of prior personal history.

4. **Should the hosted storage peer be the default mailbox (better UX) at the cost of the "no server" story?**
   - **Build the iroh storage peer in v1 (`deadbolt serve-mailbox` in the same binary), make the hosted storage peer an opt-in 1-click option during onboarding, and offer Local Folder + S3/R2 right alongside it.**
   - Don't defer the storage peer to v2: an iroh storage peer is simpler to build and test than S3 conditional-write/folder-sync edge cases because it reuses the exact `deadbolt/sync/1` protocol (verifying device Ed25519 signatures against the membership log and storing ciphertext segments without keys). Shipping the self-hostable binary from day 1 preserves the "no mandatory server" promise while giving mobile users a zero-config option.

5. **PAKE crate choice and audit:**
   - **Primary v1 pairing should be QR-only (256-bit secret over iroh TLS 1.3 + HMAC transcript confirmation, plus 6-digit SAS when the sponsor displays the QR).**
   - For the camera-less short-code fallback, **do not depend on `magic-wormhole` (EUPL-1.2) or `spake2` (unaudited, no `Zeroize`).** Implement **CPace (`draft-irtf-cfrg-cpace-21`)** directly over `curve25519-dalek`'s `ristretto255` group in ~150 lines of internal module code verified against the CFRG draft test vectors, binding both `EndpointId`s and the session ID into the generator hash, gated by a single-attempt 2-minute rendezvous ticket.

6. **Local unlock: OS biometrics only, or also a master passphrase?**
   - **Require a Master Passphrase (or high-entropy local passcode) with `Argon2id` (`m >= 256 MiB, t >= 3`) on every device, AND layer OS Biometrics / Hardware Enclave (Secure Enclave / TPM 2.0 / StrongBox P-256 key) on top for day-to-day unlock.**
   - Biometrics-only fails on Linux/CLI/headless setups and leaves software keychains vulnerable to offline disk extraction; passphrase-only lacks hardware attempt rate-limiting on mobile/laptops. Combining a hardware-bound P-256 key (which gets silicon-enforced attempt lockouts) with an `Argon2id`-wrapped fallback gives hardware rate-limiting on supported devices and strong offline brute-force resistance everywhere.

---

## 7. Prioritized Changes to Make Before v1

1. **[P0 — Crypto/Data] Replace HLC LWW and persistent per-item keys with causal per-field ops, fresh per-op/per-segment keys, and conflict-preserving item history:**
   - Order item edits by causal parent hashes (not raw HLC); make post-removal epoch `e+1` edits causally dominate epoch `e`; generate fresh encryption keys on every edit; store overwritten/conflicting values in a per-item `history` list; break the epoch key chain at acknowledged snapshot boundaries so old epoch keys and pre-snapshot segments can actually be shredded.
2. **[P0 — Crypto/Wire] Fix the AEAD AAD circularity and add XChaCha20-Poly1305 key commitment:**
   - Remove `segment ID = BLAKE3(ciphertext)` from inside the AEAD AAD; bind `(domain_sep, vault_id, epoch, author_device_id, segment_seq, op_index, causal_parents_hash, item_id, op_kind, schema_ver)` in AAD; add a BLAKE3 key-commitment tag per encrypted payload; sign the outer segment hash.
3. **[P0 — Keys/Local Security] Decouple `iroh` `EndpointId` from the device's vault signing key and specify the Local Unlock Key (`LUK`) envelope:**
   - Keep `EndpointId` as a rotatable transport key certified by the device's Ed25519 key; encrypt the local database and device Ed25519/X25519/`VEK` keys at rest under `LUK`, gated by a hardware-enclave P-256 key (Secure Enclave / StrongBox / TPM) + `Argon2id` master passphrase, and zeroize keys in RAM on lock.
4. **[P0 — Membership/Recovery] Elevate the Recovery Kit to `tier 0` (Root), add deterministic seniority + whiteout watermarks, and fix mailbox authentication:**
   - Forbid `tier 1` devices from removing the `tier 0` Recovery Kit; resolve concurrent mutual device removals by deterministic seniority `(tier, depth, add_op_hash)`; include `last_valid_head` whiteout watermarks in `RemoveDevice`; stop claiming S3 credentials can be derived from the pre-printed kit (authenticate storage peers by per-device Ed25519 membership, and use an encrypted bootstrap pointer or explicit config for S3).
5. **[P0 — Pairing] Fix the pairing protocol (dedicated `deadbolt/pair/1` ALPN, New-Device-Shows-QR or 6-digit SAS, and mutual `DeviceBind` signatures):**
   - Admit pairing on a short-lived single-connection ALPN; pin the new device's keys in the QR (or verify a 6-digit SAS derived from the TLS exporter + both public keys); require the new device to counter-sign `AddDevice` + its X25519 KEM key before receiving `VEK_e`.
6. **[P1 — Mailbox/Sync] Redesign the `Mailbox` trait around immutable per-device heads + `delete_segment`, add size padding, and disable default `iroh` pkarr publishing:**
   - Drop shared-head CAS (which breaks on Folder backends); use per-device head objects (`heads/<H(device_id)>/<seq>_<hash>`); add `delete_segment` and `acked_snapshot_frontier` watermarks; pad segments to size buckets; disable `dns.iroh.link` pkarr publishing and exchange encrypted `EndpointAddr` hints inside mailbox heads + `iroh-mdns-peer-lookup` on LAN.
7. **[P1 — Product] Ship `deadbolt serve-mailbox` (iroh storage peer) + CXF/1Password/Bitwarden import-export + post-removal password rotation checklists in v1.**
