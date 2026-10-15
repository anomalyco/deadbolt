# Deadbolt research 01: Ink & Switch (Keyhive, BeeKEM, Beelay → Subduction, Automerge)

- Retrieved: **2026-10-15**. Every status claim below is a snapshot from that date.
- Method: primary sources only: inkandswitch.com lab notebooks and essays, github.com/inkandswitch and github.com/automerge repos (README, `design/` docs, and source read in a scratch clone), crates.io, automerge.org, and papers by Kleppmann et al. Sources are linked inline. **[inference]** marks my own reasoning. **[uncertain]** marks claims I could not fully verify.
- Context: Deadbolt is a Rust password manager. Every device syncs directly with every other device (likely over iroh). Onboarding happens only by pairing with an existing device. Later there is a ciphertext-only mailbox/relay, and eventually general CRDT replication of a personal data store.

---

## 0. TL;DR

- **What is current:** Ink & Switch's stack is now **Automerge** (the CRDT; Rust core, production), **Keyhive** (access control and E2EE; Rust, *pre-alpha*), **BeeKEM** (Keyhive's decentralized group key agreement; Rust crate), and **Subduction** (sync for E2EE hash-linked data; Rust, *early preview*, with an **iroh 1.0 transport**). **Beelay has been superseded by Subduction.** **Keyline** is the successor authority model inside Keyhive; it is still being wired into core.
- **What to depend on today:** only `automerge` is production-grade. Keyhive, BeeKEM and Subduction all say outright "DO NOT use in production". They are unaudited and their APIs move weekly.
- **What to copy:**
  - devices as key-pair principals grouped under a "person" group
  - a `Relay` capability below `Read`, for servers that store ciphertext only
  - causal encryption: each chunk carries its ancestors' keys
  - content-addressed hash DAGs, where validity is decided only from an operation's causal past (BFT CRDT)
  - deterministic hash-boundary chunking, so ciphertext can be compacted without plaintext (Sedimentree)
  - signed handshakes with audience binding
  - a fixed cipher suite
- **What they warn about** (all documented):
  - no forward secrecy (FS)
  - revocation in a coordination-free system is fail-closed but griefable, and needs "rotation"
  - back-dating is undetectable without an external anchor
  - "duelling admins"
  - CRDT history grows without bound
  - metadata (IDs, membership graph, sizes, timing) leaks to relays
  - identity and key recovery are explicitly out of scope

---

## 1. Project map and maturity (as of 2026-10-15)

| Project | What | Lang | Version / last activity | License | Stated stability | Usable as dep? |
|---|---|---|---|---|---|---|
| Automerge (`automerge` crate) | JSON-like op-based CRDT with a compressed columnar history | Rust core; JS via Wasm, C bindings | crate 0.12.0 (2026-09-16); commits daily | MIT | "ready for production" since 2.0 (Jan 2023) | **Yes** |
| automerge-repo | Multi-document repo, storage and network adapters, sync servers | TypeScript | v2.x, v2.6.0 alphas | MIT | stable (JS) | JS only |
| samod | Rust implementation of automerge-repo, wire-compatible with JS | Rust | 0.15.0 (2026-09-30) | MIT | "very much a work in progress… don't use this anywhere serious yet" | Experimental |
| automerge-repo-rs (`automerge_repo`) | Older Rust repo | Rust | 0.3.0 (2025-10-03) | MIT | to be replaced by samod | No |
| Keyhive (`keyhive_core`, `keyhive_crypto`, `keyhive_wasm`, `keyline`) | Capabilities, group membership, E2EE | Rust (+Wasm/TS) | keyhive_core 0.7.0 (2026-10-13) | Apache-2.0 | **pre-alpha, unaudited, "DO NOT use in production"** | Prototype only |
| BeeKEM (`beekem`) | Concurrent TreeKEM variant (CGKA) | Rust | 0.5.0 (2026-10-13); preprint July 2026 | Apache-2.0 | part of the pre-alpha workspace | Prototype only |
| Beelay (`beelay-core`) | First Keyhive-aware relay/sync | Rust | 0.1.0-alpha.1 (2024-11-15), dormant | Apache-2.0 | superseded | **No** |
| Subduction (+ `sedimentree_core`, `subduction_iroh`, `subduction_keyhive`) | Sync protocol for encrypted hash-linked data | Rust (+Wasm) | subduction_core 0.19.0 (2026-10-07); nightly v0.20.0 (2026-10-15) | MIT OR Apache-2.0 | "early release preview… very unstable API… DO NOT use for production" | Prototype only |
| ARK (`@automerge/automerge-repo-keyhive`) | Keyhive + E2EE for automerge-repo | TS | 0.7.0-alpha.1 (2026-10-13) | n/a | alpha | JS only |

Sources:
- Keyhive README (pre-alpha warning, crate list, "Subduction (the successor to Beelay)", no audit, nonce/key-commitment construction unreviewed): https://github.com/inkandswitch/keyhive
- Subduction README (warning, crates, transports incl. Iroh/QUIC): https://github.com/inkandswitch/subduction
- Subduction depends on `iroh = "1.0"`: https://github.com/inkandswitch/subduction/blob/main/Cargo.toml. Upgrade announced in https://automerge.org/blog/2026-july/#iroh-v1-0-support
- crates.io pages for versions, dates and licenses: https://crates.io/crates/keyhive_core, https://crates.io/crates/beekem, https://crates.io/crates/subduction_core, https://crates.io/crates/sedimentree_core, https://crates.io/crates/subduction_iroh, https://crates.io/crates/automerge, https://crates.io/crates/samod, https://crates.io/crates/beelay-core, https://crates.io/crates/automerge_repo
- Last commits: https://github.com/inkandswitch/keyhive/commits/main (2026-10-13, "Bump keyhive versions (#265)"), https://github.com/inkandswitch/subduction/commits/main (2026-10-15)
- samod status: https://github.com/alexjg/samod
- Automerge 2.0 production / Rust rewrite: https://automerge.org/blog/automerge-2/
- automerge-repo v2.6.0 alphas: https://automerge.org/blog/2026-july/
- ARK npm: https://www.npmjs.com/package/@automerge/automerge-repo-keyhive. ARK API guide: https://automerge.org/docs/keyhive/ark-api-guide/ (announced in https://automerge.org/blog/2026-august/)
- Keyline not yet in core: open PR "WIP: Keyline in core & codecs" (#267, opened 2026-10-15): https://github.com/inkandswitch/keyhive/pulls. The `keyline` crate is in the repo but not on crates.io (crates.io lookup returned not-found). **[uncertain]** I do not know exactly how much of Keyline the current `keyhive_core` 0.7.0 uses.

Maturity signals worth knowing:
- Keyhive still serializes with **bincode**, which has an open "unmaintained" RUSTSEC issue (#170). The team plans to move to a bespoke encoding based on Subduction's.
  - https://github.com/inkandswitch/keyhive/issues/170
  - https://automerge.org/blog/2026-july/#bijoux
- Keyhive has an open "Audit for zeroization" issue (#187): https://github.com/inkandswitch/keyhive/issues/187
- Subduction has recent correctness bugs:
  - fragment boundaries / withheld commits: #315, #325, #326
  - "collections freeze at ~2,400 documents" (#268)
  - Wasm memory corruption in a long-lived server (#274)
  - https://github.com/inkandswitch/subduction/issues

---

## 2. "Local-first software" essay (Kleppmann, Wiggins, van Hardenberg, McGranaghan, April 2019)

Source: https://www.inkandswitch.com/essay/local-first/ (Onward! 2019, doi:10.1145/3359591.3359737)

- **Seven ideals:**
  1. no spinners
  2. multi-device
  3. network optional
  4. collaboration
  5. "the Long Now"
  6. security/privacy by default
  7. user ownership
- The essay explicitly lists **password managers** among the "personal data repositories" in scope.
- **E2EE for servers:** "Local-first apps can use end-to-end encryption so that any servers that store a copy of your files only hold encrypted data that they cannot read."
- **History-growth lesson (from PushPin):** "CRDTs store all history, including character-by-character text edits. These pile up, but can't easily be truncated because it's impossible to know when someone might reconnect to your shared document after six months away and need to merge changes from that point forward."
- **Cloud peers lesson:** servers belong as "cloud peers" that "store a copy of the document, and forward it to other peers when they come online", which solves the "closed laptop" problem. This is the exact role of Deadbolt's mailbox.
- **Responsibility shift:** "With data ownership comes responsibility: maintaining backups…". Recovery becomes the app's job.

---

## 3. Keyhive (access control + E2EE)

### 3.1 What it is
- "Local-first access control", aiming for "the guarantees of private chat but for any local-first application" ("Signal for documents").
  - Notebook index: https://www.inkandswitch.com/keyhive/notebook/
  - Entry 00 (2024-08-01): https://www.inkandswitch.com/keyhive/notebook/00/
- **Three layers** (entry 01, 2024-09-05: https://www.inkandswitch.com/keyhive/notebook/01/):
  1. *Convergent capabilities* (concap): certificate capabilities plus CRDT state.
  2. A *group-management CRDT* with coordination-free revocation.
  3. *E2EE with causal keys*, giving post-compromise security (PCS).
- **Explicit anti-goals** (entry 01):
  - user identity (binding humans to keys)
  - interactive protocols
  - a central authority
  - cryptographic agility
  - FIPS
- **Scale target:** "tens of thousands of documents, millions of readers, thousands of writers, and hundreds of admins" (entry 01). That is far above Deadbolt's needs. **[inference]**
- Renamed from "Beehive" on 2025-02-27; pre-alpha code opened 2025-03-10.
  - https://www.inkandswitch.com/keyhive/notebook/03/
  - https://www.inkandswitch.com/keyhive/notebook/04/
- Design index: https://github.com/inkandswitch/keyhive/blob/main/design/README.md
  - Keyhive is designed to be "agnostic about questions of identity and account recovery".
  - Sync is delegated to Subduction.

### 3.2 Principals and the capability model
- **Principal kinds** (glossary: https://github.com/inkandswitch/keyhive/blob/main/design/glossary.md):
  - *Individual*: a bare Ed25519 key, e.g. a device, WebCrypto context, passkey or hardware key. It publishes X25519 **prekeys** so others can add it to BeeKEM trees without a round trip.
  - *Group*: a key plus a delegation/revocation history.
  - *Document*: a group that also owns encrypted content and a BeeKEM tree.
  - *Active*: the local signer.
  - *Public*: a well-known key, used for "encrypt to anyone".
- **Self-certifying IDs:** every ID is an Ed25519 verifying key. The genesis/root key *is* the group or document ID ("membership by parenthood": the creator delegates to itself, then may discard the root key).
  - Glossary (above)
  - https://github.com/inkandswitch/keyhive/blob/main/design/group_membership.md
- **Access ladder:** `Relay < Read < Edit < Admin`.
  - `Relay` = "May sync and forward ciphertext but not decrypt it… Never placed in a BeeKEM tree."
  - `Read` = BeeKEM member.
  - `Admin` = may revoke beyond one's own proof lineage.
  - Source: glossary.
- **Transitive authority:** groups can contain groups and documents can contain documents (folders). Effective access is "the maximum over paths of the per-path minimum" (widest path).
  - Glossary; group_membership.md (cycles are allowed).
- **Device management pattern:** a person is a Group whose members are per-device Individuals. Documents delegate to the person, not to each device. Narrower sub-keys (e.g. a per-app WebCrypto context, or a notifications app with read access to one doc) hang off a device.
  - group_membership.md §Device Management
  - notebook 05: https://www.inkandswitch.com/keyhive/notebook/05/
- **Key rotation for an individual:** "Key rotation can then be handled by adding a new individual to the group and removing the old one" (notebook 05). Stateless keys themselves cannot rotate (group_membership.md).
- **Contact card:** "The minimal out-of-band bundle (verifying key + a prekey) needed to add someone" (glossary). This is the natural artifact for a Deadbolt pairing QR code. **[inference]**
- **Sub-delegation is never restricted.** Restricting it "leads to worse outcomes (e.g. users sharing secret keys)" (group_membership.md §Delegation).
- **Mutation vs read control:**
  - Write authorization is a signed delegation chain.
  - Read control is encryption.
  - Keyhive does **not** sign content chunks: "Distinguishing `Read` from `Edit` on the content path is the CRDT layer's responsibility."
  - Source: threat model T2: https://github.com/inkandswitch/keyhive/blob/main/design/threat_model.md
  - Automerge "author provenance" (who wrote which commit) is only "initial work" as of July 2026: https://automerge.org/blog/2026-july/#keyhive

### 3.3 Adding a device
- Mechanics:
  1. Obtain the new Individual's verifying key and prekey (contact card) out of band.
  2. A member with sufficient access signs a delegation into the person group.
  3. A BeeKEM **Add** places the new leaf in the next blank leaf and blanks its path to the root.
  4. Someone must do an **Update** to re-establish a root secret.
  - Sources: notebook 02 (BeeKEM): https://www.inkandswitch.com/keyhive/notebook/02/ ; glossary (prekeys, contact card)
- **Concurrent adds** land on the same leaf. They are resolved by "sorting all concurrently added leaves and blanking their paths" (notebook 02).
- **History access:** new members get the whole history. "any agent that has access now should automatically have access to all prior history, even if they weren't part of the group at the time that block was written."
  - https://github.com/inkandswitch/keyhive/blob/main/design/causal_encryption.md
- **Pairing UX:** Keyhive deliberately does not specify how the contact card is authenticated; that is "identity", which is out of scope (threat model Non-Goals). Deadbolt must design pairing authentication itself (QR + SAS, or the iroh endpoint ID inside the QR). **[inference]**

### 3.4 Removing a device: revocation semantics
Two generations of semantics exist.

**(a) Current concap model** (glossary + threat model):
- **Seniority:** "A non-admin may only revoke members junior to itself." An agent whose transitive access is at least the target's level may also revoke. A re-added agent keeps the seniority of its earliest add.
- **Conflict resolution:** conflicting concurrent revocations are "ordered by depth in the causal operation graph, then digest", so every replica picks the same survivor (T4).
- **Whiteout:** operations whose authority is later revoked are "retained for causality and excluded from materialisation". They cannot simply be tombstoned "because revocation cascades can revoke the revoker".
  - Design README: https://github.com/inkandswitch/keyhive/blob/main/design/README.md
- **Back-dating (T5):** each revocation records the document heads it was issued after. Content from the revoked key that does not causally precede that frontier is rejected. But: "Keyhive cannot distinguish a genuinely old operation that arrives late from a back-dated one. Applications that need this must add a timestamping or anchoring service."
- **Read revocation = PCS:** "The next path update after a removal produces a root secret the revoked member cannot derive… Historical plaintext is not recoverable from them" (threat model A2). Removal blanks the leaf and its path to the root, so there is no group key until someone updates (notebook 02).

**(b) Keyline, the successor authority graph** (https://github.com/inkandswitch/keyhive/blob/main/design/keyline/README.md)
- **Model:** a **state-based CRDT** of two add-only certificate kinds, delegations `{issuer, audience, subject, power, citation}` and revocations `{issuer, revoke, retain}`. Merge is set union. Authority is *derived* by a stratified-Datalog fixpoint:
  - pass 1 ignores revocations to compute each key's "admin reach";
  - pass 2 computes liveness.
- **No proof field; late binding.** A delegation is live while *some* route grounds its issuer. Removal therefore cascades implicitly, and **re-adding a key revives everything it ever issued**. "Fresh-key discipline" is required after compromise.
- **Who can revoke:**
  - the issuer or audience of a delegation: always, totally;
  - a third party: only on routes through its *admin reach*, the nodes it **ever** held Admin over. Admin reach only grows.
- **Permanence.** "Once a replica has applied a revocation, no merge may un-apply it." Revocations cannot be revoked; mistakes are healed by re-granting with `citation`.
- **"Ex-Admin sharp edge".** A removed admin keeps revocation (deny-only) power over their frozen reach forever. A durable removal therefore needs a **role rotation**: mint a successor role key, re-supply, re-roster. Cost is O(roster).
  - Rotation steps: https://github.com/inkandswitch/keyhive/blob/main/design/keyline/patterns.md#rotating-a-role
- **Root role is append-only.** If the subject key was destroyed, removal from the root role is "never durable". Concurrent mutual revocation among root admins can **permanently brick** the graph. Advice: keep the root role minimal ("one key per human owner, or just the creator") and use it rarely, "like a root CA". A retained subject key ("cold storage, threshold-split") enables re-rooting.
- **Griefing.** Any design with decentralized durable removal "hands every remover a griefing capability". Griefing is deny-only and attributable, and the victim keeps its replica.
- **Partial visibility.** A replica cannot prove it holds every revocation ("absence is not witnessable"). Withholding can only delay a revocation, because "one honest peer suffices". The recommendation is to *provisionally honour* unconfirmed revocations.
- **Open questions (as stated):**
  - **whiteout**: what happens to content the revoked key wrote while authorized; the `retain` watermark "moves the question but does not close it";
  - how a Relay revocation must trigger BeeKEM rotation: "the coupling point needs specifying".

### 3.5 Concurrency of membership changes
- Entry 01 names the hard cases:
  - two admins concurrently revoking each other
  - honest operations depending on later-revoked ones
  - back-dating
- Keyhive avoids consensus: "we currently consider it a last resort" (https://www.inkandswitch.com/keyhive/notebook/01/).
- An open issue (#127, 2025-04-23) asks exactly how membership fares "in absence of finality", using a back-dated counter-removal example: https://github.com/inkandswitch/keyhive/issues/127
- External critique (Element, not Ink & Switch), PaPoC 2026 "ERA":
  - Seniority ranking (from Kleppmann's 2025 keynote) prevents a junior admin from removing a senior one.
  - A revoked admin can back-date a counter-revocation.
  - The paper argues an optional **finality arbiter** issuing "epoch events" is needed for fairness.
  - https://arxiv.org/html/2601.22963v2
  - This is relevant if Deadbolt's mailbox should ever act as a tie-breaker. **[inference]**

### 3.6 Key agreement: BeeKEM (CGKA)
Primary sources:
- notebook 02 (2025-01-21): https://www.inkandswitch.com/keyhive/notebook/02/
- crate README: https://github.com/inkandswitch/keyhive/blob/main/beekem/README.md
- preprint *BeeKEM: Decentralized, Secure and Efficient Group Key Agreement* (Yen, Fábrega, Da, Kleppmann, Mumm, Park, Zelenka; received 2026-07-13): https://eprint.iacr.org/2026/1434
- notebook 06 (2026-07-31): https://www.inkandswitch.com/keyhive/notebook/06/

Why not existing protocols (notebook 02):
- MLS/TreeKEM needs a server-imposed total order.
- DCGKA (Weidner & Kleppmann) is decentralized but linear-cost, aimed at about 100 members.
- Causal TreeKEM needs commutative primitives such as BLS, with no good Rust library.
- BeeKEM is "closely modelled on TreeKEM", needs only **causal order**, and uses only X25519, BLAKE3 and XChaCha20-Poly1305.

Tree and operations:
- Leaves hold member IDs and rotating DH public keys. Inner nodes hold a DH public key plus an encrypted secret. The root secret is the group key.
- Operations:
  - **Update**: rotate the leaf and re-encrypt the path. This gives PCS.
  - **Add**: next blank leaf; blank the path.
  - **Remove**: blank the leaf and path; removes are applied *after* all concurrent operations so a concurrent self-update by the removed member cannot survive.

Concurrency handling:
- **Conflict keys.** When concurrent updates overlap at a node, *both* keys are kept, and the node is treated like a blank (encrypt to its "resolution"). This way "an adversary needs to compromise one of the latest leaf secrets". A later update replaces the conflict keys.
- **Merged trees have no root.** "After a merge of concurrent updates, the tree has no root key… A fresh update from any member will resolve the conflicts" (crate README).

Cost:
- O(log n) common case, O(n) worst case.
- Space O(n log n) worst case.
- "competitive with OpenMLS" (preprint abstract).

Security properties:
- **No FS.** "Old root and path secrets are kept so that earlier content stays decryptable" (crate README). Even at κ=1, standard FS fails because one individual secret can access multiple group secrets (notebook 06 fn 2).
- **Security parameter κ.** κ is the number of old individual secrets a member keeps.
  - κ>1 kills FS but is needed to read group secrets created under concurrency/partition.
  - "The actual implementation of BeeKEM uses a security parameter set to infinity" (notebook 06 fn 1).
  - An open feature request asks for an eviction / finite-retention API to bound cross-fork exposure (#217): https://github.com/inkandswitch/keyhive/issues/217
- **New property: cross-fork security.** Compromising a user does not reveal secrets from updates concurrent to that user's last processed update. Prior decentralized schemes (Causal TreeKEM, DCGKA) are vulnerable to "cross-fork attacks" (notebook 06).
- **Application secrets.** Each content chunk gets its own key, derived from the root (PCS) secret, the content reference and predecessor references (glossary; notebook 02 fn 5).

### 3.7 Causal encryption and cipher suite
- **Compress-then-encrypt.** Ranges of Automerge changes are compressed with the Automerge binary format and then encrypted, rather than encrypting each op (notebook 01).
- **Causal key embedding.** "include the keys for direct causal ancestors in each block". One (pointer, key) head unlocks the whole causal past but not concurrent or future blocks. Encrypted blobs can be stored as an unordered set.
  - https://github.com/inkandswitch/keyhive/blob/main/design/causal_encryption.md
- **Cipher suite:**
  - Ed25519 IDs and signatures
  - X25519 share keys
  - XChaCha20-Poly1305 with a **synthetic nonce** = BLAKE3(key, plaintext, doc ID); the recipient recomputes it after decryption, which gives key commitment
  - domain separator `/keyhive/`
  - **This nonce/key-commitment construction "has not been independently reviewed."**
  - Sources: https://github.com/inkandswitch/keyhive/blob/main/design/ciphersuite.md ; threat model T7 ; README

### 3.8 Threat model highlights
Source: https://github.com/inkandswitch/keyhive/blob/main/design/threat_model.md

- **Adversaries considered:**
  - untrusted relay (sees operation hashes, sizes, timing and the membership graph)
  - revoked member
  - malicious member
  - compromised device ("A user group delegating to per-device keys limits the blast radius to one device, which the user group can revoke")
  - network adversary
  - Byzantine peer (missing-predecessor operations are buffered, so withholding cannot cause divergence)
- **Accepted risks:**
  - **T8 metadata**: "Relays must see membership to evaluate capabilities"
  - **T9 genesis compromise**
- **Non-goals:** forward secrecy, identity, **key recovery or storage**, trusted time, availability, protection from a compromised host, traffic analysis.
- Keys can live in hosts' WebCrypto/hardware via an `AsyncSigner` abstraction.

---

## 4. Beelay → Subduction (sync with a keyless server)

### 4.1 Beelay as designed (notebook 05, 2025-03-13; now superseded)
Source: https://www.inkandswitch.com/keyhive/notebook/05/

- **Transport and authentication:**
  - An RPC protocol over any confidential transport.
  - Every message is Ed25519-signed and carries an **audience** (recipient public key, or hash of the URL for TLS servers) to stop phishing PITM, plus a **timestamp** against replay. Clock-skew correction comes from the rejection reply.
- **Sync proceeds in three stages:**
  1. **Membership graph** via RIBLT set reconciliation (Rateless Invertible Bloom Lookup Tables, https://arxiv.org/html/2402.02668v2). Symbols needed scale with the *difference* (≈1.35–1.7×), e.g. "a billion items in 240 bytes" for 5 differences.
  2. **Document collection** via RIBLT over `(doc ID, hash(heads, CGKA ops))`.
  3. **Per document:** RIBLT over CGKA ops, then **Sedimentree** for content.
- **Server visibility:** Automerge commit-graph hashes are kept *outside* the encryption envelope, "so the sync server knows the heads".
- **Round trips:** about 5 naively, about 2 with piggy-backing.

### 4.2 Subduction (current)
Sources:
- README: https://github.com/inkandswitch/subduction
- design docs: https://github.com/inkandswitch/subduction/tree/main/design

Overview:
- "peer-to-peer synchronization protocol… for CRDTs… efficient synchronization of encrypted, partitioned data between peers without requiring a central server."
- **Transports:** WebSocket, HTTP long-poll, **Iroh/QUIC**. A CLI server; redb and filesystem storage. Automerge was "the original target" but the protocol is generic over hash-linked data.

**Handshake** (wire format in https://github.com/inkandswitch/subduction/blob/main/design/protocol.md; details in https://github.com/inkandswitch/subduction/blob/main/design/handshake.md):
- A signed Challenge carries the issuer key, an **audience** (PeerId or DiscoveryId), a timestamp and a 128-bit nonce.
- The signed Response carries the challenge digest.
- Nonce tracking; `MAX_PLAUSIBLE_DRIFT` ±10 min (threats T2/T6: https://github.com/inkandswitch/subduction/blob/main/design/security/threats.md).

Wire objects (https://github.com/inkandswitch/subduction/blob/main/design/protocol.md):
- **`LooseCommit`** is signed and contains: IssuerVK, **SedimentreeId** (document ID, bound into the signature to prevent cross-doc upload), BlobDigest, BlobSize and parent digests.
- **`Fragment`** contains: head, boundary, 12-byte truncated checkpoints, blob digest and size.
- The payload blob is opaque, so the app encrypts it.

Sync modes (https://github.com/inkandswitch/subduction/blob/main/design/sync/README.md):
- **Batch** pull: request/response; a fingerprint summary as 8-byte SipHash-2-4 values with a random per-request seed (≈75% smaller than full digests); used for initial sync and reconnect.
- **Incremental** push: fire-and-forget to subscribers.
- **Subscriptions** and **RemoteHeads**: per-peer monotonic counters, "1.5 RTT acknowledgment".
- **[uncertain]** RIBLT from the Beelay note: I found no `riblt` references in the current Subduction or Keyhive source (grep of clones, 2026-10-15). The current docs describe only fingerprint-based batch diffing.

Policy hooks:
- `StoragePolicy::authorize_fetch/put`; unauthorized requests get an empty diff (threats T4: https://github.com/inkandswitch/subduction/blob/main/design/security/threats.md).
- `subduction_keyhive` implements these policies from Keyhive membership: a peer must be a known agent with sufficient access to the document.
  - https://github.com/inkandswitch/subduction/blob/main/subduction_keyhive/src/policy.rs

Assumptions (https://github.com/inkandswitch/subduction/blob/main/design/assumptions.md):
- idempotent, durable storage
- per-commit atomicity
- reliable delivery within a connection
- **no delivery guarantee across connections** ("Reconnection triggers fresh sync")

### 4.3 What the relay/server sees (metadata)
Compiled from Subduction protocol.md, threats T8, and Keyhive threat model T8.

- Document IDs (SedimentreeId = document public key).
- The **membership graph** (needed to evaluate `Relay`/pull rights).
- Per commit: the **issuer verifying key**, parent digests (DAG shape), blob size and digest.
- Heads, counts, sizes, timing, IP (transport-dependent).
- Mitigations suggested: application-layer encryption; "Consider padding for high-security applications"; mixnet transport is "out of scope" (design README).

### 4.4 Sedimentree: compaction of encrypted history without plaintext
Sources:
- https://github.com/inkandswitch/subduction/blob/main/design/sedimentree.md
- notebook 05

- **Problem:** per-keystroke commit hashes are too much metadata. Automerge's compact encoding has about 10% overhead, but a plaintext-blind server cannot re-compact on the fly the way the existing Automerge sync server does (notebook 05).
- **Scheme:**
  - A commit's depth = **number of leading zero bytes of its BLAKE3 hash**.
  - A commit with depth > 0 closes a **Fragment** covering history since the last checkpoint. Deeper fragments subsume shallower ones, so older history sinks into ever-larger "sediment" layers.
  - Boundaries are deterministic, so peers with different change sets agree on chunk contents.
  - **Minimization** removes supported fragments and covered commits. Identical content gives identical minimal tree and hash.
- **Sync** = exchange summaries/fingerprints of fragments plus loose commits, then transfer missing blobs.
- **Who compacts:** a *Read*-capable client must produce fragment blobs (compress-then-encrypt). The relay only stores and serves them. **[inference]**, consistent with the README "without requiring decryption during sync".
- **Maturity caveat:** several open bugs concern fragment boundaries and minimization (#306, #315, #325, #326).

---

## 5. Automerge: sync protocol, storage and the Rust core

- **Rust core.**
  - Automerge 2.0 (Jan 2023) was a "ground-up rewrite" in Rust; JS uses Wasm, plus C bindings: https://automerge.org/blog/automerge-2/
  - Automerge 3.0 (July 2025) uses the compressed representation at runtime, cutting memory ">10x" (Moby Dick paste: 700 MB → 1.3 MB): https://automerge.org/blog/automerge-3/
  - Hexane v1 storage engine (July 2026): 2–9× faster save/load: https://automerge.org/blog/2026-july/
  - Rust crate 0.12.0 (2026-09-16). Active correctness work on patches, diffs and sync (July/Aug 2026 blogs).
- **Sync protocol** (https://docs.rs/automerge/latest/automerge/sync/ ; source https://github.com/automerge/automerge/blob/main/rust/automerge/src/sync.rs):
  - Based on Kleppmann & Howard's BEC paper (https://arxiv.org/abs/2012.00472).
  - Assumes a reliable in-order stream between *two* peers per document.
  - Messages carry `heads`, `need`, and `have` (last-sync heads plus a **Bloom filter**, ~1% FPR, of changes since).
  - Persistable per-peer `State` holds `shared_heads`.
  - V2 messages can ship a whole compressed doc; a change set larger than 1/3 of the doc triggers a full-doc send.
  - **Both sides must be able to read/apply the document.** This is why it cannot run through a ciphertext-only relay, and why Beelay/Subduction exist (notebook 05).
- **Storage format** (https://automerge.org/automerge-binary-format-spec/):
  - Columnar document chunks plus (optionally deflate-compressed) change chunks.
  - `save()` writes the full compacted doc; incremental saves append changes.
  - automerge-repo pattern, as implemented in samod: store each new change as an incremental chunk, and once more than 10 new changes or more than 10 chunks are on disk, write a `doc.save()` snapshot keyed by a hash of the heads, then delete superseded chunks: https://github.com/alexjg/samod/blob/main/samod-core/src/actors/document/on_disk_state.rs
- **History is never discarded.** "Automerge stores the full history of documents… we assign a unique ID to every keystroke" (Automerge 3.0 post). I found no supported history-truncation/GC feature in the sources reviewed **[uncertain: not exhaustively verified]**.
- **Convergence is not correctness.** Ink & Switch's Livelymerge notebook: "Convergence Is Not Enough": https://www.inkandswitch.com/livelymerge/notebook/lm-02/ (via https://automerge.org/blog/2026-august/)

---

## 6. Martin Kleppmann's related papers

- **DCGKA**. Weidner, Kleppmann, Hugenroth, Beresford, *Key Agreement for Decentralized Secure Group Messaging with Strong Security Guarantees*, CCS 2021: https://eprint.iacr.org/2020/1281 , https://martin.kleppmann.com/2021/11/17/decentralized-key-agreement.html
  - No server ordering needed; works over any network, including servers that are "trusted less".
  - FS + PCS even with concurrent membership changes.
  - Uses two-party secure channels to send seed secrets.
  - Membership changes and PCS updates cost O(n).
  - Uses only standard primitives.
  - **[inference]** For a single user's ≤10 devices, linear cost is irrelevant, and DCGKA's FS is a property BeeKEM gives up.
- **BEC**. Kleppmann & Howard, *Byzantine Eventual Consistency and the Fundamental Limits of Peer-to-Peer Databases*, 2020: https://arxiv.org/abs/2012.00472
  - Sybil-immune replication is possible **iff** transactions are I-confluent.
  - Defines Byzantine causal broadcast over hash graphs plus an efficient reconciliation algorithm, which is the basis of Automerge sync.
- **BFT CRDTs**. Kleppmann, *Making CRDTs Byzantine Fault Tolerant*, PaPoC 2022: https://martin.kleppmann.com/papers/bft-crdt-papoc22.pdf
  - Use hash-derived op IDs.
  - Decide each update's validity **only from `before(u)`**, the set transitively reachable through its predecessor hashes, so all correct nodes agree.
  - Signatures are optional for SEC but needed for authentication.
- **Keynote: BEC and Local-First Access Control**, PaPoC 2025: https://martin.kleppmann.com/2025/03/31/papoc-keynote-byzantine.html ; slides https://speakerdeck.com/ept/byzantine-eventual-consistency-and-local-first-access-control
  - The ACL itself is a CRDT that must resist malicious manipulation.
  - Proposes **seniority ranking** for duelling admins: creator rank 1, added-by-rank-i gets rank i+1, ties broken by hash. This description is as summarized in the ERA paper.
  - "Paper on ACL CRDT is work in progress" (slide 91).
- **BeeKEM preprint** (2026, Kleppmann co-author): see §3.6.
- Related non-Ink & Switch context for the same problem space:
  - ERA (Element, PaPoC 2026): https://arxiv.org/html/2601.22963v2
  - Verus formal verification of local-first access control: https://arxiv.org/html/2604.23560
  - p2panda-auth notes, especially on leaked keys when combining an auth CRDT with key agreement under concurrency: https://p2panda.org/2025/08/27/notes-convergent-access-control-crdt.html

---

## 7. Lessons for Deadbolt

### 7.1 Reuse directly (candidates, ordered by safety)
1. **`automerge` crate.** Production-grade Rust CRDT, MIT, compressed history, good multi-device semantics. It is the strongest candidate for the vault/PDS document model. Pair it with `autosurgeon` for typed structs (https://github.com/automerge/autosurgeon). **Caveat:** history retention, see 7.3.
2. **`subduction_iroh` / `sedimentree_core` / `subduction_core`.**
   - For: already speaks iroh 1.0, carries opaque encrypted blobs, and has a CLI relay. It closely matches the "devices sync P2P + ciphertext mailbox" plan.
   - Against: explicitly unstable; open sync-correctness bugs.
   - Use: evaluate behind a Deadbolt-owned trait, pin exact versions, and be ready to fork. **[inference]**
3. **`keyhive_core` / `beekem`.** Do not ship on them for a password manager today: pre-alpha, unaudited, unreviewed nonce construction, bincode, Keyline migration in flight. Track them; reconsider after an audit and a stable codec. **[inference]**
4. **samod** (Rust automerge-repo). Self-described as not for serious use. Useful as a reference for storage compaction and actor structure.

### 7.2 Copy as design (even if not as code)
- **Principal model:**
  - device = Individual (Ed25519 signing key + X25519 prekeys)
  - the human = a Group over their devices
  - vault/PDS documents delegate to the human group
  - mailbox/relay = a principal with `Relay` access, *never in the key-agreement tree*
  - This maps one-to-one onto "no accounts, pair from an existing device".
- **Pairing artifact = contact card** (verifying key + prekey), authenticated out of band (QR code, iroh endpoint ID, short authentication string). Keyhive leaves this to the app.
- **Causal encryption.** Each encrypted chunk embeds its causal predecessors' keys, so a restoring device needs only the latest head key(s) to decrypt all history from mailbox ciphertext.
- **Compress-then-encrypt chunks with deterministic hash-based boundaries (Sedimentree).** This lets the mailbox store, deduplicate and serve compacted history without plaintext. Clients produce the compacted fragments.
- **BFT CRDT hygiene:**
  - content-addressed op IDs
  - signed ops
  - validity decided only from the causal past
  - buffer operations with missing predecessors
- **Transport auth.** Signed challenge/response with **audience binding** plus nonce/timestamp, even over iroh's authenticated QUIC, so app-level identity is bound to the device key used for authorization.
- **Fixed cipher suite and no negotiation;** versioned schema bytes for future migration (Subduction protocol.md; Keyhive anti-goal "cryptographic agility").
- **Set reconciliation sized to the difference** (RIBLT, or SipHash fingerprints with a random per-request seed) for collection-level sync across many PDS documents.

### 7.3 Pitfalls and open problems they document → Deadbolt implications
- **No forward secrecy, by design** (Keyhive non-goal; BeeKEM κ=∞).
  - Implication: a stolen or compromised device with old state can decrypt **all vault history**, including superseded passwords.
  - Deadbolt's "device lost" flow must therefore include *rotating the secrets themselves* (prompting password changes), not only revoking the device.
  - Consider per-item encryption with deletable keys for "forget this secret". **[inference]**
- **CRDT history grows and retains deleted values** (local-first essay; Automerge 3.0 post).
  - Implication: deleting a password from an Automerge doc does not delete it from history on any device or in mailbox ciphertext. A password manager needs a policy: per-entry encryption + key shredding, or periodic "re-genesis" (new document, old one abandoned once all devices ack).
  - The essay explains why truncation is hard: a peer may return after six months. A small, known device set makes "all devices have acked" checkable. **[inference]**
- **Revocation needs PCS *and* an online actor.** Removal blanks the BeeKEM path; secrecy against the removed device holds only after a subsequent Update. The removing device should immediately update and re-encrypt new content (notebook 02; threat model A2).
- **Offline removal races and back-dating.** A removed device can fabricate operations "from before" its removal; Keyhive cannot tell late from back-dated without an anchoring/timestamp service (T5).
  - Deadbolt option A: accept this, with whiteout via recorded heads.
  - Deadbolt option B: let the mailbox act as an *optional* finality/anchoring witness (ERA-style), with the trust trade-off made explicit. **[inference]**
- **Duelling devices.** A thief with one device could revoke the user's other devices. Keyline's answers:
  - keep the root role tiny and rarely used, e.g. an offline **recovery key** as the sole root admin and devices at a lower tier;
  - rotate roles after removing any admin-capable key;
  - use fresh keys on re-add, because re-adding the same key revives its old delegations.
  - Seniority schemes have known back-dating weaknesses (ERA).
- **Root/genesis compromise is fatal** (T9). The vault's genesis key should be created on a trusted device, used to delegate, and then destroyed or kept as cold recovery material (Keyline "Root Edges").
- **Recovery is out of scope for Keyhive.** Deadbolt must design it: e.g. a paper/recovery key as an extra Individual with Admin (or threshold-split), able to join the key-agreement tree and pull mailbox ciphertext when all devices are gone. Without it, "restore from mailbox" is impossible by construction. **[inference]**
- **Metadata leakage to the relay** (Keyhive T8, Subduction T8):
  - document IDs, the membership graph, signer key per commit, DAG shape, sizes, timing, IP.
  - For a mailbox, consider opaque per-mailbox IDs, not exposing the device graph, padding blobs, and batching uploads. These are deliberate deviations from Subduction's model. **[inference]**
- **Read vs Edit on content is the CRDT layer's job** (Keyhive T2). For multi-device vaults where every device has Edit, this barely matters. For a future PDS with shared docs, Automerge commit authorship/provenance is still WIP.
- **Scale and correctness of collection sync are not solved.** Subduction #268 shows collections freezing at about 2,400 documents. A general PDS with many small documents should stress-test this early.
- **Cross-fork exposure and secret retention.** Unbounded retention of old node secrets (κ=∞) widens exposure. There is an open request for eviction (#217). With a handful of devices, Deadbolt could choose a finite window and force re-encryption after long partitions. **[inference]**

### 7.4 Where Deadbolt can be simpler than Keyhive **[inference]**
- One human, roughly 2–10 devices, so group size is tiny. A DCGKA-style protocol (pairwise channels, O(n) per change, *with* FS for ephemeral messaging) or even "new epoch key encrypted to each remaining device's X25519 key" is cheap and much easier to audit than BeeKEM's conflict-key machinery.
- A single trust domain allows a much flatter authority model, for example:
  - a recovery root (offline)
  - device keys at Admin or Edit
  - a relay at Relay
- That model can still borrow Keyline's rules: fail-closed revocation, permanence, explicit rotation, fresh keys after compromise.
- General PDS sharing with *other people* later is where Keyhive's transitive groups and BeeKEM scale become relevant. Keep the principal and capability encoding compatible with that path: Ed25519 IDs, a Relay/Read/Edit/Admin ladder, and contact cards.

---

## 8. Open questions to settle for Deadbolt
1. Do we need FS for vault history, or is "rotate the secrets after device loss" plus per-item key shredding enough?
2. Recovery: a paper key as an admin principal? Threshold-split? What can it do: read only, or also revoke?
3. Should the mailbox be a pure `Relay`, or also an optional finality/anchoring witness for revocations?
4. How much metadata may the mailbox see? Is the device graph visible or hidden?
5. History policy: Automerge with periodic re-genesis, or a custom state-based CRDT for vault items (smaller, no keystroke history)?
6. Build on Subduction + iroh behind an abstraction now, or write a minimal sync and adopt Subduction once it stabilizes?

---

## 9. Source index
- Keyhive notebook: https://www.inkandswitch.com/keyhive/notebook/
  - entries 00–06: `/keyhive/notebook/00/` … `/06/`
  - 00 2024-08-01, 01 2024-09-05, 02 2025-01-21, 03 2025-02-27, 04 2025-03-10, 05 2025-03-13, 06 2026-07-31
- Keyhive repo and design docs: https://github.com/inkandswitch/keyhive
  - design/README.md, glossary.md, group_membership.md, causal_encryption.md, ciphersuite.md, threat_model.md
  - keyline/README.md, keyline/patterns.md, keyline/evaluation-notes.md
  - beekem/README.md
- Keyhive issues #127, #170, #187, #217, PR #267: https://github.com/inkandswitch/keyhive/issues
- Subduction repo and design docs: https://github.com/inkandswitch/subduction
  - design/README.md, assumptions.md, handshake.md, protocol.md, sedimentree.md, sync/README.md, security/threats.md
- Subduction issues #268, #274, #306, #315: https://github.com/inkandswitch/subduction/issues
- BeeKEM preprint: https://eprint.iacr.org/2026/1434
- Automerge:
  - https://github.com/automerge/automerge
  - https://docs.rs/automerge/latest/automerge/sync/
  - https://automerge.org/automerge-binary-format-spec/
  - blogs: https://automerge.org/blog/automerge-2/ , https://automerge.org/blog/automerge-3/ , https://automerge.org/blog/2026-july/ , https://automerge.org/blog/2026-august/
- samod: https://github.com/alexjg/samod
- Local-first essay: https://www.inkandswitch.com/essay/local-first/
- Kleppmann papers:
  - https://eprint.iacr.org/2020/1281
  - https://arxiv.org/abs/2012.00472
  - https://martin.kleppmann.com/papers/bft-crdt-papoc22.pdf
  - https://martin.kleppmann.com/2025/03/31/papoc-keynote-byzantine.html
- External context:
  - https://arxiv.org/html/2601.22963v2
  - https://arxiv.org/html/2604.23560
  - https://p2panda.org/2025/08/27/notes-convergent-access-control-crdt.html
