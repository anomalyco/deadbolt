# Deadbolt proposal — revision 1: no Deadbolt-run infrastructure

2026-10-15, after dax: "dropping data is not a disqualifier. I don't think we want to run any of our own infrastructure for this, ideally. We can in the future run our own relays that guarantee data availability."

Supersedes §6 (Transports) and parts of §5 (Recovery) of `04-proposal.md`.

## Principle
Devices are the source of truth. Every mailbox is a **lossy cache** that only exists to help an offline device catch up. Losing mailbox data is normal and self-healing: any online device that notices a gap re-publishes.

## Mailbox v1 = public Nostr relays (+ Blossom for big blobs)
- Each vault derives, per epoch, a **mailbox key** (Nostr keypair) and a **locator** tag from the epoch key. Relays never see device identities or a stable npub across epochs.
- Event types:
  - **Segment**: regular event, encrypted segment payload (≤ ~32 KB; split larger), inner signature by the member device (relays only see the mailbox key's signature). Tagged with the locator.
  - **Head**: addressable kind 30078 (NIP-78), `d` = H(locator ‖ device ID). Latest per device: its log seq + segment hashes. Relay keeps only the newest.
  - **Snapshot**: chunks on Blossom (content-addressed, encrypted), pointer in a head-like addressable event. Republished on a schedule so the newest snapshot is always the freshest thing on relays.
- Publish to **N relays (e.g. 5–8)** chosen from NIP-11 limits; read from all, union results. Prefer relays supporting NIP-42 AUTH (serve only to the author key).
- **Repair loop**: on every sync, a device checks each relay for the latest heads/snapshot and re-publishes what's missing. Data only disappears for good if every relay drops it *and* no device comes online in time.
- Spam/forgery: anyone can post with the locator; devices ignore anything not signed by a current member inside the ciphertext.
- Metadata: relays see the per-epoch mailbox key, locator, sizes, timing and client IP. Rotate per epoch, pad to size buckets.

## Live sync = iroh, without our relays
- Direct QUIC + hole punching. LAN via mDNS.
- **Problem to resolve:** iroh needs a relay for connection setup/fallback, and n0 says its free public relays are for dev/testing; production should use n0's paid relays or self-host. Options: (a) ship with n0 public relays and accept the risk, (b) pay n0 (their infra, not ours), (c) make iroh optional and fall back to Nostr-only sync when no direct path exists (slower, but zero infra). Recommend (c) as the floor and (a/b) as the fast path.
- Discovery without our DNS server: pkarr on the Mainline DHT (iroh supports it) or a Nostr addressable event carrying current node addresses.

## Pairing without our infra
- Same-LAN / QR: QR carries NodeAddr + one-time secret; iroh direct or via relay.
- Remote short-code: PAKE messages exchanged as ephemeral Nostr events (kind 2xxxx) keyed by H(code nameplate) — no magic-wormhole server needed.

## Recovery, honestly
- With lossy relays, "lose every device" restore is **best effort**: recovery kit derives the mailbox key/locators → fetch newest snapshot + heads → admit new device. Works as long as at least one relay kept the latest snapshot.
- Hedge without our infra: optional **encrypted export file** the user can drop anywhere (iCloud Drive, Dropbox, USB) — same snapshot format; and the folder/S3 backends stay available as user-owned mailboxes.
- Future: our own relays/Blossom with guaranteed retention are just more entries in the relay list; no protocol change.

## Mailbox abstraction stays
`Mailbox` trait gets two flavours: **lossy** (Nostr/Blossom; append + latest-head, no CAS) and **durable** (folder/S3/storage-peer/our future relays). The replication layer already never needs CAS because every log has one writer, so the same code works against both.
