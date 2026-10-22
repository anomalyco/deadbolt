# Replay sync failures without sockets

The CLI's `agent::sim` tests run four devices with real encrypted redb stores,
the core vault model, the membership gate, and production sync handlers. Run them
with:

```sh
cargo test -p deadbolt-cli --bin deadbolt agent::sim::
DEADBOLT_SIM_SEED=42 DEADBOLT_SIM_SEEDS=1 cargo test -p deadbolt-cli --bin deadbolt agent::sim::exploration
DEADBOLT_SIM_SEEDS=1000 cargo test -p deadbolt-cli --bin deadbolt agent::sim::exploration
```

In Kit's environment, put the command (including `env NAME=value`) after
`hivemind run --kind cargo --`.

## A seed controls actions and delivery

Two fixed seeds run by default. Each generates 48 actions after pairing three
devices: item creation, edits, deletion, pairing, removal, lock/unlock, crash and
reopen, sync, partitions, heals, failed writes, and revocation during sync.
Removal actions use the creator as author; concurrent removal authority conflicts
belong to the core membership tests.

The stream scheduler manually polls both protocol futures and two duplex relay
futures. A seeded generator chooses polling order and chunk size. Delaying one
direction creates backpressure; a poll-count cutoff drops a connection partway
through its exchange. Delivery order varies between directions. Bytes within a
stream stay ordered, as they do with QUIC. The adapter checks the real membership
gate between polls and cancels revoked connections.

There are no network sockets, background tasks, sleeps or wall-clock deadlines.
Device keys and genesis nonce are fixed. At-rest keys and encryption nonces still
come from the OS, and address-book timestamps use the wall clock; neither enters
the simulated scheduling or signed log. A regression runs the same trace twice
and compares its wire digest.

## Properties run throughout the trace

- **Removal confidentiality:** causal descendants of a removal must never enter
  the target's accepted log or appear in outgoing wire captures to that target.
  An isolated peer cannot know a removal occurred elsewhere. This property uses
  causal order, not the wall-clock order of writes on isolated devices.
- **Encrypted disk:** scan every changed store file for the common plaintext
  marker in generated secret values. Unchanged file versions retain their last
  successful scan.
- **Durability:** accepted entry hashes equal persisted hashes after each step.
  Crash/reopen also compares heads before and after rebuilding from disk.
- **Convergence:** after healing and unlocking, current members must agree on
  heads and items within twelve rounds. Stop early once they agree and their
  membership barriers are open. Removed devices need not converge.

Pairing uses the production proof, confirmation and welcome protocol with test
exporter bytes and signed core join consent. Its test adapter omits CLI display
and address metadata. Ticket expiry, single-use admission and TLS exporter wiring
remain covered by the real-iroh tests in `crates/net/tests/pair.rs`.

Crashes drop and reopen stores between actions. Connection cuts cover protocol
cancellation during a session. Failed-write actions inject an error at the
production persistence seam before durable append; they do not simulate torn
redb pages or power loss during fsync. Store corruption and process-kill tests
remain in `deadbolt-store`.

## Failures print a replayable, reduced trace

A failure prints its seed, full JSON action list and a shrunk JSON list. The
shrinker removes chunks and then individual actions, recreating fresh stores for
each attempt and preserving the same root failure. Replay the reduced list with:

```sh
DEADBOLT_SIM_TRACE='["Heal",{"Pair":1}]' cargo test -p deadbolt-cli --bin deadbolt agent::sim::exploration
```

Set `DEADBOLT_SIM_TIMING=1` and add `-- --nocapture` for per-action timings.

## Production seams and failure semantics

`run_sync_session` accepts generic async byte streams and the existing three-method
`SyncHandler`. `PairingStream::invite`, `PairingStream::prove`, and
`ProvenPairing::complete` share the pairing exchange with the iroh adapter. The
adapter supplies authenticated identities, exporter bytes, ticket lifetime and
connection cancellation.

`Loaded` owns transport-independent unlocked state. A `Session` adds its iroh
node. Vault changes build a private validated staging view, append new entries in
one durable transaction, then publish the view. A failed append leaves live heads
unchanged. Staging currently rebuilds the vault from its entries, trading CPU for
a small, auditable persistence seam. Sync batches publish independently per vault.

The vault list comes from the encrypted entry log. Legacy `cli/vaults` metadata is
ignored, so a crash after storing genesis cannot hide the new vault.

The startup barrier opens only after every current known peer completed a
membership round. Failed attempts retry; new members learned during that round
must also be contacted. Both inbound data and local item access remain blocked.
This deliberately fails closed when a known peer is offline; it does not claim
that a timeout proves a peer has no newer removal. A device with no peers is
ready immediately.
