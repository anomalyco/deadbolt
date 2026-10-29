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
reopen, startup rounds, sync, partitions, heals, failed writes, and revocation during sync.
Startup actions use the production barrier against the current membership, and
handlers read live readiness. Item actions use the production item-command path.
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
- **Watch coverage:** every accepted sync batch records a change for each vault
  whose items or membership grew, which is what `watch` streams, and none for
  a vault's items or devices that didn't.
- **Convergence:** after healing and unlocking, current members must agree on
  heads and items within twelve rounds. Stop early once they agree and their
  membership barriers are open. Removed devices need not converge.

Pairing uses the production proof, confirmation and welcome protocol with test
exporter bytes. The simulator shares the CLI's `Offer`, `JoinBlob`, `WelcomeMeta`,
consent and welcome-admission helpers; its adapter omits display and live addresses.
Ticket expiry, single-use admission and TLS exporter wiring
remain covered by the real-iroh tests in `crates/net/tests/net/pair.rs`.
Focused regressions also cut pairing during its exchange and check persistence
across reopening. A cut after admission can leave the inviter with a member that
never received its welcome; these traces check durability rather than convergence.

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
connection cancellation. The stream constructors and membership gate are exported
only with the net crate's `sim` feature, enabled by the CLI's dev-dependency.

`Loaded` owns transport-independent unlocked state. A `Session` adds its iroh
node. Vault changes build a private validated staging view, append new entries in
one durable transaction, then publish the view. A failed append leaves live heads
unchanged. Staging clones the validated vault, avoiding signature verification of
historical entries. Sync batches publish independently per vault.

The vault list comes from the encrypted entry log. Legacy `cli/vaults` metadata is
ignored, so a crash after storing genesis cannot hide the new vault.

Local item reads and writes are available immediately after unlock, including
imports. Readiness gates sending data to peers, accepting inbound data, and
invitations. Membership entries flow while the barrier is closed.

A startup round completes when each current member either completed its exchange
or was unreachable during the dial. A remote membership-gate refusal also completes
contact. Dial errors and dial timeouts are unreachable; other errors or timeouts
after connecting interrupt the round and require a retry. Members learned during
a round must also be attempted. Retries
wait one second and share a total 30-second budget (`2 * SYNC_TIMEOUT`), including
time spent connecting and exchanging entries. A device with no peers is ready
immediately.
Explicit sync and invitation commands share the same bounded readiness wait.

At the 30-second deadline, the startup round is cancelled, a warning is logged,
and peer data resumes using the membership learned so far. Regular background
sync continues retrying. This bounded, best-effort refresh can miss a removal
held only by an unreachable or persistently failing peer; the timeout is not
proof that membership is current. Removals learned before the deadline are
applied and enforced before data resumes. Paused-time unit tests cover dial versus
exchange failures, retries and the total deadline; simulations cover offline
writes and a fast removed peer answering before an honest peer's removal.
