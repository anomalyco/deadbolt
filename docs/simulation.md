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

The exact-cap file regression transfers a 10 MiB file, rejects a one-byte
aggregate overflow, and checks concurrent attachments and selective reads after
restart. It is explicitly **ignored in debug builds** to keep the default run
fast; the smaller file regressions still run by default. Run the full-size case
explicitly in debug with:

```sh
cargo test -p deadbolt-cli --bin deadbolt agent::sim::full_size_files_sync_and_concurrent_files_survive_reload -- --exact --ignored
```

In release builds it is **not ignored**: the existing nightly
`cargo test --workspace --release --locked` runs it automatically, alongside
the nightly seed exploration. To verify that release behavior without running
the whole workspace:

```sh
cargo test -p deadbolt-cli --bin deadbolt --release --locked agent::sim::full_size_files_sync_and_concurrent_files_survive_reload -- --exact
```

## A seed controls actions and delivery

Two fixed seeds run by default. Each generates 48 actions after pairing three
devices: item creation, edits, deletion, restoring the latest deleted item, pairing, removal, lock/unlock, crash and
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
  heads, membership, vault names, items, deleted items (with their deletion
  times), and complete histories of live and deleted items within twelve
  rounds. Stop early once they agree and their
  membership barriers are open. Removed devices need not converge.

Pairing uses the production PAKE, key confirmation and welcome protocol with a
fixed code, rendezvous key and test exporter bytes, and fixed seeds in place of
the OS randomness of the SPAKE2 scalars, so a trace replays byte for byte. The
simulator shares the CLI's `Offer`, join consent and welcome helpers; its
adapter omits display and live addresses. Rendezvous, code expiry, single use,
burning on a wrong guess and TLS exporter wiring remain covered by the
real-iroh tests in `crates/net/src/pair.rs` and `crates/net/tests/net/pair.rs`.
Focused regressions interleave outgoing frame pulls with a new attachment and a durable removal. The stream stops at the original signed frontier, aborting on loss of the last shared vault or on a pairing removal after the welcome header. The multi-vault sync handler regressions remove a recipient between pulls: the surviving vault sends its original membership and data, while not even the removed vault’s queued `Add` leaves. A replay missing a pinned data tip aborts instead of being mistaken for a safe skip. Other regressions cut pairing during its exchange and check persistence
across reopening. A cut after admission can leave the inviter with a member that
never received its welcome; these traces check durability rather than
convergence, and pairing such a device again finishes the join without a second
`Add` (`pairing_again_after_a_cut_finishes_the_join`).

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
adapter supplies authenticated identities, exporter bytes, the rendezvous, code
lifetime and connection cancellation. The stream constructors and membership gate are exported
only with the net crate's `sim` feature, enabled by the CLI's dev-dependency.

`Loaded` owns transport-independent unlocked state. A `Session` adds its iroh
node. Vault changes build a private validated staging view, append new entries in
one durable transaction, then publish the view. Validation and pre-commit errors
leave live heads unchanged. A commit error is different: redb may already have
persisted the new root, including a removal, even though its final sync returned
an error. The store reports `AppendUncertain`; native `Loaded` permanently
invalidates all live vaults until replay. The agent refuses reads, writes, sync
and pairing, clears the membership gate and closes its sync connections, cancels
background sync/health work and marks readiness closed. Startup deadlines and
retries cannot reopen it. The app's Unlock action (or `deadbolt unlock`) closes
the failed node/store under the lifecycle transition, then uses normal fresh
passphrase or biometric authentication and disk replay. Quarantine is never
treated as already unlocked: a bad passphrase leaves the device locked. Explicit
`deadbolt lock` still closes the failed handle. No uncertain mutation is retried.
A warning records only the typed failure class, I/O kind and numeric OS error,
never backend messages, paths or vault values.
Native and standalone writes use the same core transaction: validation borrows the
committed log and checks each new entry against that prefix plus previously
accepted entries in this batch. Only the new entries are encoded, one at a time,
in membership-then-data order inside one store transaction. After confirmation
the verified nodes, indexes and resolved membership become live, and the item
view is updated. A single data edit does not copy historical nodes or item state.
Compound local writes that read their earlier changes project those changes on
demand. A membership change rebuilds the view if it changes which entries count
in an already projected data log. Adding a new key therefore leaves existing
items alone. Adding a key whose earlier admission was cut is different: its
stored but ignored data now counts, so dependent edits must be replayed too.
Sync batches still publish independently per vault. The short-session regression uses
the same cut budget twice, asserts each interrupted exchange advances the
receiver before `DONE`, reopens that exact prefix, then heals.

The native `agent::session::tests::ambiguous_append_` regressions use synthetic
encrypted stores on a real file backend. They inject a lost acknowledgement
*after* the second/root-switch fsync succeeds, then reopen and verify that the
errored append persisted. They cover item changes, removals and both sides of
pairing. This is not the simulator's pre-write fault or a claim to emulate power
loss or every filesystem error. The agent regression also checks that an existing
local-only sync connection is closed and readiness cannot be republished.
The quarantine recovery regressions cover bad passphrases, overlapping explicit
unlocks, fresh biometric authentication via the existing test hook, and explicit
lock. They verify the committed edit is replayed once, not retried.

The vault list comes from the encrypted entry log. Legacy `cli/vaults` metadata is
ignored, so a crash after storing genesis cannot hide the new vault.

Local item reads and writes are available immediately after unlock, including
imports. Readiness gates sending data to peers, accepting inbound data, and
invitations. Membership entries flow while the barrier is closed. On the native agent, a
received item edit triggers immediate forwarding if there is another peer; it
does not redial the sole peer that just sent the edit. Membership changes,
local writes, and periodic anti-entropy still trigger their normal rounds.

A startup round completes when each current member either completed its exchange
or was unreachable during the dial. A remote membership-gate refusal also completes
contact. Dial errors and dial timeouts are unreachable, except a peer refusing the
dial at its handshake admission or transport limit (QUIC `CONNECTION_REFUSED`
before TLS, reported as `Rejected`), which interrupts the round. Other errors or
timeouts after connecting, including a global or per-member established-sync
`BUSY` close, interrupt the round and require a retry. Members learned during
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

The real transport, not the stream simulator, separately bounds 256 handshakes
(5 seconds each) and 32 authenticated inbound sync connections (two per member).
Address validation via QUIC Retry precedes the handshake budget; only a completed,
membership-admitted handshake may claim a sync slot. Pairing transfers to its own
bounds. Idle waits for the first or next stream expire after 60 seconds by default,
independently of the session timeout, closing the connection and releasing its
slots. Real-connection net tests stall TLS after Retry, verify member sync still
works, and exercise idle closure followed by a new successful sync. CLI and browser
background rounds dial fresh connections; callers reusing `SyncConnection` must
redial after closure. The caps do not guarantee availability under handshake or
network saturation, nor prevent a member from continually reconnecting.
