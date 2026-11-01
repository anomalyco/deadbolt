# Recovery When a Stolen Device Is More Senior

## 1. Threat Model and Current Behavior

Deadbolt's membership log (`crates/core/src/membership.rs`) is a signed causal DAG rooted at `MembershipOp::Create`. Every entry references its causal parent hashes (`Entry::deps`), and `Vault::apply` (`crates/core/src/vault.rs`) accepts an entry only if `entry.author()` is a member of `Vault::past_membership(&clock)`.

When two or more removals conflict—because they are concurrent (`A` removes `B` while `B` removes `A`), form a longer cycle, or cut an `Add` that authorized another removal—`choose_removals` (`crates/core/src/membership.rs`) arbitrates them by **seniority**:

1. `authorize(vault, ops, &[])` computes `structural`, the authority state with no cuts.
2. Each candidate removal is sorted by `(first.depth, first.entry.hash(), node.depth, node.entry.hash())`, where `first = structural.admissions[&node.entry.author()][0]` is the author's earliest structurally authorized admission (`MembershipOp::Create` at `depth = 0`, or the shallowest `MembershipOp::Add`).
3. Because an `Add` must see an admission of its author (`Authority::admitted_before`), any invited device sits strictly deeper (`node.depth > first.depth`) than the inviter's admission it saw.
4. `choose_removals` scans candidates in that fixed seniority order and greedily keeps each candidate that leaves `chosen` valid under `authorize(vault, ops, &chosen)`.

### Why a stolen senior device wins

Suppose device `A` creates the vault (`MembershipOp::Create`, `depth = 0`) and admits device `B` (`MembershipOp::Add`, `depth = 1`). Later, `A` is stolen while unlocked (or its passphrase is compromised), and the user runs `deadbolt devices remove A` on `B`, producing `r_ba` (`B` removes `A`).

Even after `r_ba` has been signed and synced to every honest device:
- The attacker holding `A`'s `DeviceSecret` can sign `r_ab` (`A` removes `B`) with `deps` pointing only to entries from before `r_ba` (for example, `[Add(B)]`), hiding causal knowledge of `r_ba`.
- To `Vault::apply`, `r_ab` is indistinguishable from a write made by `A` while offline before `r_ba`: in `r_ab`'s causal past, `A` is still an active member and `B` is an active member.
- Once `r_ab` reaches an honest device (either directly before `r_ba` was enforced, or via another member or a newly paired collaborator), `choose_removals` orders `r_ab` (`first.depth = 0`) ahead of `r_ba` (`first.depth = 1`).
- Keeping `r_ab` cuts `r_ba` (`!r_ab.saw(r_ba)`), so `r_ba` loses its authority in `authorize`. The stolen senior device `A` evicts the honest junior device `B` (`known_limitation_removed_senior_returns_with_hidden_parents` in `crates/core/src/membership_tests.rs`).

Note what the attacker **cannot** do once every honest member has already learned `r_ba`:
- Every honest member's `Vault::is_member(&A)` is `false`, so `Gate::check_dial`, `Gate::admit`, and `Gate::enforce_membership` (`crates/net/src/node.rs`) refuse `SYNC_ALPN` connections from `A`.
- Thus, in a pure device-to-device mesh where all remaining honest peers have already synced `r_ba`, `A` has no transport path to deliver `r_ab` to them.
- The vulnerability is reachable only during the race window where at least one honest member `C` has not yet synced `r_ba`, accepts a connection from `A`, receives `r_ab`, and then gossips `r_ab` to the rest of the group (which still trusts `C`).

---

## 2. Why the Greedy Resolver Works Today

The comment on `choose_removals` (`crates/core/src/membership.rs`) states the two properties that make the single greedy pass exact (finding the lexicographically greatest valid subset of removals without backtracking):

1. **Fixed candidate order (cut-independence of rank):** Candidate order `(first.depth, first.entry.hash(), node.depth, node.entry.hash())` is computed once from `structural = authorize(vault, ops, &[])` before any removal is chosen. Which removals win never reorders the remaining candidates.
2. **Hereditary validity (downward closure under subsets):** A set $S$ of removals is valid (`Graph::valid` in `crates/core/src/membership_tests.rs`) iff for every $R \in S$:
   - $R$ is authorized under $S$ (no $R' \in S \setminus \{R\}$ targets `R.entry.author()` with `!R'.saw(R)`, and `R.entry.author()` has an admission in $\text{past}(R)$ authorized under $S$),
   - `target(R)` has an admission in $\text{past}(R)$ authorized under $S$, and
   - no other $R' \in S$ with `target(R') == target(R)` is in $\text{past}(R)$.
   Dropping a removal from $S$ only removes cuts; as cuts shrink, `Authority::admissions` and `Authority::removals` only grow monotonically. Therefore, **every subset of a valid set $S$ is also valid**.

Any change to how removals override one another must preserve both properties (or replace the greedy pass with a new well-founded resolution rule and reference model in `crates/core/src/membership_tests.rs`).

---

## 3. Options

### Option A: Offline Root / Paper Recovery Key at Genesis (`depth = 0`)

`docs/design.md` ("Later") already notes:
> Recovery kit: a paper device with its own device key, added like any other device.

If the paper recovery key is created **as the genesis device** (`MembershipOp::Create` at `depth = 0`) and immediately signs `MembershipOp::Add` (`depth = 1`) for the user's first interactive device before the recovery seed is printed/saved offline and wiped from RAM:

- **How it works:**
  - The recovery key is the sole device at `first.depth == 0`.
  - Every interactive device (the creator laptop at `depth = 1`, phone at `depth = 2`, etc.) has `first.depth >= 1`.
  - The recovery key stays offline and never runs `deadbolt daemon`, so it cannot be stolen from an unlocked running session.
  - Because `RecoveryRemove` must undo what the thief already delivered, **signing via `Vault::remove` / `Vault::commit` is not sufficient**:
    1. `Vault::commit` uses `self.membership_tips` as `deps`. In `authorize` (`crates/core/src/membership.rs`), a removal only cuts operations by its target that the removal *did not see* (`!removal.saw(node)`). A removal whose `deps` are `self.membership_tips` sees—and therefore keeps—every `Remove` of honest devices and every sybil `Add` the thief already delivered.
    2. Any honest device that already applied a thief's `Remove(recovery)` considers `!vault.is_member(&recovery)`, so `Vault::commit` fails with `Error::NotMember`.
    3. `Vault::remove` sets `last_seen_seq` to the target's current data tip, which would keep the thief's post-theft data edits.
  - Instead, recovery requires a dedicated core API on `Vault` (for example, `Vault::recover_remove(&mut self, secret: &DeviceSecret, device: DeviceId, deps: Vec<Hash>, last_seen_seq: Option<u64>)`) that signs `MembershipOp::Remove { device, last_seen_seq }` with **chosen pre-theft membership parents** `deps` (such as the stolen device's admission and the recovery key's own previous membership entry) and a pre-theft `last_seen_seq`:
    - `Vault::apply` evaluates `past = self.past_membership(&clock)` at `deps`—where the recovery key is still an active member—so `apply` accepts the entry even on honest devices that had applied the thief's `Remove(recovery)`.
    - Because the recovery removal does not see the thief's post-theft operations (`!recovery_remove.saw(thief_op)`), `choose_removals` orders `recovery_remove` at `first.depth = 0` and cuts every post-theft removal and sybil `Add` by the stolen device, while `last_seen_seq` discards post-theft data writes.
- **Interaction with `choose_removals`:**
  - **Zero changes** to `choose_removals`, `authorize`, `Entry`, or wire encoding; only a new `Vault` signing helper that accepts explicit pre-theft `deps` and `last_seen_seq`.
  - Candidate order remains fixed by `structural`, and hereditary validity is unchanged because the recovery key is the genesis `DeviceSecret`.
- **Operational constraints and tradeoffs:**
  - *Vaults created before a recovery kit exists:* Because `VaultId::derive(&device, &nonce)` binds the vault ID to the `depth = 0` genesis key, a vault created without a recovery kit already has an online device at `depth = 0` and cannot retroactively receive a `depth = 0` recovery kit; upgrading requires moving items to a new vault.
  - *One-time offline property:* Importing the paper recovery kit onto an online device to sign a recovery removal exposes its `DeviceSecret` to that online host, ending its offline guarantee. After using the kit (especially if it only removes a compromised `depth >= 1` device), the kit is no longer strictly offline and the user should either provision a fresh vault or treat the kit as an online-exposed key.
  - *Pros:* Solves both total device loss and senior-device compromise with one mechanism; preserves `choose_removals` and its greedy correctness proof intact.
  - *Cons:* Requires saving a paper/offline recovery key at vault creation and choosing a pre-theft frontier (`deps` and `last_seen_seq`) when recovering.

### Option B: Quorum / Co-Signed Removals ($k$-of-$n$)

Allow a removal endorsed by a majority (or $k \ge 2$) of current members to outrank a single senior member's removal.

- **How it works:**
  - Either `MembershipOp::Remove` carries multiple `(DeviceId, Signature)` endorsements, or `choose_removals` groups co-targeted removals of `X` by distinct authors and ranks a removal by `(-(endorser_count as isize), min_endorser_seniority, ...)`.
- **Interaction with `choose_removals`:**
  - **Breaks cut-independence of rank and hereditary validity.**
  - First, a stolen senior device `A` can mint arbitrary sybil keys $S_1, S_2, \dots, S_m$ locally (`A -> Add(S_i)` with `S_i.join_consent`) and have all $m$ sybils co-sign `Remove(B)`, manufacturing an arbitrarily large quorum unless endorsements are restricted to devices whose admissions were already in $\text{past}(r_{ba})$—which is itself relative to the conflicting removal!
  - Second, if a removal's priority depends on how many of its endorsers survive cuts by other removals, candidate order is no longer fixed by `structural = authorize(vault, ops, &[])`. A senior removal cutting one endorser demotes the quorum removal mid-pass, invalidating the matroid/hereditary greedy argument.
- **Tradeoffs:**
  - *Pros:* No offline paper key needed when the user has $\ge 3$ honest devices.
  - *Cons:* Useless for the most common personal setup (2 devices: laptop + phone, where $1 \text{ vs. } 1$ has no majority); vulnerable to sybil `Add`s unless admission age is relative; destroys the fixed-order greedy proof in `choose_removals`.

### Option C: Accept the Limitation in v1 and Re-Vault on Senior Compromise

Keep `crates/core/src/membership.rs` as-is and provide a CLI/UI workflow (`deadbolt vault migrate` or export/import into a fresh vault) when a senior device is stolen.

- **How it works:**
  - As documented in `docs/design.md` ("Removing a device"), a removed device keeps all secrets it already synced, so the user must rotate passwords it saw regardless.
  - When a junior device removes a senior device, if every remaining honest device syncs the removal before the stolen device connects to them, the network gate (`Gate` in `crates/net/src/node.rs`) already blocks the stolen device from delivering a counter-removal.
  - If the stolen senior device *does* win a removal race during the sync window (or if the user wants finality without trusting that all peers heard the removal first), any surviving device still holds the complete decrypted item set in its local `store.redb` and can create a new vault (`Vault::create`) populated with the current items and pair the remaining honest devices into it.
- **Interaction with `choose_removals`:**
  - **Zero changes** to `crates/core/src/membership.rs` or `membership_tests.rs`.
- **Tradeoffs:**
  - *Pros:* Zero cryptographic, wire, or resolver complexity; aligns with `docs/design.md`'s v1 scope ("no recovery — lose every device, lose the vault").
  - *Cons:* Re-vaulting requires re-pairing remaining devices if the senior device actually wins a concurrent removal race during the gossip window.

---

## 4. Comparison Summary

| Criterion | Option A: Genesis Paper Recovery Key | Option B: Quorum ($k$-of-$n$) | Option C: Accept in v1 + Re-Vault |
| :--- | :--- | :--- | :--- |
| **Works for a 2-device vault (laptop + phone)?** | Yes | No ($1 \text{ vs. } 1$ tie) | Yes |
| **Resistant to sybil `Add`s by stolen senior?** | Yes (`depth = 0` is unique) | No (without complex relative-past rules) | Yes (new vault has fresh genesis) |
| **Preserves `choose_removals` greedy proof?** | Yes (unchanged) | No (rank depends on surviving cuts) | Yes (unchanged) |
| **Wire / `deadbolt-core` changes** | New `Vault` helper signing `Remove` with pre-theft `deps` + `last_seen_seq` (no resolver/wire change) | New op format + non-greedy resolver | None |
| **Extra user ceremony** | Save recovery kit at `init`; pre-kit vaults must move to a new vault; importing kit ends its offline property | None | Re-vault if senior wins race |

---

## 5. Recommendation

1. **Do not add quorum rules (Option B) or modify `membership::resolve`.** Quorum resolution fails in the 2-device case, invites sybil-admission gaming by the stolen device, and breaks the cut-independent candidate ordering that makes `choose_removals` simple, fast, and exhaustively verifiable against `Graph` in `crates/core/src/membership_tests.rs`.
2. **For v1 now (Option C):** Keep `membership::resolve` unchanged. In device-to-device sync, once all honest peers have received `Remove(senior)`, `Gate` (`crates/net/src/node.rs`) refuses connections from the removed senior device at the QUIC handshake layer, preventing it from injecting a backdated counter-removal.
3. **When the Recovery Kit (`docs/design.md`, "Later") is built (Option A):** Generate the paper recovery kit as the `depth = 0` genesis creator (`MembershipOp::Create`), immediately admit the first interactive device at `depth = 1`, and add a `Vault` API that signs `MembershipOp::Remove` with chosen pre-theft `deps` and `last_seen_seq` (rather than `Vault::commit`'s current tips) so the recovery removal cuts everything the thief delivered after the theft. Vaults created before recovery kits exist will need to migrate to a newly created vault to gain a `depth = 0` kit, and importing the kit onto an online machine should be treated as consuming its offline guarantee.
